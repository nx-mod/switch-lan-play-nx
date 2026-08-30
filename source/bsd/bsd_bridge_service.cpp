#include "bsd_bridge_service.hpp"
#include "../cfg/runtime_cfg.hpp"
#include <arpa/inet.h>
#include <poll.h>
#include <array>

// libnx C services used by the lazy socket stack below (same pattern as
// ldn_mitm's own ldnmitm_main.cpp).
extern "C" {
#include <switch/services/bsd.h>
#include <switch/services/nifm.h>
}

/*
 * bsd_bridge_service.cpp
 *
 * Generic commands are forwarded to the real bsd:u service byte-for-byte
 * via raw libnx HIPC dispatch (serviceMitmDispatch*) against
 * m_forward_service -- ldn_mitm never notices it's being mitm'd for these.
 * Only Bind/SendTo/RecvFrom/Close have real logic, and only for the one
 * socket bridged to the relay (see header).
 */
namespace ams::mitm::bsd {

    namespace {
        slp::RelayBridge g_relay;
        bool g_relay_connect_attempted = false;
        // Explicit on/off switch for the overlay's Start/Stop buttons --
        // EnsureRelayConnected() refuses to (re)connect while this is false.
        // Independent of g_relay.IsConnected(): being "enabled" just means
        // allowed to connect, not that it currently IS connected.
        bool g_relay_enabled = true;
        // Mirrors the active BsdBridgeService instance's own m_bridged_local_ip
        // (per-instance, not otherwise reachable from the static ConfigService
        // accessors) so the overlay can show what virtual/local address this
        // console is presenting as. 0 = no bridged session active right now.
        u32 g_last_bridged_local_ip = 0;

        // How many bridged sockets are currently open, summed across EVERY
        // process's own BsdBridgeService instance -- not just one anymore,
        // since ldn_mitm's own control channel and a game's own separate
        // gameplay socket can both be bridged at the same time now (see
        // this file's own header comment). g_relay is a single global
        // singleton tunnel shared by all of them; Close() below must only
        // tear it down once the LAST bridged socket goes away, not the
        // first one -- otherwise a game closing its own socket (e.g.
        // between rounds) would yank the relay out from under ldn_mitm's
        // still-active session too.
        int g_bridged_socket_count = 0;

        // The single instance (there is only ever one real ldn_mitm process)
        // currently bound to LdnControlPort -- lets the background drain
        // thread keep driving retransmit-checking/TCP-segment processing at
        // high frequency (5ms) without needing a full instance registry,
        // without reintroducing the cross-process collision bug: this is
        // only ever set by Bind() when a socket was verified to actually
        // bind LdnControlPort, never by an arbitrary other mitm'd process.
        // nullptr = no LDN control channel bridged right now.
        BsdBridgeService *g_active_ldn_instance = nullptr;

        // Guards g_relay/g_relay_connect_attempted/g_socket_stack_ready/
        // g_relay_enabled/g_last_bridged_local_ip.
        // Added alongside slpnx:cfg's Reconnect command (cfg/cfg_service.cpp):
        // before that, EnsureRelayConnected() was only ever called from the
        // single mitm dispatch thread (mitm::TotalThreads == 1, main.cpp), so
        // these globals were touched from one thread only. Reconnect can now
        // call ForceReconnect() from the SEPARATE cfg server thread while the
        // mitm thread is concurrently mid-EnsureRelayConnected/SendTo/RecvFrom
        // -- without this, Close() racing a live Connect()/SendIpv4() on
        // g_relay's socket is a real use-after-close.
        ams::os::SdkMutex g_relay_mutex;

        // --- per-pid dummy-session skip for intercepted APPS -----------------
        // A game (MK8DX, and most other titles) opens a dummy first bsd:u
        // session that never calls RegisterClient and crashes if intercepted
        // even when handled gracefully -- the very first session of each
        // "burst" of bsd:u activity must be forwarded transparently, and only
        // session #2+ intercepted. Each pid-burst: dummy first time through,
        // then the live count rises; once the pid's live count drops back to
        // zero (all its sessions closed) the pid is forgotten so the next
        // burst (e.g. WiFi -> Finalize -> LAN) skips its dummy again.
        // Only tracked for APPLICATION sessions (never ldn_mitm's own control
        // channel, which has no dummy). Fixed-size table -- a handful of pids
        // at most -- matching this project's zero-heap, static-array style.
        struct DummySkipEntry {
            u64 pid = 0;
            u32 live = 0;          // number of LIVE (intercepted) services for this pid right now
            bool dummy_skipped = false; // whether this burst's dummy was already forwarded
        };
        constexpr size_t MaxDummySkipEntries = 8;
        DummySkipEntry g_dummy_skip[MaxDummySkipEntries];
        ams::os::SdkMutex g_dummy_skip_mutex;

        // Watchdog: a game can force-close without calling ldn:u's own
        // Finalize()/CloseAccessPoint()/DestroyNetwork(), leaving the
        // underlying session alive indefinitely -- the normal teardown path
        // (Close()-triggers-g_relay.Close(), above) never fires for that
        // case, and we can't hook ldn:u's own teardown since we only ever
        // touch ldn_mitm's bsd:u calls. Independent safety net instead: if
        // the relay has been "connected" for a long time with NO real
        // bridged traffic at all, something is very likely orphaned (a real
        // active LDN session generates control traffic continuously), so
        // drop it and let the next real usage reconnect fresh rather than
        // staying wedged until a reboot.
        std::atomic<u64> g_last_bridge_activity_ms{0};
        constexpr u64 WatchdogIdleTimeoutMs = 10 * 60 * 1000; // 10 minutes
        bool g_watchdog_started = false;

        void TouchBridgeActivity() {
            g_last_bridge_activity_ms.store(
                ams::os::ConvertToTimeSpan(ams::os::GetSystemTick()).GetMilliSeconds(),
                std::memory_order_relaxed);
        }

        void WatchdogThreadMain(void *) {
            while (true) {
                ams::os::SleepThread(ams::TimeSpan::FromSeconds(60));
                std::scoped_lock lk(g_relay_mutex);
                if (!g_relay.IsConnected()) continue;
                u64 last = g_last_bridge_activity_ms.load(std::memory_order_relaxed);
                if (last == 0) continue; // no bridged traffic has ever flowed yet -- nothing to judge staleness against
                u64 now = ams::os::ConvertToTimeSpan(ams::os::GetSystemTick()).GetMilliSeconds();
                if (now - last < WatchdogIdleTimeoutMs) continue;
                LogFormat("BsdBridge: watchdog -- relay idle %llu ms with no bridged traffic, "
                    "closing (likely an orphaned session -- next real use reconnects fresh)",
                    static_cast<unsigned long long>(now - last));
                g_relay.Close();
                g_relay_connect_attempted = false;
                g_last_bridged_local_ip = 0;
                g_bridged_socket_count = 0; // relay's gone regardless of what any still-live instance's own m_bridged_fd thinks
                g_last_bridge_activity_ms.store(0, std::memory_order_relaxed);
            }
        }

        constexpr size_t WatchdogStackSize = 0x2000;
        alignas(ams::os::MemoryPageSize) u8 g_watchdog_stack[WatchdogStackSize];
        ams::os::ThreadType g_watchdog_thread;

        void EnsureWatchdogStarted() {
            if (g_watchdog_started) return;
            g_watchdog_started = true;
            Result rc = ams::os::CreateThread(std::addressof(g_watchdog_thread), WatchdogThreadMain, nullptr,
                g_watchdog_stack, sizeof(g_watchdog_stack), 20);
            if (R_FAILED(rc)) return;
            ams::os::SetThreadNamePointer(std::addressof(g_watchdog_thread), "BsdBridge::Watchdog");
            ams::os::StartThread(std::addressof(g_watchdog_thread));
        }

        // Drain pump: DrainRelay() (defined further down) used to run ONLY
        // when ldn_mitm itself called a bsd:u command that touches the relay
        // (RecvFrom/Poll/Select/Accept/Connect) -- observed in practice to be
        // every 100-400ms, gated entirely by ldn_mitm's own worker loop
        // cadence. That's dead time added on top of real relay latency, on
        // BOTH consoles, in BOTH directions of a join. ldn_mitm's own
        // LANDiscovery::connect() (lan_discovery.cpp) gives the whole
        // Connect-packet-out -> SyncNetwork-reply-in exchange a single flat
        // 1-second sleep with no retry -- unmodifiable (this project has to
        // sit under a completely stock ldn_mitm, that's the whole point of
        // the mitm approach) -- so every millisecond spent merely waiting
        // for ldn_mitm to get around to polling is a millisecond stolen from
        // that fixed budget.
        //
        // The original PC client this project ports (switch-lan-play/src,
        // uv_lwip/) never had this problem: it's a libuv event loop wired
        // through a full lwip TCP/IP stack, so packets are processed the
        // instant they arrive, not on whatever cadence a caller happens to
        // poll at. This thread is the Switch-native equivalent -- draining
        // the relay continuously instead of only when ldn_mitm asks.
        bool g_drain_thread_started = false;
        constexpr size_t DrainThreadStackSize = 0x2000;
        alignas(ams::os::MemoryPageSize) u8 g_drain_thread_stack[DrainThreadStackSize];
        ams::os::ThreadType g_drain_thread;

        void DrainRawRelayQueue(); // defined below -- needed here since this thread predates it in file order

        void DrainThreadMain(void *) {
            while (true) {
                DrainRawRelayQueue(); // instance-agnostic: files raw relay traffic into the shared, port-tagged queues

                // Drive the one real ldn_mitm instance's own retransmit
                // checking + TCP-segment processing at this same tight
                // cadence too, same as before this was split apart -- see
                // g_active_ldn_instance's own comment. Deliberately does NOT
                // hold g_relay_mutex across the DrainRelay() call itself:
                // DrainRelay() (and SendTo()'s TCP branch, elsewhere in this
                // file) acquires g_vtcp_mutex and, from there, can still
                // need g_relay_mutex (EnsureRelayConnected) -- holding
                // g_relay_mutex HERE while calling into something that takes
                // g_vtcp_mutex would invert that existing lock order against
                // a different thread doing vtcp-then-relay, a real deadlock.
                // Copy the pointer under the lock, release, then use it.
                BsdBridgeService *active;
                {
                    std::scoped_lock lk(g_relay_mutex);
                    active = g_active_ldn_instance;
                }
                if (active != nullptr) active->DrainRelay();

                ams::os::SleepThread(ams::TimeSpan::FromMilliSeconds(5));
            }
        }

        void EnsureDrainThreadStarted() {
            if (g_drain_thread_started) return;
            g_drain_thread_started = true;
            // Same priority tier as RelayBridge's own pump thread
            // (relay_bridge.hpp PumpThreadPriority) -- this thread is
            // downstream of that one (it consumes what the pump already
            // queued) and needs to run just as promptly.
            Result rc = ams::os::CreateThread(std::addressof(g_drain_thread), DrainThreadMain, nullptr,
                g_drain_thread_stack, sizeof(g_drain_thread_stack), 6);
            if (R_FAILED(rc)) return;
            ams::os::SetThreadNamePointer(std::addressof(g_drain_thread), "BsdBridge::Drain");
            ams::os::StartThread(std::addressof(g_drain_thread));
        }

        // Host/port come from slpnx::cfg::RuntimeCfg (cfg/runtime_cfg.hpp),
        // persisted on SD and editable at runtime from the switch-lan-play-nx
        // Tesla overlay. Falls back to a default relay if nothing is
        // configured yet (see RuntimeCfg::GetSelectedHostPort's own default).

        // ---- lazy socket stack ----------------------------------------------
        // Deferred rather than initialized in main.cpp's InitializeSystemModule:
        // this process still needs its OWN real bsd:u session for the relay
        // UDP socket in relay_bridge.hpp, but initializing nifm/bsd/socket
        // before registering the mitm would race ldn_mitm's own
        // bsdInitialize(). Only needed once traffic actually flows, well
        // after RegisterMitmServer has won the mitm-registration race.
        bool g_socket_stack_ready = false;

        consteval size_t GetLibnxBsdTransferMemorySize(const ::SocketInitConfig *config) {
            const u32 tcp_tx_buf_max_size = config->tcp_tx_buf_max_size != 0 ? config->tcp_tx_buf_max_size : config->tcp_tx_buf_size;
            const u32 tcp_rx_buf_max_size = config->tcp_rx_buf_max_size != 0 ? config->tcp_rx_buf_max_size : config->tcp_rx_buf_size;
            const u32 sum = tcp_tx_buf_max_size + tcp_rx_buf_max_size + config->udp_tx_buf_size + config->udp_rx_buf_size;
            return config->sb_efficiency * util::AlignUp(sum, os::MemoryPageSize);
        }

        constexpr const ::SocketInitConfig LibnxSocketInitConfig = {
            .tcp_tx_buf_size = 0x800,
            .tcp_rx_buf_size = 0x1000,
            .tcp_tx_buf_max_size = 0x2000,
            .tcp_rx_buf_max_size = 0x2000,
            .udp_tx_buf_size = 0x2000,
            .udp_rx_buf_size = 0x2000,
            .sb_efficiency = 4,
            .num_bsd_sessions = 3,
            .bsd_service_type = BsdServiceType_User,
        };

        alignas(os::MemoryPageSize) constinit u8 g_socket_tmem_buffer[GetLibnxBsdTransferMemorySize(std::addressof(LibnxSocketInitConfig))];

        constexpr const ::BsdInitConfig LibnxBsdInitConfig = {
            .version             = 1,
            .tmem_buffer         = g_socket_tmem_buffer,
            .tmem_buffer_size    = sizeof(g_socket_tmem_buffer),
            .tcp_tx_buf_size     = LibnxSocketInitConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size     = LibnxSocketInitConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = LibnxSocketInitConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = LibnxSocketInitConfig.tcp_rx_buf_max_size,
            .udp_tx_buf_size     = LibnxSocketInitConfig.udp_tx_buf_size,
            .udp_rx_buf_size     = LibnxSocketInitConfig.udp_rx_buf_size,
            .sb_efficiency       = LibnxSocketInitConfig.sb_efficiency,
        };

        void EnsureSocketStack() {
            if (g_socket_stack_ready) return;
            Result rc = nifmInitialize(NifmServiceType_Admin);
            LogFormat("BsdBridge: lazy nifmInitialize -> %s", R_SUCCEEDED(rc) ? "ok" : "FAILED (continuing)");
            rc = bsdInitialize(&LibnxBsdInitConfig, LibnxSocketInitConfig.num_bsd_sessions, LibnxSocketInitConfig.bsd_service_type);
            if (R_FAILED(rc)) { LogFormat("BsdBridge: lazy bsdInitialize FAILED"); return; }
            rc = socketInitialize(&LibnxSocketInitConfig);
            if (R_FAILED(rc)) { LogFormat("BsdBridge: lazy socketInitialize FAILED"); return; }
            g_socket_stack_ready = true;
            // Runtime reference keeps g_socket_tmem_buffer odr-used (its only
            // other mention is constexpr-evaluated away, which trips
            // -Werror=unused-variable).
            LogFormat("BsdBridge: lazy socket stack ready (tmem %p %zu)",
                static_cast<void *>(g_socket_tmem_buffer), sizeof(g_socket_tmem_buffer));
        }

        // fd-type tracking (TrackFd/UntrackFd/GetTrackedType) and the vtcp
        // connection helpers (FindVTcpConnByFd/ByPeer/AllocVTcpConn) are now
        // BsdBridgeService instance methods (defined near the class's other
        // methods further down) instead of free functions over globals --
        // see the header's own comment on why (per-process fd isolation).

        // Mirrors BsdBridgeService::LdnControlPort (private class member, not
        // reachable from these free functions) -- same value, ldn_mitm's own
        // DefaultPort from lan_discovery.hpp. Both the UDP control channel
        // AND the TCP station channel use this SAME port number; only the IP
        // protocol byte tells them apart.
        constexpr u16 LdnControlPort = 11452;

        // Parses one raw IPv4/UDP packet (as popped from RelayBridge::PopIpv4)
        // into its source IP, destination port, and payload -- still used for
        // the control channel only.
        bool ParseIpv4Udp(const u8 *pkt, size_t pkt_len, u32 &out_src_ip, u16 &out_dst_port,
                const u8 *&out_payload, size_t &out_payload_len) {
            if (pkt_len < 28) return false;
            u8 ihl = (pkt[0] & 0x0F) * 4;
            if (pkt[9] != 17 || pkt_len < static_cast<size_t>(ihl) + 8) return false; // 17 = IPPROTO_UDP
            out_src_ip = (static_cast<u32>(pkt[12]) << 24) | (static_cast<u32>(pkt[13]) << 16) |
                         (static_cast<u32>(pkt[14]) << 8) | static_cast<u32>(pkt[15]);
            const u8 *udp = pkt + ihl;
            out_dst_port = static_cast<u16>((udp[2] << 8) | udp[3]);
            u16 udp_len = static_cast<u16>((udp[4] << 8) | udp[5]);
            size_t payload_len = (udp_len >= 8) ? (udp_len - 8) : 0;
            if (static_cast<size_t>(ihl) + udp_len > pkt_len) return false;
            out_payload = udp + 8;
            out_payload_len = payload_len;
            return true;
        }

        // Small buffer every bridged UDP socket's incoming packets pass
        // through -- DrainRelay is the ONLY caller of GetRelay().PopIpv4(),
        // so UDP packets get sorted in here instead of RecvFrom popping the
        // shared relay queue directly (which would risk handing a TCP
        // segment to the UDP-side parser). Same capacity as RelayBridge's
        // own QueueSize.
        //
        // SHARED across every bridged process's UDP socket, not just
        // ldn_mitm's own control channel -- a game's own gameplay socket
        // (different process, different port, same relay tunnel) files in
        // here too now. dst_port is what lets each process's own RecvFrom
        // (bsd_bridge_service.cpp) pick out only the entries meant for ITS
        // OWN bound port, leaving everyone else's where they are. A plain
        // dense array + linear scan (not a ring buffer) because "remove one
        // arbitrary matching entry, not just the head" is now the normal
        // access pattern, and ControlQueueSize is small enough that O(n)
        // scan+compact costs nothing real.
        // Real ldn_mitm LAN payloads (and a game's own UDP gameplay
        // payloads, now that Bind() bridges those too) can be up to
        // LanSocket::BufferSize -- 2048, matching VTcpInboxCap (header) --
        // not RELAY_MTU (1400), which is the wire FRAGMENT size, not a
        // payload cap: relay_bridge.hpp already transparently fragments/
        // reassembles anything bigger via SendFragmented/ReassembleFrag.
        // Every local buffer in this file used to be sized to exactly
        // RELAY_MTU, which meant SendTcpSegment/SendTo silently failed
        // (return -1 / EMSGSIZE) for any real payload over ~1360-1372
        // bytes instead of ever reaching that fragmentation path --
        // confirmed as a real bug, independently hit and fixed in a
        // sibling project (ldn_mitm-dogty: "fragment full-MTU game
        // datagrams instead of dropping them").
        constexpr size_t MaxBridgedPayload = VTcpInboxCap;

        constexpr size_t ControlQueueSize = 32;
        struct ControlPacket { size_t len; u16 dst_port; u8 data[20 + 8 + MaxBridgedPayload]; };
        ControlPacket g_control_queue[ControlQueueSize];
        size_t g_control_count = 0;
        ams::os::SdkMutex g_control_queue_mutex;

        // Pulls the first queued packet whose dst_port matches, compacting
        // the rest down. Caller must hold g_control_queue_mutex.
        bool PopControlPacketForPort(u16 port, ControlPacket &out) {
            for (size_t i = 0; i < g_control_count; i++) {
                if (g_control_queue[i].dst_port != port) continue;
                out = g_control_queue[i];
                for (size_t j = i + 1; j < g_control_count; j++) {
                    g_control_queue[j - 1] = g_control_queue[j];
                }
                g_control_count--;
                return true;
            }
            return false;
        }

        // ---- real TCP tunnel -------------------------------------------------
        // Bridges ldn_mitm's OTHER socket: the LDN "station" TCP connection
        // (lan_discovery.cpp initTcp()) used for the Connect/SyncNetwork join
        // handshake after ScanResp. Builds and parses genuine TCP segments: a
        // real 3-way handshake (SYN / SYN-ACK / ACK), real sequence/ack
        // tracking, real TCP checksums, tunneled via the same
        // RelayBridge::SendIpv4/PopIpv4 plumbing the UDP control channel uses
        // (the relay is a dumb raw-packet router keyed on destination IP; it
        // doesn't care what IP protocol number a packet carries). A real
        // peer's own ldn_mitm sends genuine raw TCP (protocol 6) on port
        // 11452 -- the same port the UDP control channel uses, distinguished
        // only by the IP protocol number -- so this interops with it
        // directly.
        //
        // Confirmed from ldn_mitm's own source (lan_protocol.cpp
        // TcpLanSocketBase::recvfrom/sendto) that the TCP fd is used with
        // plain sendto(fd,buf,len,0,nullptr,0)/recvfrom(fd,buf,len,0,nullptr,0)
        // -- i.e. bsd:u's SendTo/RecvFrom commands, the SAME commands already
        // handled below for the UDP fd, just with an empty addr.
        //
        // Deliberate simplifications vs a full RFC793 stack (acceptable given
        // LDN's own traffic pattern here -- a handful of small control
        // messages, not bulk transfer): no retransmission timer or
        // congestion control on OUR side (a real peer's own TCP stack already
        // retransmits on its own timeout if we don't ACK in time -- see the
        // "no room left" note below); no out-of-order reassembly (a
        // mismatched seq is just dropped, relying on the peer's own
        // retransmit). The receive side IS a proper byte stream though --
        // segments append and short reads consume partially -- because
        // ldn_mitm reassembles LAN packets itself and depends on that.
        constexpr u8 TCP_FIN = 0x01, TCP_SYN = 0x02, TCP_RST = 0x04, TCP_PSH = 0x08, TCP_ACK = 0x10;

        // VTcpConn/PendingAccept/MaxVTcpConns/MaxPendingAccepts/VTcpInboxCap
        // are declared in the header. The arrays themselves are a single
        // shared copy here -- NOT per-instance -- see the header's own
        // comment on BsdBridgeService for why (a per-instance copy was
        // tried and exhausted this sysmodule's heap the moment more than a
        // couple of processes were bridged at once). Access is gated by
        // ownership instead: BsdBridgeService::FindVTcpConnByFd/ByPeer/
        // AllocVTcpConn/IsOwnTcpListenFd (defined further down) all refuse
        // to touch these unless `this == g_active_ldn_instance`.
        VTcpConn g_vtcp_conns[MaxVTcpConns];
        s32 g_tcp_listen_fd = -1; // set once the owning instance Bind()+Listen()s its TCP socket on LdnControlPort (host role)
        PendingAccept g_pending_accepts[MaxPendingAccepts];
        s32 g_next_synthetic_fd = 1000; // real bsd:u fds never reach this high in this narrow use case

        ams::os::SdkMutex g_vtcp_mutex; // guards everything above

        // Same idea, for a real IPv4/TCP segment.
        bool ParseIpv4Tcp(const u8 *pkt, size_t pkt_len, u32 &out_src_ip, u16 &out_src_port, u16 &out_dst_port,
                u32 &out_seq, u32 &out_ack, u8 &out_flags, const u8 *&out_payload, size_t &out_payload_len) {
            if (pkt_len < 40) return false; // 20 (ip) + 20 (tcp, no options) minimum
            u8 ihl = (pkt[0] & 0x0F) * 4;
            if (pkt[9] != 6 || pkt_len < static_cast<size_t>(ihl) + 20) return false; // 6 = IPPROTO_TCP
            out_src_ip = (static_cast<u32>(pkt[12]) << 24) | (static_cast<u32>(pkt[13]) << 16) |
                         (static_cast<u32>(pkt[14]) << 8) | static_cast<u32>(pkt[15]);
            const u8 *tcp = pkt + ihl;
            out_src_port = static_cast<u16>((tcp[0] << 8) | tcp[1]);
            out_dst_port = static_cast<u16>((tcp[2] << 8) | tcp[3]);
            out_seq = (static_cast<u32>(tcp[4]) << 24) | (static_cast<u32>(tcp[5]) << 16) |
                      (static_cast<u32>(tcp[6]) << 8) | static_cast<u32>(tcp[7]);
            out_ack = (static_cast<u32>(tcp[8]) << 24) | (static_cast<u32>(tcp[9]) << 16) |
                      (static_cast<u32>(tcp[10]) << 8) | static_cast<u32>(tcp[11]);
            size_t data_offset = static_cast<size_t>(tcp[12] >> 4) * 4;
            out_flags = tcp[13];
            if (data_offset < 20 || static_cast<size_t>(ihl) + data_offset > pkt_len) return false;
            out_payload = tcp + data_offset;
            out_payload_len = pkt_len - ihl - data_offset;
            return true;
        }

        // Standard TCP checksum: 16-bit one's-complement sum over the pseudo
        // header (src ip, dst ip, zero, protocol, tcp length) followed by the
        // full segment (header + payload), with the segment's own checksum
        // field taken as zero for the purpose of this calculation.
        u16 TcpChecksum(u32 src_ip, u32 dst_ip, const u8 *seg, size_t seg_len) {
            u32 sum = 0;
            sum += (src_ip >> 16) & 0xFFFF; sum += src_ip & 0xFFFF;
            sum += (dst_ip >> 16) & 0xFFFF; sum += dst_ip & 0xFFFF;
            sum += 6; // protocol = TCP
            sum += static_cast<u32>(seg_len);
            size_t i = 0;
            for (; i + 1 < seg_len; i += 2) {
                sum += (static_cast<u32>(seg[i]) << 8) | seg[i + 1];
            }
            if (i < seg_len) {
                sum += static_cast<u32>(seg[i]) << 8;
            }
            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            return static_cast<u16>(~sum);
        }

        // Read-only, best-effort LDN packet recognition for diagnostics only
        // -- never used to make any routing/retransmit decision, so a
        // malformed/unrecognized header just logs nothing rather than
        // failing anything. Mirrors ldn_mitm's own LANPacketHeader (source/
        // lan_protocol.hpp): magic(u32) + type(u8) + compressed(u8) +
        // length(u16) + decompress_length(u16) + reserved(u8[2]) = 12 bytes,
        // immediately followed by `length` bytes of (possibly RLE-
        // compressed) payload. Assumes the whole header+payload lands in a
        // single TCP segment, true for every LDN control packet observed
        // tonight (Connect ~35B, SyncNetwork ~270-290B compressed, both well
        // under one segment) -- a split across segments just fails the
        // length check below and logs nothing, no different from an
        // unrecognized packet.
        constexpr u32 LanMagic = 0x11451400;
        const char *LdnPacketTypeName(u8 type) {
            switch (type) {
                case 0: return "Scan";
                case 1: return "ScanResp";
                case 2: return "Connect";
                case 3: return "SyncNetwork";
                default: return "?";
            }
        }
        void LogLdnPacketIfRecognized(const char *direction, const u8 *payload, size_t payload_len) {
            if (payload_len < 12) return;
            u32 magic = static_cast<u32>(payload[0]) | (static_cast<u32>(payload[1]) << 8) |
                        (static_cast<u32>(payload[2]) << 16) | (static_cast<u32>(payload[3]) << 24);
            if (magic != LanMagic) return;
            u8 type = payload[4];
            u8 compressed = payload[5];
            u16 length = static_cast<u16>(payload[6] | (payload[7] << 8));
            u16 decompress_length = static_cast<u16>(payload[8] | (payload[9] << 8));
            if (12u + length > payload_len) return; // truncated/split across segments -- skip
            LogFormat("BsdBridge: LDN %s type=%s len=%u compressed=%u decompress_len=%u",
                direction, LdnPacketTypeName(type), length, compressed, decompress_length);
        }

        // Temporary diagnostic: hex-dump the first bytes of UDP traffic on a
        // bridged socket that ISN'T ldn_mitm's own control channel (i.e. a
        // game's own gameplay socket, bridged via is_ldn_subnet_match). We
        // don't know what this traffic actually is yet (Pia session data,
        // something else entirely, or a port we shouldn't be bridging at
        // all) -- this exists purely to find out, not for any routing
        // decision. Capped at 64 bytes so it can't blow up the log.
        void LogNonControlUdpPayload(const char *direction, u16 local_port, const u8 *payload, size_t payload_len) {
            if (local_port == LdnControlPort) return;
            // LogFormat's own internal buffer is 256 bytes for the WHOLE
            // formatted line (source/debug.cpp: char buf[0x100]) -- the
            // earlier single-line version (up to 64 bytes -> 192 hex chars
            // plus a ~60-byte prefix) could exceed that and get silently
            // truncated mid-write, corrupting the log file itself (a stray
            // embedded NUL partway through a line, garbling whatever came
            // after it -- caught via `rg` reporting "binary file matches").
            // Cap raised to 224 bytes (comfortably covers every payload
            // size observed so far, up to 196B) and split into 16-byte
            // chunks per LogFormat call so no single call gets anywhere
            // near the buffer limit, regardless of total payload size.
            constexpr size_t MaxCapture = 224;
            constexpr size_t BytesPerLine = 16;
            size_t n = payload_len < MaxCapture ? payload_len : MaxCapture;
            LogFormat("BsdBridge: non-control UDP %s (local port %u) %zu bytes%s",
                direction, local_port, payload_len, payload_len > MaxCapture ? " (truncated for log)" : "");
            for (size_t off = 0; off < n; off += BytesPerLine) {
                size_t line_n = (n - off) < BytesPerLine ? (n - off) : BytesPerLine;
                char hex[BytesPerLine * 3 + 1];
                for (size_t i = 0; i < line_n; i++) {
                    std::snprintf(hex + i * 3, 4, "%02x ", payload[off + i]);
                }
                hex[line_n * 3 > 0 ? line_n * 3 - 1 : 0] = '\0';
                LogFormat("BsdBridge:   [%04zx] %s", off, hex);
            }
        }

        // Builds and sends one raw IPv4/TCP segment via the relay.
        ssize_t SendTcpSegment(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port,
                u32 seq, u32 ack, u8 flags, const void *payload, size_t payload_len) {
            u8 packet[20 + 20 + MaxBridgedPayload];
            size_t tcp_len = 20 + payload_len;
            size_t total = 20 + tcp_len;
            if (total > sizeof(packet)) return -1;

            u8 *ip = packet;
            ip[0] = 0x45; ip[1] = 0x00;
            ip[2] = static_cast<u8>(total >> 8); ip[3] = static_cast<u8>(total);
            ip[4] = 0; ip[5] = 0; ip[6] = 0; ip[7] = 0;
            ip[8] = 64; ip[9] = 6; ip[10] = 0; ip[11] = 0; // protocol = TCP
            ip[12] = static_cast<u8>(src_ip >> 24); ip[13] = static_cast<u8>(src_ip >> 16);
            ip[14] = static_cast<u8>(src_ip >> 8);  ip[15] = static_cast<u8>(src_ip);
            ip[16] = static_cast<u8>(dst_ip >> 24); ip[17] = static_cast<u8>(dst_ip >> 16);
            ip[18] = static_cast<u8>(dst_ip >> 8);  ip[19] = static_cast<u8>(dst_ip);

            u8 *tcp = packet + 20;
            tcp[0] = static_cast<u8>(src_port >> 8); tcp[1] = static_cast<u8>(src_port);
            tcp[2] = static_cast<u8>(dst_port >> 8); tcp[3] = static_cast<u8>(dst_port);
            tcp[4] = static_cast<u8>(seq >> 24); tcp[5] = static_cast<u8>(seq >> 16);
            tcp[6] = static_cast<u8>(seq >> 8);  tcp[7] = static_cast<u8>(seq);
            tcp[8] = static_cast<u8>(ack >> 24); tcp[9] = static_cast<u8>(ack >> 16);
            tcp[10] = static_cast<u8>(ack >> 8); tcp[11] = static_cast<u8>(ack);
            tcp[12] = 5 << 4; // data offset = 5 words (20 bytes), no options
            tcp[13] = flags;
            tcp[14] = 0x20; tcp[15] = 0x00; // window = 8192, arbitrary reasonable value
            tcp[16] = 0; tcp[17] = 0;       // checksum placeholder, filled below
            tcp[18] = 0; tcp[19] = 0;       // urgent pointer, unused
            if (payload_len > 0) std::memcpy(tcp + 20, payload, payload_len);

            u16 csum = TcpChecksum(src_ip, dst_ip, tcp, tcp_len);
            tcp[16] = static_cast<u8>(csum >> 8);
            tcp[17] = static_cast<u8>(csum);

            return g_relay.SendIpv4(packet, total);
        }

        u64 NowMs() {
            return ams::os::ConvertToTimeSpan(ams::os::GetSystemTick()).GetMilliSeconds();
        }

        // ldn_mitm's own budget for this whole exchange is a flat,
        // unconditional 1-second sleep (LANDiscovery::connect(),
        // lan_discovery.cpp) -- not a generous multi-second timeout like
        // originally assumed. 300ms/6 retries (up to 1.8s) was already
        // longer than that. Tightened to fit multiple attempts inside the
        // real budget instead of just one.
        constexpr u64 DataRetransmitIntervalMs = 100;
        constexpr int MaxDataRetransmits = 6; // up to 600ms of retrying

        // Pops everything currently sitting in the relay's raw queue and
        // files each UDP packet into g_control_queue (shared, port-tagged,
        // claimed later by whichever bridged instance's own port matches --
        // genuinely per-process now that a game's own gameplay socket can
        // be bridged too). TCP segments are always ldn_mitm's own LDN
        // station channel (LdnControlPort, checked below) and processed
        // straight away against the single shared vtcp state, gated by
        // ownership (g_active_ldn_instance) rather than claimed per-port --
        // see this file's own comment on BsdBridgeService for why that
        // state stays a single shared copy instead of being duplicated per
        // process. Instance-agnostic on purpose: called continuously from
        // the background drain thread, which has no specific
        // process/instance context at all.
        void DrainRawRelayQueue() {
            {
                BsdBridgeService *owner;
                {
                    std::scoped_lock lk(g_relay_mutex);
                    owner = g_active_ldn_instance;
                }
                if (owner != nullptr) {
                    std::scoped_lock lk(g_vtcp_mutex);
                    owner->CheckDataRetransmits(g_last_bridged_local_ip);
                }
            }
            u8 pkt[20 + 20 + MaxBridgedPayload];
            size_t pkt_len = 0;
            while (g_relay.PopIpv4(pkt, sizeof(pkt), &pkt_len) == 1) {
                if (pkt_len < 20) continue;
                u8 proto = pkt[9];

                if (proto == 17) { // UDP -- files into g_control_queue for
                                    // WHICHEVER bridged process's RecvFrom is
                                    // bound to this dst_port (ldn_mitm's own
                                    // control channel, or any other process's
                                    // gameplay socket -- no longer just
                                    // LdnControlPort, see this file's own
                                    // header comment).
                    u32 src_ip = 0; u16 dst_port = 0;
                    const u8 *payload = nullptr; size_t payload_len = 0;
                    if (!ParseIpv4Udp(pkt, pkt_len, src_ip, dst_port, payload, payload_len)) continue;
                    std::scoped_lock lk(g_control_queue_mutex);
                    if (g_control_count < ControlQueueSize) {
                        ControlPacket &slot = g_control_queue[g_control_count];
                        // Re-store the FULL raw packet (not just the payload) so
                        // the control RecvFrom path below can reuse the exact
                        // same parsing it always has.
                        size_t copy_len = pkt_len < sizeof(slot.data) ? pkt_len : sizeof(slot.data);
                        std::memcpy(slot.data, pkt, copy_len);
                        slot.len = copy_len;
                        slot.dst_port = dst_port;
                        g_control_count++;
                    }
                    continue;
                }

                if (proto != 6) continue; // not TCP either -- not ours, ignore

                u32 src_ip = 0; u16 src_port = 0, dst_port = 0;
                u32 seq = 0, ack = 0; u8 flags = 0;
                const u8 *payload = nullptr; size_t payload_len = 0;
                if (!ParseIpv4Tcp(pkt, pkt_len, src_ip, src_port, dst_port, seq, ack, flags, payload, payload_len)) continue;
                if (dst_port != LdnControlPort) continue; // ldn_mitm's TCP station channel is always this port -- see this file's own comment on why the shared vtcp state doesn't need per-instance claiming

                BsdBridgeService *owner;
                {
                    std::scoped_lock lk(g_relay_mutex);
                    owner = g_active_ldn_instance;
                }
                if (owner == nullptr) continue; // no owning instance right now -- drop

                std::scoped_lock lk(g_vtcp_mutex);
                owner->HandleTcpSegment(g_last_bridged_local_ip, src_ip, src_port, seq, ack, flags, payload, payload_len);
            }
        }
    }

    BsdBridgeService::~BsdBridgeService() {
        // Safety net alongside Close()'s own clearing below: whatever the
        // teardown path was, this instance must never be left as the
        // background drain thread's target once it's gone.
        {
            std::scoped_lock lk(g_relay_mutex);
            if (g_active_ldn_instance == this) g_active_ldn_instance = nullptr;
        }
        // Dummy-skip bookkeeping: this is a LIVE (intercepted, session #2+)
        // instance for its pid. When the last one closes, forget the pid and
        // re-arm the dummy-skip so the next burst (a fresh process id) skips
        // its new dummy first session the same way. See g_dummy_skip.
        {
            std::scoped_lock lk(g_dummy_skip_mutex);
            for (size_t i = 0; i < MaxDummySkipEntries; i++) {
                DummySkipEntry &e = g_dummy_skip[i];
                if (e.pid == m_client_info.process_id.value && e.live > 0) {
                    e.live--;
                    if (e.live == 0) { e.pid = 0; e.dummy_skipped = false; }
                    break;
                }
            }
        }
    }

    slp::RelayBridge &BsdBridgeService::GetRelay() { return g_relay; }

    void BsdBridgeService::TrackFd(s32 fd, s32 type) {
        if (fd < 0) return;
        for (size_t i = 0; i < MaxTrackedFds; i++) {
            if (m_tracked_fd[i] == -1 || m_tracked_fd[i] == fd) {
                m_tracked_fd[i] = fd;
                m_tracked_type[i] = type;
                return;
            }
        }
    }

    void BsdBridgeService::UntrackFd(s32 fd) {
        for (size_t i = 0; i < MaxTrackedFds; i++) {
            if (m_tracked_fd[i] == fd) m_tracked_fd[i] = -1;
        }
    }

    s32 BsdBridgeService::GetTrackedType(s32 fd) const {
        for (size_t i = 0; i < MaxTrackedFds; i++) {
            if (m_tracked_fd[i] == fd) return m_tracked_type[i];
        }
        return -1;
    }

    VTcpConn *BsdBridgeService::FindVTcpConnByFd(s32 fd) {
        if (this != g_active_ldn_instance) return nullptr; // not the verified owner of the shared vtcp state -- never match a coincidentally-equal fd from a different process
        for (auto &c : g_vtcp_conns) { if (c.used && c.fd == fd) return &c; }
        return nullptr;
    }
    // Matches by peer IP alone: ldn_mitm always uses port 11452 for both
    // sides of this channel, so a peer's IP alone is enough to tell its one
    // connection apart from every other peer's (host role can have several
    // stations, one per distinct console/peer IP).
    VTcpConn *BsdBridgeService::FindVTcpConnByPeer(u32 peer_ip) {
        if (this != g_active_ldn_instance) return nullptr;
        for (auto &c : g_vtcp_conns) { if (c.used && c.peer_ip == peer_ip) return &c; }
        return nullptr;
    }
    VTcpConn *BsdBridgeService::AllocVTcpConn() {
        if (this != g_active_ldn_instance) return nullptr;
        for (auto &c : g_vtcp_conns) {
            if (!c.used) {
                c = VTcpConn{};
                c.used = true;
                return &c;
            }
        }
        return nullptr;
    }

    bool BsdBridgeService::IsOwnTcpListenFd(s32 fd) const {
        return this == g_active_ldn_instance && fd == g_tcp_listen_fd;
    }

    namespace {
        // Defined earlier in this file (free functions): SendTcpSegment,
        // TCP_FIN/SYN/RST/PSH/ACK, LdnControlPort, VTcpInboxCap.
    }

    // Processes one already-parsed incoming TCP segment against THIS
    // instance's own vtcp state. Caller must hold g_vtcp_mutex. Factored
    // out of DrainRelay originally so the segment-classification switch
    // could just `return` instead of juggling `continue`/`goto` inside the
    // popping loop -- kept as its own method now that DrainRelay claims
    // segments from the shared queue instead of parsing them inline.
    void BsdBridgeService::HandleTcpSegment(u32 local_ip, u32 src_ip, u16 src_port,
            u32 seq, u32 ack, u8 flags, const u8 *payload, size_t payload_len) {
        const bool is_syn = (flags & TCP_SYN) != 0;
        const bool is_ack = (flags & TCP_ACK) != 0;
        const bool is_fin = (flags & TCP_FIN) != 0;
        const bool is_rst = (flags & TCP_RST) != 0;

        VTcpConn *c = FindVTcpConnByPeer(src_ip);

        if (is_rst) {
            if (c != nullptr) c->peer_closed = true;
            LogFormat("BsdBridge: TCP RST from 0x%08x:%u -- peer aborted the connection", src_ip, src_port);
            return;
        }

        if (is_syn && !is_ack) {
            // Incoming connection request (host role). Reply SYN-ACK
            // immediately -- like a real kernel's TCP stack, not deferred
            // to Accept(), which only ever dequeues an already-handshaked
            // connection.
            if (c != nullptr) return; // already connected to this peer -- stray/retransmitted SYN
            for (auto &p : g_pending_accepts) {
                if (p.used && p.peer_ip == src_ip) return; // already pending
            }
            PendingAccept *slot = nullptr;
            for (auto &p : g_pending_accepts) { if (!p.used) { slot = &p; break; } }
            if (slot == nullptr) {
                LogFormat("BsdBridge: TCP SYN from 0x%08x:%u -- no free accept slot, dropped", src_ip, src_port);
                return;
            }
            u32 our_isn = 0;
            ams::os::GenerateRandomBytes(std::addressof(our_isn), sizeof(our_isn));
            slot->used = true;
            slot->peer_ip = src_ip;
            slot->peer_port = src_port;
            slot->their_isn = seq;
            slot->our_isn = our_isn;
            slot->got_final_ack = false;
            SendTcpSegment(local_ip, src_ip, LdnControlPort, src_port,
                our_isn, seq + 1, TCP_SYN | TCP_ACK, nullptr, 0);
            LogFormat("BsdBridge: TCP SYN from 0x%08x:%u -- replied SYN-ACK", src_ip, src_port);
            return;
        }

        if (is_syn && is_ack) {
            // SYN-ACK reply to our own Connect() (client role): complete
            // the handshake right here (send the final ACK ourselves).
            if (c != nullptr && c->syn_sent_awaiting_synack && ack == c->our_isn + 1) {
                c->their_seq = seq + 1;
                c->our_seq = c->our_isn + 1;
                c->syn_sent_awaiting_synack = false;
                c->established = true;
                SendTcpSegment(local_ip, src_ip, LdnControlPort, src_port,
                    c->our_seq, c->their_seq, TCP_ACK, nullptr, 0);
                LogFormat("BsdBridge: TCP SYN-ACK from 0x%08x:%u -- handshake complete", src_ip, src_port);
            }
            return;
        }

        if (is_fin) {
            if (c != nullptr) {
                c->peer_closed = true;
                c->their_seq = seq + 1;
                SendTcpSegment(local_ip, src_ip, LdnControlPort, src_port,
                    c->our_seq, c->their_seq, TCP_ACK, nullptr, 0);
                LogFormat("BsdBridge: TCP FIN from 0x%08x:%u -- peer closed the connection", src_ip, src_port);
            }
            return;
        }

        if (!is_ack) return; // nothing meaningful left to handle (a bare data-less, flagless segment)

        // Final handshake ACK (host role)?
        for (auto &p : g_pending_accepts) {
            if (p.used && p.peer_ip == src_ip && !p.got_final_ack && ack == p.our_isn + 1) {
                p.got_final_ack = true;
                LogFormat("BsdBridge: TCP final ACK from 0x%08x:%u -- ready for Accept()", src_ip, src_port);
                return;
            }
        }

        // Our pending outbound data segment (if any) just got acked --
        // whether this is a bare ACK or one piggybacked on the peer's own
        // data. Stop retransmitting it. Must run before the
        // payload_len==0 early-return just below, since a bare ACK (no
        // data) is exactly the normal way a peer acks our send.
        if (c != nullptr && c->has_unacked_data &&
                ack == c->unacked_seq + static_cast<u32>(c->unacked_data_len)) {
            c->has_unacked_data = false;
        }

        // Otherwise, a data (or pure-ack) segment on an established connection.
        if (c == nullptr || !c->established || payload_len == 0) return;
        if (seq != c->their_seq) {
            // Out of order or a retransmit we've already applied -- drop.
            // A real peer's own retransmit timer will resend if this was
            // actually lost, no action needed on our side.
            return;
        }
        if (payload_len > VTcpInboxCap) {
            LogFormat("BsdBridge: TCP data from 0x%08x:%u len=%zu too big, dropped", src_ip, src_port, payload_len);
            return;
        }
        if (c->inbox_len + payload_len > VTcpInboxCap) {
            // No room left -- do NOT ack, so the peer's real TCP stack
            // retransmits once its timer fires (correct backpressure, not a
            // bug). Appending rather than holding a single segment means this
            // now only fires when ldn_mitm is genuinely behind, instead of on
            // every second segment of a back-to-back pair (a Switch's initial
            // RTO is ~200ms-1s with exponential backoff, and the join path
            // sends two SyncNetworks in quick succession -- Connect ->
            // updateNodes, then SetAdvertiseData -> updateNodes).
            return;
        }
        std::memcpy(c->inbox + c->inbox_len, payload, payload_len);
        c->inbox_len += payload_len;
        c->their_seq += static_cast<u32>(payload_len);
        SendTcpSegment(local_ip, src_ip, LdnControlPort, src_port,
            c->our_seq, c->their_seq, TCP_ACK, nullptr, 0);
        LogFormat("BsdBridge: TCP data from 0x%08x:%u len=%zu -> filed for fd=%d, acked",
            src_ip, src_port, payload_len, c->fd);
        LogLdnPacketIfRecognized("recv", payload, payload_len);
    }

    // Resends the shared vtcp state's established connections' unacked
    // outbound data segments past their retransmit interval. Caller must
    // hold g_vtcp_mutex. Only ever called on g_active_ldn_instance (see
    // DrainRawRelayQueue), so no separate ownership check needed here.
    void BsdBridgeService::CheckDataRetransmits(u32 local_ip) {
        u64 now = NowMs();
        for (auto &c : g_vtcp_conns) {
            if (!c.used || !c.established || !c.has_unacked_data) continue;
            if (now - c.last_send_tick_ms < DataRetransmitIntervalMs) continue;
            if (c.retransmit_count >= MaxDataRetransmits) {
                // Give up resending -- ldn_mitm's own higher-level timeout
                // will notice and tear the session down on its own; no
                // point flooding the relay forever.
                c.has_unacked_data = false;
                LogFormat("BsdBridge: TCP data to 0x%08x:%u -- gave up retransmitting after %d attempts",
                    c.peer_ip, c.peer_port, c.retransmit_count);
                continue;
            }
            c.retransmit_count++;
            c.last_send_tick_ms = now;
            SendTcpSegment(local_ip, c.peer_ip, LdnControlPort, c.peer_port,
                c.unacked_seq, c.their_seq, TCP_PSH | TCP_ACK, c.unacked_data, c.unacked_data_len);
            LogFormat("BsdBridge: TCP data to 0x%08x:%u len=%zu -- retransmit #%d (no ack yet)",
                c.peer_ip, c.peer_port, c.unacked_data_len, c.retransmit_count);
        }
    }

    // Drains the shared raw relay queue (instance-agnostic) and then claims
    // + processes any TCP segments and retransmit checks belonging to THIS
    // instance's own bridged port.
    void BsdBridgeService::DrainRelay() {
        // TCP-segment handling and retransmit-checking now happen directly
        // inside DrainRawRelayQueue itself (gated by ownership, not by
        // per-instance port-claiming -- see its own comment), so this just
        // needs to make sure the shared queues are freshly drained before
        // the caller checks its own readability.
        DrainRawRelayQueue();
    }

    bool BsdBridgeService::IsRelayConnected() {
        std::scoped_lock lk(g_relay_mutex);
        return g_relay.IsConnected();
    }

    // Shared with EnsureRelayConnected() below -- caller must hold g_relay_mutex.
    namespace {
        bool ConnectRelayLocked() {
            EnsureSocketStack(); // lazy: must precede the relay socket's ::socket()
            EnsureWatchdogStarted();
            EnsureDrainThreadStarted();
            g_relay_connect_attempted = true;

            char host[128];
            u16 port = 0;
            slpnx::cfg::GetRuntimeCfg().GetSelectedHostPort(host, sizeof(host), &port);

            Result rc = g_relay.Connect(host, port);
            LogFormat("BsdBridge: relay connect to %s:%u -> %s", host, port,
                R_SUCCEEDED(rc) ? "ok" : "FAILED");
            return R_SUCCEEDED(rc);
        }
    }

    void BsdBridgeService::ForceReconnect() {
        // Drop the current socket (if any) and reconnect RIGHT NOW against
        // whatever host/port is now selected in RuntimeCfg -- called from
        // slpnx::ipc::ConfigService::Reconnect (cfg/cfg_service.cpp), which
        // the overlay invokes right after SelectServer. Reconnects inline
        // rather than just clearing g_relay_connect_attempted and waiting
        // for the next bridged SendTo/RecvFrom: pressing Reconnect while
        // ldn_mitm is idle (no active scan/host) needs to take effect
        // immediately, not silently wait for other traffic to trigger it.
        std::scoped_lock lk(g_relay_mutex);
        g_relay_enabled = true; // Reconnect implies "on" even if Stop was pressed earlier
        g_relay.Close();
        g_relay_connect_attempted = false;
        g_last_bridge_activity_ms.store(0, std::memory_order_relaxed);
        ConnectRelayLocked();
    }

    void BsdBridgeService::Stop() {
        // Closes the relay and stops EnsureRelayConnected() from silently
        // reconnecting on the next bridged traffic -- Reconnect alone has
        // no way to express "stay off", so Start/Stop exist separately.
        std::scoped_lock lk(g_relay_mutex);
        g_relay_enabled = false;
        g_relay.Close();
        g_relay_connect_attempted = false;
        g_last_bridge_activity_ms.store(0, std::memory_order_relaxed);
        LogFormat("BsdBridge: Stop() -- relay disabled");
    }

    void BsdBridgeService::Start() {
        std::scoped_lock lk(g_relay_mutex);
        g_relay_enabled = true;
        if (!g_relay.IsConnected()) {
            g_relay_connect_attempted = false;
            ConnectRelayLocked();
        }
        LogFormat("BsdBridge: Start() -- relay enabled");
    }

    bool BsdBridgeService::IsRelayEnabled() {
        std::scoped_lock lk(g_relay_mutex);
        return g_relay_enabled;
    }

    u32 BsdBridgeService::GetLocalIp() {
        std::scoped_lock lk(g_relay_mutex);
        return g_last_bridged_local_ip;
    }

    u32 BsdBridgeService::GetRealIp() {
        std::scoped_lock lk(g_relay_mutex);
        EnsureSocketStack(); // lazy, same as ConnectRelayLocked -- safe to call repeatedly
        u32 real_ip = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&real_ip)) && real_ip != 0) {
            return ntohl(real_ip);
        }
        return 0;
    }

    bool BsdBridgeService::EnsureRelayConnected() {
        std::scoped_lock lk(g_relay_mutex);
        if (!g_relay_enabled) return false;
        if (g_relay.IsConnected()) return true;
        if (g_relay_connect_attempted) return false; // don't retry-storm every call
        return ConnectRelayLocked();
    }

    bool BsdBridgeService::ShouldMitm(const sm::MitmProcessInfo &client_info) {
        // The ldn_mitm control channel is only half the picture: a game's
        // own gameplay socket is a SEPARATE process (own program_id) that a
        // ldn_mitm-only ShouldMitm never sees, so its actual gameplay data
        // (Pia session, UDP 49152) silently falls into a real interface not
        // on the peer's network -- the lobby joins but the game never
        // renders the peer. Widening to (almost) everyone was tried twice
        // and each exposed a real bug (fixed below), but the crashes were
        // really from mitm'ing EVERY process -- qlaunch, background
        // sysmodules, the game, even homebrew-in-applet mode -- not from
        // mitm'ing the game.
        //
        // History of the two live incidents, both now fixed:
        //  Attempt 1 broke the FTP server: the vtcp connection-tracking
        //  state (g_vtcp_conns, g_tcp_listen_fd, g_pending_accepts, the
        //  fd-type-tracking tables) were file globals shared across every
        //  mitm'd process -- fds are a PER-PROCESS numbering space, so
        //  sys-ftpd's own fd numbers could collide with ldn_mitm's tracked
        //  ones, and Listen()/Connect() treated "any SOCK_STREAM fd" as
        //  virtual-TCP with no port check, hijacking every mitm'd process's
        //  real TCP. Fixed by moving the vtcp state onto the instance.
        //  Attempt 2 (per-instance) exhausted this sysmodule's heap: that
        //  state carries ~37KB, duplicated onto EVERY mitm'd process.
        //  Fixed by moving it back to a single shared copy gated by
        //  ownership (g_active_ldn_instance) instead of duplicated.
        //  With both fixed, real gameplay data bridged successfully for
        //  minutes at a time, confirmed live.
        //
        // The resolve: accept ldn_mitm's own control channel PLUs real
        // retail applications (not "everyone"), via
        // ams::ncm::IsApplicationId(). That is the same guard the
        // sys-slp-client project uses -- a hand-rolled 0x0100000000000000
        // floor is wrong (it's the start of FIRMWARE SYSMODULES, not
        // applications) and lets system applets (qlaunch, Album /
        // homebrew-in-applet) through; IsApplicationId enforces the real
        // application range 0x0100000000010000..0x01FFFFFFFFFFFFFF, so
        // MK8DX (0x0100152000022000) is in and every system/applet/homebrew
        // false positive is out. The per-fd Bind()/SendTo()/RecvFrom()
        // logic already scopes actual interception to sockets on the LDN
        // subnet, so a game's unrelated real internet traffic still passes
        // through untouched.
        constexpr u64 LdnMitmProgramId = 0x4200000000000010ULL;

        // ldn_mitm's own control channel is always bridged -- it has no dummy
        // session, and without it nothing else works.
        if (client_info.program_id.value == LdnMitmProgramId) {
            LogFormat("BsdBridge ShouldMitm: pid=%lu program_id=0x%016lx -> YES (ldn_mitm)",
                client_info.process_id.value, client_info.program_id.value);
            return true;
        }

        // Applications only -- system services, applets and homebrew are out
        // (see the comment above on why IsApplicationId, not a raw floor).
        if (!ams::ncm::IsApplicationId(client_info.program_id)) {
            LogFormat("BsdBridge ShouldMitm: pid=%lu program_id=0x%016lx -> no (not an application)",
                client_info.process_id.value, client_info.program_id.value);
            return false;
        }

        // Dummy-session skip (ported from sys-slp-client): a game opens a dummy
        // first bsd:u session that never calls RegisterClient and freezes/
        // aborts if intercepted -- closing its forward service unregistered is
        // a system freeze. So per pid-burst the FIRST session is forwarded
        // transparently (never constructed as a bridge service at all), and
        // only session #2+ is intercepted. The pid is forgotten again once all
        // its LIVE (intercepted) sessions close, so the next burst (e.g. WiFi
        // -> Finalize -> LAN) skips its fresh dummy again. See g_dummy_skip.
        u64 pid = client_info.process_id.value;

        DummySkipEntry *entry = nullptr;
        {
            std::scoped_lock lk(g_dummy_skip_mutex);
            for (size_t i = 0; i < MaxDummySkipEntries; i++) {
                if (g_dummy_skip[i].pid == pid) { entry = &g_dummy_skip[i]; break; }
                if (g_dummy_skip[i].pid == 0 && !g_dummy_skip[i].dummy_skipped && g_dummy_skip[i].live == 0 && entry == nullptr) {
                    entry = &g_dummy_skip[i]; // first free slot
                }
            }
            if (entry == nullptr) {
                LogFormat("BsdBridge ShouldMitm: pid=%lu program_id=0x%016lx -> no (dummy-skip table full)",
                    client_info.process_id.value, client_info.program_id.value);
                return false;
            }
            if (entry->pid == 0) entry->pid = pid; // claim this free slot for the first time

            if (!entry->dummy_skipped) {
                // First session of this burst: it's the dummy -- forward it
                // transparently, remember we did, and do NOT construct a
                // bridge service for it (so its forward service is never
                // closed unregistered).
                entry->dummy_skipped = true;
                LogFormat("BsdBridge ShouldMitm: pid=%lu program_id=0x%016lx -> no (dummy first session, forwarded transparently)",
                    client_info.process_id.value, client_info.program_id.value);
                return false;
            }

            // Real session (#2+): intercept it. Count it so the destructor can
            // forget the pid once the last live session closes (re-arming the
            // dummy-skip for the next burst).
            entry->live++;
        }

        LogFormat("BsdBridge ShouldMitm: pid=%lu program_id=0x%016lx -> YES (application, %u live)",
            client_info.process_id.value, client_info.program_id.value, entry->live);
        return true;
    }

    // ---- generic forwarding helpers ---------------------------------------

    namespace {
        // {ret, errno} pair, matching libnx's own _bsdDispatchImpl convention
        // (services/bsd.c): every bsd:u command replies with this exact
        // 8-byte struct first (ret at offset 0, errno at offset 4), with any
        // extra per-command output appended after. See the interface header
        // for why the Out<> declaration order (out_ret-ish field first, then
        // out_errno) has to match this, not just this struct's field order.
        struct RetErrno { s32 ret; s32 err; };
    }

    Result BsdBridgeService::RegisterClient(sf::Out<u64> out_result, const LibraryConfigData &config,
            const sf::ClientProcessId &client_pid, u64 tmem_size, sf::CopyHandle &&transfer_memory) {
        AMS_UNUSED(client_pid); // nnSdk's placeholder field, unused -- see override_pid below for the real pid forwarding
        struct {
            LibraryConfigData config;
            u64 pid_placeholder;
            u64 tmem_size;
        } in = { config, 0, tmem_size };
        u64 out = 0;
        // in_send_pid alone makes the KERNEL stamp OUR bridge process's own
        // real pid onto the forwarded request -- we're the one physically
        // sending it. That's wrong: the real bsd:u service needs to see
        // ldn_mitm's real pid, not ours, or its own per-client bookkeeping
        // (RegisterClient here, StartMonitoring right after) ends up
        // tracking the wrong process, which can lead to the real service
        // (or Atmosphere's mitm session plumbing) deciding to tear the
        // session down. override_pid is Atmosphere's own mechanism for a
        // mitm to forward the ORIGINAL client's pid (sf_mitm_dispatch.h:
        // only takes effect when in_send_pid is also set, and stamps the
        // TLS pid buffer with the 0xFFFE... prefix the patched kernel
        // accepts from a legitimate mitm).
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 0, in, out,
            .in_send_pid = true,
            .in_num_handles = 1,
            .in_handles = { transfer_memory.GetOsHandle() },
            .override_pid = m_client_info.process_id.value);
        out_result.SetValue(out);
        LogFormat("BsdBridge: RegisterClient(tmem_size=%lu) -> rc=0x%x result=%lu", tmem_size, rc.GetValue(), out);
        return rc;
    }

    Result BsdBridgeService::RegisterClientShared(sf::Out<u64> out_result, const LibraryConfigData &config,
            const sf::ClientProcessId &client_pid, u64 tmem_size) {
        AMS_UNUSED(client_pid);
        struct {
            LibraryConfigData config;
            u64 pid_placeholder;
            u64 tmem_size;
        } in = { config, 0, tmem_size };
        u64 out = 0;
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 33, in, out,
            .in_send_pid = true,
            .override_pid = m_client_info.process_id.value);
        out_result.SetValue(out);
        return rc;
    }

    // Cmd 1 StartMonitoring is intentionally not implemented here -- see
    // the interface header for why: it auto-forwards as raw, untouched
    // bytes via ForwardRequest, which is the only way to satisfy the SF
    // framework's own PrepareForProcess validation for this specific
    // command (declaring it ourselves, in any Out<>/ClientProcessId shape
    // tried, always ends up mismatched against what the real client's
    // wire message can hold).

    Result BsdBridgeService::Socket(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol) {
        struct { s32 domain, type, protocol; } in = { domain, type, protocol };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 2, in, out);
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        TrackFd(out.ret, type); // for Bind's UDP-vs-TCP discrimination
        LogFormat("BsdBridge: Socket(domain=%d type=%d proto=%d) -> fd=%d errno=%d",
            domain, type, protocol, out.ret, out.err);
        return rc;
    }

    Result BsdBridgeService::SocketExempt(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol) {
        struct { s32 domain, type, protocol; } in = { domain, type, protocol };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 3, in, out);
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        TrackFd(out.ret, type);
        return rc;
    }

    Result BsdBridgeService::Open(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 flags, const sf::InBuffer &path) {
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 4, flags, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { path.GetPointer(), path.GetSize() } });
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    bool BsdBridgeService::VFdHasPendingRead(s32 poll_fd) {
        if (poll_fd < 0) return false; // -1 = "ignored" poll slot; must never match an also-unset -1 tracked fd
        if (poll_fd == m_bridged_fd) {
            std::scoped_lock lk(g_control_queue_mutex);
            // g_control_queue is shared across every bridged process's UDP
            // socket now -- only report readable if something in there is
            // actually addressed to THIS instance's own port, not just "the
            // queue has something in it for someone".
            for (size_t i = 0; i < g_control_count; i++) {
                if (g_control_queue[i].dst_port == m_bridged_local_port) return true;
            }
            return false;
        }
        std::scoped_lock lk(g_vtcp_mutex);
        if (IsOwnTcpListenFd(poll_fd)) {
            // Only report readable once a connection is FULLY handshaked
            // (got_final_ack) -- accept() should never return before that,
            // matching real TCP semantics; a raw not-yet-ACKed SYN isn't
            // something Accept() can do anything with yet.
            for (auto &p : g_pending_accepts) if (p.used && p.got_final_ack) return true;
            return false;
        }
        VTcpConn *c = FindVTcpConnByFd(poll_fd); // nullptr if this instance doesn't own the shared vtcp state
        return c != nullptr && (c->inbox_len > 0 || c->peer_closed);
    }

    Result BsdBridgeService::Select(sf::Out<s32> out_count, sf::Out<s32> out_errno, const SelectInData &in_data,
            const sf::InAutoSelectBuffer &readfds_in, const sf::InAutoSelectBuffer &writefds_in,
            const sf::InAutoSelectBuffer &errorfds_in,
            sf::OutAutoSelectBuffer readfds_out, sf::OutAutoSelectBuffer writefds_out,
            sf::OutAutoSelectBuffer errorfds_out) {
        DrainRelay();

        // Same synthetic-fd problem as Poll (see its own comment): a
        // host-role accepted virtual connection's fd was never allocated by
        // the real bsd:u service, so it must never appear in a forwarded
        // readfds bitmask. Clear those bits before forwarding and answer
        // them ourselves afterward, mirroring the Poll fix. ldn_mitm itself
        // only ever uses ::poll (lan_protocol.cpp Pollable::Poll), not
        // ::select, so this path is untested against real traffic -- kept
        // correct anyway since some OTHER mitm'd process could still reach
        // it via the generic forward below for fds that aren't ours.
        constexpr s32 MaxSelectFds = 1024;
        const s32 nfds = in_data.nfds;
        const size_t nwords = (nfds > 0 && nfds <= MaxSelectFds) ? (static_cast<size_t>(nfds) + 31) / 32 : 0;
        const size_t nbytes = nwords * sizeof(u32);

        if (nwords == 0 || readfds_in.GetSize() < nbytes || readfds_out.GetSize() < nbytes) {
            // Unexpected shape -- forward unconditionally rather than risk
            // mishandling it ourselves.
            RetErrno out{};
            Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 5, in_data, out,
                .buffer_attrs = {
                    SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                    SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                    SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
                    SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
                .buffers = {
                    { readfds_in.GetPointer(), readfds_in.GetSize() }, { writefds_in.GetPointer(), writefds_in.GetSize() },
                    { errorfds_in.GetPointer(), errorfds_in.GetSize() },
                    { readfds_out.GetPointer(), readfds_out.GetSize() }, { writefds_out.GetPointer(), writefds_out.GetSize() },
                    { errorfds_out.GetPointer(), errorfds_out.GetSize() } });
            out_count.SetValue(out.ret);
            out_errno.SetValue(out.err);
            return rc;
        }

        u32 forward_readfds[MaxSelectFds / 32];
        const u32 *orig_readfds = reinterpret_cast<const u32 *>(readfds_in.GetPointer());
        std::memcpy(forward_readfds, orig_readfds, nbytes);

        // Clear any synthetic fd's bit before forwarding -- the trailing
        // inject() loop below answers for it afterward regardless (it
        // walks every used vtcp conn directly, not the caller's bitmask).
        for (s32 fd = 0; fd < nfds; fd++) {
            if (!(orig_readfds[fd / 32] & (1u << (fd % 32)))) continue;
            std::scoped_lock lk(g_vtcp_mutex);
            VTcpConn *c = FindVTcpConnByFd(fd);
            if (c != nullptr && c->fd >= 1000) {
                forward_readfds[fd / 32] &= ~(1u << (fd % 32)); // never forward
            }
        }

        SelectInData forward_in = in_data;
        {
            // Same fix as Poll() (see its own comment): don't block the
            // forwarded real select() for the caller's full timeout (or
            // indefinitely, if is_null) when we already know relay/virtual
            // data is sitting ready -- forward a zero, non-blocking timeout
            // instead so already-ready data isn't delayed behind a real
            // select() that has nothing of its own to report.
            bool any_pending = false;
            for (s32 fd = 0; fd < nfds && !any_pending; fd++) {
                any_pending = VFdHasPendingRead(fd);
            }
            if (any_pending) {
                forward_in.timeout = SelectTimeval{ .tv_sec = 0, .tv_usec = 0, .is_null = false };
            }
        }
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 5, forward_in, out,
            .buffer_attrs = {
                SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = {
                { forward_readfds, nbytes }, { writefds_in.GetPointer(), writefds_in.GetSize() },
                { errorfds_in.GetPointer(), errorfds_in.GetSize() },
                { readfds_out.GetPointer(), readfds_out.GetSize() }, { writefds_out.GetPointer(), writefds_out.GetSize() },
                { errorfds_out.GetPointer(), errorfds_out.GetSize() } });
        s32 count = out.ret;
        out_errno.SetValue(out.err);

        // Relay-readability injection, select()'s fd_set bit-mask form
        // (libnx fd_set: u32 words of NFDBITS=32) -- now covers the UDP
        // control fd, the virtual TCP listener, and every established
        // virtual TCP connection, not just the one control fd.
        auto inject = [&](s32 fd) {
            if (fd < 0 || !VFdHasPendingRead(fd)) return;
            if (readfds_out.GetSize() < (static_cast<size_t>(fd) / 32 + 1) * sizeof(u32)) return;
            u32 *words = reinterpret_cast<u32 *>(readfds_out.GetPointer());
            u32 &word = words[fd / 32];
            const u32 bit = 1u << (fd % 32);
            if (!(word & bit)) {
                word |= bit;
                if (count >= 0) count++;
            }
        };
        inject(m_bridged_fd);
        // The shared vtcp state (TCP listener + connections) only applies
        // to whichever instance actually owns it -- see this file's own
        // comment on BsdBridgeService for why that's a single shared copy
        // gated by ownership rather than a per-instance one.
        if (this == g_active_ldn_instance) {
            inject(g_tcp_listen_fd);
            for (auto &c : g_vtcp_conns) if (c.used) inject(c.fd);
        }

        out_count.SetValue(count);
        return rc;
    }

    Result BsdBridgeService::Poll(sf::Out<s32> out_count, sf::Out<s32> out_errno, const sf::InAutoSelectBuffer &fds_in,
            sf::OutAutoSelectBuffer fds_out, s32 nfds, s32 timeout) {
        DrainRelay();

        // Diagnostic: confirm what timeout the caller (ldn_mitm's own
        // loopPoll -> Pollable::Poll, default 100ms) is actually asking
        // for at this call site, rather than assuming it from source
        // reading -- a real multi-second gap here could mean either the
        // real forwarded poll() is legitimately slow despite a short
        // request, or the caller is genuinely asking for something longer
        // than expected.
        LogFormat("BsdBridge: Poll(nfds=%d, timeout=%d) called", nfds, timeout);

        // Host-role accepted virtual connections have a SYNTHETIC fd (see
        // Accept above) that the REAL bsd:u service has never heard of --
        // forwarding a poll request that names one is asking the real
        // service about an fd it never allocated, which silently corrupts
        // the Poll result for the whole batch (every other fd in the same
        // call comes back wrong too, not just the unknown one). Split the
        // polled set into real fds (forwarded normally) and ours (answered
        // entirely from VFdHasPendingRead, never sent to the real service
        // at all).
        constexpr s32 MaxPollFds = 32;
        if (nfds < 0 || static_cast<size_t>(nfds) > MaxPollFds ||
                fds_in.GetSize() < static_cast<size_t>(nfds) * sizeof(struct pollfd) ||
                fds_out.GetSize() < static_cast<size_t>(nfds) * sizeof(struct pollfd)) {
            // Unexpected shape -- forward unconditionally rather than risk
            // mishandling it ourselves.
            struct { s32 nfds, timeout; } in = { nfds, timeout };
            RetErrno out{};
            Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 6, in, out,
                .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
                .buffers = { { fds_in.GetPointer(), fds_in.GetSize() }, { fds_out.GetPointer(), fds_out.GetSize() } });
            out_count.SetValue(out.ret);
            out_errno.SetValue(out.err);
            return rc;
        }

        const struct pollfd *pfds_in = reinterpret_cast<const struct pollfd *>(fds_in.GetPointer());
        struct pollfd *pfds_out = reinterpret_cast<struct pollfd *>(fds_out.GetPointer());

        struct pollfd forward_in[MaxPollFds];
        struct pollfd forward_out[MaxPollFds]{};
        s32 forward_nfds = 0;
        s32 forward_index[MaxPollFds]; // forward_in[j] came from pfds_in[forward_index[j]]

        for (s32 i = 0; i < nfds; i++) {
            pfds_out[i].fd = pfds_in[i].fd;
            pfds_out[i].events = pfds_in[i].events;
            pfds_out[i].revents = 0;

            bool is_synthetic = false;
            {
                std::scoped_lock lk(g_vtcp_mutex);
                VTcpConn *c = FindVTcpConnByFd(pfds_in[i].fd);
                is_synthetic = (c != nullptr && c->fd >= 1000);
            }
            if (is_synthetic) continue; // answered entirely below, never forwarded

            forward_index[forward_nfds] = i;
            forward_in[forward_nfds] = pfds_in[i];
            forward_nfds++;
        }

        // If any polled fd (real or virtual/synthetic) already has relay
        // data waiting, don't block the forwarded real poll for the
        // caller's full timeout -- the real socket never sees relay
        // traffic, so a real poll() with e.g. a multi-second timeout would
        // sit there for its entire duration even though we already know
        // what to report, delaying delivery of already-ready data by up to
        // that whole timeout. Confirmed live: repeated multi-second
        // "Poll injected POLLIN" gaps (3.1s/4.8s/1.8s, stacking to ~10s)
        // right as ldn_mitm re-polled after a lobby exit, matching a
        // reported UI pause backing out of a lobby.
        bool any_pending = false;
        for (s32 i = 0; i < nfds && !any_pending; i++) {
            any_pending = VFdHasPendingRead(pfds_in[i].fd);
        }

        s32 count = 0;
        if (forward_nfds > 0) {
            struct { s32 nfds, timeout; } in = { forward_nfds, any_pending ? 0 : timeout };
            RetErrno out{};
            u64 dispatch_start_ms = NowMs();
            serviceMitmDispatchInOut(m_forward_service.get(), 6, in, out,
                .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
                .buffers = { { forward_in, sizeof(struct pollfd) * static_cast<size_t>(forward_nfds) },
                            { forward_out, sizeof(struct pollfd) * static_cast<size_t>(forward_nfds) } });
            u64 dispatch_ms = NowMs() - dispatch_start_ms;
            if (dispatch_ms > 500) {
                // The real forwarded poll() took far longer than the
                // any_pending-adjusted timeout we asked for -- points at
                // the real underlying bsd:u/network stack itself being
                // slow, not our own forwarding logic.
                LogFormat("BsdBridge: Poll real forward took %llums (asked timeout=%d, any_pending=%d, forward_nfds=%d)",
                    static_cast<unsigned long long>(dispatch_ms), in.timeout, any_pending ? 1 : 0, forward_nfds);
            }
            out_errno.SetValue(out.err);
            if (out.ret > 0) {
                for (s32 j = 0; j < forward_nfds; j++) {
                    u32 revents = forward_out[j].revents;
                    // ldn_mitm's own LDUdpSocket::onClose() has no retry/recovery --
                    // a transient local-interface hiccup (sleep, airplane mode, a
                    // brief WiFi drop) makes it latch a permanent SignalLost/Error
                    // state and spin on the dead fd forever, even though the
                    // interface (and our own relay connection underneath it) may
                    // recover seconds later. We never route this fd's actual data
                    // through the real socket anyway (SendTo/RecvFrom for it go
                    // through g_relay), so its real POLLERR/POLLHUP is not
                    // information ldn_mitm needs -- swallow it here instead of
                    // letting it trigger ldn_mitm's own unrecoverable error path.
                    // Scoped to only the bridged UDP control fd, not TCP virtual
                    // connections, where a real peer disconnect is genuine signal.
                    if (pfds_in[forward_index[j]].fd == m_bridged_fd && m_bridged_local_port == LdnControlPort) {
                        revents &= ~(POLLERR | POLLHUP | POLLNVAL);
                    }
                    pfds_out[forward_index[j]].revents = revents;
                    if (revents != 0) count++;
                }
            }
        } else {
            out_errno.SetValue(0);
        }

        // Poll interception: the real socket(s) never see relay traffic, so
        // without this ldn_mitm's worker (lan_protocol.cpp Pollable::Poll ->
        // onRead only on POLLIN) would never call RecvFrom/Accept even while
        // data sat waiting in our queues. For every polled fd that's one of
        // ours (the UDP control fd, the virtual TCP listener, or an
        // established virtual TCP connection, synthetic or not) and has
        // something pending, OR in POLLIN and fix up the returned count.
        for (s32 i = 0; i < nfds; i++) {
            if (pfds_out[i].revents & (POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL)) continue;
            if (!VFdHasPendingRead(pfds_out[i].fd)) continue;
            pfds_out[i].revents |= POLLIN;
            count++;
            LogFormat("BsdBridge: Poll injected POLLIN for fd=%d", pfds_out[i].fd);
        }

        out_count.SetValue(count);
        return ResultSuccess();
    }

    Result BsdBridgeService::Sysctl(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u64> out_oldlen,
            const sf::InBuffer &name, const sf::InBuffer &new_val, sf::OutBuffer old_val_out) {
        struct { s32 ret; s32 err; u64 oldlen; } out{};
        Result rc = serviceMitmDispatchOut(m_forward_service.get(), 7, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                              SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { name.GetPointer(), name.GetSize() }, { new_val.GetPointer(), new_val.GetSize() },
                        { old_val_out.GetPointer(), old_val_out.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        out_oldlen.SetValue(out.oldlen);
        return rc;
    }

    Result BsdBridgeService::Recv(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
            sf::OutAutoSelectBuffer buffer) {
        struct { s32 fd, flags; } in = { fd, flags };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 8, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { buffer.GetPointer(), buffer.GetSize() } });
        out_size.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    // ---- the bridged commands ----------------------------------------------

    Result BsdBridgeService::Bind(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr) {
        // Always forward the real Bind (harmless -- there's no real local
        // network for it to conflict with, and if the console's WiFi
        // interface happens to be usable this keeps ldn_mitm's own
        // real-network path alive as a bonus, not a replacement).
        struct { s32 fd; } in = { fd };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 13, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr.GetPointer(), addr.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);

        if (addr.GetSize() >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in sin;
            std::memcpy(&sin, addr.GetPointer(), sizeof(sin));
            u16 port = ntohs(sin.sin_port);
            bool is_udp = GetTrackedType(fd) == SOCK_DGRAM;
            if (port == LdnControlPort && !is_udp) {
                // ldn_mitm's OWN TCP station listener socket (separate fd
                // from its UDP control socket, same port number). Remember
                // this exact fd so Listen() can gate g_tcp_listen_fd on it
                // specifically -- see Listen()'s own comment for why that
                // gating matters (it's what keeps an unrelated process's
                // own real TCP listener from being hijacked).
                m_ldn_tcp_bind_fd = fd;
                LogFormat("BsdBridge: Bind fd=%d -> port %u but NOT UDP (tcp listener); forwarding only",
                    fd, port);
            }
            if (is_udp) {
                // Learn our own local IP the same way ldn_mitm itself would
                // see it (nifmGetCurrentIpAddress internally resolves the
                // same interface state GetSockName reads here) -- see the
                // header's own comment on why this must stay consistent
                // rather than inventing a separate address. Done for EVERY
                // UDP bind now (not just LdnControlPort) so a DIFFERENT
                // process's own gameplay socket can be recognized as
                // LDN-relevant by sharing this same address, below.
                u32 learned_ip = 0;
                u8 sockname_buf[sizeof(struct sockaddr_in)];
                RetErrno gsn_out{};
                Result gsn_rc = serviceMitmDispatchInOut(m_forward_service.get(), 16, in, gsn_out,
                    .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
                    .buffers = { { sockname_buf, sizeof(sockname_buf) } });
                if (R_SUCCEEDED(gsn_rc) && gsn_out.err == 0) {
                    struct sockaddr_in local_sin;
                    std::memcpy(&local_sin, sockname_buf, sizeof(local_sin));
                    learned_ip = ntohl(local_sin.sin_addr.s_addr);
                }

                // Fallback: with no associated WiFi interface GetSockName can
                // legitimately report 0.0.0.0; the relay routes replies by
                // the source IP we embed in each packet, so a zero source
                // would make every response unroutable. nifm knows our real
                // address even when the raw socket view doesn't -- and since
                // every bridged process shares the SAME nifm interface, this
                // fallback is also what makes a game's own socket resolve to
                // the identical address ldn_mitm's own control channel used,
                // even if ITS GetSockName also comes back zero.
                if (learned_ip == 0) {
                    u32 nifm_ip = 0;
                    EnsureSocketStack(); // nifmGetCurrentIpAddress needs nifm initialized
                    if (R_SUCCEEDED(nifmGetCurrentIpAddress(&nifm_ip)) && nifm_ip != 0) {
                        learned_ip = ntohl(nifm_ip);
                        LogFormat("BsdBridge: GetSockName gave 0.0.0.0, using nifm ip instead");
                    }
                }

                // Bridge-worthy if this is ldn_mitm's own known control
                // port (the original, still-needed case -- this is also
                // what FIRST establishes g_last_bridged_local_ip each
                // session, before any other process could possibly match
                // it), OR this socket's own address matches the LDN virtual
                // subnet another process already established -- i.e. a
                // game's own gameplay socket, bound to the SAME
                // nifm-assigned address LDN is using. Everything else
                // (unrelated real internet traffic from any process) falls
                // through untouched.
                u32 established_ip;
                {
                    std::scoped_lock lk(g_relay_mutex);
                    established_ip = g_last_bridged_local_ip;
                }
                bool is_ldn_control_port = (port == LdnControlPort);
                bool is_ldn_subnet_match = (established_ip != 0 && learned_ip == established_ip);

                if (is_ldn_control_port || is_ldn_subnet_match) {
                    m_bridged_fd = fd;
                    m_bridged_local_ip = learned_ip;
                    m_bridged_local_port = port;
                    LogFormat("BsdBridge: Bind fd=%d -> port %u (%s), bridging this socket to the relay, local ip = 0x%08x",
                        fd, port, is_ldn_control_port ? "ldn_mitm control port" : "matches LDN subnet",
                        m_bridged_local_ip);

                    {
                        std::scoped_lock lk(g_relay_mutex);
                        g_last_bridged_local_ip = m_bridged_local_ip;
                        g_bridged_socket_count++;
                        // See g_active_ldn_instance's own comment -- only
                        // ever set for a socket verified to actually be
                        // ldn_mitm's own control channel, never for a
                        // subnet-matched OTHER process's own socket.
                        if (is_ldn_control_port) g_active_ldn_instance = this;
                    }

                    EnsureRelayConnected();
                }
            }
        }
        return rc;
    }

    Result BsdBridgeService::SendTo(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
            const sf::InAutoSelectBuffer &buffer, const sf::InAutoSelectBuffer &addr) {
        // ldn_mitm's TCP "station" socket also goes through SendTo (see
        // TcpLanSocketBase::sendto -- ::sendto(fd,buf,len,0,nullptr,0), addr
        // always empty since it's a connected socket). Route it into the
        // virtual-TCP tunnel instead of falling through to the UDP path
        // below or the generic forward above.
        {
            std::scoped_lock lk(g_vtcp_mutex);
            VTcpConn *c = FindVTcpConnByFd(fd);
            if (c != nullptr) {
                if (!c->established || !EnsureRelayConnected()) {
                    out_errno.SetValue(EIO);
                    out_size.SetValue(-1);
                    return ResultSuccess();
                }
                const size_t payload_len = buffer.GetSize();
                if (payload_len > VTcpInboxCap) {
                    out_errno.SetValue(EMSGSIZE);
                    out_size.SetValue(-1);
                    return ResultSuccess();
                }
                // Real TCP data segment: PSH|ACK, our current seq/ack.
                // Recorded into unacked_data so CheckDataRetransmits (called
                // from DrainRelay) resends it if no ack shows up in time --
                // the relay's own transport is unreliable UDP, and this used
                // to be genuinely fire-and-forget, which is what let a
                // single dropped join/SyncNetwork packet turn into a
                // "communication error" with no recovery.
                ssize_t sent = SendTcpSegment(m_bridged_local_ip, c->peer_ip, LdnControlPort, c->peer_port,
                    c->our_seq, c->their_seq, TCP_PSH | TCP_ACK, buffer.GetPointer(), payload_len);
                LogFormat("BsdBridge: SendTo(tcp fd=%d, %zu bytes -> peer 0x%08x:%u seq=%u) relay_sent=%zd",
                    fd, payload_len, c->peer_ip, c->peer_port, c->our_seq, sent);
                LogLdnPacketIfRecognized("send", static_cast<const u8 *>(buffer.GetPointer()), payload_len);
                if (sent >= 0) {
                    c->has_unacked_data = true;
                    std::memcpy(c->unacked_data, buffer.GetPointer(), payload_len);
                    c->unacked_data_len = payload_len;
                    c->unacked_seq = c->our_seq;
                    c->last_send_tick_ms = NowMs();
                    c->retransmit_count = 0;
                    c->our_seq += static_cast<u32>(payload_len);
                }
                TouchBridgeActivity();
                out_errno.SetValue(sent >= 0 ? 0 : EIO);
                out_size.SetValue(sent >= 0 ? static_cast<s32>(payload_len) : -1);
                return ResultSuccess();
            }
        }

        if (!IsBridged(fd)) {
            struct { s32 fd, flags; } in = { fd, flags };
            RetErrno out{};
            Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 11, in, out,
                .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
                .buffers = { { buffer.GetPointer(), buffer.GetSize() }, { addr.GetPointer(), addr.GetSize() } });
            out_size.SetValue(out.ret);
            out_errno.SetValue(out.err);
            return rc;
        }

        // Bridged socket: build a raw IPv4+UDP packet matching what a real
        // local broadcast/unicast would look like on the wire, and hand it
        // to the relay bridge -- never touching the real (nonexistent)
        // local network for this socket.
        if (!EnsureRelayConnected()) {
            out_errno.SetValue(EIO);
            out_size.SetValue(-1);
            return ResultSuccess();
        }

        struct sockaddr_in dst_sin{};
        if (addr.GetSize() >= sizeof(dst_sin)) {
            std::memcpy(&dst_sin, addr.GetPointer(), sizeof(dst_sin));
        }
        u32 dst_ip = ntohl(dst_sin.sin_addr.s_addr);
        u16 dst_port = ntohs(dst_sin.sin_port);

        const size_t payload_len = buffer.GetSize();
        u8 packet[20 + 8 + MaxBridgedPayload];
        size_t total = 20 + 8 + payload_len;
        if (total > sizeof(packet)) {
            out_errno.SetValue(EMSGSIZE);
            out_size.SetValue(-1);
            return ResultSuccess();
        }

        u8 *ip = packet;
        ip[0] = 0x45; ip[1] = 0x00;
        ip[2] = static_cast<u8>(total >> 8); ip[3] = static_cast<u8>(total);
        ip[4] = 0; ip[5] = 0; ip[6] = 0; ip[7] = 0;
        ip[8] = 64; ip[9] = 17; ip[10] = 0; ip[11] = 0;
        ip[12] = static_cast<u8>(m_bridged_local_ip >> 24); ip[13] = static_cast<u8>(m_bridged_local_ip >> 16);
        ip[14] = static_cast<u8>(m_bridged_local_ip >> 8);  ip[15] = static_cast<u8>(m_bridged_local_ip);
        ip[16] = static_cast<u8>(dst_ip >> 24); ip[17] = static_cast<u8>(dst_ip >> 16);
        ip[18] = static_cast<u8>(dst_ip >> 8);  ip[19] = static_cast<u8>(dst_ip);

        u8 *udp = packet + 20;
        u16 udp_len = static_cast<u16>(8 + payload_len);
        // Source port must be THIS instance's own bound port, not always
        // LdnControlPort -- true for ldn_mitm's own control channel, but a
        // game's own gameplay socket is bound to some other port, and
        // stamping the wrong source port here would make the peer's own
        // reply come back addressed to a port nobody's listening on.
        udp[0] = static_cast<u8>(m_bridged_local_port >> 8); udp[1] = static_cast<u8>(m_bridged_local_port);
        udp[2] = static_cast<u8>(dst_port >> 8); udp[3] = static_cast<u8>(dst_port);
        udp[4] = static_cast<u8>(udp_len >> 8); udp[5] = static_cast<u8>(udp_len);
        udp[6] = 0; udp[7] = 0;
        std::memcpy(packet + 28, buffer.GetPointer(), payload_len);

        ssize_t sent = GetRelay().SendIpv4(packet, total);
        LogFormat("BsdBridge: SendTo(bridged fd=%d, %zu bytes -> dst 0x%08x:%u) relay_sent=%zd",
            fd, payload_len, dst_ip, dst_port, sent);
        LogNonControlUdpPayload("send", m_bridged_local_port,
            static_cast<const u8 *>(buffer.GetPointer()), payload_len);
        TouchBridgeActivity();

        out_errno.SetValue(sent >= 0 ? 0 : EIO);
        out_size.SetValue(sent >= 0 ? static_cast<s32>(payload_len) : -1);
        return ResultSuccess();
    }

    Result BsdBridgeService::RecvFrom(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd,
            s32 flags, sf::OutAutoSelectBuffer buffer, sf::OutAutoSelectBuffer addr_out) {
        DrainRelay();

        // Virtual-TCP fd (ldn_mitm's LDN station socket -- see SendTo above).
        {
            std::scoped_lock lk(g_vtcp_mutex);
            VTcpConn *c = FindVTcpConnByFd(fd);
            if (c != nullptr) {
                if (c->inbox_len == 0) {
                    if (c->peer_closed) {
                        LogFormat("BsdBridge: RecvFrom(tcp fd=%d) -- delivering EOF (peer_closed) to ldn_mitm", fd);
                    }
                    out_ret.SetValue(c->peer_closed ? 0 : -1);
                    out_errno.SetValue(c->peer_closed ? 0 : EWOULDBLOCK);
                    out_addrlen.SetValue(0);
                    return ResultSuccess();
                }
                size_t deliver = c->inbox_len;
                if (deliver > buffer.GetSize()) deliver = buffer.GetSize();
                std::memcpy(buffer.GetPointer(), c->inbox, deliver);
                // Keep whatever didn't fit. ldn_mitm asks for only
                // sizeof(buffer) - recvSize bytes while it holds a partial
                // packet (LanSocket::recvPartPacket), which happens as soon as
                // the peer's own stack coalesces two LAN packets into one
                // segment -- so a short read here is normal, and dropping the
                // tail would silently desync its stream rather than error.
                c->inbox_len -= deliver;
                if (c->inbox_len > 0) {
                    std::memmove(c->inbox, c->inbox + deliver, c->inbox_len);
                }

                struct sockaddr_in src_sin{};
                src_sin.sin_family = AF_INET;
                src_sin.sin_port = htons(c->peer_port);
                src_sin.sin_addr.s_addr = htonl(c->peer_ip);
                size_t addrlen = (addr_out.GetSize() < sizeof(src_sin)) ? addr_out.GetSize() : sizeof(src_sin);
                std::memcpy(addr_out.GetPointer(), &src_sin, addrlen);

                LogFormat("BsdBridge: RecvFrom(tcp fd=%d) delivered %zu bytes from 0x%08x:%u", fd, deliver, c->peer_ip, c->peer_port);
                TouchBridgeActivity();
                out_ret.SetValue(static_cast<s32>(deliver));
                out_errno.SetValue(0);
                out_addrlen.SetValue(static_cast<u32>(addrlen));
                return ResultSuccess();
            }
        }

        if (!IsBridged(fd)) {
            struct { s32 fd, flags; } in = { fd, flags };
            struct { s32 ret; s32 err; u32 addrlen; } out{};
            Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 9, in, out,
                .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
                .buffers = { { buffer.GetPointer(), buffer.GetSize() }, { addr_out.GetPointer(), addr_out.GetSize() } });
            out_ret.SetValue(out.ret);
            out_errno.SetValue(out.err);
            out_addrlen.SetValue(out.addrlen);
            return rc;
        }

        // Deliver one packet from g_control_queue (filed by DrainRelay above,
        // which is now the only caller of GetRelay().PopIpv4() -- see its own
        // comment for why RecvFrom no longer pops the shared relay queue
        // directly). Shared across every bridged process's UDP socket now,
        // so pull specifically the first entry addressed to THIS instance's
        // own bound port -- see PopControlPacketForPort's own comment.
        u8 ip_packet[20 + 8 + MaxBridgedPayload];
        size_t ip_len = 0;
        {
            std::scoped_lock lk(g_control_queue_mutex);
            ControlPacket pkt;
            if (!PopControlPacketForPort(m_bridged_local_port, pkt)) {
                out_ret.SetValue(-1);
                out_errno.SetValue(EWOULDBLOCK);
                out_addrlen.SetValue(0);
                return ResultSuccess();
            }
            ip_len = pkt.len < sizeof(ip_packet) ? pkt.len : sizeof(ip_packet);
            std::memcpy(ip_packet, pkt.data, ip_len);
        }

        u32 src_ip = 0; u16 dst_port_unused = 0;
        const u8 *payload = nullptr; size_t payload_len = 0;
        if (!ParseIpv4Udp(ip_packet, ip_len, src_ip, dst_port_unused, payload, payload_len)) {
            out_ret.SetValue(-1);
            out_errno.SetValue(EWOULDBLOCK);
            out_addrlen.SetValue(0);
            return ResultSuccess();
        }
        u8 ihl = (ip_packet[0] & 0x0F) * 4;
        const u8 *udp = ip_packet + ihl;
        u16 src_port = static_cast<u16>((udp[0] << 8) | udp[1]);
        if (payload_len > buffer.GetSize()) payload_len = buffer.GetSize();

        std::memcpy(buffer.GetPointer(), payload, payload_len);

        struct sockaddr_in src_sin{};
        src_sin.sin_family = AF_INET;
        src_sin.sin_port = htons(src_port);
        src_sin.sin_addr.s_addr = htonl(src_ip);
        size_t addrlen = (addr_out.GetSize() < sizeof(src_sin)) ? addr_out.GetSize() : sizeof(src_sin);
        std::memcpy(addr_out.GetPointer(), &src_sin, addrlen);

        LogFormat("BsdBridge: RecvFrom(bridged fd=%d) delivered %zu bytes from relay (src 0x%08x:%u)",
            fd, payload_len, src_ip, src_port);
        LogNonControlUdpPayload("recv", m_bridged_local_port,
            static_cast<const u8 *>(buffer.GetPointer()), payload_len);
        TouchBridgeActivity();

        out_ret.SetValue(static_cast<s32>(payload_len));
        out_errno.SetValue(0);
        out_addrlen.SetValue(static_cast<u32>(addrlen));
        return ResultSuccess();
    }

    Result BsdBridgeService::Close(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd) {
        // Host-role accepted virtual connections have a SYNTHETIC fd (see
        // Accept below) that was never a real bsd:u fd -- forwarding Close
        // for one to the real service would close whatever unrelated real fd
        // happens to share that number. Everything else (the UDP control fd,
        // the TCP listener fd, and a client-role virtual connection, which
        // reuses the REAL fd from its own Socket() call) still has a genuine
        // real fd behind it and should still be closed for real.
        bool is_synthetic = false;
        {
            std::scoped_lock lk(g_vtcp_mutex);
            VTcpConn *c = FindVTcpConnByFd(fd);
            if (c != nullptr) {
                is_synthetic = (c->fd >= 1000);
                if (c->established) {
                    SendTcpSegment(m_bridged_local_ip, c->peer_ip, LdnControlPort, c->peer_port,
                        c->our_seq, c->their_seq, TCP_FIN | TCP_ACK, nullptr, 0);
                }
                LogFormat("BsdBridge: Close(tcp fd=%d) -- tearing down connection to 0x%08x:%u",
                    fd, c->peer_ip, c->peer_port);
                *c = VTcpConn{};
            }
            if (IsOwnTcpListenFd(fd)) {
                g_tcp_listen_fd = -1;
                LogFormat("BsdBridge: Close(fd=%d) -- was the virtual TCP listener", fd);
            }
        }

        if (is_synthetic) {
            UntrackFd(fd);
            out_ret.SetValue(0);
            out_errno.SetValue(0);
            return ResultSuccess();
        }

        struct { s32 fd; } in = { fd };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 26, in, out);
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        UntrackFd(fd);
        if (IsBridged(fd)) {
            LogFormat("BsdBridge: Close(fd=%d) -- unbridging (was the relay-bridged socket)", fd);
            bool was_ldn_control_port = (m_bridged_local_port == LdnControlPort);
            m_bridged_fd = -1;
            m_bridged_local_ip = 0;
            m_bridged_local_port = 0;

            // Tear down the relay connection too, but only once the LAST
            // bridged socket across every process closes -- g_relay is a
            // single global singleton now shared by ldn_mitm's own control
            // channel AND any other process's own gameplay socket (see
            // this file's own header comment), so closing it on the FIRST
            // one to go away would yank the tunnel out from under whichever
            // one is still active. Without eventually closing it at all,
            // it would outlive the LDN session entirely, so a stale/dead
            // connection (relay restarted, PC slept and its NAT mapping
            // expired, etc.) gets silently REUSED by the next game's
            // session instead of reconnecting fresh, leaving "connected"
            // stuck in the overlay and every subsequent join failing with
            // a communication error until a full reboot. Closing once
            // count hits zero means the next EnsureRelayConnected() (from
            // whatever LDN session comes next) always dials a brand new
            // connection.
            std::scoped_lock relay_lk(g_relay_mutex);
            if (was_ldn_control_port && g_active_ldn_instance == this) g_active_ldn_instance = nullptr;
            if (g_bridged_socket_count > 0) g_bridged_socket_count--;
            if (g_bridged_socket_count == 0) {
                g_relay.Close();
                g_relay_connect_attempted = false;
                g_last_bridged_local_ip = 0;
                g_last_bridge_activity_ms.store(0, std::memory_order_relaxed);
            }
        }
        return rc;
    }

    // ---- remaining generic forwards -----------------------------------------

    Result BsdBridgeService::Send(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
            const sf::InAutoSelectBuffer &buffer) {
        struct { s32 fd, flags; } in = { fd, flags };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 10, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { buffer.GetPointer(), buffer.GetSize() } });
        out_size.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::Accept(sf::Out<s32> out_fd, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
        // Host role: ldn_mitm's real accept() on its (never actually bound to
        // anything real) TCP listener would just fail forever, since nothing
        // reaches the real local network for this project. Answer it
        // ourselves instead -- the SYN-ACK and handshake tracking already
        // happened in DrainRelay/HandleTcpSegment (matching a real kernel's
        // TCP stack: accept() only ever DEQUEUES an already-handshaked
        // connection, it doesn't drive the handshake), so this just needs to
        // find a got_final_ack pending accept and turn it into a real fd.
        if (IsOwnTcpListenFd(fd)) {
            DrainRelay();
            std::scoped_lock lk(g_vtcp_mutex);
            for (auto &p : g_pending_accepts) {
                if (!p.used || !p.got_final_ack) continue;
                VTcpConn *c = AllocVTcpConn();
                if (c == nullptr) {
                    // No free slot (StationCountMax-ish limit reached) -- leave
                    // it pending; matches ldn_mitm's own "no free station"
                    // rejection (LANDiscovery::onConnect), just deferred
                    // instead of immediately closing.
                    continue;
                }
                p.used = false;
                c->fd = g_next_synthetic_fd++;
                c->established = true;
                c->peer_ip = p.peer_ip;
                c->peer_port = p.peer_port;
                c->our_seq = p.our_isn + 1;
                c->their_seq = p.their_isn + 1;
                TrackFd(c->fd, SOCK_STREAM);

                struct sockaddr_in peer_sin{};
                peer_sin.sin_family = AF_INET;
                peer_sin.sin_port = htons(c->peer_port);
                peer_sin.sin_addr.s_addr = htonl(c->peer_ip);
                size_t addrlen = (addr_out.GetSize() < sizeof(peer_sin)) ? addr_out.GetSize() : sizeof(peer_sin);
                std::memcpy(addr_out.GetPointer(), &peer_sin, addrlen);

                LogFormat("BsdBridge: Accept(tcp listener fd=%d) -> new fd=%d peer=0x%08x:%u",
                    fd, c->fd, c->peer_ip, c->peer_port);
                out_fd.SetValue(c->fd);
                out_errno.SetValue(0);
                out_addrlen.SetValue(static_cast<u32>(addrlen));
                return ResultSuccess();
            }
            out_fd.SetValue(-1);
            out_errno.SetValue(EWOULDBLOCK);
            out_addrlen.SetValue(0);
            return ResultSuccess();
        }

        struct { s32 fd; } in = { fd };
        struct { s32 ret; s32 err; u32 addrlen; } out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 12, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr_out.GetPointer(), addr_out.GetSize() } });
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        out_addrlen.SetValue(out.addrlen);
        return rc;
    }

    Result BsdBridgeService::Connect(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr) {
        // Parsed up front now, regardless of type, so the branch below can
        // gate on the ACTUAL destination, not just "is this a TCP socket".
        struct sockaddr_in dst_sin{};
        if (addr.GetSize() >= sizeof(dst_sin)) {
            std::memcpy(&dst_sin, addr.GetPointer(), sizeof(dst_sin));
        }
        u32 dst_ip = ntohl(dst_sin.sin_addr.s_addr);
        u16 dst_port = ntohs(dst_sin.sin_port);

        // Only ldn_mitm's own LDN station channel ever needs the virtual
        // connect below -- gated on BOTH being a TCP socket AND actually
        // targeting LdnControlPort, not just "any SOCK_STREAM socket's
        // connect() call" (that used to hijack ANY outbound TCP connect
        // from ANY mitm'd process once ShouldMitm covered more than
        // ldn_mitm -- a real connect() to a real destination would have
        // been silently rerouted through the relay instead of actually
        // reaching it). Everything else falls through to the real forward
        // below, same as always.
        if (GetTrackedType(fd) == SOCK_STREAM && dst_port == LdnControlPort) {
            // Client role: ldn_mitm's own LANDiscovery::connect()
            // (lan_discovery.cpp) does a single synchronous ::connect() on
            // this fd -- the LDN station channel -- to the discovered
            // host's ipv4Address:11452. Drive a real TCP 3-way handshake
            // (genuine SYN, real seq/ack, real checksums) over the relay and
            // block (matching ldn_mitm's own synchronous usage -- its
            // worker thread makes no other bsd:u calls while waiting on
            // this one, so blocking this single dispatch thread costs no
            // real concurrency) until it completes or we give up.
            if (!EnsureRelayConnected()) {
                out_ret.SetValue(-1);
                out_errno.SetValue(EIO);
                return ResultSuccess();
            }

            u32 our_isn = 0;
            ams::os::GenerateRandomBytes(std::addressof(our_isn), sizeof(our_isn));

            {
                std::scoped_lock lk(g_vtcp_mutex);
                VTcpConn *c = AllocVTcpConn();
                if (c == nullptr) {
                    out_ret.SetValue(-1);
                    out_errno.SetValue(ENOBUFS);
                    return ResultSuccess();
                }
                c->fd = fd;
                c->peer_ip = dst_ip;
                c->peer_port = dst_port;
                c->our_isn = our_isn;
                c->syn_sent_awaiting_synack = true;
            }

            LogFormat("BsdBridge: Connect(tcp fd=%d) -> dst 0x%08x:%u isn=%u, sending SYN",
                fd, dst_ip, dst_port, our_isn);

            // Retry the SYN a few times in case the first is dropped by the
            // relay's own unreliable UDP transport (see relay_bridge.hpp);
            // ~3s total before giving up, comfortably under however long the
            // game itself waits for a failed join. The final ACK completing
            // the handshake is sent by HandleTcpSegment as soon as it sees
            // the SYN-ACK (it has g_last_bridged_local_ip available), not
            // here -- this loop just waits for `established` to flip.
            constexpr int MaxAttempts = 6;
            constexpr int RetryIntervalMs = 500;
            bool established = false;
            for (int attempt = 0; attempt < MaxAttempts && !established; attempt++) {
                SendTcpSegment(m_bridged_local_ip, dst_ip, LdnControlPort, dst_port,
                    our_isn, 0, TCP_SYN, nullptr, 0);
                for (int waited = 0; waited < RetryIntervalMs; waited += 20) {
                    os::SleepThread(TimeSpan::FromMilliSeconds(20));
                    DrainRelay();
                    std::scoped_lock lk(g_vtcp_mutex);
                    VTcpConn *c = FindVTcpConnByFd(fd);
                    if (c != nullptr && c->established) { established = true; break; }
                }
            }

            if (!established) {
                std::scoped_lock lk(g_vtcp_mutex);
                VTcpConn *c = FindVTcpConnByFd(fd);
                if (c != nullptr) *c = VTcpConn{};
                LogFormat("BsdBridge: Connect(tcp fd=%d) -> TIMED OUT waiting for SYN-ACK", fd);
                out_ret.SetValue(-1);
                out_errno.SetValue(ETIMEDOUT);
                return ResultSuccess();
            }

            LogFormat("BsdBridge: Connect(tcp fd=%d) -> established with 0x%08x:%u", fd, dst_ip, dst_port);
            out_ret.SetValue(0);
            out_errno.SetValue(0);
            return ResultSuccess();
        }

        struct { s32 fd; } in = { fd };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 14, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr.GetPointer(), addr.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::GetPeerName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
        struct { s32 fd; } in = { fd };
        struct { s32 ret; s32 err; u32 addrlen; } out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 15, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr_out.GetPointer(), addr_out.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        out_addrlen.SetValue(out.addrlen);
        return rc;
    }

    Result BsdBridgeService::GetSockName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out) {
        struct { s32 fd; } in = { fd };
        struct { s32 ret; s32 err; u32 addrlen; } out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 16, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { addr_out.GetPointer(), addr_out.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        out_addrlen.SetValue(out.addrlen);
        return rc;
    }

    Result BsdBridgeService::GetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_optlen, s32 fd, s32 level, s32 optname,
            sf::OutAutoSelectBuffer optval) {
        struct { s32 fd, level, optname; } in = { fd, level, optname };
        struct { s32 ret; s32 err; u32 optlen; } out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 17, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { optval.GetPointer(), optval.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        out_optlen.SetValue(out.optlen);
        return rc;
    }

    Result BsdBridgeService::Listen(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 backlog) {
        struct { s32 fd, backlog; } in = { fd, backlog };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 18, in, out);
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);

        // Host role: this is ldn_mitm's LDN station listener (initTcp(true)
        // in the real source, bound to LdnControlPort). Mark it so Accept/
        // Poll answer from the virtual-TCP tunnel instead of the real
        // (never actually reachable) local listener the forward above just
        // harmlessly set up.
        //
        // Gated on fd == m_ldn_tcp_bind_fd (set in Bind(), only when this
        // exact fd was bound to LdnControlPort as TCP) -- NOT just "any
        // SOCK_STREAM fd got Listen()'d". That unconditional version used
        // to hijack every mitm'd process's own real TCP listener (e.g.
        // sys-ftpd's PASV data socket) once ShouldMitm covered more than
        // ldn_mitm alone: Accept() below never falls back to real
        // forwarding once a fd matches g_tcp_listen_fd, so a real,
        // unrelated listener got permanently unable to accept real
        // connections. Confirmed live -- this is what broke FTP.
        if (fd >= 0 && fd == m_ldn_tcp_bind_fd) {
            std::scoped_lock lk(g_vtcp_mutex);
            g_tcp_listen_fd = fd;
            LogFormat("BsdBridge: Listen(fd=%d) -- marked as the virtual TCP listener (was bound to LdnControlPort)", fd);
        }
        return rc;
    }

    Result BsdBridgeService::Ioctl(sf::Out<s32> out_result, sf::Out<s32> out_errno, s32 fd, u32 request, u32 bufcount,
            const sf::InAutoSelectBuffer &buf_in1, const sf::InAutoSelectBuffer &buf_in2,
            const sf::InAutoSelectBuffer &buf_in3, const sf::InAutoSelectBuffer &buf_in4,
            sf::OutAutoSelectBuffer buf_out1, sf::OutAutoSelectBuffer buf_out2,
            sf::OutAutoSelectBuffer buf_out3, sf::OutAutoSelectBuffer buf_out4) {
        struct { s32 fd; u32 request, bufcount; } in = { fd, request, bufcount };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 19, in, out,
            .buffer_attrs = {
                SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_In | SfBufferAttr_HipcAutoSelect, SfBufferAttr_In | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect,
                SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect, SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = {
                { buf_in1.GetPointer(), buf_in1.GetSize() }, { buf_in2.GetPointer(), buf_in2.GetSize() },
                { buf_in3.GetPointer(), buf_in3.GetSize() }, { buf_in4.GetPointer(), buf_in4.GetSize() },
                { buf_out1.GetPointer(), buf_out1.GetSize() }, { buf_out2.GetPointer(), buf_out2.GetSize() },
                { buf_out3.GetPointer(), buf_out3.GetSize() }, { buf_out4.GetPointer(), buf_out4.GetSize() } });
        out_result.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::Fcntl(sf::Out<s32> out_result, sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 arg) {
        struct { s32 fd, cmd, arg; } in = { fd, cmd, arg };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 20, in, out);
        out_result.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::SetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 level, s32 optname,
            const sf::InAutoSelectBuffer &optval) {
        struct { s32 fd, level, optname; } in = { fd, level, optname };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 21, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { optval.GetPointer(), optval.GetSize() } });
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::Shutdown(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 how) {
        struct { s32 fd, how; } in = { fd, how };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 22, in, out);
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    // Real bsdShutdownAllSockets(int how) (libnx bsd.c) sends only `how` --
    // no pid; the previous {pid,how} input here didn't match what ldn_mitm's
    // real client ever puts on the wire for this command.
    Result BsdBridgeService::ShutdownAllSockets(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 how) {
        struct { s32 how; } in = { how };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 23, in, out);
        out_ret.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::Write(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &buffer) {
        struct { s32 fd; } in = { fd };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 24, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { buffer.GetPointer(), buffer.GetSize() } });
        out_size.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::Read(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, sf::OutAutoSelectBuffer buffer) {
        struct { s32 fd; } in = { fd };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 25, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { buffer.GetPointer(), buffer.GetSize() } });
        out_size.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::DuplicateSocket(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 fd, u64 target_pid) {
        struct { s32 fd; u64 target_pid; } in = { fd, target_pid };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 27, in, out);
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::GetResourceStatistics(sf::Out<s32> out_errno, sf::OutBuffer out_stats, u64 pid) {
        s32 err = 0;
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 28, pid, err,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcMapAlias },
            .buffers = { { out_stats.GetPointer(), out_stats.GetSize() } });
        out_errno.SetValue(err);
        return rc;
    }

    Result BsdBridgeService::RecvMMsg(sf::Out<s32> out_count, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags,
            s32 timeout, sf::OutAutoSelectBuffer out_data) {
        struct { s32 fd, vlen, flags, timeout; } in = { fd, vlen, flags, timeout };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 29, in, out,
            .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
            .buffers = { { out_data.GetPointer(), out_data.GetSize() } });
        out_count.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::SendMMsg(sf::Out<s32> out_count, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags,
            const sf::InAutoSelectBuffer &in_data) {
        struct { s32 fd, vlen, flags; } in = { fd, vlen, flags };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 30, in, out,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
            .buffers = { { in_data.GetPointer(), in_data.GetSize() } });
        out_count.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::EventFd(sf::Out<s32> out_fd, sf::Out<s32> out_errno, u64 initval, s32 flags) {
        struct { u64 initval; s32 flags; } in = { initval, flags };
        RetErrno out{};
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 31, in, out);
        out_fd.SetValue(out.ret);
        out_errno.SetValue(out.err);
        return rc;
    }

    Result BsdBridgeService::RegisterResourceStatisticsName(sf::Out<s32> out_errno, u64 pid, const sf::InBuffer &name) {
        s32 err = 0;
        Result rc = serviceMitmDispatchInOut(m_forward_service.get(), 32, pid, err,
            .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcMapAlias },
            .buffers = { { name.GetPointer(), name.GetSize() } });
        out_errno.SetValue(err);
        return rc;
    }
}
