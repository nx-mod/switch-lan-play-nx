#pragma once
#include <stratosphere.hpp>
#include "interfaces/ibsd_mitm_service.hpp"
#include "../relay_bridge.hpp"
#include "../debug.hpp"

/*
 * bsd_bridge_service.hpp -- bsd:u MITM covering ldn_mitm's own process AND
 * every other process's bsd:u session (see ShouldMitm) EXCEPT this
 * sysmodule's own.
 *
 * Why every process, not just ldn_mitm: ldn_mitm's own LDN control channel
 * (bound to port 11452, its DefaultPort -- lan_discovery.hpp) is only half
 * the picture. The LDN service surface it exposes to games
 * (ldn_icommunication.hpp) hands a game GetIpv4Address()'s virtual-LAN
 * address and nothing else data-shaped besides the tiny SetAdvertiseData
 * (which round-trips through ldn_mitm's own SyncNetwork, already covered).
 * There is no "send game data" LDN IPC call -- real gameplay traffic is the
 * GAME's OWN separate bsd:u session, opening its own socket bound to that
 * same virtual IP and talking UDP directly, exactly as it would on a real
 * local network. That socket belongs to a DIFFERENT process than
 * ldn_mitm, with its own program_id -- a ShouldMitm scoped to ldn_mitm
 * alone never sees it at all, so a lobby could connect (ldn_mitm's own
 * traffic bridges fine) while actual gameplay data silently vanished into
 * a real WiFi interface that isn't on the same physical network as the
 * peer. Widening ShouldMitm to (almost) everyone closes that gap; per-fd
 * bridging decisions (Bind(), below) keep the actual interception scoped
 * to sockets that are genuinely using the LDN virtual subnet, so unrelated
 * processes' real internet traffic still just passes through untouched.
 *
 * ldn_mitm is NEVER modified. Every command any bridged process calls gets
 * intercepted here and either:
 *   - forwarded transparently to the real bsd:u service (everything not
 *     related to a bridged socket -- lifecycle/config commands, and any
 *     OTHER socket a process might open for its own unrelated traffic), or
 *   - answered from the relay bridge instead of the real network (SendTo/
 *     RecvFrom specifically on a socket bound within the LDN subnet).
 *
 * This class has zero knowledge of LDN's Scan/ScanResp/Connect/SyncNetwork
 * protocol, or of whatever protocol a given game speaks over its own
 * gameplay socket -- it just tunnels raw IPv4 packets between bsd:u IPC
 * and the relay, sourcing/sinking them via bsd:u instead of a real network
 * card.
 *
 * ldn_mitm (and every other bridged process) determines its OWN local IP
 * via nifm, which depends on nifm's local-network-mode actually yielding a
 * usable address without a real WiFi Direct group formed at the radio
 * level. If it doesn't, that's outside bsd:u's IPC surface entirely. We
 * query each bridged socket's own bound address via GetSockName on the
 * real service (falling back to nifm directly if that comes back
 * 0.0.0.0) to stay consistent with whatever nifm actually assigned, and
 * to recognize a DIFFERENT process's socket as LDN-relevant by it sharing
 * that SAME address -- an inconsistent embedded IP breaks in-game name
 * display and triggers spurious version-mismatch errors on the other side
 * of the LDN control-protocol layer.
 */
namespace ams::mitm::bsd {

    // ---- per-process virtual TCP state -------------------------------------
    // Was file-scope globals in bsd_bridge_service.cpp, shared across EVERY
    // mitm'd process -- safe only back when ldn_mitm was the only one ever
    // bridged. File descriptors are a PER-PROCESS numbering space, not
    // global: once a second real process (sys-ftpd) was also mitm'd, its own
    // fd numbers could numerically collide with ldn_mitm's tracked ones, and
    // its REAL Accept()/Connect()/etc. calls got silently routed through
    // logic meant only for ldn_mitm's own virtual LDN station channel --
    // confirmed live, this is what broke the FTP server entirely. Moved onto
    // the instance itself so each process gets a fully isolated copy;
    // combined with the port checks in Bind()/Listen()/Connect() (only ever
    // treat a socket as ldn_mitm's own virtual station channel if it was
    // actually bound to/connecting on LdnControlPort), a same-numbered fd
    // in a different, unrelated process can never be mistaken for this one.
    constexpr size_t VTcpInboxCap = 2048; // one compressed LAN packet is at most LanSocket::BufferSize (2048) in ldn_mitm's own source

    // A connection accepted or in progress -- accepted (host role) gets a
    // SYNTHETIC fd; our own outbound Connect() reuses the REAL fd from its
    // own Socket() call.
    struct VTcpConn {
        bool used = false;
        s32 fd = -1;
        bool established = false;              // full 3-way handshake done, data may flow
        bool syn_sent_awaiting_synack = false;  // client role: Connect() sent SYN, waiting
        u32 peer_ip = 0;                        // host order
        u16 peer_port = 0;
        u32 our_isn = 0;   // recorded at SYN time (client role) to validate the SYN-ACK's ack field
        u32 our_seq = 0;   // next byte WE will send
        u32 their_seq = 0; // next byte WE expect (the value we put in our own ack field)
        // Received bytes not yet handed to ldn_mitm. This is a TCP byte
        // STREAM, not a queue of messages: segments append, and a short
        // recv consumes only part of it. ldn_mitm reassembles LAN packets
        // itself (LanSocket::recvPartPacket) and deliberately reads with a
        // shrinking buffer -- sizeof(buffer) - recvSize -- whenever it has a
        // partial packet pending, so treating an entry as one whole message
        // and discarding whatever didn't fit desynchronizes its stream. It
        // does not report that: on a bad magic it just calls resetRecvSize()
        // and returns 0, so the connection stays up and the session silently
        // stalls until the game's own timeout gives up.
        u8 inbox[VTcpInboxCap];
        size_t inbox_len = 0;
        bool peer_closed = false;

        // Retransmission for the one outbound data segment SendTo() may
        // have in flight -- the relay transport is unreliable UDP
        // (relay_bridge.hpp), and ordinary data segments used to be
        // fire-and-forget: if the one packet in flight (e.g. ldn_mitm's
        // SyncNetwork/join request) was dropped, nothing ever resent it and
        // ldn_mitm just timed out and tore the session down
        // ("communication error"). Only ONE segment can be in flight at a
        // time here, matching ldn_mitm's own send-then-wait-for-reply usage
        // pattern for this socket. (The receive side makes no such
        // assumption -- see the inbox comment above.)
        bool has_unacked_data = false;
        u8 unacked_data[VTcpInboxCap];
        size_t unacked_data_len = 0;
        u32 unacked_seq = 0;    // seq value the pending segment was sent with
        u64 last_send_tick_ms = 0;
        int retransmit_count = 0;
    };
    // 1 client-role connection, or up to StationCountMax(8, ldn_mitm's own
    // constant) host-role accepted stations -- ldn_mitm only ever plays ONE
    // role per session, so this covers either case with room to spare.
    constexpr int MaxVTcpConns = 9;

    // A SYN has arrived and been SYN-ACKed (both happen immediately in
    // DrainRelay, matching a real kernel's TCP stack -- accept() only ever
    // DEQUEUES an already-handshaked connection, it doesn't drive the
    // handshake itself) but the final client ACK hasn't arrived yet.
    struct PendingAccept {
        bool used = false;
        u32 peer_ip = 0;
        u16 peer_port = 0;
        u32 our_isn = 0;
        u32 their_isn = 0;
        bool got_final_ack = false; // true once ready for Accept() to dequeue
    };
    constexpr int MaxPendingAccepts = 8;

    // Same per-process-isolation reasoning as the vtcp state above: Bind
    // alone can't tell SOCK_DGRAM from SOCK_STREAM, and ldn_mitm binds BOTH
    // its UDP control socket and its TCP station listener to the same
    // DefaultPort 11452 (lan_discovery.cpp initTcp/initUdp) -- Bind()'s
    // is_udp check needs this to route each fd to the right virtualization
    // path.
    constexpr size_t MaxTrackedFds = 16;

    class BsdBridgeService : public sf::MitmServiceImplBase {
        public:
            using MitmServiceImplBase::MitmServiceImplBase;
            ~BsdBridgeService();

            static bool ShouldMitm(const sm::MitmProcessInfo &client_info);

            // For slpnx::ipc::ConfigService (cfg/cfg_service.cpp): whether the
            // relay socket is currently connected, and a way to drop + retry
            // it against whatever host/port is now selected in RuntimeCfg
            // without needing a reboot (picks up a server change made in the
            // overlay immediately).
            static bool IsRelayConnected();
            static void ForceReconnect();

            // Start/Stop: an explicit on/off switch on top of the always-lazy
            // EnsureRelayConnected(), for the overlay's Start/Stop buttons.
            // Stop() closes the relay and stops it from auto-reconnecting on
            // the next bridged traffic; Start() re-enables that AND connects
            // immediately (same as ForceReconnect, but also flips the switch
            // back on). Doesn't touch the LDN session itself -- ldn_mitm
            // keeps running regardless, this only gates whether ITS traffic
            // actually reaches the relay.
            static void Stop();
            static void Start();
            static bool IsRelayEnabled();

            // The bridged UDP control socket's own local IP (host order, 0 if
            // not yet bound this session) -- for the overlay to show what
            // virtual/local address this console is presenting as, alongside
            // relay connection state.
            static u32 GetLocalIp();

            // The console's real WiFi-assigned IP (host order, 0 on failure),
            // queried directly from nifm -- unlike GetLocalIp() above, this
            // works even before ldn_mitm has bound anything this boot (lazily
            // brings up nifm itself if needed), so the overlay can always show
            // it as soon as it opens.
            static u32 GetRealIp();

            Result RegisterClient(sf::Out<u64> out_result, const LibraryConfigData &config,
                const sf::ClientProcessId &client_pid, u64 tmem_size, sf::CopyHandle &&transfer_memory);
            Result Socket(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol);
            Result SocketExempt(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol);
            Result Open(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 flags, const sf::InBuffer &path);
            Result Select(sf::Out<s32> out_count, sf::Out<s32> out_errno, const SelectInData &in_data,
                const sf::InAutoSelectBuffer &readfds_in, const sf::InAutoSelectBuffer &writefds_in,
                const sf::InAutoSelectBuffer &errorfds_in,
                sf::OutAutoSelectBuffer readfds_out, sf::OutAutoSelectBuffer writefds_out,
                sf::OutAutoSelectBuffer errorfds_out);
            Result Poll(sf::Out<s32> out_count, sf::Out<s32> out_errno, const sf::InAutoSelectBuffer &fds_in,
                sf::OutAutoSelectBuffer fds_out, s32 nfds, s32 timeout);
            Result Sysctl(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u64> out_oldlen,
                const sf::InBuffer &name, const sf::InBuffer &new_val, sf::OutBuffer old_val_out);
            Result Recv(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
                sf::OutAutoSelectBuffer buffer);
            Result RecvFrom(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd,
                s32 flags, sf::OutAutoSelectBuffer buffer, sf::OutAutoSelectBuffer addr_out);
            Result Send(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
                const sf::InAutoSelectBuffer &buffer);
            Result SendTo(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, s32 flags,
                const sf::InAutoSelectBuffer &buffer, const sf::InAutoSelectBuffer &addr);
            Result Accept(sf::Out<s32> out_fd, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out);
            Result Bind(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr);
            Result Connect(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &addr);
            Result GetPeerName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out);
            Result GetSockName(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_addrlen, s32 fd, sf::OutAutoSelectBuffer addr_out);
            Result GetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, sf::Out<u32> out_optlen, s32 fd, s32 level, s32 optname,
                sf::OutAutoSelectBuffer optval);
            Result Listen(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 backlog);
            Result Ioctl(sf::Out<s32> out_result, sf::Out<s32> out_errno, s32 fd, u32 request, u32 bufcount,
                const sf::InAutoSelectBuffer &buf_in1, const sf::InAutoSelectBuffer &buf_in2,
                const sf::InAutoSelectBuffer &buf_in3, const sf::InAutoSelectBuffer &buf_in4,
                sf::OutAutoSelectBuffer buf_out1, sf::OutAutoSelectBuffer buf_out2,
                sf::OutAutoSelectBuffer buf_out3, sf::OutAutoSelectBuffer buf_out4);
            Result Fcntl(sf::Out<s32> out_result, sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 arg);
            Result SetSockOpt(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 level, s32 optname,
                const sf::InAutoSelectBuffer &optval);
            Result Shutdown(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd, s32 how);
            Result ShutdownAllSockets(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 how);
            Result Write(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, const sf::InAutoSelectBuffer &buffer);
            Result Read(sf::Out<s32> out_size, sf::Out<s32> out_errno, s32 fd, sf::OutAutoSelectBuffer buffer);
            Result Close(sf::Out<s32> out_ret, sf::Out<s32> out_errno, s32 fd);
            Result DuplicateSocket(sf::Out<s32> out_fd, sf::Out<s32> out_errno, s32 fd, u64 target_pid);
            Result GetResourceStatistics(sf::Out<s32> out_errno, sf::OutBuffer out_stats, u64 pid);
            Result RecvMMsg(sf::Out<s32> out_count, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags,
                s32 timeout, sf::OutAutoSelectBuffer out_data);
            Result SendMMsg(sf::Out<s32> out_count, sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags,
                const sf::InAutoSelectBuffer &in_data);
            Result EventFd(sf::Out<s32> out_fd, sf::Out<s32> out_errno, u64 initval, s32 flags);
            Result RegisterResourceStatisticsName(sf::Out<s32> out_errno, u64 pid, const sf::InBuffer &name);
            Result RegisterClientShared(sf::Out<u64> out_result, const LibraryConfigData &config,
                const sf::ClientProcessId &client_pid, u64 tmem_size);

            // Public (not just called from this instance's own bsd:u
            // handlers): the background drain thread also calls this
            // directly on g_active_ldn_instance, from outside the class, to
            // keep retransmit-checking/TCP-segment processing running at
            // high frequency independent of ldn_mitm's own polling cadence
            // -- see g_active_ldn_instance's own comment
            // (bsd_bridge_service.cpp) for why that's safe.
            void DrainRelay();

            // Also public for the same reason as DrainRelay above --
            // DrainRawRelayQueue (a free function, no instance context of
            // its own) calls both of these directly on g_active_ldn_instance
            // once it identifies a TCP segment/retransmit check as
            // belonging to ldn_mitm's own LDN station channel.
            //
            // Processes one already-parsed incoming TCP segment against the
            // shared vtcp state -- caller must hold g_vtcp_mutex
            // (bsd_bridge_service.cpp).
            void HandleTcpSegment(u32 local_ip, u32 src_ip, u16 src_port,
                u32 seq, u32 ack, u8 flags, const u8 *payload, size_t payload_len);

            // Resends the shared vtcp state's established connections'
            // unacked outbound data segments past their retransmit
            // interval -- caller must hold g_vtcp_mutex.
            void CheckDataRetransmits(u32 local_ip);

        private:
            static constexpr u16 LdnControlPort = 11452; // ldn_mitm's own DefaultPort, lan_discovery.hpp

            // The one UDP socket THIS instance (i.e. this one process --
            // BsdBridgeService is instantiated per mitm'd client, so a
            // game's own process gets its own instance/its own m_bridged_fd,
            // entirely separate from ldn_mitm's) bridges to the relay.
            // Identified either by binding ldn_mitm's own LdnControlPort, or
            // (any other process) by binding the SAME local IP the LDN
            // subnet is already using -- see Bind()'s own comment.
            // -1 = not yet seen on this session.
            s32 m_bridged_fd = -1;
            u32 m_bridged_local_ip = 0;   // host order, from GetSockName after bind
            u16 m_bridged_local_port = 0; // host order, from the Bind() call itself

            // The exact fd THIS instance bound to LdnControlPort as TCP (set
            // in Bind()), if any -- Listen() only treats a fd as ldn_mitm's
            // own virtual station listener if it matches this, not just
            // "any SOCK_STREAM fd got Listen()'d" (which used to hijack
            // every mitm'd process's own real TCP listener, e.g. sys-ftpd's
            // PASV data socket, once ShouldMitm covered more than
            // ldn_mitm). -1 = no TCP bind to LdnControlPort seen yet.
            s32 m_ldn_tcp_bind_fd = -1;

            // The virtual TCP state (VTcpConn/PendingAccept arrays, the TCP
            // listener fd, the synthetic-fd counter) is deliberately NOT a
            // member here, unlike m_bridged_fd/m_ldn_tcp_bind_fd above --
            // it's a single shared global in bsd_bridge_service.cpp again
            // (g_vtcp_conns etc.), same as before this file was first split
            // apart for per-process isolation. That first attempt put a
            // full copy (VTcpConn's two 2KB buffers x 9 slots, ~37KB) on
            // EVERY mitm'd process's own instance -- with ShouldMitm
            // covering everyone, that's qlaunch, background sysmodules, AND
            // the game all carrying ~37KB of state they can never use
            // (this mechanism only ever matters for ldn_mitm's own LDN
            // station channel). Confirmed live: exhausted this sysmodule's
            // heap and crashed the console the moment the game's own
            // process tried to connect.
            //
            // Kept as a single shared copy instead, but gated by ownership
            // -- FindVTcpConnByFd/ByPeer/AllocVTcpConn (below) refuse to
            // touch it at all unless `this == g_active_ldn_instance`
            // (bsd_bridge_service.cpp), i.e. unless THIS instance is the
            // one verified to actually be ldn_mitm's own control channel.
            // That ownership check is what keeps a different process's own
            // same-numbered fd from ever being mistaken for it -- the
            // original FTP-breaking bug wasn't caused by the state being
            // shared memory, it was caused by nothing ever checking WHO was
            // asking before trusting a bare fd-number match.

            // Per-instance fd-type tracking (SOCK_DGRAM vs SOCK_STREAM),
            // seeded to -1 ("unused") since plain member-array
            // default-init is zero, not -1.
            s32 m_tracked_fd[MaxTrackedFds] = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
            s32 m_tracked_type[MaxTrackedFds] = {
                -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

            void TrackFd(s32 fd, s32 type);
            void UntrackFd(s32 fd);
            s32 GetTrackedType(s32 fd) const;

            // All three return nothing (nullptr / false) unless
            // `this == g_active_ldn_instance` -- see this class's own
            // comment above on why the shared vtcp state is gated by
            // ownership instead of being duplicated per-instance.
            VTcpConn *FindVTcpConnByFd(s32 fd);
            VTcpConn *FindVTcpConnByPeer(u32 peer_ip);
            VTcpConn *AllocVTcpConn();

            // True if `fd` is THIS instance's own virtual TCP station
            // listener -- i.e. this instance owns the shared vtcp state
            // (g_active_ldn_instance) AND fd matches the shared listener fd.
            bool IsOwnTcpListenFd(s32 fd) const;

            // Shared by Poll/Select: is THIS specific fd (this instance's
            // own bridged UDP fd, its own virtual TCP listener, or one of
            // its own established virtual TCP connections) sitting on data
            // that hasn't been read yet? Caller must call DrainRelay()
            // first so these flags are current.
            bool VFdHasPendingRead(s32 poll_fd);

            static slp::RelayBridge &GetRelay();
            static bool EnsureRelayConnected();

            bool IsBridged(s32 fd) const { return fd >= 0 && fd == m_bridged_fd; }
    };

    static_assert(ams::mitm::bsd::IsIBsdBridgeService<BsdBridgeService>);
}
