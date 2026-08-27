#pragma once
#include <switch.h>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stratosphere.hpp>

extern "C" {
#include <switch/services/nifm.h>
}

/*
 * relay_bridge.hpp -- pure, protocol-agnostic raw-IPv4-over-UDP relay
 * transport:
 *
 *   frame = [u8 type][payload]
 *     type 0x00 KEEPALIVE  -- empty, sent every KEEPALIVE_INTERVAL_MS
 *     type 0x01 IPV4       -- payload is a raw IPv4 packet, unmodified
 *     type 0x02 PING       -- 4-byte tag echoed back (not used by this
 *                              bridge yet; kept for future liveness checks)
 *     type 0x03 IPV4_FRAG  -- payload is [16-byte frag header][chunk]
 *     type 0x04 AUTH_ME    -- server challenge/response login (not used:
 *                              this project's relay config has no
 *                              username/password)
 *
 * This class knows NOTHING about LDN, ldn_mitm, or bsd:u -- it just tunnels
 * whatever raw IPv4 bytes it's given and has zero awareness of what's
 * inside them. All LDN protocol logic lives entirely in the real,
 * unmodified ldn_mitm; this class's only job is moving raw packets to/from
 * the relay.
 *
 * Inbound relay traffic is drained by a dedicated pump thread into an
 * internal packet queue rather than inline from ldn_mitm's own RecvFrom
 * calls: LANDiscovery polls its socket via bsd:u Poll BEFORE calling
 * RecvFrom (lan_protocol.cpp Pollable::Poll), so inline draining would
 * mean the poll never sees readable data and RecvFrom is never even
 * called -- classic mitm poll starvation. The pump thread lets the bridge
 * answer "readable" honestly at Poll time and have packets waiting when
 * RecvFrom arrives.
 */
namespace ams::slp {

    enum class RelayFrameType : u8 {
        Keepalive = 0x00,
        Ipv4      = 0x01,
        Ping      = 0x02,
        Ipv4Frag  = 0x03,
        AuthMe    = 0x04,
    };

    constexpr u32 RELAY_MTU = 1400;
    constexpr u32 KEEPALIVE_INTERVAL_MS = 2000; // the relay's own dashboard
        // drops a peer's room listing well before 10s -- 2s keeps a room
        // listed continuously.

    // Fixed local source port for the relay socket. Every LDN session
    // start/stop (a game re-entering the online menu, etc.) tears down and
    // recreates this socket -- see BsdBridgeService::Close()'s
    // g_relay.Close(). Without a fixed local port, each recreation gets a
    // new ephemeral port, which most NATs then map to a NEW external
    // port -- the relay sees that as a brand new client rather than the
    // same one reconnecting, which is what caused a peer's room/player
    // count on the relay's dashboard to flap on every reconnect. Binding
    // to the same local port each time keeps the NAT mapping (and so the
    // relay-visible identity) stable across reconnects for most NAT types.
    constexpr u16 RELAY_LOCAL_PORT = 45454;

    // Frag header, network-byte-order fields.
    struct FragHeader {
        u8 src_ip[4];
        u8 dst_ip[4];
        u16 id;          // big-endian on the wire
        u8 part;
        u8 total_part;
        u16 len;         // big-endian on the wire
        u16 pmtu;        // big-endian on the wire
    } __attribute__((packed));
    static_assert(sizeof(FragHeader) == 16, "FragHeader must be 16 bytes on the wire");

    namespace {
        // Hostname resolution for relay entries: getaddrinfo() crashes this
        // sysmodule/KIP context (see Connect()'s own comment below), so this
        // speaks raw DNS directly over a UDP socket instead, entirely
        // bypassing libnx's resolver.

        u32 GetDnsServer() {
            u32 addr = 0, subnet = 0, gateway = 0, dns1 = 0, dns2 = 0;
            if (R_SUCCEEDED(nifmGetCurrentIpConfigInfo(&addr, &subnet, &gateway, &dns1, &dns2))) {
                if (dns1 != 0) return dns1;
                if (dns2 != 0) return dns2;
            }
            return 0x08080808; // fallback: 8.8.8.8, network order either way (byte-symmetric)
        }

        size_t DnsEncodeName(const char *host, u8 *out, size_t cap) {
            size_t pos = 0;
            const char *label = host;
            while (*label != '\0') {
                const char *dot = strchr(label, '.');
                size_t len = dot != nullptr ? static_cast<size_t>(dot - label) : strlen(label);
                if (len == 0 || len > 63 || pos + len + 2 > cap) return 0;
                out[pos++] = static_cast<u8>(len);
                std::memcpy(out + pos, label, len);
                pos += len;
                if (dot == nullptr) break;
                label = dot + 1;
            }
            if (pos + 2 > cap) return 0;
            out[pos++] = 0x00;
            return pos;
        }

        int DnsBuildQuery(const char *host, u16 id, u8 *packet, size_t cap) {
            size_t name_len = DnsEncodeName(host, packet + 12, cap > 12 ? cap - 12 : 0);
            if (name_len == 0) return -1;
            packet[0] = static_cast<u8>(id >> 8); packet[1] = static_cast<u8>(id & 0xFF);
            packet[2] = 0x01; packet[3] = 0x00; // RD
            packet[4] = 0x00; packet[5] = 0x01; // QDCOUNT=1
            packet[6] = 0x00; packet[7] = 0x00; // ANCOUNT
            packet[8] = 0x00; packet[9] = 0x00; // NSCOUNT
            packet[10] = 0x00; packet[11] = 0x00; // ARCOUNT
            size_t pos = 12 + name_len;
            packet[pos++] = 0x00; packet[pos++] = 0x01; // QTYPE = A
            packet[pos++] = 0x00; packet[pos++] = 0x01; // QCLASS = IN
            return static_cast<int>(pos);
        }

        // Parses the first A record out of a DNS response. The RDATA is
        // already 4 raw bytes in network order -- copy straight through,
        // don't pack it MSB-first into a u32 (that reverses the address
        // once it lands in sin_addr on a little-endian target).
        bool DnsParseResponseA(const u8 *resp, size_t len, u32 *out) {
            if (len < 12) return false;
            u16 flags = static_cast<u16>((resp[2] << 8) | resp[3]);
            if (!(flags & 0x8000) || (flags & 0x000F) != 0) return false;
            u16 ancount = static_cast<u16>((resp[6] << 8) | resp[7]);
            if (ancount == 0) return false;

            size_t pos = 12;
            while (pos < len && resp[pos] != 0) {
                u8 l = resp[pos];
                if ((l & 0xC0) == 0xC0) { pos += 2; goto done_question; }
                pos += 1 + l;
            }
            pos += 5; // zero label + QTYPE + QCLASS
            done_question:

            for (u16 a = 0; a < ancount && pos + 12 <= len; a++) {
                while (pos < len) {
                    u8 l = resp[pos];
                    if ((l & 0xC0) == 0xC0) { pos += 2; break; }
                    if (l == 0) { pos += 1; break; }
                    pos += 1 + l;
                }
                if (pos + 10 > len) return false;
                u16 type = static_cast<u16>((resp[pos] << 8) | resp[pos + 1]);
                u16 rdlen = static_cast<u16>((resp[pos + 8] << 8) | resp[pos + 9]);
                if (type == 1 && rdlen == 4 && pos + 12 <= len) {
                    std::memcpy(out, resp + pos + 10, 4);
                    return true;
                }
                pos += 10 + rdlen;
            }
            return false;
        }

        // Resolves a hostname to a network-order IPv4 address via a raw DNS
        // query over UDP. *out_addr_net is network order, matching
        // sockaddr_in::sin_addr::s_addr directly.
        bool ResolveHostname(const char *host, u32 *out_addr_net) {
            u16 id = static_cast<u16>((static_cast<u32>(host[0]) << 8 | static_cast<u32>(host[1])) ^ 0x5A5A);
            u8 query[512];
            int qlen = DnsBuildQuery(host, id, query, sizeof(query));
            if (qlen < 0) return false;

            int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return false;

            struct timeval tv{};
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            struct sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = GetDnsServer();
            sa.sin_port = htons(53);

            bool ok = false;
            if (::sendto(fd, query, static_cast<size_t>(qlen), 0,
                    reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) >= 0) {
                u8 resp[512];
                ssize_t rlen = ::recvfrom(fd, resp, sizeof(resp), 0, nullptr, nullptr);
                if (rlen >= 0) {
                    ok = DnsParseResponseA(resp, static_cast<size_t>(rlen), out_addr_net);
                }
            }
            ::close(fd);
            return ok;
        }
    }

    class RelayBridge {
        public:
            RelayBridge() : m_fd(-1), m_connected(false), m_last_keepalive_tick(0),
                m_queue_head(0), m_queue_count(0), m_pump_started(false), m_pump_stop(false) {
                std::memset(&m_relay_addr, 0, sizeof(m_relay_addr));
            }

            ~RelayBridge() { Close(); }

            Result Connect(const char *host, u16 port) {
                m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
                if (m_fd < 0) {
                    return MAKERESULT(Module_Libnx, LibnxError_IoError);
                }

                // Best-effort: if this fails (port already in use somehow),
                // fall through and let the OS assign an ephemeral port on
                // first send instead, same as before this existed.
                int reuse = 1;
                setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
                struct sockaddr_in local_addr{};
                local_addr.sin_family = AF_INET;
                local_addr.sin_addr.s_addr = INADDR_ANY;
                local_addr.sin_port = htons(RELAY_LOCAL_PORT);
                bind(m_fd, reinterpret_cast<struct sockaddr *>(&local_addr), sizeof(local_addr));

                int flags = fcntl(m_fd, F_GETFL, 0);
                if (flags != -1) {
                    fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
                }

                m_relay_addr.sin_family = AF_INET;
                m_relay_addr.sin_port = htons(port);

                if (inet_pton(AF_INET, host, &m_relay_addr.sin_addr) != 1) {
                    // Hostname, not a raw IP -- calling libnx's getaddrinfo()
                    // here hard-crashes the whole bridge process (fatal
                    // report: StdAbortErrorDesc inside libnx's resolver
                    // internals, _resolverSerializeAddrInfoList; this bridge
                    // runs in a sysmodule/KIP context, not a normal
                    // application, and whatever the resolver needs isn't
                    // safely available here). Resolve with a raw DNS query
                    // over UDP instead, entirely bypassing libnx's resolver.
                    u32 resolved_net = 0;
                    if (!ResolveHostname(host, &resolved_net)) {
                        close(m_fd);
                        m_fd = -1;
                        return MAKERESULT(Module_Libnx, LibnxError_IoError);
                    }
                    m_relay_addr.sin_addr.s_addr = resolved_net;
                }

                m_connected = true;
                m_last_keepalive_tick = armGetSystemTick();

                StartPump();
                return ResultSuccess();
            }

            void Close() {
                StopPump();
                if (m_fd >= 0) {
                    close(m_fd);
                    m_fd = -1;
                }
                std::scoped_lock lk(m_queue_mutex);
                m_queue_head = 0;
                m_queue_count = 0;
                m_connected = false;
            }

            bool IsConnected() const { return m_connected; }

            // Queue status for Poll/Select interception: is there a complete
            // IPv4 packet ready to be delivered by the next RecvFrom?
            bool HasPending() {
                std::scoped_lock lk(m_queue_mutex);
                return m_queue_count > 0;
            }

            // Sends a raw IPv4 packet, fragmenting if it's over RELAY_MTU --
            // matches lan_client_send()'s own fragmentation trigger
            // (pmtu > 0 && total_part > 1).
            ssize_t SendIpv4(const void *packet, size_t len) {
                if (!m_connected) return -1;
                if (len <= RELAY_MTU) {
                    u8 buf[1 + RELAY_MTU];
                    buf[0] = static_cast<u8>(RelayFrameType::Ipv4);
                    std::memcpy(buf + 1, packet, len);
                    return SendRaw(buf, 1 + len);
                }
                return SendFragmented(packet, len);
            }

            // Pops one complete IPv4 packet received from the relay.
            // Returns 1 and fills out_buf/out_len, or 0 if the queue is empty.
            int PopIpv4(u8 *out_buf, size_t out_buf_size, size_t *out_len) {
                std::scoped_lock lk(m_queue_mutex);
                if (m_queue_count == 0) return 0;

                Packet &pkt = m_queue[m_queue_head];
                if (pkt.len > out_buf_size) {
                    // Too big for caller's buffer: drop it rather than wedge
                    // the queue head forever.
                    m_queue_head = (m_queue_head + 1) % QueueSize;
                    m_queue_count--;
                    return 0;
                }
                std::memcpy(out_buf, pkt.data, pkt.len);
                *out_len = pkt.len;
                m_queue_head = (m_queue_head + 1) % QueueSize;
                m_queue_count--;
                return 1;
            }

        private:
            static constexpr size_t QueueSize = 64;
            struct Packet {
                size_t len;
                u8 data[20 + 8 + RELAY_MTU];
            };
            static_assert(sizeof(Packet::data) >= 20 + 8 + RELAY_MTU);

            ssize_t SendRaw(const void *data, size_t len) {
                if (!m_connected) return -1;
                return ::sendto(m_fd, data, len, 0,
                    reinterpret_cast<struct sockaddr *>(&m_relay_addr), sizeof(m_relay_addr));
            }

            void SendKeepalive() {
                u8 type = static_cast<u8>(RelayFrameType::Keepalive);
                SendRaw(&type, 1);
            }

            void CheckKeepalive() {
                u64 now = armGetSystemTick();
                u64 elapsed_ns = armTicksToNs(now - m_last_keepalive_tick);
                if (elapsed_ns / 1000000 >= KEEPALIVE_INTERVAL_MS) {
                    SendKeepalive();
                    m_last_keepalive_tick = now;
                }
            }

            // ---- pump thread ------------------------------------------------

            static void PumpThreadMain(void *arg) {
                RelayBridge *self = static_cast<RelayBridge *>(arg);
                self->PumpLoop();
            }

            void StartPump() {
                if (m_pump_started) return;
                m_pump_stop = false;
                Result rc = os::CreateThread(std::addressof(m_pump_thread), PumpThreadMain, this,
                    m_pump_stack, sizeof(m_pump_stack), PumpThreadPriority);
                if (R_FAILED(rc)) return; // keepalive still piggybacks on SendTo callers
                os::SetThreadNamePointer(std::addressof(m_pump_thread), "slp::RelayPump");
                os::StartThread(std::addressof(m_pump_thread));
                m_pump_started = true;
            }

            void StopPump() {
                if (!m_pump_started) return;
                m_pump_stop = true;
                os::WaitThread(std::addressof(m_pump_thread));
                os::DestroyThread(std::addressof(m_pump_thread));
                m_pump_started = false;
            }

            void PumpLoop() {
                while (!m_pump_stop) {
                    CheckKeepalive();

                    // Drain everything the relay has sent us into the queue.
                    u8 pkt[20 + 8 + RELAY_MTU];
                    size_t pkt_len = 0;
                    while (RecvIpv4(pkt, sizeof(pkt), std::addressof(pkt_len)) == 1) {
                        std::scoped_lock lk(m_queue_mutex);
                        if (m_queue_count < QueueSize) {
                            const size_t tail = (m_queue_head + m_queue_count) % QueueSize;
                            m_queue[tail].len = pkt_len;
                            std::memcpy(m_queue[tail].data, pkt, pkt_len);
                            m_queue_count++;
                        }
                        // else: queue full -> drop. LDN control packets are
                        // tiny and the consumer polls every 10ms, so this
                        // should never fill in practice.
                    }

                    os::SleepThread(TimeSpan::FromMilliSeconds(2));
                }
            }

            // Receives one relay frame. Returns:
            //   1  -- a complete (possibly reassembled) IPv4 packet is in
            //         out_buf/out_len
            //   0  -- frame handled internally (keepalive/ping/partial frag),
            //         nothing to deliver this call
            //  -1  -- no data / error
            int RecvIpv4(u8 *out_buf, size_t out_buf_size, size_t *out_len) {
                u8 raw[1 + RELAY_MTU + sizeof(FragHeader)];
                ssize_t n = ::recvfrom(m_fd, raw, sizeof(raw), 0, nullptr, nullptr);
                if (n <= 0) return -1;

                u8 type = raw[0] & 0x7F;
                switch (static_cast<RelayFrameType>(type)) {
                    case RelayFrameType::Ipv4: {
                        size_t plen = static_cast<size_t>(n - 1);
                        if (plen > out_buf_size) return -1;
                        std::memcpy(out_buf, raw + 1, plen);
                        *out_len = plen;
                        return 1;
                    }
                    case RelayFrameType::Ipv4Frag: {
                        if (static_cast<size_t>(n) < 1 + sizeof(FragHeader)) return 0;
                        return ReassembleFrag(raw + 1, static_cast<size_t>(n - 1), out_buf, out_buf_size, out_len)
                            ? 1 : 0;
                    }
                    case RelayFrameType::Keepalive:
                    case RelayFrameType::Ping:
                    case RelayFrameType::AuthMe:
                    default:
                        return 0;
                }
            }

            // Splits a packet too large for one relay frame into
            // (RELAY_MTU - sizeof(FragHeader))-byte chunks, network-byte-order
            // header fields.
            ssize_t SendFragmented(const void *packet, size_t len) {
                constexpr size_t chunk = RELAY_MTU - sizeof(FragHeader);
                size_t total_part = (len + chunk - 1) / chunk;
                if (total_part > 0xFF) return -1; // total_part is a single byte on the wire

                const u8 *bytes = static_cast<const u8 *>(packet);
                u16 id = m_next_frag_id++;

                // IPv4 header: src at offset 12, dst at offset 16 (same
                // convention used throughout this whole project).
                u8 src_ip[4], dst_ip[4];
                std::memcpy(src_ip, bytes + 12, 4);
                std::memcpy(dst_ip, bytes + 16, 4);

                size_t pos = 0;
                for (size_t part = 0; part < total_part; part++) {
                    size_t part_len = (len - pos < chunk) ? (len - pos) : chunk;

                    u8 buf[1 + sizeof(FragHeader) + chunk];
                    buf[0] = static_cast<u8>(RelayFrameType::Ipv4Frag);

                    FragHeader hdr{};
                    std::memcpy(hdr.src_ip, src_ip, 4);
                    std::memcpy(hdr.dst_ip, dst_ip, 4);
                    hdr.id = htons(id);
                    hdr.part = static_cast<u8>(part);
                    hdr.total_part = static_cast<u8>(total_part);
                    hdr.len = htons(static_cast<u16>(part_len));
                    hdr.pmtu = htons(static_cast<u16>(chunk));
                    std::memcpy(buf + 1, &hdr, sizeof(hdr));
                    std::memcpy(buf + 1 + sizeof(hdr), bytes + pos, part_len);

                    ssize_t rc = SendRaw(buf, 1 + sizeof(hdr) + part_len);
                    if (rc < 0) return rc;
                    pos += part_len;
                }
                return static_cast<ssize_t>(len);
            }

            bool ReassembleFrag(const u8 *data, size_t len, u8 *out_buf, size_t out_buf_size, size_t *out_len) {
                if (len < sizeof(FragHeader)) return false;
                FragHeader hdr;
                std::memcpy(&hdr, data, sizeof(hdr));
                u16 id = ntohs(hdr.id);
                u16 part_len = ntohs(hdr.len);
                u16 pmtu = ntohs(hdr.pmtu);
                const u8 *chunk_data = data + sizeof(hdr);
                size_t chunk_data_len = len - sizeof(hdr);
                if (part_len > chunk_data_len) return false;

                ReassemblySlot *slot = nullptr;
                for (auto &s : m_slots) {
                    if (s.used && s.id == id && std::memcmp(s.src_ip, hdr.src_ip, 4) == 0) {
                        slot = &s;
                        break;
                    }
                }
                if (!slot) {
                    for (auto &s : m_slots) {
                        if (!s.used) {
                            slot = &s;
                            slot->used = true;
                            slot->id = id;
                            slot->part_mask = 0;
                            std::memcpy(slot->src_ip, hdr.src_ip, 4);
                            break;
                        }
                    }
                }
                if (!slot) return false; // all reassembly slots busy; drop

                if (hdr.part >= 32 || static_cast<size_t>(hdr.part) * pmtu + part_len > sizeof(slot->buffer)) {
                    slot->used = false;
                    return false;
                }
                std::memcpy(slot->buffer + static_cast<size_t>(hdr.part) * pmtu, chunk_data, part_len);
                slot->part_mask |= (1u << hdr.part);

                if (hdr.part == hdr.total_part - 1) {
                    slot->total_len = static_cast<size_t>(hdr.total_part - 1) * pmtu + part_len;
                }

                u32 expected_mask = (hdr.total_part >= 32) ? 0xFFFFFFFFu : ((1u << hdr.total_part) - 1);
                if (slot->part_mask == expected_mask && slot->total_len > 0) {
                    if (slot->total_len > out_buf_size) {
                        slot->used = false;
                        return false;
                    }
                    std::memcpy(out_buf, slot->buffer, slot->total_len);
                    *out_len = slot->total_len;
                    slot->used = false;
                    return true;
                }
                return false;
            }

            int m_fd;
            bool m_connected;
            struct sockaddr_in m_relay_addr;
            u64 m_last_keepalive_tick;
            u16 m_next_frag_id = 0;

            struct ReassemblySlot {
                bool used = false;
                u16 id = 0;
                u8 src_ip[4] = {};
                u32 part_mask = 0;
                size_t total_len = 0;
                u8 buffer[RELAY_MTU * 32];
            };
            static constexpr int NUM_SLOTS = 4;
            ReassemblySlot m_slots[NUM_SLOTS];

            // ---- inbound queue + pump thread ---------------------------------
            static constexpr s32 PumpThreadPriority = 6; // same tier as the mitm server threads in main.cpp
            os::SdkMutex m_queue_mutex;
            size_t m_queue_head;
            size_t m_queue_count;
            Packet m_queue[QueueSize];

            os::ThreadType m_pump_thread;
            alignas(os::MemoryPageSize) u8 m_pump_stack[4_KB];
            bool m_pump_started;
            volatile bool m_pump_stop;
    };

}
