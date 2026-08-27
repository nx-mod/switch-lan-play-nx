#pragma once
#include <stratosphere.hpp>
#include "interfaces/ibsd_mitm_service.hpp"
#include "../relay_bridge.hpp"
#include "../debug.hpp"

/*
 * bsd_bridge_service.hpp -- bsd:u MITM targeting ldn_mitm's OWN process
 * specifically (see ShouldMitm), bridging its real local LDN control
 * socket (bound to port 11452, ldn_mitm's own DefaultPort -- confirmed
 * from the real ldn_mitm source, lan_discovery.hpp) to the internet relay.
 *
 * ldn_mitm is NEVER modified. Every command it calls on this socket gets
 * intercepted here and either:
 *   - forwarded transparently to the real bsd:u service (everything not
 *     related to the one bridged socket -- lifecycle/config commands,
 *     and any OTHER socket ldn_mitm might open), or
 *   - answered from the relay bridge instead of the real network (SendTo/
 *     RecvFrom specifically on the one socket bound to port 11452).
 *
 * This class has zero knowledge of LDN's Scan/ScanResp/Connect/SyncNetwork
 * protocol -- it just tunnels raw IPv4 packets between bsd:u IPC and the
 * relay, sourcing/sinking them via bsd:u instead of a real network card.
 *
 * ldn_mitm determines its OWN local IP via nifmGetCurrentIpAddress()
 * (lan_discovery.cpp getNodeInfo()), which depends on nifm's
 * local-network-mode actually yielding a usable address without a real
 * WiFi Direct group formed at the radio level. If it doesn't, ldn_mitm's
 * own NodeInfo.ipv4Address will be wrong/zero regardless of anything this
 * bridge does -- that's outside bsd:u's IPC surface entirely. We query the
 * bridged socket's own bound address via GetSockName on the real service
 * to stay consistent with whatever nifm actually assigned, rather than
 * inventing our own address scheme that could disagree with what ldn_mitm
 * embeds in its own LDN payloads -- an inconsistent embedded IP breaks
 * in-game name display and triggers spurious version-mismatch errors on
 * the other side of the LDN control-protocol layer.
 */
namespace ams::mitm::bsd {

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

        private:
            static constexpr u16 LdnControlPort = 11452; // ldn_mitm's own DefaultPort, lan_discovery.hpp

            // The one socket we care about: ldn_mitm's real local LDN
            // control socket, identified the moment it Bind()s to
            // LdnControlPort. -1 = not yet seen on this session.
            s32 m_bridged_fd = -1;
            u32 m_bridged_local_ip = 0; // host order, from GetSockName after bind

            static slp::RelayBridge &GetRelay();
            static bool EnsureRelayConnected();

            bool IsBridged(s32 fd) const { return fd >= 0 && fd == m_bridged_fd; }
    };

    static_assert(ams::mitm::bsd::IsIBsdBridgeService<BsdBridgeService>);
}
