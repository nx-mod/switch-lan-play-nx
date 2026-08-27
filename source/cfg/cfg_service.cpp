#include "cfg_service.hpp"
#include "runtime_cfg.hpp"
#include "../bsd/bsd_bridge_service.hpp"

#include <cstring>
#include <cstdio>
#include <arpa/inet.h>

namespace slpnx::ipc {

    namespace {

        constexpr const char *Version = "0.1.0";

        void copy_str(const ams::sf::OutAutoSelectBuffer &out, const char *str) {
            char buf[128];
            std::memset(buf, 0, sizeof(buf));
            std::strncpy(buf, str, sizeof(buf) - 1);
            size_t n = out.GetSize();
            if (n > sizeof(buf))
                n = sizeof(buf);
            std::memcpy(out.GetPointer(), buf, n);
        }

        // host order -> dotted-quad string, or empty if ip==0.
        void ip_to_str(u32 ip_host, char *out, size_t out_cap) {
            if (ip_host == 0) {
                out[0] = '\0';
                return;
            }
            struct in_addr addr;
            addr.s_addr = htonl(ip_host);
            const char *s = inet_ntoa(addr);
            std::strncpy(out, s ? s : "", out_cap - 1);
            out[out_cap - 1] = '\0';
        }

    }

    ams::Result ConfigService::GetVersion(const ams::sf::OutAutoSelectBuffer &version) {
        const size_t n = version.GetSize();
        char buf[32];
        std::memset(buf, 0, sizeof(buf));
        std::strncpy(buf, Version, sizeof(buf) - 1);
        std::memcpy(version.GetPointer(), buf, n < sizeof(buf) ? n : sizeof(buf));
        R_SUCCEED();
    }

    ams::Result ConfigService::GetState(const ams::sf::OutAutoSelectBuffer &connected,
                                        const ams::sf::OutAutoSelectBuffer &enabled,
                                        const ams::sf::OutAutoSelectBuffer &sel_index,
                                        const ams::sf::OutAutoSelectBuffer &host,
                                        const ams::sf::OutAutoSelectBuffer &port,
                                        const ams::sf::OutAutoSelectBuffer &local_ip,
                                        const ams::sf::OutAutoSelectBuffer &real_ip) {
        auto &rt = slpnx::cfg::GetRuntimeCfg();

        u32 conn = ams::mitm::bsd::BsdBridgeService::IsRelayConnected() ? 1 : 0;
        u32 en = ams::mitm::bsd::BsdBridgeService::IsRelayEnabled() ? 1 : 0;
        u32 sel = static_cast<u32>(rt.GetSelectedIndex());

        char h[16];
        u16 p = 0;
        rt.GetSelectedHostPort(h, sizeof(h), &p);
        u32 p32 = p;

        char local_ip_str[16];
        ip_to_str(ams::mitm::bsd::BsdBridgeService::GetLocalIp(), local_ip_str, sizeof(local_ip_str));
        char real_ip_str[16];
        ip_to_str(ams::mitm::bsd::BsdBridgeService::GetRealIp(), real_ip_str, sizeof(real_ip_str));

        copy_str(host, h);
        copy_str(local_ip, local_ip_str);
        copy_str(real_ip, real_ip_str);
        std::memcpy(connected.GetPointer(), std::addressof(conn), sizeof(conn));
        std::memcpy(enabled.GetPointer(), std::addressof(en), sizeof(en));
        std::memcpy(sel_index.GetPointer(), std::addressof(sel), sizeof(sel));
        std::memcpy(port.GetPointer(), std::addressof(p32), sizeof(p32));
        R_SUCCEED();
    }

    ams::Result ConfigService::SelectServer(u32 index) {
        auto &rt = slpnx::cfg::GetRuntimeCfg();
        R_UNLESS(rt.SelectServer(index), ams::sf::hipc::ResultInvalidRequestSize());
        R_SUCCEED();
    }

    ams::Result ConfigService::Reload() {
        slpnx::cfg::GetRuntimeCfg().ReloadServers();
        R_SUCCEED();
    }

    ams::Result ConfigService::Reconnect() {
        ams::mitm::bsd::BsdBridgeService::ForceReconnect();
        R_SUCCEED();
    }

    ams::Result ConfigService::Start() {
        ams::mitm::bsd::BsdBridgeService::Start();
        R_SUCCEED();
    }

    ams::Result ConfigService::Stop() {
        ams::mitm::bsd::BsdBridgeService::Stop();
        R_SUCCEED();
    }

}
