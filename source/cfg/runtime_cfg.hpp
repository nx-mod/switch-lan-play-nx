#pragma once
#include <stratosphere.hpp>

/*
 * runtime_cfg.hpp -- persisted relay server selection for switch-lan-play-nx.
 *
 * BsdBridgeService::EnsureRelayConnected() (bsd_bridge_service.cpp) already
 * connects lazily on first bridged traffic and owns the actual RelayBridge
 * socket, so this class only answers "what host/port should that connect
 * to" and persists the answer across reboots.
 */
namespace slpnx::cfg {

    constexpr const char *CONFIG_PATH   = "sdmc:/config/switch-lan-play-nx/servers.conf";
    constexpr const char *SELECTED_PATH = "sdmc:/config/switch-lan-play-nx/selected.cfg";

    // Falls back to whatever was hardcoded here before the config port, so a
    // fresh install with no servers.conf yet still bridges to the same relay
    // this project was tested against all session.
    constexpr const char *DefaultRelayHost = "10.102.227.153";
    constexpr u16 DefaultRelayPort = 11451;

    class RuntimeCfg {
        public:
            RuntimeCfg();

            // Read + parse the server list from SD. Returns count (0 on error
            // or missing file -- not fatal, GetSelectedHostPort() still falls
            // back to DefaultRelayHost/Port in that case).
            int ReloadServers();

            int ServerCount();
            const char *ServerName(int index);
            const char *ServerHost(int index);
            unsigned short ServerPort(int index);

            // Persists the selection to SELECTED_PATH.
            int SelectServer(u32 index);
            int GetSelectedIndex();

            // Fills out_host (NUL-terminated, up to host_cap bytes) and
            // out_port with the currently selected server, or the built-in
            // default if nothing is configured/selected.
            void GetSelectedHostPort(char *out_host, size_t host_cap, u16 *out_port);

        private:
            ams::os::SdkMutex m_mutex;
            int m_sel_index; // -1 = none selected (use default)
    };

    RuntimeCfg &GetRuntimeCfg();

}
