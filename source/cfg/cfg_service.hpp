/*
 * cfg_service.hpp -- slpnx:cfg IPC service.
 *
 * Standalone service (not a MITM) the Tesla overlay talks to. Registered at boot,
 * independent of any game/ ldn_mitm, so the overlay can pick a relay server, see
 * what the bridge is currently connected to, and start/stop/reconnect it.
 *
 * Commands (must match overlay/source/slpnxcfg.c):
 *   65000 GetVersion   -> out buffer char[32]
 *   65001 GetState     -> out buffer u32 connected, out buffer u32 enabled,
 *                          out buffer u32 sel_index, out buffer char[128] host,
 *                          out buffer u32 port, out buffer char[16] local_ip,
 *                          out buffer char[16] real_ip
 *   65002 SelectServer -> in  u32 index
 *   65003 Reload
 *   65004 Reconnect
 *   65005 Start
 *   65006 Stop
 */
#pragma once

#include <stratosphere.hpp>

namespace slpnx::ipc {

    class ConfigService {
    public:
        ams::Result GetVersion(const ams::sf::OutAutoSelectBuffer &version);
        ams::Result GetState(const ams::sf::OutAutoSelectBuffer &connected,
                             const ams::sf::OutAutoSelectBuffer &enabled,
                             const ams::sf::OutAutoSelectBuffer &sel_index,
                             const ams::sf::OutAutoSelectBuffer &host,
                             const ams::sf::OutAutoSelectBuffer &port,
                             const ams::sf::OutAutoSelectBuffer &local_ip,
                             const ams::sf::OutAutoSelectBuffer &real_ip);
        ams::Result SelectServer(u32 index);
        ams::Result Reload();
        ams::Result Reconnect();
        ams::Result Start();
        ams::Result Stop();
    };

}

#define AMS_SLPNXCFG_SERVICE_INTERFACE(C, H)                                                                                                                                          \
    AMS_SF_METHOD_INFO(C, H, 65000, ams::Result, GetVersion,   (const ams::sf::OutAutoSelectBuffer &version),                                                    (version),           ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65001, ams::Result, GetState,     (const ams::sf::OutAutoSelectBuffer &connected, const ams::sf::OutAutoSelectBuffer &enabled, const ams::sf::OutAutoSelectBuffer &sel_index, const ams::sf::OutAutoSelectBuffer &host, const ams::sf::OutAutoSelectBuffer &port, const ams::sf::OutAutoSelectBuffer &local_ip, const ams::sf::OutAutoSelectBuffer &real_ip), (connected, enabled, sel_index, host, port, local_ip, real_ip), ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65002, ams::Result, SelectServer, (u32 index),                                                                                       (index),             ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65003, ams::Result, Reload,       (),                                                                                                (),                  ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65004, ams::Result, Reconnect,    (),                                                                                                (),                  ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65005, ams::Result, Start,        (),                                                                                                (),                  ams::hos::Version_Min, ams::hos::Version_Max) \
    AMS_SF_METHOD_INFO(C, H, 65006, ams::Result, Stop,         (),                                                                                                (),                  ams::hos::Version_Min, ams::hos::Version_Max)

AMS_SF_DEFINE_INTERFACE(slpnx::ipc, IConfigService, AMS_SLPNXCFG_SERVICE_INTERFACE, 0x534c504e /* "SLPN" */)
