// Minimal ldn:u client that talks ONLY the commands ldn_mitm implements.
//
// libnx's ldnInitialize() cannot be used here. It branches on hosversion and
// issues commands beyond ldn_mitm's table (which ends at 402), and a command
// that never reaches a handler takes the whole IPC session with it -- the
// client sees 0xF601 (session closed) and every later call then fails 0xE401
// (invalid handle). Nothing is logged server-side, because nothing ran.
//
// Driving the raw command IDs keeps the probe pinned to exactly the surface a
// real game uses, which is the surface we actually want to exercise.
//
// Command IDs, from ldn_mitm's interfaces/icommunication.hpp:
//     0 GetState            1 GetNetworkInfo       2 GetIpv4Address
//     3 GetDisconnectReason
//   100 AttachStateChangeEvent                   102 Scan
//   200 OpenAccessPoint    201 CloseAccessPoint   202 CreateNetwork
//   204 DestroyNetwork     206 SetAdvertiseData
//   300 OpenStation        301 CloseStation       302 Connect
//   304 Disconnect
//   400 Initialize         401 Finalize

#pragma once

#include <switch.h>

// CreateNetworkConfig, 0x98 -- ldn_mitm ldn_types.hpp
typedef struct {
    LdnSecurityConfig security_config; // 0x44
    LdnUserConfig     user_config;     // 0x30
    u8                pad[0x4];
    LdnNetworkConfig  network_config;  // 0x20
} LdnRawCreateNetworkConfig;

// ConnectNetworkData, 0x7C
typedef struct {
    LdnSecurityConfig security_config; // 0x44
    LdnUserConfig     user_config;     // 0x30
    s32               local_communication_version;
    u32               option;
} LdnRawConnectNetworkData;

Result ldnRawInitialize(void);
void   ldnRawExit(void);

Result ldnRawGetState(u32 *out_state);
Result ldnRawGetIpv4Address(u32 *out_addr, u32 *out_mask);
Result ldnRawGetNetworkInfo(LdnNetworkInfo *out);
Result ldnRawGetDisconnectReason(u32 *out_reason);

Result ldnRawScan(u16 channel, const LdnScanFilter *filter,
                  LdnNetworkInfo *out, s32 count, s32 *out_total);

Result ldnRawOpenAccessPoint(void);
Result ldnRawCloseAccessPoint(void);
Result ldnRawCreateNetwork(const LdnRawCreateNetworkConfig *cfg);
Result ldnRawDestroyNetwork(void);
Result ldnRawSetAdvertiseData(const void *data, size_t size);

Result ldnRawOpenStation(void);
Result ldnRawCloseStation(void);
Result ldnRawConnect(const LdnRawConnectNetworkData *data, const LdnNetworkInfo *info);
Result ldnRawDisconnect(void);
