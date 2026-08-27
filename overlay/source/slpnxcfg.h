#pragma once
#include <switch.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client for the switch-lan-play-nx config service "slpnx:cfg".
 *
 * IPC commands (must match ../../source/cfg/cfg_service.hpp):
 *   65000 GetVersion   -> out buffer char[32]
 *   65001 GetState     -> out u32 connected, out u32 enabled, out u32 sel_index,
 *                          out buffer char[128] host, out u32 port,
 *                          out buffer char[16] local_ip, out buffer char[16] real_ip
 *   65002 SelectServer -> in u32 index
 *   65003 Reload
 *   65004 Reconnect
 *   65005 Start
 *   65006 Stop
 */

typedef struct {
    Service s;
} SlpNxCfgService;

/* Returned by slpnxCfgGetConfig() when the "slpnx:cfg" service is not
 * registered, i.e. the sysmodule isn't installed / isn't running yet.
 * Distinct from a real IPC failure so the UI can show a helpful message
 * instead of a raw error code. */
#define SLPNXCFG_RESULT_NOT_INSTALLED MAKERESULT(Module_Libnx, LibnxError_NotFound)

/* Connect to the "slpnx:cfg" service.
 * Returns SLPNXCFG_RESULT_NOT_INSTALLED (without blocking) if the
 * sysmodule is not present -- see slpnxcfg.c for why that check matters:
 * a plain smGetService() on an unregistered name BLOCKS until someone
 * registers it, which would hang the overlay forever on open. */
Result slpnxCfgGetConfig(SlpNxCfgService *out);

void slpnxCfgClose(SlpNxCfgService *s);

Result slpnxCfgGetVersion(SlpNxCfgService *s, char *version);   /* >= 32 bytes */
Result slpnxCfgGetState(SlpNxCfgService *s, u32 *connected, u32 *enabled, u32 *selIndex,
                        char *host, u32 *port, char *localIp, char *realIp);
                        /* host >= 128 bytes, localIp/realIp >= 16 bytes each */
Result slpnxCfgSelectServer(SlpNxCfgService *s, u32 index);
Result slpnxCfgReload(SlpNxCfgService *s);
Result slpnxCfgReconnect(SlpNxCfgService *s);
Result slpnxCfgStart(SlpNxCfgService *s);
Result slpnxCfgStop(SlpNxCfgService *s);

#ifdef __cplusplus
}
#endif
