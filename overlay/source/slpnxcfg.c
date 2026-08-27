#include "slpnxcfg.h"

enum {
    SlpNxCfgCmdGetVersion   = 65000,
    SlpNxCfgCmdGetState     = 65001,
    SlpNxCfgCmdSelect       = 65002,
    SlpNxCfgCmdReload       = 65003,
    SlpNxCfgCmdReconnect    = 65004,
    SlpNxCfgCmdStart        = 65005,
    SlpNxCfgCmdStop         = 65006,
};

static const u32 BufferOut = SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out;

/* Atmosphere sm extension: AtmosphereHasService (cmd 65100) -- asks whether
 * a service name is registered WITHOUT blocking. A plain smGetService() on
 * a name nobody has registered yet BLOCKS the calling thread until someone
 * does, which would hang this overlay forever inside doWithSmSession() if
 * switch-lan-play-nx isn't installed or hasn't booted yet. sm switched from
 * CMIF to TIPC serialization in 12.0.0, so pick the matching session
 * accessor for the running firmware. */
static Result slpnxAtmosphereHasService(bool *out, SmServiceName name) {
    u8 tmp = 0;
    Result rc;

    if (hosversionAtLeast(12, 0, 0))
        rc = tipcDispatchInOut(smGetServiceSessionTipc(), 65100, name, tmp);
    else
        rc = serviceDispatchInOut(smGetServiceSession(), 65100, name, tmp);

    if (R_SUCCEEDED(rc))
        *out = (tmp != 0);
    return rc;
}

Result slpnxCfgGetConfig(SlpNxCfgService *out) {
    bool has_service = false;
    Result rc = slpnxAtmosphereHasService(&has_service, smEncodeName("slpnx:cfg"));
    if (R_FAILED(rc))
        return rc;

    if (!has_service)
        return SLPNXCFG_RESULT_NOT_INSTALLED;

    return smGetService(&out->s, "slpnx:cfg");
}

void slpnxCfgClose(SlpNxCfgService *s) {
    serviceClose(&s->s);
}

Result slpnxCfgGetVersion(SlpNxCfgService *s, char *version) {
    return serviceDispatch(&s->s, SlpNxCfgCmdGetVersion,
        .buffer_attrs = { BufferOut },
        .buffers = { { version, 32 } },
    );
}

Result slpnxCfgGetState(SlpNxCfgService *s, u32 *connected, u32 *enabled, u32 *selIndex,
                        char *host, u32 *port, char *localIp, char *realIp) {
    return serviceDispatch(&s->s, SlpNxCfgCmdGetState,
        .buffer_attrs = { BufferOut, BufferOut, BufferOut, BufferOut, BufferOut, BufferOut, BufferOut },
        .buffers = {
            { connected, sizeof(*connected) },
            { enabled, sizeof(*enabled) },
            { selIndex, sizeof(*selIndex) },
            { host, 128 },
            { port, sizeof(*port) },
            { localIp, 16 },
            { realIp, 16 },
        },
    );
}

Result slpnxCfgSelectServer(SlpNxCfgService *s, u32 index) {
    return serviceDispatchIn(&s->s, SlpNxCfgCmdSelect, index);
}

Result slpnxCfgReload(SlpNxCfgService *s) {
    return serviceDispatch(&s->s, SlpNxCfgCmdReload);
}

Result slpnxCfgReconnect(SlpNxCfgService *s) {
    return serviceDispatch(&s->s, SlpNxCfgCmdReconnect);
}

Result slpnxCfgStart(SlpNxCfgService *s) {
    return serviceDispatch(&s->s, SlpNxCfgCmdStart);
}

Result slpnxCfgStop(SlpNxCfgService *s) {
    return serviceDispatch(&s->s, SlpNxCfgCmdStop);
}
