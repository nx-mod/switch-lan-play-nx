#include "ldn_raw.h"
#include <string.h>

static Service g_ldn_srv;   // ldn:u
static Service g_ldn_comm;  // IUserLocalCommunicationService
static bool    g_have_srv;
static bool    g_have_comm;

Result ldnRawInitialize(void) {
    Result rc = smGetService(&g_ldn_srv, "ldn:u");
    if (R_FAILED(rc)) return rc;
    g_have_srv = true;

    // cmd 0: CreateUserLocalCommunicationService
    rc = serviceDispatch(&g_ldn_srv, 0,
        .out_num_objects = 1,
        .out_objects = &g_ldn_comm,
    );
    if (R_FAILED(rc)) return rc;
    g_have_comm = true;

    // cmd 400: Initialize(pid). Deliberately NOT 402 (Initialize2) -- 400 is
    // the plain form every LDN title has always used, and it needs no version
    // negotiation we would then have to keep in step with.
    //
    // The u64 is required. Atmosphere decodes sf::ClientProcessId from the PID
    // descriptor, but the raw request must still carry a placeholder word for
    // it. Sending the descriptor alone makes the request malformed, and sf
    // drops the session before dispatch -- which looks like 0xF601 at the
    // client with nothing at all logged server-side, because no handler ran.
    const u64 pid_placeholder = 0;
    rc = serviceDispatchIn(&g_ldn_comm, 400, pid_placeholder,
        .in_send_pid = true,
    );
    return rc;
}

void ldnRawExit(void) {
    if (g_have_comm) {
        serviceDispatch(&g_ldn_comm, 401); // Finalize, best effort
        serviceClose(&g_ldn_comm);
        g_have_comm = false;
    }
    if (g_have_srv) {
        serviceClose(&g_ldn_srv);
        g_have_srv = false;
    }
}

Result ldnRawGetState(u32 *out_state) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatchOut(&g_ldn_comm, 0, *out_state);
}

Result ldnRawGetIpv4Address(u32 *out_addr, u32 *out_mask) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    struct { u32 addr; u32 mask; } out;
    Result rc = serviceDispatchOut(&g_ldn_comm, 2, out);
    if (R_SUCCEEDED(rc)) { *out_addr = out.addr; *out_mask = out.mask; }
    return rc;
}

Result ldnRawGetDisconnectReason(u32 *out_reason) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatchOut(&g_ldn_comm, 3, *out_reason);
}

Result ldnRawGetNetworkInfo(LdnNetworkInfo *out) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    // NetworkInfo derives sf::LargeData with no transfer-mode preference tag,
    // and sf_buffers.hpp resolves that to Pointer, NOT AutoSelect (see
    // PreferredTransferMode: IsLargeData -> BufferTransferMode::Pointer).
    // Sending an auto-select descriptor here makes the request malformed and
    // takes the session down before the handler runs.
    return serviceDispatch(&g_ldn_comm, 1,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcPointer | SfBufferAttr_FixedSize },
        .buffers = { { out, sizeof(*out) } },
    );
}

Result ldnRawScan(u16 channel, const LdnScanFilter *filter,
                  LdnNetworkInfo *out, s32 count, s32 *out_total) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    // in: ScanFilter then channel, matching the interface's (channel, filter)
    // argument order after Atmosphere packs raw data -- channel is a u16 and
    // sits ahead of the 0x60 filter in the request.
    struct {
        u16 channel;
        u8  pad[6];
        LdnScanFilter filter;
    } in;
    memset(&in, 0, sizeof(in));
    in.channel = channel;
    in.filter = *filter;

    u32 total = 0;
    Result rc = serviceDispatchInOut(&g_ldn_comm, 102, in, total,
        .buffer_attrs = { SfBufferAttr_Out | SfBufferAttr_HipcAutoSelect },
        .buffers = { { out, (size_t)count * sizeof(LdnNetworkInfo) } },
    );
    if (R_SUCCEEDED(rc)) *out_total = (s32)total;
    return rc;
}

Result ldnRawOpenAccessPoint(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 200);
}

Result ldnRawCloseAccessPoint(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 201);
}

Result ldnRawCreateNetwork(const LdnRawCreateNetworkConfig *cfg) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatchIn(&g_ldn_comm, 202, *cfg);
}

Result ldnRawDestroyNetwork(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 204);
}

Result ldnRawSetAdvertiseData(const void *data, size_t size) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 206,
        .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcAutoSelect },
        .buffers = { { (void *)data, size } },
    );
}

Result ldnRawOpenStation(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 300);
}

Result ldnRawCloseStation(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 301);
}

Result ldnRawConnect(const LdnRawConnectNetworkData *data, const LdnNetworkInfo *info) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    // NetworkInfo is LargeData -> Pointer transfer mode; see ldnRawGetNetworkInfo.
    return serviceDispatchIn(&g_ldn_comm, 302, *data,
        .buffer_attrs = { SfBufferAttr_In | SfBufferAttr_HipcPointer },
        .buffers = { { (void *)info, sizeof(*info) } },
    );
}

Result ldnRawDisconnect(void) {
    if (!g_have_comm) return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    return serviceDispatch(&g_ldn_comm, 304);
}
