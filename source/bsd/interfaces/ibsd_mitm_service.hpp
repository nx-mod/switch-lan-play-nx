/*
 * ibsd_mitm_service.hpp -- bsd:u MITM IPC interface, switch-lan-play-nx.
 *
 * Command layout matches libnx's own services/bsd.c (_bsdDispatchImpl):
 * every bsd:u command replies with the SAME raw 8-byte struct
 * { s32 ret; s32 errno; } first (ret at offset 0,
 * errno at offset 4), with any extra per-command output data appended
 * after those two words. libstratosphere's own AMS_SF_METHOD_INFO assigns
 * raw-data wire offsets to same-alignment Out<> scalars in DECLARATION
 * order (RawDataOffsetCalculator does a stable sort by alignment; s32
 * Out<> fields all share alignment 4, so equal-alignment fields keep
 * their declared order) -- so the Out<> param that represents "ret" for
 * each command (out_fd for Socket, out_size for Recv/Send, out_count for
 * Select/Poll, out_result for Ioctl/Fcntl, etc.) MUST be declared before
 * out_errno, or the reply this service sends back to ldn_mitm has ret and
 * errno swapped relative to what libnx's client-side bsd.c expects.
 */

#pragma once

#include <stratosphere.hpp>

namespace ams::mitm::bsd {
    /* Mirrors libnx's internal LibraryConfigData (bsd.c) byte-for-byte --
       we never interpret this, only forward it untouched to the real
       service, so an opaque 32-byte blob is all that's needed here. */
    struct LibraryConfigData {
        u8 raw[0x20];
    };
    static_assert(sizeof(LibraryConfigData) == 0x20);

    /* Mirrors libnx's own BsdSelectTimeval + the anonymous {nfds, timeout}
       struct bsdSelect() sends as raw in-data (bsd.c): sizeof(struct
       timeval)=16, sizeof(BsdSelectTimeval)=24 (tv[16] + is_null[1], padded
       to align 8), combined struct = 32 bytes (nfds[4] padded to 8, then
       timeout[24]). `nfds` and `timeout` must be declared together in this
       one struct, not as separate scalar/buffer params -- that doesn't
       match the real wire shape. */
    struct SelectTimeval {
        s64 tv_sec;
        s64 tv_usec;
        bool is_null;
        u8 _pad[7];
    };
    static_assert(sizeof(SelectTimeval) == 24 && alignof(SelectTimeval) == 8);

    struct SelectInData {
        s32 nfds;
        u8 _pad[4];
        SelectTimeval timeout;
    };
    static_assert(sizeof(SelectInData) == 32 && alignof(SelectInData) == 8);
}

#define AMS_SLP_NX_BSD_MITM_SERVICE(C, H)                                                                             \
    /* Cmd 0: RegisterClient -- socket library init. Raw inline data, not a  \
       buffer (nnSdk quirk, see libnx bsd.c _bsdRegisterClient()): a 32-byte \
       LibraryConfigData blob + pid placeholder + tmem size, forwarded      \
       byte-for-byte with the real transfer memory handle re-sent through. */\
    AMS_SF_METHOD_INFO(C, H, 0,  Result, RegisterClient,                                                              \
        (ams::sf::Out<u64> out_result, const ams::mitm::bsd::LibraryConfigData &config,                               \
         const ams::sf::ClientProcessId &client_pid, u64 tmem_size, ams::sf::CopyHandle &&transfer_memory),           \
        (out_result, config, client_pid, tmem_size, std::move(transfer_memory)))                                      \
    /* Cmd 1: StartMonitoring is DELIBERATELY NOT declared here -- see       \
       ProcessMessageForMitmImpl (sf_cmif_service_dispatch.cpp): any cmd_id  \
       we don't declare gets forwarded to the real service as raw,          \
       untouched bytes via ctx.session->ForwardRequest(ctx), with no        \
       re-serialization through our own interface at all. That's the only   \
       way to get this command right: real _bsdStartMonitoring (libnx      \
       bsd.c) sends .in_send_pid=true with just an 8-byte `pid` as its      \
       entire raw payload, but declaring a ClientProcessId param (required  \
       to satisfy PrepareForProcess's meta.send_pid ==                      \
       CommandMeta::HasInProcessIdHolder check) INTRINSICALLY reserves      \
       another 8 bytes of required input size in this SF framework's own   \
       accounting (confirmed via sf_impl_command_serialization.hpp's        \
       GetUnfixedOutPointerSizeOffset = InDataSize + InHeadersSize + 0x10,  \
       and directly measured via DIAG instrumentation this session:         \
       meta_raw_size=40 vs required command_raw_size=48) -- i.e. declaring  \
       BOTH ClientProcessId AND the real pid needs 16 bytes of raw data,    \
       but the real client's message only ever carries 8. There is no      \
       interface declaration that satisfies both PrepareForProcess checks   \
       simultaneously for this specific command; only auto-forwarding      \
       avoids the conflict, since it never re-derives our own reply from a  \
       declared shape at all. (Every prior fix attempt for this command --  \
       out-param shape, in_send_pid, override_pid, adding ClientProcessId   \
       -- fixed a real, confirmed mismatch, but this was the one that       \
       actually let ldn_mitm past it without svc::ResultSessionClosed.) */  \
    AMS_SF_METHOD_INFO(C, H, 2,  Result, Socket,                                                                      \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                  \
        (out_fd, out_errno, domain, type, protocol))                                                                  \
    AMS_SF_METHOD_INFO(C, H, 3,  Result, SocketExempt,                                                                \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 domain, s32 type, s32 protocol),                  \
        (out_fd, out_errno, domain, type, protocol))                                                                  \
    /* Real bsdOpen(pathname, flags) -> _bsdDispatchIn(4, flags, ...,       \
       buffers=[pathname]): `flags` is raw in-data alongside the path       \
       buffer, not the only input. */                                      \
    AMS_SF_METHOD_INFO(C, H, 4,  Result, Open,                                                                        \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 flags, const ams::sf::InBuffer &path),            \
        (out_fd, out_errno, flags, path))                                                                             \
    /* Real bsdSelect: raw in-data is the combined {nfds,timeout} struct     \
       above (not a lone nfds scalar), and exactly 6 buffers -- the client   \
       sends readfds/writefds/exceptfds as BOTH an In and an Out buffer     \
       descriptor each (same pointer reused for both roles; select()        \
       modifies in place). `timeout` is not a buffer at all -- it's part    \
       of the combined in-data struct above. */                             \
    AMS_SF_METHOD_INFO(C, H, 5,  Result, Select,                                                                      \
        (ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, const ams::mitm::bsd::SelectInData &in_data,       \
         const ams::sf::InAutoSelectBuffer &readfds_in, const ams::sf::InAutoSelectBuffer &writefds_in,               \
         const ams::sf::InAutoSelectBuffer &errorfds_in,                                                              \
         ams::sf::OutAutoSelectBuffer readfds_out, ams::sf::OutAutoSelectBuffer writefds_out,                         \
         ams::sf::OutAutoSelectBuffer errorfds_out),                                                                  \
        (out_count, out_errno, in_data, readfds_in, writefds_in, errorfds_in,                                         \
         readfds_out, writefds_out, errorfds_out))                                                                    \
    AMS_SF_METHOD_INFO(C, H, 6,  Result, Poll,                                                                        \
        (ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, const ams::sf::InAutoSelectBuffer &fds_in,         \
         ams::sf::OutAutoSelectBuffer fds_out, s32 nfds, s32 timeout),                                                \
        (out_count, out_errno, fds_in, fds_out, nfds, timeout))                                                       \
    /* Real bsdSysctl(name,namelen,oldp,oldlenp,newp,newlen) ->             \
       _bsdDispatchOut(7, *oldlenp, buffer_attrs=[In,In,Out],              \
       buffers=[name,newp,oldp]): ZERO raw in-data (no nfds/fd/etc, only   \
       buffers), 3 buffers not 4 (there's no separate "old_val_in" -- that \
       was a phantom param that never existed on the wire), and the extra  \
       output word is the returned oldlenp (u64), not a 4th buffer. */     \
    AMS_SF_METHOD_INFO(C, H, 7,  Result, Sysctl,                                                                      \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u64> out_oldlen,                        \
         const ams::sf::InBuffer &name, const ams::sf::InBuffer &new_val, ams::sf::OutBuffer old_val_out),            \
        (out_ret, out_errno, out_oldlen, name, new_val, old_val_out))                                                 \
    AMS_SF_METHOD_INFO(C, H, 8,  Result, Recv,                                                                        \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                  \
         ams::sf::OutAutoSelectBuffer buffer),                                                                        \
        (out_size, out_errno, fd, flags, buffer))                                                                     \
    /* Cmd 9: RecvFrom -- the socket we actually care about. Wire layout    \
       (verified against libnx bsdRecvFrom / _bsdDispatchImpl): raw[0]=s32  \
       ret, raw[4]=s32 errno, raw[8]=u32 addrlen. This one was already      \
       declared in the correct ret-before-errno order. */                  \
    AMS_SF_METHOD_INFO(C, H, 9,  Result, RecvFrom,                                                                    \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen, s32 fd, s32 flags,    \
         ams::sf::OutAutoSelectBuffer buffer, ams::sf::OutAutoSelectBuffer addr_out),                                 \
        (out_ret, out_errno, out_addrlen, fd, flags, buffer, addr_out))                                               \
    AMS_SF_METHOD_INFO(C, H, 10, Result, Send,                                                                        \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                  \
         const ams::sf::InAutoSelectBuffer &buffer),                                                                  \
        (out_size, out_errno, fd, flags, buffer))                                                                     \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SendTo,                                                                      \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, s32 flags,                                  \
         const ams::sf::InAutoSelectBuffer &buffer, const ams::sf::InAutoSelectBuffer &addr),                         \
        (out_size, out_errno, fd, flags, buffer, addr))                                                               \
    /* Accept/GetPeerName/GetSockName all go through libnx's own            \
       _bsdCmdInSockfdOutSockaddr helper -- like RecvFrom, that's           \
       _bsdDispatchInOut(cmd_id, sockfd, *addrlen, ...), so the real reply  \
       is {ret, errno, addrlen}, not just {ret, errno}. (Bind/Connect use   \
       the plain _bsdCmdInSockfdSockaddr IN-only helper instead -- no      \
       addrlen out -- so those two stay 2-field.) */                       \
    AMS_SF_METHOD_INFO(C, H, 12, Result, Accept,                                                                      \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen, s32 fd,                \
         ams::sf::OutAutoSelectBuffer addr_out),                                                                      \
        (out_fd, out_errno, out_addrlen, fd, addr_out))                                                               \
    AMS_SF_METHOD_INFO(C, H, 13, Result, Bind,                                                                        \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, const ams::sf::InAutoSelectBuffer &addr),    \
        (out_ret, out_errno, fd, addr))                                                                               \
    AMS_SF_METHOD_INFO(C, H, 14, Result, Connect,                                                                     \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, const ams::sf::InAutoSelectBuffer &addr),    \
        (out_ret, out_errno, fd, addr))                                                                               \
    AMS_SF_METHOD_INFO(C, H, 15, Result, GetPeerName,                                                                 \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen, s32 fd,               \
         ams::sf::OutAutoSelectBuffer addr_out),                                                                      \
        (out_ret, out_errno, out_addrlen, fd, addr_out))                                                              \
    AMS_SF_METHOD_INFO(C, H, 16, Result, GetSockName,                                                                 \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_addrlen, s32 fd,               \
         ams::sf::OutAutoSelectBuffer addr_out),                                                                      \
        (out_ret, out_errno, out_addrlen, fd, addr_out))                                                              \
    /* bsdGetSockOpt: _bsdDispatchInOut(17, in, *optlen, ...) -- same       \
       {ret, errno, extra} shape (extra = returned option length). */      \
    AMS_SF_METHOD_INFO(C, H, 17, Result, GetSockOpt,                                                                  \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, ams::sf::Out<u32> out_optlen, s32 fd, s32 level,     \
         s32 optname, ams::sf::OutAutoSelectBuffer optval),                                                           \
        (out_ret, out_errno, out_optlen, fd, level, optname, optval))                                                 \
    AMS_SF_METHOD_INFO(C, H, 18, Result, Listen,                                                                      \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 backlog),                                \
        (out_ret, out_errno, fd, backlog))                                                                            \
    /* Real bsdIoctl ALWAYS sends 4 in-attributed + 4 out-attributed buffer  \
       descriptors (bsd.c bufcount handling for SIOCGIFCONF/SIOCGIFMEDIA/   \
       SIOCGIFXMEDIA use 2 of each; the generic IOC_IN/IOC_OUT case uses    \
       just 1; the rest are always-present {NULL,0} descriptors) -- not     \
       the single in/out buffer pair this project declared before, which   \
       would misalign every buffer after the first for any real call. */   \
    AMS_SF_METHOD_INFO(C, H, 19, Result, Ioctl,                                                                       \
        (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd, u32 request, u32 bufcount,                \
         const ams::sf::InAutoSelectBuffer &buf_in1, const ams::sf::InAutoSelectBuffer &buf_in2,                      \
         const ams::sf::InAutoSelectBuffer &buf_in3, const ams::sf::InAutoSelectBuffer &buf_in4,                      \
         ams::sf::OutAutoSelectBuffer buf_out1, ams::sf::OutAutoSelectBuffer buf_out2,                                \
         ams::sf::OutAutoSelectBuffer buf_out3, ams::sf::OutAutoSelectBuffer buf_out4),                               \
        (out_result, out_errno, fd, request, bufcount, buf_in1, buf_in2, buf_in3, buf_in4,                            \
         buf_out1, buf_out2, buf_out3, buf_out4))                                                                     \
    AMS_SF_METHOD_INFO(C, H, 20, Result, Fcntl,                                                                       \
        (ams::sf::Out<s32> out_result, ams::sf::Out<s32> out_errno, s32 fd, s32 cmd, s32 arg),                        \
        (out_result, out_errno, fd, cmd, arg))                                                                        \
    AMS_SF_METHOD_INFO(C, H, 21, Result, SetSockOpt,                                                                  \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 level, s32 optname,                      \
         const ams::sf::InAutoSelectBuffer &optval),                                                                  \
        (out_ret, out_errno, fd, level, optname, optval))                                                             \
    AMS_SF_METHOD_INFO(C, H, 22, Result, Shutdown,                                                                    \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd, s32 how),                                    \
        (out_ret, out_errno, fd, how))                                                                                \
    /* Real bsdShutdownAllSockets(int how) (libnx bsd.c) sends only `how` -- \
       no pid in the request wire data (ldn_mitm never had one to send). */  \
    AMS_SF_METHOD_INFO(C, H, 23, Result, ShutdownAllSockets,                                                          \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 how),                                            \
        (out_ret, out_errno, how))                                                                                    \
    AMS_SF_METHOD_INFO(C, H, 24, Result, Write,                                                                       \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, const ams::sf::InAutoSelectBuffer &buffer), \
        (out_size, out_errno, fd, buffer))                                                                            \
    AMS_SF_METHOD_INFO(C, H, 25, Result, Read,                                                                        \
        (ams::sf::Out<s32> out_size, ams::sf::Out<s32> out_errno, s32 fd, ams::sf::OutAutoSelectBuffer buffer),       \
        (out_size, out_errno, fd, buffer))                                                                            \
    AMS_SF_METHOD_INFO(C, H, 26, Result, Close,                                                                       \
        (ams::sf::Out<s32> out_ret, ams::sf::Out<s32> out_errno, s32 fd), (out_ret, out_errno, fd))                   \
    AMS_SF_METHOD_INFO(C, H, 27, Result, DuplicateSocket,                                                             \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, s32 fd, u64 target_pid),                              \
        (out_fd, out_errno, fd, target_pid))                                                                          \
    AMS_SF_METHOD_INFO(C, H, 28, Result, GetResourceStatistics,                                                       \
        (ams::sf::Out<s32> out_errno, ams::sf::OutBuffer out_stats, u64 pid), (out_errno, out_stats, pid))            \
    AMS_SF_METHOD_INFO(C, H, 29, Result, RecvMMsg,                                                                    \
        (ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags, s32 timeout,          \
         ams::sf::OutAutoSelectBuffer out_data),                                                                      \
        (out_count, out_errno, fd, vlen, flags, timeout, out_data), ams::hos::Version_3_0_0)                          \
    AMS_SF_METHOD_INFO(C, H, 30, Result, SendMMsg,                                                                    \
        (ams::sf::Out<s32> out_count, ams::sf::Out<s32> out_errno, s32 fd, s32 vlen, s32 flags,                       \
         const ams::sf::InAutoSelectBuffer &in_data),                                                                 \
        (out_count, out_errno, fd, vlen, flags, in_data), ams::hos::Version_3_0_0)                                    \
    AMS_SF_METHOD_INFO(C, H, 31, Result, EventFd,                                                                     \
        (ams::sf::Out<s32> out_fd, ams::sf::Out<s32> out_errno, u64 initval, s32 flags),                              \
        (out_fd, out_errno, initval, flags), ams::hos::Version_7_0_0)                                                 \
    AMS_SF_METHOD_INFO(C, H, 32, Result, RegisterResourceStatisticsName,                                              \
        (ams::sf::Out<s32> out_errno, u64 pid, const ams::sf::InBuffer &name),                                        \
        (out_errno, pid, name), ams::hos::Version_15_0_0)                                                             \
    AMS_SF_METHOD_INFO(C, H, 33, Result, RegisterClientShared,                                                        \
        (ams::sf::Out<u64> out_result, const ams::mitm::bsd::LibraryConfigData &config,                               \
         const ams::sf::ClientProcessId &client_pid, u64 tmem_size),                                                  \
        (out_result, config, client_pid, tmem_size), ams::hos::Version_10_0_0)

AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::bsd, IBsdBridgeService, AMS_SLP_NX_BSD_MITM_SERVICE, 0xB51D9E01)
