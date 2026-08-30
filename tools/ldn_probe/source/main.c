// ldn_probe -- a minimal LDN control-plane exerciser.
//
// The point of this tool is that ONE binary runs in two very different
// places and drives the same ldn:u surface in both:
//
//   real console : ldn_probe -> ldn:u -> ldn_mitm -> bsd:u -> slp-nx -> relay
//   Eden         : ldn_probe -> HLE ldn:u -> LANDiscovery -> helper -> relay
//
// Both ends meet at the switch-lan-play relay, so if one side hosts and the
// other's scan lists that network, the whole bridge is proven end to end.
//
// It deliberately stops at the LDN control plane and never opens a gameplay
// socket, so nothing here needs Pia -- which is exactly the wall every
// scripted fake host has hit. A network appearing in a scan, and a node
// count going up on the host, is the entire success condition.
//
// IPC goes through ldn_raw.c rather than libnx's ldn* wrappers; see the
// comment at the top of ldn_raw.h for why.

#include <stdio.h>
#include <string.h>
#include <switch.h>

#include "ldn_raw.h"

// Arbitrary, but fixed on both sides so probe networks are easy to pick out
// of a scan that may also contain real games. Reads as "LDN_PROB" in a hexdump.
#define PROBE_LOCAL_COMM_ID 0x4C444E5F50524F42LL

#define MAX_SCAN 8

static LdnNetworkInfo g_scan[MAX_SCAN];
static s32  g_scan_count = 0;
static char g_status[256] = "ready";
static bool g_init_ok = false;

static const char *state_name(u32 s) {
    switch (s) {
        case 0:  return "None";
        case 1:  return "Initialized";
        case 2:  return "AccessPoint";
        case 3:  return "AccessPointCreated";
        case 4:  return "Station";
        case 5:  return "StationConnected";
        case 6:  return "Error";
        default: return "?";
    }
}

static void set_status(const char *what, Result rc) {
    if (R_SUCCEEDED(rc)) {
        snprintf(g_status, sizeof(g_status), "%s: OK", what);
    } else {
        snprintf(g_status, sizeof(g_status), "%s: FAILED rc=0x%08X (mod=%d desc=%d)",
                 what, (unsigned)rc, (int)R_MODULE(rc), (int)R_DESCRIPTION(rc));
    }
}

static void fill_common(LdnSecurityConfig *sec, LdnUserConfig *user) {
    memset(sec, 0, sizeof(*sec));
    sec->security_mode = 1; // Product
    // passphrase_size must be 0x10-0x40. Neither ldn_mitm nor Eden does real
    // LDN key derivation, so the content only has to match on both sides.
    sec->passphrase_size = 0x10;
    memcpy(sec->passphrase, "ldn_probe_pass!!", 0x10);

    memset(user, 0, sizeof(*user));
    snprintf(user->user_name, sizeof(user->user_name), "ldn_probe");
}

static void do_host(void) {
    LdnRawCreateNetworkConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    fill_common(&cfg.security_config, &cfg.user_config);
    cfg.network_config.intent_id.local_communication_id = PROBE_LOCAL_COMM_ID;
    cfg.network_config.intent_id.scene_id = 0;
    cfg.network_config.channel = 0;   // overwritten by CreateNetwork anyway
    cfg.network_config.node_count_max = 8;
    cfg.network_config.local_communication_version = 1;

    Result rc = ldnRawOpenAccessPoint();
    if (R_FAILED(rc)) { set_status("OpenAccessPoint", rc); return; }

    rc = ldnRawCreateNetwork(&cfg);
    if (R_FAILED(rc)) { set_status("CreateNetwork", rc); return; }

    // Something non-zero so the advertise path is exercised too. This is also
    // the second updateNodes() of the pair that coalesces into one TCP
    // segment -- the case the bridge's receive-stream reassembly handles.
    static const u8 advert[] = "ldn_probe advertise";
    rc = ldnRawSetAdvertiseData(advert, sizeof(advert));
    set_status("Host up (CreateNetwork+Advertise)", rc);
}

static void do_scan(void) {
    u32 st = 0;
    ldnRawGetState(&st);

    if (st == 1) { // Initialized
        Result rc = ldnRawOpenStation();
        if (R_FAILED(rc)) { set_status("OpenStation", rc); return; }
    }

    LdnScanFilter filter;
    memset(&filter, 0, sizeof(filter));
    // flags = 0: no filtering. A diagnostic wants to see every network on the
    // relay, including real games, not just our own.
    filter.flags = 0;

    g_scan_count = 0;
    memset(g_scan, 0, sizeof(g_scan));
    Result rc = ldnRawScan(0, &filter, g_scan, MAX_SCAN, &g_scan_count);
    if (R_FAILED(rc)) { set_status("Scan", rc); g_scan_count = 0; return; }

    snprintf(g_status, sizeof(g_status), "Scan: OK, %d network(s)", (int)g_scan_count);
}

static void do_join(int index) {
    if (index < 0 || index >= g_scan_count) {
        snprintf(g_status, sizeof(g_status), "Join: nothing at slot %d", index);
        return;
    }

    LdnRawConnectNetworkData d;
    memset(&d, 0, sizeof(d));
    fill_common(&d.security_config, &d.user_config);
    d.local_communication_version = 1;
    d.option = 0;

    Result rc = ldnRawConnect(&d, &g_scan[index]);
    set_status("Connect", rc);
}

static void do_leave(void) {
    u32 st = 0;
    ldnRawGetState(&st);

    if (st == 5) {          // StationConnected
        set_status("Disconnect", ldnRawDisconnect());
    } else if (st == 3) {   // AccessPointCreated
        set_status("DestroyNetwork", ldnRawDestroyNetwork());
    } else {
        snprintf(g_status, sizeof(g_status), "Leave: nothing to leave (state %s)",
                 state_name(st));
    }
}

static void draw(void) {
    u32 st = 0;
    // Surface these rather than swallowing them. Rendering a dead session as
    // "None"/"(none)" hid a session-closed error behind what looked like an
    // ordinary idle state.
    Result rc_state = ldnRawGetState(&st);

    printf("\x1b[2J\x1b[H");
    printf("ldn_probe -- LDN control-plane exerciser\n");
    printf("=======================================\n\n");
    if (R_SUCCEEDED(rc_state))
        printf("state : %s\n", state_name(st));
    else
        printf("state : <GetState failed 0x%08X mod=%d desc=%d>\n",
               (unsigned)rc_state, (int)R_MODULE(rc_state), (int)R_DESCRIPTION(rc_state));

    u32 addr = 0, mask = 0;
    Result rc_ip = ldnRawGetIpv4Address(&addr, &mask);
    if (R_SUCCEEDED(rc_ip)) {
        printf("addr  : %u.%u.%u.%u\n",
               (addr >> 24) & 0xFF, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
    } else {
        printf("addr  : <failed 0x%08X>\n", (unsigned)rc_ip);
    }

    if (R_SUCCEEDED(rc_state) && (st == 3 || st == 5)) {
        LdnNetworkInfo info;
        memset(&info, 0, sizeof(info));
        Result rc_ni = ldnRawGetNetworkInfo(&info);
        if (R_FAILED(rc_ni))
            printf("netinfo: <failed 0x%08X mod=%d desc=%d>\n",
                   (unsigned)rc_ni, (int)R_MODULE(rc_ni), (int)R_DESCRIPTION(rc_ni));
        if (R_SUCCEEDED(rc_ni)) {
            printf("nodes : %d/%d   ssid: %.32s\n",
                   (int)info.node_count, (int)info.node_count_max, info.common.ssid.str);
            for (int i = 0; i < info.node_count && i < 8; i++) {
                const LdnNodeInfo *n = &info.nodes[i];
                u32 a = n->ip_addr.addr;
                printf("  [%d] %-16.16s %u.%u.%u.%u %s\n", (int)n->node_id, n->user_name,
                       (a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                       n->is_connected ? "connected" : "-");
            }
        }
    }

    if (g_scan_count > 0) {
        printf("\nscan results:\n");
        for (int i = 0; i < g_scan_count; i++) {
            const LdnNetworkInfo *n = &g_scan[i];
            printf("  [%d] ssid=%-20.20s nodes=%d lcid=%016llX\n", i,
                   n->common.ssid.str, (int)n->node_count,
                   (unsigned long long)n->network_id.intent_id.local_communication_id);
        }
    }

    printf("\nstatus: %s\n", g_status);
    if (g_init_ok)
        printf("\n[A] host   [B] scan   [X] join #0   [Y] leave   [+] exit\n");
    else
        printf("\nldn not initialized -- [+] exit\n");
    consoleUpdate(NULL);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    consoleInit(NULL);

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    Result rc = ldnRawInitialize();
    g_init_ok = R_SUCCEEDED(rc);
    set_status("ldnRawInitialize", rc);

    while (appletMainLoop()) {
        padUpdate(&pad);
        const u64 down = padGetButtonsDown(&pad);

        if (down & HidNpadButton_Plus) break;
        // Without a session every call just returns 0xE401 (invalid handle),
        // which buries the real error from init under noise.
        if (g_init_ok) {
            if (down & HidNpadButton_A) do_host();
            if (down & HidNpadButton_B) do_scan();
            if (down & HidNpadButton_X) do_join(0);
            if (down & HidNpadButton_Y) do_leave();
        }

        draw();
    }

    ldnRawExit();
    consoleExit(NULL);
    return 0;
}
