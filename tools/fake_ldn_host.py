#!/usr/bin/env python3
"""Host a fake LDN lobby for any title, against either a real slp relay OR
switch-lan-play-nx's ZeroTier broadcast transport, using LdnNode
(slp_ldn.py, adapted from sys-slp-client's spike/slp_ldn.py). Consolidates
what were three near-duplicate per-game scripts (D3/Torchlight II/WWZ) into
one reusable tool.

ZeroTier mode (--zt-ip): join the same ZeroTier network the console's
switch-lan-play-nx is configured for (see source/cfg/runtime_cfg.hpp's
DefaultNetworkId) with the official ZeroTier client on this machine, find
your own assigned IPv4 on that network (`zerotier-cli listnetworks`), and
pass it as --zt-ip. This machine then broadcasts LDN control frames
directly to every console on the network, exactly like ZtBridge
(source/zt_bridge.hpp) does -- no relay server involved at all.

local_comm_id defaults to the title's own program_id, which is the
convention every title tested this session actually uses (confirmed via
each console's own trace log: "BSD ShouldMitm ... program_id=0x...").

Caveat: LdnNode builds a generic, protocol-valid NetworkInfo. It will
answer a real Scan() and register on the relay, but a game's own UI may
still filter on game-specific advertise_data fields this generic host
doesn't populate -- confirmed with Diablo III and Torchlight II (the
sysmodule correctly returned the result, the game just didn't render it).
MK8DX (with demo_host.py's game-specific reply tuning, not this tool) DID
render correctly, so how far this gets you is genuinely game-dependent.

Usage:
    python3 tools/fake_ldn_host.py <lcid_hex> [--name NAME] [--relay HOST] \
        [--port PORT] [--ip A.B.C.D] [--max N]
    python3 tools/fake_ldn_host.py <lcid_hex> --zt-ip A.B.C.D [--zt-port PORT] \
        [--name NAME] [--ip A.B.C.D] [--max N]

Examples:
    # Diablo III, against tekn0 (classic relay mode)
    python3 tools/fake_ldn_host.py 0x01001b300b9be000 --name luigi \
        --relay tekn0.net --max 4

    # World War Z, against the local relay (defaults)
    python3 tools/fake_ldn_host.py 0x010099f013898000 --name WWZ-FAKE

    # World War Z, over ZeroTier (this machine's own ZT address is
    # 10.244.1.50 on the console's configured network)
    python3 tools/fake_ldn_host.py 0x010099f013898000 --name WWZ-FAKE \
        --zt-ip 10.244.1.50
"""
import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "spike"))
import slp_ldn as ldn


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        print(f"[fake-host] could not resolve {host!r}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lcid", help="local_comm_id / program_id, hex (e.g. 0x010099f013898000)")
    ap.add_argument("--name", default="FAKE-HOST", help="room/player name shown in-game")
    ap.add_argument("--relay", default="127.0.0.1", help="relay hostname or IP (default: local); ignored if --zt-ip is given")
    ap.add_argument("--port", type=int, default=11451, help="relay port (default: 11451); ignored if --zt-ip is given")
    ap.add_argument("--zt-ip", default=None,
                     help="switch to ZeroTier broadcast mode: this machine's own ZeroTier-assigned "
                          "IPv4 on the console's network (see `zerotier-cli listnetworks`). Overrides --relay/--port.")
    ap.add_argument("--zt-port", type=int, default=45455,
                     help="ZtBridge's broadcast port (default: 45455, matches ZT_BRIDGE_PORT in "
                          "source/zt_bridge.hpp -- only change this if that constant changes)")
    ap.add_argument("--ip", default="10.13.200.77",
                     help="our virtual LAN IP embedded in the fake LDN NetworkInfo, dotted quad "
                          "(default: 10.13.200.77) -- unrelated to --zt-ip, same distinction as "
                          "ZtBridge's own local_ip vs. its ZeroTier envelope address")
    ap.add_argument("--max", type=int, default=8, dest="node_count_max",
                     help="max players advertised (default: 8)")
    ap.add_argument("--advertise-len", type=int, default=0,
                     help="pad advertiseData to N zero bytes (0-384, default: 0). "
                          "Diagnostic only: this is NOT the game's real advertise_data "
                          "format, just a non-zero-length placeholder to test whether a "
                          "title's lobby list gates on advertiseDataSize > 0 alone or "
                          "actually validates the content (a real host was observed with "
                          "advertiseDataLen=384; this tool otherwise always sends 0). "
                          "Ignored if --mk8dx-appdata is given.")
    ap.add_argument("--mk8dx-appdata", action="store_true",
                     help="populate advertiseData with MK8DX's real app-data layout "
                          "(kinnay 'LDN Application Data (Pia)': 1B unknown + 33B "
                          "nickname + 2B padding + 88B Mii info + 4B unknown = 128B), "
                          "using --name as the nickname. Without this, MK8DX's own "
                          "in-game lobby UI won't show a name at all -- it reads the "
                          "nickname from here, not from NodeInfo.userName. Layout "
                          "verified against kartlanpwn/CVE-2024-45200 (sys-slp-client/"
                          "spike/slp_fake_player.py's build_app_data()).")
    ap.add_argument("--security-mode", type=int, default=0,
                     help="LdnNetworkInfo.securityMode (default: 0). MK8DX's own real "
                          "CreateNetwork was captured at securityMode=1 -- a generic host "
                          "defaulting to 0 mismatches it.")
    ap.add_argument("--lcv", type=int, default=6,
                     help="localCommunicationVersion (default: 6). A mismatch here is "
                          "confirmed to produce MK8DX's own \"software versions don't "
                          "match\" join error -- its real CreateNetwork was captured at "
                          "lcv=14, not this tool's default of 6.")
    args = ap.parse_args()

    lcid = int(args.lcid, 16)
    fake_ip = [int(o) for o in args.ip.split(".")]

    if args.zt_ip is not None:
        relay = ("255.255.255.255", args.zt_port)
        bind_ip = args.zt_ip
        print(f"[fake-host] ZeroTier broadcast mode: bind={bind_ip} broadcast_port={args.zt_port}")
    else:
        relay = (resolve(args.relay), args.port)
        bind_ip = None

    node = ldn.LdnNode(fake_ip, args.name, relay, bind_ip=bind_ip)
    node.state = ldn.STATE_INITIALIZED
    node.open_access_point()
    node.create_network(local_comm_id=lcid, node_count_max=args.node_count_max,
                        security_mode=args.security_mode, lcv=args.lcv)
    if args.mk8dx_appdata:
        # Verbatim templates from three independent real MK8DX captures
        # (two named "Link", one named "DEV-TESTS", one an older 384-byte
        # spike capture) that all matched byte-for-byte except two
        # session-random 4-byte fields at 0x00 and 0x0C. The "no name"
        # UTF-16LE string at 0x4C and the whole structured block at
        # 0x60-0x97 (game rule/capability table) are confirmed
        # fixed/game-constant across all three, not guesses. When hosting
        # under one of these exact names, use its own real capture
        # untouched; for any other name, patch the name field (relative
        # offset 25, 33-byte zero-padded, same width as NodeInfo.userName)
        # into the closest template.
        REAL_APPDATA_TEMPLATES = {
            "Link": bytes.fromhex(
                "028cc6020000000002180000cc108c990000000000000000014c696e6b"
                "0000000000000000000000000000000000000000000000000000000000"
                "a494b3680424fffd4f95a754c0198e2cb11f6e006f0020006e0061006d00"
                "6500000000000000000000000040400000000100002101000208040304"
                "020c0601040306020a010409171304030d080000040a0008040a0004021"
                "40001000000"
            ),
            "DEV-TESTS": bytes.fromhex(
                "19aa44080000000002180000183b37320000000000000000014445562d"
                "5445535453000000000000000000000000000000000000000000000000"
                "677e307bddbf38c44183ae659e29ab68e3036e006f0020006e0061006d00"
                "6500000000000000000000000040400000000100002101000208040304"
                "020c0601040306020a010409171304030d080000040a0008040a0004021"
                "40001000000"
            ),
        }
        if args.name in REAL_APPDATA_TEMPLATES:
            appdata = REAL_APPDATA_TEMPLATES[args.name]
            print(f"[fake-host] advertiseData set from real MK8DX capture for "
                  f"{args.name!r} (exact, untouched, {len(appdata)}B)")
        else:
            template = REAL_APPDATA_TEMPLATES["Link"]
            name_b = args.name.encode("utf-8")[:33]
            buf = bytearray(template)
            buf[25:25 + 33] = name_b.ljust(33, b"\x00")
            appdata = bytes(buf)
            print(f"[fake-host] advertiseData set from real MK8DX template with "
                  f"name patched ({len(appdata)}B), nickname={args.name!r}")
        node.network_info["advertise"] = appdata
    elif args.advertise_len > 0:
        adv_len = min(args.advertise_len, 384)
        node.network_info["advertise"] = bytes(adv_len)
        print(f"[fake-host] advertiseData padded to {adv_len} zero bytes (diagnostic, not real game data)")
    via = f"ZeroTier broadcast {relay[0]}:{relay[1]} (bound {bind_ip})" if args.zt_ip is not None \
        else f"relay {relay[0]}:{relay[1]}"
    print(f"[fake-host] hosting '{args.name}' (max {args.node_count_max}) at "
          f"{args.ip} lcid=0x{lcid:016x} via {via}")
    print("[fake-host] scan/search for a lobby on the console now. Ctrl-C to stop.")
    last_node_count = node.network_info.get("node_count", 1)
    try:
        while True:
            node.keepalive()
            time.sleep(2)
            cur_count = node.network_info.get("node_count", 1)
            if cur_count != last_node_count:
                print(f"[fake-host] node_count changed {last_node_count} -> {cur_count}")
                for n in node.network_info.get("nodes", []):
                    if not n.get("is_connected") and n is not node.network_info["nodes"][0]:
                        continue
                    ip = ".".join(str(o) for o in n["ip"])
                    print(f"    node {n['node_id']}: {n['name']!r} @ {ip} "
                          f"connected={n['is_connected']} lcv={n['lcv']}")
                last_node_count = cur_count
    except KeyboardInterrupt:
        print("\n[fake-host] stopping")
    finally:
        node.destroy_network()
        node.close_access_point()
        node.close()


if __name__ == "__main__":
    main()
