#!/usr/bin/env python3
"""Join a fake (or real) LDN lobby as a station, against either a real slp
relay OR switch-lan-play-nx's ZeroTier broadcast transport, using LdnNode
(slp_ldn.py). The join-side counterpart to fake_ldn_host.py -- scans for a
lobby by local_comm_id, connects to the first match, and reports the
resulting NetworkInfo (host name, node count, per-node IPs) so you can
verify a join actually completes without needing a second real console.

ZeroTier mode (--zt-ip): same as fake_ldn_host.py -- join the same
ZeroTier network the console's switch-lan-play-nx is configured for, find
your own assigned IPv4 on that network (`zerotier-cli listnetworks`), and
pass it as --zt-ip.

local_comm_id defaults to the title's own program_id (same convention as
fake_ldn_host.py) -- confirmed via each console's own trace log:
"BsdBridge ShouldMitm ... program_id=0x...".

Usage:
    python3 tools/fake_ldn_join.py <lcid_hex> [--name NAME] [--relay HOST] \
        [--port PORT] [--ip A.B.C.D] [--scan-timeout S] [--connect-timeout S] \
        [--hold S]
    python3 tools/fake_ldn_join.py <lcid_hex> --zt-ip A.B.C.D [--zt-port PORT] \
        [--name NAME] [--ip A.B.C.D]

Examples:
    # Mario Kart 8 Deluxe, against tekn0 (classic relay mode)
    python3 tools/fake_ldn_join.py 0x0100152000022000 --name FAKE-JOIN \
        --relay tekn0.net

    # World War Z, against the local relay (defaults)
    python3 tools/fake_ldn_join.py 0x010099f013898000 --name WWZ-JOIN

    # Over ZeroTier (this machine's own ZT address is 10.244.1.51 on the
    # console's configured network)
    python3 tools/fake_ldn_join.py 0x010099f013898000 --name WWZ-JOIN \
        --zt-ip 10.244.1.51
"""
import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import slp_ldn as ldn


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        print(f"[fake-join] could not resolve {host!r}: {e}", file=sys.stderr)
        sys.exit(1)


def fmt_ip(b):
    return ".".join(str(o) for o in b)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lcid", help="local_comm_id / program_id, hex (e.g. 0x0100152000022000)")
    ap.add_argument("--name", default="FAKE-JOIN", help="player name shown in-game")
    ap.add_argument("--relay", default="127.0.0.1", help="relay hostname or IP (default: local); ignored if --zt-ip is given")
    ap.add_argument("--port", type=int, default=11451, help="relay port (default: 11451); ignored if --zt-ip is given")
    ap.add_argument("--zt-ip", default=None,
                     help="switch to ZeroTier broadcast mode: this machine's own ZeroTier-assigned "
                          "IPv4 on the console's network (see `zerotier-cli listnetworks`). Overrides --relay/--port.")
    ap.add_argument("--zt-port", type=int, default=45455,
                     help="ZtBridge's broadcast port (default: 45455, matches ZT_BRIDGE_PORT in "
                          "source/zt_bridge.hpp -- only change this if that constant changes)")
    ap.add_argument("--ip", default="10.13.200.78",
                     help="our virtual LAN IP embedded in our own NodeInfo when connecting, "
                          "dotted quad (default: 10.13.200.78 -- one past fake_ldn_host.py's "
                          "default of .77 so the two don't collide if run against each other "
                          "on the same box)")
    ap.add_argument("--scan-timeout", type=float, default=2.0,
                     help="seconds to wait for ScanResp replies (default: 2.0)")
    ap.add_argument("--connect-timeout", type=float, default=3.0,
                     help="seconds to wait for SyncNetwork after sending Connect (default: 3.0)")
    ap.add_argument("--index", type=int, default=0,
                     help="if multiple lobbies match lcid, which scan result to join (default: 0, the first)")
    ap.add_argument("--hold", type=float, default=30.0,
                     help="seconds to stay connected after a successful join, sending "
                          "keepalives, before disconnecting (default: 30). Ctrl-C to stop "
                          "early or hold indefinitely with a very large value -- this is what "
                          "gives switch-lan-play-nx's own bridge time to actually exchange "
                          "data with the real host, not just complete the handshake.")
    ap.add_argument("--exchange-interval", type=float, default=0.5,
                     help="seconds between each ongoing send/receive exchange against the "
                          "host after joining (default: 0.5). The joiner keeps re-sending its "
                          "own node state over the per-station TCP session AND drains whatever "
                          "the host broadcasts back -- real two-way traffic, not just idle.")
    args = ap.parse_args()

    lcid = int(args.lcid, 16)
    fake_ip = [int(o) for o in args.ip.split(".")]

    if args.zt_ip is not None:
        relay = ("255.255.255.255", args.zt_port)
        bind_ip = args.zt_ip
        print(f"[fake-join] ZeroTier broadcast mode: bind={bind_ip} broadcast_port={args.zt_port}")
    else:
        relay = (resolve(args.relay), args.port)
        bind_ip = None

    node = ldn.LdnNode(fake_ip, args.name, relay, bind_ip=bind_ip)
    node.state = ldn.STATE_INITIALIZED
    node.open_station()

    via = f"ZeroTier broadcast {relay[0]}:{relay[1]} (bound {bind_ip})" if args.zt_ip is not None \
        else f"relay {relay[0]}:{relay[1]}"
    print(f"[fake-join] scanning for lcid=0x{lcid:016x} via {via} "
          f"(timeout {args.scan_timeout}s)...")

    try:
        results = node.scan(timeout=args.scan_timeout, local_comm_id=lcid)
        if not results:
            print("[fake-join] no lobby found -- nothing advertising this lcid replied to Scan")
            sys.exit(1)

        print(f"[fake-join] found {len(results)} lobby(ies):")
        for i, info in enumerate(results):
            host = info["nodes"][0] if info["nodes"] else None
            host_desc = f"{host['name']!r} @ {fmt_ip(host['ip'])}" if host else "?"
            print(f"    [{i}] ssid={info['ssid']!r} host={host_desc} "
                  f"nodes={info['node_count']}/{info['node_count_max']} "
                  f"advertise_len={len(info['advertise'])}")

        if args.index >= len(results):
            print(f"[fake-join] --index {args.index} out of range (only {len(results)} result(s))")
            sys.exit(1)

        target = results[args.index]
        host_ip = fmt_ip(target["nodes"][0]["ip"]) if target["nodes"] else "?"
        print(f"[fake-join] connecting to [{args.index}] at {host_ip} "
              f"(timeout {args.connect_timeout}s)...")

        ok = node.connect(target, timeout=args.connect_timeout)
        if not ok:
            print(f"[fake-join] FAILED to reach StationConnected "
                  f"(ended in state {node.state}, disconnect_reason={node.disconnect_reason})")
            sys.exit(1)

        info = node.network_info
        print(f"[fake-join] JOINED. state=STATION_CONNECTED "
              f"node_count={info['node_count']}/{info['node_count_max']}")
        for n in info["nodes"]:
            print(f"    node {n['node_id']}: {n['name']!r} @ {fmt_ip(n['ip'])} "
                  f"connected={n['is_connected']} lcv={n['lcv']}")

        print(f"[fake-join] holding connection for {args.hold}s "
              f"(exchanging both ways with the host; Ctrl-C to stop early)...")
        end = time.time() + args.hold
        while time.time() < end:
            # Ongoing two-way exchange: keep re-sending our own node state to the
            # host over the per-station TCP session AND drain anything the host
            # broadcasts/sends back -- so we're genuinely RECEIVING, not just
            # idling ("send and wait, nothing returned").
            before = node.lan_events
            node.station_exchange()
            recv = node.lan_events - before
            node.recv_next()
            print(f"[fake-join] exchange both ways "
                  f"(sent node state, drained {recv} event(s) from host), "
                  f"state={node.state}")
            time.sleep(args.exchange_interval)
            if node.state != ldn.STATE_STATION_CONNECTED:
                print(f"[fake-join] dropped out of STATION_CONNECTED "
                      f"(now state={node.state}, disconnect_reason={node.disconnect_reason})")
                break
    except KeyboardInterrupt:
        print("\n[fake-join] stopping")
    finally:
        node.disconnect()
        node.close_station()
        node.close()


if __name__ == "__main__":
    main()
