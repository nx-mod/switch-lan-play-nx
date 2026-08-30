#!/usr/bin/env python3
"""Scan-only LDN probe from the PC side, against a switch-lan-play relay.

Deliberately does not join -- this is just "can the PC see what the console
is advertising", which is the first half of proving the bridge end to end.
"""
import os, sys, time, argparse

# slp_ldn.py lives one level up, in switch-lan-play-nx/tools -- keep this
# relative so the probe stays self-contained inside this repo.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import slp_ldn  # noqa: E402
from slp_ldn import LdnNode, network_id_of  # noqa: E402


def ip_str(raw):
    return ".".join(str(b) for b in raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--relay", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11451)
    ap.add_argument("--ip", default="10.13.200.78")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()

    my_ip = bytes(int(x) for x in a.ip.split("."))
    node = LdnNode(my_ip, "PC-SCAN", (a.relay, a.port))
    # __init__ leaves state at STATE_NONE -- fake_ldn_host.py/fake_ldn_join.py
    # both do this same thing right after construction. There is no separate
    # "initialize" call in LdnNode; this stands in for it.
    node.state = slp_ldn.STATE_INITIALIZED
    print("PC node {} -> relay {}:{}".format(ip_str(my_ip), a.relay, a.port))

    try:
        node.open_station()
        for r in range(1, a.rounds + 1):
            results = node.scan(timeout=a.timeout)
            print("\n--- round {} : {} network(s) ---".format(r, len(results)))
            for i, info in enumerate(results):
                ssid = bytes(info["ssid"]).split(b"\0")[0].decode("ascii", "replace") \
                    if isinstance(info.get("ssid"), (bytes, bytearray)) else info.get("ssid")
                print("  [{}] ssid={!r} nodes={} lcid=0x{:016X}".format(
                    i, ssid, info.get("node_count"), network_id_of(info)))
                for n in info.get("nodes", [])[: info.get("node_count", 0)]:
                    ip = n.get("ip")
                    print("       node{} {} ip={} connected={}".format(
                        n.get("node_id"), repr(n.get("name")),
                        ip_str(ip) if isinstance(ip, (bytes, bytearray)) else ip,
                        n.get("is_connected")))
            if not results:
                print("  (nothing seen)")
            time.sleep(0.5)
    finally:
        node.close()


if __name__ == "__main__":
    main()
