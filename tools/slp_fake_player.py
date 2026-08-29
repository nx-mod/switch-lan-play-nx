#!/usr/bin/env python3
"""
sys-slp-client — laptop "fake LAN player" for MK8DX end-to-end verification.

Acts as an MK8DX LAN-mode room HOST over the slp relay, so a console running
MK8DX in LAN mode (with our bsd:u MITM + tunnel) should see it in the "LAN
Play" browser. This verifies the whole M2 path without any console involvement
on the laptop side: relay -> tunnel -> console and console -> tunnel -> relay.

How MK8DX LAN browsing works (kinnay/NintendoClients "LAN Protocol"):
  - The console opens a UDP socket on the virtual LAN IP :30000 and broadcasts
    a Browse Request (packet type 0, plaintext, NOT a Pia packet).
  - The room host replies with a Browse Reply (packet type 1, sent 3x) as a
    unicast to the requester's :30000. It is plaintext too.
  - Pia session traffic (ports 49152-49155) is encrypted with the session key;
    a fake host cannot decrypt it, so we only speak the :30000 browse protocol.

Over the relay, the console's broadcast arrives here as an slp Ipv4 frame
([0x01] + IPv4 + UDP, dst 255.255.255.255:30000). We reply with a crafted
Browse Reply (benign room advertisement) wrapped in IPv4+UDP -> slp Ipv4 frame
with dst = the console's virtual IP; the relay's src-IP cache unicasts it back.

Usage:
    python3 spike/slp_fake_player.py [server_port]
        --name NAME      player/room name shown in the LAN browser (default "SP-FAKE")
        --ip IP          our virtual LAN IP, same /24 as the console (default 10.13.37.100)
        --relay HOST     relay host (default 127.0.0.1)
        --safe-appdata   set app-data length > 150 so MK8DX <= 3.0.1 (CVE-2024-45200)
                         skips the vulnerable memcpy. Use if the test console is
                         running an unpatched MK8DX build. Default (128) displays
                         the room correctly on patched (>= 3.0.3) builds.

Verify:
  1. run this on the laptop against the relay
  2. on the console open MK8DX -> LAN Play (L + R + Left Stick on the title)
  3. the console's Browse Requests are logged here, we reply, and the console
     should list "<name>" as a room host
"""

import argparse
import socket
import struct
import sys
import time

import slp_spike
from slp_spike import IPV4, IPV4_FRAG, build_ipv4, build_udp

# Known-accepted MK8DX browse-reply header (type 1, session-info size 1266).
# Byte layout verified against kartlanpwn (CVE-2024-45200) which is proven to
# be parsed and processed by MK8DX as a valid Browse Reply. The exploit
# payload is NOT reproduced here — the post-app-data filler is zeroed and the
# app-data length is benign.
REPLY_MAGIC = (
    b"\x01\x00\x00\x04\xf2"          # type 1, u32 session-info size 1266
    b"\x00\x00\x00\x01\x01\x50\xc0"  # game mode / network id
    + b"\x00" * 26                   # attributes + participant counts region
    + b"\x01\x00\x02\x00\x0e\x02\x0d\x00\x00"
)

# MK8DX app data layout (kinnay "LDN Application Data (Pia)"): 1B unknown +
# 33B nickname + 2B padding + 88B Mii info + 4B unknown = 128 bytes.
def build_app_data(name):
    nb = name.encode("utf-8")[:33]
    return (
        b"\x00"
        + nb + b"\x00" * (33 - len(nb))
        + b"\x00\x00"
        + b"\x00" * 88
        + b"\x00\x00\x00\x00"
    )


def build_browse_reply(name, appdata_length=128):
    """Benign MK8DX Browse Reply (1024 B, mirroring the accepted kartlanpwn
    layout: app data at packet[47], app-data length at packet[431])."""
    appdata = build_app_data(name)
    out = bytearray(REPLY_MAGIC)        # 47 bytes -> app data at offset 47
    out += appdata                      # 128 bytes
    out += b"\x00" * 256                # app-data field is 0x180 total; pad to 431
    out += struct.pack(">I", appdata_length)
    out += b"\x00" * 1024
    return bytes(out[:1024])


def parse_udp(pkt):
    """Return (src_ip, dst_ip, sport, dport, payload) for an IPv4+UDP packet,
    or None if it isn't a valid UDP datagram."""
    if len(pkt) < 20:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if len(pkt) < ihl + 8 or pkt[9] != 17:
        return None
    total = int.from_bytes(pkt[2:4], "big")
    if total < ihl + 8 or total > len(pkt):
        return None
    u = ihl
    sport = int.from_bytes(pkt[u:u + 2], "big")
    dport = int.from_bytes(pkt[u + 2:u + 4], "big")
    ulen = int.from_bytes(pkt[u + 4:u + 6], "big")
    if ulen < 8 or u + ulen > total:
        return None
    src = pkt[12:16]
    dst = pkt[16:20]
    return (src, dst, sport, dport, pkt[u + 8:u + ulen])


class FragAssembler:
    """Reassemble relay Ipv4Frag frames back into one IPv4 packet
    (mirrors slp_tunnel.cpp OnFrag / the relay's FragParser)."""

    def __init__(self, max_entries=4):
        self.max_entries = max_entries
        self.entries = {}  # (src, id) -> dict(parts=..., lens=..., total=..., pmtu=...)

    def feed(self, payload):
        if len(payload) < 16:
            return None
        src = payload[0:4]
        fid = int.from_bytes(payload[8:10], "big")
        part, total = payload[10], payload[11]
        clen = int.from_bytes(payload[12:14], "big")
        pmtu = int.from_bytes(payload[14:16], "big")
        if total == 0 or part >= total or pmtu == 0 or clen > pmtu:
            return None
        if len(payload) < 16 + clen:
            return None
        key = (src, fid)
        if key not in self.entries:
            if len(self.entries) >= self.max_entries:
                self.entries.clear()
            self.entries[key] = {
                "total": total, "pmtu": pmtu, "parts": [None] * total,
            }
        e = self.entries[key]
        if e["total"] != total:
            return None
        if e["parts"][part] is not None:
            return None
        e["parts"][part] = payload[16:16 + clen]
        if all(p is not None for p in e["parts"]):
            buf = bytearray()
            for i, p in enumerate(e["parts"]):
                buf.extend(b"\x00" * (pmtu - len(p)))
                buf.extend(p)
            self.entries.pop(key, None)
            return bytes(buf)
        return None


class FakePlayer:
    def __init__(self, server, name, my_ip, appdata_length):
        self.name = name
        self.my_ip = my_ip
        self.appdata_length = appdata_length
        self.server = server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(0.05)
        self.frags = FragAssembler()
        self.browse_requests = 0
        self.replies_sent = 0
        self.other_udp = 0

    # --- slp framing ---
    def send(self, typ, payload=b""):
        self.sock.sendto(bytes([typ | (0 if slp_spike.HDR else 0x80)]) + payload, self.server)

    def keepalive(self):
        self.send(slp_spike.KEEPALIVE)

    def send_udp(self, src, dst, sport, dport, payload):
        self.send(IPV4, build_udp(src, sport, dst, dport, payload))

    # --- inbound ---
    def _on_ipv4(self, pkt):
        if len(pkt) < 20:
            return
        if pkt[12:16] == bytes([172, 10, 13, 37]):
            return  # LDN plugin scan broadcast, not game traffic
        parsed = parse_udp(pkt)
        if parsed is None:
            return
        src, dst, sport, dport, payload = parsed
        if dport == 30000 and len(payload) >= 1 and payload[0] == 0:
            self._on_browse_request(src, sport)
        else:
            self.other_udp += 1
            self._log(f"udp {_ip(src)}:{sport} -> {_ip(dst)}:{dport} "
                      f"{len(payload)}B (no browse reply)")

    def _on_browse_request(self, src_ip, sport):
        self.browse_requests += 1
        self._log(f"!! Browse Request from {_ip(src_ip)}:{sport} "
                  f"(reply #{self.replies_sent + 1})")
        reply = build_browse_reply(self.name, self.appdata_length)
        for _ in range(3):  # hosts transmit the reply three times
            self.send_udp(self.my_ip, src_ip, 30000, sport, reply)
            self.replies_sent += 1
            time.sleep(0.03)

    def step(self):
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout:
            return
        if not data:
            return
        typ = data[0] & slp_spike.HDR
        payload = data[1:]
        if typ == IPV4:
            self._on_ipv4(payload)
        elif typ == IPV4_FRAG:
            rebuilt = self.frags.feed(payload)
            if rebuilt is not None:
                self._on_ipv4(rebuilt)

    # --- misc ---
    def _log(self, msg):
        print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _ip(b):
    return ".".join(str(x) for x in b)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("port", nargs="?", type=int, default=11551)
    ap.add_argument("--name", default="SP-FAKE")
    ap.add_argument("--ip", default="10.13.37.100")
    ap.add_argument("--relay", default="127.0.0.1")
    ap.add_argument("--safe-appdata", action="store_true",
                    help="app-data length 256 (>150) so vulnerable MK8DX <= 3.0.1 "
                         "skips the CVE-2024-45200 memcpy")
    args = ap.parse_args()

    my_ip = tuple(int(x) for x in args.ip.split("."))
    assert len(my_ip) == 4, "bad --ip"
    appdata_length = 256 if args.safe_appdata else 128

    print(f"SP-FAKE relay={args.relay}:{args.port} virtual_ip={args.ip} "
          f"name={args.name!r} appdata_length={appdata_length}")
    fp = FakePlayer((args.relay, args.port), args.name, my_ip, appdata_length)
    fp.keepalive()  # register with the relay (a peer is invisible until it sends)
    print("registered; waiting for the console's LAN-mode Browse Requests...")
    print("(console: MK8DX -> title screen -> LAN Play, L+R+left stick)")

    last_ka = time.monotonic()
    try:
        while True:
            fp.step()
            now = time.monotonic()
            if now - last_ka >= 5.0:
                fp.keepalive()
                last_ka = now
            time.sleep(0.005)
    except KeyboardInterrupt:
        pass

    print(f"\nstats: browse_requests={fp.browse_requests} replies_sent={fp.replies_sent} "
          f"other_udp={fp.other_udp}")


if __name__ == "__main__":
    main()
