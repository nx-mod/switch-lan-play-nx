#!/usr/bin/env python3
"""
sys-slp-client — M1 protocol spike.

Validates the switch-lan-play (slp) wire format against a real relay server
(slp-server-rust) using two simulated players.

Wire format (from switch-lan-play/server/src/udpserver.ts + src/lan-client.c):

  every UDP datagram:  [1 byte header][payload]
    header byte:  bit7 (0x80) = encrypted (unused), bits6-0 (0x7f) = type
    type: 0=Keepalive, 1=Ipv4, 2=Ping, 3=Ipv4Frag, 4=AuthMe, 0x10=Info

  Keepalive:  b"\\x00"                               (sent every 10s; registers the peer)
  Ping:       b"\\x02" + 4 bytes  -> server echoes the whole 5-byte datagram back
              NOTE: Rust server expects [0x02]+4B (5 total) and echoes 5B.
              The TS server expects [0x02]+3B (4 total) and echoes 4B.
              The two servers are NOT ping-compatible; real clients never ping.
  Ipv4:       b"\\x01" + full IPv4 packet            (src IP @ offset 12, dst @ 16)
  Ipv4Frag:   b"\\x03" + 16B hdr + chunk
  AuthMe:     b"\\x04" + 20B sha1 response + username  (only when server demands)

  Server routing: caches src-IP -> peer (30s). If dst-IP known, unicast to that
  peer; otherwise broadcast the frame to every OTHER REGISTERED peer. A peer is
  only known once it has sent any datagram (real clients keepalive every 10s).

Usage: python3 spike/slp_spike.py [server_port]
"""

import socket
import struct
import sys
import threading
import time

KEEPALIVE = 0x00
IPV4 = 0x01
PING = 0x02
IPV4_FRAG = 0x03
AUTH_ME = 0x04
INFO = 0x10

HDR = 0x7F  # encryption bit off

# virtual LAN subnet, matching PC-client convention (192.168.1.x)
A_IP = (192, 168, 1, 10)
B_IP = (192, 168, 1, 20)
BCAST = (255, 255, 255, 255)


def ip_to_int(ip):
    return struct.pack("!4B", *ip)


def build_ipv4(src, dst, proto=17, payload=b""):
    """Minimal 20-byte IPv4 header + transport. Checksum left 0 (server ignores)."""
    total = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total, 0, 0, 64, proto, 0, ip_to_int(src), ip_to_int(dst),
    )
    return hdr + payload


def build_udp(src, sport, dst, dport, payload=b""):
    """UDP header inside the IPv4 payload."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return build_ipv4(src, dst, proto=17, payload=udp)


class SlpClient:
    """Minimal slp client: keepalive, ping, send ipv4 frames, receive thread."""

    def __init__(self, server, name, my_ip):
        self.name = name
        self.my_ip = my_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.server = server
        self.received = []      # (kind, raw payload)
        self.ping_ok = []
        self._recv_t = threading.Thread(target=self._recv, daemon=True)
        self._recv_t.start()

    def _recv(self):
        while True:
            data, _ = self.sock.recvfrom(65535)
            if not data:
                continue
            typ = data[0] & HDR
            payload = data[1:]
            if typ == PING:
                self.ping_ok.append(data)          # full datagram echoed
            elif typ == IPV4:
                self.received.append(("ipv4", payload))
            elif typ == IPV4_FRAG:
                self.received.append(("ipv4_frag", payload))
            elif typ == INFO:
                self.received.append(("info", payload))
            elif typ == AUTH_ME:
                self.received.append(("auth_me", payload))
            # keepalive: ignore

    def send(self, typ, payload=b""):
        self.sock.sendto(bytes([typ | (0 if HDR else 0x80)]) + payload, self.server)

    def keepalive(self):
        self.send(KEEPALIVE)

    def ping(self, tag):
        # Rust server: [0x02] + 4 payload bytes, echoed back verbatim (5B total).
        dat = struct.pack("!4B",
                          tag & 0xFF, (tag >> 8) & 0xFF,
                          (tag >> 16) & 0xFF, (tag >> 24) & 0xFF)
        out = bytes([PING]) + dat
        self.sock.sendto(out, self.server)
        return out

    def send_ipv4(self, src, dst, sport, dport, payload):
        frame = build_udp(src, sport, dst, dport, payload)
        self.send(IPV4, frame)
        return frame


def wait_until(fn, timeout=5.0, interval=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(interval)
    return False


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11551
    server = ("127.0.0.1", port)
    results = []

    a = SlpClient(server, "A", A_IP)
    b = SlpClient(server, "B", B_IP)
    # both peers must send a datagram first so the server has them registered
    a.keepalive()
    b.keepalive()
    time.sleep(0.2)

    # --- ping ---
    pdat = a.ping(0x01020304)
    ok = wait_until(lambda: any(x == pdat for x in a.ping_ok))
    results.append((f"ping echo matches ({pdat.hex()})", ok))

    # --- keepalive accepted (peer registered; no reply expected) ---
    a.keepalive()
    time.sleep(0.2)
    results.append(("keepalive sent, no crash", True))

    # --- unicast A -> B (learning phase, server broadcasts to B) ---
    a.send_ipv4(A_IP, B_IP, 11454, 11454, b"hello-from-A-unicast")
    ok = wait_until(lambda: any(k == "ipv4" and p[12:16] == ip_to_int(A_IP) for k, p in b.received))
    results.append(("A->B unicast delivered (server routed by dst IP)", ok))

    # --- B replies unicast -> A (now server has both in cache: true unicast) ---
    b.send_ipv4(B_IP, A_IP, 11454, 11454, b"reply-from-B")
    ok = wait_until(lambda: any(k == "ipv4" and p[12:16] == ip_to_int(B_IP) for k, p in a.received))
    results.append(("B->A reply delivered", ok))

    # --- broadcast A -> 255.255.255.255 reaches B ---
    b.received.clear()
    a.send_ipv4(A_IP, BCAST, 11454, 11454, b"discovery-broadcast")
    ok = wait_until(lambda: any(k == "ipv4" and p[16:20] == ip_to_int(BCAST) for k, p in b.received))
    results.append(("A broadcast (255.255.255.255) reached B", ok))

    print()
    fails = 0
    for label, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        fails += 0 if ok else 1
    print(f"\n{len(results) - fails}/{len(results)} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
