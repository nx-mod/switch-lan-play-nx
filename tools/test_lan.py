#!/usr/bin/env python3
"""
sys-slp-client — local test suite for the Pia LAN browse + session emulation.

Runs as many locally-verifiable tests as possible WITHOUT a console:

  Browse layer (unit):       5.7+ crypto challenge round-trip, key dependence,
                             version/counter echo, crypto-off path, reply layouts.
  Session layer (unit):      LAN session-key derivation, AES-GCM packet
                             encrypt/decrypt (mac_len=8), wrong-key/tamper reject.
  End-to-end (live relay):   two emulated players over slp-server-rust:
                             create room (browse reply) -> join (encrypted
                             session request/message handshake) -> keep-alive.

"Start game" is NOT testable locally: session traffic after join is game
protocol, only real consoles can run it.

Usage:  python3 spike/test_lan.py [relay_host] [relay_port]
"""

import socket
import struct
import sys
import time

from Crypto.Cipher import AES

import slp_lan as lan
import slp_pia as pia
from slp_lan import (GAME_KEYS, PROFILES, SIZES, CHALLENGE_SIZE,
                     build_browse_request, build_browse_reply,
                     build_session_info, parse_browse_request,
                     parse_challenge_block, extract_session_info,
                     decrypt_request_challenge, build_challenge_block,
                     verify_challenge_reply, bcast_for, broadcast_addr_for)

RES = []
RELAY_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11451

SWSH = PROFILES["swsh"]
MK8DX = PROFILES["mk8dx"]
BCAST = bcast_for(bytes([10, 13, 37, 100]))
MASK_24 = bytes([255, 255, 255, 0])


def test(name, fn):
    try:
        fn()
        RES.append((name, True, ""))
    except Exception as e:  # noqa: BLE001
        RES.append((name, False, str(e)))


def ok(cond, msg=""):
    if not cond:
        raise AssertionError(msg or "assertion failed")


# ============================================================== browse unit =

def t_browse_req_57():
    req = build_browse_request(crypto_enabled=True, version=lan.CHALLENGE_VERSION_2)
    p = parse_browse_request(req)
    ok(p is not None and p["type"] == 0 and p["size"] == 0x23A)
    ok(p["challenge"] is not None and len(p["challenge"]) == CHALLENGE_SIZE)
    ch = parse_challenge_block(p["challenge"])
    ok(ch["version"] == 2 and ch["enabled"] == 1 and len(ch["key"]) == 16)


def t_browse_req_le56():
    req = build_browse_request(crypto_enabled=False)
    p = parse_browse_request(req)
    ok(p is not None and p["challenge"] is None)


def t_challenge_roundtrip():
    key = SWSH["key"]
    req = build_browse_request(crypto_enabled=True, version=1, challenge_key=bytes(range(16)),
                               broadcast_addr=BCAST, game_key=key)
    block = parse_browse_request(req)["challenge"]
    chal = decrypt_request_challenge(key, block, BCAST)
    ok(chal == bytes((i * 7) & 0xFF for i in range(256)), "challenge bytes recovered")


def t_reply_verify():
    key = SWSH["key"]
    my_key = bytes((0xA0 + i) & 0xFF for i in range(16))
    req = build_browse_request(crypto_enabled=True, version=1, challenge_key=bytes(range(16)),
                               broadcast_addr=BCAST, game_key=key)
    req_block = parse_browse_request(req)["challenge"]
    rep = build_challenge_block(key, req_block, my_key, BCAST)
    got = verify_challenge_reply(key, req_block, rep, BCAST)
    chal = decrypt_request_challenge(key, req_block, BCAST)
    ok(got == lan.hmac_sha256(key, chal)[:16], "HMAC response matches")
    ok(parse_challenge_block(rep)["version"] == 1, "version echoed")
    ok(parse_challenge_block(rep)["counter"] == parse_challenge_block(req_block)["counter"],
       "counter echoed")


def t_reply_wrong_key():
    key = SWSH["key"]
    my_key = bytes(range(16, 32))
    req = build_browse_request(crypto_enabled=True, version=1, challenge_key=bytes(range(16)),
                               broadcast_addr=BCAST, game_key=key)
    req_block = parse_browse_request(req)["challenge"]
    rep = build_challenge_block(key, req_block, my_key, BCAST)
    try:
        verify_challenge_reply(b"WRONG-KEY-DERIVED!", req_block, rep, BCAST)
        raise AssertionError("wrong key accepted")
    except ValueError:
        pass


def t_reply_tamper():
    key = SWSH["key"]
    my_key = bytes(range(16, 32))
    req = build_browse_request(crypto_enabled=True, version=1, challenge_key=bytes(range(16)),
                               broadcast_addr=BCAST, game_key=key)
    req_block = parse_browse_request(req)["challenge"]
    rep = bytearray(build_challenge_block(key, req_block, my_key, BCAST))
    rep[0x2A] ^= 0x01  # flip a bit in the encrypted response
    try:
        verify_challenge_reply(key, req_block, bytes(rep), BCAST)
        raise AssertionError("tampered reply accepted")
    except ValueError:
        pass


def t_crypto_off_reply():
    key = SWSH["key"]
    my_key = bytes(range(16, 32))
    req = build_browse_request(crypto_enabled=False)
    req_block = parse_browse_request(req)["challenge"]
    ok(req_block is None, "no challenge block in crypto-off request")
    # build reply for a crypto-off request: host still emits a challenge block
    # (enabled=0) only for 5.7+ requests; <=5.6 requests have no block at all.
    fake_block = bytearray(CHALLENGE_SIZE)
    fake_block[0] = 1
    fake_block[1] = 0
    fake_block[0x0A:0x1A] = my_key
    rep = build_challenge_block(key, bytes(fake_block), my_key, BCAST)
    got = verify_challenge_reply(key, bytes(fake_block), rep, BCAST)
    ok(len(got) == 16, "crypto-off reply decodes to HMAC")


def t_session_info_layouts():
    for layout, size in (("5.3-5.6", SIZES["5.3-5.6"]), ("5.10+", SIZES["5.10+"])):
        info = build_session_info(layout, "TEST", bytes([10, 13, 37, 100]),
                                  syscomm=6, appcomm=1)
        ok(len(info) == size, f"{layout} size {len(info)} != {size}")
        ok(info[0x26] == 6 and info[0x27] == 1, f"{layout} comm versions")
    info510 = build_session_info("5.10+", "TEST", bytes([10, 13, 37, 100]),
                                 session_key_param=b"K" * 32)
    ok(info510[0x4F1:0x4F1 + 32] == b"K" * 32, "5.10+ session key param stored")


def t_mk8dx_reply_builds():
    req = build_browse_request(crypto_enabled=False)
    reply = build_browse_reply(MK8DX, parse_browse_request(req),
                               bytes([10, 13, 37, 100]), "SP-FAKE")
    ex = extract_session_info(reply)
    ok(ex is not None and ex["size"] == SIZES["5.3-5.6"], "MK8DX session-info size")
    ok(len(reply) == 1 + 4 + SIZES["5.3-5.6"], "MK8DX reply length")


def t_swsh_reply_builds():
    req = build_browse_request(crypto_enabled=True, version=2, challenge_key=bytes(range(16)),
                               broadcast_addr=BCAST, game_key=SWSH["key"])
    reply = build_browse_reply(SWSH, parse_browse_request(req),
                               bytes([10, 13, 37, 100]), "ROOM")
    ex = extract_session_info(reply)
    ok(ex is not None and ex["size"] == SIZES["5.10+"], "Sw/Sh session-info size")
    # 1297 + 5 + 298 challenge = 1600B > 1364B max -> challenge block dropped
    ok(len(reply) <= lan.MAX_BROWSE_REPLY_SIZE, "Sw/Sh reply within 1364B max")
    ok(ex["challenge"] is None, "Sw/Sh reply has no challenge block (fits <=1364)")
    ok(ex["info"][0x4F1:0x4F1 + 32] != b"\x00" * 32, "session key param echoed")


# ============================================================== session unit =

def t_session_key_derivation():
    skp = bytes(range(32))
    k1 = pia.derive_session_key(GAME_KEYS["swsh"], skp)
    ok(len(k1) == 16)
    k2 = pia.derive_session_key(GAME_KEYS["swsh"], bytes(range(32))[:31] + b"\x00")
    ok(k1 != k2, "skp change alters session key")
    ok(k1 == pia.derive_session_key(GAME_KEYS["swsh"], skp), "deterministic")


def t_pia_packet_roundtrip():
    key = pia.derive_session_key(GAME_KEYS["swsh"], bytes(range(32)))
    src_ip, src_var, dst_var = bytes([10, 13, 37, 100]), 0x11223344, 0x55667788
    pl = pia.lan_session_request(0x12345678)
    pkt = pia.build_pia_packet(key, [pl], src_ip, src_var, dst_var, nonce_ctr=7)
    out = pia.parse_pia_packet(key, pkt, src_ip)
    ok(out is not None, "packet parses")
    ok(out["src_var"] == src_var and out["dst_var"] == dst_var)
    ok(out["payloads"] == [pl], "LAN payload intact")


def t_pia_wrong_key():
    key = pia.derive_session_key(GAME_KEYS["swsh"], bytes(range(32)))
    wrong = pia.derive_session_key(GAME_KEYS["smm2"], bytes(range(32)))
    src_ip, src_var, dst_var = bytes([10, 13, 37, 100]), 0x11223344, 0x55667788
    pkt = pia.build_pia_packet(key, [pia.lan_keep_alive()], src_ip, src_var, dst_var, 1)
    ok(pia.parse_pia_packet(wrong, pkt, src_ip) is None, "wrong key rejected")


def t_pia_tamper():
    key = pia.derive_session_key(GAME_KEYS["swsh"], bytes(range(32)))
    src_ip, src_var, dst_var = bytes([10, 13, 37, 100]), 0x11223344, 0x55667788
    pkt = bytearray(pia.build_pia_packet(key, [pia.lan_keep_alive()],
                                         src_ip, src_var, dst_var, 1))
    pkt[0x20] ^= 0x01  # corrupt the encrypted payload
    ok(pia.parse_pia_packet(key, bytes(pkt), src_ip) is None, "tampered rejected")


def t_pia_bundle():
    key = pia.derive_session_key(GAME_KEYS["swsh"], bytes(range(32)))
    src_ip, src_var, dst_var = bytes([10, 13, 37, 101]), 0x22222222, 0x11111111
    pkt = pia.build_pia_packet(key, [pia.lan_keep_alive(), pia.lan_session_request(1)],
                               src_ip, src_var, dst_var, 9)
    out = pia.parse_pia_packet(key, pkt, src_ip)
    ok(out is not None and len(out["payloads"]) == 2, "two payloads decoded")
    ok(out["payloads"][0][0] == pia.LAN_KEEP_ALIVE and out["payloads"][1][0] == pia.LAN_SESSION_REQUEST)


# ========================================================= end-to-end relay =

def relay_available():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    try:
        s.sendto(bytes([0x00]), (RELAY_HOST, RELAY_PORT))
        s.close()
        return True
    except OSError:
        return False


class RelayPeer:
    """A virtual console speaking slp Ipv4 framing to the relay."""

    def __init__(self, ip):
        import socket
        import slp_spike
        self.ip = ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(0.05)
        self.server = (RELAY_HOST, RELAY_PORT)
        self.pending = []

    def send_raw(self, typ, payload=b""):
        self.sock.sendto(bytes([typ]) + payload, self.server)

    def keepalive(self):
        self.send_raw(0x00)

    # Must match the console's tunnel: slp_client.h sets SLP_MTU 1400 and any
    # IPv4 frame larger than that has to go out as Ipv4Frag (type 0x02) frames,
    # not one oversized type 0x01 frame. Sending the 1569-byte MK8DX LAN browse
    # reply unfragmented meant the console never received it at all -- its
    # RecvFrom on :30000 just returned EAGAIN forever and the game gave up with
    # 2618-0006. WiFi was unaffected only because a ScanResp is ~169 bytes.
    #
    # Frag header (big-endian, from slpFrameIpv4Frag / OnFrag):
    #   u8 type=0x02 | u32 src | u32 dst | u16 id | u8 part | u8 total
    #   | u16 chunk_len | u16 mtu | chunk...
    # OnFrag rebuilds with off = part * mtu, so every chunk except the last
    # must be exactly MTU bytes, and total must be <= MaxTotalParts (4).
    SLP_MTU = 1400
    MAX_PARTS = 4

    def send_udp(self, dst, sport, dport, payload):
        import slp_spike
        pkt = slp_spike.build_udp(self.ip, sport, dst, dport, payload)
        if len(pkt) <= self.SLP_MTU:
            self.send_raw(0x01, pkt)
            return

        total = (len(pkt) + self.SLP_MTU - 1) // self.SLP_MTU
        if total > self.MAX_PARTS:
            raise ValueError(
                f"packet {len(pkt)}B needs {total} frags, console accepts "
                f"at most {self.MAX_PARTS}")

        self._frag_id = (getattr(self, "_frag_id", 0) + 1) & 0xFFFF
        src_u32 = int.from_bytes(self.ip, "big")
        dst_u32 = int.from_bytes(bytes(dst), "big")
        for part in range(total):
            chunk = pkt[part * self.SLP_MTU:(part + 1) * self.SLP_MTU]
            hdr = (src_u32.to_bytes(4, "big") + dst_u32.to_bytes(4, "big")
                   + self._frag_id.to_bytes(2, "big")
                   + bytes([part, total])
                   + len(chunk).to_bytes(2, "big")
                   + self.SLP_MTU.to_bytes(2, "big"))
            self.send_raw(0x02, hdr + chunk)

    def pump(self):
        try:
            while True:
                data, _ = self.sock.recvfrom(65535)
                if data and (data[0] & 0x7F) == 0x01:
                    self.pending.append(data[1:])
        except (socket.timeout, BlockingIOError):
            pass

    def next_udp(self, dst_ip, timeout=2.0):
        end = time.time() + timeout
        while time.time() < end:
            self.pump()
            for i, pkt in enumerate(self.pending):
                if len(pkt) >= 20 and pkt[16:20] == dst_ip:
                    u = (pkt[0] & 0x0F) * 4
                    dport = int.from_bytes(pkt[u + 2:u + 4], "big")
                    ulen = int.from_bytes(pkt[u + 4:u + 6], "big")
                    payload = pkt[u + 8:u + ulen]
                    del self.pending[i]
                    return payload
            time.sleep(0.02)
        return None


def t_e2e_lobby():
    host, client = RelayPeer(bytes([10, 13, 37, 100])), RelayPeer(bytes([10, 13, 37, 101]))
    host.keepalive()
    client.keepalive()
    time.sleep(0.2)

    key = SWSH["key"]
    host_key = bytes((0xA0 + i) & 0xFF for i in range(16))  # host's challenge key
    client_ck = bytes((0x10 + i) & 0xFF for i in range(16))  # client's challenge key
    bcast = bcast_for(client.ip)
    network_id = 0x55556666
    host_var = 0x11111111
    client_var = 0x22222222

    # 1) client broadcasts a 5.7+ browse request
    req = build_browse_request(crypto_enabled=True, version=2, challenge_key=client_ck,
                               broadcast_addr=bcast, game_key=key)
    client.send_udp(bcast, 30000, 30000, req)
    host_req = host.next_udp(bcast)
    ok(host_req is not None, "host received browse request")
    hp = parse_browse_request(host_req)
    ok(hp is not None and hp["challenge"] is not None, "challenge present in request")

    # 2) host builds a browse reply: the 0x12A challenge reply would make the
    #    packet 1600B, over the 1364B protocol max, so the builder drops it and
    #    sends the <=5.6 form. The challenge crypto is verified separately below.
    reply = build_browse_reply(SWSH, hp, host.ip, "E2E-ROOM", my_key=host_key)
    host.send_udp(client.ip, 30000, 30000, reply)

    # 3) client receives reply (<=1364, no challenge block) + session key param
    rep_udp = client.next_udp(client.ip)
    ok(rep_udp is not None and rep_udp[0] == 1, "client received browse reply")
    ok(len(rep_udp) <= lan.MAX_BROWSE_REPLY_SIZE, "reply within 1364 protocol max")
    ex = extract_session_info(rep_udp)
    ok(ex is not None and ex["challenge"] is None,
       "challenge block dropped when it would exceed 1364B")
    rep_key = parse_challenge_block(hp["challenge"])["key"]
    skp = host_key + rep_key  # host reply key ++ request key
    ok(ex["info"][0x4F1:0x4F1 + 32] == skp, "session key param echoed in reply")

    # 3b) the 5.7+ challenge round-trip still works (standalone block)
    cblock = build_challenge_block(key, hp["challenge"], host_key, bcast)
    got = verify_challenge_reply(key, hp["challenge"], cblock, bcast)
    chal = decrypt_request_challenge(key, hp["challenge"], bcast)
    ok(got == lan.hmac_sha256(key, chal)[:16], "client verifies host HMAC response")

    # 4) both sides derive the LAN session key
    skey_c = pia.derive_session_key(key, skp)
    skey_h = pia.derive_session_key(key, host_key + client_ck)
    ok(skey_c == skey_h, "session keys agree")

    # 5) client joins: encrypted Session Request broadcast on 49152
    sreq = pia.lan_session_request(network_id)
    pkt = pia.build_pia_packet(skey_c, [sreq], client.ip, client_var, host_var, nonce_ctr=0x11, packet_id=1)
    client.send_udp(bcast, 49152, 49152, pkt)
    host_pkt = host.next_udp(bcast)
    ok(host_pkt is not None, "host received session request")
    hpkt = pia.parse_pia_packet(skey_h, host_pkt, client.ip)
    ok(hpkt is not None, "host decrypts session request")
    htype, hbody = pia.parse_lan_message(hpkt["payloads"][0])
    ok(htype == pia.LAN_SESSION_REQUEST and hbody == struct_s(network_id), "session request payload")

    # 6) host sends encrypted Session Message (LanSessionInfo fragment) back
    info = build_session_info("5.10+", "E2E-ROOM", host.ip, syscomm=6, appcomm=1,
                              session_key_param=skp)
    smsg = pia.lan_session_message(0x77778888, 0, 0, 1, len(info), info)
    pkt = pia.build_pia_packet(skey_h, [smsg], host.ip, host_var, client_var, nonce_ctr=0x22, packet_id=1)
    host.send_udp(client.ip, 49152, 49152, pkt)
    c_pkt = client.next_udp(client.ip)
    ok(c_pkt is not None, "client received session message")
    cpkt = pia.parse_pia_packet(skey_c, c_pkt, host.ip)
    ok(cpkt is not None, "client decrypts session message")
    ctype, cbody = pia.parse_lan_message(cpkt["payloads"][0])
    ok(ctype == pia.LAN_SESSION_MESSAGE, "session message type")
    ok(cbody[4:6] == struct.pack(">H", 0), "seq id 0")
    frag_info = cbody[12:12 + struct.unpack(">I", cbody[8:12])[0]]
    ok(frag_info == info, "client received host's LanSessionInfo")
    ex2 = extract_session_info(bytes([1]) + struct.pack(">I", len(info)) + info + b"\x00" * 0x12A)
    ok(ex2["info"][0x4F1:0x4F1 + 32] == skp, "room session key param intact")

    # 7) encrypted keep-alive both directions decrypt
    ka = pia.lan_keep_alive()
    pkt = pia.build_pia_packet(skey_c, [ka], client.ip, client_var, host_var, nonce_ctr=0x33, packet_id=2)
    client.send_udp(bcast, 49152, 49152, pkt)
    h_ka = host.next_udp(bcast)
    ok(h_ka is not None and pia.parse_pia_packet(skey_h, h_ka, client.ip) is not None,
       "host decrypts client keep-alive")


def struct_s(v):
    import struct
    return struct.pack(">I", v)


def main():
    print(f"relay: {RELAY_HOST}:{RELAY_PORT}  games: swsh/mk8dx/splatoon2/smm2")
    print()

    tests = [
        ("browse: 5.7+ request parses + challenge block", t_browse_req_57),
        ("browse: <=5.6 request has no challenge", t_browse_req_le56),
        ("browse: request challenge decrypts to known bytes", t_challenge_roundtrip),
        ("browse: host reply verifies (HMAC + version + counter echo)", t_reply_verify),
        ("browse: wrong game key rejected by verifier", t_reply_wrong_key),
        ("browse: tampered reply rejected (GCM tag)", t_reply_tamper),
        ("browse: crypto-off path round-trips", t_crypto_off_reply),
        ("browse: session-info layouts (5.3-5.6 / 5.10+)", t_session_info_layouts),
        ("browse: MK8DX (<=5.6) reply builds", t_mk8dx_reply_builds),
        ("browse: Sw/Sh (5.7+) reply builds w/ challenge + skp", t_swsh_reply_builds),
        ("session: LAN session-key derivation", t_session_key_derivation),
        ("session: Pia packet encrypt/decrypt round-trip", t_pia_packet_roundtrip),
        ("session: wrong session key rejected", t_pia_wrong_key),
        ("session: tampered packet rejected", t_pia_tamper),
        ("session: bundled messages decode", t_pia_bundle),
    ]

    e2e = [("e2e: create lobby -> join -> keep-alive (relay)", t_e2e_lobby)]

    for name, fn in tests:
        test(name, fn)
    if relay_available():
        for name, fn in e2e:
            test(name, fn)
    else:
        print(f"  (relay {RELAY_HOST}:{RELAY_PORT} not reachable — skipping e2e tests)")

    print()
    fails = 0
    for name, ok_, err in RES:
        print(f"  [{'PASS' if ok_ else 'FAIL'}] {name}" + (f"  ({err})" if err else ""))
        fails += 0 if ok_ else 1
    print(f"\n{len(RES) - fails}/{len(RES)} passed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
