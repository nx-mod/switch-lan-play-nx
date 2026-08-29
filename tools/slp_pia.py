#!/usr/bin/env python3
"""
sys-slp-client — Pia session-layer emulation (LAN mode, Pia 5.7+).

Enables a fully-local "two players create a lobby and join it" test at the Pia
transport level (no console needed): browse + crypto challenge + session-key
derivation + AES-GCM session traffic over the slp relay.

Spec: kinnay/NintendoClients wiki (Pia-Protocol, LAN-Protocol).

Session key (LAN, up to 6.30):
    skp_inc = session_key_param (32B) with last byte incremented by 1
    session_key = HMAC-SHA256(game_key, skp_inc)[0:16]

Pia packet header v9 (Pia 5.27-5.45):
    0x00 magic 32 AB 98 64 | 0x04 0x80|9 | 0x05 u32 dst var | 0x09 u32 src var
    0x0D u16 packet id     | 0x0F u8 footer size | 0x10 8B nonce
    0x18 8B GCM tag (mac_len=8)
    then encrypted payload, then plaintext footer (u16 dst var ids)

LAN AES-GCM nonce (5.27-5.45): 4B source IP ++ 1B src var&0xFF ++ 7B (header
nonce[1:8]).

Messages (5.27-6.30): [u8 flags][if&1 u8 msg flags][if&2 u16 payload size]
    [if&4 u8 proto type + u24 port][if&8 u64 destination][payload][pad to 4].
LAN protocol type = 0x44. Payload = LAN message (types 3..7).
"""

import struct

from Crypto.Cipher import AES

from slp_lan import hmac_sha256

MAGIC = b"\x32\xab\x98\x64"
HDR_VERSION = 9          # Pia 5.27 - 5.45
LAN_PROTOCOL = 0x44      # Pia-Protocols wiki
PORT_49152 = 0xC000

# LAN message types (LAN-Protocol wiki)
LAN_HOST_REQUEST = 3
LAN_HOST_MESSAGE = 4
LAN_SESSION_REQUEST = 5
LAN_SESSION_MESSAGE = 6
LAN_KEEP_ALIVE = 7


def derive_session_key(game_key, session_key_param):
    """LAN session key: HMAC-SHA256(game_key, skp with last byte +1)[0:16]."""
    skp = bytearray(session_key_param)
    skp[-1] = (skp[-1] + 1) & 0xFF
    return hmac_sha256(game_key, bytes(skp))[:16]


# ---------------------------------------------------------------- packets ---

def build_pia_packet(session_key, lan_payloads, src_ip, src_var, dst_var,
                     nonce_ctr, packet_id=1):
    """Encrypt one or more LAN payloads into a single v9 Pia packet.

    lan_payloads: list of bytes (each starts with the LAN message type).
    Returns the raw datagram to send on UDP 49152.
    """
    body = b""
    for pl in lan_payloads:
        msg = bytes([0x0F])            # flags: msg-flags + payload-size + proto + dst
        msg += bytes([0x01])           # msg flags: destination is bitmap (broadcast)
        msg += struct.pack(">H", len(pl))
        msg += bytes([LAN_PROTOCOL])
        msg += struct.pack(">I", 0)[1:]  # 24-bit protocol port
        msg += struct.pack(">Q", 0)    # destination bitmap = 0 (broadcast)
        msg += pl
        msg += b"\x00" * ((-len(msg)) % 4)
        body += msg
    body += b"\xff" * ((-len(body)) % 16)  # pad to block size with 0xFF

    hdr_nonce = int.to_bytes(nonce_ctr, 8, "big")
    nonce = src_ip + bytes([src_var & 0xFF]) + hdr_nonce[1:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=8)
    ct, tag = cipher.encrypt_and_digest(body)

    footer = struct.pack(">H", dst_var & 0xFFFF)
    hdr = MAGIC
    hdr += bytes([0x80 | HDR_VERSION])
    hdr += struct.pack(">I", dst_var)
    hdr += struct.pack(">I", src_var)
    hdr += struct.pack(">H", packet_id)
    hdr += bytes([len(footer) // 2])
    hdr += hdr_nonce
    hdr += tag
    return hdr + ct + footer


def why_parse_failed(packet):
    """Human-readable reason parse_pia_packet() would reject `packet`.

    Exists because every rejection used to be reported as "wrong key or
    corrupted", which sent us chasing nonce/key bugs when the real cause was a
    header check failing long before any decryption was attempted."""
    if len(packet) < 0x20:
        return f"too short ({len(packet)}B < 0x20)"
    if packet[:4] != MAGIC:
        return f"bad magic {packet[:4].hex()} (want {MAGIC.hex()})"
    ver = packet[4] & 0x7F
    if ver != HDR_VERSION:
        return (f"Pia header version {ver}, parser only supports v{HDR_VERSION} "
                f"(byte[4]={packet[4]:#04x})")
    fsize = packet[15]
    if not packet[0x20:-fsize * 2 if fsize else None]:
        return f"empty body (fsize={fsize})"
    return "AES-GCM verify failed (key or nonce)"


def parse_pia_packet(session_key, packet, src_ip):
    """Decrypt and verify a v9 Pia packet. Returns (lan_payloads, src_var,
    dst_var) or None on failure."""
    if len(packet) < 0x20 or packet[:4] != MAGIC:
        return None
    if packet[4] & 0x7F != HDR_VERSION:
        return None
    dst_var = struct.unpack(">I", packet[5:9])[0]
    src_var = struct.unpack(">I", packet[9:13])[0]
    fsize = packet[15]
    hdr_nonce = packet[0x10:0x18]
    tag = packet[0x18:0x20]
    body = packet[0x20:-fsize * 2]
    if not body:
        return None
    nonce = src_ip + bytes([src_var & 0xFF]) + hdr_nonce[1:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=8)
    try:
        plain = cipher.decrypt_and_verify(body, tag)
    except ValueError:
        return None
    plain = plain.rstrip(b"\xff")  # drop 0xFF block padding from our builder
    payloads = []
    pos = 0
    while pos < len(plain):
        flags = plain[pos]
        pos += 1
        plen = None
        if flags & 1:
            pos += 1
        if flags & 2:
            plen = struct.unpack(">H", plain[pos:pos + 2])[0]
            pos += 2
        if flags & 4:
            pos += 4
        if flags & 8:
            pos += 8
        if plen is None:
            break
        payloads.append(plain[pos:pos + plen])
        pos += plen
        pos += (-pos) % 4  # message padding to 4
        if plen == 0:
            break
    return {"payloads": payloads, "src_var": src_var, "dst_var": dst_var}


# ------------------------------------------------------------ LAN messages --

def lan_host_request(network_id):
    return bytes([LAN_HOST_REQUEST]) + b"\x00" * 11 + struct.pack(">I", network_id)


def lan_host_message(network_id, station_location):
    """Type 4 (5.10-5.45): network id + StationLocation (6B = 4B ip + 2B port)."""
    return (bytes([LAN_HOST_MESSAGE]) + b"\x00" * 11 + struct.pack(">I", network_id)
            + station_location)


def lan_session_request(network_id):
    return bytes([LAN_SESSION_REQUEST]) + b"\x00" * 11 + struct.pack(">I", network_id)


def lan_session_message(random_id, seq_id, frag_index, num_frags, frag_size, frag_data):
    return (bytes([LAN_SESSION_MESSAGE]) + b"\x00" * 11
            + struct.pack(">I", random_id)
            + struct.pack(">H", seq_id)
            + bytes([frag_index, num_frags])
            + struct.pack(">I", frag_size)
            + frag_data)


def lan_keep_alive():
    return bytes([LAN_KEEP_ALIVE]) + b"\x00" * 11


def parse_lan_message(payload):
    """Return (lan_type, body)."""
    if not payload:
        return None
    return payload[0], payload[12:]  # 1B type + 11B padding, then fields
