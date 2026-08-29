#!/usr/bin/env python3
"""
sys-slp-client — Pia LAN browse-protocol codec + crypto (laptop fake player).

Implements the Pia "LAN Protocol" browse request/reply including the 5.7+
crypto challenge, per kinnay/NintendoClients wiki (LAN-Protocol, Pia-Types,
Pia-Game-Keys). Used by slp_fake_player.py and the local test harness
test_lan.py.

Wire layouts (all big-endian):
  request (5.7-5.45): [u8 type=0][u32 size=0x23A][criteria 0x23A][challenge 0x12A]
  request (<=5.6):    [u8 type=0][u32 size=0x23A][criteria 0x23A]
  reply   (5.7-5.45): [u8 type=1][u32 size][LanSessionInfo][challenge reply 0x12A]
  reply   (<=5.6):    [u8 type=1][u32 size][LanSessionInfo]

Challenge block (5.7-6.33, challenge version 1-3), 0x12A bytes:
  [0x00 u8 version][0x01 u8 crypto_enabled][0x02 8B counter]
  [0x0A 16B challenge key][0x1A 16B AES-GCM tag][0x2A 256B data (or 16B in reply)]
Nonce: 4B broadcast addr (local|~mask) ++ 8B counter  (12B total, AES-GCM).

Challenge encryption key = AES(game_key, challenge_key_field)   (AES-ECB, 16B)
Response content        = HMAC-SHA256(game_key, challenge)[0:16]
Response key            = HMAC-SHA256(game_key, my_key ++ req_key)[0:16]
Session key param       = my_key ++ req_key (32B), echoed in the session info
"""

import hmac
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from enl import derive_key, add_game_params

# Pia version <-> challenge version (LAN-Protocol wiki "Version")
CHALLENGE_VERSION_1 = 1  # Pia 5.7 - 5.10
CHALLENGE_VERSION_2 = 2  # Pia 5.11 - 5.45
CHALLENGE_VERSION_3 = 3  # Pia 6.16 - 6.33

# System communication version (LAN-Protocol wiki)
SYSCOMM = {0: "5.3", 2: "5.6", 3: "5.7", 4: "5.8", 5: "5.9", 6: "5.10",
           7: "5.11-5.18", 8: "5.19-5.45", 10: "6.16-6.30", 22: "6.41"}

# Game keys: ENL-derived games use derive_key(); others are hardcoded from Pia-Game-Keys wiki.
# Most first-party games derive the key via ENL and are NOT published here.
def _game_key(game_id: str) -> bytes:
    """Get game key, deriving via ENL where applicable."""
    enl_derived = {"splatoon2", "smm2", "nssports"}
    if game_id in enl_derived:
        return derive_key(game_id)
    return _HARDCODED_KEYS[game_id]

_HARDCODED_KEYS = {
    "mk8dx":     b"ABCDEFGHIJKLMNOP",                              # Mario Kart 8 Deluxe
    "swsh":      b"p1frXqxmeCZWFv0X",                              # Pokemon Sword/Shield
    "sv":        b"p1frXqxmeCZWFv0X",                              # Pokemon Scarlet/Violet (same key)
    "splatoon3": bytes.fromhex("78deee82d86875782c40b15278f37815"),
    "gb_nso":    bytes.fromhex("54ddaeaedb3ce1a39f793c962bf4a36c"),  # Game Boy - NSO
    "bdsp":      bytes.fromhex("9900bd0cdcfa65639918bd0fc7fa6577"),  # Brilliant Diamond 1.3.0
    "pokemonfr": bytes.fromhex("83ca7fab734c34633b10183526c1e85b"),  # Pokemon Fire Red
    "za":        b"p3bwdaSsywFXUkDu",                              # Pokemon Legends: Z-A
    "marioparty": b"ndcube_buffet_ss",                             # Super Mario Party
}

# Back-compat: GAME_KEYS dict for existing code
class _GameKeysDict(dict):
    def __getitem__(self, key):
        return _game_key(key)

    def get(self, key, default=None):
        try:
            return _game_key(key)
        except KeyError:
            return default

    def __contains__(self, key):
        return key in _HARDCODED_KEYS or key in {"splatoon2", "smm2", "nssports"}

GAME_KEYS = _GameKeysDict()

# Pia version era <-> LAN browse UDP port (LAN-Protocol wiki).
BROWSE_PORTS = {
    "5.3-5.6":     30000,
    "5.7-5.9":     30000,
    "5.10-5.45":   30000,
    "6.16-6.30":   35000,
    "6.41-7.2":    35000,
}

# Search criteria fixed size for <=5.45 requests
SEARCH_CRITERIA_SIZE = 0x23A
CHALLENGE_SIZE = 0x12A  # 298

# Hard protocol maximum for browse request/reply packets (kinnay LAN-Protocol
# wiki). The game's read buffer equals this (1364). A reply that exceeds it is
# truncated by the receiver and rejected. A 5.7+ reply (session info + 0x12A
# challenge reply) can only be sent when the session info leaves room.
MAX_BROWSE_REPLY_SIZE = 1364

# LanSessionInfo sizes per Pia era (LAN-Protocol wiki field tables).
# 5.3-5.6  = 4+4+24+2+2+2+1+1+2+384+4+1+35+800 = 1266  (StationLocation host)
# 5.7-5.9  = 1266 + 32 session key param               = 1298
# 5.10-5.45= host becomes 18B StationAddress + const(8)+var(4)+svc(4),
#            same 800B station block, +32 skp           = 1297
# Up to 5.2 = same 1266 (no syscomm/appcomm; u32 session type).
# Pia 6.x replies carry LanNetworkProperty, NOT LanSessionInfo (needs its own
# builder; browse port 35000).
SIZES = {
    "5.2-":     0x4F2,  # 1266  not used
    "5.3-5.6":  0x4F2,  # 1266  StationLocation host
    "5.7-5.9":  0x512,  # 1298  StationLocation host + session key param
    "5.10-5.18": 0x511,  # 1297  StationAddress host + session key param
    "5.19-5.45": 0x511,  # 1297  same layout as 5.10-5.18
    "5.10+":    0x511,  # 1297  alias used by build_session_info
}

# Profile defaults (tune on-console later). layout is the LanSessionInfo era;
# Pia 6.x titles need the LanNetworkProperty builder and are marked pending.
PROFILES = {
    "mk8dx":     {"key": GAME_KEYS["mk8dx"],     "challenge": True,  "layout": "5.3-5.6", "syscomm": 2,  "appcomm": 13, "browse_port": 30000},
    "splatoon2": {"key": GAME_KEYS["splatoon2"], "challenge": False, "layout": "5.3-5.6", "syscomm": 2,  "appcomm": 0,  "browse_port": 30000},
    "smm2":      {"key": GAME_KEYS["smm2"],      "challenge": False, "layout": "5.3-5.6", "syscomm": 2,  "appcomm": 0,  "browse_port": 30000},
    "swsh":      {"key": GAME_KEYS["swsh"],      "challenge": True,  "layout": "5.10+",  "syscomm": 6,  "appcomm": 1,  "browse_port": 30000},
    "marioparty": {"key": GAME_KEYS["marioparty"], "challenge": False, "layout": "5.3-5.6", "syscomm": 2, "appcomm": 0, "browse_port": 30000},
    # Pia 6.x (need LanNetworkProperty reply + challenge v3, browse :35000):
    # splatoon3 / nssports / za   -> pending
}

# Title id (u64 program id) -> profile name, so the per-title choice can be
# baked in (native-LAN Pia titles that use the bsd browse path).
TITLES = {
    0x0100152000022000: "mk8dx",
    0x0100F8F0000A2000: "splatoon2",
    0x01009B90006DC000: "smm2",
    0x0100ABF008968000: "swsh",  # Sword
    0x01008DB008C2C000: "swsh",  # Shield
    0x010079500849A000: "marioparty",
}

# ---------------------------------------------------------------- ids ---------
# Pia-Types wiki: LAN ids derived from the host's local IP + UDP port.
#   network id     (LAN <=5.45): ((ip & 0xFFFF) << 16) | port
#   constant id    (LAN <=5.9):  ip << 32 | port
#   service var id (LAN <=5.45): ((ip & 0xFFFF) << 16) | port
# Example (wiki): host ip 192.168.178.215, port 49154 -> network id 0xB2D7C002.

def ip_u32(ip):
    return int.from_bytes(ip, "big")


def lan_network_id(ip, port=30000):
    return ((ip_u32(ip) & 0xFFFF) << 16) | port


def lan_constant_id(ip, port=30000):
    return (ip_u32(ip) << 32) | port


def lan_service_variable_id(ip, port=30000):
    return ((ip_u32(ip) & 0xFFFF) << 16) | port


# ---------------------------------------------------------------- crypto ---

def aes_ecb_encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def aes_gcm_encrypt(key, nonce, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return ct, tag


def aes_gcm_decrypt(key, nonce, tag, data):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag)


def hmac_sha256(key, msg):
    return hmac.new(key, msg, SHA256).digest()


def nonce_from(broadcast_addr, counter):
    """12B AES-GCM nonce: 4B broadcast addr ++ 8B counter."""
    return broadcast_addr + counter


def broadcast_addr_for(local, mask):
    """4B subnet broadcast = local | ~mask."""
    lm = int.from_bytes(local, "big")
    mm = int.from_bytes(mask, "big")
    return int.to_bytes(lm | (~mm & 0xFFFFFFFF), 4, "big")


# ------------------------------------------------- challenge block ---------

def parse_challenge_block(block):
    """Parse a 0x12A challenge block -> dict(version, enabled, counter,
    key, tag, data)."""
    assert len(block) == CHALLENGE_SIZE, "challenge block must be 0x12A bytes"
    return {
        "version": block[0],
        "enabled": block[1],
        "counter": block[2:10],
        "key": block[0x0A:0x1A],
        "tag": block[0x1A:0x2A],
        "data": block[0x2A:],
    }


def decrypt_request_challenge(game_key, block, broadcast_addr):
    """Host side: decrypt the 256-byte challenge from a browse request."""
    ch = parse_challenge_block(block)
    if not ch["enabled"]:
        return ch["data"][:256]
    enc_key = aes_ecb_encrypt(game_key, ch["key"])
    nonce = nonce_from(broadcast_addr, ch["counter"])
    return aes_gcm_decrypt(enc_key, nonce, ch["tag"], ch["data"][:256])


def build_challenge_block(game_key, req_block, my_key, broadcast_addr,
                          counter=None):
    """Build the 0x12A challenge-reply block for a 5.7+ browse request.

    Response content = HMAC-SHA256(game_key, challenge)[0:16], encrypted with
    the response key derived from the session key param (my_key ++ req_key)."""
    ch = parse_challenge_block(req_block)
    if counter is None:
        counter = ch["counter"]
    if not ch["enabled"]:
        block = bytearray(CHALLENGE_SIZE)
        block[0] = ch["version"]
        block[1] = 0
        block[2:10] = counter
        block[0x0A:0x1A] = my_key
        block[0x2A:0x2A + 16] = hmac_sha256(game_key, b"")[:16]  # placeholder
        return bytes(block)

    challenge = decrypt_request_challenge(game_key, req_block, broadcast_addr)
    content = hmac_sha256(game_key, challenge)[:16]
    resp_key = hmac_sha256(game_key, my_key + ch["key"])[:16]
    nonce = nonce_from(broadcast_addr, counter)
    ct, tag = aes_gcm_encrypt(resp_key, nonce, content)

    block = bytearray(CHALLENGE_SIZE)
    block[0] = ch["version"]
    block[1] = 1
    block[2:10] = counter
    block[0x0A:0x1A] = my_key
    block[0x1A:0x2A] = tag
    block[0x2A:0x2A + len(ct)] = ct
    return bytes(block)


def verify_challenge_reply(game_key, req_block, reply_block, broadcast_addr):
    """Console side: check a challenge-reply block and recover the response.

    Session key param = reply challenge key ++ request challenge key
    (LAN-Protocol wiki "Session Key Param"); the response key is derived from
    it, so the host and console derive the SAME key.
    Returns the decrypted response content if valid, else raises ValueError."""
    ch = parse_challenge_block(reply_block)
    req_key = parse_challenge_block(req_block)["key"]
    if not ch["enabled"]:
        return hmac_sha256(game_key, decrypt_request_challenge(
            game_key, req_block, broadcast_addr))[:16]
    resp_key = hmac_sha256(game_key, ch["key"] + req_key)[:16]
    nonce = nonce_from(broadcast_addr, ch["counter"])
    content = aes_gcm_decrypt(resp_key, nonce, ch["tag"], ch["data"][:16])
    return content


# ------------------------------------------------- browse request ----------

def parse_browse_request(data):
    """Parse a browse request. Returns dict(type, size, criteria,
    challenge) where challenge is the raw 0x12A bytes or None."""
    if len(data) < 5:
        return None
    typ, size = data[0], struct.unpack(">I", data[1:5])[0]
    if typ != 0:
        return None
    if size == SEARCH_CRITERIA_SIZE:
        criteria = data[5:5 + size]
        rest = data[5 + size:]
        challenge = rest[:CHALLENGE_SIZE] if len(rest) >= CHALLENGE_SIZE else None
        return {"type": typ, "size": size, "criteria": criteria,
                "challenge": challenge}
    return {"type": typ, "size": size, "criteria": data[5:5 + size],
            "challenge": None}


def build_browse_request(crypto_enabled=True, version=CHALLENGE_VERSION_2,
                         counter=None, challenge_key=None, broadcast_addr=None,
                         game_key=None):
    """Console side (synthetic, for tests): build a 5.7+ browse request."""
    if counter is None:
        counter = int.to_bytes(0x1122334455667788, 8, "big")
    if challenge_key is None:
        challenge_key = bytes(range(16))
    criteria = bytes(SEARCH_CRITERIA_SIZE)
    if not crypto_enabled:
        return bytes([0]) + struct.pack(">I", SEARCH_CRITERIA_SIZE) + criteria

    block = bytearray(CHALLENGE_SIZE)
    block[0] = version
    block[1] = 1
    block[2:10] = counter
    block[0x0A:0x1A] = challenge_key
    if game_key is not None and broadcast_addr is not None:
        enc_key = aes_ecb_encrypt(game_key, challenge_key)
        nonce = nonce_from(broadcast_addr, counter)
        challenge = bytes((i * 7) & 0xFF for i in range(256))
        ct, tag = aes_gcm_encrypt(enc_key, nonce, challenge)
        block[0x1A:0x2A] = tag
        block[0x2A:] = ct
    else:
        block[0x1A:0x2A] = bytes(16)
        block[0x2A:] = bytes(256)
    return bytes([0]) + struct.pack(">I", SEARCH_CRITERIA_SIZE) + criteria + bytes(block)


# ------------------------------------------------- browse reply ------------

def build_session_info(layout, name, my_ip, host_constant=b"\x01" * 8,
                       host_variable=b"\x02" * 4, host_service=b"\x03" * 4,
                       game_mode=0, network_id=0, attributes=b"",
                       session_type=0, app_data=b"", app_data_size=None,
                       is_opened=1, syscomm=None, appcomm=None,
                       session_key_param=b"",
                       current_participants=1, min_participants=1,
                       max_participants=8):
    """LanSessionInfo for the 5.3-5.6 and 5.10+ layouts. Sizes per SIZES."""
    if layout == "5.3-5.6":
        info = bytearray(SIZES["5.3-5.6"])
        info[0:4] = struct.pack(">I", game_mode)
        info[4:8] = struct.pack(">I", network_id)
        info[8:8 + 24] = attributes.ljust(24, b"\x00")[:24]
        info[0x20:0x22] = struct.pack(">H", current_participants)
        info[0x22:0x24] = struct.pack(">H", min_participants)
        info[0x24:0x26] = struct.pack(">H", max_participants)
        info[0x26] = syscomm if syscomm is not None else 0
        info[0x27] = appcomm if appcomm is not None else 0
        info[0x28:0x2A] = struct.pack(">H", session_type)
        info[0x2A:0x2A + 384] = app_data.ljust(384, b"\x00")[:384]
        info[0x1AA:0x1AE] = struct.pack(">I", app_data_size if app_data_size is not None else 0)
        info[0x1AE] = is_opened
        # host StationLocation: 4B addr + 2B port + ... (35B)
        info[0x1AF:0x1AF + 4] = my_ip
        info[0x1AF + 4:0x1AF + 6] = struct.pack(">H", 30000)
        # first station = host
        st = bytearray(50)
        st[0] = 1  # role host
        st[1] = 1  # username encoding UTF-8
        nb = name.encode("utf-8")[:40]
        st[2:2 + len(nb)] = nb
        info[0x1D2:0x1D2 + 50] = st
        return bytes(info)

    if layout == "5.10+":
        info = bytearray(SIZES["5.10+"])
        info[0:4] = struct.pack(">I", game_mode)
        info[4:8] = struct.pack(">I", network_id)
        info[8:8 + 24] = attributes.ljust(24, b"\x00")[:24]
        info[0x20:0x22] = struct.pack(">H", current_participants)
        info[0x22:0x24] = struct.pack(">H", min_participants)
        info[0x24:0x26] = struct.pack(">H", max_participants)
        info[0x26] = syscomm if syscomm is not None else 6
        info[0x27] = appcomm if appcomm is not None else 1
        info[0x28:0x2A] = struct.pack(">H", session_type)
        info[0x2A:0x2A + 384] = app_data.ljust(384, b"\x00")[:384]
        info[0x1AA:0x1AE] = struct.pack(">I", app_data_size if app_data_size is not None else 0)
        info[0x1AE] = is_opened
        # host StationAddress 18B: 4B ip + 2B port + 12B zero (IPv4 inet addr)
        info[0x1AF:0x1AF + 4] = my_ip
        info[0x1AF + 4:0x1AF + 6] = struct.pack(">H", 30000)
        info[0x1C1:0x1C1 + 8] = host_constant
        info[0x1C9:0x1C9 + 4] = host_variable
        info[0x1CD:0x1CD + 4] = host_service
        st = bytearray(50)
        st[0] = 1
        st[1] = 1
        nb = name.encode("utf-8")[:40]
        st[2:2 + len(nb)] = nb
        info[0x1D1:0x1D1 + 50] = st
        info[0x4F1:0x4F1 + 32] = session_key_param.ljust(32, b"\x00")[:32]
        return bytes(info)
    raise ValueError(f"unknown layout {layout}")


def build_browse_reply(profile, request, my_ip, name, my_key=None,
                       broadcast_addr=None, game_mode=None, network_id=None,
                       min_participants=None, max_participants=None,
                       current_participants=None):
    """Build a full browse-reply packet for a parsed browse request.

    broadcast_addr must be the request's destination broadcast IP (used for
    the AES-GCM nonce of the challenge reply). It defaults to the host's own
    subnet broadcast."""
    layout = profile["layout"]
    session_key_param = b""
    if request["challenge"] is not None and profile["challenge"]:
        if my_key is None:
            my_key = bytes((0xA0 + i) & 0xFF for i in range(16))
        ch = parse_challenge_block(request["challenge"])
        session_key_param = my_key + ch["key"]
    if network_id is None:
        # Pia-Types: LAN network id = ((ip & 0xFFFF) << 16) | port, unless the
        # profile pins one (KartLANPwn's fake-host magic).
        network_id = profile.get("network_id",
                                 lan_network_id(my_ip, profile.get("browse_port", 30000)))
    info = build_session_info(layout, name, my_ip,
                              game_mode=profile.get("game_mode", 0) if game_mode is None else game_mode,
                              network_id=network_id,
                              session_type=profile.get("session_type", 0),
                              syscomm=profile.get("syscomm"),
                              appcomm=profile.get("appcomm"),
                              current_participants=profile.get("current_participants", 1) if current_participants is None else current_participants,
                              min_participants=profile.get("min_participants", 1) if min_participants is None else min_participants,
                              max_participants=profile.get("max_participants", 8) if max_participants is None else max_participants,
                              session_key_param=session_key_param)
    packet = bytes([1]) + struct.pack(">I", len(info)) + info
    if request["challenge"] is not None and profile["challenge"]:
        reply_block = build_challenge_block(profile["key"], request["challenge"],
                                            my_key, broadcast_addr or bcast_for(my_ip))
        # The reply MUST carry a challenge response when the request carried a
        # challenge -- otherwise 5.7+ games reject the room and it never lists.
        # MK8DX does send one (browse requests arrive with challenge=True).
        #
        # build_challenge_block() pads to CHALLENGE_SIZE (0x12A = 298), but that
        # is the size of the REQUEST block. Only 0x3A bytes are actually
        # populated (version@0, counter@2, my_key@0x0A, content@0x2A+16) and the
        # rest is zero padding. Appending all 298 makes the datagram 1569 bytes,
        # over the 1364 maximum, so the old code silently skipped the block
        # entirely and we sent every reply with no response at all.
        #
        # A real console's reply has to fit under 1364 too, so the reply block
        # cannot be 298. Send the populated extent; 1271 + 58 = 1329, which fits.
        # SLP_CHALLENGE_LEN overrides the length for experimentation, and
        # SLP_CHALLENGE=off restores the old (broken) omit-it behaviour.
        import os as _os
        if _os.environ.get("SLP_CHALLENGE", "on").lower() != "off":
            _n = int(_os.environ.get("SLP_CHALLENGE_LEN", "0x3A"), 0)
            _blk = reply_block[:_n] if 0 < _n < len(reply_block) else reply_block
            if len(packet) + len(_blk) <= MAX_BROWSE_REPLY_SIZE:
                packet += _blk
            else:
                print(f"[LAN] challenge block {len(_blk)}B would exceed "
                      f"{MAX_BROWSE_REPLY_SIZE}B cap -- omitted")
    return packet


def bcast_for(my_ip):
    return broadcast_addr_for(my_ip, bytes([255, 255, 255, 0]))


def extract_session_info(packet):
    """Parse a reply: (type, size, info, challenge or None)."""
    if len(packet) < 5 or packet[0] != 1:
        return None
    size = struct.unpack(">I", packet[1:5])[0]
    info = packet[5:5 + size]
    challenge = packet[5 + size:]
    return {"type": 1, "size": size, "info": info,
            "challenge": challenge[:CHALLENGE_SIZE] if len(challenge) >= CHALLENGE_SIZE else None}
