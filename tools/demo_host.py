#!/usr/bin/env python3
"""
Host a demo Mario Kart 8 Deluxe lobby (both WiFi/LDN and LAN mode) against the relay server.
Usage: python3 spike/demo_host.py [relay_ip] [relay_port]
"""
import os
import sys
import time
import socket
import struct
import threading
import slp_lan as lan
import slp_pia as pia
from test_lan import RelayPeer
from slp_ldn import LdnNode

RELAY_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11451

# Virtual IPs for our hosts on the slp relay
WIFI_IP = bytes([10, 13, 37, 3])
LAN_IP = bytes([10, 13, 37, 100])

MK8DX = lan.PROFILES["mk8dx"]
# MK8DX uses title ID for local communication ID by default
MK8DX_LCID = 0x0100152000022000

# Reply values that satisfy the joiner's LAN search criteria (decoded from a
# real MK8DX LAN browse: min participants 2, max 14, opened-only, game mode 1,
# session type 0) and match the KartLANPwn working fake-host magic
# (syscomm 2 / appcomm 13 / network id 0x0150C000).
MK8DX_LAN_REPLY = dict(lan.PROFILES["mk8dx"])

# The room fields below are TUNING GUESSES, not protocol requirements. None of
# them come from the base "mk8dx" profile, which would otherwise compute
# network_id from our IP and use game_mode 0 / min 1 / max 8. They accumulated
# while chasing 2618-0006 and were never validated against a real MK8DX host's
# reply, so they are a prime suspect for the lobby not listing.
#
# SLP_LAN_PROFILE=defaults  -> plain profile, no overrides (A)
# SLP_LAN_PROFILE=tuned     -> the accumulated overrides (B, default)
import os as _os
_PROFILE = _os.environ.get("SLP_LAN_PROFILE", "tuned").lower()
if _PROFILE == "defaults":
    print("[LAN] reply profile: DEFAULTS (no overrides)")
else:
    print("[LAN] reply profile: TUNED (game_mode=1, pinned network_id, min=2, max=14)")
    # syscomm/appcomm come from the profile (2 / 13). The game's search
    # criteria carry an unexplained 0x0A (=10) at offset 0x11 with search flags
    # 0x0FFF ("match every field"), so if that is the communication version it
    # wants, 13 can never match. Overridable so we can sweep it without a
    # rebuild: SLP_APPCOMM / SLP_SYSCOMM.
    import os as _o
    if _o.environ.get("SLP_APPCOMM"):
        MK8DX_LAN_REPLY["appcomm"] = int(_o.environ["SLP_APPCOMM"], 0)
    if _o.environ.get("SLP_SYSCOMM"):
        MK8DX_LAN_REPLY["syscomm"] = int(_o.environ["SLP_SYSCOMM"], 0)
    MK8DX_LAN_REPLY.update({"game_mode": 1, "network_id": 0x0150C000,
                            "session_type": 0, "min_participants": 2,
                            "max_participants": 14,
                            # 1, not 2: the LAN lobby actually seen on hardware
                            # was advertised with 1.
                            "current_participants": 1}) 

def host_wifi():
    print(f"[WIFI] Starting LDN host at {list(WIFI_IP)}...")
    node = LdnNode(WIFI_IP, "mario", (RELAY_HOST, RELAY_PORT))
    node.state = 1 # STATE_INITIALIZED
    node.open_access_point()
    # Match a real MK8DX room: 8 max players and a random session id
    # (the default bytes(range(16)) looked obviously synthetic next to the
    # console's own room in the relay playground).
    node.create_network(local_comm_id=MK8DX_LCID, node_count_max=8,
                        session_id=os.urandom(16))
    print(f"[WIFI] Network created. LCID={hex(MK8DX_LCID)}")
    
    last_count = 0
    while True:
        node.keepalive()
        # Monitor connections
        conns = sum(1 for s in node.stations.values() if s.get("connected"))
        if conns != last_count:
            print(f"[WIFI] Peer count changed: {last_count} -> {conns}")
            last_count = conns
        time.sleep(5)

# --- PIA nonce source-IP discovery -------------------------------------
# The v9 Pia nonce is  src_ip(4) + src_var&0xFF + hdr_nonce[1:] .  The GAME
# builds it from the address it believes it owns -- its REAL nifm address,
# e.g. 10.172.227.168 -- but the packet reaches us stamped with the VIRTUAL
# relay address (10.13.37.2), so decrypt_and_verify() fails the MAC and we
# reported it as "wrong key".  ldn_mitm never hits this because it requires a
# static 10.13.x.x console IP, making the two addresses identical.
# We do not know the console's DHCP address here, so try the virtual address
# first, then sweep the real /24, and cache whatever verifies for that peer.
REAL_LAN_PREFIX = bytes([10, 172, 227])
_PIA_SRC_CACHE = {}

# build_browse_reply()'s default host key when none is passed.
DEFAULT_MY_KEY = bytes((0xA0 + i) & 0xFF for i in range(16))
# peer -> session_key_param advertised to it in the browse reply
ADVERTISED_SKP = {}

def pia_try_parse(key, payload, src):
    """Returns (parsed, src_ip_used) or (None, None)."""
    peer = bytes(src)
    cached = _PIA_SRC_CACHE.get(peer)
    if cached is not None:
        parsed = pia.parse_pia_packet(key, payload, cached)
        if parsed is not None:
            return parsed, cached
    # The client encrypts with the DERIVED session key, not the raw game key:
    #   session_key = HMAC-SHA256(game_key, skp with last byte +1)[:16]
    # where skp is the session_key_param we advertised in the browse reply.
    keys = []
    skp = ADVERTISED_SKP.get(peer)
    if skp is not None:
        keys.append(("derived", pia.derive_session_key(key, skp)))
    keys.append(("raw", key))

    candidates = [peer] + [REAL_LAN_PREFIX + bytes([o]) for o in range(1, 255)]
    for kind, k in keys:
        for cand in candidates:
            parsed = pia.parse_pia_packet(k, payload, cand)
            if parsed is not None:
                print(f"[LAN] PIA decrypted with {kind} key, "
                      f"nonce src_ip {'.'.join(map(str, cand))} "
                      f"(arrived from {'.'.join(map(str, peer))})")
                _PIA_SRC_CACHE[peer] = cand
                return parsed, cand
    return None, None

# Track session_key_param per client (keyed by src_var)
SESSION_KEY_PARAMS = {}

def host_lan():
    print(f"[LAN] Starting LAN mode host at {list(LAN_IP)}...")
    peer = RelayPeer(LAN_IP)
    peer.server = (RELAY_HOST, RELAY_PORT)
    
    bcast = lan.bcast_for(LAN_IP)
    
    while True:
        peer.keepalive()
        peer.pump()
        for i in range(len(peer.pending)-1, -1, -1):
            pkt = peer.pending.pop(i)   # consume up front: avoids double-delete / stale-index bugs
            if len(pkt) < 20: continue
            
            dst = pkt[16:20]
            # The console's tunnel presents its virtual LAN src IP (10.13.37.2)
            # but keeps the ORIGINAL broadcast dst from the game, which is the
            # real WiFi subnet broadcast (e.g. 10.172.227.255). Accept any
            # broadcast / non-unicast destination so browse requests arrive.
            is_our_ip = (dst == LAN_IP or dst == bytes([10, 13, 37, 2]))
            if not is_our_ip and dst != bcast and dst != bytes([255, 255, 255, 255]):
                # accept any *-.-.-.255 subnet broadcast (real WiFi subnet too)
                if dst[3] != 255:
                    continue
                
            u = (pkt[0] & 0x0F) * 4
            if pkt[9] != 17: continue # not UDP
            sport = int.from_bytes(pkt[u+0:u+2], "big")
            dport = int.from_bytes(pkt[u+2:u+4], "big")
            ulen = int.from_bytes(pkt[u+4:u+6], "big")
            payload = pkt[u+8:u+ulen]
            src = pkt[12:16]
            
            if dport == 30000:
                # Browse request
                req = lan.parse_browse_request(payload)
                if req is not None:
                    print(f"[LAN] Received browse request from {list(src)} (challenge={req['challenge'] is not None}). Replying...")
                    # dst is the console's subnet broadcast (e.g. 10.172.227.255);
                    # the challenge-reply AES-GCM nonce must use that broadcast.
                    # Never let a crypto failure kill the LAN thread: if the
                    # nonce doesn't match (e.g. something rewrote the broadcast
                    # in transit) we still want the host alive and logging.
                    try:
                        reply = lan.build_browse_reply(MK8DX_LAN_REPLY, req, LAN_IP,
                                                       "luigi", broadcast_addr=dst)
                    except Exception as e:
                        print(f"[LAN] build_browse_reply FAILED for dst={list(dst)}: {e!r}")
                        continue
                    # Dump the game's SEARCH CRITERIA. The game decides whether
                    # to list a room by matching these against the session info
                    # we advertise; we have been guessing at those fields
                    # without ever reading what is actually being asked for.
                    try:
                        _c = req.get("criteria") or b""
                        # FULL dump: everything past the first 64 bytes has never
                        # been examined, and the criteria are the game's own
                        # filter spec. Print non-zero regions so attribute
                        # filters we fail to satisfy become visible.
                        print(f"[LAN] criteria ({len(_c)}B) non-zero regions:")
                        _run = None
                        for _i in range(len(_c)):
                            if _c[_i]:
                                if _run is None:
                                    _run = _i
                            elif _run is not None:
                                print(f"[LAN]   [{_run:#05x}..{_i:#05x}] {_c[_run:_i].hex()}")
                                _run = None
                        if _run is not None:
                            print(f"[LAN]   [{_run:#05x}..{len(_c):#05x}] {_c[_run:].hex()}")
                        if len(_c) >= 12:
                            import struct as _st
                            _gm = _st.unpack(">I", _c[0:4])[0]
                            _nid = _st.unpack(">I", _c[4:8])[0]
                            _min = _st.unpack(">H", _c[8:10])[0]
                            _max = _st.unpack(">H", _c[10:12])[0]
                            print(f"[LAN]   as session-info layout -> game_mode={_gm} "
                                  f"network_id={_nid:#010x} min={_min} max={_max}")
                        print(f"[LAN]   WE ADVERTISE -> game_mode="
                              f"{MK8DX_LAN_REPLY.get('game_mode')} "
                              f"network_id={MK8DX_LAN_REPLY.get('network_id')} "
                              f"min={MK8DX_LAN_REPLY.get('min_participants')} "
                              f"max={MK8DX_LAN_REPLY.get('max_participants')} "
                              f"cur={MK8DX_LAN_REPLY.get('current_participants')}")
                    except Exception as e:
                        print(f"[LAN] criteria dump failed: {e!r}")

                    # Remember the session_key_param this reply advertised.
                    # The client derives its Pia session key from it, so without
                    # it we cannot decrypt anything it sends to :49152. Nothing
                    # used to store this -- SESSION_KEY_PARAMS was read but never
                    # written -- so every session packet failed to parse.
                    try:
                        if req["challenge"] is not None and MK8DX["challenge"]:
                            _ch = lan.parse_challenge_block(req["challenge"])
                            ADVERTISED_SKP[bytes(src)] = DEFAULT_MY_KEY + _ch["key"]
                    except Exception as e:
                        print(f"[LAN] could not record session_key_param: {e!r}")
                    for _ in range(3):
                        peer.send_udp(src, 30000, 30000, reply)
                
            elif dport == 49152:
                # Pia Session layer - handle PIA handshake
                print(f"[LAN] Received session-layer UDP from {list(src)} on 49152 "
                      f"({len(payload)}B: {payload[:16].hex()}...).")
                
                # Try to parse PIA packet
                MK8DX_KEY = MK8DX["key"]  # 'ABCDEFGHIJKLMNOP'
                parsed, pia_src_ip = pia_try_parse(MK8DX_KEY, payload, src)
                if parsed is None:
                    print(f"[LAN] Failed to parse PIA packet: {pia.why_parse_failed(payload)}")
                    print(f"[LAN]   header: {payload[:32].hex()}")
                    continue
                
                src_var = parsed['src_var']
                dst_var = parsed['dst_var']
                print(f"[LAN] Parsed PIA packet: src_var={src_var:#x}, dst_var={dst_var:#x}, payloads={len(parsed['payloads'])}")
                
                for lan_payload in parsed['payloads']:
                    lan_type, lan_body = pia.parse_lan_message(lan_payload)
                    print(f"[LAN] LAN message type={lan_type} len={len(lan_body)}")
                    
                    if lan_type == pia.LAN_SESSION_REQUEST:
                        # Session Request (type 5) - reply with Session Message (type 6)
                        network_id = struct.unpack(">I", lan_body[:4])[0]
                        print(f"[LAN] Session Request: network_id={network_id:#x}")
                    
                        # Get the session_key_param we stored for this client (keyed by src_var)
                        # The session_key_param = host_key + client_key (32 bytes)
                        # We stored it during browse reply
                        session_key_param = SESSION_KEY_PARAMS.get(src_var)
                        if session_key_param is None:
                            print(f"[LAN] No session_key_param for src_var={src_var:#x}, using dummy")
                            # Fallback: use host_key + dummy client_key
                            host_key = bytes((0xA0 + i) & 0xFF for i in range(16))
                            dummy_client_key = bytes((0x10 + i) & 0xFF for i in range(16))
                            session_key_param = host_key + dummy_client_key
                    
                        print(f"[LAN] Using session_key_param: {session_key_param.hex()}")
                        session_key = pia.derive_session_key(MK8DX["key"], session_key_param)
                        print(f"[LAN] Derived session_key: {session_key.hex()}")
                    
                        # Build Session Message reply with LanSessionInfo
                        session_info = lan.build_session_info(
                            layout="5.10+",
                            name="localhost",
                            my_ip=LAN_IP,
                            host_constant=b"\x01" * 8,
                            host_variable=b"\x02" * 4,
                            host_service=b"\x03" * 4,
                            game_mode=1,
                            network_id=network_id,
                            session_type=0,
                            syscomm=2,
                            appcomm=13,
                            session_key_param=b"",  # filled by build_pia_packet
                            min_participants=2,
                            max_participants=14,
                        )
                    
                        # Fragment the session info (max 1400 bytes per fragment)
                        frag_size = 1400
                        frags = [session_info[i:i+frag_size] for i in range(0, len(session_info), frag_size)]
                    
                        # Send Session Message fragments
                        for frag_idx, frag in enumerate(frags):
                            lan_msg = pia.lan_session_message(
                                random_id=0x77778888,
                                seq_id=0,
                                frag_index=frag_idx,
                                num_frags=len(frags),
                                frag_size=len(frag),
                                frag_data=frag
                            )
                            # Build PIA packet
                            pia_pkt = pia.build_pia_packet(
                                session_key, [lan_msg], LAN_IP, 0x11223344, 0x55667788,
                                nonce_ctr=0, packet_id=1
                            )
                            # Send via relay
                            for _ in range(3):
                                peer.send_udp(src, 49152, 49152, pia_pkt)
                            print(f"[LAN] Sent Session Message fragment {frag_idx+1}/{len(frags)}")
                
                    elif lan_type == pia.LAN_KEEP_ALIVE:
                        print(f"[LAN] Keep-alive received, replying")
                        # Reply with keep-alive
                        lan_msg = pia.lan_keep_alive()
                        MK8DX_KEY = MK8DX["key"]
                        session_key = pia.derive_session_key(MK8DX_KEY, b"\x00" * 32)
                        pia_pkt = pia.build_pia_packet(
                            session_key, [lan_msg], LAN_IP, 0x11223344, 0x55667788,
                            nonce_ctr=0, packet_id=1
                        )
                        for _ in range(3):
                            peer.send_udp(src, 49152, 49152, pia_pkt)
                

        time.sleep(1)

def main():
    print(f"Connecting to slp relay at {RELAY_HOST}:{RELAY_PORT}")
    w_thread = threading.Thread(target=host_wifi, daemon=True)
    w_thread.start()
    
    l_thread = threading.Thread(target=host_lan, daemon=True)
    l_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping hosts.")

if __name__ == "__main__":
    main()
