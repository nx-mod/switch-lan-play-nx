#!/usr/bin/env python3
"""
Join a demo Mario Kart 8 Deluxe lobby (both WiFi/LDN and LAN mode) against the relay server.
Usage: python3 spike/demo_join.py [relay_ip] [relay_port]
"""
import sys
import time
import threading
import slp_lan as lan
from test_lan import RelayPeer
from slp_ldn import LdnNode

RELAY_HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
RELAY_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11451

# Virtual IPs for our clients on the slp relay
WIFI_IP = bytes([10, 13, 37, 4])
LAN_IP = bytes([10, 13, 37, 101])

MK8DX = lan.PROFILES["mk8dx"]
MK8DX_LCID = 0x0100152000022000 

def join_wifi():
    print(f"[WIFI] Starting LDN client at {list(WIFI_IP)}...")
    node = LdnNode(WIFI_IP, "MK8-W-CLIENT", (RELAY_HOST, RELAY_PORT))
    node.state = 1 # STATE_INITIALIZED
    node.open_station()
    
    print(f"[WIFI] Scanning for MK8DX lobbies (LCID={hex(MK8DX_LCID)})...")
    results = node.scan(timeout=2.0, local_comm_id=MK8DX_LCID)
    if not results:
        print("[WIFI] No lobbies found.")
        return
        
    print(f"[WIFI] Found {len(results)} lobbies! Joining the first one: {results[0]['nodes'][0]['name']}")
    success = node.connect(results[0], timeout=3.0)
    if success:
        print("[WIFI] Successfully joined LDN lobby!")
    else:
        print("[WIFI] Failed to join.")

def join_lan():
    print(f"[LAN] Starting LAN mode client at {list(LAN_IP)}...")
    peer = RelayPeer(LAN_IP)
    peer.server = (RELAY_HOST, RELAY_PORT)
    peer.keepalive()
    
    bcast = bytes([255, 255, 255, 255])
    
    print(f"[LAN] Broadcasting browse request to 30000...")
    req = lan.build_browse_request(crypto_enabled=False, version=1, broadcast_addr=bcast, game_key=MK8DX["key"])
    peer.send_udp(bcast, 30000, 30000, req)
    
    reply = peer.next_udp(LAN_IP, timeout=2.0)
    if reply is None:
        print("[LAN] No browse reply received.")
        return
        
    print("[LAN] Received browse reply!")
    info = lan.extract_session_info(reply)
    if info:
        print(f"[LAN] Parsed LanSessionInfo (size {info['size']}). Room name is likely embedded inside.")
        print("[LAN] Success: The room would now appear in the MK8DX LAN menu!")

def main():
    print(f"Connecting to slp relay at {RELAY_HOST}:{RELAY_PORT}")
    w_thread = threading.Thread(target=join_wifi)
    l_thread = threading.Thread(target=join_lan)
    
    w_thread.start()
    l_thread.start()
    
    w_thread.join()
    l_thread.join()

if __name__ == "__main__":
    main()
