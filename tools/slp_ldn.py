#!/usr/bin/env python3
"""
sys-slp-client — LDN control plane codec + virtual console state machine.

Python port of ldn_mitm's lan_protocol.cpp / lan_discovery.cpp adapted for the
slp relay: instead of real UDP broadcast / per-station TCP, every LAN control
frame is a UDP datagram on the control port (11452, ldn_mitm's DefaultPort)
carried through the relay as an IPv4/UDP packet by our tunnel. This is exactly
what sys-slp-client's ldn:u MITM (LdnControl) does on console.

Wire layout (identical to ldn_mitm):

  LANPacketHeader (12 B, no padding):
    magic u32       0x11451400
    type  u8        Scan=0 ScanResp=1 Connect=2 SyncNetwork=3
    compressed u8   0/1
    length u16      on-wire body length (after RLE)
    decompress_length u16   original body length when compressed
    reserved u8[2]

  body: NetworkInfo (0x480) for ScanResp/SyncNetwork, NodeInfo (0x40) for
  Connect. RLE compression: a literal 0x00 byte is written as (0x00, count)
  meaning "zero repeated count+1 times"; every other byte is literal.

Control flow (mirrors LANDiscovery):
  host:  OpenAccessPoint -> CreateNetwork -> on Scan reply ScanResp; on Connect
         copy station NodeInfo + record its tunnel src IP -> UpdateNodes ->
         unicast SyncNetwork to every connected station.
  client: OpenStation -> scan() (broadcast Scan, collect ScanResp) ->
         connect() (unicast Connect to nodes[0].ipv4Address, wait for
         SyncNetwork) -> StationConnected.

Usage: import slp_ldn as ldn
"""

import os
import socket
import struct
import threading
import time

LAN_MAGIC = 0x11451400

LAN_SCAN = 0
LAN_SCAN_RESP = 1
LAN_CONNECT = 2
LAN_SYNC_NETWORK = 3

CONTROL_PORT = 11452
FAKE_SSID = "12345678123456781234567812345678"

# CommState
STATE_NONE, STATE_INITIALIZED, STATE_ACCESS_POINT, \
    STATE_ACCESS_POINT_CREATED, STATE_STATION, STATE_STATION_CONNECTED, \
    STATE_ERROR = range(7)

# NodeStateChange
NSC_NONE, NSC_CONNECT, NSC_DISCONNECT, NSC_DISCONNECT_AND_CONNECT = range(4)

HDR = struct.Struct("<IBBH H 2x")          # 12 B
# LITTLE-endian. ldn_mitm and slp-server-rust both read this header LE
# (see lan_protocol.rs: magic=get_u32_le, len/decompress_len=get_u16_le),
# and the console's C++ memcpy's it on little-endian ARM64. This was ">"
# (big-endian), which broke BOTH directions: inbound magic never matched
# so a Scan was silently dropped and no ScanResp was ever sent, and
# outbound packets carried a byte-reversed magic the relay rejected.
# Net effect: the fake WiFi/LDN lobby was never visible to anything.
# All LDN wire structs are LITTLE-endian: slp-server-rust reads them with
# get_u32_le/get_u16_le and the console C++ memcpy's them on little-endian
# ARM64. These were ">" (big-endian), which byte-reversed every multi-byte
# field -- e.g. a node IP of 10.13.37.3 showed up on the relay as 3.37.13.10,
# and nodeCountMax/advertiseDataSize came out garbage, so MK8DX rejected the
# advertised lobby even though the relay happily listed it.
SSID = struct.Struct("<B33s")
NODE = struct.Struct("<I6sbb33sb h16s")    # 64 B
COMMON = struct.Struct("<6s34sh bB4x")     # 48 B
LDN = struct.Struct("<16sHB3xBB512sHH384s148s")   # 0x430
NETWORK = struct.Struct("<32s48s1072s")    # 0x480

NODE_COUNT_MAX = 8


# --------------------------------------------------------------------------- #
# RLE (exact port of lan_protocol.cpp compress/decompress)                    #
# --------------------------------------------------------------------------- #

def compress(data):
    """Return compressed bytes, or None if the result is not smaller."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        i += 1
        count = 0
        if c == 0:
            while i < n and data[i] == 0 and count < 0xFF:
                count += 1
                i += 1
        if c == 0:
            out.append(0)
            out.append(count)
        else:
            out.append(c)
    out = bytes(out)
    return out if len(out) < len(data) else None


def decompress(data):
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        c = data[i]
        i += 1
        out.append(c)
        if c == 0:
            if i == n:
                raise ValueError("RLE truncated")
            count = data[i]
            i += 1
            for _ in range(count):
                out.append(0)
    return bytes(out)


# --------------------------------------------------------------------------- #
# packet codec                                                                #
# --------------------------------------------------------------------------- #

def pack_header(ptype, body, use_compression=True):
    if use_compression:
        comp = compress(body)
    else:
        comp = None
    if comp is not None:
        return HDR.pack(LAN_MAGIC, ptype, 1, len(comp), len(body)) + comp
    return HDR.pack(LAN_MAGIC, ptype, 0, len(body), 0) + body


def unpack_packet(buf):
    if len(buf) < HDR.size:
        return None
    magic, ptype, compressed, length, dl = HDR.unpack(buf[:HDR.size])
    if magic != LAN_MAGIC:
        return None
    total = HDR.size + length
    if len(buf) < total:
        return None
    body = buf[HDR.size:total]
    if compressed:
        body = decompress(body)
        if len(body) != dl:
            raise ValueError("decompressed length mismatch")
    return ptype, body


# --------------------------------------------------------------------------- #
# struct builders                                                             #
# --------------------------------------------------------------------------- #

def ip_bytes_u32(ip):
    return int.from_bytes(ip, "big")


def ip_u32_bytes(v):
    return v.to_bytes(4, "big")


def build_ssid(s):
    raw = s.encode("utf-8")
    if len(raw) > 32:
        raise ValueError("ssid too long")
    return SSID.pack(len(raw), raw.ljust(32, b"\x00") + b"\x00")


def fake_mac(ip):
    # ldn_mitm getFakeMac: 02:00:<ip 4 bytes as written in memory>
    return bytes([0x02, 0x00]) + ip


def build_node_info(ip, node_id, is_connected, name, lcv=6, mac=None):
    if mac is None:
        mac = fake_mac(ip)
    name_b = name.encode("utf-8")[:32]
    return NODE.pack(ip_bytes_u32(ip), mac, node_id, is_connected,
                     name_b.ljust(32, b"\x00") + b"\x00", 0, lcv, b"\x00" * 16)


def parse_node_info(buf):
    ip, mac, nid, conn, name, _u1, lcv, _u2 = NODE.unpack(buf)
    return dict(ip=ip_u32_bytes(ip), mac=mac, node_id=nid, is_connected=conn,
                name=name.rstrip(b"\x00").decode("utf-8", "replace"), lcv=lcv)


def build_ldn_network_info(nodes, node_count_max=7, security_mode=0,
                           advertise=b"", unk_random=b"\x00" * 16):
    if len(nodes) > NODE_COUNT_MAX:
        raise ValueError("too many nodes")
    if len(advertise) > 384:
        raise ValueError("advertise too long")
    buf = bytearray(LDN.size)
    LDN.pack_into(buf, 0, unk_random, security_mode, 0,
                  node_count_max, len(nodes),
                  b"".join(nodes).ljust(512, b"\x00"),
                  0, len(advertise), advertise.ljust(384, b"\x00"),
                  b"\x00" * 148)
    return bytes(buf)


def build_common_network_info(bssid, ssid=FAKE_SSID, channel=6, link_level=3,
                              network_type=2):
    return COMMON.pack(bssid, build_ssid(ssid), channel, link_level,
                       network_type)


def build_network_info(intent_id, session_id, common, ldn, network_type=2):
    if isinstance(intent_id, int):
        intent = intent_id.to_bytes(16, "little")
    else:
        intent = intent_id
    if isinstance(session_id, bytes):
        session = session_id
    else:
        session = session_id
    return NETWORK.pack(intent + session, common, ldn)


def parse_network_info(buf):
    if len(buf) != NETWORK.size:
        raise ValueError(f"NetworkInfo size {len(buf)} != 0x480")
    netid, common, ldn = NETWORK.unpack(buf)
    intent = netid[:16]
    session = netid[16:32]
    bssid = common[:6]
    slen = common[6]
    ssid = common[7:7 + slen].decode("utf-8", "replace")
    channel, link, ntype = struct.unpack(">hbB", common[40:44])
    nmax, ncount = ldn[22], ldn[23]
    nodes = []
    for i in range(ncount):
        nodes.append(parse_node_info(ldn[24 + i * 64:24 + (i + 1) * 64]))
    adv_size = struct.unpack(">H", ldn[536:538])[0]
    advertise = ldn[540:540 + adv_size]
    return dict(intent=intent, session=session, bssid=bssid, ssid=ssid,
                channel=channel, link_level=link, network_type=ntype,
                node_count_max=nmax, node_count=ncount, nodes=nodes,
                advertise=advertise)


# --------------------------------------------------------------------------- #
# virtual TCP (station connection)                                            #
# --------------------------------------------------------------------------- #
# ldn_mitm's own station connection (Connect + SyncNetwork) is a REAL TCP
# socket, not a UDP datagram like Scan/ScanResp -- see this module's own
# docstring above. switch-lan-play-nx's bridge (source/bsd/
# bsd_bridge_service.cpp, SendTcpSegment/HandleTcpSegment) emulates that
# real TCP connection over the relay's raw UDP transport with a genuine
# SYN/SYN-ACK/ACK handshake and real IP/TCP headers + checksums. This is a
# byte-exact port of that same wire format, so a real console's ldn_mitm
# (via that bridge) can actually complete a handshake with this tool.
#
# Outer IP/TCP headers are real, standard headers -- network byte order
# (big-endian) per RFC, unrelated to the LDN payload's own little-endian
# struct encoding above.

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _tcp_checksum(src_ip, dst_ip, seg):
    s = 0
    s += (src_ip[0] << 8) | src_ip[1]
    s += (src_ip[2] << 8) | src_ip[3]
    s += (dst_ip[0] << 8) | dst_ip[1]
    s += (dst_ip[2] << 8) | dst_ip[3]
    s += 6  # IPPROTO_TCP
    s += len(seg)
    i = 0
    while i + 1 < len(seg):
        s += (seg[i] << 8) | seg[i + 1]
        i += 2
    if i < len(seg):
        s += seg[i] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
    """Real IPv4+TCP segment, byte-exact match for switch-lan-play-nx's
    SendTcpSegment: standard 20B IP + 20B TCP (no options), real
    pseudo-header checksum, IP header checksum left 0 (the bridge's own
    receiver doesn't check it either)."""
    tcp_len = 20 + len(payload)
    total = 20 + tcp_len
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0x00, total, 0, 0, 64, 6, 0,
                         bytes(src_ip), bytes(dst_ip))
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port,
                          seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          5 << 4, flags, 0x2000, 0, 0)
    seg = tcp_hdr + payload
    csum = _tcp_checksum(src_ip, dst_ip, seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return ip_hdr + seg


def _parse_ipv4_tcp(pkt):
    """Return (src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    or None. Mirrors bsd_bridge_service.cpp's ParseIpv4Tcp."""
    if len(pkt) < 40:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] != 6 or len(pkt) < ihl + 20:
        return None
    src_ip = pkt[12:16]
    dst_ip = pkt[16:20]
    tcp = pkt[ihl:]
    src_port, dst_port, seq, ack = struct.unpack("!HHII", tcp[0:12])
    data_offset = (tcp[12] >> 4) * 4
    flags = tcp[13]
    if data_offset < 20 or ihl + data_offset > len(pkt):
        return None
    payload = pkt[ihl + data_offset:]
    return src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload


def _seq_gt(a, b):
    return ((a - b) & 0xFFFFFFFF) < 0x80000000 and a != b


class VTcp:
    """One virtual TCP connection over the relay -- either role (client:
    connect(), or server: created on an inbound SYN and driven by
    on_segment() until ESTABLISHED). State machine mirrors
    BsdBridgeService::HandleTcpSegment exactly."""

    def __init__(self, node, peer_ip, peer_port, my_port=CONTROL_PORT):
        self.node = node
        self.peer_ip = bytes(peer_ip)
        self.peer_port = peer_port
        self.my_port = my_port
        self.state = "CLOSED"  # CLOSED, SYN_SENT, SYN_RCVD, ESTABLISHED
        self.our_isn = 0
        self.our_seq = 0
        self.their_seq = 0
        self.inbox = []
        self._lock = threading.Lock()

    def _send(self, seq, ack, flags, payload=b""):
        seg = _build_tcp_segment(self.node.ip, self.peer_ip, self.my_port,
                                 self.peer_port, seq, ack, flags, payload)
        self.node.sock.sendto(bytes([0x01]) + seg, self.node.server)

    def connect(self, timeout=3.0):
        """Client role: SYN -> wait for SYN-ACK (on_segment completes the
        handshake and sends our final ACK) -> ESTABLISHED."""
        self.our_isn = int.from_bytes(os.urandom(4), "big")
        with self._lock:
            self.our_seq = self.our_isn
            self.state = "SYN_SENT"
            self._send(self.our_isn, 0, TCP_SYN)
        end = time.time() + timeout
        while time.time() < end:
            if self.state == "ESTABLISHED":
                return True
            time.sleep(0.01)
        return False

    def wait_established(self, timeout=5.0):
        """Server role: on_segment (called from the node's recv loop)
        handles the inbound SYN and final ACK; just wait for it here."""
        end = time.time() + timeout
        while time.time() < end:
            if self.state == "ESTABLISHED":
                return True
            time.sleep(0.01)
        return False

    def send(self, payload, timeout=2.0, retries=6):
        with self._lock:
            if self.state != "ESTABLISHED":
                return False
            seq = self.our_seq
        for _ in range(retries):
            with self._lock:
                if self.state != "ESTABLISHED":
                    return False
                self._send(seq, self.their_seq, TCP_PSH | TCP_ACK, payload)
            end = time.time() + timeout / retries
            while time.time() < end:
                with self._lock:
                    if _seq_gt(self.our_seq, seq) or self.our_seq == (seq + len(payload)) & 0xFFFFFFFF:
                        return True
                time.sleep(0.01)
        return False

    def recv(self, timeout=2.0):
        end = time.time() + timeout
        while time.time() < end:
            with self._lock:
                if self.inbox:
                    return self.inbox.pop(0)
            time.sleep(0.01)
        return None

    def close(self):
        with self._lock:
            if self.state == "ESTABLISHED":
                self._send(self.our_seq, self.their_seq, TCP_FIN | TCP_ACK)
            self.state = "CLOSED"

    def on_segment(self, seq, ack, flags, payload):
        with self._lock:
            if flags & TCP_RST:
                self.state = "CLOSED"
                return
            is_syn = bool(flags & TCP_SYN)
            is_ack = bool(flags & TCP_ACK)
            is_fin = bool(flags & TCP_FIN)

            if is_syn and not is_ack:
                self.our_isn = int.from_bytes(os.urandom(4), "big")
                self.their_seq = (seq + 1) & 0xFFFFFFFF
                self.state = "SYN_RCVD"
                self._send(self.our_isn, self.their_seq, TCP_SYN | TCP_ACK)
                # The SYN segment itself carries seq=our_isn (sent above,
                # unchanged); it also consumes one sequence number, so
                # everything we send AFTER it must start from isn+1 -- this
                # was missing and made every following data segment's seq
                # off by one, so the client's on_segment always saw a
                # seq mismatch against its own (correctly incremented)
                # their_seq and silently dropped SyncNetwork forever.
                self.our_seq = (self.our_isn + 1) & 0xFFFFFFFF
                return

            if is_syn and is_ack:
                if self.state == "SYN_SENT" and ack == (self.our_isn + 1) & 0xFFFFFFFF:
                    self.their_seq = (seq + 1) & 0xFFFFFFFF
                    self.our_seq = (self.our_isn + 1) & 0xFFFFFFFF
                    self.state = "ESTABLISHED"
                    self._send(self.our_seq, self.their_seq, TCP_ACK)
                return

            if is_fin:
                self.their_seq = (seq + 1) & 0xFFFFFFFF
                self._send(self.our_seq, self.their_seq, TCP_ACK)
                self.state = "CLOSED"
                return

            if not is_ack:
                return

            if self.state == "SYN_RCVD" and ack == (self.our_isn + 1) & 0xFFFFFFFF:
                self.state = "ESTABLISHED"
                return

            if self.state != "ESTABLISHED":
                return

            # Consume the peer's ack of our outbound data UNCONDITIONALLY,
            # whether this is a bare ACK or the ack is piggybacked on the
            # peer's own data. Mirrors bsd_bridge_service.cpp
            # HandleTcpSegment, which consumes the ack for every ACK-bearing
            # segment before its payload_len==0 early-return -- so a
            # piggybacked ack on a data segment (e.g. the host's SyncNetwork
            # acking our Connect) advances our_seq the same way a bare ACK
            # does. Without this, send() never sees its Connect acknowledged
            # and gives up retrying even though the reply is already here.
            if _seq_gt(ack, self.our_seq):
                self.our_seq = ack

            if len(payload) == 0:
                return

            if seq == self.their_seq:
                self.inbox.append(bytes(payload))
                self.their_seq = (self.their_seq + len(payload)) & 0xFFFFFFFF
                self._send(self.our_seq, self.their_seq, TCP_ACK)


def network_id_of(info):
    """intentId.localCommunicationId (u64 LE at offset 0)."""
    return struct.unpack("<Q", info["intent"][:8])[0]


def scene_id_of(info):
    return struct.unpack("<H", info["intent"][8 + 2:8 + 2 + 2])[0]


# --------------------------------------------------------------------------- #
# virtual console                                                             #
# --------------------------------------------------------------------------- #

class LdnNode:
    """One virtual console: LDN control state machine over a relay socket.

    Mirror of sys-slp-client's LdnControl (and ldn_mitm's LANDiscovery):
      - no real UDP broadcast: Scan/ScanResp are unicast/broadcast IPv4/UDP
        datagrams on CONTROL_PORT carried by the relay;
      - no per-station TCP: Connect + SyncNetwork are unicast UDP datagrams.
    """

    def __init__(self, ip, name, relay, port=CONTROL_PORT, bind_ip=None):
        """relay=(host, port): either a real slp relay server (unicast --
        the relay does its own room-based fan-out), or the ZeroTier
        broadcast address/port (('255.255.255.255', ZT_BROADCAST_PORT) from
        zt_ldn_transport.py) for switch-lan-play-nx's ZtBridge transport,
        which has no relay server at all -- every console on the network
        broadcasts directly.

        bind_ip: required for ZT broadcast mode. Your own ZeroTier-assigned
        IPv4 on the target network (e.g. from `zerotier-cli listnetworks`),
        so the OS sends broadcasts out the right interface AND so this
        node can recognize (and drop) its own broadcasts echoed back to
        itself -- see ZtBridge's own m_self_addr filtering
        (source/zt_bridge.hpp) this mirrors. Leave None for classic relay
        mode (binds 0.0.0.0, no self-filtering needed since the relay never
        echoes your own traffic back to you).
        """
        self.ip = bytes(ip)
        self.name = name
        self.port = port
        self.server = relay
        self.bind_ip = bind_ip
        self.state = STATE_NONE
        self.disconnect_reason = 0
        self.network_info = None          # dict (ours or host's, when joined)
        self.host_network = None          # station side: target network
        self.scan_results = []            # list of network_info dicts
        self._scan_filter_lcid = None
        self.stations = {}                # host side: node_id -> dict
        self.lan_events = 0
        self.recv_srcs = []               # (src_ip, dst_ip, ptype) debug log

        self._vtcp = {}                   # peer_ip bytes -> VTcp
        self._vtcp_lock = threading.Lock()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.bind_ip is not None:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind((self.bind_ip, 0))
        else:
            self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(0.05)
        self._inbox = []
        self._inbox_lock = threading.Lock()
        self._closed = threading.Event()
        threading.Thread(target=self._recv_loop, daemon=True).start()
        # The console processes control frames inline on the relay run-loop
        # thread; mirror that with an auto-step thread so hosts reply to
        # Scan/Connect without the test having to pump them.
        threading.Thread(target=self._auto_step, daemon=True).start()

    def close(self):
        """Stop threads + close the socket so the node leaves the room."""
        self._closed.set()
        try:
            self.sock.close()
        except OSError:
            pass

    # ---- transport ------------------------------------------------------- #

    def _recv_loop(self):
        while not self._closed.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except (socket.timeout, BlockingIOError, OSError):
                continue
            # ZT broadcast mode: our own broadcasts loop back to this same
            # socket (same reason ZtBridge::RecvIpv4 filters on m_self_addr,
            # source/zt_bridge.hpp) -- drop them rather than talking to
            # ourselves.
            if self.bind_ip is not None and addr[0] == self.bind_ip:
                continue
            if not data or (data[0] & 0x7F) != 0x01:
                continue
            pkt = data[1:]
            if len(pkt) < 20:
                continue
            if pkt[9] == 6:
                self._on_tcp_frame(pkt)
                continue
            src = pkt[12:16]
            dst = pkt[16:20]
            uoff = (pkt[0] & 0x0F) * 4
            if pkt[9] != 17:
                continue
            dport = int.from_bytes(pkt[uoff + 2:uoff + 4], "big")
            ulen = int.from_bytes(pkt[uoff + 4:uoff + 6], "big")
            if dport != self.port:
                continue
            payload = pkt[uoff + 8:uoff + ulen]
            with self._inbox_lock:
                self._inbox.append((src, dst, payload))

    def _on_tcp_frame(self, pkt):
        parsed = _parse_ipv4_tcp(pkt)
        if parsed is None:
            return
        src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload = parsed
        if dst_port != self.port:
            return
        is_bare_syn = bool(flags & TCP_SYN) and not bool(flags & TCP_ACK)
        with self._vtcp_lock:
            if is_bare_syn:
                # Host role: always start fresh on a bare SYN, whether this
                # is a genuinely new peer or one reconnecting after its
                # previous session already ended -- the old vtcp (if any)
                # is simply replaced. Without this, a second connection
                # attempt from the same peer IP found the stale vtcp
                # object, silently completed a handshake on it, and then
                # sat with nothing listening for its Connect packet, since
                # the _serve_incoming_station thread for the FIRST session
                # had already returned. Only while actually advertising a
                # network -- matches BsdBridgeService only accepting a
                # fresh SYN via its own AP-role listener.
                if self.state != STATE_ACCESS_POINT_CREATED:
                    return
                vtcp = VTcp(self, src_ip, src_port, my_port=self.port)
                self._vtcp[bytes(src_ip)] = vtcp
            else:
                vtcp = self._vtcp.get(bytes(src_ip))
        if vtcp is None:
            return
        vtcp.on_segment(seq, ack, flags, payload)
        if is_bare_syn:
            threading.Thread(target=self._serve_incoming_station,
                             args=(vtcp,), daemon=True).start()

    def _serve_incoming_station(self, vtcp):
        """Host role: drive one incoming station's connection from its SYN
        through Connect -> SyncNetwork, entirely on its own thread so
        multiple stations can be mid-handshake at once."""
        if not vtcp.wait_established(timeout=5.0):
            return
        body = vtcp.recv(timeout=5.0)
        if body is None:
            return
        pkt = unpack_packet(body)
        if pkt is None or pkt[0] != LAN_CONNECT:
            return
        self._handle_connect(vtcp.peer_ip, pkt[1], vtcp)

    def _auto_step(self):
        while not self._closed.is_set():
            try:
                self.step()
            except Exception:  # noqa: BLE001  (keep the pump alive)
                pass
            time.sleep(0.005)

    def keepalive(self):
        self.sock.sendto(bytes([0x00]), self.server)

    def send_control(self, dst, payload):
        udp = struct.pack("!HHHH", self.port, self.port, 8 + len(payload), 0) + payload
        total = 20 + len(udp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                         self.ip, dst)
        self.sock.sendto(bytes([0x01]) + ip + udp, self.server)

    def send_broadcast(self, ptype, body=b""):
        self.send_control(bytes([self.ip[0], self.ip[1], self.ip[2], 255]),
                          pack_header(ptype, body))

    def send_unicast(self, dst_ip, ptype, body=b""):
        self.send_control(bytes(dst_ip), pack_header(ptype, body))

    # ---- state helpers ---------------------------------------------------- #

    def _set_state(self, v):
        self.state = v
        self.lan_events += 1

    # ---- host side -------------------------------------------------------- #

    def open_access_point(self):
        if self.state == STATE_NONE:
            raise RuntimeError("not initialized")
        self.stations = {}
        self._set_state(STATE_ACCESS_POINT)
        return True

    def close_access_point(self):
        self.stations = {}
        self._set_state(STATE_INITIALIZED)
        return True

    def create_network(self, local_comm_id=0x1234, scene_id=0, session_id=None,
                       node_count_max=7, channel=6, security_mode=0, lcv=6):
        if self.state != STATE_ACCESS_POINT:
            raise RuntimeError(f"create_network in state {self.state}")
        if session_id is None:
            session_id = bytes(range(16))
        self.network_info = self._make_network(
            local_comm_id, scene_id, session_id, node_count_max, channel,
            security_mode, lcv)
        self.stations = {}
        self._set_state(STATE_ACCESS_POINT_CREATED)
        self._update_nodes()
        return True

    def destroy_network(self):
        self.stations = {}
        self._set_state(STATE_ACCESS_POINT)
        return True

    def _make_network(self, lcid, scene, session_id, nmax, channel, smode, lcv):
        intent = struct.pack("<QHH4x", lcid, 0, scene)
        node0 = build_node_info(self.ip, 0, 1, self.name, lcv)
        ldn = build_ldn_network_info([node0], node_count_max=nmax,
                                     security_mode=smode)
        common = build_common_network_info(fake_mac(self.ip), channel=channel)
        return parse_network_info(
            build_network_info(intent, session_id, common, ldn))

    def _update_nodes(self):
        connected = [nid for nid, s in self.stations.items() if s["connected"]]
        for nid, s in self.stations.items():
            s["node"]["is_connected"] = 1 if s["connected"] else 0
        self.network_info["node_count"] = len(connected) + 1
        n0 = self.network_info["nodes"][0]
        n0["is_connected"] = 1
        self.network_info["nodes"] = [n0] + [
            self.stations[nid]["node"] for nid in sorted(self.stations)
            if self.stations[nid]["connected"]]
        for nid in connected:
            vtcp = self.stations[nid].get("vtcp")
            if vtcp is not None:
                vtcp.send(pack_header(LAN_SYNC_NETWORK, self._network_bytes()))

    def _network_bytes(self):
        n0 = self.network_info["nodes"][0]
        node0 = build_node_info(n0["ip"], 0, 1, n0["name"], n0["lcv"], n0["mac"])
        station_bytes = []
        for nid in sorted(self.stations):
            s = self.stations[nid]
            if not s["connected"]:
                continue
            n = s["node"]
            station_bytes.append(
                build_node_info(n["ip"], n["node_id"], 1, n["name"], n["lcv"],
                                n["mac"]))
        ldn = build_ldn_network_info(
            [node0] + station_bytes,
            node_count_max=self.network_info["node_count_max"],
            security_mode=0,
            advertise=self.network_info["advertise"],
            unk_random=b"\x00" * 16)
        common = build_common_network_info(
            self.network_info["bssid"], ssid=self.network_info["ssid"],
            channel=self.network_info["channel"],
            link_level=self.network_info["link_level"],
            network_type=self.network_info["network_type"])
        return build_network_info(self.network_info["intent"],
                                  self.network_info["session"], common, ldn)

    def _handle_connect(self, src_ip, body, vtcp):
        """Host role: a station's Connect arrived over its own TCP
        connection (see _serve_incoming_station). Registers the station and
        replies with SyncNetwork over that same connection (via
        _update_nodes -> the station's stored vtcp), exactly matching
        ldn_mitm's own real per-station TCP connection."""
        if self.state != STATE_ACCESS_POINT_CREATED:
            return
        if len(body) != NODE.size:
            return
        ni = parse_node_info(body)

        # Reuse the slot this IP already holds. A console legitimately
        # re-sends Connect (retry, or rejoin after a reboot), and blindly
        # allocating a fresh node_id each time listed the same player
        # twice -- e.g. Link appearing at BOTH node 1 and node 2 with the
        # same 10.13.37.2. MK8DX then sees itself duplicated in the node
        # table, which is a plausible cause of the crash on join.
        nid = next((k for k, st in self.stations.items()
                    if st["ip"] == src_ip), None)
        if nid is None:
            if len(self.stations) >= NODE_COUNT_MAX - 1:
                return
            nid = 1
            while nid in self.stations:
                nid += 1

        ni["node_id"] = nid   # host assigns the slot (ldn_mitm overrideInfo)
        self.stations[nid] = dict(ip=src_ip, node=ni, connected=True,
                                  last_seen=time.time(), vtcp=vtcp)
        self._update_nodes()

    # ---- station side ----------------------------------------------------- #

    def open_station(self):
        if self.state == STATE_NONE:
            raise RuntimeError("not initialized")
        self.stations = {}
        self._set_state(STATE_STATION)
        return True

    def close_station(self):
        self.stations = {}
        self._set_state(STATE_INITIALIZED)
        return True

    def scan(self, timeout=0.6, local_comm_id=None):
        """Broadcast Scan; collect ScanResp filtered like ldn_mitm's ScanFilter
        (ScanFilterFlag_LocalCommunicationId) when local_comm_id is given."""
        self.scan_results = []
        self._scan_filter_lcid = local_comm_id
        self.send_broadcast(LAN_SCAN)
        end = time.time() + timeout
        while time.time() < end:
            self.step()
            time.sleep(0.02)
        return list(self.scan_results)

    def connect(self, network_info, timeout=2.0):
        """Real TCP connection to the host's control port, matching
        ldn_mitm's own LANDiscovery::connect() -- SYN/SYN-ACK/ACK, send
        Connect over the stream, wait for SyncNetwork back on the same
        connection. See the VTcp class docstring for why this can't be a
        plain UDP datagram like Scan/ScanResp."""
        host_ip = network_info["nodes"][0]["ip"]
        my = build_node_info(self.ip, 0, 1, self.name,
                             network_info["nodes"][0]["lcv"])
        self.host_network = network_info
        vtcp = VTcp(self, host_ip, self.port, my_port=self.port)
        with self._vtcp_lock:
            self._vtcp[bytes(host_ip)] = vtcp
        if not vtcp.connect(timeout=timeout):
            return False
        if not vtcp.send(pack_header(LAN_CONNECT, my)):
            return False
        end = time.time() + timeout
        while time.time() < end:
            body = vtcp.recv(timeout=0.05)
            if body is not None:
                pkt = unpack_packet(body)
                if pkt is not None and pkt[0] == LAN_SYNC_NETWORK:
                    try:
                        info = parse_network_info(pkt[1])
                    except ValueError:
                        continue
                    self.network_info = info
                    if self.state == STATE_STATION:
                        self._set_state(STATE_STATION_CONNECTED)
                    self.lan_events += 1
                    return True
        return self.state == STATE_STATION_CONNECTED

    def disconnect(self):
        self._set_state(STATE_STATION)
        return True

    # ---- frame dispatch --------------------------------------------------- #

    def step(self):
        while True:
            with self._inbox_lock:
                if not self._inbox:
                    return
                batch = self._inbox
                self._inbox = []
            for src, dst, payload in batch:
                self.recv_srcs.append((src, dst))
                self._handle_packet(src, payload)

    def _handle_packet(self, src_ip, payload):
        pkt = unpack_packet(payload)
        if pkt is None:
            return
        ptype, body = pkt
        if ptype == LAN_SCAN:
            if self.state == STATE_ACCESS_POINT_CREATED:
                self.send_unicast(src_ip, LAN_SCAN_RESP, self._network_bytes())
        elif ptype == LAN_SCAN_RESP:
            try:
                info = parse_network_info(body)
            except ValueError:
                return
            if self._scan_filter_lcid is not None and \
                    network_id_of(info) != self._scan_filter_lcid:
                return
            for i, e in enumerate(self.scan_results):
                if e["bssid"] == info["bssid"]:
                    self.scan_results[i] = info
                    return
            self.scan_results.append(info)
        elif ptype == LAN_CONNECT:
            # Real Connect now arrives over TCP (_serve_incoming_station ->
            # _handle_connect below), matching ldn_mitm's own real TCP
            # station connection. Kept here as a no-op case rather than
            # removed so an unexpected UDP Connect (e.g. from an older peer)
            # doesn't fall through to "unrecognized packet" silently.
            return
        elif ptype == LAN_SYNC_NETWORK:
            try:
                info = parse_network_info(body)
            except ValueError:
                return
            self.network_info = info
            if self.state == STATE_STATION:
                self._set_state(STATE_STATION_CONNECTED)
            self.lan_events += 1
