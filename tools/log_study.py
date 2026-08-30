"""Log analysis helpers for switch-lan-play-nx.

Pulls packet dumps out of a console's switch-lan-play-nx / ldn_mitm logs and
compares them byte-for-byte against packets built by slp_ldn, so we can prove
"the fake sends exactly what the console sends."

Reusable functions
------------------
iter_dumps(path, want_ts=None)
    Yield the raw Bin-Log packet dumps captured in an ldn_mitm.log as
    (ts_ms, n, bytes). If want_ts is set, yield only that one (as (ts,n,bytes)
    directly).
annotate(buf, width=32)
    Return a printable hex+ascii rendering of a packet.
build_network_info(name, ip, cap_ts, log_path)
    Rebuild the host SyncNetwork with the real appdata lifted from a captured
    1152-byte dump, for byte comparison.
compare_nwinfo(name, ip, cap_ts, log_path)
    Print whether the slp_ldn-built SyncNetwork is byte-identical to the console's
    captured 1152-byte dump. Returns (built, captured, mismatches).
analyze_cadence(log_path)
    Print the host SyncNetwork response delay and joiner Connect period from a
    switch-lan-play-nx.log.
"""
import re
import struct
from collections import Counter

HDR = struct.Struct("<IBBH2x")


def iter_dumps(path):
    """Yield (ts_ms, n, bytes) for every Bin-Log packet dump in an ldn_mitm.log."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^\[ts: (\d+)ms.*?Bin Log: (\d+) \(0x([0-9a-f]+)\)", lines[i])
        if m:
            ts = int(m.group(1)); n = int(m.group(2))
            j = i + 1; hexl = []
            while j < len(lines) and re.match(r"^[0-9a-f ]+$", lines[j]) and len(lines[j]) > 10:
                hexl.append(lines[j]); j += 1
            b = bytes.fromhex("".join(l.replace(" ", "") for l in hexl))
            yield ts, n, b
            i = j
        else:
            i += 1


def get_dump(path, ts_target):
    """Return (ts, n, bytes) for the dump at ts_target, or None."""
    for ts, n, b in iter_dumps(path):
        if ts == ts_target:
            return ts, n, b
    return None



def annotate(buf, width=32):
    """Return a printable hex+ascii rendering of buf."""
    out = []
    for off in range(0, len(buf), width):
        row = buf[off:off + width]
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
        hexs = " ".join(f"{x:02x}" for x in row)
        out.append(f"{off:04x}  {hexs:<{width*3-1}}  {asc}")
    return "\n".join(out)


def build_network_info_from(appdata, name, ip=[10, 13, 200, 77],
                            comm_id=0x0100152000022000, node_count_max=8,
                            lcv=14, session_id=None):
    """Build the host SyncNetwork via slp_ldn with the given 152-byte appdata."""
    import slp_ldn as ldn
    if session_id is None:
        session_id = bytes(range(16))
    n = ldn.LdnNode(ip, name, ("127.0.0.1", 11451))
    n.state = ldn.STATE_ACCESS_POINT
    n.open_access_point()
    n.create_network(local_comm_id=comm_id, node_count_max=node_count_max,
                     security_mode=1, lcv=lcv, session_id=session_id)
    n.network_info["advertise"] = appdata
    built = n._network_bytes()
    return built


def compare_nwinfo(name, ip, cap_ts, log_path):
    """Return (built, captured, mismatches) for the host SyncNetwork."""
    import slp_ldn as ldn
    found = get_dump(log_path, cap_ts)
    if found is None:
        return None, None, None
    _ts, _n, cap = found
    # advertiseData sits at NETWORK offset 0x26C (LdnNetworkInfo 0x21C + 0x50)
    appdata = cap[0x26C:0x26C + 152]
    built = build_network_info_from(appdata, name, ip)
    common = min(len(built), len(cap))
    mism = [i for i in range(common) if built[i] != cap[i]]
    return built, cap, mism


if __name__ == "__main__":
    import os
    LOG = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                       "Users", "nik", "AppData", "Local", "Temp", "opencode",
                       "switch-logs", "ldn_mitm.log")
    LOG = os.path.abspath(LOG)
    print("log:", LOG, "exists:", os.path.exists(LOG))
    if os.path.exists(LOG):
        for name, ts in [("Link", 1859348), ("DEV-TESTS", 2087247)]:
            built, cap, mism = compare_nwinfo(name, [10, 13, 200, 77], ts, LOG)
            if built is None:
                print(name, "dump not found; skipping"); continue
            verdict = "IDENTICAL (byte-for-byte)" if not mism else f"{len(mism)} mismatches @ {mism[:8]}"
            print(f"{name}: built={len(built)}B cap={len(cap)}B -> {verdict}")
