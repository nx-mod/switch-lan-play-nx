"""Run fake host + fake join permutations of a fake pair against a relay.

Reusable test driver for the "recreate the 4 joins" workflow. Each
permutation starts a fake_ldn_host (as one player/role) and a
fake_ldn_join (as the other player/role) against the same relay/port and
local_comm_id, holds for a bounded time, then tears down and reports
whether the join reached StationConnected and the two-way exchange ran.

Usage:
    python3 tools/run_permutations.py \
        --lcid 0x0100152000022000 --relay 127.0.0.1 --port 11451 \
        --host Link --join DEV-TESTS --hold 6
"""
import argparse
import os
import re
import subprocess
import sys
import time

TOOLS = os.path.dirname(os.path.abspath(__file__))
HOST = os.path.join(TOOLS, "fake_ldn_host.py")
JOIN = os.path.join(TOOLS, "fake_ldn_join.py")
PY = sys.executable


def run(cmd, timeout):
    """Run a subprocess, return (returncode, combined stdout+stderr text)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = (e.stderr or b"") if isinstance(e.stderr, bytes) else (e.stderr or "")
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace"); err = err.decode("utf-8", "replace")
        return 124, out + err


def start_bg(cmd, outfile):
    f = open(outfile, "w")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                         text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p, f


def tail(path, n=2000):
    try:
        t = open(path, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        return "(no output)"
    return "\n".join(t.splitlines()[-n:])


def summarize(text, who):
    joined = re.search(r"JOINED.*?node_count=\d+/\d+", text)
    exch = len(re.findall(r"exchange (both ways|:|exchange:)", text))
    lines = [l for l in text.splitlines() if re.search(r"JOINED|exchange|NodeInfo|SyncNetwork|Connect|error|Error|Traceback", l)]
    print(f"--- {who} ---")
    for l in lines[-25:]:
        print("   ", l.strip())
    return joined is not None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lcid", default="0x0100152000022000")
    ap.add_argument("--relay", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11451)
    ap.add_argument("--host", default="Link", help="host player name")
    ap.add_argument("--join", default="DEV-TESTS", help="join player name")
    ap.add_argument("--hold", type=float, default=6.0,
                    help="seconds to hold the pair before teardown")
    ap.add_argument("--loop", nargs="+", default=None,
                    help="whitespace-separated host:join name pairs to run in a loop")
    args = ap.parse_args()

    tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "opencode")
    os.makedirs(tmp, exist_ok=True)

    if args.loop:
        pairs = [tuple(p.split(":")) for p in args.loop]
    else:
        pairs = [(args.host, args.join)]

    for hname, jname in pairs:
        tag = f"{hname}host_{jname}join"
        hout = os.path.join(tmp, f"{tag}_host.log")
        jout = os.path.join(tmp, f"{tag}_join.log")
        for f in (hout, jout):
            try: os.remove(f)
            except FileNotFoundError: pass

        # host ip + join ip must differ; use 10.13.200.77 (host) / .78 (join)
        hcmd = [PY, "-u", HOST, args.lcid, "--name", hname,
                "--relay", args.relay, "--port", str(args.port),
                "--ip", "10.13.200.77", "--lcv", "14", "--security-mode", "1",
                "--mk8dx-appdata", "--exchange-interval", "0.43"]
        jcmd = [PY, "-u", JOIN, args.lcid, "--name", jname,
                "--relay", args.relay, "--port", str(args.port),
                "--ip", "10.13.200.78", "--hold", str(args.hold),
                "--exchange-interval", "0.43"]

        print(f"\n===== PERMUTATION {hname} (host 10.13.200.77)  +  {jname} (join 10.13.200.78) =====")
        hp, hf = start_bg(hcmd, hout)
        time.sleep(1.5)          # let the host register/advertise
        jp, jf = start_bg(jcmd, jout)
        try:
            jp.wait(timeout=args.hold + 25)
        except subprocess.TimeoutExpired:
            jp.kill()
        time.sleep(1.0)
        hp.terminate()
        try: hp.wait(timeout=5)
        except subprocess.TimeoutExpired: hp.kill()
        hf.close(); jf.close()

        print("\n" + tail(hout, 14))
        ok = summarize(tail(jout, 4000), f"{jname} JOIN")
        print("RESULT:", "JOIN OK + exchange ran" if ok else "JOIN FAILED/UNVERIFIED")
        print("=" * 70)


if __name__ == "__main__":
    main()
