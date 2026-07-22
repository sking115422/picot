"""Aggregate host-vs-container fidelity across multiple sessions.

For each captured benign session:
- Compute a wall/monotonic offset by matching python3 execve events
  between strace and host bpftrace (much more reliable than the
  launcher's date-based offset which suffers from BOOT-read latency).
- Slice to the "workload phase" (between sentinel_received and session_end
  MARKs emitted by container_agent_script.py) with a small buffer to
  absorb residual clock jitter.
- Exclude strace's own tgid (identified by comm=="strace")
- Exclude docker-exec artifacts (comm in {"runc:[2:INIT]", "touch"})
- Report per-syscall strace vs host counts and the aggregate ratio.

Prints per-session summaries and a final aggregate.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter
from pathlib import Path


UNISTD = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
STRACE_LINE_RE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+([a-zA-Z0-9_]+)\(")
MARK_RE = re.compile(r"MARK (\d+) (\S+)")
DOCKER_EXEC_COMMS = {"runc:[2:INIT]", "touch"}
JITTER_BUFFER_NS = 20_000_000  # ±20ms around MARK window edges


def load_syscall_names() -> dict[int, str]:
    out: dict[int, str] = {}
    with open(UNISTD) as fp:
        for line in fp:
            if line.startswith("#define __NR_"):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        out[int(parts[2])] = parts[1][len("__NR_"):]
                    except ValueError:
                        continue
    return out


def find_mark_ns(stderr_path: Path, name: str) -> int | None:
    with open(stderr_path) as fp:
        for line in fp:
            m = MARK_RE.match(line)
            if m and m.group(2) == name:
                return int(m.group(1))
    return None


def iter_host_events(host_path: Path):
    opener = gzip.open if str(host_path).endswith(".gz") else open
    with opener(host_path, "rt", errors="replace") as fp:
        for line in fp:
            if not line.startswith("T|"):
                continue
            parts = line.rstrip().split("|")
            if len(parts) < 6:
                continue
            try:
                yield {
                    "ts_ns": int(parts[1]),
                    "sc": int(parts[2]),
                    "tgid": int(parts[3]),
                    "tid": int(parts[4]),
                    "comm": parts[5],
                }
            except ValueError:
                continue


def recover_offset(strace_path: Path, host_path: Path) -> int:
    """Match python3 execve between strace and host to get true offset.

    Returns wall_ns - mono_ns (i.e., add to mono to get wall).

    Strategy: bpftrace attaches AFTER the main agent process's execve, so
    host only sees execves of the subprocess/child python3 processes. On
    strace side, look for execves that happen AFTER the sentinel_received
    MARK (that's where subprocess spawning happens) and pair the first
    such strace execve with the first host execve of comm=="python3".
    """
    stderr_path = strace_path.parent / "container.stderr"
    sentinel_ns = find_mark_ns(stderr_path, "sentinel_received")
    if sentinel_ns is None:
        raise RuntimeError("no sentinel_received MARK; cannot align")

    execve_re = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+execve\(\"[^\"]*python3\"")
    strace_execve_wall_ns = None
    with open(strace_path, errors="replace") as fp:
        for line in fp:
            m = execve_re.match(line)
            if m:
                wall_ns = int(float(m.group(2)) * 1e9)
                if wall_ns > sentinel_ns:
                    strace_execve_wall_ns = wall_ns
                    break

    host_execve_mono = None
    for e in iter_host_events(host_path):
        if e["sc"] == 59 and e["comm"] == "python3":
            host_execve_mono = e["ts_ns"]
            break

    if strace_execve_wall_ns is None or host_execve_mono is None:
        raise RuntimeError("could not find matching python3 execve for offset")

    return strace_execve_wall_ns - host_execve_mono


def compare_session(sess: Path, names: dict[int, str]) -> dict:
    host_path = sess / "l3_host.trace.gz"
    if not host_path.exists():
        host_path = sess / "l3_host.trace"
    strace_path = sess / "l1_container.strace"
    stderr_path = sess / "container.stderr"

    sentinel_wall_ns = find_mark_ns(stderr_path, "sentinel_received")
    session_end_wall_ns = find_mark_ns(stderr_path, "session_end")
    if sentinel_wall_ns is None or session_end_wall_ns is None:
        raise RuntimeError(f"{sess}: could not find MARK boundaries")

    offset = recover_offset(strace_path, host_path)

    strace_tgid = None
    for e in iter_host_events(host_path):
        if e["comm"] == "strace":
            strace_tgid = e["tgid"]
            break

    win_start = sentinel_wall_ns - JITTER_BUFFER_NS
    win_end = session_end_wall_ns + JITTER_BUFFER_NS

    host_counts_workload: Counter[int] = Counter()
    host_total_all_phases = 0
    for e in iter_host_events(host_path):
        host_total_all_phases += 1
        if e["tgid"] == strace_tgid:
            continue
        if e["comm"] in DOCKER_EXEC_COMMS:
            continue
        wall = e["ts_ns"] + offset
        if not (win_start <= wall < win_end):
            continue
        host_counts_workload[e["sc"]] += 1

    strace_counts_workload: Counter[str] = Counter()
    strace_total_all_phases = 0
    with open(strace_path, errors="replace") as fp:
        for line in fp:
            m = STRACE_LINE_RE.match(line)
            if not m:
                continue
            strace_total_all_phases += 1
            wall_ns = int(float(m.group(2)) * 1e9)
            if not (win_start <= wall_ns < win_end):
                continue
            strace_counts_workload[m.group(3)] += 1

    host_counts_by_name: Counter[str] = Counter()
    for sc, c in host_counts_workload.items():
        host_counts_by_name[names.get(sc, f"sc_{sc}")] += c

    host_total = sum(host_counts_workload.values())
    strace_total = sum(strace_counts_workload.values())

    return {
        "session": sess.name,
        "recovered_offset_ns": offset,
        "workload_strace_total": strace_total,
        "workload_host_total": host_total,
        "ratio": (host_total / strace_total) if strace_total else float("nan"),
        "strace_counts": dict(strace_counts_workload),
        "host_counts": dict(host_counts_by_name),
        "workload_span_ms": (session_end_wall_ns - sentinel_wall_ns) / 1e6,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("captures_root", type=Path,
                    default=Path(__file__).parent.parent / "captures",
                    nargs="?")
    ap.add_argument("--pattern", default="benign_*")
    args = ap.parse_args()

    sessions = sorted(args.captures_root.glob(args.pattern))
    if not sessions:
        print(f"no sessions under {args.captures_root}", file=sys.stderr)
        return 1

    names = load_syscall_names()

    results = []
    for sess in sessions:
        try:
            r = compare_session(sess, names)
            results.append(r)
        except Exception as e:
            print(f"[skip] {sess.name}: {e}", file=sys.stderr)

    print(f"{'session':<40} {'workload_ms':>11} {'strace':>7} {'host':>7} {'ratio':>7}")
    for r in results:
        print(f"{r['session']:<40} {r['workload_span_ms']:>11.1f} "
              f"{r['workload_strace_total']:>7d} {r['workload_host_total']:>7d} "
              f"{r['ratio']:>7.3f}")

    agg_strace: Counter[str] = Counter()
    agg_host: Counter[str] = Counter()
    for r in results:
        for n, c in r["strace_counts"].items():
            agg_strace[n] += c
        for n, c in r["host_counts"].items():
            agg_host[n] += c

    print()
    print(f"=== aggregate across {len(results)} sessions ===")
    print(f"  strace total: {sum(agg_strace.values()):,}")
    print(f"  host total:   {sum(agg_host.values()):,}")
    if sum(agg_strace.values()):
        print(f"  ratio:        {sum(agg_host.values())/sum(agg_strace.values()):.4f}")

    print()
    print(f"{'syscall':<22} {'strace':>8} {'host':>8} {'diff':>8} {'ratio':>8}")
    all_names = set(agg_strace) | set(agg_host)
    rows = []
    for n in all_names:
        s = agg_strace.get(n, 0)
        h = agg_host.get(n, 0)
        ratio = h / s if s else float("inf") if h else 0.0
        rows.append((n, s, h, h - s, ratio))
    rows.sort(key=lambda x: -(x[1] + x[2]))
    for n, s, h, d, r in rows[:40]:
        print(f"{n:<22} {s:>8d} {h:>8d} {d:>+8d} {r:>8.3f}")

    print()
    only_strace = [n for n in agg_strace if n not in agg_host]
    only_host = [n for n in agg_host if n not in agg_strace]
    print(f"in strace but not host: {sorted(only_strace)}")
    print(f"in host  but not strace: {sorted(only_host)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
