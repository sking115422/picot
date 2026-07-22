"""Coarse comparison of L1 container strace vs host bpftrace output.

Reports:
- Per-syscall count in container vs host (subtree only)
- Total volume (all-host vs container-subtree host vs container)
- Which syscalls appear in container but not in host-subtree
- Which syscalls appear in host-subtree but not in container
- Basic sanity: process count, wall-clock span, session duration

Only answers: "if we knew the container's process subtree perfectly,
how much of the container's syscall stream can we recover on the host,
and vice versa?" The subtree slice is done by walking sched_process_fork
events forward from the container's root pid.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


SYSCALL_LINE_RE = re.compile(r"^T\|(\d+)\|(\d+)\|(\d+)\|(\d+)\|(.*)$")
FORK_LINE_RE = re.compile(r"^F\|(\d+)\|(\d+)\|(\d+)\|(.*)$")


def _load_syscall_names() -> dict[int, str]:
    """Load the full x86_64 syscall table from the kernel header.

    Falls back to a small hardcoded map if the header isn't present.
    """
    header_candidates = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
    ]
    for path in header_candidates:
        try:
            with open(path) as fp:
                out: dict[int, str] = {}
                for line in fp:
                    if not line.startswith("#define __NR_"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[1][len("__NR_"):]
                        try:
                            nr = int(parts[2])
                            out[nr] = name
                        except ValueError:
                            continue
                if out:
                    return out
        except FileNotFoundError:
            continue
    # Minimal fallback if headers aren't installed
    return {0: "read", 1: "write", 3: "close", 257: "openat"}


X86_64_SYSCALL_NAMES = _load_syscall_names()

STRACE_LINE_RE = re.compile(
    r"^(?P<pid>\d+)\s+"           # optional pid prefix (strace -f)
    r"(?P<ts>\d+\.\d+)\s+"        # unix epoch timestamp (strace -ttt)
    r"(?P<syscall>[a-zA-Z0-9_]+)\("
)


def name_of(nr: int) -> str:
    return X86_64_SYSCALL_NAMES.get(nr, f"sc_{nr}")


def parse_host_trace(path: Path) -> tuple[list[dict], list[dict], int | None]:
    """Return (syscall_events, fork_events, boot_mono_ns)."""
    opener = gzip.open if str(path).endswith(".gz") else open
    events: list[dict] = []
    forks: list[dict] = []
    boot: int | None = None
    with opener(path, "rt", errors="replace") as fp:
        for line in fp:
            if line.startswith("BOOT|"):
                m = re.search(r"nsecs=(\d+)", line)
                if m:
                    boot = int(m.group(1))
                continue
            if line.startswith("T|"):
                m = SYSCALL_LINE_RE.match(line.rstrip())
                if m:
                    events.append({
                        "ts_ns": int(m.group(1)),
                        "sc": int(m.group(2)),
                        "tgid": int(m.group(3)),
                        "tid": int(m.group(4)),
                        "comm": m.group(5),
                    })
            elif line.startswith("F|"):
                m = FORK_LINE_RE.match(line.rstrip())
                if m:
                    forks.append({
                        "ts_ns": int(m.group(1)),
                        "ppid": int(m.group(2)),
                        "cpid": int(m.group(3)),
                        "child_comm": m.group(4),
                    })
    return events, forks, boot


def build_subtree(container_root_pid: int, forks: list[dict]) -> set[int]:
    """All pids in the container_root_pid's fork subtree.

    Walk forks in time order; a fork adopts the child into the tree
    iff the parent is already in the tree. This can miss races where
    an ancestor was created before we started tracing; the launcher
    starts bpftrace *before* docker run so in principle this is clean.
    """
    tree: set[int] = {container_root_pid}
    # Sort by ts for correctness
    for f in sorted(forks, key=lambda x: x["ts_ns"]):
        if f["ppid"] in tree:
            tree.add(f["cpid"])
    return tree


def parse_strace(path: Path) -> Counter:
    """Return Counter mapping syscall name -> count."""
    counts: Counter = Counter()
    with open(path, errors="replace") as fp:
        for line in fp:
            m = STRACE_LINE_RE.match(line)
            if m:
                counts[m.group("syscall")] += 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path,
                    help="captures/benign_<N>_<ts>/")
    args = ap.parse_args()

    meta = json.loads((args.session_dir / "meta.json").read_text())
    container_pid = meta["container_pid"]

    host_trace = args.session_dir / "l3_host.trace.gz"
    if not host_trace.exists():
        host_trace = args.session_dir / "l3_host.trace"

    strace_file = args.session_dir / "l1_container.strace"

    print(f"session: {meta['session_id']}")
    print(f"container_pid (host): {container_pid}")
    print(f"host trace: {host_trace}")
    print(f"container strace: {strace_file}")
    print()

    events, forks, boot = parse_host_trace(host_trace)
    print(f"host events (already cgroup-filtered): {len(events):,}  "
          f"forks: {len(forks):,}  boot_ns: {boot}")

    # bpftrace filters in-kernel by cgroup, so every event here belongs
    # to the target container subtree by construction. But strace itself
    # runs inside the cgroup and its ptrace/wait4/write bookkeeping shows
    # up as a huge chunk of the host trace. Exclude strace's tgid so the
    # comparison reflects agent syscalls only.
    #
    # Identify strace pids by comm; every event with comm=="strace" is
    # its own bookkeeping. This is the fair filter because strace itself
    # never appears in its own trace output.
    strace_pids = {e["tgid"] for e in events if e["comm"] == "strace"}
    print(f"strace tgids to exclude: {sorted(strace_pids)}")

    agent_events = [e for e in events if e["tgid"] not in strace_pids]
    host_sub = Counter(e["sc"] for e in agent_events)
    host_all = Counter(e["sc"] for e in events)  # keep for reference
    tree_pids = set(e["tgid"] for e in agent_events)
    print(f"agent-side pids: {sorted(tree_pids)}")
    print(f"host syscalls in cgroup (all): {sum(host_all.values()):,}")
    print(f"host syscalls in cgroup (excluding strace): "
          f"{sum(host_sub.values()):,}")

    if strace_file.exists():
        cont = parse_strace(strace_file)
        print(f"container strace syscalls: {sum(cont.values()):,}")
    else:
        cont = Counter()
        print("WARN: no container strace found")

    # Per-syscall comparison table
    print()
    print(f"{'syscall':<20s} {'container':>10s} {'host_sub':>10s} "
          f"{'ratio':>8s} {'host_all':>10s}")
    print("-" * 70)

    all_names = set()
    all_names.update(cont.keys())
    for nr in host_sub:
        all_names.add(name_of(nr))
    for nr in host_all:
        all_names.add(name_of(nr))

    def merge_by_name(counter_by_nr: Counter) -> Counter:
        out: Counter = Counter()
        for nr, c in counter_by_nr.items():
            out[name_of(nr)] += c
        return out

    host_sub_named = merge_by_name(host_sub)
    host_all_named = merge_by_name(host_all)

    for name in sorted(all_names,
                       key=lambda n: -(cont.get(n, 0) + host_sub_named.get(n, 0))):
        c = cont.get(name, 0)
        h = host_sub_named.get(name, 0)
        ha = host_all_named.get(name, 0)
        ratio = f"{h/c:.2f}" if c else ("inf" if h else "-")
        # Only show the ones with any signal
        if c == 0 and h == 0:
            continue
        print(f"{name:<20s} {c:>10d} {h:>10d} {ratio:>8s} {ha:>10d}")

    print()
    print("=== summary ===")
    print(f"container-only syscalls (in strace, not host-sub): "
          f"{sorted(n for n in cont if n not in host_sub_named)[:10]}")
    print(f"host-sub-only syscalls (not in strace): "
          f"{sorted(n for n in host_sub_named if n not in cont)[:10]}")

    total_c = sum(cont.values())
    total_h = sum(host_sub_named.values())
    if total_c:
        print(f"host-sub/container ratio: {total_h/total_c:.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
