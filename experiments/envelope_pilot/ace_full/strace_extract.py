"""Parse a raw strace -f -ttt log into normalized event dicts.

Output shape matches the existing pilot extractor so downstream code
(evaluate.py, mcp_subtree.py adapted) can consume it unchanged:

  {
    "event":       "openat" | "unlinkat" | "connect" | "sendto" | "execve"
                    | "read" | "write" | "close" | "stat" | ...,
    "pid":         12345,     # container-namespace pid (strace pid field)
    "path":        "/tmp/x",  # for path-carrying syscalls
    "write_intent": True,     # openat with O_WRONLY or O_RDWR
    "flags":       2,         # openat raw flags (int if parseable)
    "family":      1,         # connect: AF_LOCAL=1 AF_INET=2 AF_INET6=10
    "argv":        [...],     # execve args (list of strings)
    "comm":        None,      # not directly available; use pid tracking instead
    "ts":          1783697913.126766,  # wall-clock float seconds
    "ret":         0,         # return value if parseable
  }

We DO NOT emit comm because strace doesn't record it per line. Downstream
code that needs comm can derive it from the execve chain (which we DO
emit — argv[0] on execve is the comm-eqivalent).

For unfinished/resumed pairs (strace -f without --syscall-limit), we
emit the event once when it's resumed (has both args and return).
Unfinished-only lines are skipped (they'll be captured on their resume).
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterator

# Basic line: `pid ts syscall(args) = ret`
COMPLETE_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"(?P<sc>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s*=\s*(?P<ret>-?\d+|\?|-1\s+\S+.*)$"
)
# Unfinished: `pid ts syscall(args <unfinished ...>`
UNFINISHED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"(?P<sc>[a-zA-Z0-9_]+)\((?P<args>.*)\s+<unfinished\s+\.\.\.>\s*$"
)
# Resumed: `pid ts <... syscall resumed>args) = ret`
RESUMED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"<\.\.\.\s+(?P<sc>\S+)\s+resumed>\s*(?P<args>.*)\)\s*=\s*(?P<ret>-?\d+|\?)"
)
# Signal-death / process-exit noise
SIGNAL_RE = re.compile(r"^\d+\s+\d+\.\d+\s+---\s+SIG")
EXITED_RE = re.compile(r"^\d+\s+\d+\.\d+\s+\+\+\+")

# Path-carrying syscalls we care about
PATH_SYSCALLS = {"openat", "open", "unlinkat", "unlink", "execve", "creat",
                 "chdir", "mkdir", "rmdir", "rename", "readlinkat", "readlink",
                 "stat", "newfstatat", "lstat", "access", "faccessat", "faccessat2"}

# openat flags (partial — we care about write vs read intent)
O_WRONLY = 1
O_RDWR = 2
O_ACCMODE = 3

# String flag words we might see in openat args
WRITE_FLAG_WORDS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"}

# connect() family constants
FAMILY_LOOKUP = {
    "AF_UNIX": 1, "AF_LOCAL": 1,
    "AF_INET": 2,
    "AF_INET6": 10,
    "AF_NETLINK": 16,
}


def parse_openat_flags(args: str) -> tuple[int | None, bool]:
    """Given openat args like `AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC`,
    return (flag_int_if_available, write_intent_bool)."""
    write_intent = any(w in args for w in WRITE_FLAG_WORDS)
    return None, write_intent


def parse_path_from_args(args: str) -> str | None:
    """Extract the first quoted string from an args blob."""
    # Path is the first quoted string after possible dirfd
    # `AT_FDCWD, "/etc/ld.so.cache", ...` → /etc/ld.so.cache
    # `"/tmp/foo", 0100600` → /tmp/foo (execve)
    m = re.search(r'"((?:[^"\\]|\\.)*)"', args)
    if not m:
        return None
    return m.group(1).encode().decode("unicode_escape", errors="replace")


def parse_family_from_connect_args(args: str) -> int | None:
    """connect args like `4, {sa_family=AF_INET, sin_port=htons(...)}, 16`."""
    m = re.search(r"sa_family=(AF_[A-Z0-9_]+)", args)
    if m:
        return FAMILY_LOOKUP.get(m.group(1))
    return None


def parse_execve_argv(args: str) -> list[str]:
    """execve args: `"/bin/ls", ["ls", "-la"], 0x... /* ... vars */`."""
    # Find the [...] list
    m = re.search(r'\[(.*?)\](?=,|$)', args)
    if not m:
        return []
    inside = m.group(1)
    argv = []
    for q in re.findall(r'"((?:[^"\\]|\\.)*)"', inside):
        argv.append(q.encode().decode("unicode_escape", errors="replace"))
    return argv


def build_event(pid: int, ts: float, sc: str, args: str, ret: str | None) -> dict:
    ev = {
        "event": sc,
        "pid": pid,
        "ts": ts,
    }
    if sc in PATH_SYSCALLS:
        path = parse_path_from_args(args)
        if path is not None:
            ev["path"] = path
    if sc == "openat" or sc == "open":
        _, write_intent = parse_openat_flags(args)
        ev["write_intent"] = write_intent
    if sc == "execve":
        argv = parse_execve_argv(args)
        if argv:
            ev["argv"] = argv
    if sc == "connect":
        fam = parse_family_from_connect_args(args)
        if fam is not None:
            ev["family"] = fam
    if ret is not None:
        try:
            ev["ret"] = int(ret)
        except ValueError:
            pass
    return ev


def iter_strace_events(strace_path: Path) -> Iterator[dict]:
    """Yield normalized event dicts from a strace log.

    Handles unfinished/resumed by tracking per-pid pending syscalls and
    emitting the event on resume. Skips signal/exit metadata lines.
    """
    pending: dict[int, tuple[float, str, str]] = {}  # pid -> (ts_start, sc, args_partial)

    with strace_path.open(errors="replace") as fp:
        for line in fp:
            if SIGNAL_RE.match(line) or EXITED_RE.match(line):
                continue

            m = COMPLETE_RE.match(line)
            if m:
                pid = int(m.group("pid"))
                ts = float(m.group("ts"))
                sc = m.group("sc")
                args = m.group("args")
                ret = m.group("ret")
                yield build_event(pid, ts, sc, args, ret)
                continue

            m = UNFINISHED_RE.match(line)
            if m:
                pid = int(m.group("pid"))
                ts = float(m.group("ts"))
                sc = m.group("sc")
                args_partial = m.group("args")
                pending[pid] = (ts, sc, args_partial)
                continue

            m = RESUMED_RE.match(line)
            if m:
                pid = int(m.group("pid"))
                sc = m.group("sc")
                if pid not in pending or pending[pid][1] != sc:
                    continue
                ts_start, _, args_start = pending.pop(pid)
                args_end = m.group("args")
                ret = m.group("ret")
                combined_args = f"{args_start},{args_end}".strip(",")
                yield build_event(pid, ts_start, sc, combined_args, ret)
                continue
            # else: unmatched line, ignore


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--filter-syscall", default=None,
                    help="Only show events of this syscall type")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    strace_dir = args.session_dir / "strace"
    strace_files = list(strace_dir.glob("*.strace.log"))
    if not strace_files:
        print(f"[strace] no strace log at {strace_dir}")
        return 1
    strace_path = strace_files[0]

    if args.summary:
        from collections import Counter
        by_sc = Counter()
        n = 0
        for ev in iter_strace_events(strace_path):
            by_sc[ev["event"]] += 1
            n += 1
            if args.limit and n >= args.limit:
                break
        print(f"total events: {n}")
        for sc, c in by_sc.most_common(20):
            print(f"  {c:>6}  {sc}")
    else:
        n = 0
        for ev in iter_strace_events(strace_path):
            if args.filter_syscall and ev["event"] != args.filter_syscall:
                continue
            print(json.dumps(ev))
            n += 1
            if args.limit and n >= args.limit:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
