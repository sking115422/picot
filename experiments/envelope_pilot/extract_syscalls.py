"""Extract syscall observations from an ACE-C session's l3.jsonl.

Normalizes each syscall event into a compact record with just the fields
needed to check envelope membership:

  {
    "event": "openat",           # syscall name
    "path": "/tmp/foo",          # for path-carrying syscalls (openat, unlinkat, execve)
    "flags": 2,                  # openat flags (numeric)
    "write_intent": true,        # derived: does this open imply write?
    "family": 1,                 # connect family (1=AF_LOCAL, 2=AF_INET, 10=AF_INET6)
    "comm": "python3",
    "pid": 12345,
  }

We DROP:
  - _calibration event (metadata, not a syscall)
  - exit_group (not a security-relevant syscall for envelope purposes)
  - runc:[N:INIT] / runc:[N:CHILD] events (container-mechanic overhead;
    we saw the same problem in the layer1_discrepancy pilot)

The comm filter is imperfect — some legitimate agent-spawned children
might have runc-derived comms briefly during transition. For a pilot,
excluding all runc: events is a conservative simplification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterator

# O_WRONLY = 1, O_RDWR = 2. Any bit set in write_flags == write intent.
WRITE_FLAG_MASK = 0b11  # O_ACCMODE
O_WRONLY = 1
O_RDWR = 2
O_CREAT = 0o100
O_TRUNC = 0o1000
O_APPEND = 0o2000

DROP_COMMS_PREFIX = ("runc:",)
DROP_EVENTS = {"_calibration", "exit_group"}


def is_write_open(flags: int | None) -> bool:
    if flags is None:
        return False
    accmode = flags & WRITE_FLAG_MASK
    return accmode in (O_WRONLY, O_RDWR)


def normalize(event: dict) -> dict | None:
    ev = event.get("event")
    if ev in DROP_EVENTS or ev is None:
        return None
    comm = event.get("comm", "")
    if any(comm.startswith(p) for p in DROP_COMMS_PREFIX):
        return None
    out: dict = {
        "event": ev,
        "comm": comm,
        "pid": event.get("pid"),
    }
    if ev in ("openat", "unlinkat", "execve"):
        out["path"] = event.get("path")
    if ev == "openat":
        flags = event.get("flags")
        out["flags"] = flags
        out["write_intent"] = is_write_open(flags)
    if ev in ("connect", "sendto"):
        out["family"] = event.get("family")
        out["fd"] = event.get("fd")
    return out


def iter_session_syscalls(session_dir: Path) -> Iterator[dict]:
    l3 = session_dir / "l3.jsonl"
    with l3.open() as fp:
        for line in fp:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            norm = normalize(event)
            if norm is not None:
                yield norm


def summarize(events: list[dict]) -> dict:
    """Compact stats about a session's syscalls."""
    from collections import Counter
    ev_counts = Counter(e["event"] for e in events)
    read_paths = sorted({e["path"] for e in events if e["event"] == "openat"
                         and not e.get("write_intent") and e.get("path")})
    write_paths = sorted({e["path"] for e in events if e["event"] == "openat"
                          and e.get("write_intent") and e.get("path")})
    unlink_paths = sorted({e["path"] for e in events if e["event"] == "unlinkat"
                           and e.get("path")})
    exec_paths = sorted({e["path"] for e in events if e["event"] == "execve"
                         and e.get("path")})
    connect_families = Counter(e.get("family") for e in events if e["event"] == "connect")
    comms = Counter(e.get("comm") for e in events)
    return {
        "total": len(events),
        "event_counts": dict(ev_counts),
        "read_paths": read_paths,
        "write_paths": write_paths,
        "unlink_paths": unlink_paths,
        "exec_paths": exec_paths,
        "connect_families": dict(connect_families),
        "comm_top": dict(comms.most_common(15)),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path)
    ap.add_argument("--summary", action="store_true", help="Print summary instead of full list")
    args = ap.parse_args()

    events = list(iter_session_syscalls(args.session_dir))
    if args.summary:
        print(json.dumps(summarize(events), indent=2))
    else:
        for e in events:
            print(json.dumps(e))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
