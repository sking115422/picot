"""Shared utilities for the host-side attribution experiments.

Loads:
- L1 (in-container strace text) → list[dict] with container-namespace pids
- L2_ext / L3 (host eBPF JSONL, v1 envelope) → list[dict] with host pids
- session.json + stream.jsonl (agent app layer)

Namespace bridge: L1 sees container-pid space, eBPF sees host-pid space.
We bridge by aligning execve/clone events on wall-clock ts and by argv/comm.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

CAPTURES_ROOT = Path("/lts/ai_sec_exp/cle4as/src/captures_phase4")


# ---- session discovery ----------------------------------------------

def find_sessions(root: Path = CAPTURES_ROOT, limit: int | None = None) -> list[Path]:
    """Yield session directories (those containing session.json), sorted.

    Sorting is critical: the random sampler downstream uses this list as
    its pool, so the pool must be deterministic across runs. Filesystem
    walk order is not; we sort by full path string to fix that."""
    paths = sorted(p.parent for p in root.rglob("session.json"))
    if limit:
        return paths[:limit]
    return paths


def load_session_meta(session_dir: Path) -> dict:
    return json.loads((session_dir / "session.json").read_text())


# ---- L1 strace parsing ----------------------------------------------

# strace -ttt -f format:
#   <pid> <epoch.us> <syscall>(<args>) = <ret>
_STRACE_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<epoch>\d+\.\d+)\s+"
    r"(?P<sc>[a-z][a-z_0-9]*)\((?P<args>.*?)\)\s*=\s*(?P<ret>.*?)$"
)
_STRACE_UNFINISHED = re.compile(
    r"^(?P<pid>\d+)\s+(?P<epoch>\d+\.\d+)\s+"
    r"(?P<sc>[a-z][a-z_0-9]*)\((?P<args>.*)<unfinished\s*\.\.\.>\s*$"
)


def parse_l1(path: Path) -> list[dict]:
    """Parse strace -ttt -f into events with container-namespace pids."""
    events: list[dict] = []
    if not path.exists():
        return events
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = _STRACE_RE.match(line)
            if not m:
                m = _STRACE_UNFINISHED.match(line)
                if not m:
                    continue
                ret = "?"
            else:
                ret = m["ret"].strip()
            sec, us = m["epoch"].split(".")
            ts_ns = int(sec) * 1_000_000_000 + int(us) * 1_000
            events.append({
                "ts_ns": ts_ns,
                "pid": int(m["pid"]),  # container-namespace
                "syscall": m["sc"],
                "args_raw": m["args"],
                "ret": ret,
            })
    return events


def l1_pids(events: list[dict]) -> set[int]:
    return {e["pid"] for e in events}


# ---- v1 envelope JSONL parsing --------------------------------------

def parse_v1_jsonl(path: Path) -> list[dict]:
    """Parse a host-side L2_ext or L3 v1 envelope JSONL slice."""
    events: list[dict] = []
    if not path.exists():
        return events
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event", "").startswith("_"):
                continue  # skip metadata records
            events.append(e)
    return events


def host_pids(events: list[dict]) -> set[int]:
    return {e["pid"] for e in events if "pid" in e}


# ---- namespace bridge: align L1 ↔ host on execve ts -----------------

def bridge_pid_map(l1: list[dict], host: list[dict],
                   tol_ms: int = 50) -> dict[int, int]:
    """Map host_pid → container_pid by matching execve events on ts.

    Returns a dict; not every host pid will be mapped (threads share argv).
    """
    l1_execve = [e for e in l1 if e["syscall"] == "execve"]
    host_execve = [e for e in host if e.get("event") == "execve"]
    bridge: dict[int, int] = {}
    used_l1: set[int] = set()
    tol_ns = tol_ms * 1_000_000
    for he in host_execve:
        hpid = he["pid"]
        h_ts = he["ts_ns"]
        # find nearest unused L1 execve within tol
        best = None
        best_d = tol_ns + 1
        for i, le in enumerate(l1_execve):
            if i in used_l1:
                continue
            d = abs(le["ts_ns"] - h_ts)
            if d < best_d:
                best_d = d
                best = i
        if best is not None:
            bridge[hpid] = l1_execve[best]["pid"]
            used_l1.add(best)
    return bridge


# ---- process forest from clone events -------------------------------

@dataclass
class ProcNode:
    pid: int
    ppid: int | None = None
    comm: str | None = None
    argv: list[str] | None = None
    children: set[int] = field(default_factory=set)
    syscall_counts: dict[str, int] = field(default_factory=dict)


def build_host_forest(events: list[dict]) -> dict[int, ProcNode]:
    """Build a process tree from v1 envelope events.

    parent_tid in clone/clone3 args points to the *caller* tid; the new
    pid is the pid recorded on the clone event itself when fired by the
    new task, or seen later as a previously-unknown pid.

    We approximate by:
    1. Seeding nodes from every distinct pid we see.
    2. For each clone event, the calling tid (event pid/tid) is the
       parent of the *next-seen new pid* — but the v1 envelope as
       captured here records the clone event under the caller, not
       the child. We walk events in order; whenever a new pid first
       appears, we attribute it to the most recent clone caller tid
       within a small temporal window.
    """
    forest: dict[int, ProcNode] = {}

    # Pass 1: seed nodes from execve (these always carry the new pid)
    for e in events:
        pid = e.get("pid")
        if pid is None:
            continue
        if pid not in forest:
            forest[pid] = ProcNode(pid=pid, comm=e.get("comm"))

    # Pass 2: argv from execve
    for e in events:
        if e.get("event") == "execve":
            pid = e.get("pid")
            if pid in forest:
                args = e.get("args", {}) or {}
                forest[pid].argv = args.get("argv")
                forest[pid].comm = e.get("comm") or forest[pid].comm

    # Pass 3: ppid attribution via clone temporal proximity
    # Walk in ts order; track recent clone callers (caller_tid → ts).
    sorted_events = sorted(events, key=lambda e: e.get("ts_ns", 0))
    seen_pids: set[int] = set()
    last_clone: list[tuple[int, int, int]] = []  # (ts, caller_pid, caller_tid)

    for e in sorted_events:
        et = e.get("event")
        pid = e.get("pid")
        ts = e.get("ts_ns", 0)
        if et in ("clone", "clone3"):
            last_clone.append((ts, pid, e.get("tid", pid)))
            if len(last_clone) > 64:
                last_clone = last_clone[-64:]
        if pid is not None and pid not in seen_pids:
            seen_pids.add(pid)
            # Attribute to nearest recent clone caller (within 100ms)
            ppid = None
            for cts, cpid, ctid in reversed(last_clone):
                if ts - cts > 100_000_000:
                    break
                if cpid != pid:
                    ppid = cpid
                    break
            if pid in forest and ppid is not None:
                forest[pid].ppid = ppid
                if ppid in forest:
                    forest[ppid].children.add(pid)

    # Pass 4: syscall histograms per pid
    for e in events:
        pid = e.get("pid")
        ev = e.get("event")
        if pid in forest and ev:
            forest[pid].syscall_counts[ev] = forest[pid].syscall_counts.get(ev, 0) + 1

    return forest


def build_l1_forest(events: list[dict]) -> dict[int, ProcNode]:
    """Build a process tree from strace -f text, container-namespace pids.

    L1's clone returns the new pid in `ret`, so attribution is exact:
    if pid X calls clone() and ret=Y, then ppid(Y) = X.
    """
    forest: dict[int, ProcNode] = {}
    for e in events:
        pid = e["pid"]
        if pid not in forest:
            forest[pid] = ProcNode(pid=pid)

    # execve argv: parse args_raw for the second arg (a list)
    for e in events:
        if e["syscall"] != "execve":
            continue
        m = re.match(r'"([^"]*)"\s*,\s*\[(.*?)\](?:\s*,|\s*$)', e["args_raw"], re.S)
        if m:
            argv_raw = m.group(2)
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', argv_raw)
            if e["pid"] in forest:
                forest[e["pid"]].argv = argv
                forest[e["pid"]].comm = (argv[0] if argv else None)

    # clone parent→child via ret
    for e in events:
        if e["syscall"] not in ("clone", "clone3"):
            continue
        try:
            child = int(e["ret"])
        except (ValueError, TypeError):
            continue
        if child <= 0:
            continue
        parent = e["pid"]
        if child not in forest:
            forest[child] = ProcNode(pid=child)
        forest[child].ppid = parent
        if parent in forest:
            forest[parent].children.add(child)

    # syscall histograms per pid
    for e in events:
        pid = e["pid"]
        sc = e["syscall"]
        forest[pid].syscall_counts[sc] = forest[pid].syscall_counts.get(sc, 0) + 1

    return forest


# ---- app layer ------------------------------------------------------

def parse_stream(stream_path: Path) -> list[dict]:
    """Parse stream.jsonl into a list of records preserving ts where present."""
    out: list[dict] = []
    if not stream_path.exists():
        return out
    for line in stream_path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def extract_tool_calls(stream: list[dict]) -> list[dict]:
    """Extract (id, name, t_start_approx) for each tool_use in the stream.

    stream.jsonl entries don't carry per-message ts; we approximate using
    the order of tool_use → tool_result pairs and rely on session
    t_start_unix_ns to anchor. For tighter timing, callers should fall
    back to filename mtime or external markers.
    """
    calls: list[dict] = []
    pending: dict[str, dict] = {}
    for i, rec in enumerate(stream):
        msg = rec.get("message", {}) if isinstance(rec.get("message"), dict) else {}
        for c in (msg.get("content") or []):
            if c.get("type") == "tool_use":
                tc = {"order": i, "id": c.get("id"), "name": c.get("name", ""),
                      "input": c.get("input", {}), "result": None}
                pending[c.get("id")] = tc
                calls.append(tc)
            elif c.get("type") == "tool_result":
                tu_id = c.get("tool_use_id")
                if tu_id in pending:
                    pending[tu_id]["result_order"] = i
    return calls


# ---- session triple loader ------------------------------------------

@dataclass
class SessionTraces:
    meta: dict
    l1: list[dict]
    l2ext: list[dict]
    l3: list[dict]
    stream: list[dict]
    session_dir: Path


def load_session(session_dir: Path) -> SessionTraces:
    meta = load_session_meta(session_dir)
    l1_path = Path(meta["l1_strace_path"])
    return SessionTraces(
        meta=meta,
        l1=parse_l1(l1_path),
        l2ext=parse_v1_jsonl(session_dir / "l2ext.jsonl"),
        l3=parse_v1_jsonl(session_dir / "l3.jsonl"),
        stream=parse_stream(session_dir / "stream.jsonl"),
        session_dir=session_dir,
    )
