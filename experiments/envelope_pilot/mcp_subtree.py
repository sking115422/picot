"""Identify the MCP server process subtree in an ACE-C l3.jsonl trace.

Approach: define the MCP subtree strictly, from the execve chain.

1. Find the "MCP root pid" — the pid whose execve transitioned from
   `comm == "claude"` (Claude Code CLI) to a binary NOT under
   `/usr/local/bin/claude` (i.e., Claude spawning something else).
2. The subtree is: that pid, plus any pid whose comm ever matched
   one of a small set of distinctive MCP-runtime comms
   ("libuv-worker", "HTTP Client", "Bun Pool <N>") AND whose comm did
   NOT include "claude" or "strace" (which are ancestor identities).

Ambiguous comms like "node" and "python3" are only accepted if the pid
was already identified as the MCP root.

For sessions where the l3.jsonl has no path fields on execve events
(a data-quality issue), we fall back to comm-only identification: any
pid whose comm ever matched a distinctive MCP-internal comm is
in-subtree. This is looser but recoverable.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

# Comms that only appear inside an MCP runtime in this corpus.
COMM_DISTINCTIVE = {
    "libuv-worker",
    "HTTP Client",
    "V8Worker",
    "Bun Pool 0", "Bun Pool 1", "Bun Pool 2", "Bun Pool 3", "Bun Pool 4",
    "MainThread",
}

# Comms that identify NON-MCP processes (ancestors we should exclude).
COMM_ANCESTOR = {
    "claude",
    "claude.exe",
    "strace",
    "sh",
    "runc:[0:PARENT]",
    "runc:[1:CHILD]",
    "runc:[2:INIT]",
    "docker-entrypoi",
    "grep",  # bookkeeping the CLI spawns
    "6",     # numeric-comm artifact from strace-under-runc
}


def iter_events(l3_path: Path):
    with l3_path.open() as fp:
        for line in fp:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def find_mcp_root_pid_by_execve(l3_path: Path) -> int | None:
    """Path-based identification: find the pid where Claude Code
    execs a non-claude binary under /usr/local/bin/."""
    for d in iter_events(l3_path):
        if d.get("event") != "execve":
            continue
        comm = d.get("comm") or ""
        path = d.get("path") or ""
        if comm == "claude" and path.startswith("/usr/local/bin/") \
                and not path.startswith("/usr/local/bin/claude"):
            return d.get("pid")
    return None


def pid_comm_history(l3_path: Path) -> dict[int, set[str]]:
    """Map pid → set of comm strings that pid ever had."""
    h: dict[int, set[str]] = defaultdict(set)
    for d in iter_events(l3_path):
        pid = d.get("pid")
        comm = d.get("comm") or ""
        if pid is not None and comm:
            h[pid].add(comm)
    return h


def find_mcp_root_pid_fallback(l3_path: Path, per_pid: dict[int, set[str]]) -> int | None:
    """When execve path fields are empty (data-quality issue), fall back
    to the busiest pid whose comm history has a non-ancestor identity.

    A pid can have `claude` as an early comm (from before it re-execed)
    AND `awslabs.aws-doc` as its final comm — we want to include it as
    MCP because the *distinctive* comm is not an ancestor.

    Ancestor exclusion here is: a pid whose comm set is a subset of the
    ancestor set. If it has *any* non-ancestor comm, it's a candidate.
    """
    counts: dict[int, int] = {}
    for d in iter_events(l3_path):
        pid = d.get("pid")
        if pid is None:
            continue
        counts[pid] = counts.get(pid, 0) + 1
    for pid, _ in sorted(counts.items(), key=lambda x: -x[1]):
        comms = per_pid.get(pid, set())
        if not comms:
            continue
        # Skip pids whose ALL comms are ancestor-shape
        non_ancestor = comms - COMM_ANCESTOR
        if not non_ancestor:
            continue
        # Skip pids whose non-ancestor comms are just distinctive-worker
        # types (Bun Pool, HTTP Client) — those are threads under Claude
        # Code (which uses Bun internally for HTTP requests to Bedrock).
        # Real MCP root pids have a *unique* comm string that identifies
        # them as the MCP binary.
        if non_ancestor <= COMM_DISTINCTIVE:
            continue
        return pid
    return None


def build_subtree_pids(l3_path: Path) -> set[int]:
    """Return the set of pids considered in the MCP subtree.

    Rules (in order):
    - Include the MCP root pid identified by execve path (if available);
      or fall back to the busiest non-ancestor pid.
    - For any other pid, include it iff its comm history contains a
      distinctive MCP-internal comm AND does not contain a comm from
      the ANCESTOR set (which would mark it as Claude Code or wrapper).
    """
    per_pid = pid_comm_history(l3_path)
    root_pid = find_mcp_root_pid_by_execve(l3_path)
    if root_pid is None:
        root_pid = find_mcp_root_pid_fallback(l3_path, per_pid)

    subtree: set[int] = set()
    if root_pid is not None:
        subtree.add(root_pid)

    for pid, comms in per_pid.items():
        if pid in subtree:
            continue
        has_distinctive = bool(comms & COMM_DISTINCTIVE)
        has_ancestor = bool(comms & COMM_ANCESTOR)
        if has_distinctive and not has_ancestor:
            subtree.add(pid)

    return subtree


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path)
    args = ap.parse_args()
    l3 = args.session_dir / "l3.jsonl"

    root = find_mcp_root_pid_by_execve(l3)
    per_pid = pid_comm_history(l3)
    subtree = build_subtree_pids(l3)

    print(f"session: {args.session_dir}")
    print(f"root pid (path-based): {root}")
    print(f"subtree size: {len(subtree)}")
    print(f"subtree pids: {sorted(subtree)}")
    print(f"per-subtree-pid comms:")
    for pid in sorted(subtree):
        print(f"  {pid}: {sorted(per_pid[pid])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
