"""Identify the MCP server process subtree in an ace_full strace log.

Approach:
  1. Walk strace events; build a parent→child map from clone/clone3 events.
     (pid = caller, ret = new child pid.)
  2. Find the "MCP root pid" — the pid whose FIRST execve has a path
     under /usr/local/bin/ that is NOT /usr/local/bin/claude (which
     Claude Code CLI itself uses) and NOT a wrapper like `rg`.
  3. Subtree = MCP root pid + all transitive descendants in the fork map.

For built-in tool sessions (ace_bi, mcp=builtin/claude-code), there IS
no separate MCP server — the "MCP" is Claude Code itself. In that case
the subtree is the entire agent subtree from claude's own pid onward,
minus the container-bootstrap ancestors (docker-entrypoint, initial sh).
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from strace_extract import iter_strace_events


ANCESTOR_BINARIES = {
    "/usr/local/bin/claude",
    "/usr/local/sbin/claude",
    "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",
    "/bin/sh",
    "/usr/bin/sh",
    "/usr/local/bin/sh",
    "/usr/local/sbin/sh",
    "/usr/sbin/sh",
    "/bin/dash",
    "/usr/bin/grep",  # Claude Code shells out to grep for ripgrep fallback checks
    "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe",  # dup for safety
}


def build_fork_map(strace_path: Path) -> dict[int, list[int]]:
    """Return parent_pid -> list of child pids from clone events."""
    parent_to_children: dict[int, list[int]] = defaultdict(list)
    for ev in iter_strace_events(strace_path):
        if ev["event"] in ("clone", "clone3") and ev.get("ret") is not None:
            child = ev["ret"]
            if isinstance(child, int) and child > 0:
                parent_to_children[ev["pid"]].append(child)
    return parent_to_children


def find_mcp_root_pid(strace_path: Path) -> int | None:
    """Find the pid whose first execve is under /usr/local/bin/ and is
    not one of the known Claude-Code-related ancestor binaries.

    Only considers the FIRST execve per pid — later re-execs (like an
    MCP re-execing into node) don't change the pid identity.
    """
    seen_first: dict[int, str] = {}
    for ev in iter_strace_events(strace_path):
        if ev["event"] != "execve":
            continue
        path = ev.get("path")
        pid = ev.get("pid")
        if not path or pid in seen_first:
            continue
        seen_first[pid] = path

    # Now pick the first-execve-per-pid that's under /usr/local/bin
    # AND not on the ancestor list.
    candidates = []
    for pid, first_path in seen_first.items():
        if not first_path.startswith("/usr/local/bin/") and not first_path.startswith("/usr/local/sbin/"):
            continue
        if first_path in ANCESTOR_BINARIES:
            continue
        # Skip claude.exe-family paths (Node.js wrappers)
        if "claude" in first_path.lower() and "claude-code" in first_path:
            continue
        candidates.append((pid, first_path))

    if not candidates:
        return None
    # Return the earliest pid (numerically) — MCPs usually spawn in a
    # deterministic order after Claude Code initialization
    candidates.sort(key=lambda x: x[0])
    return candidates[0][0]


def build_subtree_pids(strace_path: Path, ace_bi: bool = False) -> set[int]:
    """Return the set of pids in the MCP/agent subtree."""
    fork_map = build_fork_map(strace_path)

    if ace_bi:
        # For ace_bi (built-in tools), everything in the container is
        # agent activity. Strace can lose clone edges (some children
        # appear without their fork being captured), so building a
        # subtree by fork-walking underestimates. Instead: take every
        # pid that appears in the trace as agent-related, EXCEPT known-
        # ancestor comms (runc/docker/initial-sh bootstrap).
        #
        # We identify bootstrap pids as those whose first execve path
        # matches one of: docker-entrypoint, runc, /bin/sh with args
        # like `-c "strace..."`. Everything else is agent-space.
        BOOTSTRAP_PATH_PREFIXES = (
            "/usr/local/bin/docker-entrypoint",
        )
        BOOTSTRAP_EXECVE_KEYWORDS = ("docker-entrypoint",)

        bootstrap_pids = set()
        all_pids = set()
        for ev in iter_strace_events(strace_path):
            pid = ev.get("pid")
            if pid is None:
                continue
            all_pids.add(pid)
            if ev.get("event") != "execve":
                continue
            path = ev.get("path") or ""
            argv = ev.get("argv") or []
            # Bootstrap detection: shells that spawn strace as their next act
            if any(path.startswith(p) for p in BOOTSTRAP_PATH_PREFIXES):
                bootstrap_pids.add(pid)
            if any(kw in path for kw in BOOTSTRAP_EXECVE_KEYWORDS):
                bootstrap_pids.add(pid)
            if argv and argv[0].endswith("/strace") or argv and argv[0] == "strace":
                bootstrap_pids.add(pid)

        return all_pids - bootstrap_pids
    else:
        root = find_mcp_root_pid(strace_path)
        if root is None:
            return set()

    # BFS from root through fork_map
    subtree = {root}
    frontier = [root]
    while frontier:
        parent = frontier.pop()
        for child in fork_map.get(parent, []):
            if child not in subtree:
                subtree.add(child)
                frontier.append(child)
    return subtree


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("session_dir", type=Path)
    ap.add_argument("--ace-bi", action="store_true")
    args = ap.parse_args()

    strace_dir = args.session_dir / "strace"
    strace_files = list(strace_dir.glob("*.strace.log"))
    if not strace_files:
        print("no strace log")
        return 1
    strace_path = strace_files[0]

    root = find_mcp_root_pid(strace_path)
    subtree = build_subtree_pids(strace_path, ace_bi=args.ace_bi)

    print(f"session: {args.session_dir}")
    print(f"MCP root pid: {root}")
    print(f"subtree size: {len(subtree)}")
    print(f"subtree pids: {sorted(subtree)}")

    # Show execve path per subtree pid (first execve)
    first_execve_by_pid: dict[int, str] = {}
    for ev in iter_strace_events(strace_path):
        if ev["event"] == "execve" and ev["pid"] in subtree \
                and ev["pid"] not in first_execve_by_pid \
                and ev.get("path"):
            first_execve_by_pid[ev["pid"]] = ev["path"]
    print("first execve per subtree pid:")
    for pid in sorted(subtree):
        print(f"  {pid}: {first_execve_by_pid.get(pid, '<no execve>')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
