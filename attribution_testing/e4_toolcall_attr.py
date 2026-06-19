"""E4 — Tool-call → pid/tid attribution.

Given known tool-call boundaries (from stream.jsonl + session metadata),
identify the host-side pids/tids that fired during each tool call and
compare to L1 ground truth in the same window.

Tool-call window construction:
- `tool_result` records carry an ISO timestamp (end-of-call).
- The *start* of a tool call is bounded by the prior tool_result, or by
  session start for the first call.
- We tighten this with a heuristic: scan the host events for the first
  syscall in the MCP server pid that occurs after the prior boundary
  and before the tool_result ts. That yields a tool-call window
  [t_first_mcp_syscall, t_tool_result].

Per tool call:
- pid_set = set of host pids that emitted any event in [t_start, t_end]
- l1_set  = set of L1 tids (within the same window).
- Compare cardinality, breakdown by argv basename ("the right MCP
  server" should be the dominant pid).

Metric:
- "ambiguous_tool_call_rate": fraction of tool calls where >1 pid
  *outside the agent process tree but inside the MCP subtree* fired.
  In a clean attribution case this is 0 (one MCP server per call).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from common import find_sessions, load_session, extract_tool_calls
from e1_process_forest import execve_subjects

RESULTS = Path(__file__).parent / "results"


def iso_to_ns(s: str) -> int:
    # Trailing Z → UTC
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1_000_000_000)


def build_tool_windows(stream: list[dict], t_start_ns: int, t_end_ns: int) -> list[dict]:
    """Pair tool_use and tool_result; emit windowed tool calls."""
    pending: dict[str, dict] = {}
    calls: list[dict] = []
    last_boundary = t_start_ns
    for rec in stream:
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        contents = (msg.get("content") or []) if msg else []
        for c in contents:
            if c.get("type") == "tool_use":
                pending[c.get("id")] = {
                    "id": c.get("id"),
                    "name": c.get("name", ""),
                    "input": c.get("input", {}),
                    "t_window_lower": last_boundary,
                }
            elif c.get("type") == "tool_result":
                tu_id = c.get("tool_use_id")
                ts_iso = rec.get("timestamp")
                if tu_id in pending and ts_iso:
                    p = pending.pop(tu_id)
                    t_end = iso_to_ns(ts_iso)
                    p["t_end_ns"] = t_end
                    p["is_error"] = bool(c.get("is_error"))
                    calls.append(p)
                    last_boundary = t_end
    # Drop any still-pending (unterminated) calls
    return calls


def per_session(s) -> dict:
    if not s.l1 or not s.l3:
        return {"session": s.session_dir.name, "skip": "no_l1_or_l3"}
    t_start = s.meta["t_start_unix_ns"]
    t_end = s.meta["t_end_unix_ns"]
    calls = build_tool_windows(s.stream, t_start, t_end)
    if not calls:
        return {"session": s.session_dir.name,
                "mcp": s.meta.get("mcp"), "n_calls": 0}

    mcp_basename = s.meta["mcp"].split("/")[-1]

    # Identify the MCP server pid: among host execve subjects, find one
    # whose argv0 basename matches the MCP server binary pattern. We
    # match on argv0/path basename, not joined argv (avoids false hits
    # from prompts/arguments containing the mcp name).
    host_sub = execve_subjects(s.l3, "host")
    mcp_pids: set[int] = set()
    for hpid, info in host_sub.items():
        argv = info.get("argv") or []
        path = info.get("argv0") or ""
        argv0 = argv[0] if argv else path
        base = argv0.rsplit("/", 1)[-1].lower()
        # Common MCP server binary names: mcp-server-X, X-mcp-server,
        # or node/python running "*mcp*" script (we'd need argv[1] for
        # those, kept as a follow-up).
        if "mcp-server" in base or "mcp_server" in base:
            mcp_pids.add(hpid)
        elif base in ("node", "python", "python3", "uv", "uvx") and argv:
            # script name in argv[1]
            argv1 = argv[1] if len(argv) > 1 else ""
            argv1_base = argv1.rsplit("/", 1)[-1].lower()
            if "mcp" in argv1_base and ("server" in argv1_base or argv1_base.startswith("mcp-")):
                mcp_pids.add(hpid)

    # Only score on MCP tool calls — built-in tools like Bash/Read/Write
    # don't go through the MCP server so attribution to mcp_pids is
    # not the right metric for them.
    mcp_prefix = "mcp__"
    rows = []
    for call in calls:
        if not call["name"].startswith(mcp_prefix):
            continue
        # We use t_window_lower → t_end_ns as the tool-call window
        lo = call["t_window_lower"]
        hi = call["t_end_ns"]
        host_in: list[dict] = [e for e in s.l3
                                if lo <= e.get("ts_ns", 0) <= hi]
        l1_in: list[dict] = [e for e in s.l1 if lo <= e["ts_ns"] <= hi]

        host_pids = {e["pid"] for e in host_in if "pid" in e}
        host_tids = {e["tid"] for e in host_in if "tid" in e}
        l1_tids = {e["pid"] for e in l1_in}

        # Pids inside the MCP subtree (limited to mcp_pids and any pid
        # whose ppid resolves to an mcp_pid via the host forest)
        from common import build_host_forest
        hf = build_host_forest(s.l3)
        in_mcp_subtree = set(mcp_pids)
        # walk descendants
        frontier = set(mcp_pids)
        while frontier:
            nxt = set()
            for p in frontier:
                if p in hf:
                    nxt |= hf[p].children - in_mcp_subtree
            in_mcp_subtree |= nxt
            frontier = nxt

        host_pids_in_mcp = host_pids & in_mcp_subtree
        n_pids_in_mcp = len(host_pids_in_mcp)

        rows.append({
            "id": call["id"],
            "name": call["name"],
            "n_host_pids": len(host_pids),
            "n_host_tids": len(host_tids),
            "n_l1_tids": len(l1_tids),
            "n_pids_in_mcp_subtree": n_pids_in_mcp,
            "ambiguous": n_pids_in_mcp > 1,
            "mcp_pids_seen": sorted(host_pids_in_mcp)[:5],
        })

    return {
        "session": s.session_dir.name,
        "mcp": s.meta.get("mcp"),
        "variant": s.meta.get("variant"),
        "n_calls": len(rows),
        "n_mcp_pids_identified": len(mcp_pids),
        "calls": rows,
    }


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    sessions = find_sessions(limit=args.limit)
    print(f"E4 over {len(sessions)} sessions")
    rows = []
    for i, sd in enumerate(sessions):
        try:
            s = load_session(sd)
            rows.append(per_session(s))
            if (i + 1) % 10 == 0:
                print(f"  {i+1}/{len(sessions)}")
        except Exception as e:
            rows.append({"session": sd.name, "error": str(e)})

    (RESULTS / "e4.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    total_calls = 0
    total_ambig = 0
    total_no_mcp = 0
    pid_count_dist = []
    for r in rows:
        for c in r.get("calls", []):
            total_calls += 1
            if c["ambiguous"]:
                total_ambig += 1
            if c["n_pids_in_mcp_subtree"] == 0:
                total_no_mcp += 1
            pid_count_dist.append(c["n_pids_in_mcp_subtree"])
    summary = {
        "n_sessions": len(rows),
        "total_tool_calls": total_calls,
        "ambiguous_calls_pct": (total_ambig/total_calls) if total_calls else None,
        "no_mcp_pid_calls_pct": (total_no_mcp/total_calls) if total_calls else None,
        "n_pids_in_mcp_p50": sorted(pid_count_dist)[len(pid_count_dist)//2] if pid_count_dist else None,
        "n_pids_in_mcp_p95": sorted(pid_count_dist)[int(0.95*len(pid_count_dist))] if pid_count_dist else None,
    }
    (RESULTS / "e4_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
