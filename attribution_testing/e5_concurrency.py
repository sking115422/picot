"""E5 — Concurrency stress.

Some MCP servers (or some calls within them) generate threads that run
concurrently. The question: when two tool-call windows overlap, can we
disambiguate them at the tid (thread) level?

We don't have many natively-overlapping tool calls in the corpus
(Claude Code dispatches sequentially in most cases), so we synthesize
overlap by **time-shifting** consecutive tool calls within the same
session so their windows overlap by 50%, then ask: are the active
*tid sets* during each shifted window disjoint?

If tid sets are disjoint → tid+window suffices.
If they overlap → we need app-layer correlation (e.g., mcp_jsonrpc
request id) to attribute.

We also report the natural (non-synthetic) overlap rate.
"""
from __future__ import annotations

import json
from pathlib import Path

from common import find_sessions, load_session
from e4_toolcall_attr import build_tool_windows
from e1_process_forest import execve_subjects

RESULTS = Path(__file__).parent / "results"


def per_session(s) -> dict:
    if not s.l3:
        return {"session": s.session_dir.name, "skip": "no_l3"}

    calls = build_tool_windows(s.stream, s.meta["t_start_unix_ns"],
                               s.meta["t_end_unix_ns"])
    mcp_calls = [c for c in calls if c["name"].startswith("mcp__")]
    if len(mcp_calls) < 2:
        return {"session": s.session_dir.name, "n_calls": len(mcp_calls)}

    # Find MCP pid set
    sub = execve_subjects(s.l3, "host")
    mcp_pids: set[int] = set()
    for hpid, info in sub.items():
        argv = info.get("argv") or []
        argv0 = argv[0] if argv else (info.get("argv0") or "")
        base = argv0.rsplit("/", 1)[-1].lower()
        if "mcp-server" in base:
            mcp_pids.add(hpid)

    # Index events by ts for fast windowed lookup
    events_sorted = sorted(s.l3, key=lambda e: e.get("ts_ns", 0))

    def tids_in(lo: int, hi: int) -> set[int]:
        return {e["tid"] for e in events_sorted
                if "tid" in e and e.get("pid") in mcp_pids
                and lo <= e.get("ts_ns", 0) <= hi}

    natural_overlaps = 0
    natural_pairs = 0
    synth_disjoint = 0
    synth_overlap_count = 0

    # Natural overlap detection (windows abut in our reconstruction so
    # rarely overlap; counted for completeness)
    for i, a in enumerate(mcp_calls):
        for b in mcp_calls[i+1:]:
            natural_pairs += 1
            if a["t_window_lower"] <= b["t_end_ns"] and b["t_window_lower"] <= a["t_end_ns"]:
                natural_overlaps += 1

    # Synthetic 50%-overlap stress: for each consecutive pair, shift the
    # second window so it overlaps the first by 50% of the first's
    # duration, then check tid-set disjointness.
    for a, b in zip(mcp_calls, mcp_calls[1:]):
        a_lo, a_hi = a["t_window_lower"], a["t_end_ns"]
        a_dur = a_hi - a_lo
        if a_dur <= 0:
            continue
        b_lo, b_hi = b["t_window_lower"], b["t_end_ns"]
        b_dur = b_hi - b_lo
        if b_dur <= 0:
            continue

        # Shift b so it starts at a_lo + a_dur/2
        new_b_lo = a_lo + a_dur // 2
        # Use original b's events but re-window: take events from b's
        # original window and pretend they were at the shifted time
        # (no remapping needed — we just pull the same tid set under a
        # different overlap label).
        a_tids = tids_in(a_lo, a_hi)
        b_tids = tids_in(b_lo, b_hi)
        if not a_tids or not b_tids:
            continue
        synth_overlap_count += 1
        if a_tids.isdisjoint(b_tids):
            synth_disjoint += 1

    return {
        "session": s.session_dir.name,
        "mcp": s.meta.get("mcp"),
        "n_mcp_calls": len(mcp_calls),
        "natural_overlap_pairs": natural_overlaps,
        "natural_pair_count": natural_pairs,
        "synth_disjoint": synth_disjoint,
        "synth_overlap_count": synth_overlap_count,
        "synth_disjoint_rate":
            (synth_disjoint / synth_overlap_count) if synth_overlap_count else None,
    }


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    sessions = find_sessions(limit=args.limit)
    print(f"E5 over {len(sessions)} sessions")
    rows = []
    for sd in sessions:
        try:
            s = load_session(sd)
            rows.append(per_session(s))
        except Exception as e:
            rows.append({"session": sd.name, "error": str(e)})

    (RESULTS / "e5.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    have = [r for r in rows if r.get("synth_overlap_count", 0) > 0]
    n_syn = sum(r["synth_overlap_count"] for r in have)
    n_dis = sum(r["synth_disjoint"] for r in have)
    summary = {
        "n_sessions_examined": len(rows),
        "n_sessions_with_overlapping_pairs": len(have),
        "synth_overlap_pairs_total": n_syn,
        "synth_disjoint_total": n_dis,
        "synth_disjoint_rate": (n_dis/n_syn) if n_syn else None,
        "natural_overlap_pairs_total": sum(r.get("natural_overlap_pairs",0) for r in rows),
    }
    (RESULTS / "e5_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
