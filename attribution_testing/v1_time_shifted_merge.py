"""V1 — Time-shifted merge variant.

Sanity check on whether E6's strong attribution numbers are an artifact
of temporal isolation between sessions in the merged stream. Original E6
preserves each session's original capture ts, so sessions live in
distinct temporal clusters separated by minutes — the 200ms
clone-inheritance window can never cross sessions.

V1 rebases each session's ts to a shared anchor t=0 so all sessions
run "concurrently" on the millisecond scale. Same prediction code,
same scoring, same trial design — only the merge is changed.

If F1 stays similar to E6, the 200ms inheritance window is robust
to temporal collisions. If F1 drops, the temporal-isolation property
was leaking into attribution.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from common import find_sessions, load_session
from e6_merged_attribution import (
    MergedEvent, _source_subtrees, _stream_tool_windows,
    predict, _pr_f1, adjusted_rand_index,
    pick_distinct_mcp_sessions,
)

RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def merge_sessions_time_shifted(sessions: list, layer: str) -> list[MergedEvent]:
    """Like merge_sessions but rebases each session's events to a
    shared anchor (t=0) so sessions overlap rather than sit in
    separate temporal clusters."""
    SHARED_CGROUP = 999_999
    merged: list[MergedEvent] = []
    for s in sessions:
        events = s.l3 if layer == "l3" else s.l2ext
        sid = s.meta.get("session_id", s.session_dir.name)
        mcp_name = s.meta.get("mcp", "")
        windows = _stream_tool_windows(s.session_dir / "stream.jsonl")
        session_pids, mcp_subtrees = _source_subtrees(events)
        mcp_pids: set[int] = set()
        for st in mcp_subtrees.values():
            mcp_pids |= st

        # Find this session's earliest ts to use as the rebase anchor.
        if not events:
            continue
        anchor = min((e.get("ts_ns", 0) for e in events if e.get("ts_ns")),
                     default=0)
        if anchor == 0:
            continue

        # Shift the windows alongside the events
        shifted_windows = [(lo - anchor, hi - anchor, tu) for lo, hi, tu in windows]

        for e in events:
            ev = dict(e)
            ev["cgroup_id"] = SHARED_CGROUP
            orig_ts = ev.get("ts_ns", 0)
            ev["ts_ns"] = orig_ts - anchor   # rebase to t=0
            ts = ev["ts_ns"]
            pid = ev.get("pid")
            in_session = pid in session_pids
            in_mcp = pid in mcp_pids
            tc_id = ""
            if in_mcp:
                for lo, hi, tu in shifted_windows:
                    if lo <= ts <= hi:
                        tc_id = tu
                        break
            merged.append(MergedEvent(
                event=ev,
                src_session=sid if in_session else "",
                src_mcp=mcp_name if in_mcp else "",
                src_tool_call=tc_id,
            ))
    # Sort interleaves all sessions by shifted ts -> events from
    # different sessions now genuinely overlap.
    merged.sort(key=lambda m: m.event.get("ts_ns", 0))
    return merged


def run_trial(sessions: list, layer: str) -> dict:
    merged = merge_sessions_time_shifted(sessions, layer)
    preds = predict(merged)

    sess_true = [m.src_session for m in merged]
    sess_pred = [p["session"] for p in preds]
    mcp_true = [m.src_mcp for m in merged]
    mcp_pred = [p["mcp"] for p in preds]
    tc_true = [m.src_tool_call for m in merged]
    tc_pred = [p["tool_call"] for p in preds]

    return {
        "n_events": len(merged),
        "session": {**_pr_f1(sess_true, sess_pred),
                    "ari": adjusted_rand_index(sess_true, sess_pred)},
        "mcp": {**_pr_f1(mcp_true, mcp_pred),
                "ari": adjusted_rand_index(mcp_true, mcp_pred)},
        "tool_call": {**_pr_f1(tc_true, tc_pred),
                      "ari": adjusted_rand_index(tc_true, tc_pred)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    pool = find_sessions(limit=args.limit)
    rng = random.Random(args.seed)

    rows = []
    for t in range(args.n_trials):
        chosen_dirs = pick_distinct_mcp_sessions(pool, args.n_sessions, rng)
        if not chosen_dirs:
            continue
        chosen = [load_session(sd) for sd in chosen_dirs]
        for layer in ("l2ext", "l3"):
            row = run_trial(chosen, layer)
            row.update({"trial": t, "layer": layer,
                        "mcps": [s.meta["mcp"] for s in chosen]})
            rows.append(row)
            print(f"trial {t} {layer}: "
                  f"sess F1={row['session']['f1']:.3f} ARI={row['session']['ari']:.3f}; "
                  f"mcp F1={row['mcp']['f1']:.3f} ARI={row['mcp']['ari']:.3f}; "
                  f"tc F1={row['tool_call']['f1']:.3f} ARI={row['tool_call']['ari']:.3f}")

    (RESULTS / "v1.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def agg(layer: str):
        sub = [r for r in rows if r["layer"] == layer]
        out = {"n_trials": len(sub)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[level]["f1"] for r in sub if r[level]["f1"] is not None]
            ps = [r[level]["precision"] for r in sub if r[level]["precision"] is not None]
            rs = [r[level]["recall"] for r in sub if r[level]["recall"] is not None]
            ars = [r[level]["ari"] for r in sub]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "f1_min": min(ms) if ms else None,
                "f1_max": max(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = {"l2ext": agg("l2ext"), "l3": agg("l3")}
    (RESULTS / "v1_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
