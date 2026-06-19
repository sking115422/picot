"""V3 — Score attribution on bare-host captures.

Same prediction code as E6, but with bare-host captures as input.
Bare-host captures have:
- No L1 oracle (no in-container strace)
- No cgroup-per-session shortcut (host had no Docker)
- No runc/docker-entrypoint preamble in the trace

Ground truth is derived from the bare-host trace itself: for each
captured session, we identify its session pid (the one that ran
`claude -p`), compute its descendant subtree, identify any
mcp-server-* execve under it, and label every event accordingly.

This is the same kind of reachability-based ground truth as E6, but
applied to bare-host data instead of a Docker-derived dataset.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from common import parse_v1_jsonl
from e6_merged_attribution import (
    MergedEvent, _source_subtrees, _stream_tool_windows,
    predict, _pr_f1, adjusted_rand_index,
)

RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


def load_v3_session(sess_dir: Path) -> dict:
    """Load a bare-host capture: meta, l3 trace, stream."""
    meta = json.loads((sess_dir / "session.json").read_text())
    l3_events = parse_v1_jsonl(sess_dir / "l3.jsonl")
    stream = []
    sp = sess_dir / "stream.jsonl"
    if sp.exists():
        for line in sp.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                stream.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return {
        "meta": meta,
        "l3": l3_events,
        "stream": stream,
        "session_dir": sess_dir,
    }


def merge_v3_sessions(sessions: list, n_sessions: int) -> list[MergedEvent]:
    """Merge N bare-host captures into one stream with shared cgroup_id.

    Each capture's L3 trace was the *full host trace* during the
    capture window, not a per-session slice. Ground-truth labels apply
    only to events in the session subtree (rooted at `claude -p`); the
    rest get src_*='' (host noise the predictor must ignore).
    """
    SHARED = 999_999
    merged: list[MergedEvent] = []
    for s in sessions[:n_sessions]:
        events = s["l3"]
        sid = s["meta"]["session_id"]
        mcp_label = s["meta"]["mcp"]

        session_pids, mcp_subtrees = _source_subtrees(events)
        mcp_pids: set[int] = set()
        for st in mcp_subtrees.values():
            mcp_pids |= st

        windows = _stream_tool_windows(s["session_dir"] / "stream.jsonl")

        for e in events:
            ev = dict(e)
            ev["cgroup_id"] = SHARED
            ts = ev.get("ts_ns", 0)
            pid = ev.get("pid")
            in_session = pid in session_pids
            in_mcp = pid in mcp_pids
            tc_id = ""
            if in_mcp:
                for lo, hi, tu in windows:
                    if lo <= ts <= hi:
                        tc_id = tu
                        break
            merged.append(MergedEvent(
                event=ev,
                src_session=sid if in_session else "",
                src_mcp=mcp_label if in_mcp else "",
                src_tool_call=tc_id,
            ))
    merged.sort(key=lambda m: m.event.get("ts_ns", 0))
    return merged


def run_trial(sessions: list, n_sessions: int) -> dict:
    merged = merge_v3_sessions(sessions, n_sessions)
    preds = predict(merged)

    sess_true = [m.src_session for m in merged]
    sess_pred = [p["session"] for p in preds]
    mcp_true = [m.src_mcp for m in merged]
    mcp_pred = [p["mcp"] for p in preds]
    tc_true = [m.src_tool_call for m in merged]
    tc_pred = [p["tool_call"] for p in preds]

    return {
        "n_events": len(merged),
        "n_with_session_truth": sum(1 for s in sess_true if s),
        "n_with_mcp_truth": sum(1 for s in mcp_true if s),
        "n_with_tc_truth": sum(1 for s in tc_true if s),
        "session": {**_pr_f1(sess_true, sess_pred),
                    "ari": adjusted_rand_index(sess_true, sess_pred)},
        "mcp": {**_pr_f1(mcp_true, mcp_pred),
                "ari": adjusted_rand_index(mcp_true, mcp_pred)},
        "tool_call": {**_pr_f1(tc_true, tc_pred),
                      "ari": adjusted_rand_index(tc_true, tc_pred)},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures")
    ap.add_argument("--n-sessions", type=int, default=3,
                    help="how many bare-host sessions per merged trial")
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cap_root = Path(args.captures_dir)
    sess_dirs = sorted([p for p in cap_root.iterdir() if p.is_dir()])
    print(f"found {len(sess_dirs)} bare-host captures")
    sessions = [load_v3_session(sd) for sd in sess_dirs]
    # Drop any with empty traces
    sessions = [s for s in sessions if s["l3"]]
    print(f"{len(sessions)} sessions with non-empty l3 trace")

    # Group by MCP for distinct-MCP sampling
    by_mcp: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_mcp[s["meta"]["mcp"]].append(s)
    print("sessions by MCP:", {k: len(v) for k, v in by_mcp.items()})

    rng = random.Random(args.seed)
    rows = []
    n_distinct = min(args.n_sessions, len(by_mcp))

    for t in range(args.n_trials):
        mcps = list(by_mcp.keys())
        if len(mcps) < n_distinct:
            print(f"trial {t}: not enough distinct MCPs")
            continue
        chosen_mcps = rng.sample(mcps, n_distinct)
        chosen = [rng.choice(by_mcp[m]) for m in chosen_mcps]
        row = run_trial(chosen, n_distinct)
        row.update({"trial": t, "mcps": chosen_mcps})
        rows.append(row)
        print(f"trial {t}: "
              f"sess F1={row['session']['f1']:.3f} ARI={row['session']['ari']:.3f}; "
              f"mcp F1={row['mcp']['f1']:.3f} ARI={row['mcp']['ari']:.3f}; "
              f"tc F1={row['tool_call']['f1']:.3f} ARI={row['tool_call']['ari']:.3f}")

    (RESULTS / "v3.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def agg():
        out = {"n_trials": len(rows)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[level]["f1"] for r in rows if r[level]["f1"] is not None]
            ps = [r[level]["precision"] for r in rows if r[level]["precision"] is not None]
            rs = [r[level]["recall"] for r in rows if r[level]["recall"] is not None]
            ars = [r[level]["ari"] for r in rows]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "f1_min": min(ms) if ms else None,
                "f1_max": max(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = agg()
    (RESULTS / "v3_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
