"""V3 scoring against the Kuzu graph, with optional cohesion filter.

Compares three configurations on the same V3 captures:
1. baseline   — graph-based attribution (matches in-memory predict)
2. cohesion   — cohesion filter applied post-build
3. tightboth  — cohesion + (Phase 3c, when added)
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
    _pr_f1, adjusted_rand_index,
)
from graph_builder import build_graph
from kuzu_attribution import attribute_events_by_query
from cohesion_filter import cohesion_filter

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)
RESULTS = Path(__file__).parent / "results"


def load_v3_session(sess_dir: Path) -> dict:
    meta = json.loads((sess_dir / "session.json").read_text())
    l3_events = parse_v1_jsonl(sess_dir / "l3.jsonl")
    return {"meta": meta, "l3": l3_events, "session_dir": sess_dir}


def merge_v3_sessions(sessions: list, n_sessions: int) -> list[MergedEvent]:
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


def score(merged: list, preds: list[dict]) -> dict:
    sess_true = [m.src_session for m in merged]
    sess_pred = [p["session"] for p in preds]
    mcp_true = [m.src_mcp for m in merged]
    mcp_pred = [p["mcp"] for p in preds]
    tc_true = [m.src_tool_call for m in merged]
    tc_pred = [p["tool_call"] for p in preds]
    return {
        "session": {**_pr_f1(sess_true, sess_pred),
                    "ari": adjusted_rand_index(sess_true, sess_pred)},
        "mcp": {**_pr_f1(mcp_true, mcp_pred),
                "ari": adjusted_rand_index(mcp_true, mcp_pred)},
        "tool_call": {**_pr_f1(tc_true, tc_pred),
                      "ari": adjusted_rand_index(tc_true, tc_pred)},
    }


def run_trial(sessions: list, n_sessions: int, db_path: Path,
                cohesion_threshold: float = 0.10) -> dict:
    merged = merge_v3_sessions(sessions, n_sessions)
    builder = build_graph(merged, db_path)

    # Score 1: baseline (no filter)
    preds_baseline = attribute_events_by_query(builder, merged)
    scores_baseline = score(merged, preds_baseline)

    # Apply cohesion filter
    cohesion_stats = cohesion_filter(builder.conn, threshold=cohesion_threshold)

    # Score 2: cohesion-filtered
    preds_cohesion = attribute_events_by_query(builder, merged)
    scores_cohesion = score(merged, preds_cohesion)

    return {
        "n_events": len(merged),
        "n_pids_examined": cohesion_stats.n_pids_examined,
        "n_pids_demoted": cohesion_stats.n_pids_demoted,
        "baseline": scores_baseline,
        "cohesion": scores_cohesion,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures")
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=0.10)
    args = ap.parse_args()

    cap_root = Path(args.captures_dir)
    sess_dirs = sorted([p for p in cap_root.iterdir() if p.is_dir()])
    sessions = [load_v3_session(sd) for sd in sess_dirs]
    sessions = [s for s in sessions if s["l3"]]
    print(f"loaded {len(sessions)} bare-host sessions")

    by_mcp: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_mcp[s["meta"]["mcp"]].append(s)

    rng = random.Random(args.seed)
    rows = []
    for t in range(args.n_trials):
        mcps = list(by_mcp.keys())
        if len(mcps) < args.n_sessions:
            print(f"trial {t}: not enough distinct MCPs")
            continue
        chosen_mcps = rng.sample(mcps, args.n_sessions)
        chosen = [rng.choice(by_mcp[m]) for m in chosen_mcps]
        db_path = KUZU_DIR / f"v3_kuzu_t{t}.kz"
        row = run_trial(chosen, args.n_sessions, db_path, args.threshold)
        row.update({"trial": t, "mcps": chosen_mcps})
        rows.append(row)
        print(f"trial {t}: examined={row['n_pids_examined']} demoted={row['n_pids_demoted']}")
        for cfg in ("baseline", "cohesion"):
            s = row[cfg]
            print(f"  {cfg:9s}: sess F1={s['session']['f1']:.3f} "
                  f"mcp F1={s['mcp']['f1']:.3f} "
                  f"tc F1={s['tool_call']['f1']:.3f}")

    (RESULTS / "v3_kuzu.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def agg(key: str):
        out = {"n_trials": len(rows)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[key][level]["f1"] for r in rows if r[key][level]["f1"] is not None]
            ps = [r[key][level]["precision"] for r in rows if r[key][level]["precision"] is not None]
            rs = [r[key][level]["recall"] for r in rows if r[key][level]["recall"] is not None]
            ars = [r[key][level]["ari"] for r in rows]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = {"baseline": agg("baseline"), "cohesion": agg("cohesion"),
               "threshold": args.threshold}
    (RESULTS / "v3_kuzu_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
