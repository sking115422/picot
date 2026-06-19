"""V3 attribution scoring on v2 captures (sched_fork-aware).

Same as v3_score_kuzu.py but skips the cohesion filter (which the
Phase 3b doc already documented as a null result and which has a
Cypher bug on v2's larger graphs). Just baseline scoring across N
trials of merged-v2-session attribution.

Compares directly to the v1 baseline numbers (V3 with cgroup-gated
clone-window inheritance, no sched_fork). The question this answers:
does adding deterministic parent->child edges from sched_fork lift
session/MCP/tool-call attribution F1 over the v1 timing-window
heuristic?
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from common import parse_v1_jsonl
from e6_merged_attribution import (
    MergedEvent, _source_subtrees, _tool_windows,
    _pr_f1, adjusted_rand_index,
)
from graph_builder import build_graph
from kuzu_attribution import attribute_events_by_query


KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)
RESULTS = Path(__file__).parent / "results"


def load_v3_session(sd: Path) -> dict:
    return {
        "dir": sd,
        "meta": json.loads((sd / "session.json").read_text()),
        "l3": parse_v1_jsonl(sd / "l3.jsonl"),
    }


def merge_v3_sessions(sessions: list, n_sessions: int,
                      windows_pref: str = "auto") -> list[MergedEvent]:
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
        windows, wsrc = _tool_windows(s["dir"], prefer=windows_pref)
        s["_windows_source"] = wsrc
        s["_n_windows"] = len(windows)
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
              windows_pref: str = "auto") -> dict:
    merged = merge_v3_sessions(sessions, n_sessions, windows_pref=windows_pref)
    builder = build_graph(merged, db_path)
    preds = attribute_events_by_query(builder, merged)
    scores = score(merged, preds)
    win_sources = [s.get("_windows_source", "?") for s in sessions[:n_sessions]]
    win_counts = [s.get("_n_windows", 0) for s in sessions[:n_sessions]]
    return {
        "n_events": len(merged),
        "windows_source": win_sources,
        "n_windows": win_counts,
        **scores,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures_v2")
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--windows", choices=["auto", "hooks", "stream"],
                    default="auto",
                    help="ground-truth tool-call window source. "
                         "auto=hooks-if-present-else-stream, "
                         "hooks=tight only, stream=loose only")
    ap.add_argument("--out-suffix", default="",
                    help="suffix for output filenames (e.g. _tight)")
    args = ap.parse_args()

    cap_root = Path(args.captures_dir)
    sess_dirs = sorted(p for p in cap_root.iterdir()
                       if p.is_dir() and (p / "session.json").exists())
    sessions = [load_v3_session(sd) for sd in sess_dirs]
    sessions = [s for s in sessions if s["l3"]]

    by_mcp: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_mcp[s["meta"]["mcp"]].append(s)

    rng = random.Random(args.seed)
    rows = []
    for t in range(args.n_trials):
        mcps = list(by_mcp.keys())
        if len(mcps) < args.n_sessions:
            print(f"trial {t}: not enough distinct MCPs ({len(mcps)})")
            continue
        chosen_mcps = rng.sample(mcps, args.n_sessions)
        chosen = [rng.choice(by_mcp[m]) for m in chosen_mcps]
        db_path = KUZU_DIR / f"v3_v2{args.out_suffix}_t{t}.kz"
        row = run_trial(chosen, args.n_sessions, db_path,
                        windows_pref=args.windows)
        row.update({"trial": t, "mcps": chosen_mcps,
                    "session_dirs": [s["dir"].name for s in chosen]})
        rows.append(row)
        print(f"trial {t}: events={row['n_events']:7d} "
              f"win={row['windows_source']} n={row['n_windows']} | "
              f"sess F1={row['session']['f1']:.3f} P={row['session']['precision']:.3f} R={row['session']['recall']:.3f} | "
              f"mcp F1={row['mcp']['f1']:.3f} | "
              f"tc F1={row['tool_call']['f1']:.3f} P={row['tool_call']['precision']:.3f} R={row['tool_call']['recall']:.3f}")

    (RESULTS / f"v3_v2{args.out_suffix}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n")

    def agg():
        out = {"n_trials": len(rows)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[level]["f1"] for r in rows if r[level]["f1"] is not None]
            ps = [r[level]["precision"] for r in rows if r[level]["precision"] is not None]
            rs = [r[level]["recall"] for r in rows if r[level]["recall"] is not None]
            ars = [r[level]["ari"] for r in rows]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = agg()
    summary["windows_pref"] = args.windows
    (RESULTS / f"v3_v2{args.out_suffix}_summary.json").write_text(
        json.dumps(summary, indent=2))
    print()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
