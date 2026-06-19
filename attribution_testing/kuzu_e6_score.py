"""Run E6 trials with Kuzu-backed attribution; compare F1/ARI to the
in-memory E6 numbers as a Phase 2 parity check.

Should produce numbers within rounding error of the existing E6
results in results/e6_summary.json. Any divergence is a porting bug.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from common import find_sessions, load_session
from e6_merged_attribution import (
    merge_sessions, _pr_f1, adjusted_rand_index,
    pick_distinct_mcp_sessions,
)
from kuzu_attribution import build_and_attribute

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)
RESULTS = Path(__file__).parent / "results"


def run_trial(sessions: list, layer: str, db_path: Path) -> dict:
    merged = merge_sessions(sessions, layer)
    preds, _builder = build_and_attribute(merged, db_path)

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
            db_path = KUZU_DIR / f"e6_kuzu_t{t}_{layer}.kz"
            row = run_trial(chosen, layer, db_path)
            row.update({"trial": t, "layer": layer,
                        "mcps": [s.meta["mcp"] for s in chosen]})
            rows.append(row)
            print(f"trial {t} {layer}: "
                  f"sess F1={row['session']['f1']:.3f} ARI={row['session']['ari']:.3f}; "
                  f"mcp F1={row['mcp']['f1']:.3f} ARI={row['mcp']['ari']:.3f}; "
                  f"tc F1={row['tool_call']['f1']:.3f} ARI={row['tool_call']['ari']:.3f}")

    (RESULTS / "kuzu_e6.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

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
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = {"l2ext": agg("l2ext"), "l3": agg("l3")}
    (RESULTS / "kuzu_e6_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
