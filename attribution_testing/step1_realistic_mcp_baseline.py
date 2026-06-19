"""Step 1: Measure deployment-realistic MCP attribution baseline.

The original layered detector hits MCP F1 = 1.0 on the corpus partly
because it uses `claude mcp add` registration calls — these are
captured artifacts that don't exist in real deployments. To
estimate what AgentShield would actually achieve in the field, we
disable layer 2 and run with structural + broadened-regex only.

Both the predictor AND ground-truth construction get the same
toggle, since `_source_subtrees` ALSO uses the layered detector to
decide what's an MCP. (If we left ground truth using layer 2 but
disabled it in the predictor, ground truth would have MCP labels
the predictor cannot reach by construction — comparing them would
measure a definitional mismatch, not an attribution gap.)

Compares two configurations on the same E6 trials:
- WITH_MCP_ADD: layer 2 enabled (corpus-realistic baseline)
- NO_MCP_ADD:   layer 2 disabled (deployment-realistic baseline)
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
from graph_builder import build_graph
from kuzu_attribution import attribute_events_by_query

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)
RESULTS = Path(__file__).parent / "results"


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


def run_trial(sessions: list, layer: str, db_path: Path,
                enable_claude_mcp_add: bool) -> dict:
    merged = merge_sessions(sessions, layer,
                              enable_claude_mcp_add=enable_claude_mcp_add)
    builder = build_graph(merged, db_path,
                            enable_claude_mcp_add=enable_claude_mcp_add)
    preds = attribute_events_by_query(builder, merged)
    return {"n_events": len(merged), **score(merged, preds)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    pool = find_sessions(limit=args.limit)
    rng_with = random.Random(args.seed)
    rng_without = random.Random(args.seed)

    rows = []
    for cfg_name, enable in (("WITH_MCP_ADD", True),
                                ("NO_MCP_ADD", False)):
        rng = random.Random(args.seed)  # same trial draws either way
        for t in range(args.n_trials):
            chosen_dirs = pick_distinct_mcp_sessions(pool, args.n_sessions, rng)
            if not chosen_dirs:
                continue
            chosen = [load_session(sd) for sd in chosen_dirs]
            for layer in ("l3",):  # one layer is enough for this comparison
                db_path = KUZU_DIR / f"step1_{cfg_name}_t{t}_{layer}.kz"
                row = run_trial(chosen, layer, db_path, enable)
                row.update({"cfg": cfg_name, "trial": t, "layer": layer,
                            "mcps": [s.meta["mcp"] for s in chosen]})
                rows.append(row)
                print(f"{cfg_name} trial {t}: "
                      f"sess F1={row['session']['f1']:.3f} "
                      f"mcp F1={row['mcp']['f1']:.3f} "
                      f"tc F1={row['tool_call']['f1']:.3f}")

    (RESULTS / "step1.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )

    def agg(cfg_name: str):
        sub = [r for r in rows if r["cfg"] == cfg_name]
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

    summary = {"WITH_MCP_ADD": agg("WITH_MCP_ADD"),
                "NO_MCP_ADD": agg("NO_MCP_ADD")}
    (RESULTS / "step1_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
