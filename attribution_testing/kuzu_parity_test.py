"""Parity test: Kuzu-backed attribution should produce identical
predictions to e6_merged_attribution.predict() on the same merged
trace.

For each of N trials, build the Kuzu graph, query attribution from
the graph, and compare against the in-memory predict() output. Any
divergence means the graph is missing information the in-memory
predictor uses.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter
from pathlib import Path

from common import find_sessions, load_session
from e6_merged_attribution import (
    merge_sessions, predict, pick_distinct_mcp_sessions, _pr_f1,
    adjusted_rand_index,
)
from kuzu_attribution import build_and_attribute

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)


def compare_preds(in_mem: list[dict], kuzu_preds: list[dict]) -> dict:
    """Three counters per level: matches, in-mem-but-kuzu-empty, mismatches."""
    out = {}
    for level in ("session", "mcp", "tool_call"):
        match = mismatch = mem_only = kuzu_only = 0
        for a, b in zip(in_mem, kuzu_preds):
            av, bv = a[level], b[level]
            if av == bv:
                match += 1
            elif av and not bv:
                mem_only += 1
            elif bv and not av:
                kuzu_only += 1
            else:
                mismatch += 1
        out[level] = {
            "match": match, "mismatch": mismatch,
            "mem_only": mem_only, "kuzu_only": kuzu_only,
            "agreement_pct": match / max(1, len(in_mem)),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-trials", type=int, default=3)
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
        for layer in ("l3",):
            merged = merge_sessions(chosen, layer)
            in_mem = predict(merged)
            db_path = KUZU_DIR / f"parity_t{t}_{layer}.kz"
            kuzu_preds, _builder = build_and_attribute(merged, db_path)
            cmp = compare_preds(in_mem, kuzu_preds)
            row = {
                "trial": t, "layer": layer,
                "n_events": len(merged),
                "compare": cmp,
            }
            rows.append(row)
            print(f"trial {t} {layer}: n={len(merged)}")
            for level, c in cmp.items():
                print(f"  {level}: agreement={c['agreement_pct']:.4f} "
                      f"match={c['match']} mismatch={c['mismatch']} "
                      f"mem_only={c['mem_only']} kuzu_only={c['kuzu_only']}")

    out = Path(__file__).parent / "results" / "kuzu_parity.jsonl"
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


if __name__ == "__main__":
    main()
