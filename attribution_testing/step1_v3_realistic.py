"""Step 1 (V3 variant): measure deployment-realistic MCP attribution
on bare-host captures with layer 2 disabled.

Mirrors step1_realistic_mcp_baseline.py but operates on V3 captures
(filesystem/memory/git MCPs, no Docker, no `claude mcp add` call).
This is the test that should expose any real lift layer 2 was
providing — V3's MCPs all match the broadened-regex (mcp-server-*)
but the bare-host trace has very different surrounding noise than
the corpus.
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

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)
RESULTS = Path(__file__).parent / "results"


def load_v3_session(sess_dir: Path) -> dict:
    meta = json.loads((sess_dir / "session.json").read_text())
    return {
        "meta": meta,
        "l3": parse_v1_jsonl(sess_dir / "l3.jsonl"),
        "session_dir": sess_dir,
    }


def merge_v3_sessions(sessions: list, n_sessions: int,
                        enable_claude_mcp_add: bool) -> list[MergedEvent]:
    SHARED = 999_999
    merged: list[MergedEvent] = []
    for s in sessions[:n_sessions]:
        events = s["l3"]
        sid = s["meta"]["session_id"]
        mcp_label = s["meta"]["mcp"]
        session_pids, mcp_subtrees = _source_subtrees(
            events, enable_claude_mcp_add=enable_claude_mcp_add,
        )
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


def score(merged, preds):
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


def run_trial(sessions, n_sessions, db_path, enable_claude_mcp_add):
    merged = merge_v3_sessions(sessions, n_sessions, enable_claude_mcp_add)
    builder = build_graph(merged, db_path,
                            enable_claude_mcp_add=enable_claude_mcp_add)
    preds = attribute_events_by_query(builder, merged)
    return {"n_events": len(merged), **score(merged, preds)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures")
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cap_root = Path(args.captures_dir)
    sess_dirs = sorted([p for p in cap_root.iterdir() if p.is_dir()])
    sessions = [load_v3_session(sd) for sd in sess_dirs]
    sessions = [s for s in sessions if s["l3"]]

    by_mcp: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_mcp[s["meta"]["mcp"]].append(s)

    rows = []
    for cfg_name, enable in (("WITH_MCP_ADD", True),
                                ("NO_MCP_ADD", False)):
        rng = random.Random(args.seed)
        for t in range(args.n_trials):
            mcps = list(by_mcp.keys())
            if len(mcps) < args.n_sessions:
                continue
            chosen_mcps = rng.sample(mcps, args.n_sessions)
            chosen = [rng.choice(by_mcp[m]) for m in chosen_mcps]
            db_path = KUZU_DIR / f"step1v3_{cfg_name}_t{t}.kz"
            row = run_trial(chosen, args.n_sessions, db_path, enable)
            row.update({"cfg": cfg_name, "trial": t,
                        "mcps": chosen_mcps})
            rows.append(row)
            print(f"{cfg_name} trial {t}: "
                  f"sess F1={row['session']['f1']:.3f} "
                  f"mcp F1={row['mcp']['f1']:.3f} "
                  f"tc F1={row['tool_call']['f1']:.3f}")

    (RESULTS / "step1_v3.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )

    def agg(cfg_name):
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
    (RESULTS / "step1_v3_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
