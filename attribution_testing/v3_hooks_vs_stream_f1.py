"""Compare stream-mode vs. hooks-mode tool-call attribution as F1
against the SAME ground truth — namely, hook-anchored tool-call
windows.

Why hook-anchored ground truth: stream-derived ground truth (what
Phase 5 used) inherits stream's loose timing for built-in tools,
which is the same imprecision that hurts the predictor. Comparing
two stream-derived numbers obscures whether the gap is a predictor
bug or a ground-truth bug. Hook-anchored windows are precise by
construction (PreToolUse and PostToolUse fire at definitive
boundaries), so using them as ground truth gives a fair test of
each mode's predictor.

Per-trial flow:
  1. Pick N hook-enabled V3 sessions; merge their host events.
  2. Build the graph in `mode` (stream or hooks).
  3. For each kernel event in the merged trace, derive:
       - true_tool_call: which tool call's hook-anchored window
         contains this event (and event's pid is in MCP subtree
         for non-built-in OR in agent's session subtree for
         built-in). Otherwise "" (not in any tool call).
       - pred_tool_call: what the predictor (= the graph's
         ToolCall vertices and their windows) attributes to this
         event under `mode`'s window definitions.
  4. Compute per-event precision / recall / F1.

We score session, MCP, and tool-call levels for completeness, but
the headline number is tool-call F1 — that's where hooks have
something new to contribute.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

from common import parse_v1_jsonl
from agent_layer import extract_agent_layer_dispatch
from agent_layer_hooks import hooks_available_for_session
from e6_merged_attribution import (
    MergedEvent, _source_subtrees, _stream_tool_windows,
    _pr_f1, adjusted_rand_index,
)
from graph_builder import build_graph_with_agent_layer
from kuzu_attribution import attribute_events_by_query

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
RESULTS = Path(__file__).parent / "results"


def load_session(sess_dir: Path) -> dict:
    return {
        "dir": sess_dir,
        "meta": json.loads((sess_dir / "session.json").read_text()),
        "l3": parse_v1_jsonl(sess_dir / "l3.jsonl"),
    }


def hook_anchored_tool_windows(sess: dict, session_id_in_graph: str
                                ) -> list[tuple[int, int, str, str]]:
    """For one session, return [(t_open, t_close, tool_use_id, mcp_id_or_'')]
    from its hook-anchored agent-layer extraction. Used as ground truth.
    """
    ext = extract_agent_layer_dispatch(
        sess["dir"], session_id_in_graph,
        sess["meta"]["t_start_unix_ns"],
        sess["meta"]["t_end_unix_ns"],
        mode="hooks",
    )
    out = []
    for tc in ext.tool_calls:
        if tc.t_open_ns > 0 and tc.t_close_ns > 0:
            out.append((tc.t_open_ns, tc.t_close_ns,
                          tc.tool_call_id, tc.mcp_id))
    return out


def merge_with_hook_truth(sessions: list, n_sessions: int
                           ) -> list[MergedEvent]:
    """Merge N sessions; ground-truth labels come from hook-anchored
    windows (more reliable than stream-jsonl windows)."""
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
        # Hook-anchored windows for ground-truth tool-call labeling
        windows = hook_anchored_tool_windows(s, sid)
        for e in events:
            ev = dict(e)
            ev["cgroup_id"] = SHARED
            ts = ev.get("ts_ns", 0)
            pid = ev.get("pid")
            in_session = pid in session_pids
            in_mcp = pid in mcp_pids
            tc_id = ""
            # Attribute to a tool call only if pid is in an MCP subtree
            # (for non-built-in calls) — built-ins fire from claude
            # itself, so we attribute via session membership for those.
            if in_session:
                for lo, hi, tu, mid in windows:
                    if lo <= ts <= hi:
                        # If this window is for an MCP call, only
                        # attribute pids inside the MCP subtree.
                        if mid and not in_mcp:
                            continue
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


def run_trial(sessions: list, n_sessions: int, mode: str,
                db_path: Path) -> dict:
    merged = merge_with_hook_truth(sessions, n_sessions)
    # Use the agent-layer-bearing builder; it picks tool-call windows
    # based on `mode`.
    sess0 = sessions[0]
    builder = build_graph_with_agent_layer(
        [m.event for m in merged], db_path,
        session_dir=sess0["dir"],
        session_id_in_graph="sess_0",
        t_start_ns=sess0["meta"]["t_start_unix_ns"],
        t_end_ns=sess0["meta"]["t_end_unix_ns"],
        extractor_mode=mode,
    )
    preds = attribute_events_by_query(builder, merged)
    return {"n_events": len(merged), **score(merged, preds)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures_hooks")
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    cap_dir = Path(args.captures_dir)
    sess_dirs = sorted([p for p in cap_dir.iterdir()
                          if p.is_dir() and (p / "session.json").exists()])
    sessions = [load_session(sd) for sd in sess_dirs]
    sessions = [s for s in sessions if s["l3"]
                  and hooks_available_for_session(s["dir"])]
    print(f"loaded {len(sessions)} hook-enabled sessions")

    by_mcp: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_mcp[s["meta"]["mcp"]].append(s)

    rng = random.Random(args.seed)
    rows = []
    KUZU_DIR.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)

    for cfg, mode in (("STREAM", "stream"), ("HOOKS", "hooks")):
        rng = random.Random(args.seed)
        for t in range(args.n_trials):
            mcps = list(by_mcp.keys())
            if len(mcps) < args.n_sessions:
                continue
            chosen_mcps = rng.sample(mcps, args.n_sessions)
            chosen = [rng.choice(by_mcp[m]) for m in chosen_mcps]
            db = KUZU_DIR / f"hf_{cfg}_t{t}.kz"
            row = run_trial(chosen, args.n_sessions, mode, db)
            row.update({"cfg": cfg, "trial": t,
                        "mcps": chosen_mcps})
            rows.append(row)
            print(f"{cfg:6s} trial {t}: "
                  f"sess F1={row['session']['f1']:.3f} "
                  f"mcp F1={row['mcp']['f1']:.3f} "
                  f"tc F1={row['tool_call']['f1']:.3f}")

    (RESULTS / "phase6a_f1.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )

    def agg(cfg):
        sub = [r for r in rows if r["cfg"] == cfg]
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

    summary = {"STREAM": agg("STREAM"), "HOOKS": agg("HOOKS")}
    (RESULTS / "phase6a_f1_summary.json").write_text(
        json.dumps(summary, indent=2)
    )
    print()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
