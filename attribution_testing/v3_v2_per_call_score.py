"""V3 v2 per-call scoring against hook-anchored ground truth.

Phase 8 found that per-event tool-call F1 is the wrong shape — most
MCP-server kernel events fall outside any tool-execution window by
definition, and "ground truth" was constructed from the same loose
heuristic the predictor uses.

This scorer is the right shape: per-call. For each ground-truth tool
call (PreToolUse/PostToolUse pair from hook events), did the
predictor produce a ToolCall vertex with the matching tool_use_id?
And does its kernel-timing window cover the actual tool-execution
period?

Two modes are evaluated for the predictor:
  - passive: kernel-only. Existing path; relies on sendto JSON-RPC
    parsing. Does not work for stdio-transport MCPs (most of them).
  - hooks: cooperative. Ingests hook events into ToolCall vertices
    directly. Deterministic — every PreToolUse becomes a ToolCall.

This is run on each source session in isolation (no merging) since
the per-call question is about whether the predictor identifies each
real call, not about disambiguating across sessions.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from common import parse_v1_jsonl
from e6_merged_attribution import _hook_tool_windows
from graph_builder import build_graph_with_agent_layer
from agent_layer_hooks import HOOK_OUT_ROOT, _claude_session_id


RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)
KUZU_DIR = Path(__file__).parent / "kuzu_graphs"
KUZU_DIR.mkdir(exist_ok=True)


class ME:
    """Minimal MergedEvent shim for build_graph."""
    __slots__ = ('event', 'src_session', 'src_mcp', 'src_tool_call')

    def __init__(self, e: dict):
        self.event = e
        self.src_session = ""
        self.src_mcp = ""
        self.src_tool_call = ""


def score_session(session_dir: Path, mode: str, db_path: Path) -> dict:
    """Build a graph for one v2 session, score per-call against hook GT.

    mode: "passive" -> no agent-layer ingest; "hooks" -> ingest hook
    events as ToolCall vertices.
    """
    events = parse_v1_jsonl(session_dir / "l3.jsonl")
    if not events:
        return {"session": session_dir.name, "error": "no events"}

    # Tight GT pairs: PreToolUse/PostToolUse matched by tool_use_id.
    gt = _hook_tool_windows(session_dir)
    # Also: tool_use_ids that fired PreToolUse but had no matching
    # PostToolUse (errored or aborted calls). These are still real
    # tool calls; the GT definition just can't bound the close edge.
    # Count them for identification but exclude from timing coverage.
    gt_ids_paired = {tu for _, _, tu in gt}
    hook_sid = _claude_session_id(session_dir)
    gt_orphan_pre: list[tuple[int, str]] = []
    if hook_sid:
        hp = HOOK_OUT_ROOT / f"{hook_sid}.events.jsonl"
        if hp.exists():
            for line in hp.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                h = ev.get("hook", "")
                tu = ev.get("tool_use_id", "")
                if (h in ("PreToolUse", "preToolUse")
                        and tu and tu not in gt_ids_paired):
                    ts_ns = int(float(ev.get("ts", 0)) * 1_000_000_000)
                    gt_orphan_pre.append((ts_ns, tu))

    merged = [ME(dict(e)) for e in events]

    if db_path.exists():
        if db_path.is_dir():
            shutil.rmtree(db_path)
        else:
            db_path.unlink()
    # Kuzu also creates a sidecar .wal file
    wal = db_path.with_suffix(db_path.suffix + ".wal")
    if wal.exists():
        wal.unlink()

    if mode == "passive":
        # Build the kernel-shape graph with no agent-layer ingest.
        # The predictor's sendto-JSON-RPC mechanism is the only path
        # to a ToolCall vertex.
        from graph_builder import build_graph
        b = build_graph(merged, db_path)
    elif mode == "hooks":
        ts_start = min(e.get("ts_ns", 0) for e in events)
        ts_end = max(e.get("ts_ns", 0) for e in events)
        # The kernel-shape walk opens a Session vertex when it sees
        # an `execve` of claude with -p; ingest_agent_layer expects
        # that session_id. We pass "sess_0" — same convention used
        # elsewhere when there's a single session.
        b = build_graph_with_agent_layer(
            merged, db_path,
            session_dir=session_dir,
            session_id_in_graph="sess_0",
            t_start_ns=ts_start, t_end_ns=ts_end,
            extractor_mode="hooks",
        )
    else:
        raise ValueError(f"unknown mode: {mode}")

    # Pull every ToolCall vertex.
    res = b.conn.execute(
        "MATCH (t:ToolCall) "
        "OPTIONAL MATCH (t)-[:handled_by]->(m:MCP) "
        "RETURN t.tool_call_id, t.t_open_ns, t.t_close_ns, "
        "       coalesce(m.mcp_id, '') AS mid, t.is_builtin"
    )
    pred = []
    while res.has_next():
        tcid, t_open, t_close, mid, is_b = res.get_next()
        pred.append({
            "tool_call_id": tcid,
            "t_open_ns": int(t_open) if t_open else 0,
            "t_close_ns": int(t_close) if t_close else -1,
            "mcp_id": mid,
            "is_builtin": bool(is_b),
        })

    # Match by tool_use_id.
    pred_by_id = {p["tool_call_id"]: p for p in pred}
    gt_all_ids = {tu_id for _, _, tu_id in gt} | {
        tu for _, tu in gt_orphan_pre}

    matched = []
    matched_orphan = []
    missed = []
    for t_pre, t_post, tu_id in gt:
        if tu_id in pred_by_id:
            p = pred_by_id[tu_id]
            t_open = p["t_open_ns"]
            t_close = p["t_close_ns"]
            # "Covers" = predictor window contains the entire hook
            # window. -1 close is treated as open-ended.
            covers_lo = t_open > 0 and t_open <= t_pre
            covers_hi = t_close <= 0 or t_close >= t_post
            covers = covers_lo and covers_hi
            matched.append({
                "tool_use_id": tu_id,
                "gt_t_pre_ns": t_pre,
                "gt_t_post_ns": t_post,
                "pred_t_open_ns": t_open,
                "pred_t_close_ns": t_close,
                "open_gap_ms": (t_pre - t_open) / 1e6 if t_open > 0 else None,
                "close_gap_ms": (t_close - t_post) / 1e6 if t_close > 0 else None,
                "covers": covers,
                "mcp_id": p["mcp_id"],
                "is_builtin": p["is_builtin"],
            })
        else:
            missed.append({
                "tool_use_id": tu_id,
                "gt_t_pre_ns": t_pre,
                "gt_t_post_ns": t_post,
            })

    # Orphan PreToolUse calls: count identification but skip coverage.
    for ts_pre, tu_id in gt_orphan_pre:
        if tu_id in pred_by_id:
            p = pred_by_id[tu_id]
            matched_orphan.append({
                "tool_use_id": tu_id,
                "gt_t_pre_ns": ts_pre,
                "pred_t_open_ns": p["t_open_ns"],
                "pred_t_close_ns": p["t_close_ns"],
                "mcp_id": p["mcp_id"],
                "is_builtin": p["is_builtin"],
            })
        else:
            missed.append({
                "tool_use_id": tu_id,
                "gt_t_pre_ns": ts_pre,
                "gt_t_post_ns": None,
                "orphan_pre": True,
            })

    extra = [p for p in pred if p["tool_call_id"] not in gt_all_ids]

    return {
        "session": session_dir.name,
        "mode": mode,
        "n_gt_paired": len(gt),
        "n_gt_orphan_pre": len(gt_orphan_pre),
        "n_gt_total": len(gt) + len(gt_orphan_pre),
        "n_pred": len(pred),
        "n_matched_paired": len(matched),
        "n_matched_orphan": len(matched_orphan),
        "n_matched_total": len(matched) + len(matched_orphan),
        "n_covers": sum(1 for m in matched if m["covers"]),
        "n_missed": len(missed),
        "n_extra": len(extra),
        "matched": matched,
        "matched_orphan": matched_orphan,
        "missed": missed,
        "extra": extra,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures_v2")
    ap.add_argument("--mode", choices=["passive", "hooks", "both"],
                    default="both",
                    help="passive=kernel-only, hooks=hooks-ingested, "
                         "both=run both modes for comparison")
    ap.add_argument("--out-suffix", default="")
    args = ap.parse_args()

    cap_root = Path(args.captures_dir)
    sess_dirs = sorted(p for p in cap_root.iterdir()
                       if p.is_dir() and (p / "session.json").exists())

    modes = ["passive", "hooks"] if args.mode == "both" else [args.mode]

    all_rows = []
    for mode in modes:
        print(f"\n=== mode: {mode} ===")
        rows = []
        for sd in sess_dirs:
            db = KUZU_DIR / f"per_call_{mode}_{sd.name}.kz"
            row = score_session(sd, mode, db)
            rows.append(row)
            print(
                f"  {sd.name:<35} "
                f"gt={row['n_gt_total']:>2} (paired={row['n_gt_paired']}, "
                f"orphan_pre={row['n_gt_orphan_pre']}) "
                f"pred={row['n_pred']:>2} "
                f"matched={row['n_matched_total']:>2} "
                f"covers={row['n_covers']:>2}/{row['n_matched_paired']} "
                f"missed={row['n_missed']:>2} extra={row['n_extra']:>2}"
            )
        all_rows.extend(rows)

        tot_gt = sum(r["n_gt_total"] for r in rows)
        tot_paired = sum(r["n_gt_paired"] for r in rows)
        tot_matched = sum(r["n_matched_total"] for r in rows)
        tot_matched_paired = sum(r["n_matched_paired"] for r in rows)
        tot_covers = sum(r["n_covers"] for r in rows)
        tot_extra = sum(r["n_extra"] for r in rows)

        ident = tot_matched / tot_gt if tot_gt else 0.0
        cover = (tot_covers / tot_matched_paired
                 if tot_matched_paired else 0.0)
        precision = (tot_matched / (tot_matched + tot_extra)
                     if (tot_matched + tot_extra) else 0.0)

        print()
        print(f"  AGGREGATE ({mode}):")
        print(f"    GT calls:                {tot_gt} "
              f"(paired={tot_paired}, orphan_pre={tot_gt - tot_paired})")
        print(f"    Identified (id-match):   {tot_matched}/{tot_gt} = "
              f"{100*ident:.1f}%  [per-call recall]")
        print(f"    Of paired, covers:       {tot_covers}/{tot_matched_paired} = "
              f"{100*cover:.1f}%  [kernel-timing covers hook window]")
        print(f"    Extra (no GT match):     {tot_extra}  "
              f"[over-attribution]")
        print(f"    Precision on calls:      {100*precision:.1f}%")

    out_path = RESULTS / f"v3_v2_per_call{args.out_suffix}.jsonl"
    out_path.write_text("\n".join(json.dumps(r) for r in all_rows) + "\n")
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
