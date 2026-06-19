"""Compare stream-mode vs. hooks-mode agent-layer attribution.

Builds two Kuzu graphs from each fresh V3 capture (one per
extractor mode), then for each ToolCall counts how many kernel
events (file reads/writes/connects) fall inside its [t_open_ns,
t_close_ns] window. Reports both per-call event counts and total
events attributed.

Hooks-mode is expected to lift per-tool-call kernel attribution
because:
  - Built-in tool boundaries become precise (PreToolUse/PostToolUse
    are fixed wall-clock points, vs. the loose stream-jsonl ts
    fallback the stream extractor uses).
  - Concurrent calls into the same MCP get their own t_open/t_close
    with distinct tool_use_ids.

This script scores both and prints the per-call differences.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from common import parse_v1_jsonl
from graph_builder import build_graph_with_agent_layer

KUZU_DIR = Path(__file__).parent / "kuzu_graphs"


def load_session(sd: Path) -> dict:
    return {
        "dir": sd,
        "meta": json.loads((sd / "session.json").read_text()),
        "l3": parse_v1_jsonl(sd / "l3.jsonl"),
    }


def build_and_summarize(sess: dict, mode: str) -> dict:
    """Build a Kuzu graph in `mode`, return per-tool-call event counts.

    Counts: file reads/writes/unlinks, socket connects/sends — anything
    in any session-bound process whose ts falls in the ToolCall's
    [t_open_ns, t_close_ns] window.
    """
    db = KUZU_DIR / f"compare_{sess['dir'].name}_{mode}.kz"
    b = build_graph_with_agent_layer(
        sess["l3"], db,
        session_dir=sess["dir"],
        session_id_in_graph="sess_0",
        t_start_ns=sess["meta"]["t_start_unix_ns"],
        t_end_ns=sess["meta"]["t_end_unix_ns"],
        extractor_mode=mode,
    )

    out = {"mode": mode, "session": sess["dir"].name, "tool_calls": []}

    # All ToolCalls with their windows
    res = b.conn.execute("""
        MATCH (tc:ToolCall)
        RETURN tc.tool_call_id, tc.name, tc.is_builtin, tc.kernel_timing,
               tc.t_open_ns, tc.t_close_ns
        ORDER BY tc.t_open_ns
    """)
    rows = []
    while res.has_next():
        rows.append(res.get_next())

    # For each ToolCall, count events in its window. We restrict to
    # events whose pid is bound to the session.
    for row in rows:
        tcid, name, is_builtin, timing, t_open, t_close = row
        if t_close <= 0 or t_open <= 0 or t_close < t_open:
            attributed = None
        else:
            count_q = """
                MATCH (p:Process)-[:member_of_session]->(s:Session)
                MATCH (p)-[r]->(x)
                WHERE label(r) IN ['read','write','unlink','connect','send','recv']
                  AND r.ts_ns >= $lo AND r.ts_ns <= $hi
                RETURN count(r)
            """
            try:
                cr = b.conn.execute(count_q, {"lo": t_open, "hi": t_close})
                attributed = cr.get_next()[0]
            except Exception:
                attributed = -1
        out["tool_calls"].append({
            "name": name,
            "is_builtin": is_builtin,
            "timing": timing,
            "t_open": t_open,
            "t_close": t_close,
            "duration_ms": (t_close - t_open) / 1e6 if (t_close > 0 and t_open > 0) else None,
            "attributed_events": attributed,
        })

    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="v3_captures_hooks")
    args = ap.parse_args()

    cap_dir = Path(args.captures_dir)
    KUZU_DIR.mkdir(exist_ok=True)

    rows = []
    for sd in sorted(cap_dir.iterdir()):
        if not sd.is_dir():
            continue
        if not (sd / "session.json").exists():
            continue
        sess = load_session(sd)
        for mode in ("stream", "hooks"):
            row = build_and_summarize(sess, mode)
            rows.append(row)
            print(f"[{mode:6s}] {sd.name}")
            for tc in row["tool_calls"]:
                dur = tc["duration_ms"]
                dur_s = f"{dur:.0f}ms" if dur is not None else "n/a"
                ae = tc["attributed_events"]
                ae_s = str(ae) if ae is not None else "n/a"
                print(f"  {tc['name']:35s} builtin={tc['is_builtin']!s:5s} "
                      f"timing={tc['timing']:11s} dur={dur_s:>7s} "
                      f"events_in_window={ae_s}")

    out_path = Path("results") / "hooks_vs_stream.jsonl"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"\nwrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
