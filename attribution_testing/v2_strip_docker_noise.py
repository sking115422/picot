"""V2 — Strip Docker/runc/strace noise before merging.

Sanity check on whether the predictor was implicitly leaning on the
Docker/runc preamble pattern as a session-boundary marker. We
identify and drop every event from pids that are part of the
runc -> containerd-shim -> docker-entrypoint -> strace ancestry chain
of each session, before merging. The merged stream then contains
only events from `claude -p` and its descendants.

If F1 stays the same as E6, the pre-claude noise was genuinely
irrelevant to attribution. If F1 drops, the predictor was using
that noise as a temporal boundary signal.

Note: this is a *diagnostic* test, not a deployment-realism test.
A real deployment also has no Docker noise, but it has different
pre-claude noise of its own (sshd fork, env setup, shell startup).
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import defaultdict
from pathlib import Path

from common import find_sessions, load_session
from e6_merged_attribution import (
    MergedEvent, _source_subtrees, _stream_tool_windows,
    predict, _pr_f1, adjusted_rand_index,
    pick_distinct_mcp_sessions,
)

RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


_DOCKER_NOISE_PATTERNS = [
    re.compile(r'^runc(:|$)'),
    re.compile(r'^containerd'),
    re.compile(r'^docker-entrypoint'),
    re.compile(r'^docker-init'),
    re.compile(r'^strace$'),
    re.compile(r'^/?bin/sh$'),
]


def _identify_noise_pids(events: list[dict]) -> set[int]:
    """Return pid set for runc/containerd/docker-entrypoint/strace
    chain. We mark a pid as 'noise' if any of its execve argvs
    matches a noise pattern AND none of its descendants execve into
    `claude`/`mcp-server-*`.

    Approach: walk events in ts order, build child_of map, find
    pids that ever execve into a noise binary. Then find pids that
    ever execve into `claude` (with `-p`) — these are the session
    roots and must NOT be marked as noise.

    A "noise pid" is one whose execve history contains a noise
    pattern AND that is NOT a session root or an MCP root. The
    `claude mcp add` registration call is also noise.
    """
    by_ts = sorted(events, key=lambda e: e.get("ts_ns", 0))
    pid_argvs: dict[int, list[list[str]]] = defaultdict(list)

    for e in by_ts:
        if e.get("event") != "execve":
            continue
        pid = e.get("pid")
        if pid is None:
            continue
        argv = (e.get("args") or {}).get("argv") or []
        pid_argvs[pid].append(argv)

    noise_pids: set[int] = set()
    for pid, argv_list in pid_argvs.items():
        # Skip if any argv looks like the actual session root
        # (claude with -p), or an MCP server execve
        is_session_or_mcp = False
        for argv in argv_list:
            if not argv:
                continue
            base = (argv[0] or "").rsplit("/", 1)[-1].lower()
            if base == "claude" and any(a in ("-p", "--print") for a in argv):
                is_session_or_mcp = True
                break
            if re.match(r"^mcp[-_]server[-_]", base):
                is_session_or_mcp = True
                break
            # node|python|uvx wrapper for MCP
            if base in ("node", "python", "python3", "uv", "uvx") and len(argv) > 1:
                argv1 = (argv[1] or "").rsplit("/", 1)[-1].lower()
                if "mcp" in argv1 and ("server" in argv1 or argv1.startswith("mcp-")):
                    is_session_or_mcp = True
                    break
        if is_session_or_mcp:
            continue

        # Otherwise, mark as noise if any argv matches a noise pattern,
        # OR if argv looks like `claude mcp add ...` (registration call).
        for argv in argv_list:
            if not argv:
                continue
            base = (argv[0] or "").rsplit("/", 1)[-1]
            if any(p.match(base) for p in _DOCKER_NOISE_PATTERNS):
                noise_pids.add(pid)
                break
            if base == "claude" and "mcp" in argv and "add" in argv:
                noise_pids.add(pid)
                break

    return noise_pids


def merge_sessions_strip_noise(sessions: list, layer: str) -> tuple[list[MergedEvent], dict]:
    """Like merge_sessions but drops events from Docker/strace
    ancestry pids before merging."""
    SHARED_CGROUP = 999_999
    merged: list[MergedEvent] = []
    n_dropped = 0
    n_kept = 0
    for s in sessions:
        events = s.l3 if layer == "l3" else s.l2ext
        sid = s.meta.get("session_id", s.session_dir.name)
        mcp_name = s.meta.get("mcp", "")
        windows = _stream_tool_windows(s.session_dir / "stream.jsonl")
        session_pids, mcp_subtrees = _source_subtrees(events)
        mcp_pids: set[int] = set()
        for st in mcp_subtrees.values():
            mcp_pids |= st

        noise_pids = _identify_noise_pids(events)

        for e in events:
            pid = e.get("pid")
            if pid in noise_pids:
                n_dropped += 1
                continue
            n_kept += 1
            ev = dict(e)
            ev["cgroup_id"] = SHARED_CGROUP
            ts = ev.get("ts_ns", 0)
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
                src_mcp=mcp_name if in_mcp else "",
                src_tool_call=tc_id,
            ))
    merged.sort(key=lambda m: m.event.get("ts_ns", 0))
    return merged, {"dropped": n_dropped, "kept": n_kept}


def run_trial(sessions: list, layer: str) -> dict:
    merged, stats = merge_sessions_strip_noise(sessions, layer)
    preds = predict(merged)

    sess_true = [m.src_session for m in merged]
    sess_pred = [p["session"] for p in preds]
    mcp_true = [m.src_mcp for m in merged]
    mcp_pred = [p["mcp"] for p in preds]
    tc_true = [m.src_tool_call for m in merged]
    tc_pred = [p["tool_call"] for p in preds]

    return {
        "n_events": len(merged),
        "events_dropped": stats["dropped"],
        "events_kept": stats["kept"],
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
            row = run_trial(chosen, layer)
            row.update({"trial": t, "layer": layer,
                        "mcps": [s.meta["mcp"] for s in chosen]})
            rows.append(row)
            print(f"trial {t} {layer}: dropped={row['events_dropped']} kept={row['events_kept']} "
                  f"sess F1={row['session']['f1']:.3f}; "
                  f"mcp F1={row['mcp']['f1']:.3f}; "
                  f"tc F1={row['tool_call']['f1']:.3f}")

    (RESULTS / "v2.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def agg(layer: str):
        sub = [r for r in rows if r["layer"] == layer]
        out = {"n_trials": len(sub),
               "total_dropped": sum(r["events_dropped"] for r in sub),
               "total_kept": sum(r["events_kept"] for r in sub)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[level]["f1"] for r in sub if r[level]["f1"] is not None]
            ps = [r[level]["precision"] for r in sub if r[level]["precision"] is not None]
            rs = [r[level]["recall"] for r in sub if r[level]["recall"] is not None]
            ars = [r[level]["ari"] for r in sub]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "f1_min": min(ms) if ms else None,
                "f1_max": max(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
            }
        return out

    summary = {"l2ext": agg("l2ext"), "l3": agg("l3")}
    (RESULTS / "v2_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
