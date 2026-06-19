"""E3 — Session partitioning without cgroup-per-session.

In our pipeline each session gets its own container so cgroup_id partitions
sessions for free. In a real deployment that property doesn't hold:
agents can run bare on the host, or one container can serve many
sessions. So if AgentShield can't lean on cgroup_id, what *can* it use?

Two candidate strategies, scored against ground-truth session ids:

1. **agent_root**: each `execve` of `/usr/local/bin/claude` (or any
   "claude" basename argv0) marks a new session root. All descendants
   reachable via clone/execve edges in the host forest before the next
   such execve belong to that session.

2. **claude_pid_subtree**: same as (1) but uses pid subtree closure
   over the entire trace, ignoring time windows. (Should fail when
   sessions reuse the agent.)

Stress condition synthesized from existing data: we *concatenate* N
sessions' host-side traces into a single combined trace, simulating
multiple sessions sharing a host. Ground truth is the per-event
session_id label.

Metric: Adjusted Rand Index between predicted partitioning and the
ground-truth labels, computed at the event level (every host event
gets a predicted session id and a true session id).
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from common import find_sessions, load_session, parse_v1_jsonl

RESULTS = Path(__file__).parent / "results"


def adjusted_rand_index(true_labels: list, pred_labels: list) -> float:
    """Adjusted Rand Index — chance-corrected clustering agreement.

    Implementation per Hubert & Arabie (1985). Returns 1.0 for perfect
    agreement, 0.0 for chance.
    """
    from collections import Counter
    from math import comb
    if not true_labels or len(true_labels) != len(pred_labels):
        return 0.0
    n = len(true_labels)
    # contingency
    cont: dict[tuple, int] = Counter(zip(true_labels, pred_labels))
    a: dict = Counter(true_labels)
    b: dict = Counter(pred_labels)

    sum_comb_c = sum(comb(v, 2) for v in cont.values())
    sum_comb_a = sum(comb(v, 2) for v in a.values())
    sum_comb_b = sum(comb(v, 2) for v in b.values())
    expected = sum_comb_a * sum_comb_b / comb(n, 2) if n >= 2 else 0
    max_index = (sum_comb_a + sum_comb_b) / 2
    if max_index == expected:
        return 1.0
    return (sum_comb_c - expected) / (max_index - expected)


def partition_agent_root(events: list[dict]) -> dict[int, str]:
    """Strategy 1: each `execve` of claude marks a new session start.

    Returns a list of predicted session ids parallel to `events`.
    Implemented as event-index → session_id map for clarity.
    """
    # Walk events in ts order. Each "claude" execve opens a new session.
    # An event belongs to the session of its pid; a pid belongs to the
    # session of the most recent claude_root that is its ancestor (via
    # clone/execve edges).
    pred: dict[int, str] = {}  # event_index → session_id

    # Build child→parent and pid→session_root maps as we walk
    parent_of: dict[int, int] = {}
    session_of: dict[int, str] = {}
    next_sid = 0

    sorted_idx = sorted(range(len(events)), key=lambda i: events[i].get("ts_ns", 0))
    last_clone_caller = None

    for idx in sorted_idx:
        e = events[idx]
        ev = e.get("event")
        pid = e.get("pid")
        if pid is None:
            pred[idx] = "unknown"
            continue

        if ev == "execve":
            args = e.get("args") or {}
            argv = args.get("argv") or []
            argv0 = (argv[0] if argv else "") or args.get("path", "")
            base = argv0.rsplit("/", 1)[-1]
            if base == "claude" and "-p" in argv:
                # New session root — only when claude is invoked with -p
                # (the dataset's per-session invocation marker)
                sid = f"session_{next_sid}"
                next_sid += 1
                session_of[pid] = sid
        elif ev in ("clone", "clone3"):
            last_clone_caller = pid

        # Inherit session from caller if not yet labeled
        if pid not in session_of:
            # Try to inherit from last clone caller
            if last_clone_caller is not None and last_clone_caller in session_of:
                session_of[pid] = session_of[last_clone_caller]
            else:
                # Fall back to "unassigned" until claude is seen
                session_of[pid] = "preroot"

        pred[idx] = session_of[pid]

    return pred


def partition_cgroup(events: list[dict]) -> dict[int, str]:
    """Baseline: partition by cgroup_id."""
    return {i: f"cgroup_{e.get('cgroup_id', 'none')}"
            for i, e in enumerate(events)}


def stress_concat(sessions: list, layer: str = "l3") -> tuple[list[dict], list[str]]:
    """Concatenate N sessions' host-side events; return events + true labels.

    Re-stamps cgroup_id of all sessions to the *same* value, simulating
    a deployment where one container hosts many sessions. ts_ns is left
    alone — the original capture was already temporally separated, so
    we synthetically interleave by sorting on ts after concat.
    """
    combined: list[dict] = []
    labels: list[str] = []
    SHARED_CGROUP = 999999
    for s in sessions:
        events = s.l3 if layer == "l3" else s.l2ext
        sid = s.meta.get("session_id", s.session_dir.name)
        for e in events:
            e2 = dict(e)
            e2["cgroup_id"] = SHARED_CGROUP
            combined.append(e2)
            labels.append(sid)
    # Re-sort by ts_ns (interleaves sessions; preserves stress)
    order = sorted(range(len(combined)), key=lambda i: combined[i].get("ts_ns", 0))
    combined = [combined[i] for i in order]
    labels = [labels[i] for i in order]
    return combined, labels


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-sessions", type=int, default=5,
                    help="how many real sessions to concatenate per stress trial")
    ap.add_argument("--n-trials", type=int, default=5)
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()

    pool = find_sessions(limit=args.limit)
    random.seed(42)

    trials = []
    for t in range(args.n_trials):
        chosen_dirs = random.sample(pool, args.n_sessions)
        chosen = [load_session(sd) for sd in chosen_dirs]
        for layer in ("l2ext", "l3"):
            events, true_labels = stress_concat(chosen, layer=layer)
            if not events:
                continue
            cg_pred = partition_cgroup(events)
            cg_pred_list = [cg_pred[i] for i in range(len(events))]
            ar_pred = partition_agent_root(events)
            ar_pred_list = [ar_pred[i] for i in range(len(events))]
            trials.append({
                "trial": t,
                "layer": layer,
                "n_sessions_concat": len(chosen),
                "n_events": len(events),
                "ari_cgroup_baseline": adjusted_rand_index(true_labels, cg_pred_list),
                "ari_agent_root": adjusted_rand_index(true_labels, ar_pred_list),
                "n_sessions_recovered_by_agent_root": len(set(ar_pred_list)),
            })

    (RESULTS / "e3.jsonl").write_text("\n".join(json.dumps(r) for r in trials) + "\n")

    # Aggregate
    def mean(xs): return sum(xs)/len(xs) if xs else 0
    summary = {}
    for layer in ("l2ext", "l3"):
        sub = [t for t in trials if t["layer"] == layer]
        summary[layer] = {
            "n_trials": len(sub),
            "ari_cgroup_baseline_mean": mean([t["ari_cgroup_baseline"] for t in sub]),
            "ari_agent_root_mean": mean([t["ari_agent_root"] for t in sub]),
            "ari_agent_root_min": min((t["ari_agent_root"] for t in sub), default=None),
            "ari_agent_root_max": max((t["ari_agent_root"] for t in sub), default=None),
        }
    (RESULTS / "e3_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
