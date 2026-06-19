"""E2 — Per-subprocess syscall attribution vs. L1.

For every host_pid bridged to an L1 tid (E1 logic), compare the
host-side syscall counts (filtered to host-observable types) to the L1
counts for the bridged L1 tid.

Per (subprocess, syscall_type) cell:
- L1_count   = how many times tid X invoked syscall Y in L1
- HOST_count = how many times pid X' invoked event Y on the host
- delta_pct  = (HOST - L1) / L1

Aggregate to per-subprocess and per-session metrics.

The expected ordering (from the L1-dominance analysis) is L3 closer to
L1 than L2_ext, since L3's libbpf path has full 256B paths and reliable
clone3 attribution.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from common import find_sessions, load_session
from e1_process_forest import execve_subjects, bridge_execve, HOST_OBSERVABLE

RESULTS = Path(__file__).parent / "results"


def per_session(s) -> dict:
    if not s.l1:
        return {"session": s.session_dir.name, "skip": "no_l1"}

    l1_sub = execve_subjects(s.l1, "l1")

    out: dict = {
        "session": s.session_dir.name,
        "mcp": s.meta.get("mcp"),
        "variant": s.meta.get("variant"),
    }

    # Build per-tid syscall counts for L1 (restricted to host-observable)
    l1_counts: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in s.l1:
        if e["syscall"] in HOST_OBSERVABLE:
            l1_counts[e["pid"]][e["syscall"]] += 1

    for layer_name, events in (("l2ext", s.l2ext), ("l3", s.l3)):
        if not events:
            out[layer_name] = {"skip": "no_events"}
            continue

        host_sub = execve_subjects(events, "host")
        bridge = bridge_execve(l1_sub, host_sub)

        # Per host_pid: gather counts of each event, but restricted to
        # the bridged subprocess identity. We attribute every event with
        # pid==hpid; threads of the same process show up under the same
        # tgid so this gives "per-subprocess" aggregation.
        host_counts: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for e in events:
            pid = e.get("pid")
            ev = e.get("event")
            if pid is None or not ev:
                continue
            host_counts[pid][ev] += 1

        # For each bridged subprocess, compare counts.
        per_proc = []
        for hpid, ltid in bridge.items():
            l1c = dict(l1_counts.get(ltid, {}))
            # L1 also picks up threads (they share tgid in host but
            # appear as separate tids in L1). Sum L1 counts for *all*
            # L1 tids whose execve fingerprint we matched to this hpid
            # (only one per bridge entry by construction); plus any L1
            # tid that the L1 forest says has ltid as ppid via a
            # CLONE_THREAD edge.
            hc = dict(host_counts.get(hpid, {}))
            keys = set(l1c) | set(hc)
            cell = {
                "host_pid": hpid,
                "l1_tid": ltid,
                "by_event": {
                    k: {
                        "l1": l1c.get(k, 0),
                        "host": hc.get(k, 0),
                        "delta": hc.get(k, 0) - l1c.get(k, 0),
                    }
                    for k in keys
                },
            }
            per_proc.append(cell)

        # Aggregate per-event ratios across all bridged subprocesses
        agg: dict[str, dict[str, int]] = defaultdict(lambda: {"l1": 0, "host": 0})
        for cell in per_proc:
            for ev, v in cell["by_event"].items():
                agg[ev]["l1"] += v["l1"]
                agg[ev]["host"] += v["host"]
        per_event_ratio = {
            ev: {
                "l1": v["l1"], "host": v["host"],
                "ratio": (v["host"] / v["l1"]) if v["l1"] else None,
            }
            for ev, v in agg.items()
        }

        out[layer_name] = {
            "n_bridged_subprocesses": len(bridge),
            "per_event_ratio": per_event_ratio,
        }
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    sessions = find_sessions(limit=args.limit)
    print(f"E2 over {len(sessions)} sessions")
    rows = []
    for i, sd in enumerate(sessions):
        try:
            s = load_session(sd)
            rows.append(per_session(s))
            if (i + 1) % 10 == 0:
                print(f"  {i+1}/{len(sessions)}")
        except Exception as e:
            rows.append({"session": sd.name, "error": str(e)})

    (RESULTS / "e2.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    # aggregate per-event across the corpus, per layer
    def agg(layer: str):
        ev_l1 = defaultdict(int)
        ev_host = defaultdict(int)
        n_bridged = 0
        n_sessions = 0
        for r in rows:
            d = r.get(layer)
            if not isinstance(d, dict) or "per_event_ratio" not in d:
                continue
            n_sessions += 1
            n_bridged += d.get("n_bridged_subprocesses", 0)
            for ev, v in d["per_event_ratio"].items():
                ev_l1[ev] += v["l1"]
                ev_host[ev] += v["host"]
        return {
            "n_sessions": n_sessions,
            "total_bridged_subprocesses": n_bridged,
            "by_event": {
                ev: {
                    "l1_total": ev_l1[ev],
                    "host_total": ev_host[ev],
                    "host_over_l1": (ev_host[ev] / ev_l1[ev]) if ev_l1[ev] else None,
                }
                for ev in sorted(set(ev_l1) | set(ev_host))
            },
        }

    summary = {"l2ext": agg("l2ext"), "l3": agg("l3")}
    (RESULTS / "e2_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
