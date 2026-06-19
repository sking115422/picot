"""E1 — Process forest recovery vs. L1.

We compare the host-side process forest (built from L2_ext or L3 v1
envelope events) against the in-container L1 strace forest.

L1 emits one record per (tid, syscall); the leftmost field of strace
output is *tid*, not pid. Host eBPF emits both pid (tgid) and tid.
Across namespaces, pids/tids don't match by value — we bridge them by
matching execve events on `ts_ns` + `argv[0]`.

Two different recall axes, each meaningful:

A. **Subprocess recall** — distinct execve subjects (a "subprocess"
   is a pid that runs execve). Closest to "what AgentShield can
   attribute as a process node."
B. **Thread recall** — distinct tids that emit at least one
   host-observable syscall (openat/connect/sendto/...). Threads
   created by clone(CLONE_THREAD) never execve, so the bridge falls
   back to first-syscall-ts matching here.

Edge recall is reported on the **subprocess graph** (parent execve →
child execve) since that's the level any host sensor can reconstruct.

Outputs:
- results/e1.jsonl              one row per session
- results/e1_summary.json       aggregate metrics
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from common import (
    find_sessions, load_session, build_host_forest, build_l1_forest,
)

RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)

HOST_OBSERVABLE = {
    "openat", "open", "connect", "sendto", "recvfrom",
    "execve", "clone", "clone3", "unlinkat", "unlink",
    "exit_group", "bind", "ptrace",
}


def execve_subjects(events: list[dict], src: str) -> dict[int, dict]:
    """Map pid → {ts, argv0, argv} for each pid that ran execve.

    `src` is "l1" or "host" — different schema.
    """
    out: dict[int, dict] = {}
    if src == "l1":
        import re
        for e in events:
            if e["syscall"] != "execve":
                continue
            m = re.match(r'"([^"]*)"\s*,\s*\[(.*?)\]', e["args_raw"], re.S)
            argv: list[str] = []
            argv0 = ""
            if m:
                argv0 = m.group(1)
                argv = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
            # First execve wins; subsequent execve in same pid would
            # replace the image but we keep the first observed argv.
            if e["pid"] not in out:
                out[e["pid"]] = {"ts": e["ts_ns"], "argv0": argv0, "argv": argv}
    else:
        for e in events:
            if e.get("event") != "execve":
                continue
            args = e.get("args", {}) or {}
            if e["pid"] not in out:
                out[e["pid"]] = {
                    "ts": e["ts_ns"],
                    "argv0": args.get("path", ""),
                    "argv": args.get("argv", []),
                }
    return out


def bridge_execve(l1_subj: dict[int, dict], host_subj: dict[int, dict],
                  tol_ms: int = 100) -> dict[int, int]:
    """Bridge host_pid → l1_tid by execve ts proximity + argv0 match.

    Multiple host pids may map to the same L1 tid only when the L1
    process re-execves — we keep the first match.
    """
    bridge: dict[int, int] = {}
    used: set[int] = set()
    tol_ns = tol_ms * 1_000_000

    # Sort host execves by ts; for each, find the closest unused L1 execve
    # within tolerance whose argv0 basenames match.
    def basename(p: str) -> str:
        return p.rsplit("/", 1)[-1] if p else ""

    for hpid, hinfo in sorted(host_subj.items(), key=lambda kv: kv[1]["ts"]):
        h_base = basename(hinfo["argv0"])
        # also try first argv element if argv0 is a wrapper path
        candidate_bases = {h_base}
        if hinfo["argv"]:
            candidate_bases.add(basename(hinfo["argv"][0]))

        best = None
        best_d = tol_ns + 1
        for ltid, linfo in l1_subj.items():
            if ltid in used:
                continue
            l_base = basename(linfo["argv0"])
            if l_base not in candidate_bases and basename(linfo["argv"][0] if linfo["argv"] else "") not in candidate_bases:
                continue
            d = abs(linfo["ts"] - hinfo["ts"])
            if d < best_d:
                best_d = d
                best = ltid
        if best is not None:
            bridge[hpid] = best
            used.add(best)
    return bridge


def per_session(s) -> dict:
    if not s.l1:
        return {"session": s.session_dir.name, "skip": "no_l1"}
    l1f = build_l1_forest(s.l1)

    # L1 subprocesses (pids that did execve)
    l1_sub = execve_subjects(s.l1, "l1")
    # Tids that emit at least one host-observable syscall
    l1_tids_obs = {
        e["pid"] for e in s.l1 if e["syscall"] in HOST_OBSERVABLE
    }

    out: dict = {
        "session": s.session_dir.name,
        "mcp": s.meta.get("mcp"),
        "variant": s.meta.get("variant"),
        "l1_subprocesses": len(l1_sub),
        "l1_tids_total": len(l1f),
        "l1_tids_observable": len(l1_tids_obs),
    }

    for layer_name, events in (("l2ext", s.l2ext), ("l3", s.l3)):
        if not events:
            out[layer_name] = {"skip": "no_events"}
            continue

        host_sub = execve_subjects(events, "host")
        bridge = bridge_execve(l1_sub, host_sub)
        bridged_l1_tids = set(bridge.values())

        # Edge recall on the subprocess graph
        # L1 subprocess parent edges: walk full forest, but project edges
        # to "the nearest ancestor that is in l1_sub" on each side.
        ancestor_in_sub: dict[int, int] = {}
        for tid in l1f:
            cur = tid
            while cur is not None and cur not in l1_sub:
                cur = l1f.get(cur, None).ppid if l1f.get(cur) else None
            if cur is not None:
                ancestor_in_sub[tid] = cur

        l1_proc_edges: set[tuple[int, int]] = set()
        for tid, node in l1f.items():
            if tid not in l1_sub:
                continue
            ancestor_parent = None
            cur = node.ppid
            while cur is not None:
                if cur in l1_sub:
                    ancestor_parent = cur
                    break
                cur = l1f.get(cur).ppid if cur in l1f else None
            if ancestor_parent is not None:
                l1_proc_edges.add((ancestor_parent, tid))

        # Host subprocess graph (from host forest, restricted to host_sub)
        hf = build_host_forest(events)
        host_proc_edges: set[tuple[int, int]] = set()
        for hpid, hnode in hf.items():
            if hpid not in host_sub:
                continue
            cur = hnode.ppid
            while cur is not None:
                if cur in host_sub:
                    host_proc_edges.add((cur, hpid))
                    break
                cur = hf.get(cur).ppid if cur in hf else None

        # Translate host edges to L1-tid edges via bridge
        translated_host_edges = set()
        for p, c in host_proc_edges:
            if p in bridge and c in bridge:
                translated_host_edges.add((bridge[p], bridge[c]))

        bridged_l1_proc_edges = {
            (p, c) for p, c in l1_proc_edges
            if p in bridged_l1_tids and c in bridged_l1_tids
        }
        edge_recall = (
            len(translated_host_edges & bridged_l1_proc_edges)
            / len(bridged_l1_proc_edges)
        ) if bridged_l1_proc_edges else None

        # Did host see a claude execve at all? At root?
        host_root_argv = []
        for p, n in hf.items():
            if n.argv and (n.ppid is None or n.ppid not in hf):
                host_root_argv.append(n.argv[0])
        host_saw_claude_root = any(
            "claude" in (a or "") for a in host_root_argv
        )
        host_saw_claude_anywhere = any(
            n.argv and n.argv[0] and "claude" in n.argv[0]
            for n in hf.values()
        )

        out[layer_name] = {
            "host_pids_total": len(set(e["pid"] for e in events if "pid" in e)),
            "host_tids_total": len(set(e["tid"] for e in events if "tid" in e)),
            "host_subprocesses": len(host_sub),
            "host_events": len(events),
            "subprocess_recall":
                (len(bridge) / len(l1_sub)) if l1_sub else 0.0,
            "subprocess_count_ratio":
                (len(host_sub) / len(l1_sub)) if l1_sub else 0.0,
            "edge_recall_subprocess_graph": edge_recall,
            "edges_in_l1_subgraph": len(bridged_l1_proc_edges),
            "host_saw_claude_root": host_saw_claude_root,
            "host_saw_claude_anywhere": host_saw_claude_anywhere,
            "host_root_argv0_set": list({a for a in host_root_argv})[:5],
        }
    return out


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = int(p * (len(s) - 1))
    return s[k]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    sessions = find_sessions(limit=args.limit)
    print(f"E1 over {len(sessions)} sessions")
    rows: list[dict] = []
    for i, sd in enumerate(sessions):
        try:
            s = load_session(sd)
            row = per_session(s)
            rows.append(row)
            if (i + 1) % 5 == 0:
                print(f"  {i+1}/{len(sessions)}")
        except Exception as e:
            rows.append({"session": sd.name, "error": str(e)})

    (RESULTS / "e1.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )

    def agg(layer: str):
        ok = [r[layer] for r in rows
              if isinstance(r.get(layer), dict) and "subprocess_recall" in r[layer]]
        if not ok:
            return None
        sr = [r["subprocess_recall"] for r in ok]
        edge = [r["edge_recall_subprocess_graph"] for r in ok if r["edge_recall_subprocess_graph"] is not None]
        return {
            "n": len(ok),
            "subprocess_recall_mean": sum(sr) / len(sr),
            "subprocess_recall_p50": percentile(sr, 0.5),
            "subprocess_recall_p10": percentile(sr, 0.1),
            "edge_recall_mean": (sum(edge)/len(edge)) if edge else None,
            "edge_recall_p50": percentile(edge, 0.5) if edge else None,
            "claude_root_pct": sum(r["host_saw_claude_root"] for r in ok)/len(ok),
            "claude_anywhere_pct": sum(r["host_saw_claude_anywhere"] for r in ok)/len(ok),
        }

    summary = {
        "n_sessions": len(rows),
        "n_with_l1": sum(1 for r in rows if "l1_subprocesses" in r),
        "l2ext": agg("l2ext"),
        "l3": agg("l3"),
    }
    (RESULTS / "e1_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
