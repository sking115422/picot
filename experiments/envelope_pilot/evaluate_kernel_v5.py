"""v5 evaluation: v3 attribution filtering + strict write enforcement
against SPECIFIC-BY-CONSTRUCTION envelopes generated with the v5
specificity instruction.

Enforcement compiler:
  - Attribution: only score events belonging to the MCP subtree.
  - Writes: reject any write whose path is not matched by an explicit
    envelope write_paths pattern.
  - Reads: same rules as v1 (read_paths + noise-floor prefixes).
  - No dotfile-in-scratch rule. Strict whitelist for writes.

Comparison target:
  - v3 (attribution, no compiler rule): 33% rejection
  - v4 (attribution + dotfile rule): 78% rejection
  - v5 (attribution + specific envelopes, no rule): ??? — this run
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate import (
    is_noise_read,
    path_matches,
    load_signature_syscalls,
)
from extract_syscalls import iter_session_syscalls
from mcp_subtree import build_subtree_pids


def check_event_v5(event: dict, envelope: dict) -> tuple[bool, str]:
    """Strict-write whitelist: writes require explicit pattern match."""
    ev = event["event"]
    if ev == "openat":
        path = event.get("path") or ""
        if event.get("write_intent"):
            if path_matches(path, envelope.get("file_ops", {}).get("write_paths", [])):
                return True, "write_ok"
            return False, "write_out_of_envelope"
        else:
            if path_matches(path, envelope.get("file_ops", {}).get("read_paths", [])):
                return True, "read_ok"
            return False, "read_out_of_envelope"
    if ev == "unlinkat":
        path = event.get("path") or ""
        if path_matches(path, envelope.get("file_ops", {}).get("delete_paths", [])):
            return True, "unlink_ok"
        return False, "unlink_out_of_envelope"
    if ev == "execve":
        path = event.get("path") or ""
        binaries = envelope.get("process", {}).get("allow_binaries", []) or []
        basename = path.rsplit("/", 1)[-1]
        if not envelope.get("process", {}).get("allow_spawn"):
            return False, "execve_denied_no_spawn"
        for b in binaries:
            if path == b or basename == b:
                return True, "execve_ok"
        return False, "execve_binary_not_allowed"
    if ev == "connect":
        if not envelope.get("network", {}).get("allow_egress"):
            return False, "connect_denied_no_egress"
        return True, "connect_ok_egress_allowed"
    if ev == "sendto":
        if not envelope.get("network", {}).get("allow_egress"):
            return False, "sendto_denied_no_egress"
        return True, "sendto_ok_egress_allowed"
    return True, f"unknown_event_{ev}_pass"


def event_matches_predicate(event: dict, pred: dict) -> bool:
    if event.get("event") != pred.get("syscall"):
        return False
    if "path_contains" in pred:
        path = event.get("path") or ""
        if pred["path_contains"] not in path:
            return False
    if "path_starts_with" in pred:
        path = event.get("path") or ""
        if not path.startswith(pred["path_starts_with"]):
            return False
    return True


def eval_session(session_dir: Path, envelope: dict, strict: bool):
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    events = [e for e in iter_session_syscalls(session_dir) if e.get("pid") in subtree]
    inside = 0
    reasons = Counter()
    outside = []
    for e in events:
        if not strict and is_noise_read(e):
            inside += 1
            reasons["noise_floor_read"] += 1
            continue
        ok, reason = check_event_v5(e, envelope)
        reasons[reason] += 1
        if ok:
            inside += 1
        else:
            outside.append(e)
    total = len(events)
    return {
        "total": total,
        "coverage": inside / total if total else float("nan"),
        "reasons": dict(reasons),
        "outside_sample": outside[:15],
    }


def eval_reject(session_dir: Path, envelope: dict, sig_preds: list[dict], strict: bool):
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    events = [e for e in iter_session_syscalls(session_dir) if e.get("pid") in subtree]
    matched = []
    for e in events:
        for pred in sig_preds:
            if event_matches_predicate(e, pred):
                if not strict and is_noise_read(e):
                    v = "passed_by_nf"; r = "noise_floor"
                else:
                    ok, r = check_event_v5(e, envelope)
                    v = "in_env" if ok else "rejected"
                matched.append({"event": e, "verdict": v, "reason": r})
                break
    rejected = sum(1 for m in matched if m["verdict"] == "rejected")
    return {
        "n_sig_matches": len(matched),
        "n_rejected": rejected,
        "rejection_rate": (rejected / len(matched)) if matched else float("nan"),
        "matches": matched,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--sessions", type=Path,
                    default=Path(__file__).parent / "selected_kernel_sessions.json")
    args = ap.parse_args()

    sessions = json.loads(args.sessions.read_text())
    envelopes_dir = args.run / "envelopes"

    per = []
    for sess in sessions:
        base = f"{sess['mcp_group']}__{sess['mcp_name']}__{sess['prompt_slug']}"
        ep = envelopes_dir / f"{base}.json"
        if not ep.exists():
            continue
        env_wrap = json.loads(ep.read_text())
        env = env_wrap["envelope"]
        if "_error" in env:
            continue

        cov_str = eval_session(Path(sess["benign_session_dir"]), env, strict=True)
        cov_nf = eval_session(Path(sess["benign_session_dir"]), env, strict=False)

        sig_preds = load_signature_syscalls(Path(sess["signature_path"]))
        rej = eval_reject(Path(sess["malicious_session_dir"]), env, sig_preds, strict=True)

        # Count benign write false positives (writes rejected under v5 rule)
        benign_write_fps = cov_nf["reasons"].get("write_out_of_envelope", 0)
        # Count total benign writes for FP-rate context
        total_writes = sum(1 for e in iter_session_syscalls(Path(sess["benign_session_dir"]))
                            if e.get("event") == "openat" and e.get("write_intent")
                            and e.get("pid") in build_subtree_pids(
                                Path(sess["benign_session_dir"]) / "l3.jsonl"))

        per.append({
            "mcp_id": sess["mcp_id"],
            "attack_slug": sess["attack_slug"],
            "attack_category": sess["attack_category"],
            "envelope_write_paths": env.get("file_ops", {}).get("write_paths", []),
            "coverage_strict": cov_str["coverage"],
            "coverage_noise_floor": cov_nf["coverage"],
            "n_sig_matches": rej["n_sig_matches"],
            "n_rejected": rej["n_rejected"],
            "rejection_rate": rej["rejection_rate"],
            "benign_writes_total": total_writes,
            "benign_writes_rejected": benign_write_fps,
        })
        print(
            f"{sess['mcp_id'][:45]:<45s} {sess['attack_slug'][:27]:<27s} "
            f"cov_nf={cov_nf['coverage']:.3f} "
            f"sig={rej['n_sig_matches']:>3d} rej={rej['rejection_rate']:.3f} "
            f"benign_writes {benign_write_fps}/{total_writes}"
        )

    out_path = args.run / "evaluation_kernel_v5.json"
    out_path.write_text(json.dumps(per, indent=2))
    print(f"\nwrote {out_path}")

    n = len(per)
    if not n:
        return 0
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    rej_s = [p["rejection_rate"] for p in per if p["n_sig_matches"] > 0]
    print(f"\n=== v5 aggregate (attribution + strict specific-writes) over {n} entries ===")
    print(f"  coverage nf:        {mean([p['coverage_noise_floor'] for p in per]):.3f}")
    print(f"  rejection:          {mean(rej_s):.3f}   ({len(rej_s)}/{n})")
    total_fp = sum(p['benign_writes_rejected'] for p in per)
    total_w = sum(p['benign_writes_total'] for p in per)
    print(f"  benign write FPR:   {total_fp}/{total_w} = {total_fp/max(1,total_w):.3f}")

    print(f"\n=== by category ===")
    by_cat = {}
    for p in per:
        by_cat.setdefault(p["attack_category"], []).append(p)
    for cat, entries in sorted(by_cat.items()):
        rej_s = [e["rejection_rate"] for e in entries if e["n_sig_matches"] > 0]
        print(f"  {cat:<25s} n={len(entries)} rej={mean(rej_s):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
