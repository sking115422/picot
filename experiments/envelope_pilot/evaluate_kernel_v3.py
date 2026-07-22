"""v3 evaluation: attribute events to the MCP tool subtree BEFORE
scoring against the envelope.

Key change from v1/v2: coverage and rejection are computed only over
syscalls belonging to the MCP server's process subtree, not over the
whole session cgroup. This removes Claude Code driver bookkeeping
(session state writes, cache writes, Bedrock API HTTP connects) from
the envelope's scoring surface — those aren't tool-attributable and
shouldn't be judged against a per-prompt envelope.

Coverage rules stay the same as v1: strict whitelist and noise-floor
semantics both reported.

Enforcement compiler: unchanged from v1 (NO dotfile-in-scratch rule).
The point of v3 is to isolate the effect of attribution filtering.

Compare with:
  - evaluation_kernel.json  — v1, no attribution, no compiler rules
  - evaluation_kernel_v2.json — v1 + dotfile-in-scratch compiler rule
  - evaluation_kernel_v3.json — v1 + attribution (NO compiler rule)
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate import (
    check_event,
    is_noise_read,
    load_signature_syscalls,
)
from extract_syscalls import iter_session_syscalls
from mcp_subtree import build_subtree_pids


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


def evaluate_session_filtered(session_dir: Path, envelope: dict, strict: bool) -> dict:
    """Coverage over events restricted to MCP subtree pids."""
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    all_events = list(iter_session_syscalls(session_dir))
    events = [e for e in all_events if e.get("pid") in subtree]
    inside = 0
    reasons = Counter()
    outside_events = []
    for e in events:
        if not strict and is_noise_read(e):
            inside += 1
            reasons["noise_floor_read"] += 1
            continue
        ok, reason = check_event(e, envelope)
        reasons[reason] += 1
        if ok:
            inside += 1
        else:
            outside_events.append(e)
    total = len(events)
    return {
        "total_events_all_cgroup": len(all_events),
        "total_events_mcp_subtree": total,
        "subtree_pids": sorted(subtree),
        "inside": inside,
        "outside": total - inside,
        "coverage": inside / total if total else float("nan"),
        "reason_counts": dict(reasons),
        "outside_sample": outside_events[:10],
    }


def evaluate_rejection_filtered(session_dir: Path, envelope: dict,
                                 sig_preds: list[dict], strict: bool) -> dict:
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    all_events = list(iter_session_syscalls(session_dir))
    events = [e for e in all_events if e.get("pid") in subtree]
    matched = []
    for e in events:
        for pred in sig_preds:
            if event_matches_predicate(e, pred):
                if not strict and is_noise_read(e):
                    verdict = ("passed_by_noise_floor", "noise_floor")
                else:
                    ok, reason = check_event(e, envelope)
                    verdict = ("in_envelope" if ok else "rejected", reason)
                matched.append({
                    "event": e,
                    "matched_predicate": pred,
                    "verdict": verdict[0],
                    "reason": verdict[1],
                })
                break
    rejected = sum(1 for m in matched if m["verdict"] == "rejected")
    # Also count how many signature matches exist in the FULL cgroup for reference
    full_matches = 0
    for e in all_events:
        for pred in sig_preds:
            if event_matches_predicate(e, pred):
                full_matches += 1
                break
    return {
        "n_signature_matches_full": full_matches,
        "n_signature_matches_subtree": len(matched),
        "n_rejected_by_envelope": rejected,
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

    per_entry = []
    for sess in sessions:
        base = f"{sess['mcp_group']}__{sess['mcp_name']}__{sess['prompt_slug']}"
        env_path = envelopes_dir / f"{base}.json"
        if not env_path.exists():
            continue
        env_wrap = json.loads(env_path.read_text())
        envelope = env_wrap["envelope"]
        if "_error" in envelope:
            continue

        cov_strict = evaluate_session_filtered(
            Path(sess["benign_session_dir"]), envelope, strict=True)
        cov_nf = evaluate_session_filtered(
            Path(sess["benign_session_dir"]), envelope, strict=False)

        sig_preds = load_signature_syscalls(Path(sess["signature_path"]))
        rej_strict = evaluate_rejection_filtered(
            Path(sess["malicious_session_dir"]), envelope, sig_preds, strict=True)
        rej_nf = evaluate_rejection_filtered(
            Path(sess["malicious_session_dir"]), envelope, sig_preds, strict=False)

        per_entry.append({
            "mcp_id": sess["mcp_id"],
            "prompt_slug": sess["prompt_slug"],
            "attack_slug": sess["attack_slug"],
            "attack_category": sess["attack_category"],
            "benign_events_total": cov_strict["total_events_all_cgroup"],
            "benign_events_mcp_subtree": cov_strict["total_events_mcp_subtree"],
            "coverage_strict": cov_strict["coverage"],
            "coverage_noise_floor": cov_nf["coverage"],
            "rej_strict": rej_strict,
            "rej_noise_floor": rej_nf,
        })

        print(
            f"{base}  attack={sess['attack_slug']:<27s} "
            f"events_all={cov_strict['total_events_all_cgroup']:>5d} "
            f"events_mcp={cov_strict['total_events_mcp_subtree']:>5d} "
            f"cov_str={cov_strict['coverage']:.3f} "
            f"cov_nf={cov_nf['coverage']:.3f} "
            f"sig_all={rej_strict['n_signature_matches_full']:>3d} "
            f"sig_mcp={rej_strict['n_signature_matches_subtree']:>3d} "
            f"rej_str={rej_strict['rejection_rate']:.3f}"
        )

    out_path = args.run / "evaluation_kernel_v3.json"
    out_path.write_text(json.dumps(per_entry, indent=2))
    print(f"\nwrote {out_path}")

    n = len(per_entry)
    if not n:
        return 0
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    print(f"\n=== aggregate v3 (attribution-filtered, NO dotfile rule) over {n} entries ===")
    print(f"  coverage strict:      {mean([p['coverage_strict'] for p in per_entry]):.3f}")
    print(f"  coverage noise-floor: {mean([p['coverage_noise_floor'] for p in per_entry]):.3f}")
    rej_s = [p["rej_strict"]["rejection_rate"] for p in per_entry
             if p["rej_strict"]["n_signature_matches_subtree"] > 0]
    print(f"  rejection strict:     {mean(rej_s):.3f}   ({len(rej_s)}/{n})")

    print(f"\n=== by category ===")
    by_cat = {}
    for p in per_entry:
        by_cat.setdefault(p["attack_category"], []).append(p)
    for cat, entries in sorted(by_cat.items()):
        rej_s = [e["rej_strict"]["rejection_rate"] for e in entries
                 if e["rej_strict"]["n_signature_matches_subtree"] > 0]
        print(f"  {cat:<25s} n={len(entries)} rej={mean(rej_s):.3f}")

    print(f"\n=== attribution impact on benign event volume ===")
    for p in per_entry:
        ratio = p["benign_events_mcp_subtree"] / max(1, p["benign_events_total"])
        print(f"  {p['mcp_id'][:40]:<40s} all={p['benign_events_total']:>5d} mcp={p['benign_events_mcp_subtree']:>5d} ratio={ratio:.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
