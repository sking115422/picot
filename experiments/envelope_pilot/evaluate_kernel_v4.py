"""v4 evaluation: v3 attribution + v2 dotfile-in-scratch rule together.

If v4 rejection >> v3 rejection, the dotfile rule catches genuine MCP
subtree attacks. If v4 ≈ v3, the dotfile rule was fitting driver noise.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate_kernel_v2 import check_event_v2, is_dotfile_in_scratch
from evaluate import is_noise_read, load_signature_syscalls
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


def eval_session(session_dir: Path, envelope: dict, strict: bool):
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    events = [e for e in iter_session_syscalls(session_dir) if e.get("pid") in subtree]
    inside = 0
    for e in events:
        if not strict and is_noise_read(e):
            inside += 1
            continue
        ok, _ = check_event_v2(e, envelope)
        if ok:
            inside += 1
    total = len(events)
    return inside / total if total else float("nan"), total


def eval_reject(session_dir: Path, envelope: dict, sig_preds: list[dict], strict: bool):
    subtree = build_subtree_pids(session_dir / "l3.jsonl")
    events = [e for e in iter_session_syscalls(session_dir) if e.get("pid") in subtree]
    matched = []
    for e in events:
        for pred in sig_preds:
            if event_matches_predicate(e, pred):
                if not strict and is_noise_read(e):
                    matched.append(("passed_by_nf", "noise_floor"))
                else:
                    ok, r = check_event_v2(e, envelope)
                    matched.append(("in_env" if ok else "rejected", r))
                break
    rejected = sum(1 for m, _ in matched if m == "rejected")
    return len(matched), rejected


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
        env = env_wrap["envelope"]
        if "_error" in env:
            continue

        cov_str, n_ev_b = eval_session(Path(sess["benign_session_dir"]), env, strict=True)
        cov_nf, _ = eval_session(Path(sess["benign_session_dir"]), env, strict=False)

        sig_preds = load_signature_syscalls(Path(sess["signature_path"]))
        n_sig, n_rej = eval_reject(Path(sess["malicious_session_dir"]), env, sig_preds, strict=True)
        rej_rate = (n_rej / n_sig) if n_sig else float("nan")

        per_entry.append({
            "mcp_id": sess["mcp_id"],
            "attack_slug": sess["attack_slug"],
            "attack_category": sess["attack_category"],
            "coverage_strict": cov_str,
            "coverage_noise_floor": cov_nf,
            "n_sig_matches_subtree": n_sig,
            "n_rejected": n_rej,
            "rejection_rate": rej_rate,
        })
        print(f"{base}  attack={sess['attack_slug']:<30s}  cov_nf={cov_nf:.3f}  sig={n_sig:>3d}  rej={rej_rate:.3f}")

    out_path = args.run / "evaluation_kernel_v4.json"
    out_path.write_text(json.dumps(per_entry, indent=2))
    print(f"\nwrote {out_path}")

    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    print(f"\n=== v4 aggregate (attribution + dotfile rule) ===")
    print(f"  coverage nf:   {mean([p['coverage_noise_floor'] for p in per_entry]):.3f}")
    rej_s = [p["rejection_rate"] for p in per_entry if p["n_sig_matches_subtree"] > 0]
    print(f"  rejection:     {mean(rej_s):.3f}  ({len(rej_s)}/{len(per_entry)})")

    by_cat = {}
    for p in per_entry:
        by_cat.setdefault(p["attack_category"], []).append(p)
    print(f"\n=== by category ===")
    for cat, entries in sorted(by_cat.items()):
        rej_s = [e["rejection_rate"] for e in entries if e["n_sig_matches_subtree"] > 0]
        print(f"  {cat:<25s} n={len(entries)} rej={mean(rej_s):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
