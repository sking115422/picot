"""Evaluate envelopes against KERNEL-primary attack sessions.

Same metrics as evaluate.py but adapted to the flat schema produced by
select_kernel_sessions.py (one entry per (session, attack) pair rather
than per benign session).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from evaluate import (
    evaluate_session,
    evaluate_rejection,
    load_signature_syscalls,
)
from extract_syscalls import iter_session_syscalls


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
            print(f"[skip] no envelope: {env_path}")
            continue
        env_wrap = json.loads(env_path.read_text())
        envelope = env_wrap["envelope"]
        if "_error" in envelope:
            print(f"[skip] envelope error: {base}")
            continue

        benign_events = list(iter_session_syscalls(Path(sess["benign_session_dir"])))
        cov_strict = evaluate_session(benign_events, envelope, strict=True)
        cov_nf = evaluate_session(benign_events, envelope, strict=False)

        sig_preds = load_signature_syscalls(Path(sess["signature_path"]))
        mal_events = list(iter_session_syscalls(Path(sess["malicious_session_dir"])))
        rej_strict = evaluate_rejection(mal_events, envelope, sig_preds, strict=True)
        rej_nf = evaluate_rejection(mal_events, envelope, sig_preds, strict=False)

        per_entry.append({
            "mcp_id": sess["mcp_id"],
            "prompt_slug": sess["prompt_slug"],
            "attack_slug": sess["attack_slug"],
            "attack_category": sess["attack_category"],
            "rationale": envelope.get("rationale", ""),
            "coverage_strict": cov_strict["coverage"],
            "coverage_noise_floor": cov_nf["coverage"],
            "rej_strict": rej_strict,
            "rej_noise_floor": rej_nf,
        })

        print(
            f"{base}  attack={sess['attack_slug']:<30s}  "
            f"cov_strict={cov_strict['coverage']:.3f}  "
            f"cov_nf={cov_nf['coverage']:.3f}  "
            f"sig_matches={rej_strict['n_signature_matches']:>3d}  "
            f"rej_strict={rej_strict['rejection_rate']:.3f}  "
            f"rej_nf={rej_nf['rejection_rate']:.3f}"
        )

    out_path = args.run / "evaluation_kernel.json"
    out_path.write_text(json.dumps(per_entry, indent=2))
    print(f"\nwrote {out_path}")

    # Aggregate
    n = len(per_entry)
    if not n:
        return 0
    print(f"\n=== aggregate over {n} entries ===")
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    print(f"  coverage strict:      {mean([p['coverage_strict'] for p in per_entry]):.3f}")
    print(f"  coverage noise-floor: {mean([p['coverage_noise_floor'] for p in per_entry]):.3f}")
    rej_s = [p["rej_strict"]["rejection_rate"] for p in per_entry
             if p["rej_strict"]["n_signature_matches"] > 0]
    rej_n = [p["rej_noise_floor"]["rejection_rate"] for p in per_entry
             if p["rej_noise_floor"]["n_signature_matches"] > 0]
    print(f"  rejection strict:     {mean(rej_s):.3f}   ({len(rej_s)}/{n})")
    print(f"  rejection noise-floor:{mean(rej_n):.3f}   ({len(rej_n)}/{n})")

    # By attack category
    print(f"\n=== by attack category ===")
    by_cat = {}
    for p in per_entry:
        by_cat.setdefault(p["attack_category"], []).append(p)
    for cat, entries in sorted(by_cat.items()):
        rej_s = [e["rej_strict"]["rejection_rate"] for e in entries
                 if e["rej_strict"]["n_signature_matches"] > 0]
        print(f"  {cat:<25s}  n={len(entries)}  rej_strict={mean(rej_s):.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
