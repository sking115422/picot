"""Full-corpus evaluator: score every session pair against its (mcp,
prompt)-cached envelope. Handles both ace_c (signature.json predicates)
and ace_bi (session_sentinel predicates) rejection scoring.

Reads:
  - full_corpus/session_pairs.json — all pairs to evaluate
  - <envelope_run_dir>/envelopes/*.json — cached envelopes keyed by
    <mcp>__<prompt_slug>.json

Writes:
  - <envelope_run_dir>/evaluation_full.json — per-pair results
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

# Reuse machinery from ace_c and ace_bi evaluators
from evaluate import (
    check_event,
    is_noise_read,
    load_signature_syscalls as load_ace_c_signature,
)
from evaluate_ace_bi import (
    build_sentinel_predicates,
    event_matches_sentinel_predicate,
)
from evaluate import event_matches_predicate as event_matches_ace_c_predicate
from strace_extract import iter_strace_events
from subtree import build_subtree_pids


def key_filename(mcp: str, prompt_slug: str) -> str:
    mcp_safe = mcp.replace("/", "__")
    return f"{mcp_safe}__{prompt_slug}.json"


def eval_coverage(session_dir: Path, envelope: dict,
                  strict_writes: bool, noise_floor: bool,
                  ace_bi: bool) -> dict:
    strace = list((session_dir / "strace").glob("*.strace.log"))
    if not strace:
        return {"coverage": float("nan"), "total": 0}
    subtree = build_subtree_pids(strace[0], ace_bi=ace_bi)
    if not subtree:
        return {"coverage": float("nan"), "total": 0, "reason": "no_subtree"}
    total, inside = 0, 0
    for ev in iter_strace_events(strace[0]):
        if ev.get("pid") not in subtree:
            continue
        et = ev.get("event")
        if et not in ("openat", "open", "unlink", "unlinkat", "execve",
                      "connect", "sendto"):
            continue
        total += 1
        if noise_floor and is_noise_read(ev):
            inside += 1
            continue
        ok, _ = check_event(ev, envelope, strict_writes=strict_writes)
        if ok:
            inside += 1
    return {
        "total": total,
        "inside": inside,
        "coverage": inside / total if total else float("nan"),
    }


def eval_rejection_ace_c(session_dir: Path, envelope: dict,
                        sig_preds: list[dict], strict_writes: bool,
                        noise_floor: bool) -> dict:
    strace = list((session_dir / "strace").glob("*.strace.log"))
    if not strace:
        return {"n_sig_matches": 0, "n_rejected": 0,
                "rejection_rate": float("nan"),
                "first_hit_rejected": None}
    subtree = build_subtree_pids(strace[0], ace_bi=False)
    matched = 0
    rejected = 0
    first_hit_rejected: bool | None = None
    for ev in iter_strace_events(strace[0]):
        if ev.get("pid") not in subtree:
            continue
        for pred in sig_preds:
            if event_matches_ace_c_predicate(ev, pred):
                if noise_floor and is_noise_read(ev):
                    hit_rejected = False  # NF pass
                else:
                    ok, _ = check_event(ev, envelope, strict_writes=strict_writes)
                    hit_rejected = not ok
                    if hit_rejected:
                        rejected += 1
                if first_hit_rejected is None:
                    first_hit_rejected = hit_rejected
                matched += 1
                break
    return {
        "n_sig_matches": matched,
        "n_rejected": rejected,
        "rejection_rate": (rejected / matched) if matched else float("nan"),
        "first_hit_rejected": first_hit_rejected,
    }


def eval_rejection_ace_bi(session_dir: Path, envelope: dict,
                          sentinels: dict, strict_writes: bool,
                          noise_floor: bool) -> dict:
    strace = list((session_dir / "strace").glob("*.strace.log"))
    if not strace:
        return {"n_sig_matches": 0, "n_rejected": 0,
                "rejection_rate": float("nan"),
                "first_hit_rejected": None}
    subtree = build_subtree_pids(strace[0], ace_bi=True)
    preds = build_sentinel_predicates(sentinels)
    matched = 0
    rejected = 0
    first_hit_rejected: bool | None = None
    for ev in iter_strace_events(strace[0]):
        if ev.get("pid") not in subtree:
            continue
        for pred in preds:
            if event_matches_sentinel_predicate(ev, pred):
                if noise_floor and is_noise_read(ev):
                    hit_rejected = False
                else:
                    ok, _ = check_event(ev, envelope, strict_writes=strict_writes)
                    hit_rejected = not ok
                    if hit_rejected:
                        rejected += 1
                if first_hit_rejected is None:
                    first_hit_rejected = hit_rejected
                matched += 1
                break
    return {
        "n_sig_matches": matched,
        "n_rejected": rejected,
        "rejection_rate": (rejected / matched) if matched else float("nan"),
        "first_hit_rejected": first_hit_rejected,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True,
                    help="Envelope run dir (containing envelopes/)")
    ap.add_argument("--pairs", type=Path,
                    default=Path(__file__).parent / "full_corpus" / "session_pairs.json")
    ap.add_argument("--subset", choices=["ace_c", "ace_bi", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap number of pairs to evaluate (for testing)")
    args = ap.parse_args()

    pairs = json.loads(args.pairs.read_text())
    envelopes_dir = args.run / "envelopes"

    if args.subset == "ace_c":
        pairs = [p for p in pairs if not p["is_ace_bi"]]
    elif args.subset == "ace_bi":
        pairs = [p for p in pairs if p["is_ace_bi"]]
    if args.limit:
        pairs = pairs[:args.limit]

    print(f"[eval-full] evaluating {len(pairs)} session pairs (subset={args.subset})")

    per_pair = []
    for i, pair in enumerate(pairs, 1):
        k = pair["envelope_key"]
        env_file = envelopes_dir / key_filename(k["mcp"], k["prompt_slug"])
        if not env_file.exists():
            continue
        env_wrap = json.loads(env_file.read_text())
        env = env_wrap.get("envelope") or {}
        if "_error" in env or not env:
            continue

        ace_bi = pair.get("is_ace_bi", False)
        b_dir = Path(pair["benign_session_dir"])
        m_dir = Path(pair["malicious_session_dir"])

        # Coverage: use v5-style (strict writes) + noise floor
        cov = eval_coverage(b_dir, env, strict_writes=True,
                            noise_floor=True, ace_bi=ace_bi)

        # Rejection: same envelope, v5 strict
        if ace_bi:
            rej = eval_rejection_ace_bi(m_dir, env,
                                         pair["session_sentinels"],
                                         strict_writes=True, noise_floor=True)
        else:
            sig_path = pair.get("signature_path")
            if not sig_path:
                continue
            sig_preds = load_ace_c_signature(Path(sig_path))
            rej = eval_rejection_ace_c(m_dir, env, sig_preds,
                                        strict_writes=True, noise_floor=True)

        per_pair.append({
            "envelope_key": k,
            "benign_session_id": pair["benign_session_id"],
            "malicious_session_id": pair["malicious_session_id"],
            "is_ace_bi": ace_bi,
            "category": pair.get("category"),
            "attack_slug": pair.get("attack_slug"),
            "coverage_v5_nf": cov["coverage"],
            "n_events_subtree": cov["total"],
            "n_sig_matches": rej["n_sig_matches"],
            "n_rejected": rej["n_rejected"],
            "rejection_rate": rej["rejection_rate"],
            "first_hit_rejected": rej.get("first_hit_rejected"),
        })

        if i % 100 == 0:
            print(f"  ... {i}/{len(pairs)}")

    out_path = args.run / "evaluation_full.json"
    out_path.write_text(json.dumps(per_pair, indent=2))
    print(f"[eval-full] wrote {out_path}")

    # Aggregate
    def mean(xs):
        clean = [x for x in xs if x == x]
        return sum(clean) / len(clean) if clean else float("nan")

    def summarize(name, entries):
        n = len(entries)
        if not n:
            return
        covs = [e["coverage_v5_nf"] for e in entries]
        with_sig = [e for e in entries if e["n_sig_matches"] > 0]
        rejs = [e["rejection_rate"] for e in with_sig]
        n_sig = len(with_sig)
        # Attack-stopped rates
        first_stopped = sum(1 for e in with_sig if e.get("first_hit_rejected"))
        any_stopped = sum(1 for e in with_sig if e["n_rejected"] >= 1)
        all_stopped = sum(1 for e in with_sig if e["n_rejected"] == e["n_sig_matches"])
        pct = lambda k: (k / n_sig * 100) if n_sig else float('nan')

        print(f"\n=== {name} (n={n}) ===")
        print(f"  coverage_v5_nf mean:     {mean(covs):.3f} "
              f"({sum(1 for c in covs if c == c)}/{n} valid)")
        print(f"  per-syscall rejection:   {mean(rejs):.3f}  ({n_sig}/{n} had sig)")
        print(f"  attack stopped (first-hit): {pct(first_stopped):.1f}%  "
              f"({first_stopped}/{n_sig})")
        print(f"  attack stopped (any-hit):   {pct(any_stopped):.1f}%  "
              f"({any_stopped}/{n_sig})")
        print(f"  attack stopped (all-hits):  {pct(all_stopped):.1f}%  "
              f"({all_stopped}/{n_sig})")

    all_entries = per_pair
    ace_c_entries = [e for e in per_pair if not e["is_ace_bi"]]
    ace_bi_entries = [e for e in per_pair if e["is_ace_bi"]]

    summarize("full corpus", all_entries)
    summarize("ace_c",       ace_c_entries)
    summarize("ace_bi",      ace_bi_entries)

    # Per-attack-slug (ace_c) and per-category (ace_bi) breakdowns
    print("\n=== ace_c: by attack_slug (n>=3) ===")
    by_slug = defaultdict(list)
    for e in ace_c_entries:
        if e["n_sig_matches"] > 0 and e.get("attack_slug"):
            by_slug[e["attack_slug"]].append(e["rejection_rate"])
    for slug, rs in sorted(by_slug.items(), key=lambda x: -len(x[1])):
        if len(rs) < 3:
            continue
        print(f"  {slug[:38]:<38s} n={len(rs):>3d} rej={sum(rs)/len(rs):.3f}")

    print("\n=== ace_bi: by category (n>=3) ===")
    by_cat = defaultdict(list)
    for e in ace_bi_entries:
        if e["n_sig_matches"] > 0 and e.get("category"):
            by_cat[e["category"]].append(e["rejection_rate"])
    for cat, rs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        if len(rs) < 3:
            continue
        print(f"  {cat[:38]:<38s} n={len(rs):>3d} rej={sum(rs)/len(rs):.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
