"""v6a evaluation: v5 enforcement + argv-content coverage check.

New rule (only for execve):
  When execve fires, extract path-like and host-like tokens from argv.
  Every extracted token must be covered by the envelope's positive
  surface (read_paths | write_paths | delete_paths for paths, allow_hosts
  for hosts). Any uncovered token denies the execve.

This is *additive* to the v5 rules (allow_spawn, allow_binaries). If
either the binary or any argv token is not covered, the execve is denied.

No new envelope grammar. No LLM changes. The LLM's positive surface
(what benign behavior needs) becomes the argv allow-list.

Rejection tracking mirrors evaluate_full.py: n_sig_matches, n_rejected,
rejection_rate, first_hit_rejected.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
from collections import defaultdict
from pathlib import Path

from argv_tokenize import extract_tokens
from evaluate import (
    is_noise_read,
    load_signature_syscalls as load_ace_c_signature,
    event_matches_predicate as event_matches_ace_c_predicate,
    path_matches,
)
from evaluate_ace_bi import (
    build_sentinel_predicates,
    event_matches_sentinel_predicate,
)
from strace_extract import iter_strace_events
from subtree import build_subtree_pids


def _host_covered(host: str, allow_hosts: list[str]) -> bool:
    """A host token is covered iff it matches one of the allow_hosts
    entries. Supports glob patterns (`*.example.com`)."""
    for pat in allow_hosts or []:
        if fnmatch.fnmatch(host, pat) or host == pat:
            return True
    return False


def _path_covered_by_any(path: str, envelope: dict) -> bool:
    """A path token is covered iff it matches any read/write/delete
    pattern in the envelope."""
    fo = envelope.get("file_ops", {}) or {}
    for key in ("read_paths", "write_paths", "delete_paths"):
        pats = fo.get(key, []) or []
        if path_matches(path, pats):
            return True
    return False


def check_event_v6a(event: dict, envelope: dict) -> tuple[bool, str]:
    """v5 rules + argv-content check on execve.

    Return (allowed, reason). Uses v5 semantics for openat/unlinkat/
    connect/sendto; adds argv scanning for execve.
    """
    ev = event["event"]

    if ev in ("openat", "open"):
        path = event.get("path") or ""
        if event.get("write_intent"):
            wpaths = envelope.get("file_ops", {}).get("write_paths", []) or []
            if path_matches(path, wpaths):
                return True, "write_ok"
            return False, "write_out_of_envelope"
        rpaths = envelope.get("file_ops", {}).get("read_paths", []) or []
        if path_matches(path, rpaths):
            return True, "read_ok"
        return False, "read_out_of_envelope"

    if ev in ("unlink", "unlinkat"):
        path = event.get("path") or ""
        dpaths = envelope.get("file_ops", {}).get("delete_paths", []) or []
        if path_matches(path, dpaths):
            return True, "unlink_ok"
        return False, "unlink_out_of_envelope"

    if ev == "execve":
        path = event.get("path") or ""
        if not envelope.get("process", {}).get("allow_spawn"):
            return False, "execve_denied_no_spawn"
        binaries = envelope.get("process", {}).get("allow_binaries", []) or []
        basename = path.rsplit("/", 1)[-1]
        binary_ok = any(path == b or basename == b for b in binaries)
        if not binary_ok:
            return False, "execve_binary_not_allowed"

        # v6a addition: check argv tokens
        argv = event.get("argv") or []
        tokens = extract_tokens(argv)
        allow_hosts = envelope.get("network", {}).get("allow_hosts", []) or []

        for host in tokens["hosts"]:
            if not _host_covered(host, allow_hosts):
                return False, f"execve_argv_host_out_of_envelope:{host}"
        for p in tokens["paths"]:
            # Skip the binary itself (already checked)
            if p == path:
                continue
            if not _path_covered_by_any(p, envelope):
                return False, f"execve_argv_path_out_of_envelope:{p}"
        return True, "execve_ok"

    if ev == "connect":
        if not envelope.get("network", {}).get("allow_egress"):
            return False, "connect_denied_no_egress"
        return True, "connect_ok_egress_allowed"

    if ev == "sendto":
        if not envelope.get("network", {}).get("allow_egress"):
            return False, "sendto_denied_no_egress"
        return True, "sendto_ok_egress_allowed"

    return True, f"{ev}_pass"


def eval_coverage(session_dir: Path, envelope: dict, noise_floor: bool,
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
        ok, _ = check_event_v6a(ev, envelope)
        if ok:
            inside += 1
    return {"total": total, "inside": inside,
            "coverage": inside / total if total else float("nan")}


def eval_rejection_ace_c(session_dir: Path, envelope: dict,
                          sig_preds: list[dict], noise_floor: bool) -> dict:
    strace = list((session_dir / "strace").glob("*.strace.log"))
    if not strace:
        return {"n_sig_matches": 0, "n_rejected": 0,
                "rejection_rate": float("nan"), "first_hit_rejected": None}
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
                    hit_rejected = False
                else:
                    ok, _ = check_event_v6a(ev, envelope)
                    hit_rejected = not ok
                    if hit_rejected:
                        rejected += 1
                if first_hit_rejected is None:
                    first_hit_rejected = hit_rejected
                matched += 1
                break
    return {"n_sig_matches": matched, "n_rejected": rejected,
            "rejection_rate": (rejected / matched) if matched else float("nan"),
            "first_hit_rejected": first_hit_rejected}


def eval_rejection_ace_bi(session_dir: Path, envelope: dict,
                          sentinels: dict, noise_floor: bool) -> dict:
    strace = list((session_dir / "strace").glob("*.strace.log"))
    if not strace:
        return {"n_sig_matches": 0, "n_rejected": 0,
                "rejection_rate": float("nan"), "first_hit_rejected": None}
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
                    ok, _ = check_event_v6a(ev, envelope)
                    hit_rejected = not ok
                    if hit_rejected:
                        rejected += 1
                if first_hit_rejected is None:
                    first_hit_rejected = hit_rejected
                matched += 1
                break
    return {"n_sig_matches": matched, "n_rejected": rejected,
            "rejection_rate": (rejected / matched) if matched else float("nan"),
            "first_hit_rejected": first_hit_rejected}


def key_filename(mcp: str, prompt_slug: str) -> str:
    return f"{mcp.replace('/', '__')}__{prompt_slug}.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True,
                    help="Envelope run dir (containing envelopes/)")
    ap.add_argument("--pairs", type=Path,
                    default=Path(__file__).parent / "full_corpus" / "session_pairs.json")
    ap.add_argument("--subset", choices=["ace_c", "ace_bi", "all"], default="all")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    pairs = json.loads(args.pairs.read_text())
    envelopes_dir = args.run / "envelopes"

    if args.subset == "ace_c":
        pairs = [p for p in pairs if not p["is_ace_bi"]]
    elif args.subset == "ace_bi":
        pairs = [p for p in pairs if p["is_ace_bi"]]
    if args.limit:
        pairs = pairs[:args.limit]

    print(f"[eval-v6a] evaluating {len(pairs)} session pairs (subset={args.subset})")

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

        cov = eval_coverage(b_dir, env, noise_floor=True, ace_bi=ace_bi)

        if ace_bi:
            rej = eval_rejection_ace_bi(m_dir, env, pair["session_sentinels"],
                                         noise_floor=True)
        else:
            sig_path = pair.get("signature_path")
            if not sig_path:
                continue
            sig_preds = load_ace_c_signature(Path(sig_path))
            rej = eval_rejection_ace_c(m_dir, env, sig_preds, noise_floor=True)

        per_pair.append({
            "envelope_key": k,
            "benign_session_id": pair["benign_session_id"],
            "malicious_session_id": pair["malicious_session_id"],
            "is_ace_bi": ace_bi,
            "category": pair.get("category"),
            "attack_slug": pair.get("attack_slug"),
            "coverage_v6a_nf": cov["coverage"],
            "n_events_subtree": cov["total"],
            "n_sig_matches": rej["n_sig_matches"],
            "n_rejected": rej["n_rejected"],
            "rejection_rate": rej["rejection_rate"],
            "first_hit_rejected": rej.get("first_hit_rejected"),
        })

        if i % 100 == 0:
            print(f"  ... {i}/{len(pairs)}")

    out_path = args.run / "evaluation_v6a.json"
    out_path.write_text(json.dumps(per_pair, indent=2))
    print(f"[eval-v6a] wrote {out_path}")

    def mean(xs):
        clean = [x for x in xs if x == x]
        return sum(clean) / len(clean) if clean else float("nan")

    def summarize(name, entries):
        n = len(entries)
        if not n:
            return
        covs = [e["coverage_v6a_nf"] for e in entries]
        with_sig = [e for e in entries if e["n_sig_matches"] > 0]
        rejs = [e["rejection_rate"] for e in with_sig]
        n_sig = len(with_sig)
        first = sum(1 for e in with_sig if e.get("first_hit_rejected"))
        any_h = sum(1 for e in with_sig if e["n_rejected"] >= 1)
        all_h = sum(1 for e in with_sig if e["n_rejected"] == e["n_sig_matches"])
        pct = lambda k: (k / n_sig * 100) if n_sig else float('nan')

        print(f"\n=== {name} (n={n}) ===")
        print(f"  coverage v6a nf:         {mean(covs):.3f}")
        print(f"  per-syscall rejection:   {mean(rejs):.3f}  ({n_sig}/{n})")
        print(f"  first-hit stopped (B):   {pct(first):.1f}%  ({first}/{n_sig})")
        print(f"  any-hit stopped (A):     {pct(any_h):.1f}%  ({any_h}/{n_sig})")
        print(f"  all-hits stopped (C):    {pct(all_h):.1f}%  ({all_h}/{n_sig})")

    ace_c = [e for e in per_pair if not e["is_ace_bi"]]
    ace_bi = [e for e in per_pair if e["is_ace_bi"]]
    summarize("full corpus (v6a)", per_pair)
    summarize("ace_c (v6a)", ace_c)
    summarize("ace_bi (v6a)", ace_bi)

    print("\n=== ace_bi: by category (first-hit stopped) ===")
    by_cat = defaultdict(list)
    for e in ace_bi:
        if e["n_sig_matches"] > 0 and e.get("category"):
            by_cat[e["category"]].append(bool(e.get("first_hit_rejected")))
    for cat, xs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        if len(xs) < 3:
            continue
        pct = sum(xs) / len(xs) * 100
        print(f"  {cat[:38]:<38s} n={len(xs):>3d} first_hit={pct:>5.1f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
