"""Evaluator for ace_full sessions.

Runs both v3 (attribution + wildcard-permissive writes) and v5
(attribution + strict-specific writes) enforcement semantics on the
same envelope, using the same strace-parsed event stream.

Metrics computed per session:
  - Coverage strict / noise-floor (benign session)
  - Rejection strict / noise-floor (malicious session against signature)
  - Benign write false positives under v5 strict-writes rule

Signature matching uses ace_c signature.json predicates. Sentinel-based
matching (ace_bi) is a separate code path — this module handles ace_c.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
from collections import Counter
from pathlib import Path

from strace_extract import iter_strace_events
from subtree import build_subtree_pids


NOISE_FLOOR_PREFIXES = (
    "/etc/", "/usr/", "/lib/", "/lib64/",
    "/proc/", "/sys/", "/dev/", "/System/", "/opt/",
    "/root/", "/var/lib/", "/run/", "/tmp/",
    "/dev/null", "/dev/urandom",
)


def path_matches(path: str, patterns: list[str]) -> bool:
    if not path or not patterns:
        return False
    for pat in patterns:
        pat_fnmatch = pat.replace("**", "*")
        if fnmatch.fnmatch(path, pat_fnmatch):
            return True
    return False


def is_noise_read(event: dict) -> bool:
    if event.get("event") not in ("openat", "open"):
        return False
    if event.get("write_intent"):
        return False
    path = event.get("path") or ""
    return path.startswith(NOISE_FLOOR_PREFIXES)


def check_event(event: dict, envelope: dict, strict_writes: bool) -> tuple[bool, str]:
    """Envelope membership check. When strict_writes=True, writes must
    match an explicit pattern (v5). When False, matches like v1/v3."""
    ev = event["event"]
    if ev in ("openat", "open"):
        path = event.get("path") or ""
        if event.get("write_intent"):
            wpaths = envelope.get("file_ops", {}).get("write_paths", []) or []
            if path_matches(path, wpaths):
                return True, "write_ok"
            return False, "write_out_of_envelope"
        else:
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
    return True, f"{ev}_pass"


def eval_coverage(session_dir: Path, envelope: dict,
                  strict_writes: bool, noise_floor: bool,
                  ace_bi: bool = False) -> dict:
    """Coverage on benign session, MCP-subtree only."""
    strace_files = list((session_dir / "strace").glob("*.strace.log"))
    if not strace_files:
        return {"coverage": float("nan"), "total": 0, "inside": 0}
    strace_path = strace_files[0]
    subtree = build_subtree_pids(strace_path, ace_bi=ace_bi)
    if not subtree:
        return {"coverage": float("nan"), "total": 0, "inside": 0, "reason": "no_subtree"}

    total = 0
    inside = 0
    reasons: Counter = Counter()
    for ev in iter_strace_events(strace_path):
        if ev.get("pid") not in subtree:
            continue
        # Only care about security-relevant events
        ev_type = ev.get("event")
        if ev_type not in ("openat", "open", "unlink", "unlinkat", "execve",
                           "connect", "sendto"):
            continue
        total += 1
        if noise_floor and is_noise_read(ev):
            inside += 1
            reasons["noise_floor_read"] += 1
            continue
        ok, reason = check_event(ev, envelope, strict_writes=strict_writes)
        reasons[reason] += 1
        if ok:
            inside += 1
    return {
        "total": total,
        "inside": inside,
        "coverage": inside / total if total else float("nan"),
        "reasons": dict(reasons),
    }


def load_signature_syscalls(sig_path: Path) -> list[dict]:
    def walk(node):
        if isinstance(node, dict):
            if node.get("kind") == "l1_syscall":
                yield node
                return
            for k in ("any", "all", "not"):
                if k in node:
                    yield from walk(node[k])
        elif isinstance(node, list):
            for x in node:
                yield from walk(x)

    d = json.loads(sig_path.read_text())
    return list(walk(d.get("predicates")))


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


def eval_rejection(session_dir: Path, envelope: dict,
                   sig_preds: list[dict], strict_writes: bool,
                   noise_floor: bool, ace_bi: bool = False) -> dict:
    """Rejection on malicious session against sig predicates, MCP-subtree only."""
    strace_files = list((session_dir / "strace").glob("*.strace.log"))
    if not strace_files:
        return {"n_sig_matches": 0, "n_rejected": 0, "rejection_rate": float("nan")}
    strace_path = strace_files[0]
    subtree = build_subtree_pids(strace_path, ace_bi=ace_bi)

    matched = []
    for ev in iter_strace_events(strace_path):
        if ev.get("pid") not in subtree:
            continue
        for pred in sig_preds:
            if event_matches_predicate(ev, pred):
                if noise_floor and is_noise_read(ev):
                    matched.append({"verdict": "nf", "reason": "noise_floor"})
                else:
                    ok, r = check_event(ev, envelope, strict_writes=strict_writes)
                    matched.append({"verdict": "in_env" if ok else "rejected",
                                    "reason": r, "path": ev.get("path"),
                                    "event": ev.get("event")})
                break
    n_rej = sum(1 for m in matched if m["verdict"] == "rejected")
    return {
        "n_sig_matches": len(matched),
        "n_rejected": n_rej,
        "rejection_rate": (n_rej / len(matched)) if matched else float("nan"),
        "matches": matched[:5],  # sample for debugging
    }


def evaluate_one(sess: dict, envelope: dict) -> dict:
    """Full evaluation of one selected session against its envelope."""
    b_dir = Path(sess["benign_session_dir"])
    m_dir = Path(sess["malicious_session_dir"])
    ace_bi = sess.get("is_ace_bi", False)

    # v3-style coverage (permissive writes)
    cov_v3_strict = eval_coverage(b_dir, envelope, strict_writes=False,
                                   noise_floor=False, ace_bi=ace_bi)
    cov_v3_nf = eval_coverage(b_dir, envelope, strict_writes=False,
                               noise_floor=True, ace_bi=ace_bi)
    # v5-style coverage (strict writes)
    cov_v5_strict = eval_coverage(b_dir, envelope, strict_writes=True,
                                   noise_floor=False, ace_bi=ace_bi)
    cov_v5_nf = eval_coverage(b_dir, envelope, strict_writes=True,
                               noise_floor=True, ace_bi=ace_bi)

    # Rejection: same envelope, both semantics
    sig_path = sess.get("signature_path")
    if sig_path:
        sig_preds = load_signature_syscalls(Path(sig_path))
    else:
        sig_preds = []

    rej_v3 = eval_rejection(m_dir, envelope, sig_preds, strict_writes=False,
                            noise_floor=True, ace_bi=ace_bi)
    rej_v5 = eval_rejection(m_dir, envelope, sig_preds, strict_writes=True,
                            noise_floor=True, ace_bi=ace_bi)

    return {
        "session_id": sess["session_id"],
        "mcp": sess["mcp"],
        "prompt": sess["prompt"],
        "attack_slug": sess.get("attack_slug"),
        "category": sess.get("category"),
        "coverage_v3_strict": cov_v3_strict["coverage"],
        "coverage_v3_nf": cov_v3_nf["coverage"],
        "coverage_v5_strict": cov_v5_strict["coverage"],
        "coverage_v5_nf": cov_v5_nf["coverage"],
        "n_events_subtree": cov_v3_nf["total"],
        "rej_v3": rej_v3,
        "rej_v5": rej_v5,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True,
                    help="Run dir containing envelopes/")
    ap.add_argument("--sessions", type=Path,
                    default=Path(__file__).parent / "selected_ace_c.json")
    args = ap.parse_args()

    sessions = json.loads(args.sessions.read_text())
    envelopes_dir = args.run / "envelopes"

    per = []
    for sess in sessions:
        sid = sess["session_id"]
        env_path = envelopes_dir / f"{sid}.json"
        if not env_path.exists():
            continue
        env_wrap = json.loads(env_path.read_text())
        env = env_wrap.get("envelope") or {}
        if "_error" in env or not env:
            continue

        result = evaluate_one(sess, env)
        per.append(result)
        print(
            f"{sid} {sess['mcp'][:30]:<30s} {sess.get('attack_slug', '?')[:25]:<25s} "
            f"cov_v5_nf={result['coverage_v5_nf']:.3f} "
            f"sig={result['rej_v5']['n_sig_matches']:>3d} "
            f"rej_v3={result['rej_v3']['rejection_rate']:.3f} "
            f"rej_v5={result['rej_v5']['rejection_rate']:.3f}"
        )

    out_path = args.run / "evaluation_ace_c.json"
    out_path.write_text(json.dumps(per, indent=2))
    print(f"\nwrote {out_path}")

    if not per:
        return 0
    def mean(xs):
        clean = [x for x in xs if x == x]  # skip NaN
        return sum(clean) / len(clean) if clean else float("nan")
    print(f"\n=== aggregate (ace_c, n={len(per)}) ===")
    covs_v3 = [p['coverage_v3_nf'] for p in per]
    covs_v5 = [p['coverage_v5_nf'] for p in per]
    n_bad_cov = sum(1 for x in covs_v5 if x != x)
    print(f"  cov_v3_nf mean:  {mean(covs_v3):.3f}  ({len(covs_v3)-n_bad_cov}/{len(covs_v3)} valid)")
    print(f"  cov_v5_nf mean:  {mean(covs_v5):.3f}  ({len(covs_v5)-n_bad_cov}/{len(covs_v5)} valid)")

    rej_v3 = [p['rej_v3']['rejection_rate'] for p in per if p['rej_v3']['n_sig_matches'] > 0]
    rej_v5 = [p['rej_v5']['rejection_rate'] for p in per if p['rej_v5']['n_sig_matches'] > 0]
    print(f"  rejection v3:     {mean(rej_v3):.3f}   ({len(rej_v3)}/{len(per)} had sig matches)")
    print(f"  rejection v5:     {mean(rej_v5):.3f}   ({len(rej_v5)}/{len(per)} had sig matches)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
