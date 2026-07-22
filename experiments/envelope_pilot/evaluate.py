"""Evaluate generated envelopes against actual session syscalls.

Metrics:
  1. Coverage — of the benign session's syscalls, what fraction fall
     inside the envelope?
  2. Rejection — of the malicious signature's flagged syscalls, what
     fraction fall OUTSIDE the envelope (which is what we want)?
  3. Stability — deferred to a separate script (needs multiple runs).

Two enforcement semantics are reported side-by-side for coverage:
  - strict: any syscall not matched by an envelope rule is out-of-envelope
  - noise-floor: only security-relevant syscalls are subject to check
    (openat with write flags, unlinkat, connect, sendto, execve). Reads
    of "boot noise" paths under /etc, /usr, /lib, /proc, /sys, /System,
    plus SSL cert stores, always pass — these are Python/glibc/loader
    bookkeeping we cannot expect the envelope to enumerate.

Both semantics use the same envelope; only how they treat un-covered
events differs.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
from collections import Counter
from pathlib import Path

from extract_syscalls import iter_session_syscalls  # sibling module


NOISE_FLOOR_PATH_PREFIXES = (
    "/etc/",
    "/usr/",
    "/lib/",
    "/lib64/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/System/",
    "/opt/",
    "/root/",  # container root layers
    "/var/lib/",
    "/run/",
    "/tmp/",   # broadly permitted; envelope may narrow further
    "/dev/null",
    "/dev/urandom",
)


def path_matches(path: str, patterns: list[str]) -> bool:
    if not path or not patterns:
        return False
    for pat in patterns:
        # Basic glob — fnmatch handles `*` and `?`. For `**` we approximate
        # by translating to `*` before matching, since fnmatch doesn't
        # natively support `**`.
        pat_fnmatch = pat.replace("**", "*")
        if fnmatch.fnmatch(path, pat_fnmatch):
            return True
    return False


def is_noise_read(event: dict) -> bool:
    if event.get("event") != "openat":
        return False
    if event.get("write_intent"):
        return False
    path = event.get("path") or ""
    return path.startswith(NOISE_FLOOR_PATH_PREFIXES)


def check_event(event: dict, envelope: dict) -> tuple[bool, str]:
    """Return (in_envelope, reason). reason is a short tag."""
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
        # allow if path equals any allowed binary, or basename matches
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
        # Can't check host without addr — treat as allow if egress permitted
        return True, "connect_ok_egress_allowed"
    if ev == "sendto":
        if not envelope.get("network", {}).get("allow_egress"):
            return False, "sendto_denied_no_egress"
        return True, "sendto_ok_egress_allowed"
    return True, f"unknown_event_{ev}_pass"


def evaluate_session(events: list[dict], envelope: dict, strict: bool) -> dict:
    inside = 0
    outside_events = []
    reasons = Counter()
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
    coverage = inside / total if total else float("nan")
    return {
        "total_events": total,
        "inside": inside,
        "outside": total - inside,
        "coverage": coverage,
        "reason_counts": dict(reasons),
        "outside_sample": outside_events[:10],  # first 10 for inspection
    }


def load_signature_syscalls(sig_path: Path) -> list[dict]:
    """Return the syscall predicates from a malicious patch signature.

    The corpus has two predicate schemas: (a) top-level list, (b) an object
    with `any` / `all` operators containing predicate lists. Recursively
    walk and collect anything with kind=='l1_syscall'.
    """
    d = json.loads(sig_path.read_text())
    out: list[dict] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("kind") == "l1_syscall":
                out.append(node)
                return
            for k in ("any", "all", "not"):
                if k in node:
                    walk(node[k])
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(d.get("predicates"))
    return out


def event_matches_predicate(event: dict, pred: dict) -> bool:
    """Would this event have fired the malicious-signature predicate?"""
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


def evaluate_rejection(events: list[dict], envelope: dict, sig_preds: list[dict],
                      strict: bool) -> dict:
    """For each syscall matching a malicious predicate, is it out-of-envelope?"""
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
    return {
        "n_signature_matches": len(matched),
        "n_rejected_by_envelope": rejected,
        "rejection_rate": (rejected / len(matched)) if matched else float("nan"),
        "matches": matched,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True,
                    help="results/run_YYYYMMDD_HHMMSS directory")
    ap.add_argument("--sessions", type=Path,
                    default=Path(__file__).parent / "selected_sessions.json")
    args = ap.parse_args()

    sessions = json.loads(args.sessions.read_text())
    envelopes_dir = args.run / "envelopes"

    per_session = []
    for sess in sessions:
        base = f"{sess['mcp_group']}__{sess['mcp_name']}__{sess['prompt_slug']}"
        env_path = envelopes_dir / f"{base}.json"
        if not env_path.exists():
            print(f"[skip] no envelope: {env_path}")
            continue
        env_wrap = json.loads(env_path.read_text())
        envelope = env_wrap["envelope"]
        if "_error" in envelope:
            print(f"[skip] error envelope: {base}")
            continue

        # Coverage on benign
        benign_events = list(iter_session_syscalls(Path(sess["benign_session_dir"])))
        cov_strict = evaluate_session(benign_events, envelope, strict=True)
        cov_nf = evaluate_session(benign_events, envelope, strict=False)

        # Rejection on each malicious variant
        rejections = []
        for m in sess["malicious"]:
            if not m.get("signature_path"):
                continue
            sig_preds = load_signature_syscalls(Path(m["signature_path"]))
            if not sig_preds:
                continue
            l3 = Path(m["session_dir"]) / "l3.jsonl"
            if not l3.exists():
                continue
            mal_events = list(iter_session_syscalls(Path(m["session_dir"])))
            rej_strict = evaluate_rejection(mal_events, envelope, sig_preds, strict=True)
            rej_nf = evaluate_rejection(mal_events, envelope, sig_preds, strict=False)
            rejections.append({
                "attack_slug": m["attack_slug"],
                "strict": rej_strict,
                "noise_floor": rej_nf,
            })

        per_session.append({
            "mcp_id": sess["mcp_id"],
            "prompt_slug": sess["prompt_slug"],
            "rationale": envelope.get("rationale", ""),
            "coverage_strict": {
                "coverage": cov_strict["coverage"],
                "inside": cov_strict["inside"],
                "outside": cov_strict["outside"],
                "outside_top_reasons": dict(Counter(
                    r for r, c in cov_strict["reason_counts"].items()
                    if r.endswith("out_of_envelope")
                )),
            },
            "coverage_noise_floor": {
                "coverage": cov_nf["coverage"],
                "inside": cov_nf["inside"],
                "outside": cov_nf["outside"],
                "outside_top_reasons": dict(Counter(
                    r for r, c in cov_nf["reason_counts"].items()
                    if r.endswith("out_of_envelope")
                )),
            },
            "rejections": rejections,
        })
        s_cov = cov_strict["coverage"]
        n_cov = cov_nf["coverage"]
        n_att = len(rejections)
        avg_rej_strict = (
            sum(r["strict"]["rejection_rate"] for r in rejections if r["strict"]["n_signature_matches"] > 0)
            / max(1, sum(1 for r in rejections if r["strict"]["n_signature_matches"] > 0))
        ) if rejections else float("nan")
        print(f"{base}: cov_strict={s_cov:.3f} cov_nf={n_cov:.3f} "
              f"attacks={n_att} avg_rej_strict={avg_rej_strict:.3f}")

    out_path = args.run / "evaluation.json"
    out_path.write_text(json.dumps(per_session, indent=2))
    print(f"\nwrote {out_path}")

    # Aggregate
    print("\n=== aggregate ===")
    n = len(per_session)
    if n:
        avg_strict = sum(p["coverage_strict"]["coverage"] for p in per_session) / n
        avg_nf = sum(p["coverage_noise_floor"]["coverage"] for p in per_session) / n
        print(f"  mean coverage (strict):      {avg_strict:.3f}")
        print(f"  mean coverage (noise-floor): {avg_nf:.3f}")

        # Rejection aggregated across all (session, attack) pairs where sig preds fired
        all_rej_s = []
        all_rej_n = []
        for p in per_session:
            for r in p["rejections"]:
                if r["strict"]["n_signature_matches"] > 0:
                    all_rej_s.append(r["strict"]["rejection_rate"])
                if r["noise_floor"]["n_signature_matches"] > 0:
                    all_rej_n.append(r["noise_floor"]["rejection_rate"])
        if all_rej_s:
            print(f"  mean rejection (strict):      {sum(all_rej_s)/len(all_rej_s):.3f}  "
                  f"({len(all_rej_s)} attack instances with matches)")
        if all_rej_n:
            print(f"  mean rejection (noise-floor): {sum(all_rej_n)/len(all_rej_n):.3f}  "
                  f"({len(all_rej_n)} attack instances with matches)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
