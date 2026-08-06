"""
batch_replay.py — run replay_attack over a list of sessions and aggregate.

Input: a JSON file with the same shape as
picot/experiments/envelope_pilot/ace_full/full_corpus/session_pairs.json,
plus a directory containing envelopes named
<mcp_slashes_to_underscores>__<prompt_slug>.json.

Output: one JSON record per session, plus a summary at the end.

Usage:
  python batch_replay.py \\
     --pairs picot/experiments/envelope_pilot/ace_full/full_corpus/session_pairs.json \\
     --envelopes-dir picot/experiments/envelope_pilot/ace_full/results/run_..._full_v5/envelopes \\
     --out picot/experiments/enforcement/results/<run_name>.json \\
     [--limit 10] [--only-malicious]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from replay_attack import (  # noqa: E402
    run_replay, DEFAULT_IMAGE, PICOT_ROOT,
)


def envelope_key_to_filename(mcp: str, prompt_slug: str) -> str:
    return f"{mcp.replace('/', '__')}__{prompt_slug}.json"


def load_pairs(pairs_json: Path) -> list[dict]:
    with open(pairs_json) as f:
        return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", required=True)
    ap.add_argument("--envelopes-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only-malicious", action="store_true",
                     help="run only sessions with variant=='malicious'")
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--sentinel-mode",
                     choices=["original", "plausible"], default="original",
                     help="Reposition sentinels into plausible namespaces "
                          "(see replay_attack.reposition_sentinels).")
    ap.add_argument("--sessions-root", default=None,
                     help="override the sessions root; default derives from "
                          "the pairs file's benign_session_dir")
    args = ap.parse_args()

    pairs_path = Path(args.pairs)
    env_dir = Path(args.envelopes_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pairs = load_pairs(pairs_path)
    if args.only_malicious:
        pairs = [p for p in pairs
                 if (p.get("variant") or "").startswith("malicious")]
    if args.limit:
        pairs = pairs[: args.limit]

    print(f"[batch] running {len(pairs)} sessions", file=sys.stderr)

    results = []
    stats = {
        "n_total": 0,
        "n_ok": 0,
        "n_failed": 0,
        "write_fired": 0,
        "exfil_fired": 0,
        "cred_read": 0,
        "any_kernel_fired": 0,
        "attack_stopped": 0,
        "envelope_missing": 0,
        "session_missing": 0,
    }
    # Per primary_signal partition ({KERNEL, APP, BOTH, None}).
    # We split into two sub-buckets:
    #   - kernel_testable: kernel_paths is non-empty (the attack has at
    #     least one kernel-visible side effect the envelope can be asked
    #     to block).
    #   - not_kernel_testable: kernel_paths empty — the attack is app-
    #     layer only. Kernel enforcement cannot help here by construction.
    by_signal: dict[str, dict[str, int]] = {}

    def _bucket(sig: str | None) -> dict[str, int]:
        key = sig or "ACE_BI"
        return by_signal.setdefault(key, {
            "n": 0,
            "n_kernel_testable": 0,
            "attack_stopped": 0,
            "attack_stopped_kt": 0,   # stopped among kernel_testable
            "any_kernel_fired": 0,
        })

    t0 = time.time()
    for i, pair in enumerate(pairs):
        session_id = pair.get("malicious_session_id") or \
                     pair.get("benign_session_id")
        env_key = pair.get("envelope_key", {})
        mcp = env_key.get("mcp", "")
        slug = env_key.get("prompt_slug", "")
        env_filename = envelope_key_to_filename(mcp, slug)
        env_path = env_dir / env_filename

        session_dir = pair.get("malicious_session_dir") or \
                      pair.get("benign_session_dir")
        session_json = Path(session_dir) / "session.json"

        rec = {
            "session_id": session_id,
            "envelope_key": env_key,
            "variant": pair.get("variant"),
            "category": pair.get("category"),
        }
        stats["n_total"] += 1

        if not env_path.exists():
            rec["error"] = f"envelope missing: {env_path}"
            stats["envelope_missing"] += 1
            stats["n_failed"] += 1
            results.append(rec)
            continue
        if not session_json.exists():
            rec["error"] = f"session missing: {session_json}"
            stats["session_missing"] += 1
            stats["n_failed"] += 1
            results.append(rec)
            continue

        print(f"[batch] {i+1}/{len(pairs)} {session_id} "
              f"({mcp}/{slug})", file=sys.stderr)
        try:
            r = run_replay(session_json, env_path, args.image,
                            signature_path=pair.get("signature_path"),
                            sentinel_mode=args.sentinel_mode)
            rec.update(asdict(r))
            # Strip the noisy full stderr; keep denial summary only.
            rec.pop("stdout_tail", None)
            rec.pop("stderr_tail", None)
            stats["n_ok"] += 1
            if r.sentinel_write_fired: stats["write_fired"] += 1
            if r.sentinel_exfil_fired: stats["exfil_fired"] += 1
            if r.sentinel_cred_read: stats["cred_read"] += 1
            if r.any_kernel_fired:
                stats["any_kernel_fired"] += 1
            if r.attack_stopped:
                stats["attack_stopped"] += 1
            b = _bucket(r.primary_signal)
            b["n"] += 1
            b["attack_stopped"] += int(r.attack_stopped)
            b["any_kernel_fired"] += int(r.any_kernel_fired)
            # kernel_testable: has at least one kernel-visible sentinel path.
            kt = bool(r.kernel_paths)
            if kt:
                b["n_kernel_testable"] += 1
                b["attack_stopped_kt"] += int(r.attack_stopped)
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"exception: {e!r}"
            stats["n_failed"] += 1

        results.append(rec)

    stats["elapsed_s"] = time.time() - t0

    out = {"stats": stats, "by_primary_signal": by_signal, "results": results}
    out_path.write_text(json.dumps(out, indent=2))
    print(f"[batch] wrote {out_path}", file=sys.stderr)

    print("--- summary ---", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k}: {v}", file=sys.stderr)
    print("--- by primary_signal (all sessions / kernel-testable only) ---",
          file=sys.stderr)
    for k, v in by_signal.items():
        n = v["n"]
        stopped = v["attack_stopped"]
        rate = (stopped / n) if n else 0
        nkt = v["n_kernel_testable"]
        stopped_kt = v["attack_stopped_kt"]
        rate_kt = (stopped_kt / nkt) if nkt else 0
        print(f"  {k}: all {stopped}/{n} ({rate:.1%}); "
              f"kernel-testable {stopped_kt}/{nkt} ({rate_kt:.1%})",
              file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
