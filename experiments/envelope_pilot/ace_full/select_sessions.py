"""Select ace_full sessions for envelope-pilot evaluation.

ace_full layout is flat: `sessions/<sid>/{session.json, strace/, stream.jsonl, ...}`.
We pair benign+malicious variants by (mcp, prompt) and require:
  1. Both a benign and a malicious variant exist for this (mcp, prompt)
  2. The malicious variant has `gold_label == "malicious_fired"` (attack
     actually executed in this session — otherwise there's nothing to reject)
  3. At least one session_sentinel value appears in the malicious session's
     strace log (ground-truth check that the sentinel is a real IOC in this run)

Diversity selection: greedy pick to maximize coverage across attack
categories, threat_models, and MCPs.

Output: JSON list with fields:
  - session_id, mcp, prompt, category, threat_model, gold_label
  - benign_session_dir, malicious_session_dir
  - session_sentinels (from malicious session.json)
  - is_ace_bi (True if mcp == "builtin/claude-code")
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

DEFAULT_ROOT = Path("/lts/ai_sec_exp/picot/data/ace_full/sessions")
CORPUS_MCPS = Path("/lts/ai_sec_exp/picot/data/ace_full/corpus/mcps")


def walk_syscall_predicates(node):
    """Yield l1_syscall predicates from an ace_c signature's `predicates`."""
    if isinstance(node, dict):
        if node.get("kind") == "l1_syscall":
            yield node
            return
        for k in ("any", "all", "not"):
            if k in node:
                yield from walk_syscall_predicates(node[k])
    elif isinstance(node, list):
        for x in node:
            yield from walk_syscall_predicates(x)


def load_ace_c_signature(mcp: str, attack_slug: str) -> dict | None:
    """Load signature.json for an ace_c attack from corpus/mcps/."""
    sig_path = CORPUS_MCPS / mcp / "run_recipe" / "malicious_patches" / attack_slug / "signature.json"
    if not sig_path.exists():
        return None
    try:
        return json.loads(sig_path.read_text())
    except json.JSONDecodeError:
        return None


def event_matches_ace_c_predicate(event_line: str, pred: dict) -> bool:
    """Cheap substring-based match against a raw strace line.
    Fires if the line contains the syscall name AND the path_contains
    substring (if any). Purposely loose — for candidate selection only.
    """
    sc = pred.get("syscall")
    if not sc or sc not in event_line:
        return False
    if "path_contains" in pred:
        if pred["path_contains"] not in event_line:
            return False
    if "path_starts_with" in pred:
        if pred["path_starts_with"] not in event_line:
            return False
    return True


def load_session_meta(sd: Path) -> dict | None:
    sj = sd / "session.json"
    if not sj.exists():
        return None
    try:
        return json.loads(sj.read_text())
    except json.JSONDecodeError:
        return None


def strace_path_for(sd: Path) -> Path | None:
    strace_dir = sd / "strace"
    if not strace_dir.exists():
        return None
    files = list(strace_dir.glob("*.strace.log"))
    return files[0] if files else None


def sentinels_fire_in_strace(sd: Path, sentinels: dict) -> tuple[bool, dict]:
    """Return (any_fired, per_sentinel_hits). Only checks distinctive
    sentinel values (paths, hosts, IPs) — not raw token strings which
    might appear coincidentally in the strace log's binary data."""
    strace = strace_path_for(sd)
    if not strace or not sentinels:
        return False, {}
    try:
        content = strace.read_text(errors="replace")
    except Exception:
        return False, {}
    hits = {}
    for k, v in sentinels.items():
        if k in ("token", "url_token"):
            continue  # noise-prone
        if not isinstance(v, str) or not v:
            continue
        hits[k] = content.count(v)
    return any(c > 0 for c in hits.values()), hits


def ace_c_signature_fires_in_strace(sd: Path, mcp: str, attack_slug: str) -> tuple[bool, dict]:
    """For ace_c: does the attack's signature.json actually fire in this
    malicious session's strace log?

    Loose match: substring on raw strace line. Good enough for candidate
    selection. Precise evaluation happens later.
    """
    sig = load_ace_c_signature(mcp, attack_slug)
    if sig is None:
        return False, {"reason": "no_signature"}
    preds = list(walk_syscall_predicates(sig.get("predicates")))
    if not preds:
        return False, {"reason": "no_l1_predicates"}

    strace = strace_path_for(sd)
    if not strace:
        return False, {"reason": "no_strace"}
    try:
        lines = strace.read_text(errors="replace").splitlines()
    except Exception:
        return False, {"reason": "read_failed"}

    total_hits = 0
    for line in lines:
        for pred in preds:
            if event_matches_ace_c_predicate(line, pred):
                total_hits += 1
                break
    return total_hits > 0, {"predicates": preds, "total_hits": total_hits}


def gather_candidates(root: Path, subset: str) -> list[dict]:
    """Group sessions by (mcp, prompt); pair benign+malicious_fired."""
    by_key: dict[tuple[str, str], dict] = defaultdict(lambda: {"benign": [], "malicious": []})

    total = 0
    for sd in root.iterdir():
        if not sd.is_dir():
            continue
        d = load_session_meta(sd)
        if d is None:
            continue
        total += 1
        mcp = d.get("mcp", "")
        # Subset filter
        if subset == "ace_c" and mcp == "builtin/claude-code":
            continue
        if subset == "ace_bi" and mcp != "builtin/claude-code":
            continue

        key = (mcp, d.get("prompt", ""))
        variant = d.get("variant", "")
        if variant == "benign":
            by_key[key]["benign"].append((sd, d))
        elif variant.startswith("malicious") and d.get("gold_label") == "malicious_fired":
            by_key[key]["malicious"].append((sd, d))

    print(f"[select] scanned {total} sessions (subset={subset})")

    is_ace_bi_subset = (subset == "ace_bi")
    candidates: list[dict] = []
    for (mcp, prompt), variants in by_key.items():
        if not variants["benign"] or not variants["malicious"]:
            continue
        b_sd, b_meta = variants["benign"][0]
        for m_sd, m_meta in variants["malicious"]:
            entry = {
                "session_id": m_meta.get("session_id"),
                "mcp": mcp,
                "prompt": prompt,
                "category": m_meta.get("category"),
                "threat_model": m_meta.get("threat_model"),
                "gold_label": m_meta.get("gold_label"),
                "variant": m_meta.get("variant"),
                "benign_session_dir": str(b_sd),
                "malicious_session_dir": str(m_sd),
                "is_ace_bi": mcp == "builtin/claude-code",
            }
            # Route to sentinel or signature check
            if entry["is_ace_bi"]:
                # For ace_bi we trust gold_label=='malicious_fired' as the
                # firing signal (the corpus authors already decided). We
                # DON'T require sentinels-in-strace because attacks like
                # file_bash_injection touch paths like `/tmp/<token>.stamp`
                # which don't match the canonical sentinel `write_path`.
                sentinels = m_meta.get("session_sentinels") or {}
                _, hits = sentinels_fire_in_strace(m_sd, sentinels)
                entry["session_sentinels"] = sentinels
                entry["sentinel_hits_in_strace"] = hits
            else:
                # ace_c: pull attack slug from variant string
                v = m_meta.get("variant", "")
                if ":" in v:
                    attack_slug = v.split(":", 1)[1]
                else:
                    patches = m_meta.get("patches_applied") or []
                    attack_slug = patches[0] if patches else None
                if not attack_slug:
                    continue
                fired, info = ace_c_signature_fires_in_strace(m_sd, mcp, attack_slug)
                if not fired:
                    continue
                entry["attack_slug"] = attack_slug
                entry["signature_hits_in_strace"] = info.get("total_hits", 0)
                sig_path = CORPUS_MCPS / mcp / "run_recipe" / "malicious_patches" / attack_slug / "signature.json"
                entry["signature_path"] = str(sig_path) if sig_path.exists() else None
            candidates.append(entry)
    return candidates


def diverse_pick(candidates: list[dict], target: int, per_key_cap: int | None = None) -> list[dict]:
    """Greedy diversified pick.

    Diversity key = (category|attack_slug, mcp).
    - per_key_cap=None (default): pass 1 picks one per key, pass 2 fills.
      Good when many MCPs × many categories exist (ace_c).
    - per_key_cap=N: cap per-key at N. Good when diversity is dominated
      by one key (ace_bi has only one MCP; balance across categories).
    """
    if not candidates:
        return []

    def signal_strength(c):
        if c.get("is_ace_bi"):
            return sum(v for k, v in c.get("sentinel_hits_in_strace", {}).items()
                       if k not in ("token", "url_token"))
        return c.get("signature_hits_in_strace", 0)

    candidates = sorted(candidates, key=lambda c: -signal_strength(c))

    def diversity_key(c):
        return (c.get("category") or c.get("attack_slug"), c["mcp"])

    if per_key_cap is not None:
        counts: dict[tuple, int] = {}
        selected = []
        for c in candidates:
            k = diversity_key(c)
            if counts.get(k, 0) >= per_key_cap:
                continue
            counts[k] = counts.get(k, 0) + 1
            selected.append(c)
            if len(selected) >= target:
                return selected
        return selected

    seen = set()
    selected: list[dict] = []
    for c in candidates:
        k = diversity_key(c)
        if k in seen:
            continue
        seen.add(k)
        selected.append(c)
        if len(selected) >= target:
            return selected

    used_sids = {c["session_id"] for c in selected}
    for c in candidates:
        if c["session_id"] in used_sids:
            continue
        selected.append(c)
        used_sids.add(c["session_id"])
        if len(selected) >= target:
            break
    return selected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--subset", choices=["ace_c", "ace_bi", "all"], default="ace_c")
    ap.add_argument("--target", type=int, default=50)
    ap.add_argument("--per-key-cap", type=int, default=None,
                    help="Cap picks per (category, mcp) key (useful for ace_bi)")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    candidates = gather_candidates(args.root, args.subset)
    print(f"[select] viable candidates (paired + fired + sentinel-observed): {len(candidates)}")

    picked = diverse_pick(candidates, args.target, per_key_cap=args.per_key_cap)

    out = args.out or Path(__file__).parent / f"selected_{args.subset}.json"
    out.write_text(json.dumps(picked, indent=2))

    print(f"[select] picked {len(picked)}:")
    for c in picked:
        cat = c.get("category") or c.get("attack_slug") or c.get("threat_model", "?")
        if c.get("is_ace_bi"):
            hits = sum(v for k, v in c.get("sentinel_hits_in_strace", {}).items()
                       if k not in ("token", "url_token"))
        else:
            hits = c.get("signature_hits_in_strace", 0)
        print(f"  [{hits:>4}] {c['mcp'][:38]:<38s} {c['prompt'][:28]:<28s} cat={cat}")

    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
