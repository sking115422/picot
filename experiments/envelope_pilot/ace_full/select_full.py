"""Select ALL usable (mcp, prompt) → paired sessions from ace_full for
the full-corpus v5 run.

Two outputs:
  1. envelope_keys.json — list of unique (mcp, prompt) tuples with
     one representative benign session_dir + prompt_text_path for the
     envelope generator to consume. Envelopes cached by these keys.
  2. session_pairs.json — full list of (benign_dir, malicious_dir,
     attack_metadata) pairs to evaluate. Each pair references its
     envelope_key.

Constraint: only include (mcp, prompt) where at least one benign
session AND at least one malicious_fired session exist.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

DEFAULT_ROOT = Path("/lts/ai_sec_exp/picot/data/ace_full/sessions")
CORPUS_MCPS = Path("/lts/ai_sec_exp/picot/data/ace_full/corpus/mcps")
CORPUS_BUILTIN = Path("/lts/ai_sec_exp/picot/data/ace_full/corpus/builtin_fixtures")


def load_meta(sd: Path) -> dict | None:
    sj = sd / "session.json"
    if not sj.exists():
        return None
    try:
        return json.loads(sj.read_text())
    except json.JSONDecodeError:
        return None


def prompt_text_path_for(mcp: str, prompt_slug: str, category: str | None) -> Path | None:
    if mcp == "builtin/claude-code" and category:
        for ext in (".txt", ".md"):
            p = CORPUS_BUILTIN / category / "prompts" / f"{prompt_slug}{ext}"
            if p.exists():
                return p
    for ext in (".txt", ".md"):
        p = CORPUS_MCPS / mcp / "run_recipe" / "prompts" / f"{prompt_slug}{ext}"
        if p.exists():
            return p
    return None


def signature_path_for(mcp: str, attack_slug: str) -> Path | None:
    p = CORPUS_MCPS / mcp / "run_recipe" / "malicious_patches" / attack_slug / "signature.json"
    return p if p.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--subset", choices=["ace_c", "ace_bi", "all"], default="all")
    ap.add_argument("--out-dir", type=Path,
                    default=Path(__file__).parent / "full_corpus")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    # First pass: group by (mcp, prompt) → all benign/fired sessions
    grouped: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"benign": [], "fired": [], "category": None})

    scanned = 0
    for sd in args.root.iterdir():
        if not sd.is_dir():
            continue
        d = load_meta(sd)
        if d is None:
            continue
        scanned += 1
        mcp = d.get("mcp") or ""
        prompt = d.get("prompt") or ""
        # Subset filter
        if args.subset == "ace_c" and mcp == "builtin/claude-code":
            continue
        if args.subset == "ace_bi" and mcp != "builtin/claude-code":
            continue

        key = (mcp, prompt)
        entry = {"session_id": d.get("session_id"), "path": str(sd),
                 "variant": d.get("variant"), "category": d.get("category"),
                 "gold_label": d.get("gold_label"),
                 "sentinels": d.get("session_sentinels") or {}}
        variant = d.get("variant") or ""
        if variant == "benign":
            grouped[key]["benign"].append(entry)
        elif variant.startswith("malicious") and d.get("gold_label") == "malicious_fired":
            grouped[key]["fired"].append(entry)
        if grouped[key]["category"] is None:
            grouped[key]["category"] = d.get("category")

    print(f"[full-select] scanned {scanned} sessions ({args.subset})")

    # Filter to keys with both benign and fired
    usable = {k: v for k, v in grouped.items() if v["benign"] and v["fired"]}
    print(f"[full-select] usable (mcp, prompt) tuples: {len(usable)}")

    # Build envelope_keys.json: one per (mcp, prompt), pick first benign
    envelope_keys = []
    for (mcp, prompt), v in usable.items():
        benign = v["benign"][0]
        # Category for this key — from any session
        cat = v["category"]
        prompt_path = prompt_text_path_for(mcp, prompt, cat)
        envelope_keys.append({
            "mcp": mcp,
            "prompt_slug": prompt,
            "category": cat,
            "is_ace_bi": mcp == "builtin/claude-code",
            "prompt_text_path": str(prompt_path) if prompt_path else None,
            "representative_benign_dir": benign["path"],
            "n_benign_sessions": len(v["benign"]),
            "n_fired_sessions": len(v["fired"]),
        })

    # Build session_pairs.json: for each (mcp, prompt), each fired variant
    # pairs with the first benign of that key (cheapest matching). Also
    # emit attack metadata (sentinels for ace_bi, attack_slug + signature
    # path for ace_c).
    session_pairs = []
    for (mcp, prompt), v in usable.items():
        benign = v["benign"][0]
        for m in v["fired"]:
            entry = {
                "envelope_key": {"mcp": mcp, "prompt_slug": prompt},
                "benign_session_dir": benign["path"],
                "benign_session_id": benign["session_id"],
                "malicious_session_dir": m["path"],
                "malicious_session_id": m["session_id"],
                "variant": m["variant"],
                "category": m["category"],
                "is_ace_bi": mcp == "builtin/claude-code",
                "session_sentinels": m["sentinels"],
            }
            if mcp != "builtin/claude-code":
                v_str = m["variant"] or ""
                attack_slug = v_str.split(":", 1)[1] if ":" in v_str else None
                entry["attack_slug"] = attack_slug
                sig = signature_path_for(mcp, attack_slug) if attack_slug else None
                entry["signature_path"] = str(sig) if sig else None
            session_pairs.append(entry)

    (args.out_dir / "envelope_keys.json").write_text(json.dumps(envelope_keys, indent=2))
    (args.out_dir / "session_pairs.json").write_text(json.dumps(session_pairs, indent=2))

    print(f"[full-select] wrote {len(envelope_keys)} envelope keys → envelope_keys.json")
    print(f"[full-select] wrote {len(session_pairs)} session pairs → session_pairs.json")

    # Show a summary
    ace_c_keys = sum(1 for k in envelope_keys if not k["is_ace_bi"])
    ace_bi_keys = sum(1 for k in envelope_keys if k["is_ace_bi"])
    ace_c_pairs = sum(1 for p in session_pairs if not p["is_ace_bi"])
    ace_bi_pairs = sum(1 for p in session_pairs if p["is_ace_bi"])
    print(f"\n  ace_c: {ace_c_keys} keys / {ace_c_pairs} session pairs")
    print(f"  ace_bi: {ace_bi_keys} keys / {ace_bi_pairs} session pairs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
