"""Pick 10 diverse benign+malicious pairs where the malicious variant is
KERNEL-primary AND its l1_syscall predicates actually fire in the trace.

This is the discriminating criterion the diverse-spread pilot lacked:
we require the trace to *actually contain* the signature's kernel-visible
events, otherwise there's nothing to reject.

Diversity axes:
  - Attack category (silent_exfil, credential_theft, command_injection,
    resource_exhaustion, log_poisoning, path_redirect, tool_chain_pollution)
  - MCP group (anthropic_ref_servers, anthropic_awesome_mcp_servers,
    rand_github)
  - Tool type (file, exec, net, db)

We iterate through KERNEL-primary attacks, verify signature-matches on
their trace, then greedy-pick to maximize coverage across the axes.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

CORPUS_MCPS = Path("/lts/ai_sec_exp/cle4as_int/data/corpus/mcps")
SESSIONS = Path("/lts/ai_sec_exp/cle4as_int/data/sessions")


def walk_syscall_predicates(node):
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


def count_signature_matches(mal_session_dir: Path, preds: list[dict]) -> int:
    l3 = mal_session_dir / "l3.jsonl"
    if not l3.exists():
        return 0
    matches = 0
    with l3.open() as fp:
        for line in fp:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if any(event_matches_predicate(event, p) for p in preds):
                matches += 1
    return matches


def find_paired_prompts_with_variant(mcp_group: str, mcp_name: str, attack_slug: str) -> list[dict]:
    """All prompt dirs under this MCP where both `benign/` and
    `malicious-<attack_slug>/` exist."""
    mcp_sess = SESSIONS / mcp_group / mcp_name
    out = []
    if not mcp_sess.exists():
        return out
    for prompt_dir in sorted(mcp_sess.iterdir()):
        if not prompt_dir.is_dir():
            continue
        benign = prompt_dir / "benign"
        mal = prompt_dir / f"malicious-{attack_slug}"
        if benign.exists() and mal.exists():
            out.append({"prompt_dir": prompt_dir, "benign_dir": benign, "mal_dir": mal})
    return out


def prompt_text_for(mcp_group, mcp_name, prompt_file):
    p = CORPUS_MCPS / mcp_group / mcp_name / "run_recipe" / "prompts" / prompt_file
    return p if p.exists() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "selected_kernel_sessions.json")
    ap.add_argument("--target-count", type=int, default=10)
    args = ap.parse_args()

    # Step 1: enumerate KERNEL-primary attacks with syscall preds
    candidates = []  # dicts with all we need
    for sig_path in CORPUS_MCPS.glob("*/*/run_recipe/malicious_patches/*/signature.json"):
        try:
            sig = json.loads(sig_path.read_text())
        except Exception:
            continue
        if sig.get("primary_signal") != "KERNEL":
            continue
        preds = list(walk_syscall_predicates(sig.get("predicates")))
        if not preds:
            continue

        parts = sig_path.relative_to(CORPUS_MCPS).parts
        mcp_group = parts[0]
        mcp_name = parts[1]
        attack_slug = parts[4]
        category = sig.get("category", "unknown")

        # Step 2: for each prompt with this attack, count signature matches
        paired = find_paired_prompts_with_variant(mcp_group, mcp_name, attack_slug)
        for p in paired:
            n_matches = count_signature_matches(p["mal_dir"], preds)
            if n_matches < 1:
                continue

            b_sess = json.loads((p["benign_dir"] / "session.json").read_text())
            prompt_file = b_sess.get("prompt_file")
            prompt_text_path = prompt_text_for(mcp_group, mcp_name, prompt_file)

            candidates.append({
                "mcp_group": mcp_group,
                "mcp_name": mcp_name,
                "mcp_id": f"{mcp_group}/{mcp_name}",
                "attack_slug": attack_slug,
                "attack_category": category,
                "n_signature_matches": n_matches,
                "prompt_dir": str(p["prompt_dir"]),
                "prompt_slug": p["prompt_dir"].name,
                "prompt_file": prompt_file,
                "prompt_text_path": str(prompt_text_path) if prompt_text_path else None,
                "benign_session_dir": str(p["benign_dir"]),
                "benign_session_id": b_sess.get("session_id"),
                "malicious_session_dir": str(p["mal_dir"]),
                "signature_path": str(sig_path),
            })

    print(f"total viable candidates (KERNEL attack + trace has matches): {len(candidates)}")
    if not candidates:
        print("no candidates!")
        return 1

    # Step 3: greedy diverse selection maximizing (category, mcp_group, mcp_id)
    # coverage.
    seen_cats: set[str] = set()
    seen_mcps: set[str] = set()
    selected = []

    # Sort candidates so higher-signal (more matches) comes first as tiebreak
    candidates.sort(key=lambda c: -c["n_signature_matches"])

    # Pass 1: one attack per (category, mcp_id) — force diversity
    for c in candidates:
        key = (c["attack_category"], c["mcp_id"])
        if c["attack_category"] in seen_cats and c["mcp_id"] in seen_mcps:
            continue
        seen_cats.add(c["attack_category"])
        seen_mcps.add(c["mcp_id"])
        selected.append(c)
        if len(selected) >= args.target_count:
            break

    # Pass 2: if we didn't hit target, fill with high-match remaining
    if len(selected) < args.target_count:
        used = {(c["mcp_id"], c["attack_slug"], c["prompt_slug"]) for c in selected}
        for c in candidates:
            k = (c["mcp_id"], c["attack_slug"], c["prompt_slug"])
            if k in used:
                continue
            selected.append(c)
            used.add(k)
            if len(selected) >= args.target_count:
                break

    args.out.write_text(json.dumps(selected, indent=2))
    print(f"\nselected {len(selected)}:")
    for s in selected:
        print(f"  [{s['n_signature_matches']:>3}] {s['mcp_id']:60s} "
              f"prompt={s['prompt_slug']:<30s} attack={s['attack_slug']:<30s} "
              f"cat={s['attack_category']}")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
