"""Pick 10 diverse (benign, malicious) session pairs from ACE-C.

Diversity axis: MCP identity. We spread across all three top-level MCP
groups (anthropic_ref_servers, anthropic_awesome_mcp_servers, rand_github)
and across tool categories (file-heavy, network-heavy, database, exec,
etc.). Within each MCP we pick the first prompt where both a benign and
some malicious variant exist.

Writes: selected_sessions.json — list of dicts with everything downstream
scripts need (session paths, prompt path, malicious signature path).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

CORPUS_MCPS = Path("/lts/ai_sec_exp/cle4as_int/data/corpus/mcps")
SESSIONS = Path("/lts/ai_sec_exp/cle4as_int/data/sessions")

# Hand-picked diverse set. Rationale in comment per MCP.
# Format: (group, mcp) — the code finds the first well-paired prompt.
DIVERSE_TARGETS = [
    ("anthropic_ref_servers", "filesystem"),      # file-heavy, canonical
    ("anthropic_ref_servers", "git"),             # exec-heavy (git subprocesses)
    ("anthropic_ref_servers", "postgres"),        # network + database
    ("anthropic_ref_servers", "time"),            # narrow tool, minimal side-effects
    ("anthropic_ref_servers", "everything"),      # varied echo/output tools
    ("anthropic_awesome_mcp_servers", "bytebase__dbhub"),           # 3rd-party DB
    ("anthropic_awesome_mcp_servers", "aws-documentation-mcp-server"),  # network fetch
    ("rand_github", "chroma-core__chroma-mcp"),   # vector DB, mixed I/O
    ("rand_github", "tufantunc__ssh-mcp"),        # SSH — network + exec
    ("rand_github", "zcaceres__fetch-mcp"),       # HTTP fetch
]


def find_first_paired_prompt(mcp_sessions: Path) -> tuple[Path, list[Path]] | None:
    """First prompt dir under mcp_sessions with both a benign/ and >=1 malicious-*.

    Returns (prompt_dir, [benign_dir, *malicious_dirs]) or None.
    """
    for prompt_dir in sorted(mcp_sessions.iterdir()):
        if not prompt_dir.is_dir():
            continue
        variants = list(prompt_dir.iterdir())
        benign = next((v for v in variants if v.is_dir() and v.name == "benign"), None)
        malicious = [
            v for v in variants if v.is_dir() and v.name.startswith("malicious-")
        ]
        if benign and malicious:
            return prompt_dir, [benign, *malicious]
    return None


def signature_for(mcp_group: str, mcp_name: str, attack_slug: str) -> Path | None:
    """Locate the malicious patch signature.json for a given attack."""
    p = CORPUS_MCPS / mcp_group / mcp_name / "run_recipe" / "malicious_patches" / attack_slug / "signature.json"
    return p if p.exists() else None


def prompt_text_for(mcp_group: str, mcp_name: str, prompt_file: str) -> Path | None:
    p = CORPUS_MCPS / mcp_group / mcp_name / "run_recipe" / "prompts" / prompt_file
    return p if p.exists() else None


def collect_tool_schemas(mcp_group: str, mcp_name: str) -> dict:
    """Extract MCP tool schemas from a benign session's stream.jsonl init event.

    The tools list comes from the Claude init event; per-MCP tool details
    (name + input schema) live in tool_use blocks. For a blind envelope
    we only need to name the tools; deeper schema retrieval can come
    later if the pilot decides it's needed.
    """
    # Placeholder — schemas are extracted downstream from stream.jsonl.
    # Here we just return the MCP identifier so downstream can locate it.
    return {"mcp": f"{mcp_group}/{mcp_name}"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=Path(__file__).parent / "selected_sessions.json")
    args = ap.parse_args()

    selected = []
    for group, mcp in DIVERSE_TARGETS:
        mcp_sess_dir = SESSIONS / group / mcp
        if not mcp_sess_dir.exists():
            print(f"[skip] no sessions dir for {group}/{mcp}")
            continue
        found = find_first_paired_prompt(mcp_sess_dir)
        if not found:
            print(f"[skip] no paired prompt under {group}/{mcp}")
            continue
        prompt_dir, variant_dirs = found
        benign_dir = variant_dirs[0]
        malicious_dirs = variant_dirs[1:]

        # Load benign session.json to get prompt_file
        b_session = json.loads((benign_dir / "session.json").read_text())
        prompt_file = b_session.get("prompt_file")
        prompt_text_path = prompt_text_for(group, mcp, prompt_file) if prompt_file else None

        entry = {
            "mcp_group": group,
            "mcp_name": mcp,
            "mcp_id": f"{group}/{mcp}",
            "prompt_dir": str(prompt_dir),
            "prompt_slug": prompt_dir.name,
            "prompt_file": prompt_file,
            "prompt_text_path": str(prompt_text_path) if prompt_text_path else None,
            "benign_session_dir": str(benign_dir),
            "benign_session_id": b_session.get("session_id"),
            "malicious": [],
        }

        for m_dir in malicious_dirs:
            attack_slug = m_dir.name.removeprefix("malicious-")
            m_session_path = m_dir / "session.json"
            m_session = json.loads(m_session_path.read_text()) if m_session_path.exists() else {}
            sig = signature_for(group, mcp, attack_slug)
            entry["malicious"].append({
                "attack_slug": attack_slug,
                "session_dir": str(m_dir),
                "session_id": m_session.get("session_id"),
                "signature_path": str(sig) if sig else None,
            })

        selected.append(entry)
        print(f"[ok] {group}/{mcp} :: prompt={prompt_dir.name} malicious={len(malicious_dirs)}")

    args.out.write_text(json.dumps(selected, indent=2))
    print(f"\nwrote {len(selected)} entries → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
