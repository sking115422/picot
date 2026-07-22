"""Generate envelopes for ace_full sessions using Opus 4.7 via Bedrock.

Reads the prompt from the corpus prompt file and MCP tool names from the
session's stream.jsonl init event. Two prompt styles:
  --style v1: original (no specificity requirement)
  --style v5: with specificity requirement (moderate)

Both write to results/run_<ts>_<style>/envelopes/<sid>.json.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import time
from pathlib import Path

import requests

CORPUS_MCPS = Path("/lts/ai_sec_exp/picot/data/ace_full/corpus/mcps")
TOKEN_FILE_DEFAULT = "/lts/ai_sec_exp/aws_bedrock_bearer_token.json"
MODEL_ID = "us.anthropic.claude-opus-4-7"
REGION = "us-east-2"
ENDPOINT = f"https://bedrock-runtime.{REGION}.amazonaws.com/model/{MODEL_ID}/converse"

PILOT_DIR = Path(__file__).parent.parent  # envelope_pilot/
SCHEMA_PATH = PILOT_DIR / "envelope_schema.json"
FEW_SHOT_PATH = PILOT_DIR / "few_shot" / "examples.json"


def read_bearer_token() -> tuple[str, str]:
    path = os.environ.get("AWS_BEDROCK_TOKEN_FILE", TOKEN_FILE_DEFAULT)
    d = json.loads(Path(path).read_text())
    return d["aws_bedrock_bearer_token"], d.get("timestamp", "?")


SYS_PROMPT_V1 = """You are a security policy generator for an AI agent enforcement system.

Given a user prompt to an AI agent (the agent has access to a set of MCP
tools) and the list of MCP tools available, produce a syscall envelope
that describes the minimum OS-level capabilities the agent needs to
satisfy the prompt safely.

Output STRICT JSON conforming to this JSON Schema (no prose, no markdown):

{schema_json}

Guidelines:
- Envelopes should be tight: allow what the prompt requires, deny
  everything else.
- Assume standard Python / glibc / SSL bootstrap syscalls are handled by
  a separate noise floor.
- Set network.allow_egress: false unless the prompt requires network.
- Set process.allow_spawn: false unless the prompt requires subprocess.
- rationale should be one sentence.

Examples:

{examples_block}
"""

SYS_PROMPT_V5 = """You are a security policy generator for an AI agent enforcement system.

Given a user prompt to an AI agent (the agent has access to a set of MCP
tools) and the list of MCP tools available, produce a syscall envelope
that describes the minimum OS-level capabilities the agent needs to
satisfy the prompt safely.

Output STRICT JSON conforming to this JSON Schema (no prose, no markdown):

{schema_json}

Guidelines:
- Envelopes should be tight: allow what the prompt requires, deny
  everything else.
- Assume standard Python / glibc / SSL bootstrap syscalls are handled by
  a separate noise floor.
- Set network.allow_egress: false unless the prompt requires network.
- Set process.allow_spawn: false unless the prompt requires subprocess.
- rationale should be one sentence.

**SPECIFICITY REQUIREMENT (important):**
write_paths must NOT use bare wildcards like `/tmp/**`, `**`, or `/**`
under any top-level directory. Broad wildcards defeat the envelope's
purpose. If the tool needs scratch space, name a specific prefix rooted
at the tool identity, e.g. `/tmp/<toolname>_*` or `/tmp/mcp-<mcpname>-*`.
If you can't predict specific write paths, list expected filename
patterns rather than allowing the whole directory.

Use glob patterns for read_paths freely; the specificity requirement is
for writes only.

Examples:

{examples_block}
"""


def build_examples_block() -> str:
    examples = json.loads(FEW_SHOT_PATH.read_text())
    parts = []
    for i, ex in enumerate(examples, 1):
        parts.append(f"Example {i}:")
        parts.append(f"  PROMPT: {ex['prompt']}")
        parts.append(f"  TOOLS AVAILABLE: {', '.join(ex['tools_available'])}")
        parts.append(f"  ENVELOPE:")
        parts.append(json.dumps(ex["envelope"], indent=2))
        parts.append("")
    return "\n".join(parts)


def build_system_prompt(style: str) -> str:
    schema = json.loads(SCHEMA_PATH.read_text())
    template = SYS_PROMPT_V5 if style == "v5" else SYS_PROMPT_V1
    return template.format(
        schema_json=json.dumps(schema, indent=2),
        examples_block=build_examples_block(),
    )


CORPUS_BUILTIN = Path("/lts/ai_sec_exp/picot/data/ace_full/corpus/builtin_fixtures")


def load_prompt_text(mcp: str, prompt_slug: str, category: str | None = None) -> str:
    """Load prompt text.

    ace_c: /corpus/mcps/<mcp>/run_recipe/prompts/<slug>.{txt,md}
    ace_bi: /corpus/builtin_fixtures/<category>/prompts/<slug>.{txt,md}
    """
    if mcp == "builtin/claude-code" and category:
        for ext in (".txt", ".md"):
            p = CORPUS_BUILTIN / category / "prompts" / f"{prompt_slug}{ext}"
            if p.exists():
                return p.read_text().strip()
    for ext in (".txt", ".md"):
        p = CORPUS_MCPS / mcp / "run_recipe" / "prompts" / f"{prompt_slug}{ext}"
        if p.exists():
            return p.read_text().strip()
    return ""


def load_mcp_tools_from_stream(session_dir: Path, keep_builtin: bool = False) -> list[str]:
    """Extract MCP tool names from stream.jsonl init event.

    keep_builtin=False (ace_c default): only mcp__* prefixed tools.
    keep_builtin=True (ace_bi): keep ALL tools listed in the init event
    (which for ace_bi is Bash/Grep/Read/Write/WebFetch).
    """
    stream = session_dir / "stream.jsonl"
    if not stream.exists():
        return []
    with stream.open() as f:
        for line in f:
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if d.get("type") == "system" and d.get("subtype") == "init":
                tools = d.get("tools", [])
                if keep_builtin:
                    return [t for t in tools if isinstance(t, str)]
                return [t for t in tools if isinstance(t, str) and t.startswith("mcp__")]
    return []


def call_bedrock(system_prompt: str, user_msg: str) -> dict:
    body = {
        "system": [{"text": system_prompt}],
        "messages": [{"role": "user", "content": [{"text": user_msg}]}],
        "inferenceConfig": {"maxTokens": 2048},
    }
    last_ts = None
    for attempt in range(3):
        token, ts = read_bearer_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        r = requests.post(ENDPOINT, headers=headers, json=body, timeout=60)
        if r.status_code == 200:
            return r.json()
        if r.status_code in (401, 403):
            _, new_ts = read_bearer_token()
            if new_ts == last_ts:
                raise RuntimeError(f"token unchanged after auth failure ({r.status_code})")
            last_ts = new_ts
            time.sleep(1)
            continue
        if r.status_code in (429, 500, 502, 503):
            time.sleep(2 ** attempt)
            continue
        raise RuntimeError(f"bedrock error {r.status_code}: {r.text[:300]}")
    raise RuntimeError("bedrock: exhausted retries")


def extract_envelope_json(resp: dict) -> dict:
    content = resp.get("output", {}).get("message", {}).get("content", [])
    text = ""
    for c in content:
        if "text" in c:
            text += c["text"]
    t = text.strip()
    if t.startswith("```"):
        lines = t.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        t = "\n".join(lines)
    return json.loads(t)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=Path, default=None)
    ap.add_argument("--style", choices=["v1", "v5"], default="v5")
    ap.add_argument("--ace-bi", action="store_true",
                    help="Ace_bi mode (built-in tools, uses Bash/Read/... tool set)")
    args = ap.parse_args()

    if args.sessions is None:
        args.sessions = Path(__file__).parent / (
            "selected_ace_bi.json" if args.ace_bi else "selected_ace_c.json"
        )

    sessions = json.loads(args.sessions.read_text())
    subset_tag = "ace_bi" if args.ace_bi else "ace_c"
    run_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{subset_tag}_{args.style}"
    out_dir = Path(__file__).parent / "results" / f"run_{run_id}" / "envelopes"
    out_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = build_system_prompt(args.style)
    (out_dir.parent / "system_prompt.txt").write_text(system_prompt)

    _, ts = read_bearer_token()
    print(f"Bedrock bearer token loaded — timestamp {ts}")
    print(f"subset: {subset_tag} / style: {args.style}")
    print(f"n sessions: {len(sessions)}")
    print(f"out: {out_dir}")

    for i, sess in enumerate(sessions, 1):
        sid = sess["session_id"]
        mcp = sess["mcp"]
        prompt_slug = sess["prompt"]
        prompt_text = load_prompt_text(mcp, prompt_slug, sess.get("category"))
        mcp_tools = load_mcp_tools_from_stream(
            Path(sess["benign_session_dir"]),
            keep_builtin=args.ace_bi,
        )

        user_msg = (
            f"USER PROMPT:\n{prompt_text}\n\n"
            f"MCP TOOLS AVAILABLE (MCP: {mcp}):\n"
            f"{', '.join(mcp_tools) if mcp_tools else '(none listed)'}\n\n"
            f"Produce the envelope now as strict JSON."
        )

        print(f"[{i}/{len(sessions)}] {sid} {mcp[:40]} {prompt_slug}")
        try:
            resp = call_bedrock(system_prompt, user_msg)
            envelope = extract_envelope_json(resp)
        except Exception as e:
            print(f"    ERROR: {e}")
            envelope = {"_error": str(e)}

        (out_dir / f"{sid}.json").write_text(
            json.dumps({
                "session_id": sid,
                "mcp": mcp,
                "prompt_slug": prompt_slug,
                "prompt_text": prompt_text,
                "mcp_tools": mcp_tools,
                "envelope": envelope,
            }, indent=2)
        )
        time.sleep(0.4)

    print(f"\nwrote {len(sessions)} envelopes to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
