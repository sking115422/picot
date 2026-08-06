"""Generate envelopes for every unique (mcp, prompt_slug) key in the
full-corpus selection. Cached by key so one envelope covers all sessions
with the same driving intent.

Reuses the LLM machinery from generate_envelopes.py (v1/v5 prompts,
Bedrock client, envelope-JSON extraction).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import time
from pathlib import Path

from generate_envelopes import (
    build_system_prompt,
    call_bedrock,
    extract_envelope_json,
    load_prompt_text,
    load_mcp_tools_from_stream,
    read_bearer_token,
    resolve_model_id,
    DEFAULT_MODEL_ID,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", type=Path,
                    default=Path(__file__).parent / "full_corpus" / "envelope_keys.json")
    ap.add_argument("--style", choices=["v1", "v5", "v7"], default="v5")
    ap.add_argument("--model", default="opus",
                    help="Bedrock model alias (opus/sonnet/haiku) or full model id")
    ap.add_argument("--resume", action="store_true",
                    help="Skip keys already present in output dir")
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()

    model_id = resolve_model_id(args.model)
    model_tag = args.model.replace("/", "_").replace(".", "")

    keys = json.loads(args.keys.read_text())
    run_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + f"_full_{args.style}_{model_tag}"
    out_dir = args.out_dir or (Path(__file__).parent / "results" / f"run_{run_id}" / "envelopes")
    out_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = build_system_prompt(args.style)
    (out_dir.parent / "system_prompt.txt").write_text(system_prompt)
    (out_dir.parent / "model_id.txt").write_text(model_id + "\n")

    _, ts = read_bearer_token()
    print(f"Bedrock bearer token loaded — timestamp {ts}")
    print(f"style: {args.style}  model: {model_id}  n keys: {len(keys)}")
    print(f"out: {out_dir}")

    def key_filename(k: dict) -> str:
        # Sanitize mcp path for a filename
        mcp_safe = k["mcp"].replace("/", "__")
        return f"{mcp_safe}__{k['prompt_slug']}.json"

    n_done = 0
    n_skipped = 0
    for i, k in enumerate(keys, 1):
        out_file = out_dir / key_filename(k)
        if args.resume and out_file.exists():
            n_skipped += 1
            continue

        mcp = k["mcp"]
        prompt_slug = k["prompt_slug"]
        category = k.get("category")
        prompt_text = load_prompt_text(mcp, prompt_slug, category)
        mcp_tools = load_mcp_tools_from_stream(
            Path(k["representative_benign_dir"]),
            keep_builtin=k.get("is_ace_bi", False),
        )

        user_msg = (
            f"USER PROMPT:\n{prompt_text}\n\n"
            f"MCP TOOLS AVAILABLE (MCP: {mcp}):\n"
            f"{', '.join(mcp_tools) if mcp_tools else '(none listed)'}\n\n"
            f"Produce the envelope now as strict JSON."
        )

        print(f"[{i}/{len(keys)}] {mcp[:40]:<40s} {prompt_slug[:30]:<30s}")
        try:
            resp = call_bedrock(system_prompt, user_msg, model_id=model_id)
            envelope = extract_envelope_json(resp)
        except Exception as e:
            print(f"    ERROR: {e}")
            envelope = {"_error": str(e)}

        out_file.write_text(json.dumps({
            "mcp": mcp,
            "prompt_slug": prompt_slug,
            "category": category,
            "is_ace_bi": k.get("is_ace_bi", False),
            "prompt_text": prompt_text,
            "mcp_tools": mcp_tools,
            "envelope": envelope,
        }, indent=2))
        n_done += 1
        time.sleep(0.4)

    print(f"\nwrote {n_done} envelopes ({n_skipped} skipped, resume)")
    print(f"out: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
