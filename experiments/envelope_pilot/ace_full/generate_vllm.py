"""Generate envelopes for all (mcp, prompt_slug) keys using a local
vllm-backed open-weight model.

Parallel to generate_full.py but replaces the Bedrock HTTP client with
in-process vllm.LLM.generate() over a batched prompt list. Reuses the
same v1/v5/v7 system prompt templates, JSON extraction, and file naming.

Usage:
  python generate_vllm.py \\
    --model Qwen/Qwen3-32B-FP8 --model-tag qwen3-32b-fp8 \\
    --style v5 --tp 1

The output dir is results/run_<ts>_full_<style>_<model_tag>/envelopes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from pathlib import Path

# Reuse prompt-building + extraction machinery from the Bedrock path.
sys.path.insert(0, str(Path(__file__).parent))
from generate_envelopes import (  # noqa: E402
    build_system_prompt,
    extract_envelope_json,
    load_prompt_text,
    load_mcp_tools_from_stream,
)


def render_prompts(system_prompt: str, user_msgs: list[str], tokenizer,
                     disable_thinking: bool = True) -> list[str]:
    """Wrap each user message in the model's chat template.

    For Qwen3 hybrid-thinking models, disable_thinking=True passes
    enable_thinking=False so the model skips the <think>...</think>
    block and emits JSON immediately, avoiding truncation."""
    rendered = []
    for um in user_msgs:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": um},
        ]
        kwargs = {"tokenize": False, "add_generation_prompt": True}
        # Only Qwen3's chat template accepts enable_thinking.
        if disable_thinking:
            try:
                out = tokenizer.apply_chat_template(
                    messages, enable_thinking=False, **kwargs)
            except (TypeError, ValueError):
                out = tokenizer.apply_chat_template(messages, **kwargs)
        else:
            out = tokenizer.apply_chat_template(messages, **kwargs)
        rendered.append(out)
    return rendered


def build_user_msg(prompt_text: str, mcp: str, mcp_tools: list[str]) -> str:
    return (
        f"USER PROMPT:\n{prompt_text}\n\n"
        f"MCP TOOLS AVAILABLE (MCP: {mcp}):\n"
        f"{', '.join(mcp_tools) if mcp_tools else '(none listed)'}\n\n"
        f"Produce the envelope now as strict JSON."
    )


def key_filename(k: dict) -> str:
    mcp_safe = k["mcp"].replace("/", "__")
    return f"{mcp_safe}__{k['prompt_slug']}.json"


def extract_envelope_from_text(text: str) -> dict:
    """Tolerant extractor for open-weight outputs.

    Handles:
      - <think>...</think> reasoning blocks (Qwen3, DeepSeek-R1 style)
      - Markdown ``` fences
      - Fallback to first {...} block
    """
    t = text.strip()
    # Strip <think>...</think> if closed. If unclosed (out of tokens
    # during thinking), the whole thing is unusable so we'll still
    # error below.
    if "<think>" in t and "</think>" in t:
        end = t.rindex("</think>") + len("</think>")
        t = t[end:].strip()
    if t.startswith("```"):
        lines = t.split("\n")
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        t = "\n".join(lines)
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", t, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    raise ValueError(f"could not parse JSON from: {text[:400]!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", type=Path,
                    default=Path(__file__).parent / "full_corpus" / "envelope_keys.json")
    ap.add_argument("--style", choices=["v1", "v5", "v7"], default="v5")
    ap.add_argument("--model", required=True,
                    help="HuggingFace model id, e.g. Qwen/Qwen3-32B-FP8")
    ap.add_argument("--model-tag", required=True,
                    help="Short tag for output dir naming, e.g. qwen3-32b-fp8")
    ap.add_argument("--tp", type=int, default=1,
                    help="Tensor-parallel size")
    ap.add_argument("--max-model-len", type=int, default=16384)
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--gpu-memory-utilization", type=float, default=0.90)
    ap.add_argument("--limit", type=int, default=None,
                    help="Cap number of keys (for smoke tests)")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--out-dir", type=Path, default=None)
    args = ap.parse_args()

    keys = json.loads(args.keys.read_text())
    if args.limit:
        keys = keys[: args.limit]

    run_id = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + \
             f"_full_{args.style}_{args.model_tag}"
    out_dir = args.out_dir or (
        Path(__file__).parent / "results" / f"run_{run_id}" / "envelopes"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    system_prompt = build_system_prompt(args.style)
    (out_dir.parent / "system_prompt.txt").write_text(system_prompt)
    (out_dir.parent / "model_id.txt").write_text(args.model + "\n")
    (out_dir.parent / "meta.json").write_text(json.dumps({
        "model_id": args.model, "tag": args.model_tag,
        "style": args.style, "tp": args.tp,
        "max_model_len": args.max_model_len,
        "n_keys": len(keys),
    }, indent=2))

    print(f"[gen] style={args.style} model={args.model} tp={args.tp} "
          f"n_keys={len(keys)}", flush=True)
    print(f"[gen] out: {out_dir}", flush=True)

    # Build user-msg per key.
    tasks: list[tuple[dict, str]] = []
    for k in keys:
        out_file = out_dir / key_filename(k)
        if args.resume and out_file.exists():
            continue
        mcp = k["mcp"]
        prompt_slug = k["prompt_slug"]
        category = k.get("category")
        prompt_text = load_prompt_text(mcp, prompt_slug, category)
        mcp_tools = load_mcp_tools_from_stream(
            Path(k["representative_benign_dir"]),
            keep_builtin=k.get("is_ace_bi", False),
        )
        user_msg = build_user_msg(prompt_text, mcp, mcp_tools)
        tasks.append((k, user_msg, mcp_tools, prompt_text))
    print(f"[gen] {len(tasks)} keys to generate", flush=True)
    if not tasks:
        print("[gen] nothing to do")
        return 0

    # Import vllm lazily so imports don't crash callers who just want
    # the extraction functions.
    from transformers import AutoTokenizer
    from vllm import LLM, SamplingParams

    print(f"[gen] loading tokenizer: {args.model}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)

    print(f"[gen] loading LLM (tp={args.tp}, max_model_len={args.max_model_len})",
          flush=True)
    t0 = time.time()
    llm = LLM(
        model=args.model,
        tensor_parallel_size=args.tp,
        max_model_len=args.max_model_len,
        gpu_memory_utilization=args.gpu_memory_utilization,
        trust_remote_code=True,
        enforce_eager=False,
        dtype="auto",
    )
    print(f"[gen] LLM loaded in {time.time()-t0:.1f}s", flush=True)

    prompts = render_prompts(
        system_prompt,
        [t[1] for t in tasks],
        tokenizer,
    )
    print(f"[gen] rendered {len(prompts)} prompts; example length={len(prompts[0])}",
          flush=True)

    sp = SamplingParams(
        temperature=0.0,
        max_tokens=args.max_tokens,
        stop=["```"],  # short-circuit past markdown ```
    )
    # Actually, don't stop on ``` — we strip it in the extractor. Remove stop.
    sp = SamplingParams(temperature=0.0, max_tokens=args.max_tokens)

    print(f"[gen] generating...", flush=True)
    t0 = time.time()
    outputs = llm.generate(prompts, sp)
    dt_gen = time.time() - t0
    print(f"[gen] generated {len(outputs)} responses in {dt_gen:.1f}s "
          f"({dt_gen/len(outputs):.2f}s/key)", flush=True)

    n_ok = n_err = 0
    for (k, user_msg, mcp_tools, prompt_text), out in zip(tasks, outputs):
        text = out.outputs[0].text
        try:
            envelope = extract_envelope_from_text(text)
        except Exception as e:
            print(f"[gen] parse error on {key_filename(k)}: {e}", flush=True)
            envelope = {"_error": str(e), "_raw": text[:2000]}
            n_err += 1
        else:
            n_ok += 1
        out_file = out_dir / key_filename(k)
        out_file.write_text(json.dumps({
            "mcp": k["mcp"],
            "prompt_slug": k["prompt_slug"],
            "category": k.get("category"),
            "is_ace_bi": k.get("is_ace_bi", False),
            "prompt_text": prompt_text,
            "mcp_tools": mcp_tools,
            "envelope": envelope,
        }, indent=2))

    print(f"[gen] done. n_ok={n_ok} n_err={n_err} out={out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
