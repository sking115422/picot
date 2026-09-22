"""Build an intent-oriented manifest over the PICOT ACE snapshot.

The source corpus is only read. The generated manifest makes pairing,
repetition, prompt provenance, execution context, and intended experimental
role explicit without changing ACE's original session metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .io import read_json, write_json, write_jsonl
from .paths import (
    DEFAULT_CORPUS_ROOT,
    DEFAULT_OUTPUT_ROOT,
    DEFAULT_SESSIONS_ROOT,
    PICOT_ROOT,
    portable_path,
    resolve_input,
    resolve_picot_output,
)


SCHEMA_VERSION = "picot.ace-intent-manifest.v1"


def stable_id(*parts: object) -> str:
    payload = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def read_stream_init(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8", errors="replace") as handle:
        for _ in range(30):
            line = handle.readline()
            if not line:
                break
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("type") == "system" and item.get("subtype") == "init":
                return item
    return {}


def infer_subcorpus(meta: dict[str, Any]) -> str:
    if meta.get("threat_model") == "mcp_tool_tampering":
        return "ace_mcp"
    if meta.get("mcp") == "builtin/claude-code":
        return "ace_builtin"
    return "ace_unknown"


def infer_delivery_vector(meta: dict[str, Any], subcorpus: str) -> str:
    if subcorpus == "ace_mcp":
        return "mcp_package_tampering"
    category = str(meta.get("category") or "")
    for prefix, vector in (
        ("user_direct_", "user_direct"),
        ("multi_step_", "multi_step"),
        ("retrieval_", "retrieval"),
        ("resource_", "resource_abuse"),
        ("file_", "file_indirect"),
        ("web_", "web_indirect"),
        ("mem_", "memory_indirect"),
    ):
        if category.startswith(prefix):
            return vector
    return "unknown"


def security_evaluation_role(meta: dict[str, Any], delivery_vector: str) -> str:
    variant = str(meta.get("variant") or "")
    label = str(meta.get("gold_label") or "")
    if variant == "benign":
        return "benign_behavior_candidate"
    if delivery_vector == "user_direct":
        return "direct_request_policy_test"
    if label == "malicious_fired":
        return "task_inconsistent_positive"
    if label == "dormant":
        return "non_executed_negative"
    if label == "latent":
        return "ambiguous_or_sensor_control"
    return "other_malicious_variant"


def build_prompt_index(corpus_root: Path) -> tuple[dict[tuple[str, str], Path], dict[tuple[str, str], Path], dict[str, list[Path]]]:
    mcp_index: dict[tuple[str, str], Path] = {}
    builtin_index: dict[tuple[str, str], Path] = {}
    by_stem: dict[str, list[Path]] = defaultdict(list)

    mcp_root = corpus_root / "mcps"
    if mcp_root.is_dir():
        for path in mcp_root.glob("**/run_recipe/prompts/*.txt"):
            if path.name.startswith("_"):
                continue
            relative = path.relative_to(mcp_root)
            parts = relative.parts
            marker = parts.index("run_recipe")
            mcp = "/".join(parts[:marker])
            mcp_index[(mcp, path.stem)] = path
            by_stem[path.stem].append(path)

    builtin_root = corpus_root / "builtin_fixtures"
    if builtin_root.is_dir():
        for path in builtin_root.glob("**/prompts/*.txt"):
            category = path.parent.parent.name
            builtin_index[(category, path.stem)] = path
            by_stem[path.stem].append(path)
    return mcp_index, builtin_index, by_stem


def resolve_prompt_source(
    meta: dict[str, Any],
    indexes: tuple[dict[tuple[str, str], Path], dict[tuple[str, str], Path], dict[str, list[Path]]],
) -> tuple[Path | None, str]:
    mcp_index, builtin_index, by_stem = indexes
    prompt_slug = str(meta.get("prompt") or "")
    subcorpus = infer_subcorpus(meta)
    if subcorpus == "ace_mcp":
        path = mcp_index.get((str(meta.get("mcp") or ""), prompt_slug))
        if path:
            return path, "mcp_recipe"
    else:
        path = builtin_index.get((str(meta.get("category") or ""), prompt_slug))
        if path:
            return path, "builtin_fixture"

    candidates = by_stem.get(prompt_slug, [])
    unique_contents: dict[str, Path] = {}
    for path in candidates:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        unique_contents.setdefault(content, path)
    if len(unique_contents) == 1:
        return next(iter(unique_contents.values())), "unique_slug_fallback"
    return None, "unresolved"


def render_prompt(template: str, sentinels: dict[str, Any]) -> str:
    rendered = template
    for key, value in sorted(sentinels.items(), key=lambda item: -len(item[0])):
        if not isinstance(value, (str, int, float)):
            continue
        rendered = rendered.replace("{{" + key + "}}", str(value))
        rendered = rendered.replace("{" + key + "}", str(value))
    return rendered.strip()


def capture_succeeded(meta: dict[str, Any]) -> bool:
    return_code = meta.get("returncode", meta.get("exit_code"))
    if return_code not in (None, 0):
        return False
    if bool(meta.get("timed_out", False)):
        return False
    terminal_reason = meta.get("terminal_reason")
    return terminal_reason in (None, "completed")


def build_record(
    session_dir: Path,
    corpus_root: Path,
    prompt_indexes,
) -> dict[str, Any]:
    meta_path = session_dir / "session.json"
    meta = read_json(meta_path)
    stream_path = session_dir / "stream.jsonl"
    init = read_stream_init(stream_path)
    strace_files = sorted((session_dir / "strace").glob("*.strace.log"))
    strace_path = strace_files[0] if strace_files else None

    subcorpus = infer_subcorpus(meta)
    delivery_vector = infer_delivery_vector(meta, subcorpus)
    prompt_source, prompt_source_kind = resolve_prompt_source(meta, prompt_indexes)
    prompt_template = ""
    if prompt_source is not None:
        prompt_template = prompt_source.read_text(encoding="utf-8", errors="replace").strip()
    prompt_text = render_prompt(prompt_template, meta.get("session_sentinels") or {})

    mcp = str(meta.get("mcp") or "")
    category = str(meta.get("category") or "")
    threat_model = str(meta.get("threat_model") or "")
    artifact_id = str(meta.get("artifact_id") or "")
    prompt_slug = str(meta.get("prompt") or "")
    variant = str(meta.get("variant") or "")
    cwd = str(init.get("cwd") or "")
    tool_names = sorted(str(tool) for tool in (init.get("tools") or []))

    if subcorpus == "ace_mcp":
        environment_parts = (subcorpus, mcp, cwd, tuple(tool_names))
    else:
        environment_parts = (subcorpus, threat_model, artifact_id, cwd, tuple(tool_names))
    environment_group_id = stable_id(*environment_parts)
    task_group_id = stable_id(environment_group_id, prompt_slug)
    repeat_group_id = stable_id(task_group_id, variant)

    succeeded = capture_succeeded(meta)
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": str(meta.get("session_id") or session_dir.name),
        "session_label": str(meta.get("session_label") or session_dir.name),
        "subcorpus": subcorpus,
        "threat_model": threat_model,
        "delivery_vector": delivery_vector,
        "mcp": mcp,
        "category": category or None,
        "artifact_id": artifact_id or None,
        "prompt_slug": prompt_slug,
        "prompt_text": prompt_text or None,
        "prompt_template": prompt_template or None,
        "prompt_sha256": hashlib.sha256(prompt_text.encode("utf-8")).hexdigest() if prompt_text else None,
        "prompt_source": portable_path(prompt_source) if prompt_source else None,
        "prompt_source_kind": prompt_source_kind,
        "variant": variant,
        "gold_label": meta.get("gold_label"),
        "security_evaluation_role": security_evaluation_role(meta, delivery_vector),
        "capture_succeeded": succeeded,
        "benign_calibration_candidate": bool(variant == "benign" and succeeded and prompt_text and strace_path),
        "agent": {
            "model": meta.get("model") or init.get("model"),
            "harness": "claude_code_cli" if init.get("claude_code_version") else "unknown",
            "harness_version": init.get("claude_code_version"),
            "cwd": cwd or None,
            "tools": tool_names,
            "mcp_servers": [server.get("name") for server in (init.get("mcp_servers") or []) if isinstance(server, dict)],
        },
        "grouping": {
            "environment_group_id": environment_group_id,
            "task_group_id": task_group_id,
            "repeat_group_id": repeat_group_id,
        },
        "artifacts": {
            "session_dir": portable_path(session_dir),
            "session_json": portable_path(meta_path),
            "stream_jsonl": portable_path(stream_path) if stream_path.is_file() else None,
            "strace_log": portable_path(strace_path) if strace_path else None,
        },
        "source_read_only": True,
    }


def add_group_statistics(records: list[dict[str, Any]]) -> None:
    task_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    repeat_counts: Counter[str] = Counter()
    for record in records:
        grouping = record["grouping"]
        task_groups[grouping["task_group_id"]].append(record)
        repeat_counts[grouping["repeat_group_id"]] += 1
    for group_records in task_groups.values():
        benign = sum(record["variant"] == "benign" for record in group_records)
        malicious = len(group_records) - benign
        for record in group_records:
            grouping = record["grouping"]
            grouping.update(
                {
                    "task_group_session_count": len(group_records),
                    "task_group_benign_count": benign,
                    "task_group_malicious_count": malicious,
                    "has_benign_malicious_pair": benign > 0 and malicious > 0,
                    "exact_repeat_count": repeat_counts[grouping["repeat_group_id"]],
                }
            )


def summarize_manifest(records: list[dict[str, Any]]) -> dict[str, Any]:
    def count(field):
        return dict(sorted(Counter(record.get(field) for record in records).items(), key=lambda item: str(item[0])))

    prompt_resolution = Counter(record["prompt_source_kind"] for record in records)
    labels = Counter(str(record.get("gold_label")) for record in records)
    variants = Counter("benign" if record["variant"] == "benign" else "malicious_variant" for record in records)
    task_groups = {record["grouping"]["task_group_id"] for record in records}
    paired_groups = {
        record["grouping"]["task_group_id"]
        for record in records
        if record["grouping"]["has_benign_malicious_pair"]
    }
    repeated_benign_groups = {
        record["grouping"]["repeat_group_id"]
        for record in records
        if record["variant"] == "benign" and record["grouping"]["exact_repeat_count"] >= 2
    }
    return {
        "schema_version": "picot.ace-intent-manifest-summary.v1",
        "sessions": len(records),
        "subcorpora": count("subcorpus"),
        "delivery_vectors": count("delivery_vector"),
        "gold_labels": dict(sorted(labels.items())),
        "variant_classes": dict(sorted(variants.items())),
        "security_evaluation_roles": count("security_evaluation_role"),
        "prompt_resolution": dict(sorted(prompt_resolution.items())),
        "sessions_with_prompt_text": sum(bool(record["prompt_text"]) for record in records),
        "sessions_with_strace": sum(bool(record["artifacts"]["strace_log"]) for record in records),
        "capture_succeeded": sum(bool(record["capture_succeeded"]) for record in records),
        "benign_calibration_candidates": sum(bool(record["benign_calibration_candidate"]) for record in records),
        "task_groups": len(task_groups),
        "paired_task_groups": len(paired_groups),
        "repeated_benign_exact_groups": len(repeated_benign_groups),
    }


def build_manifest(sessions_root: Path, corpus_root: Path, limit: int | None = None):
    prompt_indexes = build_prompt_index(corpus_root)
    session_dirs = sorted(path.parent for path in sessions_root.glob("*/session.json"))
    if limit is not None:
        session_dirs = session_dirs[:limit]
    records = [build_record(path, corpus_root, prompt_indexes) for path in session_dirs]
    add_group_statistics(records)
    records.sort(key=lambda record: record["session_id"])
    return records, summarize_manifest(records)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sessions-root", type=Path, default=DEFAULT_SESSIONS_ROOT)
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_intent_manifest_v1.jsonl")
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_intent_manifest_summary_v1.json")
    parser.add_argument("--limit", type=int, default=None, help="Deterministic smoke-test limit")
    args = parser.parse_args()

    sessions_root = resolve_input(args.sessions_root)
    corpus_root = resolve_input(args.corpus_root)
    output = resolve_picot_output(args.output)
    summary_path = resolve_picot_output(args.summary)
    if not sessions_root.is_dir():
        parser.error(f"sessions root not found: {sessions_root}")
    if not corpus_root.is_dir():
        parser.error(f"corpus root not found: {corpus_root}")

    records, summary = build_manifest(sessions_root, corpus_root, args.limit)
    write_jsonl(output, records)
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"wrote {len(records)} records to {output.relative_to(PICOT_ROOT)}")
    print(f"wrote summary to {summary_path.relative_to(PICOT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

