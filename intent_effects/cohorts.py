"""Build leakage-resistant feasibility cohorts and prompt-shuffle controls."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .io import iter_jsonl, write_json, write_jsonl
from .paths import DEFAULT_OUTPUT_ROOT, PICOT_ROOT, resolve_input, resolve_picot_output


def _rotation_offset(environment_group_id: str, size: int, seed: int) -> int:
    digest = hashlib.sha256(f"{seed}:{environment_group_id}".encode("utf-8")).digest()
    return 1 + int.from_bytes(digest[:8], "big") % (size - 1)


def unique_tasks(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one benign, prompt-resolved representative per task group."""
    by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if not record.get("benign_calibration_candidate"):
            continue
        by_task[record["grouping"]["task_group_id"]].append(record)
    representatives = []
    for task_records in by_task.values():
        task_records.sort(key=lambda record: record["session_id"])
        representatives.append(task_records[0])
    return sorted(representatives, key=lambda record: record["grouping"]["task_group_id"])


def build_prompt_shuffle(records: list[dict[str, Any]], seed: int = 42):
    """Pair each task with a different prompt in the same environment.

    A deterministic non-zero rotation is used within each environment. It is a
    bijection, so every prompt appears exactly once as an aligned target and
    once as a shuffled control inside that environment.
    """
    environments: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in unique_tasks(records):
        environments[record["grouping"]["environment_group_id"]].append(record)

    mappings: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for environment_id, tasks in sorted(environments.items()):
        tasks.sort(key=lambda record: record["grouping"]["task_group_id"])
        if len(tasks) < 2:
            task = tasks[0]
            excluded.append(
                {
                    "environment_group_id": environment_id,
                    "task_group_id": task["grouping"]["task_group_id"],
                    "reason": "no_second_prompt_in_same_environment",
                }
            )
            continue
        offset = _rotation_offset(environment_id, len(tasks), seed)
        for index, target in enumerate(tasks):
            shuffled = tasks[(index + offset) % len(tasks)]
            if target["prompt_sha256"] == shuffled["prompt_sha256"]:
                # Same text under two slugs is not a valid intent control.
                excluded.append(
                    {
                        "environment_group_id": environment_id,
                        "task_group_id": target["grouping"]["task_group_id"],
                        "reason": "rotated_prompt_text_is_identical",
                    }
                )
                continue
            mappings.append(
                {
                    "schema_version": "picot.prompt-shuffle.v1",
                    "seed": seed,
                    "environment_group_id": environment_id,
                    "subcorpus": target["subcorpus"],
                    "mcp": target.get("mcp"),
                    "threat_model": target.get("threat_model"),
                    "artifact_id": target.get("artifact_id"),
                    "target": {
                        "task_group_id": target["grouping"]["task_group_id"],
                        "prompt_slug": target["prompt_slug"],
                        "prompt_sha256": target["prompt_sha256"],
                        "prompt_text": target["prompt_text"],
                    },
                    "shuffled": {
                        "task_group_id": shuffled["grouping"]["task_group_id"],
                        "prompt_slug": shuffled["prompt_slug"],
                        "prompt_sha256": shuffled["prompt_sha256"],
                        "prompt_text": shuffled["prompt_text"],
                    },
                }
            )
    mappings.sort(key=lambda row: row["target"]["task_group_id"])
    excluded.sort(key=lambda row: row["task_group_id"])
    return mappings, excluded


def repeated_benign_cohort(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for record in records:
        grouping = record["grouping"]
        if not record.get("benign_calibration_candidate"):
            continue
        if grouping.get("exact_repeat_count", 0) < 2:
            continue
        rows.append(
            {
                "schema_version": "picot.repeated-benign-cohort.v1",
                "session_id": record["session_id"],
                "subcorpus": record["subcorpus"],
                "delivery_vector": record["delivery_vector"],
                "prompt_slug": record["prompt_slug"],
                "prompt_sha256": record["prompt_sha256"],
                "environment_group_id": grouping["environment_group_id"],
                "task_group_id": grouping["task_group_id"],
                "repeat_group_id": grouping["repeat_group_id"],
                "exact_repeat_count": grouping["exact_repeat_count"],
                "strace_log": record["artifacts"]["strace_log"],
            }
        )
    return sorted(rows, key=lambda row: (row["repeat_group_id"], row["session_id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_intent_manifest_v1.jsonl")
    parser.add_argument("--shuffle-output", type=Path, default=DEFAULT_OUTPUT_ROOT / "prompt_shuffle_v1.jsonl")
    parser.add_argument("--repeated-output", type=Path, default=DEFAULT_OUTPUT_ROOT / "repeated_benign_cohort_v1.jsonl")
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUTPUT_ROOT / "cohort_summary_v1.json")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    manifest_path = resolve_input(args.manifest)
    shuffle_output = resolve_picot_output(args.shuffle_output)
    repeated_output = resolve_picot_output(args.repeated_output)
    summary_output = resolve_picot_output(args.summary)

    records = list(iter_jsonl(manifest_path))
    mappings, excluded = build_prompt_shuffle(records, seed=args.seed)
    repeated = repeated_benign_cohort(records)
    summary = {
        "schema_version": "picot.cohort-summary.v1",
        "seed": args.seed,
        "eligible_unique_benign_tasks": len(unique_tasks(records)),
        "matched_prompt_shuffle_tasks": len(mappings),
        "excluded_prompt_shuffle_tasks": len(excluded),
        "excluded_reasons": dict(sorted(Counter(row["reason"] for row in excluded).items())),
        "shuffle_tasks_by_subcorpus": dict(sorted(Counter(row["subcorpus"] for row in mappings).items())),
        "repeated_benign_sessions": len(repeated),
        "repeated_benign_groups": len({row["repeat_group_id"] for row in repeated}),
        "repeated_benign_sessions_by_subcorpus": dict(sorted(Counter(row["subcorpus"] for row in repeated).items())),
    }
    write_jsonl(shuffle_output, mappings)
    write_jsonl(repeated_output, repeated)
    write_json(summary_output, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"wrote prompt shuffle to {shuffle_output.relative_to(PICOT_ROOT)}")
    print(f"wrote repeated-benign cohort to {repeated_output.relative_to(PICOT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

