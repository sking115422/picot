"""Extract semantic effect sets from sessions in an ACE intent manifest."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .effects import SCHEMA_VERSION, aggregate_effects
from .io import iter_jsonl, write_json, write_jsonl
from .paths import DEFAULT_OUTPUT_ROOT, PICOT_ROOT, path_from_record, resolve_input, resolve_picot_output
from .strace import iter_strace_events


def choose_records(
    records: list[dict[str, Any]],
    only_benign: bool,
    sample_per_stratum: int | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    eligible = [
        record
        for record in records
        if record.get("artifacts", {}).get("strace_log")
        and (not only_benign or record.get("variant") == "benign")
    ]
    eligible.sort(key=lambda record: record["session_id"])
    if sample_per_stratum is not None:
        counts: Counter[tuple] = Counter()
        sampled = []
        for record in eligible:
            stratum = (
                record.get("subcorpus"),
                record.get("delivery_vector"),
                record.get("gold_label"),
            )
            if counts[stratum] >= sample_per_stratum:
                continue
            counts[stratum] += 1
            sampled.append(record)
        eligible = sampled
    if limit is not None:
        eligible = eligible[:limit]
    return eligible


def extract_record(record: dict[str, Any]) -> dict[str, Any]:
    strace_value = record["artifacts"]["strace_log"]
    strace_path = path_from_record(strace_value)
    effects, statistics = aggregate_effects(iter_strace_events(strace_path))
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": record["session_id"],
        "subcorpus": record["subcorpus"],
        "delivery_vector": record["delivery_vector"],
        "threat_model": record["threat_model"],
        "gold_label": record.get("gold_label"),
        "variant": record["variant"],
        "security_evaluation_role": record["security_evaluation_role"],
        "prompt_slug": record["prompt_slug"],
        "prompt_sha256": record.get("prompt_sha256"),
        "grouping": record["grouping"],
        "agent": record["agent"],
        "source_strace": strace_value,
        "statistics": statistics,
        "effects": effects,
    }


def summarize(records: list[dict[str, Any]], errors: list[dict[str, str]]) -> dict[str, Any]:
    total_unique = sum(record["statistics"]["unique_effect_count"] for record in records)
    family_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    for record in records:
        family_counts.update(record["statistics"]["effect_family_counts"])
        class_counts.update(record["statistics"]["semantic_class_counts"])
    return {
        "schema_version": "picot.semantic-effects-summary.v1",
        "sessions": len(records),
        "errors": errors,
        "unique_effects_across_sessions": total_unique,
        "mean_unique_effects_per_session": round(total_unique / len(records), 3) if records else 0.0,
        "effect_family_counts": dict(sorted(family_counts.items())),
        "semantic_class_counts": dict(sorted(class_counts.items())),
        "sessions_by_subcorpus": dict(sorted(Counter(record["subcorpus"] for record in records).items())),
        "sessions_by_label": dict(sorted(Counter(str(record.get("gold_label")) for record in records).items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_intent_manifest_v1.jsonl")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_semantic_effects_v1.jsonl")
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUTPUT_ROOT / "ace_semantic_effects_summary_v1.json")
    parser.add_argument("--only-benign", action="store_true")
    parser.add_argument("--sample-per-stratum", type=int, default=None)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    manifest_path = resolve_input(args.manifest)
    output = resolve_picot_output(args.output)
    summary_path = resolve_picot_output(args.summary)
    records = list(iter_jsonl(manifest_path))
    selected = choose_records(records, args.only_benign, args.sample_per_stratum, args.limit)

    extracted = []
    errors: list[dict[str, str]] = []
    for record in selected:
        try:
            extracted.append(extract_record(record))
        except (OSError, ValueError) as exc:
            errors.append({"session_id": record["session_id"], "error": str(exc)})

    write_jsonl(output, extracted)
    summary = summarize(extracted, errors)
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"wrote {len(extracted)} records to {output.relative_to(PICOT_ROOT)}")
    print(f"wrote summary to {summary_path.relative_to(PICOT_ROOT)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

