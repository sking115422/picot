"""Small deterministic JSON/JSONL helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, Mapping, Any

from .paths import resolve_picot_output


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}") from exc


def _atomic_text_write(path: Path, chunks: Iterable[str]) -> Path:
    output = resolve_picot_output(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for chunk in chunks:
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return output


def write_json(path: Path, value: Mapping[str, Any]) -> Path:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    return _atomic_text_write(path, [rendered])


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> Path:
    return _atomic_text_write(
        path,
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
    )

