"""Path helpers enforcing PICOT's write boundary."""

from __future__ import annotations

from pathlib import Path


PICOT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ACE_ROOT = PICOT_ROOT / "data" / "ace_full"
DEFAULT_SESSIONS_ROOT = DEFAULT_ACE_ROOT / "sessions"
DEFAULT_CORPUS_ROOT = DEFAULT_ACE_ROOT / "corpus"
DEFAULT_OUTPUT_ROOT = PICOT_ROOT / "data" / "intent_effects"


def resolve_input(path: Path) -> Path:
    """Resolve an input path without imposing a location restriction."""
    candidate = path if path.is_absolute() else PICOT_ROOT / path
    return candidate.resolve()


def resolve_picot_output(path: Path) -> Path:
    """Resolve an output and reject any path escaping the PICOT tree.

    Resolving before the write also catches paths that traverse a symlink to
    another project. Inputs may live elsewhere and are always opened read-only;
    outputs may only live below PICOT_ROOT.
    """
    candidate = path if path.is_absolute() else PICOT_ROOT / path
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(PICOT_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"refusing to write outside PICOT: {resolved} (root={PICOT_ROOT})"
        ) from exc
    return resolved


def portable_path(path: Path) -> str:
    """Use a PICOT-relative path when possible, absolute otherwise."""
    resolved = path.resolve(strict=False)
    try:
        return str(resolved.relative_to(PICOT_ROOT))
    except ValueError:
        return str(resolved)


def path_from_record(value: str) -> Path:
    """Resolve a path stored in a generated PICOT record."""
    path = Path(value)
    return path.resolve() if path.is_absolute() else (PICOT_ROOT / path).resolve()

