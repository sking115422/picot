# PICOT intent-effects pipeline

This package creates a derived, intent-oriented view of ACE for the
intent-conditioned OS anomaly-detection study. It does not import or modify
the CLE4AS/ke4as repositories.

## Write boundary

- Inputs are opened read-only.
- Every CLI output is rejected unless its resolved path is below the PICOT
  repository root. This also prevents writing through a symlink into another
  project.
- The default input is PICOT's local snapshot at `data/ace_full/`.
- Derived data is written to `data/intent_effects/` and is ignored by Git.

## Build the full intent manifest

From the PICOT repository root:

```bash
python -m intent_effects.manifest
```

This produces:

- `data/intent_effects/ace_intent_manifest_v1.jsonl`
- `data/intent_effects/ace_intent_manifest_summary_v1.json`

Each manifest row resolves the full trusted prompt, records the agent and tool
context, marks the experimental role of the session, and supplies stable group
IDs for environment-matched tasks, benign/malicious pairs, and exact repeats.

## Extract a stratified semantic-effect sample

```bash
python -m intent_effects.extract --sample-per-stratum 2
```

Omit `--sample-per-stratum` to process every manifest session. Use
`--only-benign` to build the first calibration cohort.

The v1 extractor models filesystem reads/writes/creates/deletes/renames,
program execution, and network connect/bind events. It retains exact resources
and adds semantic resource classes, task/runtime/sensitive role hints, risk
levels, counts, and execution outcomes. The classification is intentionally
auditable and conservative; v1 labels are inputs to manual review, not final
ground truth.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s intent_effects/tests -v
```

The JSON schemas under `intent_effects/schemas/` specify both generated record
formats.

## Build feasibility cohorts

```bash
PYTHONDONTWRITEBYTECODE=1 python -m intent_effects.cohorts
```

This creates a deterministic, bijective prompt shuffle within each compatible
environment and a separate cohort containing all eligible exact repeated
benign executions. Environments with only one prompt are excluded explicitly;
the generator never falls back to an unrelated tool surface.

With the current PICOT-local ACE snapshot, this yields 804 prompt mappings
across 79 environments and 509 repeated-benign sessions across 99 groups.
