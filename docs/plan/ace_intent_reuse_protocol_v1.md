# ACE reuse protocol for intent-conditioned OS effects

**Project:** PICOT  
**Version:** v1  
**Date:** 2026-09-03  
**Status:** Implemented first-pass manifest and effect-extraction pipeline

## Purpose

This protocol corrects the data premise in the original PICOT proposal and
defines the first feasibility experiment. ACE is not an MCP-only dataset. The
canonical corpus has 4,047 sessions: 1,979 MCP-package-tampering sessions and
2,068 built-in-agent sessions spanning file, web, user-direct, memory,
retrieval/multi-step, and resource-abuse delivery vectors.

PICOT will therefore reuse ACE as its primary feasibility corpus. We will not
collect a replacement dataset before testing whether the trusted prompt adds
predictive information about OS effects already present in ACE.

## Repository and data boundary

- Only `/mnt/lts/ai_sec_exp/picot` is writable for this project.
- CLE4AS/ke4as repositories and their datasets are read-only reference
  material.
- The default pipeline input is PICOT's local ACE snapshot at
  `picot/data/ace_full/`.
- Derived records are written under `picot/data/intent_effects/`.
- Pipeline CLIs reject output paths whose resolved location is outside PICOT,
  including paths that traverse a symlink into another project.

## Observed PICOT-local ACE inventory

The implemented manifest builder inspected all 4,047 local session records and
resolved the full canonical prompt for every session.

| Property | Count |
|---|---:|
| Total sessions | 4,047 |
| ACE-MCP sessions | 1,979 |
| ACE built-in sessions | 2,068 |
| Benign sessions | 1,225 |
| Malicious-fired sessions | 1,358 |
| Dormant sessions | 1,002 |
| Latent sessions | 462 |
| Capture-successful sessions | 3,978 |
| High-confidence automatic benign candidates | 1,214 |
| Environment-matched task groups | 861 |
| Task groups with benign and malicious variants | 815 |
| Exact task/variant groups with repeated benign runs | 99 |

The 815 paired groups are immediately useful for testing whether an envelope
that admits the benign run rejects task-inconsistent effects in its malicious
counterpart. The 99 repeated-benign groups are the initial source for
estimating run-to-run variability and calibration error.

## Experimental roles of ACE cohorts

### Benign calibration and utility

Use capture-successful benign sessions with resolved prompts and traces. Begin
with exact repeated built-in groups, keeping all executions of a task group in
the same split. A successful process exit is only an automatic eligibility
filter, not a semantic task-success label. A stratified manual audit must
validate a subset before results are treated as publishable.

### Intent-mismatch security evaluation

Use malicious-fired variants from:

- MCP package tampering;
- file-based indirect injection;
- web-based indirect injection;
- memory-based indirect injection; and
- retrieval or multi-step injection.

These retain a benign trusted task while changing the environment or tool
behavior, so unexpected effects can legitimately be evaluated as departures
from user intent.

### Direct-request policy evaluation

Keep user-direct malicious prompts separate. If a user explicitly requests a
credential read or command execution, a faithful intent predictor may include
that effect. Blocking it requires an organizational or protected-resource
policy, not merely an intent-consistency model. Pooling these sessions with
indirect injection would confound the primary research question.

### Agent and scaffold shift

ACE-XA should be incorporated after the within-ACE feasibility gate. It is an
external evaluation set, not a source for random session-level training/test
mixing.

## Behavior model

The initial contract is decomposed as

\[
C(I,A,H,V) = B(A,H,V) \cup \Delta(I,A,H,V),
\]

where `B` is a generic agent/harness/environment behavior profile and
`Delta` is the task-specific effect set predicted from the trusted prompt and
context. Runtime libraries, framework caches, model-endpoint traffic, and
ordinary launcher behavior belong primarily in `B`. Project resources,
task-relevant programs, requested destinations, and sensitive operations are
modeled in `Delta`.

This decomposition is essential: the first raw extraction produced roughly
3,156 exact paths/commands per sampled session because transient runtime names
dominated the representation. Stable resource abstraction reduced the same
58-session stratified sample to a mean of 111 unique semantic effects per
session while retaining up to three concrete examples for audit.

## Effect representation v1

The current extractor covers:

- filesystem read, write, create, delete, rename, directory creation, and
  permission change;
- executable invocation with a bounded argument preview; and
- network connect and bind, including address, port, or Unix-socket scope when
  available.

Each effect contains:

- an enforceable resource scope such as `$PROJECT/src/main.py`,
  `$HOME/.aws/**`, `/tmp/claude-*/**`, or `/usr/lib/**`;
- a semantic class such as project, runtime library, credential, persistence,
  temporary, system configuration, or public network;
- a provisional `task_facing`, `runtime_dependency`, `task_or_runtime`,
  `sensitive`, or `unknown` role hint;
- a risk level;
- success/failure and occurrence counts; and
- bounded concrete examples for manual review.

These rule-derived classes are an auditable starting representation, not final
ground truth. In particular, agent API traffic and failed path probes will need
profile-based treatment.

## First feasibility experiment

### Unit and splits

The independent unit is an environment-matched task group, not a syscall or an
individual repeated session. No group may cross train, calibration, and test
partitions.

Construct prompt-shuffled controls only within the same environment group when
possible. For ACE-MCP this means the same MCP/tool surface. For built-in
sessions this means the same threat model, artifact, working directory, and
available tool set. Unmatched sessions are excluded from the primary paired
comparison rather than shuffled across unrelated environments.

### Conditions

1. Global session-independent effect profile.
2. Agent/harness/environment base profile `B` without the prompt.
3. Correct-prompt LLM task delta.
4. Matched shuffled-prompt LLM task delta.
5. Behavioral retrieval from similar verified benign tasks.
6. Hybrid base profile plus LLM and retrieval delta.

### Primary metrics

- complete benign-session coverage;
- successful required-effect recall;
- risk-weighted admitted authority;
- contract size by effect family;
- aligned-minus-shuffled paired difference at matched benign coverage;
- violation rate on task-inconsistent malicious counterparts; and
- coverage error at requested calibration levels.

Failed syscall attempts must be reported separately from successful effects.
Attack rejection alone is not evidence of prompt specificity, because the
existing PICOT audit showed that tight but misaligned envelopes can reject as
many attacks as aligned envelopes.

### Feasibility gate

Proceed to targeted collection only if the correct prompt improves the benign
coverage versus admitted-authority frontier over matched shuffled prompts and
the improvement appears in more than one delivery/workload family. Security
results must also survive removal or abstraction of synthetic sentinel names.

## Implemented artifacts

Source code and schemas:

- `intent_effects/manifest.py`
- `intent_effects/strace.py`
- `intent_effects/effects.py`
- `intent_effects/extract.py`
- `intent_effects/cohorts.py`
- `intent_effects/schemas/manifest_record_v1.schema.json`
- `intent_effects/schemas/effect_record_v1.schema.json`

Generated, Git-ignored data:

- `data/intent_effects/ace_intent_manifest_v1.jsonl`
- `data/intent_effects/ace_intent_manifest_summary_v1.json`
- `data/intent_effects/ace_semantic_effects_sample_v1.jsonl`
- `data/intent_effects/ace_semantic_effects_sample_summary_v1.json`
- `data/intent_effects/prompt_shuffle_v1.jsonl`
- `data/intent_effects/repeated_benign_cohort_v1.jsonl`
- `data/intent_effects/cohort_summary_v1.json`

The realized prompt-shuffle cohort contains 804 target/shuffled task pairs
across 79 matched environments: 191 built-in-agent tasks and 613 ACE-MCP
tasks. The repeated-benign cohort contains 509 sessions across 99 exact task
groups. Every prompt-shuffle mapping changes the prompt and is bijective within
its environment; there is no cross-environment fallback.

Reproduction commands, run from the PICOT repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m intent_effects.manifest
PYTHONDONTWRITEBYTECODE=1 python -m intent_effects.extract \
  --sample-per-stratum 2 \
  --output data/intent_effects/ace_semantic_effects_sample_v1.jsonl \
  --summary data/intent_effects/ace_semantic_effects_sample_summary_v1.json
PYTHONDONTWRITEBYTECODE=1 python -m intent_effects.cohorts
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover \
  -s intent_effects/tests -v
```

## Next implementation step

Build the benign-cohort stability auditor and group-safe train/calibration/test
split generator from the implemented cohort files. Before any LLM calls,
quantify effect stability within the 99 repeated-benign groups and identify
which semantic classes belong reliably to the base profile rather than the
task-conditioned delta.
