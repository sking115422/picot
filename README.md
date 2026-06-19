# PICOT

**Provenance for Intent-Conditioned OS-layer Telemetry.**

Research code for paper 2: deterministic-as-possible attribution of
kernel-level activity (eBPF syscalls) to the agent-layer entities
that caused it — which session, which MCP server, which specific
tool call. The longer-term goal is intent-conditioned OS-layer
prediction as the basis of an allow/block system for LLM agents;
the current focus is establishing reliable attribution.

## Status

See [docs/2026-06-15_state_of_the_work.md](docs/2026-06-15_state_of_the_work.md)
for the consolidated entry point. Per-phase writeups are in
[docs/progress/](docs/progress/).

Current numbers (V3 corpus, per-event scoring unless noted):

| Level | Precision | Recall | F1 | Mechanism |
|---|---:|---:|---:|---|
| Session | 0.79 | 0.85 | 0.82 | sched_fork + cgroup-gating |
| MCP | 0.97 | 0.65 | 0.76 | sched_fork + layered detector |
| Tool-call (hooks) | — | 100% | 85% timing | hook-anchored ToolCall vertices |
| Tool-call (passive) | — | 33% | 0% timing | broken on stdio MCPs (Phase 10 candidate) |

## Layout

```
attribution_testing/
  agent_layer*.py       — extractors (stream | hooks | dispatcher)
  graph_builder.py      — walks events, builds Kuzu graph
  kuzu_*.py             — graph DB schema + per-event attribution
  mcp_detector.py       — layered MCP-process detector
  hooks/                — Claude Code hook bundle (PreToolUse, etc.)
  queries/              — saved Cypher queries for the populated graph
  results/              — small jsonl/json/md outputs from scorers
  v3_*_capture*.py      — capture runners (v1 sensor / v2 sched_fork)
  v3_*_score*.py        — scoring runners (per-event / per-call)

docs/
  2026-06-15_state_of_the_work.md  — entry point
  progress/                        — per-phase writeups (chronological)
```

The capture corpora (`v3_captures*/`) and Kuzu graph databases
(`kuzu_graphs/`) are not tracked — they're regenerable from
[cle4as](https://github.com/sking115422/app_os_ai_security_exploration)
captures via the `v3_*_capture*.py` runners.

## External dependencies

This repo's code shells out to but does not vendor:

- `bpftrace` — for ad-hoc kernel tracing
- `kuzu` — embedded graph DB (Python binding)
- The L3 sensor binaries from cle4as: `/lts/ai_sec_exp/cle4as/src/sensors/l3_libbpf/build/l3-sensor` and `l3_v2_libbpf/build/l3v2-sensor`
- The cle4as capture corpus at `/lts/ai_sec_exp/cle4as/src/captures_phase4/`

Hook scripts live under `attribution_testing/hooks/` and patch
`~/.claude/settings.json` via `hooks/install.sh`.
