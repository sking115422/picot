# Phase 9 — per-call metric and hooks-mode predictor

**Date:** 2026-06-17

## Problem

Phase 8 established that per-event tool-call F1 was the wrong shape:
~99.6% of MCP-server kernel events fall outside any tool-execution
window, and the "ground truth" we were scoring against was itself a
loose heuristic.

Spinning up a per-call diagnostic surfaced something more
fundamental: **the existing kernel-only predictor essentially does
not detect tool calls for stdio-transport MCPs.** The predictor's
mechanism (in `graph_builder._open_tool_call` at
[graph_builder.py:441-455](../../ds_gen/attribution_testing/graph_builder.py#L441))
keys on `sendto` syscalls whose payload contains
`"method":"tools/call"`. The L3 v2 sensor only attaches to
`sys_enter_sendto`, which fires for socket sends, not pipe writes.
All three of our v2 test MCPs (filesystem, git, memory) communicate
over stdio (anonymous pipes) — invisible to the sensor.

In one sample session (memory_02), the entire 252,614-event trace
contained 343 `sendto` events and exactly **0** JSON-RPC `tools/call`
frames. The sendto traffic was VS Code IPC and ancillary git/python
sockets, none of which is the agent↔MCP path.

This means the headline "tool-call precision = 1.000" from Phase 7
was reading off near-zero coverage: when the predictor occasionally
did produce a ToolCall vertex, it was right by luck more than by
mechanism.

## What this phase does

Two things, both small:

1. **Per-call scorer.** New `v3_v2_per_call_score.py` runs each v2
   capture through the graph builder in isolation (no merging) and
   asks, for each ground-truth tool call (PreToolUse/PostToolUse pair
   from hook events): did the predictor produce a ToolCall vertex
   with the matching tool_use_id? Does its kernel-timing window
   cover the actual tool-execution period?

   The scorer reports two numbers separately:
   - **Per-call recall:** of N hook-attested tool calls, how many
     does the predictor produce a matching ToolCall vertex for?
   - **Timing coverage:** of the matched paired calls, on how many
     does the predictor's `(t_open_ns, t_close_ns)` cover the hook
     window `(PreToolUse.ts, PostToolUse.ts)`?

   PreToolUse without matching PostToolUse (errored / aborted calls
   where Stop fired before PostToolUse) are counted for
   identification but excluded from coverage, since their close edge
   is unbounded.

2. **Hooks-mode predictor.** The existing
   `build_graph_with_agent_layer(..., extractor_mode="hooks")` path
   already ingests hook events as ToolCall vertices via
   `agent_layer_hooks.extract_agent_layer_from_hooks`. This phase
   wires hooks-mode into the per-call scorer so we can compare
   passive (kernel-only) vs hooks-mode predictions against the same
   ground truth.

## Result

Run on all 9 v2 captures (18 ground-truth tool calls total: 13
PreToolUse/PostToolUse pairs + 5 PreToolUse-only orphans where the
call errored before PostToolUse fired):

| Mode    | Per-call recall | Timing coverage | Per-call precision |
|---------|----------------:|----------------:|-------------------:|
| Passive | 6/18 = **33.3%** | 0/2 = **0.0%**   | 6/7 = 85.7%         |
| Hooks   | 18/18 = **100%** | 11/13 = **84.6%** | 18/19 = 94.7%        |

Reading the deltas:

- **Passive recall is 33% because most of the v2 MCPs are stdio.**
  The 6 it does identify are mostly cases where the kernel-side
  mechanism happened to open a `tc_<n>` vertex but on the wrong
  pid/ts — id-matching is artificially generous; the underlying
  signal is much weaker than the number suggests. The "of paired,
  covers" column shows this clearly: 0 of the 2 passive matches had
  a kernel-timing window covering the hook window.

- **Hooks recall is 100% by construction.** Every PreToolUse fires a
  hook; every hook event becomes a ToolCall vertex. There is no
  inference step — it's deterministic tagging from the agent layer.

- **Hooks timing coverage is 84.6%, not 100%.** Two paired calls had
  `t_open` ~10–15ms *after* PreToolUse. That's the time between the
  hook firing and the agent dispatching the actual tool call. Not
  an attribution failure; the hook is upstream of the kernel work.
  We could widen coverage to "predictor window overlaps hook window"
  rather than "predictor window contains hook window" if the strict
  containment isn't useful, but ~10ms slack is small for any real
  query.

- **Hooks per-call precision is 94.7%, not 100%.** One spurious
  ToolCall vertex (`tc_0`) was opened by the kernel-side
  sendto-JSON-RPC parser in addition to the hook-anchored ones. In
  hooks mode we should probably suppress that — the hook events are
  authoritative and the kernel-side guess is noise. Open question:
  flag for hooks-mode to suppress kernel-side ToolCall vertex
  creation.

## Significance

The right summary of where we are now:

- **Session attribution** (sched_fork-walked subtree, ~98%
  precision): solid, deterministic for in-trace forks.
- **MCP attribution** (~97% precision under sched_fork): solid,
  deterministic for in-trace forks.
- **Tool-call attribution, passive (kernel-only):** does not work
  for stdio MCPs. Needs sensor extension to trace `write`/`writev`
  on the agent's stdio fds (Phase 10 candidate, see below).
- **Tool-call attribution, hooks:** 100% per-call recall, ~85%
  timing coverage with ~10ms slack on the open edge. Deterministic
  by construction; PreToolUse → ToolCall vertex is a direct mapping
  from agent-layer cooperation.

The Phase 7 narrative — "precision is high, recall is workload-
limited" — held for session and MCP. For tool-call it was masking a
mechanism failure. With hooks-mode the narrative is genuine: every
real call is identified, every match has correct timing within
hook resolution.

## Path A scoping (deferred)

For passive tool-call attribution to work on stdio MCPs the L3
sensor needs to trace `write` and/or `writev` on the agent's stdio
fds. This is non-trivial because:

- `write` is a high-volume syscall — every log line, every stdout
  flush from any process on the box fires it. Naive tracing
  explodes trace size.
- The sensor would need an in-kernel filter: only emit write events
  where the destination is a pipe to a known MCP child, OR where
  the first N bytes parse as a JSON-RPC frame.
- The cleanest filter is probably "fd whose target inode is a pipe
  shared with a process whose parent has a `claude` execve in its
  argv history." That's traceable in BPF but adds bookkeeping.

Path A would unlock passive (no-cooperation-required) tool-call
attribution for cooperating-but-not-instrumented agents, plus
agents that don't expose hooks (Cursor, ChatGPT SDK clients, etc).
Hooks-mode is a strict superset for instrumented Claude Code, but
Path A is what generalizes.

Estimated work: ~1–2 days of BPF + parser, plus a recapture pass.
Recommend deferring until we know detection-side use cases need
passive attribution rather than hook-anchored.

## Files

- `ds_gen/attribution_testing/v3_v2_per_call_score.py` — new scorer
- `ds_gen/attribution_testing/results/v3_v2_per_call.jsonl` — per-session output
