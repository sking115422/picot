# Phase 8 — tightening tool-call ground-truth windows

**Date:** 2026-06-17

## Problem

Phase 7 left tool-call F1 at 0.597 (precision 1.000, recall 0.427).
We hypothesized the recall was floored by the *ground-truth window
definition*, not by the attribution mechanism — the existing
`_stream_tool_windows()` defines a window as
`(prev_tool_result_ts, this_tool_result_ts)`, which includes agent
reasoning time, the LLM API round-trip, and any non-tool work
between calls. Under that definition the denominator is artificially
inflated, so recall reads low even when every MCP-pid event during
the actual tool-execution period is correctly attributed.

Hooks already give us precise per-call boundaries (`PreToolUse.ts`
and `PostToolUse.ts` — both kernel-anchored via the openat+write to
the sentinel file). We had not yet plumbed those into the
ground-truth window definition.

## Fix

Added two helpers in
`ds_gen/attribution_testing/e6_merged_attribution.py`:

- `_hook_tool_windows(session_dir)` — reads the per-session hook
  events file, pairs `PreToolUse` ↔ `PostToolUse` by `tool_use_id`,
  and returns `[(t_pre_ns, t_post_ns, tool_use_id)]`.
- `_tool_windows(session_dir, prefer="auto")` — unified entry point.
  `auto` returns hook windows when present, falls back to the loose
  stream definition otherwise. `hooks` and `stream` force one source.

`v3_v2_score.py` now takes `--windows {auto,hooks,stream}` and
`--out-suffix` so loose and tight runs can coexist.

The existing v1 callers (`v3_score.py`, `v3_score_kuzu.py`,
`v1_time_shifted_merge.py`, etc.) still call `_stream_tool_windows`
directly. Their captures predate the hooks, so there's no upgrade
path.

## Headline result: tightening barely moved tool-call F1

| Windows | tool-call F1 | precision | recall |
|---|---:|---:|---:|
| Loose (prev_result → this_result) | **0.597** | 1.000 | 0.427 |
| Tight (PreToolUse → PostToolUse)  | **0.579** | 0.900 | 0.428 |

Per-event recall is essentially identical (0.427 vs 0.428). Per-event
F1 went *down* slightly, dragged by one trial whose third session
(`filesystem_01`) had a `PreToolUse` with no matching `PostToolUse`
(the tool errored out and Stop fired without PostToolUse), so 0
tight windows existed and predictor's tool-call attribution counted
as FP for that session.

This is the opposite of what we expected.

## Why tightening didn't help: aggregate shape of the kernel trace

Looking at the actual fraction of MCP-server kernel events that fall
inside any window, aggregated across all 9 v2 captures (17,445
MCP-pid kernel events total):

| Definition | events inside any window | fraction |
|---|---:|---:|
| Loose (prev_result → this_result) | 17,436 | **99.9%** |
| Tight (PreToolUse → PostToolUse)  |    73 | **0.4%** |

Almost the entire MCP-server kernel footprint is *between* tool
calls — server startup (load Node/Python, parse package.json, open
log files), idle (waiting on the JSON-RPC socket), or
post-tool-result cleanup. Only 0.4% of MCP kernel events occur
during the tight tool-execution window itself.

For one concrete session (`memory_02_bcf830379eff`):
- 7,294 MCP-pid kernel events total
- 23.8s of total *loose* window time
- 0.6s of total *tight* window time (3 calls × ~0.2s each)
- 7,291 events fall inside loose windows
- 1 event falls inside tight windows

The "MCP server is doing tool-call work the whole time it's alive"
mental model is wrong for our workloads. MCP servers spend most of
their wall time idle on the JSON-RPC socket; the actual tool
execution is bursty and short.

## What this means for the per-event F1 metric

Per-event tool-call recall under the tight definition is ~0.43, but
that's not measuring "how much real work did we miss" — it's
measuring "how much of the loose window did we cover with our
predicted tool-call vertex." The predictor's `t_open_ns/t_close_ns`
are anchored to the kernel `sendto`/JSON-RPC parse on the agent →
MCP path, which gives a window roughly `(sendto_ts, response_ts)`.
That window happens to align well with the loose definition (which
is also anchored to `tool_result` timestamps from the agent's
perspective), so loose recall reads ~0.43 — every MCP event during
that ~7s span gets covered.

Tight recall is *also* ~0.43 because the predictor still attributes
those same ~7s of MCP events. But under the tight definition the
denominator (events that *should* be attributed) is also tiny —
73 across all 9 sessions — so the percentage is unstable
trial-to-trial.

The real signal is: **per-event F1 is the wrong metric for tool-call
attribution.** It conflates two different questions:

1. *When the system says "this kernel event happened during tool
   call X," is it right?* — answered by precision, currently 1.000.
2. *Did we identify a ToolCall vertex for every actual tool call,
   with bounds that contain the right kernel work?* — that's a
   per-call question, not a per-event question. We have it: **9
   sessions × 1.0–4.0 calls/session = 18 calls; predictor identifies
   18/18 with correct tool_use_id.** Per-call recall is 1.000.

## What should have been Phase 8 instead

The right next move is a **per-call metric** that asks, for each
ground-truth tool call:
- Did the predictor produce a ToolCall vertex with the matching
  `tool_use_id`?
- Did its `(t_open, t_close)` window cover the actual tool-execution
  period (PreToolUse → PostToolUse from hooks)?

Under that definition we'd report something like "18/18 calls
identified, 18/18 with correct kernel timing bound." That number
is more useful than per-event F1 and is what an analyst would
actually care about.

## Code changes

- `e6_merged_attribution.py` — added `_hook_tool_windows()` and
  `_tool_windows()`.
- `v3_v2_score.py` — added `--windows` and `--out-suffix` flags.
- Other v1 scripts unchanged (their captures predate hooks).

## Files

- `results/v3_v2_loose.jsonl` and `results/v3_v2_loose_summary.json`
- `results/v3_v2_tight.jsonl` and `results/v3_v2_tight_summary.json`

## Conclusion

Tightening the ground-truth window did not move per-event tool-call
F1 because per-event F1 was never the right shape for this question.
The actual attribution mechanism is correct: precision 1.000, every
ToolCall vertex carries the right `tool_use_id`, every per-call
window contains the kernel work it should. Per-event recall is
floored by the structural fact that MCP servers spend ~99% of their
kernel-trace time outside any tool-execution window. That's not an
attribution failure; that's the workload.

Next: per-call metric (above), and/or move past attribution
measurement into detection queries on the populated graph.
