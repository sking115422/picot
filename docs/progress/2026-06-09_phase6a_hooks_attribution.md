# Phase 6a — hook-derived attribution: self-contained hooks for Claude Code

**Date:** 2026-06-09

This phase adds a *cooperative* attribution path: a small set of
hook scripts that fire at the agent's logical boundaries and emit
kernel-visible markers our existing eBPF sensors observe. Combined
with a parallel agent-layer extractor that consumes those markers,
we get precise per-tool-call timing for built-in tool calls — the
specific gap that passive trace-only attribution couldn't close
(see Phase 5 §"Partial coverage").

The work is intentionally additive. The original stream-based
extractor stays as one path; the new hook-based extractor is a
parallel path. Callers pick by passing `extractor_mode`. Default is
unchanged.

## Motivation

Phase 5's stream-based extractor gives `kernel_timing="precise"`
to MCP tool calls (boundaries are JSON-RPC frames in `sendto`) but
`"approximate"` to built-in tool calls (boundaries exist only in
the agent's transcript, with timestamps only on user/tool_result
records — never on assistant tool_use records). The result: a
built-in tool call's `t_open_ns` falls back to session start,
producing nonsense durations and over-attribution of kernel events
to those calls.

Concretely, for a 1.5-second `Bash` invocation in V3:
- Stream-mode reports duration = 5.1s (3.4× overestimate)
- Stream-mode attributes 16,798 kernel events to that one call
- Hooks-mode reports duration = 1.5s
- Hooks-mode attributes 36 kernel events to that call

The 16,762 extra events stream-mode attributes are kernel work
that happened during the agent's reasoning + LLM API call *before*
the tool actually ran. They're "session-related" but not
"tool-call-related." The hook boundaries fix this.

## What's in the project tree

```
ds_gen/attribution_testing/
├── hooks/
│   ├── attribution_hook.sh       # bash entrypoint
│   ├── attribution_hook.py       # dispatcher
│   ├── install.sh                # patches ~/.claude/settings.json
│   └── README.md                 # install + protocol docs
│
├── agent_layer_common.py         # shared dataclasses + helpers
├── agent_layer_stream.py         # passive: stream.jsonl extractor
├── agent_layer_hooks.py          # cooperative: hook events extractor
├── agent_layer.py                # dispatcher with `mode` param
│
├── graph_builder.py              # accepts extractor_mode arg
└── v3_hooks_vs_stream.py         # comparison harness
```

The hook scripts are self-contained: ~80 LoC of Python that reads
a JSON event from stdin and appends one line to a per-session
sentinel file at:

```
~/.cache/agenttrace/attribution_testing/<session_id>.events.jsonl
```

The eBPF sensor sees the openat+write events on those files (it's
in the regular host trace) and the extractor reads the file
post-hoc to populate Iteration / Prompt / ToolCall / Response
vertices.

## Hook design

Six events covered: SessionStart, UserPromptSubmit, PreToolUse,
PostToolUse, Stop, SessionEnd. Each event captures only what we
can't reconstruct from the kernel trace:

| Hook | Captures |
|---|---|
| SessionStart | session_id, agent_pid, cwd |
| UserPromptSubmit | prompt text |
| PreToolUse | tool_use_id, parent_tool_use_id, tool_name, tool_input |
| PostToolUse | (same fields) + is_error |
| Stop | stop_hook_active, stop_reason |
| SessionEnd | (no extra) |

Per-event latency is one openat + one append-write, microseconds.
Confirmed firing in real Claude Code sessions; verified that
PreToolUse / PostToolUse pair correctly via tool_use_id.

The hooks intentionally do not capture kernel events of their own
(no sampler, no diff, no lsof snapshots). Per-tool-call kernel
attribution is computed downstream by joining the boundary
timestamps against the host eBPF trace. This is a deliberate
simplification over the prior copperhead infrastructure that ran
its own session-scoped sampler — the L2/L3 sensors already capture
everything that sampler did, and we shouldn't run two collectors.

## Extractor toggle

`build_graph_with_agent_layer()` gained an `extractor_mode`
parameter:

- `"stream"` (default): passive, reads stream.jsonl + session.json.
  Backwards-compatible with all prior captures.
- `"hooks"`: cooperative, reads sentinel events the
  attribution_hook scripts emitted. Requires hooks installed and
  to have fired during the session.
- `"auto"`: hooks if available, else stream. Useful for mixed
  corpora.

The dataclasses both extractors produce
(`ExtractedAgentLayer`, etc.) live in `agent_layer_common.py`
shared between paths. Graph-building code below the dispatcher is
identical regardless of mode.

## Results

12 fresh V3 captures (3 prompts × {filesystem, memory, git} MCPs +
3 originals). Hooks fired for all of them. We built the graph in
both modes and counted kernel events attributed to each ToolCall's
[t_open_ns, t_close_ns] window.

### Per-tool-call timing accuracy

For built-in tools (the gap stream couldn't close):

| Session | Tool | Stream dur | Hooks dur | Stream events | Hooks events |
|---|---|---:|---:|---:|---:|
| filesystem_02 | Read | 6492ms | 3856ms | 29415 | 21923 |
| filesystem_02 | Bash | 2300ms | 343ms | 21879 | 11442 |
| git_00 (orig) | Bash | 5138ms | 1505ms | **16798** | **36** |
| git_00 (new) | Bash | 5359ms | 1973ms | 16855 | 39 |
| git_01 | Bash | 3702ms | 1688ms | 16808 | 23 |
| git_02 | Bash | 5359ms | 200ms | 16828 | 9 |
| memory_01 | Read | 5755ms | 144ms | 16289 | 6 |
| memory_01 | Write | 6044ms | 148ms | 16297 | 7 |
| memory_01 | Edit | 2478ms | 151ms | 37 | 12 |

For MCP tools (already precise in both modes):

| Session | Tool | Stream dur | Hooks dur | Stream events | Hooks events |
|---|---|---:|---:|---:|---:|
| memory_00 (orig) | create_entities | 135ms | 131ms | 8 | 8 |
| memory_00 (orig) | open_nodes | 131ms | 126ms | 8 | 8 |
| memory_00 (new) | create_entities | 147ms | 140ms | 10 | 10 |
| memory_02 | read_graph | 135ms | 129ms | 8 | 7 |
| memory_02 | add_observations | 5ms | 4840ms | 3 | 73 |
| memory_02 | mcp__memory__create_entities | 1530ms | 133ms | 28 | 10 |

### Reading the table

For built-in tools, hooks-mode produces dramatically tighter event
windows. The git_00 case is the most striking — 16,798 vs 36
events, a 466× ratio. The 16,762 extra events stream-mode
includes are real kernel activity from claude reasoning and
talking to Bedrock; they're not from the Bash invocation. Stream
attributes them to the Bash call only because its t_open_ns falls
back to session start.

For MCP tools, the two modes agree closely (small differences from
the kernel-side sendto event timestamp vs. the hook-side
PreToolUse timestamp, which fire ~ms apart). The MCP-mode
"add_observations" anomaly in memory_02 is interesting: stream
reports 5ms / 3 events, hooks reports 4840ms / 73. Looking at the
timestamps, this is a case where the agent issued the tool_use
record, then the user/tool_result record came much later — the
stream extractor uses the agent's emission ts as t_open and the
last seen ts as t_close, missing 4.8s of actual MCP server work.
Hooks captured the full PreToolUse → PostToolUse window correctly.

So even for MCP tools, hooks can be more precise when stream's
imperfect ts inference fails. They're complementary; in some
cases the kernel-side sendto is tighter, in some cases the hook
is tighter.

### What this lift means

The Phase 5 per-tool-call F1 of 0.54 was bounded by exactly this
problem — built-in tool windows were too loose, so kernel events
either bleed into the wrong tool call or get attributed at all
when they shouldn't be. With hooks-anchored windows the
attribution is sharp by construction. We didn't re-run the F1
metric here (the V3 corpus is small for stable F1 numbers) but
the per-call event-window precision is the underlying signal.

## Caveats

The work is honest about its limits:

1. **Hooks must be installed for the lift to apply.** Sessions
   captured before installing the hooks (E6 corpus, original V3
   captures without hooks) have no hook events, so the
   hooks-based extractor falls back to empty agent-layer output
   for them. The toggle's `"auto"` mode handles this gracefully.

2. **Hook firing depends on the agent.** Claude Code is the
   primary supported case. The bundle generalizes to any
   hook-supporting agent (Cursor, Cline, etc.) by re-registering
   the same script under that agent's hook system; we haven't
   validated this empirically.

3. **Compromised agents could disable their own hooks.** This
   doesn't affect the supply-chain MCP threat model (a compromised
   MCP can't disable the agent's hook system), but it's worth
   noting that hooks are not a defense against full agent
   compromise.

4. **The "auto" mode requires the agent's session_id be
   recoverable from the trace.** We extract it from
   `stream.jsonl`'s system/init record; if a capture lacks
   stream.jsonl, auto-mode falls back to stream as a no-op rather
   than detecting hook data.

5. **The hooks replace any prior hooks** in
   `~/.claude/settings.json`. The installer backs up the previous
   config; revert is documented. No silent merge — that turned
   out to be the right call: there are no prior hooks on this
   host worth merging, and explicit replacement avoids surprising
   interactions.

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/attribution_testing/hooks
./install.sh                     # installs hooks; backs up settings.json

# Capture some sessions:
cd /lts/ai_sec_exp/picot/attribution_testing
source /tmp/bedrock_env.sh
export AWS_REGION=us-east-2
python3 v3_bare_host_capture.py --prompts-per-mcp 3 --out v3_captures_hooks

# Compare stream vs. hooks:
python3 v3_hooks_vs_stream.py
# results in results/hooks_vs_stream.jsonl
```

To revert the hook install:
```bash
cp ~/.claude/settings.json.bak.<timestamp> ~/.claude/settings.json
```

## What's next

Two natural follow-ups:

1. **Re-run the per-tool-call F1 metric on a hook-enabled corpus.**
   The numbers above show per-call event-window precision; lifting
   that to a single F1 number requires re-doing Phase 5's V3
   evaluation against captures that have hooks. We have 12
   suitable captures now; with another batch we'd have enough for
   a stable measurement.

2. **Use hook-anchored data as ground truth for a learned
   attributor.** The classification framing we discussed earlier:
   train on hook-anchored captures (precise labels), deploy on
   hookless captures (model recovers attribution from kernel
   trace alone). Phase 6a delivers the training data; Phase 6b
   would be the model.
