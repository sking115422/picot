# Attribution-testing hooks for Claude Code

A small hook bundle that emits agent-layer boundary events to a
sentinel file. The events are kernel-visible (one openat+write per
hook fire), so our existing eBPF sensors (L2/L3) capture them
alongside the rest of the host trace. The hook-derived agent-layer
extractor reads these events and uses them to anchor Iteration,
Prompt, ToolCall, and Response vertices in our provenance graph.

## What's here

| File | Purpose |
|---|---|
| `attribution_hook.sh` | Bash entrypoint Claude Code invokes |
| `attribution_hook.py` | Python dispatcher that writes to the sentinel file |
| `install.sh` | One-shot installer that patches `~/.claude/settings.json` |
| `README.md` | This file |

## Install

```bash
cd /lts/ai_sec_exp/picot/attribution_testing/hooks
./install.sh                   # backs up settings.json, registers hooks
ATTR_HOOKS_DRY_RUN=1 ./install.sh   # preview without modifying
```

The installer:
1. Backs up `~/.claude/settings.json` to
   `~/.claude/settings.json.bak.<timestamp>`.
2. Replaces the `hooks` block with a fresh registration that points
   all five hook events (SessionStart, UserPromptSubmit, PreToolUse,
   PostToolUse, Stop, SessionEnd) at `attribution_hook.sh`.
3. Prints how to revert.

To revert: `cp ~/.claude/settings.json.bak.<timestamp> ~/.claude/settings.json`.

## What gets captured

Each hook fire writes one JSON line to:

```
~/.cache/agenttrace/attribution_testing/<session_id>.events.jsonl
```

Per-event fields:

| Field | When | Meaning |
|---|---|---|
| `ts` | always | wall-clock seconds at hook fire |
| `hook` | always | which hook event |
| `session_id` | always | agent's own session UUID |
| `agent_pid` | always | PID of the agent process |
| `cwd` | always | agent's cwd at hook time |
| `tool_use_id` | Pre/PostToolUse | Claude Code's tool_use id |
| `parent_tool_use_id` | Pre/PostToolUse | parent's tool_use_id when nested |
| `tool_name` | Pre/PostToolUse | e.g. "Read", "mcp__memory__add_observations" |
| `tool_input` | Pre/PostToolUse | the tool's input args |
| `is_error` | PostToolUse | whether the call errored |
| `prompt` | UserPromptSubmit | user's prompt text |
| `stop_hook_active` | Stop | whether Stop was invoked by another hook |
| `stop_reason` | Stop | termination reason |

## What's NOT captured

Kernel events. Per-tool-call kernel attribution is done downstream
by joining the boundary timestamps in this file against the L2/L3
host eBPF trace. The hooks capture only what we can't reconstruct
from the trace — the agent's own structured context at boundary
moments.

## Replacing existing hooks

This installer replaces the `hooks` block wholesale. If you had
other hooks registered (e.g. an older project's telemetry hooks),
they will be removed. The pre-install backup file lets you recover
the previous configuration; you can also merge by hand.

## Verifying the install

After installing, run any Claude Code session. The sentinel file
appears at `~/.cache/agenttrace/attribution_testing/<sid>.events.jsonl`
within a second or two of session start. Tail it to see events as
they fire:

```bash
tail -f ~/.cache/agenttrace/attribution_testing/*.events.jsonl
```

If nothing appears, check `~/.cache/agenttrace/attribution_testing/hook_errors.log`
for hook-side errors, and confirm Claude Code picked up the new
settings (it reads `~/.claude/settings.json` at session start, so
restart any in-flight sessions).
