# Phase 5 — agent-layer schema extension

**Date:** 2026-06-08

This phase extends the provenance graph to express agent-shape
abstractions (Session, Iteration, Prompt, Response, Tool, ToolCall)
alongside the existing kernel-shape vertices (Process, File,
Socket). The schema is designed to be agent-platform-agnostic so the
same shape extends to ChatGPT, Qwen, Gemini, or any other tool-using
agent — what changes per agent is the extractor that maps the
agent's transcript format to the common schema.

This doc covers what got added, what we can reliably build today
from the existing L1/L2/L3 captures, and what the known gaps are.

## Motivation

Phase 1–4 produced a provenance graph that was strong on the OS
layer (Process/File/Socket reachable from a Session via the
clone-descendant subtree) but weak on the agent layer — there was
no first-class representation of conversation structure (who asked
what, what the agent answered, which tools were called as part of
which user request). For analyst-facing exploration that's the
abstraction that matters: an investigator opening a graph wants to
ask "what did session X actually do for the user's question?" not
"which pids inherited from the agent's clone caller?"

The Phase 5 schema lets the analyst ask the first question
directly. The kernel-shape vertices remain as leaves of the
agent-shape — the same data, restructured.

## Schema additions

Five new vertex types and ten new edge types, all additive (no
existing vertex/edge was removed). Existing kernel-shape
attribution metrics continue to compute the same numbers.

### New vertices

| Vertex | What it is | Source signal |
|---|---|---|
| **Iteration** | One user-prompt → assistant-response turn within a session | `stream.jsonl` user/assistant boundaries |
| **Prompt** | Text content of the user's input for an iteration | `session.json["prompt"]` (initial), or user message text (subsequent turns in multi-turn agents) |
| **Response** | Text content of the assistant's final output | `result` record's `result` field in `stream.jsonl` |
| **Tool** | Abstract tool definition (name, schema, is_builtin) | `system/init` record's `tools` list |
| ~~ToolCall~~ | (extended) Now carries `iteration_id`, `is_builtin`, `kernel_timing`, `is_error` | existing `tools/call` JSON-RPC + agent transcript |

`Session` also gained two fields: `terminator_status` (clean /
error / timeout / crash) and `terminator_reason` (the agent's
stop_reason or terminal_reason). `terminator_status="clean"` plus
`reason="end_turn"` means a normal completed session.

### New edges

| Edge | Direction | Meaning |
|---|---|---|
| has_iteration | Session → Iteration | An iteration belongs to this session |
| follows | Iteration → Iteration | Temporal ordering within a session (multi-turn) |
| has_prompt | Iteration → Prompt | The user's input for this iteration |
| has_response | Iteration → Response | The agent's response (absent if silent or terminated) |
| issued | Iteration → ToolCall | A tool call dispatched during this iteration |
| exposes | MCP → Tool | A tool advertised by this MCP |
| invokes | ToolCall → Tool | The abstract tool a specific call references |
| handled_by | ToolCall → MCP | Which MCP handled this call (absent for built-in tools) |
| first_call | Iteration → ToolCall | The first ToolCall in this iteration (convenience) |
| next_call | ToolCall → ToolCall | Within an iteration, the next ToolCall in time order |
| parent_call | ToolCall → ToolCall | Cross-tool nesting (e.g., Task tool dispatching subcalls) |

## What's buildable today vs. what's blocked

The schema is intentionally aspirational: not every vertex and edge
is fully reliable from current captures, but the schema can hold
the data when it's available. The status grading:

### Solid (full coverage today)

- **Session, Iteration, Prompt, Response** — all extractable from
  `stream.jsonl` + `session.json`. Reliable.
- **Tool (built-in)** — `system/init`'s tool list is the source of
  truth and is captured every session.
- **Tool (third-party)** — same source. Identifying third-party
  tools by the `mcp__<server>__<tool>` naming convention is
  reliable.
- **ToolCall (third-party)** — uses `tools/call` JSON-RPC frame
  detection from sendto buffers, plus stream.jsonl boundaries.
  Working since Phase 3.
- **All edges between agent-shape vertices** — pure stream.jsonl
  extraction, no kernel involvement.
- **All kernel-shape vertices and edges** — unchanged from Phase 4.
- **Termination status** — `result` record carries it
  unambiguously.

### Partial coverage

- **ToolCall (built-in)** — exists in `stream.jsonl` (we know that
  it happened) but has no kernel-side anchor (the call doesn't
  cross a process boundary). Recorded in the graph with
  `is_builtin=true` and `kernel_timing="approximate"`. The
  `t_open_ns` / `t_close_ns` fields use stream record timestamps,
  which represent when the agent emitted the record — not when
  the syscall actually fired. For per-call kernel attribution
  under concurrency (parallel built-in tool calls), this is
  insufficient — same information-theoretic ceiling as the
  per-tool-call concurrency problem documented earlier.

- **parent_call (nested ToolCalls)** — schema-supported, but our
  current captures rarely use the Task tool or similar nesting,
  so the edge is usually empty. When present
  (`stream.jsonl["parent_tool_use_id"]` is set), the edge is
  authoritative.

### Schema-ready, no real data

- **follows (Iteration → Iteration)** — for multi-turn
  conversations. `claude -p` mode produces single-iteration
  sessions, so the edge is empty in our captures. When we move
  to multi-turn or non-Claude-Code agents, it'll populate.

## Caveats explicit

Three known limitations in the current capture pipeline that
constrain what the schema can express:

1. **Built-in tool kernel-timing is approximate.** The agent
   process executes built-in tools internally — there's no kernel
   event marking the start of `Read("/etc/passwd")` as a tool
   call. We mark these `kernel_timing="approximate"` so analyst
   queries can filter on it. An analyst who only wants
   precisely-attributed tool calls writes
   `WHERE kernel_timing="precise"`. For built-in tools without
   that filter, the during-tool-call attribution uses the stream
   record's emission time, which is best-effort.

2. **Large-MCP `tools/list` truncation is not an issue with this
   approach.** Earlier we worried about the 256B sendto buffer
   truncating the `tools/list` JSON-RPC response for MCPs with
   100+ tools. The Phase 5 extractor sidesteps this by reading
   the agent's `system/init` record (which has the full advertised
   tool list, including all third-party MCP tools). Source of
   truth for Tool vertices is therefore the agent's own perspective
   on what tools it can call, not the wire-level JSON-RPC.

3. **No reading of `~/.claude.json` config contents.** Earlier
   layered-detector design considered parsing the config file's
   bytes. We don't do that and don't need to — the system/init
   record already encodes the agent's effective tool registry.

## What this enables

Three categories of query become natural that weren't expressible
before:

### Iteration-level analysis

```cypher
MATCH (s:Session)-[:has_iteration]->(i:Iteration)
MATCH (i)-[:has_prompt]->(p:Prompt)
OPTIONAL MATCH (i)-[:has_response]->(r:Response)
OPTIONAL MATCH (i)-[:issued]->(tc:ToolCall)
RETURN p.text AS prompt,
       count(DISTINCT tc) AS n_tool_calls,
       r.text AS response,
       i.outcome AS outcome
```

Reads as a conversation transcript with kernel evidence implicit.

### Intent-conditioned detection

```cypher
MATCH (i:Iteration)-[:has_prompt]->(p:Prompt)
WHERE p.text =~ '(?i).*weather.*'
MATCH (i)-[:issued]->(tc:ToolCall)
MATCH (tc:ToolCall {is_builtin: false})-[:handled_by]->(m:MCP)
MATCH (proc:Process)-[:member_of_mcp]->(m)
MATCH (proc)-[:read]->(f:File)
WHERE f.path =~ '.*credentials.*'
RETURN i.iteration_id, p.text, tc.name, f.path
```

That's the threat-model query: "find iterations where the user
asked about something innocuous, but a tool call read credential
files." Today the prompt-to-kernel-event link is one Cypher
query; before Phase 5 it would have required cross-referencing
stream.jsonl by hand.

### Tool-schema validation (forward-looking)

The Tool vertex carries the abstract tool's name and (eventually)
its input schema. ToolCalls reference Tools via `invokes`. That
makes "find ToolCalls whose arguments don't match their Tool's
schema" a one-hop graph query. We don't currently capture tool
schemas (would require extending the `system/init` extractor to
also pull `inputSchema` from the JSON-RPC `tools/list` response,
which we have via stream.jsonl). Schema-ready for when we do.

## Cross-agent generalization

The schema is intentionally agent-platform-agnostic. To support a
new agent (ChatGPT, Qwen, Gemini, etc.) the work is: write an
extractor that maps that agent's transcript format to the same
ExtractedAgentLayer dataclass shape. Once the extractor exists,
the graph builder, Cypher queries, and analyst tooling all work
unchanged.

What varies per agent:
- **Transcript format** — Claude Code uses stream-json with
  user/assistant message records. ChatGPT's API uses a different
  message structure. Qwen has its own format. Each gets its own
  extractor.
- **Built-in tool list** — Claude Code's built-ins include `Read`,
  `Write`, `Bash`, etc. Other agents have different built-ins.
  Hardcoded per agent or extracted from the agent's tool registry
  on session start.
- **MCP detection** — agents that use MCP can share the layered
  MCP detector. Agents that use other tool protocols (OpenAI's
  function calling, Gemini's function declarations) need their
  own protocol-specific MCP-equivalent detection.

What stays invariant:
- The schema (vertices + edges).
- The Cypher detection queries.
- The kernel-shape attribution (Process/File/Socket and the
  Phase 2 cgroup-gated clone-inheritance).
- The Explorer-based visualization.

This is what we mean when we say the schema "generalizes across
agents and hosts." The graph speaks the agent's logical structure,
and detectors written against that structure don't care which
specific agent produced the data.

## Files

- `ds_gen/attribution_testing/kuzu_schema.py` — schema definition
  with the new vertex/edge tables.
- `ds_gen/attribution_testing/agent_layer.py` — Claude Code
  extractor (stream.jsonl + session.json → ExtractedAgentLayer).
- `ds_gen/attribution_testing/graph_builder.py` — `KuzuGraphBuilder`
  with new `ingest_agent_layer()` method and a top-level
  `build_graph_with_agent_layer()` convenience function.

## What's next

Two natural follow-ups:

1. **Agent-layer Cypher query pack.** The existing `queries/`
   directory has six kernel-shape queries. Add ~5 agent-shape
   queries (iteration overview, intent-conditioned detection
   patterns, tool-schema validation if we capture schemas).

2. **A second-agent extractor** to validate the generalization
   claim. ChatGPT's transcript format is the obvious choice; if
   the same schema and queries continue to work after writing a
   ChatGPT extractor, the agent-platform-agnostic claim is
   validated empirically.

These are independent and can happen in either order.
