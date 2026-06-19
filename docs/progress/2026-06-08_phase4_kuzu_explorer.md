# Phase 4 — Kuzu Explorer setup and analyst exploration

**Date:** 2026-06-08

This doc covers the visualization side of the provenance-graph
work: how to launch Kuzu Explorer against a captured graph, what
the saved Cypher queries do, and what to look at when poking at one
of the V3 sessions.

## Setup

Kuzu Explorer ships as a Docker image with a bundled `kuzu` Node
binding. Our graphs were built with `kuzu==0.11.3`; the image at
`kuzudb/explorer:latest` has the matching version.

The launcher is at
`ds_gen/attribution_testing/explorer.sh`. It bind-mounts the parent
directory of a `.kz` file as read-only, sets `KUZU_DIR` and
`KUZU_FILE` to point Explorer at the graph, and exposes the UI on
`http://localhost:8000`.

```bash
cd /lts/ai_sec_exp/picot/attribution_testing
./explorer.sh kuzu_graphs/cgroup_smoke.kz   # any built graph
# open http://localhost:8000
# Ctrl-C in the terminal stops the container
```

The graph is mounted read-only so accidental UI mutations can't
corrupt our captures.

## Saved queries

Six Cypher queries live at `ds_gen/attribution_testing/queries/`,
plus a README. Suggested order to run them in:

| File | What it does |
|---|---|
| `01_session_overview.cypher` | First thing to run. One row per session: anchor pid, MCP count, descendant count. Sanity check the build. |
| `02_session_subgraph.cypher` | Pick a session id from query 1; render its full subgraph (Session, MCPs, Processes, sample files). Best for visual inspection. |
| `03_mcp_touch_set.cypher` | What each MCP server actually touched (files + sockets). Cross-check against expectations. |
| `04_credential_forward_trace.cypher` | Headline detection-shaped query. Finds processes that read credential-path files and shows their later writes/connects. |
| `05_tool_call_activity.cypher` | Per-tool-call event count, broken down by file/socket. |
| `06_orphan_processes.cypher` | Processes NOT bound to any session. Sanity-check on cgroup-gated inheritance — should return system daemons, not anything claude/MCP. |

Each query is self-documenting; see the queries/ directory.

## Walkthrough — a V3 session in Explorer

This section walks through what to look at in a single bare-host
benign capture. It assumes the Explorer is running against
`kuzu_graphs/cgroup_smoke.kz` (a single V3 session, ~134k events).

### Step 1: get oriented

Run `01_session_overview.cypher`. You should see one session,
something like:

```
session  anchor_pid  n_mcps  n_descendants
sess_0   101903      1       52
```

One session, anchored at the `claude -p` pid (101903), with one
loaded MCP (memory-server) and 52 descendant processes bound to
it under cgroup-gated inheritance.

### Step 2: render the session subgraph

In query 02, set `$session = 'sess_0'`. Explorer renders the
graph: Session → MCP → ToolCall vertices in the center, Process
vertices around them, File vertices as leaves.

Things to look at:

- The MCP vertex: confirm its anchor_pid (~101903's child) is the
  `mcp-server-memory` process.
- The `claude` Process vertex (anchor_pid) has many `child_of`
  edges to short-lived subprocesses — these are claude's own
  parallel tool work.
- The MCP's subtree is smaller — the memory MCP doesn't fan out
  much.

### Step 3: cross-check the MCP touch-set

Run `03_mcp_touch_set.cypher`. The memory MCP should touch its
own state file (`~/.claude/projects/.../memory/MEMORY.md` or
similar) and a small number of Bedrock-related TLS sockets if it
does any direct LLM calls (most MCPs don't — claude does the LLM
calls and forwards results to the MCP).

If you see the MCP touching `~/.aws/credentials` or
`~/.ssh/...`, that is the threat-model alarm condition. In a
benign capture, you should NOT see those paths under the MCP.

### Step 4: run the credential forward-trace

Run `04_credential_forward_trace.cypher`. On a V3 benign capture
you should see a few rows:

- One for `claude` itself reading `~/.aws/credentials` — expected,
  this is how the agent authenticates to Bedrock.
- Possibly one for `git` reading `~/.netrc` — expected if claude
  invoked git for a workspace operation.

What would be alarming: a row whose `mcp` column is non-empty
(meaning a process bound to an MCP read credentials). The schema
of the query already filters down to "process read credential
file then did something else"; if that process is in an MCP's
subtree, the threat model is satisfied.

### Step 5: check the orphan list

Run `06_orphan_processes.cypher`. The list should consist of:
- System daemons (irqbalance, systemd-resolve, sshd workers)
- Other-cgroup processes from your host (VS Code language
  servers, fabric-manager, etc.)
- Pre-existing processes that started before the trace began

What should NOT be in this list: any pid whose comm is `claude`,
`mcp-server-*`, `node` running an MCP script, or any descendant
of a session anchor. If those appear here, attribution dropped
something — either the cgroup-gating rejected an inheritance it
shouldn't have, or the session-root execve detection missed a
session.

## What this enables that the per-event-color view didn't

Three things become natural in the graph framing:

1. **Subgraph rendering** — the entire structure of a session is
   visible at once. The per-event-color view requires you to
   filter all events by attribution and reconstruct the
   structure mentally.
2. **One-hop reachability queries** — "did MCP X touch file F"
   becomes a single-edge match. "Did this tool call do any
   network I/O" is a `during`-window-bounded edge filter. Both
   were multi-step manual scans before.
3. **Forward-trace queries** — query 04 is the canonical
   example. It expresses "data flowed from credential file to
   network destination through process P" as a graph traversal
   instead of a manual cross-event correlation.

The per-event-color view (the dict-based predictor's output) is
still computed under the hood; the graph is built from those same
attributions. What changed is the *interface* for analysis:
analyst-facing exploration becomes Cypher, not pandas, and visual
inspection becomes "render the subgraph" instead of "read
JSONL and grep."

## Limits of the visualization

A couple of practical notes for what doesn't work well yet:

- **Whole-session graphs with thousands of file vertices render
  slowly.** Query 02 limits to 500 nodes for that reason. For a
  large session, the right approach is filtered views (per-MCP,
  per-tool-call) rather than whole-session.
- **Path-string identity for files** means a file that gets
  unlinked and recreated at the same path becomes one vertex,
  not two. For our threat model this is acceptable; if we ever
  needed (dev, inode) identity, the sensor would need to be
  extended to capture stat info.
- **No time-axis playback in Explorer.** It renders a static
  graph. Time-windowed views (per-tool-call) require running
  Cypher with explicit timestamp predicates rather than scrubbing
  a timeline.

These are mostly inconveniences, not blockers. The graph
structure is the deliverable; visualization is the analyst's
window into it.

## Files

- `ds_gen/attribution_testing/explorer.sh` — Docker launcher
- `ds_gen/attribution_testing/queries/` — six saved Cypher queries
  with a README on suggested order and parameters
- `ds_gen/attribution_testing/kuzu_graphs/` — built graphs
  (any `.kz` file works as input to `explorer.sh`)
