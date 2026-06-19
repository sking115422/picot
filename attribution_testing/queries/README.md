# Provenance graph queries — analyst exploration

A small set of Cypher queries for inspecting attribution graphs
built by `graph_builder.py`. Run them in Kuzu Explorer (see
`../explorer.sh`) or programmatically via the Python `kuzu` package.

## Launch the Explorer

```bash
cd /lts/ai_sec_exp/picot/attribution_testing
./explorer.sh kuzu_graphs/cgroup_smoke.kz
# open http://localhost:8000
```

The launcher mounts the graph file read-only, so you can't
accidentally mutate captures from the UI.

## Where to start (suggested order)

1. **`01_session_overview.cypher`** — first thing to run. Shows
   how many sessions are in the graph and how many descendants
   each one has. Sanity check that the build worked.

2. **`02_session_subgraph.cypher`** — pick a session_id from query
   1, paste it as the `$session` parameter, get a renderable
   subgraph view. Best query for "what does this session look
   like?" Limited to 500 rows so the UI can draw it.

3. **`03_mcp_touch_set.cypher`** — what each MCP server actually
   touched at the kernel layer. Cross-check against expectations
   (e.g., the filesystem MCP should be touching `/home/ubuntu/work/`
   files, the memory MCP should be touching its own state file,
   neither should be opening `~/.aws/credentials`).

4. **`04_credential_forward_trace.cypher`** — the headline
   detection-shaped query. Finds any process that read a
   credential-path file and shows what it did afterward (writes,
   network connects). Empty result = no credential touches in
   this graph. Non-empty rows are the things to investigate.

5. **`05_tool_call_activity.cypher`** — per-tool-call event count
   broken down by file/socket. Lets you see which tool calls
   were heavy I/O vs. light, and whether activity is concentrated
   correctly in the MCP subtree.

6. **`06_orphan_processes.cypher`** — sanity-check on the
   cgroup-gated inheritance. Should return system daemons
   (irqbalance, systemd-resolve) and other-cgroup processes,
   NOT anything claude- or MCP-related. If you see a `claude`
   or `mcp-server-*` comm here, attribution dropped something.

## Notes on query parameters

Kuzu Explorer takes parameters via the parameter panel
(top of the editor). For query 02, set `session` to a session_id
from query 01 (the strings look like `sess_0`, `sess_1`, etc.).

## Note on schema

The schema is documented in [../kuzu_schema.py](../kuzu_schema.py).
Vertices: Session, MCP, ToolCall, Process, File, Socket. Edges:
child_of, member_of_session, member_of_mcp, has_mcp,
has_tool_call, read, write, unlink, connect, send, recv, bind.
Both `member_of_*` edges carry a `bound_at_ts_ns` field useful
for diagnosing attribution-rule edge cases.
