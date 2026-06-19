// 05: per-tool-call activity summary
//
// For each ToolCall vertex, count how many file/socket events
// happened during its [t_open_ns, t_close_ns] window in the MCP's
// subtree. This is the per-tool-call attribution result expressed
// as a graph query.

MATCH (m:MCP)-[:has_tool_call]->(t:ToolCall)
MATCH (p:Process)-[:member_of_mcp]->(m)
OPTIONAL MATCH (p)-[r:read|write]->(f:File)
WHERE r.ts_ns >= t.t_open_ns
  AND (t.t_close_ns < 0 OR r.ts_ns <= t.t_close_ns)
WITH t, m, p, count(r) AS n_file_ops
OPTIONAL MATCH (p)-[s:connect|send|recv]->(sk:Socket)
WHERE s.ts_ns >= t.t_open_ns
  AND (t.t_close_ns < 0 OR s.ts_ns <= t.t_close_ns)
RETURN t.tool_call_id     AS tool_call,
       t.name             AS tool_name,
       m.name             AS mcp,
       (t.t_close_ns - t.t_open_ns) / 1000000 AS dur_ms,
       sum(n_file_ops)    AS n_file_ops,
       count(s)           AS n_socket_ops
ORDER BY t.t_open_ns;
