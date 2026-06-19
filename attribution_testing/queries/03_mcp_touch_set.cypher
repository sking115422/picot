// 03: what files and sockets did each MCP server touch?
//
// One row per (MCP, file/socket touched) pair. This is the
// detection-query primitive — anything an MCP touches at the kernel
// layer shows up here, regardless of which tool call it happened
// during. Useful as a sanity check that an MCP isn't reading
// suspicious paths or connecting to suspicious destinations.

MATCH (m:MCP)
MATCH (p:Process)-[:member_of_mcp]->(m)
OPTIONAL MATCH (p)-[r:read|write|unlink]->(f:File)
RETURN m.name      AS mcp,
       'file'      AS kind,
       f.path      AS target,
       count(r)    AS n_ops
WHERE f IS NOT NULL
UNION
MATCH (m:MCP)
MATCH (p:Process)-[:member_of_mcp]->(m)
OPTIONAL MATCH (p)-[r:connect|send|recv|bind]->(s:Socket)
RETURN m.name      AS mcp,
       'socket'    AS kind,
       s.daddr + ':' + toString(s.dport) AS target,
       count(r)    AS n_ops
WHERE s IS NOT NULL
ORDER BY mcp, n_ops DESC;
