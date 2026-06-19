// 02: render one session's full subgraph
//
// Returns the Session vertex, its MCPs, the Process vertices bound
// to it, and a few file/socket leaves to keep the rendered graph
// readable. Set $session to the session id you want to inspect.

MATCH (s:Session {session_id: $session})
OPTIONAL MATCH (s)-[:has_mcp]->(m:MCP)
OPTIONAL MATCH (m)-[:has_tool_call]->(t:ToolCall)
OPTIONAL MATCH (p:Process)-[:member_of_session]->(s)
OPTIONAL MATCH (p)-[:read|write]->(f:File)
WITH s, m, t, p, f
LIMIT 500
RETURN s, m, t, p, f;
