// 01: per-session high-level overview
//
// One row per session showing: anchor pid, MCP count, descendant
// process count, and total file/socket touches. Use this as the
// landing query when you open a graph — gives you a feel for what
// the trace contains.

MATCH (s:Session)
WITH s,
     COUNT { MATCH (s)-[:has_mcp]->(:MCP) }                AS n_mcps,
     COUNT { MATCH (:Process)-[:member_of_session]->(s) }  AS n_descendants
RETURN s.session_id   AS session,
       s.anchor_pid   AS anchor_pid,
       n_mcps,
       n_descendants
ORDER BY s.t_start_ns;
