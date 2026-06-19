// 06: which processes are NOT bound to any session?
//
// Useful for sanity-checking the cgroup-gated inheritance: under the
// hardened rule, system daemons and other-cgroup processes should
// land here, not in any session. If a clearly-session-related comm
// (claude, mcp-server-*) shows up unbound, the inheritance dropped
// something it shouldn't have.

MATCH (p:Process)
WHERE NOT EXISTS { MATCH (p)-[:member_of_session]->(:Session) }
RETURN p.pid           AS pid,
       p.first_comm    AS comm,
       p.first_argv    AS argv
ORDER BY p.t_first_seen_ns;
