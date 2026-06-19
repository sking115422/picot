"""Phase 3b: cohesion-based session-descendant filtering.

Motivation: V3 showed that on bare host, Claude's clone-descendant
subtree includes hook subprocesses (pgrep, ps, lsof spawned by
copperhead.sh) and unrelated background processes that briefly
inherited via the 200ms clone window. These get attributed to a
session by the standard mechanism but don't really belong to the
agent's tool-related work.

The cohesion test: a session's MCPs touch a specific set of files
and sockets. A *real* descendant of the session — one doing work
on behalf of the agent's tool calls — is likely to touch some of
the same files/sockets. A drive-by descendant (sshd briefly
inheriting through a clone-window collision, or a hook spawned for
unrelated reasons) won't.

Mechanism:
1. For each session in a Kuzu graph, compute its MCP touch-set:
   File vertices read/written/unlinked by any process in any of the
   session's MCP subtrees, plus Socket vertices connected/sent-to.
2. For each pid that is `member_of_session` for that session BUT
   not `member_of_mcp` for any of its MCPs (i.e., agent-side
   descendants that are not MCP servers themselves), compute its
   own File+Socket touch-set.
3. The cohesion score = |overlap| / |pid's touch-set|. If below a
   threshold (default 0.10), the pid is demoted: its
   member_of_session edge is removed.

We do this as a post-build pass on the graph, mutating the
session-membership edges. The original detector's output stays
available; we record demotions in a new `demoted` REL TABLE so
queries can recover them.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import kuzu


@dataclass
class CohesionStats:
    n_pids_examined: int = 0
    n_pids_demoted: int = 0
    pids_demoted: list[int] = None
    threshold_used: float = 0.0


def _ensure_demoted_table(conn: kuzu.Connection) -> None:
    """Add the demoted-membership tracking table if not present."""
    try:
        conn.execute(
            "CREATE REL TABLE demoted_session_membership("
            "FROM Process TO Session, "
            "reason STRING, cohesion_score DOUBLE)"
        )
    except RuntimeError as e:
        if "already exists" not in str(e).lower():
            raise


def _query_to_set(conn: kuzu.Connection, query: str) -> set:
    out: set = set()
    res = conn.execute(query)
    while res.has_next():
        row = res.get_next()
        # If single column, store the value; otherwise tuple.
        out.add(row[0] if len(row) == 1 else tuple(row))
    return out


def cohesion_filter(conn: kuzu.Connection,
                      threshold: float = 0.10) -> CohesionStats:
    """Walk every session in the graph; demote low-cohesion descendants.

    Returns stats; mutates the graph (removes member_of_session edges
    for demoted pids and records them in demoted_session_membership).
    """
    _ensure_demoted_table(conn)
    stats = CohesionStats(threshold_used=threshold, pids_demoted=[])

    # Enumerate sessions
    sessions: list[str] = []
    res = conn.execute("MATCH (s:Session) RETURN s.session_id")
    while res.has_next():
        sessions.append(res.get_next()[0])

    for sid in sessions:
        # Compute the SESSION touch-set: files and sockets touched by
        # ANY process bound to this session (including MCP descendants
        # AND non-MCP descendants like the agent itself, hooks, etc.).
        # The cohesion test asks "is this pid doing work that overlaps
        # with what the rest of this session is doing?" — anything
        # genuinely in-session touches files the session touches.
        session_files = _query_to_set(conn, f"""
            MATCH (p:Process)-[:member_of_session]->
                  (s:Session {{session_id: '{sid}'}})
            MATCH (p)-[:read|write|unlink]->(f:File)
            RETURN DISTINCT f.path
        """)
        session_sockets = _query_to_set(conn, f"""
            MATCH (p:Process)-[:member_of_session]->
                  (s:Session {{session_id: '{sid}'}})
            MATCH (p)-[:connect|send|recv|bind]->(sk:Socket)
            RETURN DISTINCT sk.sock_key
        """)

        if not session_files and not session_sockets:
            continue

        # Find session-descendant pids that are NOT in any MCP subtree.
        # Those are the candidates for cohesion check.
        cand_res = conn.execute(f"""
            MATCH (p:Process)-[:member_of_session]->(s:Session {{session_id: '{sid}'}})
            WHERE NOT EXISTS {{
                MATCH (p)-[:member_of_mcp]->(:MCP)
            }}
            AND p.pid <> s.anchor_pid
            RETURN p.pid
        """)
        cand_pids: list[int] = []
        while cand_res.has_next():
            cand_pids.append(cand_res.get_next()[0])

        for pid in cand_pids:
            stats.n_pids_examined += 1
            # Compute pid's own touch-set
            pid_files = _query_to_set(conn,
                f"MATCH (p:Process {{pid: {pid}}})-[:read|write|unlink]"
                f"->(f:File) RETURN DISTINCT f.path"
            )
            pid_sockets = _query_to_set(conn,
                f"MATCH (p:Process {{pid: {pid}}})"
                f"-[:connect|send|recv|bind]->(sk:Socket) "
                f"RETURN DISTINCT sk.sock_key"
            )
            denom = len(pid_files) + len(pid_sockets)
            if denom == 0:
                # No file/socket activity — can't measure cohesion;
                # leave attribution alone.
                continue

            # Compute the touch-set of the SESSION EXCLUDING THIS PID.
            # We need this because pid's own touches are part of the
            # session-files union (we built session_files including
            # all bound pids), so naive overlap would always be high.
            others_files = _query_to_set(conn, f"""
                MATCH (p:Process)-[:member_of_session]->
                      (s:Session {{session_id: '{sid}'}})
                WHERE p.pid <> {pid}
                MATCH (p)-[:read|write|unlink]->(f:File)
                RETURN DISTINCT f.path
            """)
            others_sockets = _query_to_set(conn, f"""
                MATCH (p:Process)-[:member_of_session]->
                      (s:Session {{session_id: '{sid}'}})
                WHERE p.pid <> {pid}
                MATCH (p)-[:connect|send|recv|bind]->(sk:Socket)
                RETURN DISTINCT sk.sock_key
            """)
            overlap = (len(pid_files & others_files)
                       + len(pid_sockets & others_sockets))
            score = overlap / denom

            if score < threshold:
                # Demote: remove member_of_session, record in
                # demoted_session_membership.
                conn.execute(f"""
                    MATCH (p:Process {{pid: {pid}}})-[r:member_of_session]
                          ->(s:Session {{session_id: '{sid}'}})
                    DELETE r
                """)
                conn.execute(f"""
                    MATCH (p:Process {{pid: {pid}}}),
                          (s:Session {{session_id: '{sid}'}})
                    CREATE (p)-[:demoted_session_membership
                                {{reason: 'low_cohesion',
                                  cohesion_score: {score}}}]->(s)
                """)
                stats.n_pids_demoted += 1
                stats.pids_demoted.append(pid)

    return stats
