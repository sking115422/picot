"""Cypher-backed attribution queries that mirror the in-memory
predict() function in e6_merged_attribution.

Given a built Kuzu graph (one per merged trace), produce the same
per-event (session, mcp, tool_call) triples that predict() returns,
but via graph-reachability queries instead of dictionary lookups.

This exists so we can:
1. Verify parity (Phase 2): same F1/Precision/Recall as the in-memory
   version, confirming the graph is a faithful representation.
2. Use the graph as the foundation for later detection queries
   (Phase 3+) without forking the prediction code.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import kuzu

from graph_builder import KuzuGraphBuilder, build_graph


def attribute_events_by_query(builder: KuzuGraphBuilder,
                                merged_events: list) -> list[dict]:
    """Walk the merged events; for each, return the predicted
    (session, mcp, tool_call) triple using Cypher queries against
    the Kuzu graph.

    Mirrors predict() in e6_merged_attribution.

    Note: this is intentionally O(n) Cypher queries — one per event —
    and slow. The point is parity, not speed. For production use we'd
    materialize attribution as columns at flush time. Phase 3 will
    add that path.
    """
    conn = builder.conn

    # Cache pid -> [(session_id, bound_at_ts)] from the graph.
    sess_bindings: dict[int, list[tuple[str, int]]] = {}
    res = conn.execute(
        "MATCH (p:Process)-[r:member_of_session]->(s:Session) "
        "RETURN p.pid, s.session_id, r.bound_at_ts_ns"
    )
    while res.has_next():
        pid, sid, ts_bound = res.get_next()
        sess_bindings.setdefault(pid, []).append((sid, ts_bound))
    for pid in sess_bindings:
        sess_bindings[pid].sort(key=lambda x: x[1])

    mcp_bindings: dict[int, list[tuple[str, int]]] = {}
    res = conn.execute(
        "MATCH (p:Process)-[r:member_of_mcp]->(m:MCP) "
        "RETURN p.pid, m.mcp_id, r.bound_at_ts_ns"
    )
    while res.has_next():
        pid, mid, ts_bound = res.get_next()
        mcp_bindings.setdefault(pid, []).append((mid, ts_bound))
    for pid in mcp_bindings:
        mcp_bindings[pid].sort(key=lambda x: x[1])

    def session_at(pid: int, ts: int) -> str:
        # Last binding whose bound_at_ts_ns <= ts.
        bs = sess_bindings.get(pid, [])
        latest = ""
        for sid, t in bs:
            if t <= ts:
                latest = sid
            else:
                break
        return latest

    def mcp_at(pid: int, ts: int) -> str:
        bs = mcp_bindings.get(pid, [])
        latest = ""
        for mid, t in bs:
            if t <= ts:
                latest = mid
            else:
                break
        return latest

    # Tool calls: list of (mcp_id-or-empty, session_id-or-empty,
    #                       tool_call_id, is_builtin, t_open, t_close).
    # We pull EVERY ToolCall vertex (not just those reached via
    # MCP.has_tool_call), because built-in tool calls have no MCP
    # parent — they're reachable from the Iteration via `issued` and
    # the Iteration is reachable from the Session.
    tool_calls: list[tuple[str, str, str, bool, int, int]] = []
    res = conn.execute(
        "MATCH (s:Session)-[:has_iteration]->(i:Iteration)"
        "-[:issued]->(t:ToolCall) "
        "OPTIONAL MATCH (t)-[:handled_by]->(m:MCP) "
        "RETURN coalesce(m.mcp_id, '') AS mid, "
        "       s.session_id AS sid, "
        "       t.tool_call_id, t.is_builtin, "
        "       t.t_open_ns, t.t_close_ns"
    )
    while res.has_next():
        mid, sess_id, tcid, is_builtin, t_open, t_close = res.get_next()
        tool_calls.append((mid, sess_id, tcid, is_builtin, t_open, t_close))

    # Group tool calls by their owning entity for fast windowed lookup.
    # MCP-handled tool calls are looked up by mcp_id of the event's
    # process; built-ins are looked up by session_id (they fire from
    # the agent's own pid, which has member_of_session but not
    # member_of_mcp).
    tc_by_mcp: dict[str, list[tuple[str, int, int]]] = {}
    tc_by_session_builtins: dict[str, list[tuple[str, int, int]]] = {}
    for mid, sid_, tcid, is_builtin, t_open, t_close in tool_calls:
        if is_builtin:
            tc_by_session_builtins.setdefault(sid_, []).append(
                (tcid, t_open, t_close))
        elif mid:
            tc_by_mcp.setdefault(mid, []).append((tcid, t_open, t_close))

    preds: list[dict] = []
    for me in merged_events:
        e = me.event if hasattr(me, "event") else me
        pid = e.get("pid")
        ts = e.get("ts_ns", 0)
        sid = session_at(pid, ts) if pid is not None else ""
        mid = mcp_at(pid, ts) if pid is not None else ""
        tcid = ""
        # Try MCP-handled first (events from an MCP subtree)
        if mid:
            for cand_tcid, t_open, t_close in tc_by_mcp.get(mid, ()):
                hi = t_close if t_close > 0 else 2 ** 62
                if t_open <= ts <= hi:
                    tcid = cand_tcid
                    break
        # Then try built-in (events from agent's own pid in this session)
        if not tcid and sid:
            for cand_tcid, t_open, t_close in \
                    tc_by_session_builtins.get(sid, ()):
                hi = t_close if t_close > 0 else 2 ** 62
                if t_open <= ts <= hi:
                    tcid = cand_tcid
                    break
        preds.append({"session": sid, "mcp": mid, "tool_call": tcid})
    return preds


def build_and_attribute(merged_events: list, db_path: Path) -> tuple:
    """Build the Kuzu graph for a merged trace and run the attribution
    queries. Returns (predictions, builder)."""
    builder = build_graph(merged_events, db_path)
    preds = attribute_events_by_query(builder, merged_events)
    return preds, builder
