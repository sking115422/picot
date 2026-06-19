"""Build a Kuzu provenance graph from a merged host-trace stream.

The control flow mirrors e6_merged_attribution.predict(): single pass
over events sorted by ts_ns, opening Session/MCP/ToolCall vertices on
their anchor events and tracking process descendants via a 200ms
clone-inheritance window.

Implementation strategy: do the full attribution walk in pure Python
first, accumulating vertex and edge rows into in-memory lists. At the
end, bulk-load them into Kuzu via DataFrame COPY. This is ~100x
faster than per-event Cypher CREATE statements.
"""
from __future__ import annotations

import base64
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import kuzu
import pandas as pd

from kuzu_schema import apply_schema
from e6_merged_attribution import (
    is_session_root, parse_tools_call,
)
from mcp_detector import (
    StructuralState, layered_is_mcp_root, is_likely_mcp_via_jsonrpc,
)


@dataclass
class _PendingClone:
    caller_pid: int
    ts_ns: int
    caller_cgroup: int | None = None


class GraphRows:
    """Accumulator for vertex/edge rows as we walk the trace.

    Uses tuple-keyed sets to dedupe before flushing to Kuzu (since the
    same Process/File/Socket vertex may be touched many times during
    the walk and Kuzu's CREATE will fail on PK collisions)."""

    def __init__(self):
        # Kernel-shape vertices keyed by primary key
        self.sessions: dict[str, dict] = {}
        self.mcps: dict[str, dict] = {}
        self.tool_calls: dict[str, dict] = {}
        self.processes: dict[int, dict] = {}
        self.files: dict[str, dict] = {}
        self.sockets: dict[str, dict] = {}

        # Agent-shape vertices
        self.iterations: dict[str, dict] = {}
        self.prompts: dict[str, dict] = {}
        self.responses: dict[str, dict] = {}
        self.tools: dict[str, dict] = {}

        # Kernel-shape edges
        self.child_of: list[dict] = []
        # member_of_*: keyed by (pid, entity_id); value = bound_at_ts_ns
        self.member_of_session: dict[tuple[int, str], int] = {}
        self.member_of_mcp: dict[tuple[int, str], int] = {}
        self.has_mcp: set[tuple[str, str]] = set()
        self.has_tool_call: set[tuple[str, str]] = set()
        self.read: list[dict] = []
        self.write: list[dict] = []
        self.unlink: list[dict] = []
        self.connect: list[dict] = []
        self.send: list[dict] = []
        self.recv: list[dict] = []
        self.bind: list[dict] = []

        # Agent-shape edges
        self.has_iteration: set[tuple[str, str]] = set()       # (session_id, iter_id)
        self.follows: set[tuple[str, str]] = set()             # (prev_iter, next_iter)
        self.has_prompt: set[tuple[str, str]] = set()          # (iter_id, prompt_id)
        self.has_response: set[tuple[str, str]] = set()        # (iter_id, response_id)
        self.issued: set[tuple[str, str]] = set()              # (iter_id, tool_call_id)
        self.exposes: set[tuple[str, str]] = set()             # (mcp_id, tool_key)
        self.invokes: set[tuple[str, str]] = set()             # (tool_call_id, tool_key)
        self.handled_by: set[tuple[str, str]] = set()          # (tool_call_id, mcp_id)
        self.first_call: set[tuple[str, str]] = set()          # (iter_id, tool_call_id)
        self.next_call: list[tuple[str, str]] = []             # (prev_tc, next_tc)
        self.parent_call: set[tuple[str, str]] = set()         # (parent_tc, child_tc)


class KuzuGraphBuilder:
    """Walk events; produce a populated Kuzu DB on disk."""

    def __init__(self, db_path: Path, fresh: bool = True,
                 enable_claude_mcp_add: bool = True):
        self.db_path = Path(db_path)
        if fresh and self.db_path.exists():
            if self.db_path.is_dir():
                shutil.rmtree(self.db_path)
            else:
                self.db_path.unlink()
            # Kuzu also writes a .wal alongside
            wal = Path(str(self.db_path) + ".wal")
            if wal.exists():
                wal.unlink()
        # Mirror state of predict()
        self.pid_session: dict[int, str] = {}
        self.pid_mcp: dict[int, str] = {}
        self.last_clone: _PendingClone | None = None
        self.active_tool_call: dict[int, str] = {}  # mcp_pid -> tool_call_id
        self._mcp_pid_for_id: dict[str, int] = {}   # mcp_id -> anchor pid

        # Set of pids whose parent is known authoritatively from a
        # sched_fork event in the trace. These pids skip the
        # 200ms-clone-window heuristic — the kernel's sched_fork is
        # the source of truth, and we don't want the heuristic to
        # second-guess it. v1 captures (no sched_fork events) leave
        # this set empty, which preserves backwards compatibility.
        self.pid_parent_authoritative: set[int] = set()

        # Layered MCP detector state. Layer 2 (claude-mcp-add parsing)
        # registers binary names here; layer 3 (broadened regex)
        # operates statelessly. Layer 1 (structural / JSON-RPC) is
        # tracked through the per-fd-claude-sendto bookkeeping below.
        self.mcp_state = StructuralState(
            enable_claude_mcp_add=enable_claude_mcp_add,
        )
        # Pids that look like MCP servers by name pattern (layers 2+3)
        # but haven't yet been confirmed by structural evidence (layer 1).
        # Maps candidate_pid -> (label, t_seen_ns).
        self._mcp_candidates: dict[int, tuple[str, int]] = {}
        # Registered/broadened-detected pids that have been confirmed
        # promoted to full MCP nodes already.
        self._mcp_promoted: set[int] = set()

        self.rows = GraphRows()
        self._next_session_n = 0
        self._next_mcp_n = 0
        self._next_tool_call_n = 0

        self.db: kuzu.Database | None = None
        self.conn: kuzu.Connection | None = None

    # ------------------------------------------------------------------
    # Vertex helpers (idempotent — store keyed dicts and let last write win)

    def _ensure_process(self, pid: int, ts: int, comm: str | None,
                        argv: list[str] | None) -> None:
        if pid in self.rows.processes:
            return
        self.rows.processes[pid] = {
            "pid": pid,
            "first_comm": comm or "",
            "first_argv": " ".join(argv or [])[:512],
            "t_first_seen_ns": ts,
        }

    def _ensure_file(self, path: str) -> None:
        if path in self.rows.files:
            return
        self.rows.files[path] = {"path": path}

    def _ensure_socket(self, family: int, daddr: str, dport: int) -> str:
        key = f"{family}:{daddr}:{dport}"
        if key not in self.rows.sockets:
            self.rows.sockets[key] = {
                "sock_key": key, "family": family,
                "daddr": daddr, "dport": dport,
            }
        return key

    # ------------------------------------------------------------------
    # Anchor-event handlers

    def _open_session(self, pid: int, ts: int, argv: list[str]) -> str:
        sid = f"sess_{self._next_session_n}"
        self._next_session_n += 1
        self.rows.sessions[sid] = {
            "session_id": sid, "anchor_pid": pid,
            "t_start_ns": ts, "argv": " ".join(argv)[:512],
            "terminator_status": "",   # filled by agent-layer ingest
            "terminator_reason": "",
        }
        self.pid_session[pid] = sid
        # Clear any inherited MCP attribution
        self.pid_mcp.pop(pid, None)
        # Record only the first binding; later events for same (pid, sid)
        # don't override.
        self.rows.member_of_session.setdefault((pid, sid), ts)
        return sid

    def _open_mcp(self, pid: int, ts: int, label: str,
                  argv: list[str], session_id: str) -> str:
        mid = f"mcp_{self._next_mcp_n}_{label}"
        self._next_mcp_n += 1
        self.rows.mcps[mid] = {
            "mcp_id": mid, "session_id": session_id, "anchor_pid": pid,
            "name": label, "argv": " ".join(argv)[:512],
            "t_start_ns": ts,
        }
        self.rows.has_mcp.add((session_id, mid))
        self.pid_mcp[pid] = mid
        self._mcp_pid_for_id[mid] = pid
        self.rows.member_of_mcp.setdefault((pid, mid), ts)
        return mid

    def _open_tool_call(self, mcp_pid: int, mcp_id: str,
                        name: str, tu_id: str, ts: int) -> str:
        tcid = tu_id or f"tc_{self._next_tool_call_n}"
        self._next_tool_call_n += 1
        if tcid in self.rows.tool_calls:
            tcid = f"{tcid}__{self._next_tool_call_n}"
            self._next_tool_call_n += 1
        self.rows.tool_calls[tcid] = {
            "tool_call_id": tcid,
            "iteration_id": "",   # filled by agent-layer ingest if matched
            "mcp_id": mcp_id,
            "name": name,
            "is_builtin": False,   # MCP-side ToolCalls are by definition not builtin
            "kernel_timing": "precise",
            "t_open_ns": ts, "t_close_ns": -1,
            "is_error": False,
        }
        self.rows.has_tool_call.add((mcp_id, tcid))
        self.active_tool_call[mcp_pid] = tcid
        return tcid

    def _close_tool_call(self, mcp_pid: int, ts: int) -> None:
        tcid = self.active_tool_call.pop(mcp_pid, None)
        if tcid and tcid in self.rows.tool_calls:
            self.rows.tool_calls[tcid]["t_close_ns"] = ts

    # ------------------------------------------------------------------
    # Per-event ingestion

    def add_event(self, e: dict) -> None:
        ev = e.get("event")
        pid = e.get("pid")
        ts = e.get("ts_ns", 0)
        if pid is None or ev is None:
            return
        comm = e.get("comm")
        cgid = e.get("cgroup_id")

        # First time we see a pid: create Process vertex.
        if pid not in self.rows.processes:
            argv0 = (e.get("args") or {}).get("argv") if ev == "execve" else None
            self._ensure_process(pid, ts, comm, argv0)

        # Clone-window inheritance fires whenever an event's pid is
        # currently UNBOUND from a session and a recent clone caller is
        # bound. cgroup-match required: if the candidate child's cgroup
        # differs from the caller's cgroup, the inheritance is rejected.
        #
        # IMPORTANT: skip this fallback inference if the pid has already
        # been authoritatively parented by an in-trace sched_fork event.
        # That event handler (below) sets pid_parent_authoritative for
        # the child. We don't want the timing-window heuristic to
        # second-guess the kernel's own record. For v1 captures (no
        # sched_fork events at all), this set stays empty and we fall
        # through to the heuristic for every unknown pid — preserving
        # backwards compatibility.
        if (pid not in self.pid_session
                and pid not in self.pid_parent_authoritative
                and self.last_clone is not None):
            gap = ts - self.last_clone.ts_ns
            ccg = self.last_clone.caller_cgroup
            cgroup_ok = (ccg is None or cgid is None or ccg == cgid)
            if 0 <= gap < 200_000_000 and cgroup_ok:
                cpid = self.last_clone.caller_pid
                if cpid in self.pid_session:
                    self.rows.child_of.append({
                        "child_pid": pid,
                        "parent_pid": cpid,
                        "ts_ns": self.last_clone.ts_ns,
                        "via": "clone_window",
                    })
                    sid = self.pid_session[cpid]
                    self.pid_session[pid] = sid
                    self.rows.member_of_session.setdefault((pid, sid), ts)
                    if cpid in self.pid_mcp:
                        mid = self.pid_mcp[cpid]
                        self.pid_mcp[pid] = mid
                        self.rows.member_of_mcp.setdefault((pid, mid), ts)

        args = e.get("args") or {}

        if ev == "execve":
            argv = args.get("argv") or []
            if is_session_root(args):
                self._open_session(pid, ts, argv)
                # Refresh the Process vertex's argv to reflect claude
                if pid in self.rows.processes:
                    self.rows.processes[pid]["first_argv"] = (
                        " ".join(argv)[:512]
                    )

            # Layered MCP-root detection
            ok, label, layer = layered_is_mcp_root(args, self.mcp_state)
            if ok and pid in self.pid_session and pid not in self.pid_mcp:
                if layer == "registered":
                    # Layer 2 hits get promoted immediately — the
                    # registration call gave us authoritative ground
                    # truth that this binary is an MCP.
                    self._open_mcp(pid, ts, label, argv,
                                   self.pid_session[pid])
                    self._mcp_promoted.add(pid)
                else:
                    # Layer 3 (broadened name regex) is a candidate.
                    # We hold off on promoting until we see structural
                    # evidence (claude sends a JSON-RPC frame and the
                    # responder pid matches). If no evidence arrives,
                    # we still promote at the end (see _finalize).
                    self._mcp_candidates[pid] = (label, ts)

        elif ev == "sched_fork":
            # v2 sensor: authoritative parent->child edge from the
            # sched_process_fork tracepoint. Both pids are in args.
            # The event's pid/tid/cgroup_id are the parent's (current
            # at fork time was the parent).
            fa = args
            parent_pid = int(fa.get("parent_pid", 0))
            child_pid = int(fa.get("child_pid", 0))
            if parent_pid and child_pid and parent_pid != child_pid:
                # Ensure both Process vertices exist. Child may not
                # have any kernel events yet at fork time.
                self._ensure_process(parent_pid, ts,
                                     fa.get("parent_comm"), None)
                self._ensure_process(child_pid, ts,
                                     fa.get("parent_comm"), None)
                # Authoritative child_of edge.
                self.rows.child_of.append({
                    "child_pid": child_pid,
                    "parent_pid": parent_pid,
                    "ts_ns": ts,
                    "via": "sched_fork",
                })
                # Mark the child as having an authoritative parent so
                # the timing-window heuristic later in this loop doesn't
                # try to re-bind it.
                self.pid_parent_authoritative.add(child_pid)
                # Propagate session and MCP membership immediately. If
                # the parent isn't bound to a session yet, the child
                # won't be either; later events (e.g. the parent's
                # claude -p execve) will open the session and the
                # child remains unbound.
                if parent_pid in self.pid_session:
                    sid = self.pid_session[parent_pid]
                    self.pid_session[child_pid] = sid
                    self.rows.member_of_session.setdefault(
                        (child_pid, sid), ts)
                if parent_pid in self.pid_mcp:
                    mid = self.pid_mcp[parent_pid]
                    self.pid_mcp[child_pid] = mid
                    self.rows.member_of_mcp.setdefault(
                        (child_pid, mid), ts)

        elif ev in ("clone", "clone3"):
            self.last_clone = _PendingClone(
                caller_pid=pid, ts_ns=ts, caller_cgroup=cgid,
            )

        elif ev in ("openat", "open"):
            path = args.get("path") or ""
            if path:
                self._ensure_file(path)
                flags = int(args.get("flags") or 0)
                fd = -1
                accmode = flags & 3
                kind = "read" if accmode == 0 else "write"
                row = {"pid": pid, "path": path, "ts_ns": ts,
                       "fd": fd, "flags": flags}
                if kind == "read":
                    self.rows.read.append(row)
                else:
                    self.rows.write.append(row)

        elif ev in ("unlinkat", "unlink"):
            path = args.get("path") or ""
            if path:
                self._ensure_file(path)
                self.rows.unlink.append({
                    "pid": pid, "path": path, "ts_ns": ts,
                })

        elif ev == "connect":
            family = int(args.get("family") or 0)
            daddr = args.get("daddr") or ""
            dport = int(args.get("dport") or 0)
            fd = int(args.get("fd") or -1)
            if family in (2, 10) and daddr:
                key = self._ensure_socket(family, daddr, dport)
                self.rows.connect.append({
                    "pid": pid, "sock_key": key,
                    "ts_ns": ts, "fd": fd,
                })

        elif ev == "sendto":
            family = int(args.get("family") or 0)
            daddr = args.get("daddr") or ""
            dport = int(args.get("dport") or 0)
            fd = int(args.get("fd") or -1)
            length = int(args.get("len") or 0)
            if family in (2, 10) and daddr:
                key = self._ensure_socket(family, daddr, dport)
                self.rows.send.append({
                    "pid": pid, "sock_key": key,
                    "ts_ns": ts, "fd": fd, "len": length,
                })

            buf = args.get("buf_b64")

            # Layer 1 (structural) promotion: when claude sends ANY
            # JSON-RPC frame on stdio, promote candidate MCPs that
            # have been waiting for structural evidence. We can't
            # match by recipient pid (kernel doesn't tell us the
            # other end of the pipe), so we promote the most
            # recently-opened candidate within the session.
            if (buf and pid in self.pid_session
                    and is_likely_mcp_via_jsonrpc(buf)):
                sid = self.pid_session[pid]
                # Find the most recent candidate in this session.
                # Candidates are session descendants by construction
                # (we only added them if pid was already in pid_session).
                best_cand = None
                best_ts = -1
                for cand_pid, (cand_label, cand_ts) in \
                        self._mcp_candidates.items():
                    if (self.pid_session.get(cand_pid) == sid
                            and cand_ts > best_ts):
                        best_cand = (cand_pid, cand_label, cand_ts)
                        best_ts = cand_ts
                if best_cand is not None:
                    cand_pid, cand_label, cand_ts = best_cand
                    if cand_pid not in self._mcp_promoted:
                        self._open_mcp(cand_pid, cand_ts, cand_label,
                                       [], sid)
                        self._mcp_promoted.add(cand_pid)
                        del self._mcp_candidates[cand_pid]

            # Tool-call boundary detection
            if buf and pid in self.pid_session:
                parsed = parse_tools_call(buf)
                if parsed is not None:
                    name, tu_id = parsed
                    sid = self.pid_session[pid]
                    # Pick the most recently opened MCP in this session
                    candidate = None
                    for mp, mid in self.pid_mcp.items():
                        if mid in self.rows.mcps and \
                                self.rows.mcps[mid]["session_id"] == sid:
                            candidate = (mp, mid)
                    if candidate is not None:
                        self._open_tool_call(candidate[0], candidate[1],
                                             name, tu_id, ts)
            # Tool-call response: MCP sends jsonrpc reply (no method)
            if buf and pid in self.pid_mcp and pid in self.active_tool_call:
                try:
                    raw = base64.b64decode(buf)
                    if (b'"jsonrpc"' in raw and b'"id"' in raw
                            and b'"method"' not in raw):
                        self._close_tool_call(pid, ts)
                except Exception:
                    pass

        elif ev == "recvfrom":
            family = int(args.get("family") or 0)
            daddr = args.get("daddr") or ""
            dport = int(args.get("dport") or 0)
            fd = int(args.get("fd") or -1)
            length = int(args.get("len") or 0)
            if family in (2, 10) and daddr:
                key = self._ensure_socket(family, daddr, dport)
                self.rows.recv.append({
                    "pid": pid, "sock_key": key,
                    "ts_ns": ts, "fd": fd, "len": length,
                })

        elif ev == "bind":
            family = int(args.get("family") or 0)
            daddr = args.get("daddr") or ""
            dport = int(args.get("dport") or 0)
            fd = int(args.get("fd") or -1)
            if family in (2, 10) and daddr:
                key = self._ensure_socket(family, daddr, dport)
                self.rows.bind.append({
                    "pid": pid, "sock_key": key, "ts_ns": ts, "fd": fd,
                })

    def add_events(self, events: Iterable) -> None:
        evs = list(events)
        if evs and hasattr(evs[0], "event"):
            evs.sort(key=lambda m: m.event.get("ts_ns", 0))
            for m in evs:
                self.add_event(m.event)
        else:
            evs.sort(key=lambda d: d.get("ts_ns", 0))
            for e in evs:
                self.add_event(e)
        self._finalize_candidates()

    def _finalize_candidates(self) -> None:
        """Promote leftover layer-3 (broadened-regex) candidates that
        were never confirmed by structural evidence. Conservative: we
        still promote them — the broadened regex is intentionally a
        fallback. If we wanted strict structural-only attribution we'd
        skip this step."""
        for cand_pid, (label, ts) in list(self._mcp_candidates.items()):
            sid = self.pid_session.get(cand_pid)
            if sid is None:
                continue
            if cand_pid in self._mcp_promoted:
                continue
            self._open_mcp(cand_pid, ts, label, [], sid)
            self._mcp_promoted.add(cand_pid)
        self._mcp_candidates.clear()

    # ------------------------------------------------------------------
    # Agent-layer ingest — adds Iteration/Prompt/Response/Tool vertices
    # and the agent-shape edges. Called after add_events() and before
    # flush(). The session_dir + (predicted) session_id arguments tell
    # the extractor which capture to read and what session id to scope
    # the agent-layer ids to.
    #
    # session_id_in_graph: the session vertex id we already opened in
    #   the graph (e.g. "sess_0"). If the agent-extractor naturally
    #   uses a different id (e.g. the session_id field from
    #   session.json), we still anchor agent-layer ids on the graph's
    #   session vertex id so edges line up.

    def ingest_agent_layer(self, session_dir: Path,
                            session_id_in_graph: str,
                            t_start_ns: int, t_end_ns: int,
                            extractor_mode: str = "stream") -> None:
        """Extract the agent-shape vertices and edges and merge into
        self.rows.

        extractor_mode:
          - "stream" (default): passive extraction from stream.jsonl
            + session.json. Backwards-compatible.
          - "hooks": cooperative extraction from the
            attribution_hook events under
            ~/.cache/agenttrace/attribution_testing/.
          - "auto": hooks if data is present for this session, else
            stream.
        """
        from agent_layer import extract_agent_layer_dispatch
        ext = extract_agent_layer_dispatch(
            session_dir, session_id_in_graph, t_start_ns, t_end_ns,
            mode=extractor_mode,
        )

        # ---- update Session vertex with terminator info ----
        sess = self.rows.sessions.get(session_id_in_graph)
        if sess is not None:
            sess["terminator_status"] = ext.session_terminator_status
            sess["terminator_reason"] = ext.session_terminator_reason

        # ---- Tool vertices ----
        # Tools are global in the schema; key includes session_id so
        # the same tool name in different sessions doesn't collide.
        for tool in ext.tools:
            self.rows.tools[tool.tool_key] = {
                "tool_key": tool.tool_key,
                "name": tool.name,
                "is_builtin": tool.is_builtin,
                "mcp_id": tool.mcp_id,
                "description": tool.description,
            }

        # ---- Iteration / Prompt / Response vertices and edges ----
        for it in ext.iterations:
            self.rows.iterations[it.iteration_id] = {
                "iteration_id": it.iteration_id,
                "session_id":   it.session_id,
                "ordinal":      it.ordinal,
                "t_start_ns":   it.t_start_ns,
                "t_end_ns":     it.t_end_ns,
                "outcome":      it.outcome,
            }
            self.rows.has_iteration.add(
                (session_id_in_graph, it.iteration_id))

        for p in ext.prompts:
            self.rows.prompts[p["prompt_id"]] = p
            self.rows.has_prompt.add((p["iteration_id"], p["prompt_id"]))

        for r in ext.responses:
            self.rows.responses[r["response_id"]] = r
            self.rows.has_response.add((r["iteration_id"], r["response_id"]))

        # follows edges between consecutive iterations within the
        # session (single iteration in -p mode, but schema-ready for
        # multi-iteration sessions)
        sorted_iters = sorted(ext.iterations, key=lambda x: x.ordinal)
        for prev, nxt in zip(sorted_iters, sorted_iters[1:]):
            self.rows.follows.add((prev.iteration_id, nxt.iteration_id))

        # ---- ToolCall: build / update from extracted records ----
        # For built-in tools (no MCP), the kernel-shape walk never
        # opened a ToolCall vertex; we create it here from stream
        # data. For third-party tools the kernel-shape walk already
        # opened a ToolCall vertex — we update it with iteration_id
        # and is_builtin=False.
        for tc in ext.tool_calls:
            existing = self.rows.tool_calls.get(tc.tool_call_id)
            if existing is None:
                # No kernel-side anchor — create a new vertex (this is
                # the built-in case, or the rare MCP case where
                # JSON-RPC parsing missed the boundary).
                self.rows.tool_calls[tc.tool_call_id] = {
                    "tool_call_id": tc.tool_call_id,
                    "iteration_id": tc.iteration_id,
                    "mcp_id":       tc.mcp_id,
                    "name":         tc.name,
                    "is_builtin":   tc.is_builtin,
                    "kernel_timing": tc.kernel_timing,
                    "t_open_ns":    tc.t_open_ns,
                    "t_close_ns":   tc.t_close_ns,
                    "is_error":     tc.is_error,
                }
            else:
                # Kernel-side already opened a ToolCall vertex (via
                # JSON-RPC parsing of sendto). Update with agent-layer
                # fields. For timing: prefer non-(-1) values from
                # whichever source has them. Hook-anchored timestamps
                # are precise wall-clock from PreToolUse / PostToolUse;
                # kernel-side timestamps are precise wall-clock from
                # the sendto event. Either is good; the only case we
                # avoid is overwriting a real timestamp with -1.
                existing["iteration_id"] = tc.iteration_id
                existing["is_builtin"] = tc.is_builtin
                existing["kernel_timing"] = tc.kernel_timing
                existing["is_error"] = tc.is_error
                # Update t_open/t_close only when the new value is
                # better-quality (not -1). The agent-layer extractor's
                # values are usually populated; the kernel-shape walk
                # often leaves t_close_ns=-1 because parsing the
                # response frame is unreliable.
                if tc.t_open_ns and tc.t_open_ns > 0 \
                        and (existing.get("t_open_ns") or 0) <= 0:
                    existing["t_open_ns"] = tc.t_open_ns
                if tc.t_close_ns and tc.t_close_ns > 0 \
                        and (existing.get("t_close_ns") or -1) <= 0:
                    existing["t_close_ns"] = tc.t_close_ns

            # issued edge always
            self.rows.issued.add((tc.iteration_id, tc.tool_call_id))
            # invokes edge — link to Tool vertex if we have one
            tool_key = f"{session_id_in_graph}/{tc.name}"
            if tool_key in self.rows.tools:
                self.rows.invokes.add((tc.tool_call_id, tool_key))
            # handled_by edge — only for non-built-in
            if not tc.is_builtin and tc.mcp_id:
                self.rows.handled_by.add((tc.tool_call_id, tc.mcp_id))
            # parent_call edge — when nested
            if tc.parent_tool_use_id:
                self.rows.parent_call.add(
                    (tc.parent_tool_use_id, tc.tool_call_id))

        # exposes edges (MCP -> Tool): for each non-builtin tool,
        # emit one edge from the Tool's mcp_id to its tool_key. NB:
        # the agent-layer extractor uses synthetic mcp_ids of the
        # form "mcp/<session>/<server-name>" while the kernel-shape
        # uses "mcp_<n>_<server-binary>" — these need to be reconciled
        # by name-matching. For Phase 5 we accept that exposes edges
        # are agent-layer-internal (Tool -> agent's mcp_id) and may
        # not match kernel-shape MCP vertex ids. A reconciliation
        # pass below tries to bridge them.
        # Bridge: kernel-shape MCPs are in self.rows.mcps with the
        # `name` field set (e.g. "memory-bank"). The agent-layer's
        # tools have mcp_id like "mcp/<session>/memory" — we match
        # the trailing segment to MCP.name (loosely).
        for tool in ext.tools:
            if tool.is_builtin or not tool.mcp_id:
                continue
            # tool.mcp_id format: "mcp/<session>/<server-name>"
            agent_server_name = tool.mcp_id.rsplit("/", 1)[-1]
            # find the kernel-shape MCP whose name loosely matches
            best = None
            for kid, kmcp in self.rows.mcps.items():
                kname = (kmcp.get("name") or "").lower()
                if (agent_server_name.lower() in kname
                        or kname in agent_server_name.lower()):
                    best = kid
                    break
            if best is not None:
                self.rows.exposes.add((best, tool.tool_key))
                # Also rewrite the tool's mcp_id to the kernel-shape
                # id so handled_by edges line up (for any ToolCall
                # that referenced this tool's mcp_id).
                self.rows.tools[tool.tool_key]["mcp_id"] = best
                # And rewrite handled_by edges that pointed at the
                # synthetic id
                old_id = tool.mcp_id
                self.rows.handled_by = {
                    (tc, best) if mid == old_id else (tc, mid)
                    for tc, mid in self.rows.handled_by
                }
                # Also rewrite ToolCall.mcp_id field for consistency
                for tc_id, tc_row in self.rows.tool_calls.items():
                    if tc_row.get("mcp_id") == old_id:
                        tc_row["mcp_id"] = best

        # first_call + next_call within the iteration
        # Group tool_calls by iteration, sort by t_open_ns, link.
        from collections import defaultdict
        by_iter: dict[str, list] = defaultdict(list)
        for tc in ext.tool_calls:
            by_iter[tc.iteration_id].append(tc)
        for it_id, lst in by_iter.items():
            lst.sort(key=lambda x: x.t_open_ns)
            if lst:
                self.rows.first_call.add((it_id, lst[0].tool_call_id))
            for prev, nxt in zip(lst, lst[1:]):
                self.rows.next_call.append(
                    (prev.tool_call_id, nxt.tool_call_id))

    # ------------------------------------------------------------------
    # Bulk flush — open the DB, apply schema, COPY DataFrames

    def flush(self) -> None:
        self.db = kuzu.Database(str(self.db_path))
        self.conn = kuzu.Connection(self.db)
        apply_schema(self.conn)

        # ---- vertices ----
        # Type maps for each vertex DataFrame; Kuzu's COPY is strict.
        if self.rows.sessions:
            df = pd.DataFrame(self.rows.sessions.values()).astype({
                "session_id": "string", "anchor_pid": "int64",
                "t_start_ns": "int64", "argv": "string",
                "terminator_status": "string", "terminator_reason": "string",
            })
            self.conn.execute("COPY Session FROM df")
        if self.rows.mcps:
            df = pd.DataFrame(self.rows.mcps.values()).astype({
                "mcp_id": "string", "session_id": "string",
                "anchor_pid": "int64", "name": "string",
                "argv": "string", "t_start_ns": "int64",
            })
            self.conn.execute("COPY MCP FROM df")
        if self.rows.tool_calls:
            df = pd.DataFrame(self.rows.tool_calls.values()).astype({
                "tool_call_id": "string", "iteration_id": "string",
                "mcp_id": "string", "name": "string",
                "is_builtin": "bool", "kernel_timing": "string",
                "t_open_ns": "int64", "t_close_ns": "int64",
                "is_error": "bool",
            })
            self.conn.execute("COPY ToolCall FROM df")
        # Agent-layer vertices
        if self.rows.iterations:
            df = pd.DataFrame(self.rows.iterations.values()).astype({
                "iteration_id": "string", "session_id": "string",
                "ordinal": "int32",
                "t_start_ns": "int64", "t_end_ns": "int64",
                "outcome": "string",
            })
            self.conn.execute("COPY Iteration FROM df")
        if self.rows.prompts:
            df = pd.DataFrame(self.rows.prompts.values()).astype({
                "prompt_id": "string", "iteration_id": "string",
                "text": "string", "ts_ns": "int64",
            })
            self.conn.execute("COPY Prompt FROM df")
        if self.rows.responses:
            df = pd.DataFrame(self.rows.responses.values()).astype({
                "response_id": "string", "iteration_id": "string",
                "text": "string", "ts_ns": "int64",
            })
            self.conn.execute("COPY Response FROM df")
        if self.rows.tools:
            df = pd.DataFrame(self.rows.tools.values()).astype({
                "tool_key": "string", "name": "string",
                "is_builtin": "bool", "mcp_id": "string",
                "description": "string",
            })
            self.conn.execute("COPY Tool FROM df")
        if self.rows.processes:
            df = pd.DataFrame(self.rows.processes.values()).astype({
                "pid": "int64", "first_comm": "string",
                "first_argv": "string", "t_first_seen_ns": "int64",
            })
            self.conn.execute("COPY Process FROM df")
        if self.rows.files:
            df = pd.DataFrame(self.rows.files.values()).astype({
                "path": "string",
            })
            self.conn.execute("COPY File FROM df")
        if self.rows.sockets:
            df = pd.DataFrame(self.rows.sockets.values()).astype({
                "sock_key": "string", "family": "int8",
                "daddr": "string", "dport": "int32",
            })
            self.conn.execute("COPY Socket FROM df")

        # ---- edges ----
        # child_of: dedupe (child_pid, parent_pid) keeping first ts
        if self.rows.child_of:
            seen = set()
            unique_co = []
            for r in self.rows.child_of:
                k = (r["child_pid"], r["parent_pid"])
                if k in seen:
                    continue
                seen.add(k)
                unique_co.append(r)
            df = pd.DataFrame(unique_co).rename(
                columns={"child_pid": "from", "parent_pid": "to"}
            )
            df = df.astype({"from": "int64", "to": "int64",
                            "ts_ns": "int64", "via": "string"})
            self.conn.execute("COPY child_of FROM df")

        if self.rows.member_of_session:
            df = pd.DataFrame([
                {"from": p, "to": s, "bound_at_ts_ns": ts}
                for (p, s), ts in self.rows.member_of_session.items()
            ]).astype({"from": "int64", "to": "string",
                       "bound_at_ts_ns": "int64"})
            self.conn.execute("COPY member_of_session FROM df")

        if self.rows.member_of_mcp:
            df = pd.DataFrame([
                {"from": p, "to": m, "bound_at_ts_ns": ts}
                for (p, m), ts in self.rows.member_of_mcp.items()
            ]).astype({"from": "int64", "to": "string",
                       "bound_at_ts_ns": "int64"})
            self.conn.execute("COPY member_of_mcp FROM df")

        if self.rows.has_mcp:
            df = pd.DataFrame(
                [{"from": s, "to": m} for s, m in self.rows.has_mcp]
            ).astype({"from": "string", "to": "string"})
            self.conn.execute("COPY has_mcp FROM df")

        if self.rows.has_tool_call:
            df = pd.DataFrame(
                [{"from": m, "to": t} for m, t in self.rows.has_tool_call]
            ).astype({"from": "string", "to": "string"})
            self.conn.execute("COPY has_tool_call FROM df")

        # ---- agent-shape simple string-keyed edges ----
        # Each is a Set of (from_id, to_id) tuples; same flush shape.
        for edge_name, edge_set in (
            ("has_iteration",   self.rows.has_iteration),
            ("follows",         self.rows.follows),
            ("has_prompt",      self.rows.has_prompt),
            ("has_response",    self.rows.has_response),
            ("issued",          self.rows.issued),
            ("exposes",         self.rows.exposes),
            ("invokes",         self.rows.invokes),
            ("handled_by",      self.rows.handled_by),
            ("first_call",      self.rows.first_call),
            ("parent_call",     self.rows.parent_call),
        ):
            if not edge_set:
                continue
            df = pd.DataFrame(
                [{"from": a, "to": b} for a, b in edge_set]
            ).astype({"from": "string", "to": "string"})
            self.conn.execute(f"COPY {edge_name} FROM df")

        # next_call is a list (preserves order; duplicates harmless
        # since it's always (prev,next) with strict pairing)
        if self.rows.next_call:
            df = pd.DataFrame(
                [{"from": a, "to": b} for a, b in self.rows.next_call]
            ).astype({"from": "string", "to": "string"})
            self.conn.execute("COPY next_call FROM df")

        # File-touch edges: read/write/unlink share columns
        for tbl_name, rows in (("read", self.rows.read),
                                 ("write", self.rows.write)):
            if not rows:
                continue
            df = pd.DataFrame(rows).rename(columns={"pid": "from",
                                                     "path": "to"})
            df = df.astype({"from": "int64", "to": "string",
                            "ts_ns": "int64", "fd": "int32",
                            "flags": "int32"})
            self.conn.execute(f"COPY {tbl_name} FROM df")
        if self.rows.unlink:
            df = pd.DataFrame(self.rows.unlink).rename(columns={
                "pid": "from", "path": "to"
            }).astype({"from": "int64", "to": "string", "ts_ns": "int64"})
            self.conn.execute("COPY unlink FROM df")

        # Socket edges
        for tbl_name, rows, has_len in (
            ("connect", self.rows.connect, False),
            ("send", self.rows.send, True),
            ("recv", self.rows.recv, True),
            ("bind", self.rows.bind, False),
        ):
            if not rows:
                continue
            df = pd.DataFrame(rows).rename(columns={"pid": "from",
                                                     "sock_key": "to"})
            cast = {"from": "int64", "to": "string",
                    "ts_ns": "int64", "fd": "int32"}
            if has_len:
                cast["len"] = "int32"
            df = df.astype(cast)
            self.conn.execute(f"COPY {tbl_name} FROM df")

    def close(self) -> None:
        if self.conn is not None:
            del self.conn
            self.conn = None
        if self.db is not None:
            del self.db
            self.db = None


def build_graph(events: Iterable, db_path: Path,
                fresh: bool = True,
                enable_claude_mcp_add: bool = True) -> KuzuGraphBuilder:
    """One-shot: walk events, flush to Kuzu, return the builder so caller
    can run queries against it via .conn."""
    b = KuzuGraphBuilder(db_path, fresh=fresh,
                          enable_claude_mcp_add=enable_claude_mcp_add)
    b.add_events(events)
    b.flush()
    return b


def build_graph_with_agent_layer(
        events: Iterable, db_path: Path,
        session_dir: Path,
        session_id_in_graph: str,
        t_start_ns: int, t_end_ns: int,
        fresh: bool = True,
        enable_claude_mcp_add: bool = True,
        extractor_mode: str = "stream",
) -> KuzuGraphBuilder:
    """Like build_graph, plus an agent-layer ingest pass that adds
    Iteration, Prompt, Response, Tool vertices and the agent-shape
    edges from the chosen extractor.

    `session_id_in_graph` is the session vertex id the kernel walk
    opened (e.g. "sess_0"). The agent-layer ingest scopes all its
    new ids under that, so cross-layer edges line up cleanly.

    extractor_mode:
      - "stream" (default): passive extraction from stream.jsonl +
        session.json. Compatible with all existing captures.
      - "hooks": cooperative extraction from attribution_hook events
        emitted by the host's installed hook scripts. Requires the
        hooks to be installed and to have fired during the session.
      - "auto": use hooks if hook data is available for this session,
        else fall back to stream.
    """
    b = KuzuGraphBuilder(db_path, fresh=fresh,
                          enable_claude_mcp_add=enable_claude_mcp_add)
    b.add_events(events)
    b.ingest_agent_layer(session_dir, session_id_in_graph,
                          t_start_ns, t_end_ns,
                          extractor_mode=extractor_mode)
    b.flush()
    return b
