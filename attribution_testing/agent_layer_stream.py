"""Stream-based agent-layer extractor.

Reconstructs the agent layer (Iteration, Prompt, Response, Tool,
ToolCall) from the agent's transcript: stream.jsonl plus session.json.

Passive — works on any captured session without runtime cooperation.
The downside is built-in tool calls have only approximate kernel
timing because their boundaries exist only in the agent's transcript,
not in the kernel trace. See agent_layer_hooks.py for the
cooperative-attribution alternative.

The output ExtractedAgentLayer shape is shared with the hooks-based
extractor; both paths feed into KuzuGraphBuilder.ingest_agent_layer().
"""
from __future__ import annotations

import json
from pathlib import Path

from agent_layer_common import (
    ExtractedAgentLayer,
    ExtractedIteration,
    ExtractedTool,
    ExtractedToolCall,
    parse_iso_to_ns,
)


def extract_agent_layer_from_stream(
    session_dir: Path,
    session_id: str,
    session_t_start_ns: int,
    session_t_end_ns: int,
) -> ExtractedAgentLayer:
    """Extract Iteration / Prompt / Response / Tool / ToolCall from
    a session's stream.jsonl + session.json.

    `session_id` and the session timestamps come from the caller (the
    graph builder already knows them); we use them to scope ids and
    fall back when stream-internal timestamps are missing.
    """
    out = ExtractedAgentLayer()
    sj_path = session_dir / "session.json"
    sm_path = session_dir / "stream.jsonl"

    meta = {}
    if sj_path.exists():
        meta = json.loads(sj_path.read_text())

    # Parse stream.jsonl
    records = []
    if sm_path.exists():
        for line in sm_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # ---- Pass 1: tools from system/init ----
    init = next((r for r in records if r.get("type") == "system"
                  and r.get("subtype") == "init"), None)
    advertised_tools = (init or {}).get("tools", []) or []

    for tool_name in advertised_tools:
        if tool_name.startswith("mcp__"):
            parts = tool_name.split("__", 2)
            mcp_server = parts[1] if len(parts) >= 2 else ""
            tool = ExtractedTool(
                tool_key=f"{session_id}/{tool_name}",
                name=tool_name,
                is_builtin=False,
                mcp_id=f"mcp/{session_id}/{mcp_server}",
                description="",
            )
            out.tools.append(tool)
            out.mcp_tool_map.setdefault(mcp_server, []).append(tool.tool_key)
        else:
            out.tools.append(ExtractedTool(
                tool_key=f"{session_id}/{tool_name}",
                name=tool_name,
                is_builtin=True,
                mcp_id="",
            ))

    # ---- Pass 2: iterations + initial prompt ----
    # In Claude Code -p mode there's exactly one iteration per session.
    # The initial prompt comes from session.json (set from -p argv).
    # Multi-turn agents would produce multiple iterations; this
    # extractor handles the single-turn case explicitly and that's
    # what our captures are.
    initial_prompt_text = meta.get("prompt", "") or ""
    iter_id = f"iter/{session_id}/0"
    prompt_id = f"prompt/{session_id}/0"

    out.prompts.append({
        "prompt_id": prompt_id,
        "iteration_id": iter_id,
        "text": initial_prompt_text[:8192],
        "ts_ns": session_t_start_ns,
    })

    # ---- Pass 3: tool_use / tool_result in the stream ----
    pending: dict[str, ExtractedToolCall] = {}
    last_t_ns = session_t_start_ns

    def lookup_tool_meta(name: str) -> tuple[bool, str]:
        if name.startswith("mcp__"):
            parts = name.split("__", 2)
            mcp_server = parts[1] if len(parts) >= 2 else ""
            return False, f"mcp/{session_id}/{mcp_server}"
        return True, ""

    for rec in records:
        rtype = rec.get("type", "")
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        if not msg:
            continue
        contents = msg.get("content")
        if not isinstance(contents, list):
            continue

        rec_ts = parse_iso_to_ns(rec.get("timestamp", ""))
        if rec_ts:
            last_t_ns = rec_ts

        for c in contents:
            if not isinstance(c, dict):
                continue
            ctype = c.get("type")

            if ctype == "tool_use" and rtype == "assistant":
                tu_id = c.get("id", "")
                name = c.get("name", "")
                is_builtin, mcp_id = lookup_tool_meta(name)
                # Built-in tools have only approximate kernel timing
                # in the stream-based path — the boundary exists only
                # in the agent's transcript, not in the kernel trace.
                tc = ExtractedToolCall(
                    tool_call_id=tu_id,
                    iteration_id=iter_id,
                    mcp_id=mcp_id,
                    name=name,
                    is_builtin=is_builtin,
                    kernel_timing="precise" if not is_builtin else "approximate",
                    t_open_ns=last_t_ns,
                    t_close_ns=-1,
                    is_error=False,
                    parent_tool_use_id=rec.get("parent_tool_use_id") or "",
                )
                pending[tu_id] = tc

            elif ctype == "tool_result" and rtype == "user":
                tu_id = c.get("tool_use_id", "")
                if tu_id in pending:
                    pending[tu_id].t_close_ns = last_t_ns
                    pending[tu_id].is_error = bool(c.get("is_error", False))

    # Orphans: tool calls that never got a result. Mark errored.
    for tc in pending.values():
        if tc.t_close_ns == -1:
            tc.t_close_ns = session_t_end_ns
            tc.is_error = True

    out.tool_calls.extend(pending.values())
    out.tool_calls.sort(key=lambda x: x.t_open_ns)

    # ---- Pass 4: response and termination ----
    result_rec = next((r for r in records if r.get("type") == "result"), None)
    if result_rec is not None:
        terminal = result_rec.get("terminal_reason") or ""
        stop = result_rec.get("stop_reason") or ""
        is_err = bool(result_rec.get("is_error", False))
        result_text = result_rec.get("result") or ""

        if is_err:
            out.session_terminator_status = "error"
        elif terminal == "completed":
            out.session_terminator_status = "clean"
        else:
            out.session_terminator_status = terminal or "unknown"
        out.session_terminator_reason = stop or terminal or ""

        if result_text:
            response_id = f"resp/{session_id}/0"
            out.responses.append({
                "response_id": response_id,
                "iteration_id": iter_id,
                "text": result_text[:8192],
                "ts_ns": session_t_end_ns,
            })
            outcome = "responded"
            response_id_for_iter = response_id
        else:
            outcome = "silent"
            response_id_for_iter = ""
    else:
        out.session_terminator_status = "crash"
        out.session_terminator_reason = "no result record"
        outcome = "terminated"
        response_id_for_iter = ""

    out.iterations.append(ExtractedIteration(
        iteration_id=iter_id,
        session_id=session_id,
        ordinal=0,
        t_start_ns=session_t_start_ns,
        t_end_ns=session_t_end_ns,
        outcome=outcome,
        prompt_id=prompt_id,
        response_id=response_id_for_iter,
    ))

    return out
