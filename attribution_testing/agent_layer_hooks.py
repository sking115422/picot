"""Hooks-based agent-layer extractor.

Reconstructs the agent layer from the boundary events emitted by our
hook scripts (see hooks/attribution_hook.{sh,py}). Each event lives on
a kernel-visible openat+write to:

  ~/.cache/agenttrace/attribution_testing/<session_id>.events.jsonl

The extractor reads that file post-hoc and builds the same
ExtractedAgentLayer shape that the stream-based extractor produces,
so the graph builder ingests either path identically.

What this gains over the stream-based path:
  - Built-in tool kernel-timing becomes precise. PreToolUse and
    PostToolUse fire at the exact boundary of the agent's tool
    dispatch; the openat+write is timestamped by the kernel. No more
    `kernel_timing="approximate"`.
  - Concurrent tool calls into the same MCP get unambiguous
    boundaries: each call has its own PreToolUse/PostToolUse pair
    with a distinct tool_use_id, serialized in the agent's main
    loop.
  - Multi-instance under the same uid disambiguates: each session
    has its own session_id-keyed sentinel file.

Caveats:
  - Requires the hooks to be installed on the host (see
    hooks/install.sh).
  - If hooks were not installed for a particular session, the
    sentinel file won't exist and the extractor falls through to
    minimal output. Caller should detect this case.

We use stream.jsonl as a secondary source for prompt text and
response text only — those aren't currently emitted by our hooks
because Claude Code passes them via different mechanisms (prompt
via -p argv → session.json; response is the agent's final output to
stdout). When we generalize to other agents we may add those to the
hook output.
"""
from __future__ import annotations

import json
from pathlib import Path

from agent_layer_common import (
    ExtractedAgentLayer,
    ExtractedIteration,
    ExtractedTool,
    ExtractedToolCall,
    is_builtin_tool_name,
    mcp_id_from_tool_name,
    parse_iso_to_ns,
)


HOOK_OUT_ROOT = Path.home() / ".cache" / "agenttrace" / "attribution_testing"


def _read_hook_events(hook_session_id: str) -> list[dict]:
    """Read all hook events for a given (agent-side) session_id."""
    path = HOOK_OUT_ROOT / f"{hook_session_id}.events.jsonl"
    if not path.exists():
        return []
    events: list[dict] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    events.sort(key=lambda e: e.get("ts", 0))
    return events


def _claude_session_id(session_dir: Path) -> str:
    """Find the agent-side (Claude Code) session_id for this captured
    session. Claude Code's session_id appears in stream.jsonl's
    system/init record; we extract it from there.

    This is what the hook scripts use as their per-session output
    filename, so we need it to find the right hook-events file.
    """
    sm = session_dir / "stream.jsonl"
    if not sm.exists():
        return ""
    for line in sm.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("type") == "system" and r.get("subtype") == "init":
            return r.get("session_id", "")
        # session_id may also appear on later records
        sid = r.get("session_id", "")
        if sid:
            return sid
    return ""


def extract_agent_layer_from_hooks(
    session_dir: Path,
    session_id: str,
    session_t_start_ns: int,
    session_t_end_ns: int,
) -> ExtractedAgentLayer:
    """Extract Iteration / Prompt / Response / Tool / ToolCall from
    the hook-emitted boundary events for this session.

    `session_id` here is the graph's session-vertex id (e.g.
    "sess_0") — used to scope agent-layer ids. The agent's own
    session_id (used by the hooks for filenames) comes from
    stream.jsonl.
    """
    out = ExtractedAgentLayer()

    hook_sid = _claude_session_id(session_dir)
    hook_events = _read_hook_events(hook_sid) if hook_sid else []

    # ---- prompt + response text from stream.jsonl / session.json ----
    # Hooks don't carry prompt text on PreToolUse and don't carry the
    # agent's final response. We pull these from the same sources the
    # stream-based extractor does — minimal duplication.
    sj_path = session_dir / "session.json"
    sm_path = session_dir / "stream.jsonl"
    meta = json.loads(sj_path.read_text()) if sj_path.exists() else {}
    initial_prompt_text = meta.get("prompt", "") or ""

    # If the UserPromptSubmit hook fired, it carries the prompt; prefer
    # that since it's exactly what the agent saw.
    ups = next((e for e in hook_events
                 if e.get("hook") == "UserPromptSubmit"), None)
    if ups and ups.get("prompt"):
        initial_prompt_text = ups["prompt"]

    # response + termination from stream.jsonl's result record
    result_rec = None
    if sm_path.exists():
        for line in sm_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("type") == "result":
                result_rec = r
                break

    # ---- iteration / prompt / response vertices ----
    iter_id = f"iter/{session_id}/0"
    prompt_id = f"prompt/{session_id}/0"
    out.prompts.append({
        "prompt_id": prompt_id,
        "iteration_id": iter_id,
        "text": initial_prompt_text[:8192],
        "ts_ns": session_t_start_ns,
    })

    response_id_for_iter = ""
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
    elif any(e.get("hook") == "Stop" for e in hook_events):
        # Stop hook fired but no result record — agent finished but
        # we don't have the response text.
        out.session_terminator_status = "clean"
        outcome = "silent"
    else:
        out.session_terminator_status = "crash"
        out.session_terminator_reason = "no result record / no Stop hook"
        outcome = "terminated"

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

    # ---- tool calls from PreToolUse/PostToolUse pairs ----
    # The hook output gives us precise ts and full tool_use_id +
    # tool_name + tool_input + parent_tool_use_id + is_error. Pair
    # them up by tool_use_id.
    pending: dict[str, ExtractedToolCall] = {}
    seen_tool_names: set[str] = set()

    for ev in hook_events:
        h = ev.get("hook", "")
        ts_s = ev.get("ts", 0)
        ts_ns = int(ts_s * 1_000_000_000)
        tu_id = ev.get("tool_use_id", "")
        name = ev.get("tool_name", "")

        if h in ("PreToolUse", "preToolUse") and tu_id:
            seen_tool_names.add(name)
            is_builtin = is_builtin_tool_name(name)
            mid = mcp_id_from_tool_name(name, session_id)
            tc = ExtractedToolCall(
                tool_call_id=tu_id,
                iteration_id=iter_id,
                mcp_id=mid,
                name=name,
                is_builtin=is_builtin,
                # Hook-anchored boundaries are precise for both
                # built-in and MCP tools — that's the lift over the
                # stream-based path.
                kernel_timing="precise",
                t_open_ns=ts_ns,
                t_close_ns=-1,
                is_error=False,
                parent_tool_use_id=ev.get("parent_tool_use_id") or "",
            )
            pending[tu_id] = tc

        elif h in ("PostToolUse", "postToolUse") and tu_id in pending:
            tc = pending[tu_id]
            tc.t_close_ns = ts_ns
            tc.is_error = bool(ev.get("is_error", False))

    # Orphans: PreToolUse without matching PostToolUse
    for tc in pending.values():
        if tc.t_close_ns == -1:
            tc.t_close_ns = session_t_end_ns
            tc.is_error = True

    out.tool_calls.extend(pending.values())
    out.tool_calls.sort(key=lambda x: x.t_open_ns)

    # ---- Tool vertices from observed tool names ----
    # Without a system/init record (which we may or may not have), we
    # build Tool vertices from the union of names we saw fire. This
    # is a strict subset of what the agent had access to but covers
    # everything that actually ran.
    for name in seen_tool_names:
        is_builtin = is_builtin_tool_name(name)
        mid = mcp_id_from_tool_name(name, session_id)
        out.tools.append(ExtractedTool(
            tool_key=f"{session_id}/{name}",
            name=name,
            is_builtin=is_builtin,
            mcp_id=mid,
        ))
        if not is_builtin:
            parts = name.split("__", 2)
            server = parts[1] if len(parts) >= 2 else ""
            out.mcp_tool_map.setdefault(server, []).append(
                f"{session_id}/{name}")

    # If we ALSO have a system/init record, supplement with the
    # advertised tool list — these are tools the agent could have
    # called but didn't. Useful for analyst exploration.
    if sm_path.exists():
        for line in sm_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("type") == "system" and r.get("subtype") == "init":
                for tool_name in (r.get("tools") or []):
                    if tool_name in seen_tool_names:
                        continue
                    is_builtin = is_builtin_tool_name(tool_name)
                    mid = mcp_id_from_tool_name(tool_name, session_id)
                    out.tools.append(ExtractedTool(
                        tool_key=f"{session_id}/{tool_name}",
                        name=tool_name,
                        is_builtin=is_builtin,
                        mcp_id=mid,
                    ))
                    if not is_builtin:
                        parts = tool_name.split("__", 2)
                        server = parts[1] if len(parts) >= 2 else ""
                        out.mcp_tool_map.setdefault(server, []).append(
                            f"{session_id}/{tool_name}")
                break

    return out


def hooks_available_for_session(session_dir: Path) -> bool:
    """Check whether the hooks-based extractor has data to work with
    for this session. Returns True iff the hook output file exists."""
    hook_sid = _claude_session_id(session_dir)
    if not hook_sid:
        return False
    return (HOOK_OUT_ROOT / f"{hook_sid}.events.jsonl").exists()
