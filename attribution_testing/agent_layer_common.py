"""Common types and helpers shared across agent-layer extractor paths.

Two extractor implementations live in sibling modules:
  - agent_layer_stream.py : reconstructs the agent layer from the
    agent's transcript (stream.jsonl + session.json). Passive — works
    on any captured session without runtime cooperation.
  - agent_layer_hooks.py  : reconstructs from kernel-visible boundary
    events emitted by the attribution_hook.{sh,py} hooks. Cooperative —
    requires the hooks to be installed on the host.

Both produce the same ExtractedAgentLayer shape, which the graph
builder ingests via KuzuGraphBuilder.ingest_agent_layer().

The dispatcher in agent_layer.py picks one based on a `mode` argument
so callers can A/B between passive and cooperative attribution
without rewriting code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# Hardcoded list of Claude Code's built-in tools. Used as a fallback
# when the agent's tool registry isn't available; primary source of
# truth is the agent itself (system/init record from stream.jsonl, or
# the tool_name on a hook event).
KNOWN_BUILTIN_TOOLS = {
    "Task", "Bash", "Edit", "Read", "Write", "Glob", "Grep",
    "NotebookEdit", "TodoWrite", "WebFetch", "WebSearch",
    "AskUserQuestion", "ExitPlanMode", "EnterPlanMode",
    "Skill", "ToolSearch", "ScheduleWakeup",
    "TaskOutput", "TaskStop", "EnterWorktree", "ExitWorktree",
    "CronCreate", "CronDelete", "CronList",
}


@dataclass
class ExtractedTool:
    tool_key: str
    name: str
    is_builtin: bool
    mcp_id: str
    description: str = ""


@dataclass
class ExtractedToolCall:
    tool_call_id: str
    iteration_id: str
    mcp_id: str           # "" for built-ins
    name: str
    is_builtin: bool
    kernel_timing: str    # "precise" or "approximate"
    t_open_ns: int
    t_close_ns: int
    is_error: bool
    parent_tool_use_id: str = ""


@dataclass
class ExtractedIteration:
    iteration_id: str
    session_id: str
    ordinal: int
    t_start_ns: int
    t_end_ns: int
    outcome: str          # "responded" / "silent" / "terminated"
    prompt_id: str = ""
    response_id: str = ""


@dataclass
class ExtractedAgentLayer:
    """All extracted agent-layer artifacts for one session."""
    session_terminator_status: str = ""
    session_terminator_reason: str = ""
    iterations: list[ExtractedIteration] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    responses: list[dict] = field(default_factory=list)
    tools: list[ExtractedTool] = field(default_factory=list)
    tool_calls: list[ExtractedToolCall] = field(default_factory=list)
    mcp_tool_map: dict[str, list[str]] = field(default_factory=dict)


def parse_iso_to_ns(iso: str) -> int:
    if not iso:
        return 0
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return 0


def is_builtin_tool_name(name: str) -> bool:
    """Is `name` an agent built-in tool, vs. an MCP-provided one?

    MCP tools are namespaced by the agent as `mcp__<server>__<tool>`;
    anything without that prefix is treated as built-in.
    """
    return not name.startswith("mcp__")


def mcp_id_from_tool_name(name: str, session_id: str) -> str:
    """For MCP tools, return the agent-layer MCP id; for builtins,
    the empty string."""
    if not name.startswith("mcp__"):
        return ""
    parts = name.split("__", 2)
    server = parts[1] if len(parts) >= 2 else ""
    return f"mcp/{session_id}/{server}"
