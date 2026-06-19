"""Agent-layer extractor — dispatcher.

Two extractor implementations live in sibling modules:
  - agent_layer_stream.py — passive, reads stream.jsonl + session.json
  - agent_layer_hooks.py  — cooperative, reads sentinel events the
                            attribution_hook scripts emitted

Both produce the same ExtractedAgentLayer shape, which the graph
builder ingests via KuzuGraphBuilder.ingest_agent_layer().

This module exposes:
  - extract_agent_layer(...)          — backward-compatible alias for
                                        the stream-based path
  - extract_agent_layer_dispatch(...) — explicit-mode dispatcher used
                                        by the new graph_builder entry
                                        point
  - the dataclasses (ExtractedAgentLayer, ExtractedTool, etc.) for
    callers that want to inspect the output
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from agent_layer_common import (
    ExtractedAgentLayer,
    ExtractedIteration,
    ExtractedTool,
    ExtractedToolCall,
    KNOWN_BUILTIN_TOOLS,
)
from agent_layer_stream import extract_agent_layer_from_stream
from agent_layer_hooks import (
    extract_agent_layer_from_hooks,
    hooks_available_for_session,
)

ExtractorMode = Literal["stream", "hooks", "auto"]


def extract_agent_layer_dispatch(
    session_dir: Path,
    session_id: str,
    session_t_start_ns: int,
    session_t_end_ns: int,
    mode: ExtractorMode = "stream",
) -> ExtractedAgentLayer:
    """Pick a path and run the corresponding extractor.

    mode:
      - "stream" (default): always use the stream-based extractor.
        Backwards-compatible with everything that pre-dates the hooks.
      - "hooks": always use the hooks-based extractor. If hook data
        isn't present for this session, falls back to a minimal empty
        ExtractedAgentLayer with a noted error rather than silently
        succeeding.
      - "auto": use hooks if available for this session, else fall
        back to stream. Useful when you want hook data when present
        but don't want to fail otherwise.
    """
    if mode == "stream":
        return extract_agent_layer_from_stream(
            session_dir, session_id, session_t_start_ns, session_t_end_ns,
        )
    if mode == "hooks":
        return extract_agent_layer_from_hooks(
            session_dir, session_id, session_t_start_ns, session_t_end_ns,
        )
    if mode == "auto":
        if hooks_available_for_session(session_dir):
            return extract_agent_layer_from_hooks(
                session_dir, session_id, session_t_start_ns, session_t_end_ns,
            )
        return extract_agent_layer_from_stream(
            session_dir, session_id, session_t_start_ns, session_t_end_ns,
        )
    raise ValueError(f"unknown extractor mode: {mode}")


# Backward-compat alias. Existing callers (graph_builder.py and
# anything else that imported `extract_agent_layer`) continue to
# work with the stream-based behavior unchanged.
def extract_agent_layer(
    session_dir: Path,
    session_id: str,
    session_t_start_ns: int,
    session_t_end_ns: int,
) -> ExtractedAgentLayer:
    return extract_agent_layer_from_stream(
        session_dir, session_id, session_t_start_ns, session_t_end_ns,
    )


# Re-exports for callers that imported types from agent_layer
__all__ = [
    "ExtractedAgentLayer",
    "ExtractedIteration",
    "ExtractedTool",
    "ExtractedToolCall",
    "KNOWN_BUILTIN_TOOLS",
    "ExtractorMode",
    "extract_agent_layer",
    "extract_agent_layer_dispatch",
    "extract_agent_layer_from_stream",
    "extract_agent_layer_from_hooks",
    "hooks_available_for_session",
]
