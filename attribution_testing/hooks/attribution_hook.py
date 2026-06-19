#!/usr/bin/env python3
"""Attribution-testing hook — emits agent-layer boundary events to
the sentinel file ~/.cache/agenttrace/attribution_testing/<sid>.events.jsonl.

Claude Code invokes us with:
  - hook_event_name in {SessionStart, UserPromptSubmit, PreToolUse,
    PostToolUse, Stop}
  - structured context as JSON on stdin

We capture only boundary metadata (no kernel events — those come from
the L2/L3 sensors). Each event becomes one openat+write to the
sentinel file, which itself is visible in our eBPF trace via existing
file-event capture.

Output schema (one JSON object per line):
  - ts:           wall-clock seconds since epoch
  - hook:         which hook fired
  - session_id:   the agent's own session UUID
  - tool_use_id:  Claude Code's tool_use id (PreToolUse/PostToolUse)
  - parent_tool_use_id: when a tool call was dispatched by another
                  (Task tool nesting); empty otherwise
  - tool_name:    e.g. "Read", "Bash", "mcp__memory__add_observations"
  - tool_input:   the tool's input args (PreToolUse/PostToolUse)
  - is_error:     PostToolUse only — whether the call errored
  - prompt:       UserPromptSubmit only — the user's prompt text
  - stop_hook_active / stop_reason: Stop only — termination metadata
  - agent_pid:    PID of the agent process that invoked us
  - cwd:          agent's cwd at the time the hook fired

The hook is intentionally minimal — it does no kernel-event capture
of its own, no diffing, no sampling. Per-tool-call kernel attribution
is done downstream by joining boundary-event timestamps against the
host eBPF trace.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Where boundary events go. Per-session files keep the format trivial
# to parse and avoid contention between parallel sessions.
OUT_ROOT = Path.home() / ".cache" / "agenttrace" / "attribution_testing"


def find_agent_pid() -> int | None:
    """Walk up the process tree to find the agent process (claude or
    similar). The hook runs as a subprocess of the agent, so the
    agent is somewhere in our ancestor chain.
    """
    pid = os.getppid()
    for _ in range(10):
        try:
            comm = subprocess.check_output(
                ["ps", "-p", str(pid), "-o", "comm="], text=True
            ).strip().lower()
            if "claude" in comm or "kiro" in comm:
                return pid
            ppid = subprocess.check_output(
                ["ps", "-p", str(pid), "-o", "ppid="], text=True
            ).strip()
            pid = int(ppid)
        except (subprocess.CalledProcessError, ValueError):
            break
    return None


def emit_event(session_id: str, record: dict) -> None:
    """Append one JSON-line event to the per-session sentinel file."""
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    path = OUT_ROOT / f"{session_id}.events.jsonl"
    # Append-only; one line per event.
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")


def handle(event: dict) -> None:
    hook = event.get("hook_event_name", "")
    sid = event.get("session_id", "unknown")
    cwd = event.get("cwd", "")
    agent_pid = find_agent_pid()
    ts = time.time()

    record: dict = {
        "ts": ts,
        "hook": hook,
        "session_id": sid,
        "agent_pid": agent_pid,
        "cwd": cwd,
    }

    if hook == "SessionStart":
        # No additional fields needed — session_id alone is the anchor.
        # The L2/L3 sensor will see the openat+write to our sentinel
        # file from this hook's pid (a child of agent_pid), and we'll
        # extract it as the Session boundary.
        pass

    elif hook == "UserPromptSubmit":
        record["prompt"] = event.get("prompt", "")

    elif hook in ("PreToolUse", "preToolUse"):
        record["tool_use_id"] = event.get("tool_use_id", "")
        record["parent_tool_use_id"] = event.get("parent_tool_use_id") or ""
        record["tool_name"] = event.get("tool_name", "")
        record["tool_input"] = event.get("tool_input", {})

    elif hook in ("PostToolUse", "postToolUse"):
        record["tool_use_id"] = event.get("tool_use_id", "")
        record["parent_tool_use_id"] = event.get("parent_tool_use_id") or ""
        record["tool_name"] = event.get("tool_name", "")
        record["tool_input"] = event.get("tool_input", {})
        record["is_error"] = bool(event.get("is_error", False))
        # tool_response can be large (file contents, command output);
        # we don't capture it here. Downstream code reads the agent's
        # transcript for that if needed.

    elif hook == "Stop":
        record["stop_hook_active"] = bool(event.get("stop_hook_active", False))
        record["stop_reason"] = event.get("stop_reason", "")

    elif hook == "SessionEnd":
        # Nothing structured beyond the session_id. The fact that
        # SessionEnd fired vs. didn't is itself meaningful.
        pass

    else:
        # Unknown hook event — record it but flag in the file.
        record["unknown_hook"] = True

    emit_event(sid, record)


def main() -> None:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Malformed stdin — not a fatal error from Claude Code's
        # perspective. Just exit silently.
        sys.exit(0)
    try:
        handle(event)
    except Exception as e:
        # Don't fail Claude Code's tool dispatch if our hook errors.
        # Log to a sibling file for debugging.
        OUT_ROOT.mkdir(parents=True, exist_ok=True)
        log = OUT_ROOT / "hook_errors.log"
        try:
            with open(log, "a") as f:
                f.write(
                    f"{time.time()} {type(e).__name__}: {e}\n"
                )
        except Exception:
            pass


if __name__ == "__main__":
    main()
    sys.exit(0)
