"""V3 — Bare-host capture (L3 v2 sensor variant).

Same shape as v3_bare_host_capture.py but uses the L3 v2 sensor,
which adds the sched_process_fork tracepoint for deterministic
parent->child attribution. The trace files written contain
sched_fork events alongside the v1 event types (execve, openat,
clone, etc.); downstream consumers that only know about v1 events
ignore them.

Setup expected before running:
- conda env `mcp_test_venv` with python 3.11
- npm: @modelcontextprotocol/server-filesystem, @modelcontextprotocol/server-memory
- pip (in mcp_test_venv): mcp-server-git
- claude CLI on PATH
- L3 v2 sensor binary built at ds_gen/sensors/l3_v2_libbpf/build/l3v2-sensor
- Bedrock token sourced (via /tmp/bedrock_env.sh)

Each captured session writes:
  <out_dir>/<session_id>/
    ├── session.json       lightweight metadata
    ├── stream.jsonl       claude -p output
    ├── l3.jsonl           L3 v2 trace slice (ts-windowed); event
                          source field is "l3v2-libbpf"
    └── claude.log         agent stderr

The capture window is the lifetime of `claude -p` plus a small
flush margin.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

L3_BIN = Path("/lts/ai_sec_exp/cle4as/src/sensors/l3_v2_libbpf/build/l3v2-sensor")

# (mcp_label, mcp_invocation_argv, prompts)
MCPS = [
    {
        "label": "filesystem",
        "register_argv": [
            "claude", "mcp", "add", "filesystem",
            "--scope", "user", "--",
            "mcp-server-filesystem", "/tmp/v3_capture/workspace",
        ],
        "remove_argv": ["claude", "mcp", "remove", "filesystem", "--scope", "user"],
        "prompts": [
            "Can you read /tmp/v3_capture/workspace/README.md and tell me what it says?",
            "List the files in /tmp/v3_capture/workspace.",
            "What's in /tmp/v3_capture/workspace/config.json? Use the registered MCP tools.",
        ],
    },
    {
        "label": "memory",
        "register_argv": [
            "claude", "mcp", "add", "memory",
            "--scope", "user", "--",
            "mcp-server-memory",
        ],
        "remove_argv": ["claude", "mcp", "remove", "memory", "--scope", "user"],
        "prompts": [
            "Use the memory MCP to record that my favorite color is blue, then read it back.",
            "Store a note 'meeting at 3pm tomorrow' in memory and confirm it's saved.",
            "Use the memory tool to add a fact: 'project deadline is friday' then list facts.",
        ],
    },
    {
        "label": "git",
        "register_argv": [
            "claude", "mcp", "add", "git",
            "--scope", "user", "--",
            "/home/ubuntu/miniconda3/envs/mcp_test_venv/bin/mcp-server-git",
            "--repository", "/tmp/v3_capture/workspace",
        ],
        "remove_argv": ["claude", "mcp", "remove", "git", "--scope", "user"],
        "prompts": [
            "What's the current git status of /tmp/v3_capture/workspace? Use the git MCP.",
            "Show the most recent commit log entry for /tmp/v3_capture/workspace.",
            "Show the diff for the last commit using the git MCP.",
        ],
    },
]


def now_ns() -> int:
    return int(time.time() * 1_000_000_000)


def start_l3(out_path: Path, session_id: str) -> subprocess.Popen:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "sudo", "-n", str(L3_BIN),
        "--output", str(out_path),
        "--session-id", session_id,
        "--profile", "tampering",
    ]
    log_path = out_path.parent / f"{session_id}.l3sensor.log"
    log_fh = open(log_path, "ab")
    proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if out_path.exists() and out_path.stat().st_size > 0:
            with open(out_path) as f:
                first = f.readline().strip()
            if first:
                try:
                    rec = json.loads(first)
                    if rec.get("event") == "_calibration":
                        time.sleep(0.5)
                        return proc
                except json.JSONDecodeError:
                    pass
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("L3 sensor did not emit calibration record within 5s")


def stop_l3(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    subprocess.run(["sudo", "-n", "pkill", "-TERM", "-x", "l3v2-sensor"],
                   check=False, timeout=5,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_session(mcp: dict, prompt: str, out_dir: Path,
                session_label: str) -> dict:
    """Capture one bare-host session."""
    session_id = uuid.uuid4().hex[:12]
    sess_dir = out_dir / f"{session_label}_{session_id}"
    sess_dir.mkdir(parents=True, exist_ok=True)

    l3_path = sess_dir / "l3.jsonl"
    stream_path = sess_dir / "stream.jsonl"
    claude_log = sess_dir / "claude.log"

    # Register the MCP (this happens BEFORE the sensor starts so it's
    # not in the trace — same shape as containerized capture).
    subprocess.run(mcp["register_argv"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Start the L3 sensor for just this session window
        l3_proc = start_l3(l3_path, session_id)
        t_start = now_ns()
        try:
            # Run claude -p
            cmd = [
                "claude", "-p", prompt,
                "--dangerously-skip-permissions",
                "--permission-mode", "bypassPermissions",
                "--output-format", "stream-json",
                "--verbose",
                "--model", "us.anthropic.claude-haiku-4-5-20251001-v1:0",
            ]
            with open(stream_path, "wb") as so, open(claude_log, "wb") as se:
                proc = subprocess.Popen(cmd, stdout=so, stderr=se,
                                         env=os.environ.copy())
                try:
                    rc = proc.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    rc = -1
            t_end = now_ns()
            time.sleep(0.5)  # flush
        finally:
            stop_l3(l3_proc)
    finally:
        # Remove the MCP registration so it doesn't carry to the next session
        subprocess.run(mcp["remove_argv"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Build a session.json analogous to the containerized format
    meta = {
        "session_id": session_id,
        "session_label": session_label,
        "mcp": mcp["label"],
        "prompt": prompt,
        "variant": "benign",
        "intent_class": "benign",
        "patches_applied": [],
        "model": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "container_id": None,
        "cgroup_id": None,   # bare host — no Docker cgroup
        "started_at": datetime.fromtimestamp(t_start/1e9, tz=timezone.utc).isoformat(),
        "t_start_unix_ns": t_start,
        "t_end_unix_ns": t_end,
        "duration_ms": int((t_end - t_start) / 1e6),
        "exit_code": rc,
        "tool_calls": [],
        "tool_calls_unique": [],
        "stream_json_path": str(stream_path),
        "l3_slice_path": str(l3_path),
        "l1_strace_path": None,  # no L1 oracle on bare host
    }
    (sess_dir / "session.json").write_text(json.dumps(meta, indent=2))
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/lts/ai_sec_exp/picot/attribution_testing/v3_captures",
                    help="Where to write captured sessions")
    ap.add_argument("--prompts-per-mcp", type=int, default=3)
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for mcp in MCPS:
        for i, prompt in enumerate(mcp["prompts"][:args.prompts_per_mcp]):
            label = f"{mcp['label']}_{i:02d}"
            print(f"=== capturing {label} ===")
            try:
                meta = run_session(mcp, prompt, out_dir, label)
                rows.append(meta)
                print(f"  done: rc={meta['exit_code']} duration={meta['duration_ms']}ms")
            except Exception as e:
                print(f"  ERROR: {e}")
                rows.append({"label": label, "error": str(e)})

    (out_dir / "captures.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n"
    )
    print(f"\ncaptured {len(rows)} sessions to {out_dir}")


if __name__ == "__main__":
    main()
