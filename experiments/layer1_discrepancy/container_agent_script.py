"""Scripted 'agent' for the Layer 1 discrepancy diagnostic.

Runs a fixed sequence of tool-like operations inside a container so we
get a repeatable syscall shape. Not an LLM. The operations cover the
six syscalls the L3 v2 sensor captures (openat, unlinkat, connect,
sendto, execve, clone) plus the read/write/close/stat traffic that
sensor misses.

Each step logs to stderr with a wall-clock ns marker so we can align
the strace + host bpftrace outputs against tool-call boundaries.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def mark(name: str) -> None:
    print(f"MARK {time.time_ns()} {name}", file=sys.stderr, flush=True)


def step(name: str, fn):
    mark(f"step_start:{name}")
    try:
        fn()
    finally:
        mark(f"step_end:{name}")


def read_workspace_files(root: Path) -> None:
    for p in root.rglob("*.txt"):
        p.read_bytes()


def write_output_file(root: Path) -> None:
    (root / "output.txt").write_text("hello from the scripted agent\n" * 20)


def append_to_output(root: Path) -> None:
    with (root / "output.txt").open("a") as fp:
        for i in range(5):
            fp.write(f"line {i}\n")


def stat_many(root: Path) -> None:
    for p in root.rglob("*"):
        p.stat()


def delete_file(root: Path) -> None:
    tmp = root / "scratch.txt"
    tmp.write_text("delete me")
    tmp.unlink()


def spawn_subprocess() -> None:
    subprocess.run(["/bin/echo", "child-process ran"], check=True, capture_output=True)


def spawn_python_child() -> None:
    subprocess.run(
        [sys.executable, "-c", "import os; print(os.getpid())"],
        check=True,
        capture_output=True,
    )


def local_socket_roundtrip() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
            cli.connect(("127.0.0.1", port))
            cli.sendall(b"hello\n")
            conn, _ = srv.accept()
            conn.recv(64)
            conn.close()


def multi_socket_roundtrips() -> None:
    for _ in range(3):
        local_socket_roundtrip()


SENTINEL = Path("/sentinel/go")


def wait_for_sentinel(timeout_s: float = 60.0) -> None:
    """Block until the launcher creates /work/go, or until timeout."""
    start = time.time()
    while not SENTINEL.exists():
        if time.time() - start > timeout_s:
            raise TimeoutError(f"sentinel {SENTINEL} did not appear in {timeout_s}s")
        time.sleep(0.02)


def main() -> int:
    mark("waiting_for_sentinel")
    wait_for_sentinel()
    mark("sentinel_received")

    workspace = Path(tempfile.mkdtemp(prefix="agent_ws_"))
    mark(f"session_start ws={workspace}")

    for i in range(6):
        (workspace / f"seed_{i}.txt").write_text(f"seed content {i}\n" * 30)

    try:
        step("read_workspace_files", lambda: read_workspace_files(workspace))
        step("write_output_file", lambda: write_output_file(workspace))
        step("append_to_output", lambda: append_to_output(workspace))
        step("stat_many", lambda: stat_many(workspace))
        step("spawn_subprocess", spawn_subprocess)
        step("spawn_python_child", spawn_python_child)
        step("local_socket_roundtrip", local_socket_roundtrip)
        step("multi_socket_roundtrips", multi_socket_roundtrips)
        step("delete_file", lambda: delete_file(workspace))

        summary = {
            "workspace": str(workspace),
            "wall_end_ns": time.time_ns(),
        }
        (workspace / "_summary.json").write_text(json.dumps(summary, indent=2))

    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    mark("session_end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
