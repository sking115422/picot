"""Streaming parser for the ACE ``strace -f -ttt`` logs.

This module intentionally has no dependency on CLE4AS code. It reads the
PICOT-local ACE snapshot and exposes only the argument-bearing events needed
by the first semantic-effect prototype.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator


COMPLETE_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)\s*=\s*(?P<ret>.+?)\s*$"
)
UNFINISHED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\s+<unfinished \.\.\.>\s*$"
)
RESUMED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+"
    r"<\.\.\.\s+(?P<syscall>[A-Za-z0-9_]+)\s+resumed>\s*"
    r"(?P<args>.*)\)\s*=\s*(?P<ret>.+?)\s*$"
)

QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
WRITE_FLAG_WORDS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC")
PATH_SYSCALLS = {
    "openat",
    "open",
    "creat",
    "unlinkat",
    "unlink",
    "execve",
    "mkdir",
    "mkdirat",
    "rmdir",
    "rename",
    "renameat",
    "renameat2",
    "chmod",
    "fchmodat",
}


def _decode_quoted(value: str) -> str:
    return bytes(value, "utf-8").decode("unicode_escape", errors="replace")


def quoted_strings(args: str) -> list[str]:
    return [_decode_quoted(value) for value in QUOTED_RE.findall(args)]


def parse_return_value(raw: str) -> int | None:
    match = re.match(r"\s*(-?\d+)", raw)
    return int(match.group(1)) if match else None


def parse_argv(args: str) -> list[str]:
    # The first bracketed value after the executable is argv. Environment
    # arrays may follow, so stop at the first closing bracket.
    match = re.search(r"\[(.*?)\](?=,|$)", args)
    return quoted_strings(match.group(1)) if match else []


def parse_socket(args: str) -> dict:
    family_match = re.search(r"sa_family=(AF_[A-Z0-9_]+)", args)
    family = family_match.group(1) if family_match else None
    ip_match = re.search(r'(?:inet_addr|inet_pton\([^,]+,)\("?([^"),]+)', args)
    if ip_match is None:
        ip_match = re.search(r'(?:sin_addr|sin6_addr)=[^"}]*"([^"]+)"', args)
    port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)
    unix_match = re.search(r'sun_path="((?:[^"\\]|\\.)*)"', args)
    return {
        "family": family,
        "address": ip_match.group(1) if ip_match else None,
        "port": int(port_match.group(1)) if port_match else None,
        "unix_path": _decode_quoted(unix_match.group(1)) if unix_match else None,
    }


def build_event(pid: int, timestamp: float, syscall: str, args: str, raw_return: str) -> dict:
    values = quoted_strings(args)
    event = {
        "pid": pid,
        "timestamp": timestamp,
        "syscall": syscall,
        "return_value": parse_return_value(raw_return),
    }
    if syscall in PATH_SYSCALLS and values:
        event["path"] = values[0]
        if syscall in {"rename", "renameat", "renameat2"} and len(values) >= 2:
            event["destination_path"] = values[1]
    if syscall in {"open", "openat"}:
        event["write_intent"] = any(word in args for word in WRITE_FLAG_WORDS)
        event["create_intent"] = "O_CREAT" in args
        event["truncate_intent"] = "O_TRUNC" in args
    if syscall == "creat":
        event["write_intent"] = True
        event["create_intent"] = True
    if syscall == "execve":
        event["argv"] = parse_argv(args)
    if syscall in {"connect", "bind", "sendto"}:
        event.update(parse_socket(args))
    return event


def iter_strace_events(path: Path) -> Iterator[dict]:
    pending: dict[int, tuple[float, str, str]] = {}
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            complete = COMPLETE_RE.match(line)
            if complete:
                yield build_event(
                    int(complete.group("pid")),
                    float(complete.group("ts")),
                    complete.group("syscall"),
                    complete.group("args"),
                    complete.group("ret"),
                )
                continue
            unfinished = UNFINISHED_RE.match(line)
            if unfinished:
                pid = int(unfinished.group("pid"))
                pending[pid] = (
                    float(unfinished.group("ts")),
                    unfinished.group("syscall"),
                    unfinished.group("args"),
                )
                continue
            resumed = RESUMED_RE.match(line)
            if not resumed:
                continue
            pid = int(resumed.group("pid"))
            prior = pending.pop(pid, None)
            if prior is None or prior[1] != resumed.group("syscall"):
                continue
            timestamp, syscall, initial_args = prior
            final_args = resumed.group("args")
            yield build_event(
                pid,
                timestamp,
                syscall,
                f"{initial_args}{final_args}",
                resumed.group("ret"),
            )

