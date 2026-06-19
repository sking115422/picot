"""Layered MCP detector.

Three-layer approach for identifying which processes are MCP servers:

1. STRUCTURAL (deployment-realistic): a process is an MCP if it's a
   clone-descendant of a session's `claude -p` pid AND claude sent a
   JSON-RPC frame (`initialize`, `tools/list`, `tools/call`, etc.) on
   one of that process's open fds. This is the dominant signal — it
   doesn't depend on naming and works for any MCP launched as a
   subprocess of the agent.

2. CLAUDE_MCP_ADD (corpus-realistic): in our captured corpus the
   `docker-entrypoint.sh` script runs `claude mcp add <name> -- <bin>
   <args>` to register MCPs before launching the agent. The argv of
   that registration call is plainly in the trace; we extract the
   binary name(s) and use them as a registry. This catches MCPs that
   the structural detector misses (e.g., when no tools/list ever
   fires). NOTE: real deployments do not have `claude mcp add`
   per-session — they read MCP config from a config file at agent
   start. For deployment, this layer would be replaced by parsing
   the config file's contents (requires `read` syscall on the sensor,
   which we don't currently capture).

3. BROADENED_REGEX (cheap fallback): a relaxed name regex that
   matches MCP server binaries by *any* substring placement of `mcp`
   plus `server` or by other known shapes. Catches edge cases where
   neither structural nor registration-call detection fires.

Each layer adds to the registry; later layers don't overwrite earlier
ones. Output is a function `is_mcp_root(args)` that the graph builder
calls in place of the original.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

# ---- Layer 3: broadened name-pattern regex ------------------------
# Covers more shapes than the original ^mcp[-_]server[-_]:
#   mcp-server-X            (anthropic ref convention)
#   X-mcp-server            (arxiv-mcp-server, mcp-fetch-server-shape)
#   X-mcp                   (mcp-linear, agentic-tools-mcp,
#                            metmuseum-mcp, chroma-mcp)
#   awslabs.X-mcp-server    (awslabs.* prefix)
#   mcp-X-tools / mcp-X-server (mcp-sequentialthinking-tools)
#   mcp_X / mcp-X           (mcp_excalidraw, etc.)
_BROADENED_PATTERNS = [
    re.compile(r"^mcp[-_]"),                  # mcp-X*, mcp_X*
    re.compile(r"[-_.]mcp[-_]?server"),        # *-mcp-server, *.mcp-server
    re.compile(r"[-_.]mcp$"),                  # *-mcp, *.mcp
    re.compile(r"[-_]mcp[-_]"),                # X-mcp-Y
]

_WRAPPER_BINS = {"node", "python", "python3", "uv", "uvx"}


def _broadened_name_match(argv: list[str], path: str) -> tuple[bool, str]:
    """Layer 3: relaxed name-pattern matching."""
    if not argv:
        return False, ""
    argv0 = (argv[0] or path or "").rsplit("/", 1)[-1].lower()
    for p in _BROADENED_PATTERNS:
        if p.search(argv0):
            return True, argv0
    # Wrapper case (node/python/uvx scripting an MCP)
    if argv0 in _WRAPPER_BINS and len(argv) > 1:
        argv1 = (argv[1] or "").rsplit("/", 1)[-1].lower()
        for p in _BROADENED_PATTERNS:
            if p.search(argv1):
                return True, argv1
    return False, ""


# ---- Layer 2: claude-mcp-add registration parsing ------------------

def parse_claude_mcp_add(argv: list[str]) -> tuple[str, list[str]] | None:
    """Detect a `claude mcp add <name> ... -- <bin> [<args> ...]` call
    and return (name, [bin, *args]).

    Captures use a wrapping shell script that does:
      claude mcp add <name> --scope local -- <bin> <args>
    so we look for that shape. Returns None if argv isn't this shape.
    """
    if not argv:
        return None
    argv0_base = argv[0].rsplit("/", 1)[-1]
    if argv0_base != "claude":
        return None
    # Need 'mcp' and 'add' in the early-position args
    try:
        if argv.index("mcp") > 3 or argv.index("add") > 4:
            return None
    except ValueError:
        return None
    # Name follows 'add'
    try:
        i_add = argv.index("add")
        name = argv[i_add + 1] if i_add + 1 < len(argv) else ""
    except (ValueError, IndexError):
        return None
    # Binary follows '--'; skip env vars (X=Y form) and 'env' wrappers
    try:
        i_dd = argv.index("--")
        rest = argv[i_dd + 1:]
        while rest and (rest[0] == "env" or "=" in rest[0]):
            rest = rest[1:]
        if not rest:
            return None
        return name, rest
    except ValueError:
        return None


# ---- Layer 1: structural detection (running state) -----------------

@dataclass
class StructuralState:
    """Mutable state for the structural detector. The detector runs
    incrementally as the trace is consumed; it learns the registered
    binaries from layer 2's claude-mcp-add parsing and from observed
    JSON-RPC frames going to descendants of claude.

    `enable_claude_mcp_add` controls whether layer 2 (corpus-specific
    parsing of `claude mcp add` registration calls) is active. Set
    False to measure deployment-realistic attribution (where this
    signal does not exist).
    """
    # binary basename (lower) -> registered MCP name (from claude mcp add)
    registered_bins: dict[str, str] = field(default_factory=dict)
    # extension: known argv-tuple match (basename + first arg) for cases
    # where the same binary is used for multiple MCPs distinguished
    # by arguments
    registered_argv_tuples: dict[tuple, str] = field(default_factory=dict)
    # Toggle for layer 2 (corpus-specific — disable for deployment-realistic)
    enable_claude_mcp_add: bool = True

    def register_from_claude_mcp_add(self, argv: list[str]) -> None:
        if not self.enable_claude_mcp_add:
            return
        parsed = parse_claude_mcp_add(argv)
        if parsed is None:
            return
        name, rest = parsed
        bin_name = rest[0].rsplit("/", 1)[-1].lower()
        self.registered_bins[bin_name] = name
        # Also register a tighter argv-tuple for disambiguation
        if len(rest) > 1:
            tup = (bin_name, rest[1])
            self.registered_argv_tuples[tup] = name


# ---- The main entry point: layered_is_mcp_root ---------------------

def layered_is_mcp_root(args: dict, state: StructuralState
                          ) -> tuple[bool, str, str]:
    """Return (is_mcp, label, layer) for an execve event.

    layer is one of {"registered", "structural", "broadened", ""}.

    `state` is mutated as we go (claude mcp add events register
    binaries). For structural detection, the graph builder still has
    to verify the pid is a descendant of a claude session — this
    function only handles the binary-pattern decision.
    """
    argv = args.get("argv") or []
    path = args.get("path", "") or ""
    if not argv:
        return False, "", ""

    argv0_base = (argv[0] or path or "").rsplit("/", 1)[-1].lower()
    argv1_base = (argv[1].rsplit("/", 1)[-1].lower()
                   if len(argv) > 1 else "")

    # First, learn from any `claude mcp add` calls in this stream.
    # parse_claude_mcp_add returns None for non-registration argvs,
    # so this is a no-op for everything else.
    state.register_from_claude_mcp_add(argv)

    # ---- Layer 2: previously registered? --------------------------
    # Match by argv-tuple first (more specific), then by basename.
    if (argv0_base, argv1_base) in state.registered_argv_tuples:
        label = state.registered_argv_tuples[(argv0_base, argv1_base)]
        return True, label, "registered"
    if argv0_base in state.registered_bins:
        label = state.registered_bins[argv0_base]
        return True, label, "registered"
    # Wrapper case: node /path/to/script.js — check if argv[1]'s
    # basename is registered.
    if argv0_base in _WRAPPER_BINS and argv1_base in state.registered_bins:
        label = state.registered_bins[argv1_base]
        return True, label, "registered"

    # ---- Layer 3: broadened name match ----------------------------
    ok, label = _broadened_name_match(argv, path)
    if ok:
        return True, label, "broadened"

    return False, "", ""


# ---- Layer 1 verification (called by graph builder per-pid) -------

def is_likely_mcp_via_jsonrpc(buf_b64: str) -> bool:
    """Does this `sendto.buf_b64` look like a JSON-RPC frame the
    agent sends to an MCP? True for initialize / tools/list /
    tools/call / notifications/* — i.e., anything with `"method"`
    and `"jsonrpc"`.
    """
    if not buf_b64:
        return False
    try:
        raw = base64.b64decode(buf_b64)
    except Exception:
        return False
    return b'"method"' in raw and b'"jsonrpc"' in raw
