"""Kuzu schema for the host-attribution provenance graph.

Two-layer schema: an OS layer (kernel-shape vertices) and an agent
layer (agent-shape vertices). Edges from the agent layer down through
ToolCall and Process to File/Socket leaves give the analyst the full
"what did this agent session actually do at the kernel layer" view.

OS-layer vertices (kernel-shape):
- Process    — one per host pid we ever see
- File       — one per opened path (path-string identity for now;
               (dev, inode) would be stronger but isn't in our captures)
- Socket     — one per (family, daddr, dport) for INET; pipe pairs
               keyed by their fd-pair string

Agent-layer vertices (agent-shape, generic across agent platforms):
- Session    — one per agent invocation; anchored at the agent's
               binary execve (`claude -p` for Claude Code)
- Iteration  — one per user-prompt → assistant-response turn within
               a session; the natural unit of analysis
- Prompt     — text content of the user's input for an iteration
- Response   — text content of the assistant's final output
- MCP        — one per loaded MCP server (third-party tool provider)
- Tool       — abstract tool definition (name, schema, is_builtin);
               many ToolCalls can reference one Tool
- ToolCall   — one per tool invocation; belongs to an Iteration;
               either handled_by an MCP (third-party) or no MCP
               (built-in tool, runs in the agent process)

Schema design notes:
- Kernel events stored as edges, not vertices. A `read` syscall is one
  row in the read REL table with a ts_ns. Per-tool-call attribution is
  computed by joining edges' ts_ns against a ToolCall's
  [t_open_ns, t_close_ns] window.
- Process pids are not unique across host reboots; within a single
  trace they are. One Kuzu DB per merged trace.
- The agent layer is intentionally agent-platform-agnostic. Different
  agents (Claude Code, ChatGPT, Qwen) feed agent-specific extractors
  that produce the same vertex/edge shapes. Detection queries written
  against the agent layer should generalize.
"""

# Each statement runs separately because Kuzu's DDL doesn't support
# multi-statement scripts in one execute(). The runner splits on `;\n`.
SCHEMA_STATEMENTS = [
    # ---- node tables ----
    """CREATE NODE TABLE Session(
        session_id        STRING,
        anchor_pid        INT64,
        t_start_ns        INT64,
        argv              STRING,
        terminator_status STRING,
        terminator_reason STRING,
        PRIMARY KEY(session_id)
    )""",

    """CREATE NODE TABLE Iteration(
        iteration_id   STRING,
        session_id     STRING,
        ordinal        INT32,
        t_start_ns     INT64,
        t_end_ns       INT64,
        outcome        STRING,
        PRIMARY KEY(iteration_id)
    )""",

    """CREATE NODE TABLE Prompt(
        prompt_id      STRING,
        iteration_id   STRING,
        text           STRING,
        ts_ns          INT64,
        PRIMARY KEY(prompt_id)
    )""",

    """CREATE NODE TABLE Response(
        response_id    STRING,
        iteration_id   STRING,
        text           STRING,
        ts_ns          INT64,
        PRIMARY KEY(response_id)
    )""",

    """CREATE NODE TABLE Tool(
        tool_key       STRING,
        name           STRING,
        is_builtin     BOOL,
        mcp_id         STRING,
        description    STRING,
        PRIMARY KEY(tool_key)
    )""",

    """CREATE NODE TABLE MCP(
        mcp_id        STRING,
        session_id    STRING,
        anchor_pid    INT64,
        name          STRING,
        argv          STRING,
        t_start_ns    INT64,
        PRIMARY KEY(mcp_id)
    )""",

    """CREATE NODE TABLE ToolCall(
        tool_call_id     STRING,
        iteration_id     STRING,
        mcp_id           STRING,
        name             STRING,
        is_builtin       BOOL,
        kernel_timing    STRING,
        t_open_ns        INT64,
        t_close_ns       INT64,
        is_error         BOOL,
        PRIMARY KEY(tool_call_id)
    )""",

    """CREATE NODE TABLE Process(
        pid           INT64,
        first_comm    STRING,
        first_argv    STRING,
        t_first_seen_ns INT64,
        PRIMARY KEY(pid)
    )""",

    """CREATE NODE TABLE File(
        path          STRING,
        PRIMARY KEY(path)
    )""",

    """CREATE NODE TABLE Socket(
        sock_key      STRING,
        family        INT8,
        daddr         STRING,
        dport         INT32,
        PRIMARY KEY(sock_key)
    )""",

    # ---- relationship tables ----
    "CREATE REL TABLE child_of(FROM Process TO Process, ts_ns INT64, via STRING)",
    "CREATE REL TABLE member_of_session(FROM Process TO Session, bound_at_ts_ns INT64)",
    "CREATE REL TABLE member_of_mcp(FROM Process TO MCP, bound_at_ts_ns INT64)",
    "CREATE REL TABLE has_mcp(FROM Session TO MCP)",
    "CREATE REL TABLE has_tool_call(FROM MCP TO ToolCall)",

    # ---- agent-layer relationships ----
    "CREATE REL TABLE has_iteration(FROM Session TO Iteration)",
    "CREATE REL TABLE follows(FROM Iteration TO Iteration)",
    "CREATE REL TABLE has_prompt(FROM Iteration TO Prompt)",
    "CREATE REL TABLE has_response(FROM Iteration TO Response)",
    "CREATE REL TABLE issued(FROM Iteration TO ToolCall)",
    "CREATE REL TABLE exposes(FROM MCP TO Tool)",
    "CREATE REL TABLE invokes(FROM ToolCall TO Tool)",
    "CREATE REL TABLE handled_by(FROM ToolCall TO MCP)",
    "CREATE REL TABLE first_call(FROM Iteration TO ToolCall)",
    "CREATE REL TABLE next_call(FROM ToolCall TO ToolCall)",
    "CREATE REL TABLE parent_call(FROM ToolCall TO ToolCall)",

    # File ops
    """CREATE REL TABLE read(FROM Process TO File,
        ts_ns INT64, fd INT32, flags INT32)""",
    """CREATE REL TABLE write(FROM Process TO File,
        ts_ns INT64, fd INT32, flags INT32)""",
    """CREATE REL TABLE unlink(FROM Process TO File,
        ts_ns INT64)""",

    # Socket ops
    """CREATE REL TABLE connect(FROM Process TO Socket,
        ts_ns INT64, fd INT32)""",
    """CREATE REL TABLE send(FROM Process TO Socket,
        ts_ns INT64, fd INT32, len INT32)""",
    """CREATE REL TABLE recv(FROM Process TO Socket,
        ts_ns INT64, fd INT32, len INT32)""",
    """CREATE REL TABLE bind(FROM Process TO Socket,
        ts_ns INT64, fd INT32)""",
]


def apply_schema(conn) -> None:
    """Apply the schema to a Kuzu connection. Idempotent-ish: silently
    skips tables that already exist."""
    for stmt in SCHEMA_STATEMENTS:
        try:
            conn.execute(stmt)
        except RuntimeError as e:
            msg = str(e).lower()
            if "already exists" in msg:
                continue
            raise
