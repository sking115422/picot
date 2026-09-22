# Phase 6 scoping — cooperative attribution options

**Date:** 2026-06-08
**Status:** scoping doc, not a commitment to any of these mechanisms

This doc surveys five mechanisms for *cooperative* attribution —
ways the agent or its runtime can leak structured information about
its logical state at well-defined boundaries, so passive trace
attribution doesn't have to do all the inference work alone. Each
option is scored on what it gains, what it costs, how well it
generalizes across agents and runtimes, and how robust it is.

The motivation: Phase 1–5 took passive trace-only attribution as
far as it sensibly goes. Deployment-realistic numbers are
session F1 ≈ 0.81, MCP F1 ≈ 0.84, tool-call F1 ≈ 0.54. The
remaining gaps are structural — built-in tool boundaries,
same-MCP concurrent calls, multi-instance under same uid, and
multi-turn iteration boundaries — and cannot be closed from
passive trace alone. Cooperative signals from the agent or
runtime can close them. The question is which mechanism, at
what cost.

## Important framing distinction

Two independent questions get conflated and shouldn't be:

- **Question A — what produces the marker?** What entity decides
  "the agent just started a tool call" and emits a corresponding
  event? (The agent itself via hooks, the runtime via uprobes,
  the SDK via instrumentation, etc.)

- **Question B — how does the marker reach our trace?** What
  kernel-visible event represents the marker so eBPF can see it?
  (Sentinel-file write, named-pipe write, syscall pattern,
  /sys/kernel/debug/tracing/trace_marker, etc.)

The mechanisms below answer A. Question B is transport
infrastructure that any of A's options can plug into. The
sentinel-file bus is the most likely answer to B for our setup
because our existing eBPF sensor already captures openat + write
events — markers written to a sentinel file path show up in the
trace for free.

## Option 1: Agent-emitted hooks

What we'd gain. Definitive, structured events at the agent's
logical boundaries with the agent's own metadata. PreToolUse
fires before each tool dispatch with the full tool name,
arguments, session id, and tool_use_id. SessionStart fires once
with the session id. PostToolUse fires after the call completes.
UserPromptSubmit fires when a new prompt arrives.

Closes most of our remaining gaps directly:
- Built-in tool boundaries (PreToolUse marks them as kernel-visible)
- Same-MCP concurrent calls (PreToolUse fires per-call with the
  tool_use_id, serialized in the agent's main loop)
- Same-user multi-instance (SessionStart fires with the agent's
  own session id)
- Iteration boundaries (UserPromptSubmit per turn)

Latency cost. Hooks block the agent's main loop until they exit.
Realistic design is hooks that exit fast (a single sentinel-file
write) and let async daemons collate the data — adds ~ms per
hook fire, well under the noise floor of agent latency.

Performance overhead. Per session, ~50–200 hook invocations
(SessionStart + SessionEnd + PreToolUse + PostToolUse +
UserPromptSubmit). Each is a fork/exec. On a host running many
agents that's 1–5% CPU.

Generalizability. Real but uneven. Most modern agents have hook
systems but they're all different:
- Claude Code — well-documented JSON-over-stdin protocol
- Cursor — similar shape, slightly different events
- Cline / Continue — varying sophistication
- Aider — simpler hook surface
- ChatGPT (the API) — no hooks; the agent is whatever script the
  user wrote, and it has no hook system unless they wrote one
- Qwen Agent / open-source agents — depends entirely on the
  specific implementation

So the mechanism (hooks emit kernel-visible events) generalizes
across hook-supporting agents; the configuration (which hooks to
register, what events they listen for) is per-agent. Each agent
gets its own hook config bundle.

Implementation difficulty. Low for Claude Code: write a small
set of hook scripts, document the install path, ship them as a
config bundle. The user runs them once, then their agent emits
markers automatically.

Reliability under attack. Strong vs. compromised MCP (a
compromised MCP cannot disable the agent's hooks). Weak vs.
compromised agent (the agent could disable its own hook system).
For our supply-chain MCP threat model this is fine; for full
agent-compromise scenarios it isn't.

Net assessment. Highest signal-per-cost ratio for the gaps our
schema cares about. Where supported, use them.

## Option 2: Uprobes on stable userspace boundaries (libssl)

This is the AgentSight / Argus pattern — probe libssl's
SSL_write and SSL_read. Every TLS-encrypted bidirectional stream
passes through these functions in plaintext just before
encryption / just after decryption.

What we'd gain. Plaintext of every HTTPS-bound communication the
agent does. For our use case:
- The agent's chat with the LLM provider (Bedrock, OpenAI,
  Anthropic API) — full prompt and response visible at the
  boundary
- HTTP-transport MCPs (rare today, common in some deployments) —
  full JSON-RPC visible
- Webhook deliveries, REST API calls the agent or MCP makes for
  tool work

This is the canonical "boundary tracing" trick: TLS is supposed
to make traffic opaque to the host's network observers, but it's
NOT opaque to the host's userspace observers because the
encryption happens after the call to SSL_write returns. Attach
to SSL_write and capture the buffer before it's encrypted.

Latency cost. Per-call uprobe overhead is ~1–5 microseconds.
For an agent doing 100 LLM API calls per session, negligible.

Performance overhead. Higher than hooks because every TLS write
on the host fires the probe, not just the agent's. AgentSight
reports <3% overhead in benchmarks. Cost scales with how busy
the host is, not with agent activity.

Generalizability. This is where uprobes shine. libssl is the
same library on every Linux distribution, every agent, every
language. Whether the agent is Python with `requests`, Node
with `fetch`, Go with `net/http`, Rust with `reqwest`, Bash with
`curl` — they all eventually call into libssl (or one of its
variants: BoringSSL, LibreSSL, GnuTLS). Probe the right symbol
and you see plaintext for any of them.

Catches: not every agent uses libssl. Some statically link
OpenSSL. Some use Rustls. Java agents use the JVM's TLS, which
doesn't go through libssl. Coverage isn't 100% but for the
dominant case (dynamically-linked OpenSSL), it's broad.

Implementation difficulty. Medium. Requires:
- Symbol resolution on libssl (CO-RE-style relocation handles
  per-distro version differences)
- Buffer extraction from a fixed-size kernel buffer (256B or so
  per call; multiple calls for big payloads need reassembly)
- TLS context tracking to associate writes with reads (per-pid)

The reassembly is the hard part — a single LLM API request can
be 100KB+, fragmented across many SSL_write calls. AgentSight
does this; the code is real but non-trivial. ~500 LoC of eBPF C
plus userspace reassembly.

Reliability under attack. Strong. The adversary would have to
either evade libssl entirely (statically link, raw sockets with
custom crypto — both unusual) or detach our uprobe (requires
CAP_BPF, which the adversary doesn't have if we control the
host). For supply-chain MCP threats, robust.

Net assessment. Already partially built into AgentShield (TLS
plaintext capture for LLM endpoint detection). The capability we
don't yet exploit is using these payloads to anchor agent-layer
boundaries — the LLM API's request id is in the SSL_write
plaintext, and that's a stable cross-agent identifier. Worth
investing in even if hooks are also available.

## Option 3: Uprobes on agent-runtime internal functions

This is "probe V8's tool-dispatch function" or "probe Python's
interpreter when it's running the agent." Different from option
2 because the symbol you're probing is *inside the agent
runtime*, not in a stable shared library.

What we'd gain. Direct visibility into the agent's execution:
every tool dispatch, every internal state change, even the
agent's reasoning steps if you probe the right callbacks. The
deepest level of cooperative attribution available without
modifying the agent.

Latency cost. Same per-call overhead as option 2 (microseconds),
but the probe fires *much* more often if you pick a noisy
function. Probing V8's bytecode dispatch is unworkable (millions
of calls per second). Probing a specific high-level callback is
fine.

Performance overhead. Highly dependent on what you probe. Right
call: <1%. Wrong call: 50%+ slowdown.

Generalizability. Low. Each runtime needs its own probe set:
- Node.js / V8 — probe specific JS functions via stable C entry
  points
- CPython — probe `PyEval_EvalFrameDefault` or specific bytecode
  handlers
- PyPy / V8 / JS engines with JIT — much harder, JITted code
  doesn't have stable symbols
- Ruby, Go, Rust — each needs its own approach
- Java — uprobes don't reach the JVM's internal state easily

And the symbols you'd probe are agent-version-specific. Claude
Code's internal `dispatchToolUse` (or whatever it's called) is
in the minified Node bundle, with a name that changes between
releases. You'd need either version-specific probe configs or a
heuristic that finds the right function dynamically.

Implementation difficulty. High, and a maintenance treadmill.
Each agent version needs validation, sometimes a new symbol
mapping. The kind of work that gets stale fast.

Reliability under attack. Strong against external attackers,
weak against agent-runtime authors. If Claude Code's authors
change their tool dispatch path, we silently miss everything
until we update.

Net assessment. Avoid for our purposes. The signal you'd extract
is mostly available through hooks (for agents that have them) or
through SSL_write probing (for agents that talk to LLMs over
HTTPS, which is all of them). The maintenance burden isn't worth
the marginal additional signal.

## Option 4: In-process instrumentation (modifying the agent or runtime)

For completeness — this is "fork the agent, add telemetry, run
our fork." Or "convince the agent's authors to add a telemetry
hook upstream."

What we'd gain. Anything we want, in principle. Unlimited
signal.

Cost. Massive. Maintaining a fork of a fast-moving agent is its
own project. Convincing upstream authors to add hooks for our
use case is also its own project.

Generalizability. Zero. Every agent is its own fork.

Net assessment. Don't do this. The exception would be if we
eventually want to publish a *standard* "agent telemetry"
interface that agent authors implement (like OpenTelemetry but
for agent-internal events). That's a multi-year project, not a
Phase 6.

## Option 5: Sentinel files / named pipes as a kernel-visible marker bus

NOT a separate attribution mechanism — this is the *transport
infrastructure* that hooks (option 1) write through. Mention it
because the cost analysis depends on it and because it's easy to
mistake the bus for the source of the signal.

Pattern. A fixed directory like `/var/run/copperhead/` with a
known FIFO. Whatever decides "an event happened" writes JSON
lines to this FIFO; a daemon reads and forwards to the trace.
Each write is a kernel-visible openat + write event in our
existing eBPF trace, so the marker shows up in the same data
stream as the rest of attribution. No new sensor, no new
pipeline.

The "kernel-visible" part is the key. We don't need to teach
AgentShield to read from this FIFO; we just need to teach it to
recognize openat/write events whose path matches our sentinel
pattern and parse them as agent events.

Cost. Minimal: one openat + one write per event = ~microseconds.

Generalizability. The mechanism (kernel-visible IPC primitive
that the sensor already observes) is universal. The specific
primitive is platform-specific:
- Linux — sentinel-file or named-pipe writes
- Windows — ETW (Event Tracing for Windows) or named pipes
- macOS — dtrace tracepoints

Net assessment. Use this as the transport for any of options
1–4. It is not a stand-alone attribution mechanism — it transports
events that some other mechanism produces.

## Side-by-side comparison

| Option | Source of signal | Gain | Latency | Overhead | Generalizes? | Implementation cost | Robust to attack? |
|---|---|---|---|---|---|---|---|
| 1. Agent hooks | agent's own hook system | Boundaries: session, iteration, tool dispatch — with agent's own ids | ~ms per hook (mitigable) | 1–5% on busy hosts | per-agent config; impossible for ChatGPT-API-as-script style | low for Claude Code; nil for hookless agents | strong vs. compromised MCP, weak vs. compromised agent |
| 2. libssl uprobes | dynamically-linked TLS library | LLM API plaintext, HTTPS-MCP plaintext | µs per call | <3% | yes (every dynamically-linked-libssl process) | medium (~500 LoC eBPF + reassembly) | strong |
| 3. Runtime-internal uprobes | agent runtime's symbols | Per-tool-dispatch, including built-ins | µs to ms per call | <1% to >50% (depends on function) | per-runtime, per-version | high; maintenance treadmill | strong vs. external; weak to runtime updates |
| 4. Modify agent | the agent's source | Anything | depends | depends | no | massive | depends |
| 5. Sentinel-file bus | nothing on its own (transport only) | n/a — it's a transport | µs per event | negligible | platform-specific equivalents exist | low | n/a (it's a transport) |

## Things to verify before committing to any of these

A few empirical checks worth running before deciding:

- **What's Claude Code's actual hook latency?** Estimated ~ms but
  should measure. If a no-op hook adds 30ms it changes the cost
  picture.
- **Does Cursor / Cline actually have working hooks today?**
  Worth checking. If only Claude Code does, the generalization
  story for option 1 is weaker than it might look.
- **What does the libssl uprobe approach look like with our
  existing AgentShield?** It already does TLS plaintext capture
  for LLM endpoint detection. Whether we can extend the existing
  code or need new probes affects the cost.
- **What does ChatGPT API attribution look like under this
  framing?** ChatGPT-as-CLI doesn't exist canonically; users
  access it through SDKs (`openai` Python, `openai-node`). If
  "the agent" is a Python script using the openai SDK, where do
  hooks go? Probably nowhere — the SDK doesn't have a hook
  system. So for ChatGPT-style usage, hooks fail and uprobes are
  the only option. Worth knowing this before claiming
  generalization.

That last point is important. **Hooks generalize across
agents-with-hooks, not all agents.** For agents without hooks,
uprobes are the fallback — and that's a more expensive path.
Saying "we generalize across agents" honestly means "we
generalize across hook-supporting agents" plus "we fall back to
uprobes for hookless ones, with reduced coverage."

## Recommendation summary

For attribution-reliability gains specifically:

- **Hooks (option 1)** are the right primary mechanism for
  agents that support them.
- **libssl uprobes (option 2)** are the right complementary
  secondary mechanism — they answer a different question
  (content visibility) and provide a fallback for hookless
  agents.
- **Runtime-internal uprobes (option 3)** are not worth their
  maintenance cost.
- **Modifying the agent (option 4)** is out of scope.
- **Sentinel-file bus (option 5)** is the transport infrastructure
  that wraps options 1–3.

Generalization story is real but qualified — strong for
hook-supporting agents, weaker for hookless ones. Empirically
validating against a non-Claude-Code agent (ChatGPT via SDK,
Qwen Agent, Cline, etc.) is the test that confirms or
falsifies the generalization claim.
