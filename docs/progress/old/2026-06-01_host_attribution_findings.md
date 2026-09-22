# Host-side attribution — what we can defensibly claim from eBPF alone

**Date:** 2026-06-01
**Builds on:** [layer_framing_and_roles.md](../progress/2026-05-28_layer_framing_and_roles.md), [unified_event_schema.md](../progress/2026-05-28_unified_event_schema.md), [l1_dominance_analysis.md](../progress/2026-05-27_l1_dominance_analysis.md)
**Code + raw results:** [ds_gen/attribution_testing/](../../ds_gen/attribution_testing/)

## Origin

Spencer asked in Slack: *"Can we run some experiments to check whether,
using only eBPF logs, we can identify the subprocesses of each session
and their corresponding system calls? If so, can we also identify the
subprocesses and threads belonging to each tool call?"*

Mikhail flagged a related issue: our pipeline gets one cgroup per
session for free because each session is its own container. In a real
deployment that property doesn't hold — agents can run bare on the
host, or one container can serve many sessions. So *cgroup_id* gives
container attribution, not session attribution in general.

This doc reasons through whether host-only attribution is feasible,
backs each claim with a measured experiment from
[ds_gen/attribution_testing/](../../ds_gen/attribution_testing/), and
states where the structural ceiling is.

## TL;DR

| Question | Host-only answer | Confidence |
|---|---|---|
| Process-level: identify subprocesses + their syscalls | **Yes — 100% subprocess recall, syscall counts faithful** | high (E1, E2) |
| Session-level: separate session events from host noise without cgroup-per-session | **Yes via agent-execve session roots — ARI ≈ 0.90** under stress, vs. cgroup baseline collapsing to 0 | medium-high (E3) |
| Per-MCP attribution within a session | **Yes — same subtree-closure mechanism as E1, applied to `mcp-server-*` execve roots** | high (mechanism, not separately measured) |
| Per-tool-call, sequential into one MCP | **77% land cleanly, <1% ambiguous, 22% miss for delegating MCPs** (puppeteer→chromium, postgres→libpq) | medium (E4) |
| Per-tool-call, concurrent into one MCP | **Structurally infeasible from host eBPF alone — 0/46 disjoint pairs (E5)** | high (information-theoretic ceiling, not sensor quality) |

The host trace contains every signal needed for process-, session-,
and per-MCP-level attribution under the dominant agent topology.
Per-tool-call attribution is deterministic for sequential calls and
hits an information-theoretic ceiling for concurrent calls into a
multi-threaded MCP — closing that gap requires an app-layer hook
(AgentShield's stdio tap is the natural one).

## Background — three families of app→OS attribution

This problem isn't novel. About 25 years of literature treats it
under three families:

1. **Cooperative propagation.** App carries a request id through every
   call boundary. Dapper (Google, 2010), X-Trace (NSDI '07), Magpie
   (OSDI '04), OpenTelemetry. Deterministic by construction; requires
   app cooperation.
2. **Structural isolation.** Each entity gets its own kernel-visible
   scope (cgroup, namespace, fresh pid). Falco/Tracee/Tetragon do
   per-container detection this way; Erlang/FaaS extend it per-call.
   Deterministic and zero-instrumentation, but only for entities the
   kernel can see.
3. **Causal inference from kernel events.** Whole-system provenance
   graphs — CamFlow (SOSP '17), ProTracer, BEEP, UNICORN (USENIX Sec
   '20), Kairos (S&P '24), the DARPA TC datasets. Zero-instrumentation
   but lossy at threading boundaries (the graph says "this syscall
   was caused by request A *or* B," not which).

The standard trade-off: pick **two of {deterministic, no app changes,
disambiguates concurrent work on a shared worker pool}**. Our setting
sits in eBPF boundary tracing (à la AgentSight, Tetragon) — kernel-
visible app-layer markers via stdio/TLS tap, deterministic up to the
threading boundary, probabilistic past it.

## Layer-by-layer analysis

### Layer 1 — Host trace → session events

**Mechanism.** Detect a session-root signal in the host event stream;
take the descendant pid closure via clone/clone3/execve edges; label
all events whose pid is in that closure as belonging to the session.

**Candidate session-root signals:**

| Signal | Strength | Weakness |
|---|---|---|
| `execve` of agent binary (e.g., `claude -p`) | Strong, kernel-visible, fires once per session | Hardcoded binary list; misses Python wrappers, custom launchers |
| First TLS handshake to a known LLM endpoint | Strong, behavioral | Fires after process startup, loses early syscalls |
| MCP `initialize` JSON-RPC over stdio | Strong, semantically aligned | Requires app-layer parsing (AgentShield's stdio tap) |

In practice, all three should be used as redundant evidence and
reconciled.

**Closure rule.** The descendant subtree of a session root is the
closure. This works when:
- The agent really is the parent of all session-related processes
  (true for `claude` + spawned MCPs over stdio).
- Parent→child edges are reconstructible from clone/clone3 (E1
  measured 99.8% edge recall on L3, 85% on L2_ext).

**Where it breaks (out of scope for the host-only mechanism):**
- **Daemon MCPs.** A `postgres-mcp` running as a systemd service the
  agent connects to over TCP is *not* in the agent's subtree.
  Attribution requires connect()/accept() correlation — a different
  mechanism.
- **Shared system services.** When the agent calls `getaddrinfo`,
  glibc may delegate to systemd-resolved. Are those resolved syscalls
  "part of the session"? Definitional choice, not a measurement.
- **Persistent agents serving multiple sessions.** Subtree closure
  says "one session" — wrong. Need MCP `initialize` or an app-layer
  marker firing per session, not per process.

**Measured (E3, see [results](../../ds_gen/attribution_testing/results/SUMMARY.md#e3--session-partitioning-without-cgroup-per-session)):**

Synthetic stress condition — concatenate 5 random captured sessions,
strip their distinct cgroup_ids and replace with a single shared
value, interleave by ts. Score session-id recovery using event-level
Adjusted Rand Index.

| Strategy | ARI mean | ARI range |
|---|---:|---|
| Baseline: partition by `cgroup_id` | 0.000 | — (collapses by construction) |
| **Agent-execve session roots** | **0.902** | 0.840 – 0.954 |

The 5–15% loss is from runc/docker-entrypoint events that fire
*before* the `claude -p` execve and get misattributed to whichever
session is "open" at concatenation time. In a real deployment without
the runc preamble, ARI would likely be higher.

### Layer 2 — Session events → per-MCP

Conceptually easier than Layer 1: each MCP server is its own
subprocess with a clear `execve` root (`mcp-server-*` or
`{node,python,uvx} <mcp_script>`). The same subtree-closure mechanism
applies recursively.

**Why our threat-model surface lives cleanly in the MCP subtree:**
- Files opened by the MCP — `openat` from MCP subtree pids
- Network destinations — `connect`/`sendto` from MCP subtree pids
- Child processes spawned (e.g., `command_injection` patches) —
  `clone`/`execve` from MCP subtree pids

All three attribute deterministically by subtree membership.

**Where it breaks:** same daemon-MCP and shared-system-service
caveats as Layer 1.

Not separately measured because every session in the corpus has one
MCP, but the mechanism is identical to E1's process-forest result
(100% subprocess recall, 99.8% edge recall on L3).

### Layer 3 — Per-MCP → per-tool-call

This is where the structural ceiling sits, and it's information-
theoretic, not engineering.

**Sequential tool calls (one in flight at a time):**
- The MCP server's pid (and its descendants) own all syscalls
  emitted in the tool-call window.
- Time-window + subtree attribution works.
- E4 measured 77% clean attribution, <1% ambiguous, 22% miss.
- The 22% miss is concentrated in **delegating MCPs**: puppeteer
  (the MCP server hands work off to a long-running chromium child)
  and postgres (libpq talks to the DB on behalf of the server). Fix
  is to attribute to the MCP server's *descendant subtree* across
  the whole session, not just within the window.

**Concurrent tool calls (multiple in flight on the same MCP):**
- Calls share the same pid (server process) and may share the same
  threads (worker pool).
- Syscalls from the two calls interleave in time.
- The kernel has **no signal that distinguishes them**. The thing
  that would — the JSON-RPC request id — is application-layer data
  that crossed the kernel→userspace boundary at the MCP's read() and
  thereafter exists only inside the MCP's process memory.

E5 confirmed this empirically: under synthetic 50% overlap, **0/46
overlapping pairs had disjoint tid sets** across 30 sessions.

This is the same ceiling Dapper and BEEP hit. Dapper's solution is
cooperative propagation — the application carries the request id
through every call. BEEP's solution is application instrumentation
to emit unit boundaries. Neither is zero-instrumentation.

**The escape hatch.** The boundary where the request id last exists
in kernel-visible form is the MCP's `read()` from stdin (or
`SSL_read` for TLS-tapped MCPs). If we tap that boundary, parse the
JSON-RPC request, and emit a kernel-time-stamped event with the
request id, we get a deterministic anchor *up until the request is
dispatched to a worker thread.* Past that point, we're guessing.

AgentShield's existing `L7StdioMcp` tap is exactly this primitive.
It already exists; what's needed is to wire it into the v1 emitter
as `mcp_jsonrpc` events (currently 0 in the L2_ext slice we
checked). That's the next experiment, not a research breakthrough.

## What this means for the project

**Defensible claims for the paper:**

1. **Host-only eBPF can attribute syscalls to sessions and to MCPs**
   reliably under the dominant agent topology, with a measurable
   degradation under deployment-realistic conditions (no
   cgroup-per-session) that's bounded at ARI ≈ 0.10.
2. **Per-tool-call attribution is bounded by an information-theoretic
   ceiling**, not by sensor quality. We name this explicitly and
   point to the application-boundary tap as the standard solution
   (AgentSight, Dapper, BEEP).
3. The contribution is not a novel attribution mechanism — it's
   *what we attribute* (LLM tool calls and stated intent) and *what
   we detect* (kernel-side deviations from declared intent),
   evaluated against a paired benign/malicious corpus that no prior
   dataset provides.

**Out of scope, named explicitly:**

- Daemon MCPs reachable over a socket the agent didn't open (would
  need connect/accept correlation; different mechanism).
- Persistent agents serving multiple sessions (would need
  app-layer session markers firing per session, not per process).
- Disambiguating concurrent tool calls on a shared worker pool from
  kernel events alone (impossible without an app-layer hook).

**Experiment work items, in priority order:**

1. Wire `mcp_jsonrpc` events into the v1 emitter. The probe already
   exists in legacy AgentShield (`L7StdioMcp`); just needs to feed
   `v1_emitter.rs`. Estimated 1 day.
2. Re-run E5 with `mcp_jsonrpc` request-id correlation as the
   attribution mechanism. Expected to close the concurrency gap.
3. **Concurrent-session capture run.** The current corpus is 100%
   sequential (567/567 sessions, no temporal overlap). To validate
   E3's session-extraction in non-synthetic conditions, run a small
   capture with 4–8 simultaneous agent processes on the same host.
   Estimated 2–3 hours capture + half day analysis.
4. Daemon-MCP capture. Configure one MCP (e.g., postgres-mcp) as a
   long-lived service the agent connects to via TCP, measure how
   subtree-closure breaks and what connect/accept correlation
   recovers.

## Reproduce the host-side numbers

```bash
cd /lts/ai_sec_exp/picot/attribution_testing
python3 run_all.py --limit 50
# Per-experiment outputs land in results/eN.jsonl + eN_summary.json
# Headline numbers in results/SUMMARY.md
```

## References

- Sigelman et al., *Dapper, a Large-Scale Distributed Systems Tracing Infrastructure*, 2010 — [paper](https://research.google/pubs/dapper-a-large-scale-distributed-systems-tracing-infrastructure/)
- Pasquier et al., *Practical Whole-System Provenance Capture (CamFlow)*, SOSP '17 — [camflow.org](https://camflow.org/)
- Lee et al., *High Accuracy Attack Provenance via Binary-based Execution Partition (BEEP)*, NDSS '13
- Han et al., *UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats*, USENIX Security '20
- Cheng et al., *Kairos: Practical Intrusion Detection and Investigation using Whole-system Provenance*, S&P '24 — [arXiv:2308.05034](https://arxiv.org/abs/2308.05034)
- AgentSight, *eBPF Boundary Tracing for AI Agent Activity*, PACMI '25 — [arXiv:2508.02736](https://arxiv.org/abs/2508.02736)
- Tetragon `parent_exec_id` / Tracee `tree=<pid>` — direct prior art for sub-process attribution; covered in [ebpf_security_detection.md](../lit_review/2026-05-19_ebpf_security_detection.md)
