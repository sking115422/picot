# Attribution testing — state of the work

**Date:** 2026-06-17 (originally 2026-06-15; revised with Phase 8 + 9 results)
**Purpose:** A consolidated entry point. The work spans roughly two
months and several phases; this document is the place to start if
you want the current picture without reading every prior doc.

The deeper docs (Phase 1–9 writeups, methodology versions, null
results) remain in this directory for history and detail.

---

## What this work is

We're investigating how to attribute kernel-level activity (eBPF
syscall events) to the agent-layer entities that caused it: which
*session*, which *MCP server*, which specific *tool call*. The goal
is a deterministic-as-possible mapping from raw OS traces to agent
abstractions, so a downstream detector or analyst can ask
"what did this MCP do during tool call X" and get a correct answer.

The work is part of the agenttrace project but is a self-contained
research line. Other agenttrace work (dataset generation, modeling,
benchmarks) consumes the *output* of this attribution layer but is
otherwise independent.

---

## Where we are now

Three attribution mechanisms are live and load-bearing. A fourth was
tried and de-prioritized.

### Mechanism 1 — kernel process tree from sched_fork (load-bearing)

The L3 v2 sensor (`ds_gen/sensors/l3_v2_libbpf/`) attaches to the
`sched_process_fork` kernel tracepoint and emits an authoritative
parent-pid → child-pid edge per fork. The original L3 sensor only
attached to `sys_enter_clone[3]`, which fire *before* the child task
exists and only carry the caller pid; the v1 graph builder had to
infer parent edges by binding the next-seen unknown pid to the
most-recent clone caller within a 200ms window.

The v1 timing inference was correct on **16–46% of forks per
session** (measured on three V3 captures, 2,149 forks total). 62% of
forks went through kernel codepaths that don't trigger
`sys_enter_clone[3]` at all (vfork, kernel_thread, internal
`_do_fork`); v1 missed those entirely. v2 catches them.

### Mechanism 2 — cgroup-gated clone inheritance (load-bearing fallback)

For pids that pre-existed the trace (no in-trace fork to bind them
to) and for any v1 captures, we still need a heuristic. The v1 200ms
clone-inheritance window plus a cgroup-match check is what catches
those. cgroup-gating prevents the heuristic from binding unrelated
system daemons (`irqbalance`, `systemd-resolve`, etc.) into the
agent's session subtree by rejecting bindings where the candidate
child's cgroup_id differs from the caller's.

The cgroup signal is real on any modern systemd-managed Linux host —
it isn't Docker-specific. systemd places each service in its own
cgroup, so cross-service forks are correctly rejected.

### Mechanism 3 — agent-layer hooks (load-bearing for tool-call boundaries)

Hook scripts at `ds_gen/attribution_testing/hooks/` register with
Claude Code's hook system (PreToolUse, PostToolUse, SessionStart,
UserPromptSubmit, Stop, SessionEnd) and emit one JSON line per event
to `~/.cache/agenttrace/attribution_testing/<sid>.events.jsonl`. The
sentinel-file write is itself a kernel-visible openat+write that our
eBPF sensor captures, so the markers show up in the regular trace.

The hooks-based agent-layer extractor (`agent_layer_hooks.py`) reads
these events and builds Iteration / Prompt / Response / ToolCall
vertices with kernel-precise wall-clock boundaries. The stream-based
extractor (`agent_layer_stream.py`) is the passive fallback for
captures that don't have hook data.

### Mechanism 4 — cohesion-based filtering (de-prioritized)

We tried filtering descendants whose file/socket touch-set didn't
overlap with the rest of the session. It either had no measurable
effect or harmed F1 by demoting legitimate non-MCP work (Bash
invocations, hooks). Documented as a null result; left in the code
behind a flag for reproducibility but not in the default scoring
path.

---

## Schema

The provenance graph is stored in Kuzu (embedded graph DB) with
ten vertex types and twenty edge types. Two layers:

**OS layer (kernel-shape):**
- `Process`, `File`, `Socket`
- Edges: `child_of`, `read`, `write`, `unlink`, `connect`, `send`,
  `recv`, `bind`

**Agent layer (agent-shape, agent-platform-agnostic):**
- `Session`, `Iteration`, `Prompt`, `Response`, `MCP`, `Tool`,
  `ToolCall`
- Edges: `has_iteration`, `has_prompt`, `has_response`, `issued`,
  `has_mcp`, `exposes`, `invokes`, `handled_by`, `first_call`,
  `next_call`, `parent_call`, `member_of_session`, `member_of_mcp`

The agent-layer schema is intentionally agent-platform-agnostic —
the same shape would extend to ChatGPT, Qwen, etc. with a
per-agent extractor. Today we only have a Claude Code extractor.

Schema definition: `ds_gen/attribution_testing/kuzu_schema.py`.

---

## Current attribution numbers

**Session and MCP** — 10-trial V3 metric (3 sessions per trial,
distinct MCPs), bare-host captures, per-event scoring:

| Level | Precision | Recall | F1 | Mechanism |
|---|---:|---:|---:|---|
| Session | 0.79 | 0.85 | 0.82 | sched_fork + cgroup-gating |
| MCP | 0.97 | 0.65 | 0.76 | sched_fork + layered detector |

When the system says "this kernel event belongs to session/MCP X,"
it's right ~79% of the time at the session level and ~97% at the
MCP level.

**Tool-call** — per-call metric on 9 v2 captures (18 calls), see
above for the table. The Phase 7 per-event tool-call number
(F1=0.60, precision=1.00) was misleading because of low coverage
on stdio MCPs and a circular ground-truth definition; the per-call
numbers reported here are the meaningful ones.

**Per-event tool-call F1 was the wrong metric.** Phase 8 / 9
(2026-06-17) replaced it with a per-call metric scored against
hook-anchored ground truth, and that surfaced a more important
finding: the kernel-only tool-call mechanism doesn't actually work
for stdio-transport MCPs.

**Per-call results** on all 9 v2 captures (18 ground-truth tool
calls; 13 paired PreToolUse/PostToolUse + 5 PreToolUse-only
orphans):

| Mode    | Per-call recall | Timing coverage | Per-call precision |
|---------|----------------:|----------------:|-------------------:|
| Passive (kernel-only) | 6/18 = **33.3%** | 0/2 = **0.0%**   | 6/7 = 85.7%         |
| Hooks (cooperative)   | 18/18 = **100%** | 11/13 = **84.6%** | 18/19 = 94.7%        |

Why passive is so weak: the predictor keys on `sendto` JSON-RPC
frames to detect `tools/call`, but the L3 v2 sensor only attaches
to `sys_enter_sendto`. All three v2 test MCPs (filesystem, git,
memory) communicate over **stdio pipes**, not sockets, so the
agent↔MCP traffic is invisible to the sensor entirely. The 6
passive matches are largely accidents (wrong-pid kernel-side
guesses that happened to share an id with a hook-attested call);
0/2 of the matched paired calls had a kernel-timing window
covering the hook window.

Why hooks is strong: PreToolUse → ToolCall vertex is a direct,
deterministic mapping from agent-layer cooperation. Every real
call is identified. Timing coverage is 85% rather than 100%
because the predictor's `t_open_ns` lands ~10–15ms after
PreToolUse fires (the hook is upstream of the actual tool
dispatch); 100% under a window-overlap definition.

**Tool-call attribution is reliable when hooks are available;
the passive path needs a sensor extension to trace `write`/
`writev` on stdio fds before it generalizes to non-cooperating
agents.** That's the open question now (Phase 10 candidate).

---

## What's been ruled out

These approaches were tried, didn't work for our threat model, and
should not be revisited without new evidence:

- **Cohesion-based descendant filtering.** The "are these processes
  doing related work" graph metric doesn't capture
  "session-relatedness" because legitimate session work is
  structurally heterogeneous (MCP server, Bash subprocesses, hook
  spawns, agent direct ops touch disjoint files). Documented in
  `2026-06-08_step2_cgroup_inheritance.md` and the cohesion null-
  result writeup.

- **Runtime-internal uprobes** (probing V8 / Python interpreter
  internals to extract tool dispatch). Maintenance treadmill across
  agent versions; the marginal signal over hooks-where-supported
  plus libssl-where-supported isn't worth the cost. Documented in
  `2026-06-08_phase6_scoping_cooperative_attribution.md`.

- **`claude mcp add` parsing as a primary MCP detection signal.**
  Corpus-specific (only fires under our V3 capture pipeline, not in
  real deployment). The layered detector still uses it as a layer-2
  fallback, but layer-3 (broadened name regex) gets ~all of what
  layer-2 catches in practice. Documented in
  `2026-06-08_step2_cgroup_inheritance.md` Step 1 result.

---

## Open questions

These have been articulated but not yet investigated:

1. ~~**Tool-call recall: tighten the ground-truth definition.**~~
   ~~**Per-call metric.**~~ *Both resolved in Phases 8–9
   (2026-06-17). The per-call metric was built and run; hooks-mode
   gets 18/18 identification with 85% timing coverage. The
   passive (kernel-only) path doesn't work for stdio MCPs and
   needs a sensor extension. See Phase 9 doc.*

   **Path A — passive tool-call attribution for stdio MCPs.** The
   L3 v2 sensor doesn't trace `write`/`writev`, so the JSON-RPC
   traffic between agent and stdio-transport MCPs is invisible.
   Adding a filtered write tracepoint (only emit writes whose
   target fd is a pipe to a tracked-agent child, or whose first
   bytes look like a JSON-RPC frame) would unlock passive
   tool-call attribution for non-cooperating agents (Cursor, ChatGPT
   SDK clients, etc). Estimated 1–2 days of BPF + parser, plus
   recapture. Deferred until detection-side use cases need it.

2. **Hooks-mode kernel-side ToolCall suppression.** In hooks mode
   the kernel-side `sendto` JSON-RPC parser still runs and can
   open spurious ToolCall vertices alongside the hook-anchored
   ones (we saw 1 such case in the v2 corpus). Hooks are
   authoritative; kernel-side guesses should be suppressed in
   that mode. ~10 lines.

2. **Pre-existing pid attribution.** Pids that forked before the
   trace started (sshd, systemd, etc.) have no in-trace
   `sched_fork` event, so we fall back to cgroup-gating. This is
   adequate for separating user-slice from system-slice processes
   but is heuristic. A `procfs` walk at sensor startup would give
   us deterministic pre-existing-pid attribution; the work is
   sensor-side and ~30 lines.

3. **L2_v2 port.** The deterministic-fork mechanism is currently
   only in the L3 (libbpf C) sensor. Porting to L2 (Aya/Rust) for
   production deployments would be ~30 lines of similar code.
   Deferred until we know production needs it.

4. **Cross-agent generalization.** The agent-layer schema is
   designed to be agent-platform-agnostic, but we only have a
   Claude Code extractor. Validating the claim requires writing a
   second extractor (ChatGPT SDK, Qwen Agent, Cursor) and seeing
   whether the same schema fills cleanly. Not blocked by anything
   in our work; just hasn't happened.

5. **Detection queries on the populated graph.** All the
   attribution machinery exists to support downstream
   detection — *did this MCP read credentials and then connect to
   a non-loopback host* type queries. We have the graph structure
   and the data model; we haven't run a real detection benchmark.
   This is the natural next research question.

---

## Code layout

```
ds_gen/attribution_testing/
├── README.md                        # quick start
│
├── # Sensors (parallel directories — leave originals alone)
│   sensors/l3_libbpf/                # v1 sensor; in use by other project
│   sensors/l3_v2_libbpf/             # v2 sensor with sched_fork
│
├── # Agent-layer extractors (toggleable)
│   agent_layer.py                    # dispatcher: stream | hooks | auto
│   agent_layer_stream.py             # passive: stream.jsonl
│   agent_layer_hooks.py              # cooperative: hook events
│   agent_layer_common.py             # shared dataclasses
│
├── # Hooks (self-contained Claude Code hook bundle)
│   hooks/attribution_hook.{sh,py}
│   hooks/install.sh                  # patches ~/.claude/settings.json
│
├── # Graph construction + queries
│   kuzu_schema.py                    # Kuzu schema definition
│   graph_builder.py                  # walks events, builds graph
│   kuzu_attribution.py               # per-event attribution lookup
│   queries/*.cypher                  # saved analyst queries
│   explorer.sh                       # launches Kuzu Explorer
│
├── # MCP detection
│   mcp_detector.py                   # layered detector (structural + claude-mcp-add + regex)
│
├── # V3 capture and scoring
│   v3_bare_host_capture.py           # captures using L3 v1
│   v3_bare_host_capture_v2.py        # captures using L3 v2
│   v3_score_kuzu.py                  # scoring on v1 captures
│   v3_v2_score.py                    # scoring on v2 captures (no cohesion)
│
├── # Captured corpora
│   v3_captures/                      # 9 sessions, v1 sensor
│   v3_captures_hooks/                # 12 sessions, v1 + hooks
│   v3_captures_v2/                   # 9 sessions, v2 sensor
│
└── # Results + per-phase docs
    results/*.{json,jsonl,md}
    docs/2026-06-15_state_of_the_work.md         # this file
    docs/progress/2026-06-01_*.md                 # methodology
    docs/progress/2026-06-08_step2_*.md           # cgroup-gating
    docs/progress/2026-06-09_phase6a_*.md         # hooks
    docs/progress/2026-06-15_phase7_*.md          # sched_fork
    docs/progress/2026-06-17_phase8_*.md          # tight tool-call windows
    docs/progress/2026-06-17_phase9_*.md          # per-call + hooks-mode
    (and earlier phase docs)
```

---

## How to reproduce a full pipeline

```bash
cd /lts/ai_sec_exp/picot/attribution_testing

# Build the v2 sensor (one-time, requires clang + libbpf-dev):
( cd ../sensors/l3_v2_libbpf && make )

# Install the hooks (one-time, modifies ~/.claude/settings.json):
hooks/install.sh

# Capture some sessions:
source /tmp/bedrock_env.sh
export AWS_REGION=us-east-2
python3 v3_bare_host_capture_v2.py --prompts-per-mcp 3 --out v3_captures_v2

# Score:
python3 v3_v2_score.py --captures-dir v3_captures_v2 --n-trials 10

# Visualize one capture in Kuzu Explorer:
./explorer.sh kuzu_graphs/v3_v2_t0.kz
```

---

## When to read which earlier doc

If you want a specific aspect, the older docs are organized
roughly chronologically:

- **Methodology and ground rules:**
  `2026-06-01_attribution_testing_methodology_pg_v2.md` — the
  current methodology doc with the provenance-graph framing. The
  `_pg.md` and non-`_pg` versions are superseded.

- **Why cgroup-gating, with measured numbers:**
  `2026-06-08_step2_cgroup_inheritance.md`. Includes the V3 corpus
  numbers and the specific failure modes that motivated the fix.

- **Why hooks (and what they do/don't help with):**
  `2026-06-09_phase6a_hooks_attribution.md`. Includes the
  per-tool-call event-window data showing where hooks lift
  precision and where they don't move F1.

- **Why sched_fork (and what it cost vs. helped):**
  `2026-06-15_phase7_sched_fork_attribution.md`. Includes the
  diagnostic that established v1's heuristic was correct on
  16–46% of forks, plus the v1-vs-v2 metric comparison.

- **Why tightening tool-call windows didn't help:**
  `2026-06-17_phase8_tight_tool_call_windows.md`. Documents the
  surprising-to-us finding that <0.5% of MCP-server kernel events
  occur during the actual tool-execution window. Per-event F1 is
  the wrong metric for tool-call attribution; per-call is the
  right shape.

- **Per-call metric and hooks-mode predictor:**
  `2026-06-17_phase9_per_call_metric_hooks_mode.md`. Establishes
  the per-call scorer, surfaces that the kernel-only predictor
  doesn't see stdio MCPs, and reports hooks-mode at 100/85%
  identification/coverage.

- **Lit-review framing of the work:**
  `../lit_review/2026-06-01_provenance_graphs.md`. Where this work
  sits in the broader provenance-IDS / agent-security literature.

- **Null results, for posterity:**
  `2026-06-08_step2_cgroup_inheritance.md` (cohesion filter section)
  and `2026-06-08_phase6_scoping_cooperative_attribution.md`
  (runtime-internal uprobes section).
