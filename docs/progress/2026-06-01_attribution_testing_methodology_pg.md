# Host-side attribution testing — provenance-graph framing

**Date:** 2026-06-01

This doc restates the host-side attribution testing pipeline in
provenance-graph terms. The mechanism, code, and results are the
same as in the companion methodology doc; the framing here aligns
with the conventional vocabulary used in the provenance-IDS
literature (CamFlow, Kairos, ORTHRUS, OmegaLog, BEEP).

It is self-contained — all references to other files are summarized
here.

## Question

> Given an arbitrary host-side eBPF trace, can we deterministically
> attribute each kernel event to the *session* that produced it, the
> *MCP server* that handled it, and the *tool call* during which it
> fired — using only kernel-observable signals?

The deployment scenario is AgentShield-style: a host-side sensor
runs continuously on a machine, and one big trace file accumulates
events from everything on the host. We want to label each event
with a `(session, mcp, tool_call)` triple — or "not relevant" — with
no cooperation from the agent or MCP and no in-container
instrumentation.

In provenance-graph terms: we want to construct a **per-session
provenance graph** from the host trace where the agent session, its
MCPs, and each MCP's tool calls appear as explicit entity vertices,
and every kernel event is reachable from exactly one
session-MCP-tool-call vertex chain.

## Source data — three sensor layers

Every captured session writes traces from three concurrent sensor
stacks running against the same workload. The three layers exist
for different purposes; this section summarizes what each one is.

### L1 — strace inside the container (oracle ground truth)

- **Vantage:** ptrace-based, runs as PID 1's child *inside* the
  session container. Sees every syscall every process in the
  container makes.
- **Filter:** `execve, openat, open, connect, sendto, recvfrom,
  unlinkat, unlink, ptrace, clone, clone3, exit_group, write, read,
  bind`.
- **Format:** strace text output, one line per syscall, timestamped
  with wall-clock time to microsecond resolution.
- **Pid namespace:** container-internal. The leftmost integer in
  each strace line is the *thread id (tid)*, not the process id
  (pid).
- **Role in attribution testing:** ground-truth oracle for what
  *really* happened in the container. Used to construct the
  reference provenance graph each merged experiment is scored
  against.

### L2 — extended AgentShield host eBPF

- **Vantage:** host-side, attaches to kernel tracepoints + uprobes
  via the Aya eBPF runtime in Rust. Sees every cgroup on the host.
- **Filter (tampering profile):** `openat`, `unlinkat`, `clone`,
  `clone3`, `execve` with full argv up to 16 entries × 256 bytes,
  `connect`, `sendto`, `recvfrom`. Plus the existing AgentShield
  streams: TLS plaintext payloads, JSON-RPC frames, DNS queries,
  legacy agent-activity records.
- **Format:** unified JSONL envelope, one event per line, fields
  `event, ts_ns, pid, tid, comm, cgroup_id, args, …`.
- **Pid namespace:** host. `pid` and `tid` are kernel-host values.
- **Role in attribution testing:** the production-grade host sensor
  whose graph-construction quality we're evaluating.

### L3 — standalone libbpf-C host sensor

- **Vantage:** host-side, separate codebase from L2 (no shared
  dependencies, intended as the open-source prototype that ships
  with the paper).
- **Filter:** identical event set to L2. Reads up to 256B path
  strings; emits clone3 distinctly from clone where L2 currently
  collapses them.
- **Format:** same unified JSONL envelope as L2.
- **Pid namespace:** host.
- **Role in attribution testing:** second host-side layer scored
  alongside L2. If the two produce the same numbers, the result
  is a property of the kernel signal, not an artifact of one
  sensor's implementation.

### How a session is captured

Each captured session is one run of one **(MCP, prompt, variant)**
triple. To unpack:

- **MCP** — one of 31 third-party Model Context Protocol servers in
  our corpus (filesystem, git, postgres, puppeteer, slack, etc.).
  The agent talks to one MCP per session.
- **prompt** — one of ~20 hand-curated user prompts per MCP that
  the agent will receive. Each is designed to trigger the MCP's
  tools without naming them, so the agent has to discover the right
  tool from the schema.
- **variant** — either *benign* (unmodified MCP source) or
  *malicious* (MCP source mutated by one hand-authored patch
  simulating a supply-chain compromise).

So one (MCP, prompt, variant) triple is "this MCP, this user
prompt, this benign-or-malicious source state." Capture loop per
triple:

```
1. Spin up a fresh Docker container with the MCP installed.
2. L2 + L3 host sensors are already running on the host.
3. Inside the container, run:
     strace -f -ttt -o <l1.log> claude -p "<the prompt>"
   This launches the Claude Code CLI, which reads the prompt,
   discovers the MCP tools, and dispatches tool calls. strace
   captures every syscall the container makes during the run.
4. Wait for `claude -p` to complete (or hit timeout).
5. Drain a brief post-exit window so eBPF ringbuffers flush.
6. Tear down the container.
7. Cut per-session slices from the global L2 / L3 logs by
   cgroup_id (the cgroup the container ran in is unique to the
   session).
```

Each session writes the following files to disk:

```
<session_dir>/
  ├── session.json     metadata: cgroup_id, t_start_unix_ns, mcp,
  │                    prompt, variant, tool_calls, etc.
  ├── stream.jsonl     full agent transcript from `claude -p`
  │                    (every tool_use, tool_result, text response)
  ├── l2.jsonl         L2 host-side eBPF events for this cgroup
  └── l3.jsonl         L3 host-side eBPF events for this cgroup
```

L1's strace log lives separately under a per-run directory and is
referenced from `session.json`.

### What this means for attribution testing

Three crucial properties of the source data:

1. **L1 ↔ host pid bridge is non-trivial.** L1 uses
   container-namespace pids (and emits *tid*, not pid, as its
   leftmost field); L2 and L3 use host-namespace pids. The same
   process has one number inside the container and a different one
   on the host. We bridge them on `execve` timestamps + argv
   basenames when needed.
2. **cgroup_id partitions sessions for free in the captures.** Each
   session ran in its own container, so each session has its own
   cgroup_id. This is a methodological choice that gives us clean
   ground truth — *not* a property AgentShield can rely on in the
   wild, where multiple sessions might share a host or a container.
   The merged-trace experiment deliberately strips this property.
3. **L2 and L3 are observationally equivalent.** Both are
   host-side, both emit the same envelope, both subscribe to the
   same syscall set. Across these experiments the two layers
   produce essentially identical numbers — confirming that what
   we're measuring is a property of the kernel signal, not of any
   one sensor implementation.

## The provenance graph we construct

For each merged host trace, we construct a directed acyclic graph
with four vertex types and three edge types. The graph is built
incrementally as the trace is consumed; attribution is then a
graph-reachability query on the constructed graph.

### Vertex types

| Type | Anchor event | Identity | Notes |
|---|---|---|---|
| **Session** | `execve` of `claude` with `-p` or `--print` | one per agent invocation | top of the per-session subgraph |
| **MCP** | `execve` of `mcp-server-*` (or wrapper `node\|python\|uvx <mcp script>`) | one per loaded MCP server, scoped to a session | child of session vertex |
| **ToolCall** | `sendto` of a JSON-RPC `tools/call` frame on the agent's stdio fd to an MCP | one per tool invocation, scoped to an MCP | child of MCP vertex; lifetime = request-to-response window |
| **Process** | first observed event with that pid | one per host pid | leaves attach to a process vertex |

Every kernel event in the trace is a leaf, with an edge up to its
emitting process vertex.

### Edge types

| Edge | Meaning | Source signal |
|---|---|---|
| `child_of` (Process → Process) | parent-process relationship | clone / clone3 caller-tid recorded at clone time, claimed by the next-seen new pid within 200ms; or execve in place |
| `member_of` (Process → MCP, Process → Session) | "this pid is in this entity's subtree" | derived: ancestor reachability through `child_of` from the entity's anchor pid |
| `during` (Event → ToolCall) | "this kernel event happened during this tool call" | derived: event's process is `member_of` the ToolCall's MCP, and ts is in the ToolCall's [open, close] window |

`member_of` and `during` are both *derived* edges — they fall out of
the underlying graph traversal at attribution time. We materialize
them as caches (`pid → mcp`, `pid → session`, `mcp_pid → active_tool_call`)
to keep the per-event prediction cost O(1).

### What attribution looks like as a graph query

For each kernel event in the trace:

- **Predicted session** = walk `child_of` edges up from
  `event.pid`; the first Session vertex reached is the answer
  (empty if none reachable).
- **Predicted MCP** = same walk; first MCP vertex reached.
- **Predicted tool_call** = if predicted MCP is M, look up M's
  active ToolCall vertex at `event.ts_ns`.

The dictionary lookups in our implementation (`pid_session.get(pid)`,
`pid_mcp.get(pid)`) are simply cached forms of these graph
traversals. Identical answers, O(1) per event instead of O(depth).

## Experiment construction — the merged-trace setup

To test "extract a session out of host noise," we synthesize a host
trace that contains multiple sessions running in what looks like a
single big eBPF capture.

The capture corpus has 567 sessions but they ran sequentially
during capture — no two sessions naturally overlap in time. So we
synthesize the multi-session host trace by merging captured slices.

### Merge procedure

```
def merge_sessions(sessions, layer):
  for each session s in sessions:
    ground_truth_graph = build_provenance_graph(s.l1, s.host_layer, s.stream_jsonl)
    for each event e in s.<layer>.jsonl:
      e.cgroup_id = SHARED_CGROUP   # strip cgroup-per-session shortcut
      label e with (src_session, src_mcp, src_tool_call) by
            graph reachability in ground_truth_graph
      append (e, labels) to merged

  sort merged by e.ts_ns               # interleave events by timestamp
  return merged
```

The merge:
- Concatenates each session's host events (L2 events, or L3 events,
  scored separately) from N sessions.
- **Rewrites every cgroup_id to a single shared value.** Without
  this, partitioning by cgroup_id would trivially recover
  sessions — the merge has to force the prediction mechanism to
  work without it.
- **Preserves each event's original ts_ns.** Sessions in the
  corpus are temporally separated by minutes/hours of original
  capture time, so sorting by ts naturally interleaves them while
  preserving each session's internal ordering.
- Attaches a per-event `src_*` label for scoring. **These labels
  are never read by the prediction code** — they exist only as the
  answer key.

### Ground-truth label construction (as graph queries)

For each event we compute three ground-truth labels per source
session, before merging. Each label is the answer to a reachability
query on the **source session's own** provenance graph
(constructed independently from that session's L1 and host trace):

- `src_session`: the source session id, but only for events whose
  process vertex is reachable from the session vertex. Pre-`claude`
  events (Docker runtime, container entrypoint shell) sit outside
  the session vertex's subgraph and get `src_session = ""`.
- `src_mcp`: the MCP name, but only for events whose process
  vertex is reachable from an MCP vertex. Agent-process events
  that aren't part of any MCP get `src_mcp = ""`.
- `src_tool_call`: the agent's tool-call id, but only for events
  whose process vertex is reachable from an MCP vertex AND whose
  ts is inside that MCP's tool-call window. Otherwise empty.

Because the ground truth is itself a graph query, it represents
"what an attribution mechanism *should* produce given perfect
kernel-side reasoning" — not an answer derived from privileged
metadata.

### What the merged trace looks like

```
event 0   ts=1779996959268304507  pid=708323  event=openat   src=sess_A:"":""
event 1   ts=1779996959268341600  pid=708323  event=clone    src=sess_A:"":""
...
event N   ts=1780000492359266448  pid=708340  event=sendto   src=sess_A:mcp_puppeteer:tool_call_47
event N+1 ts=1780002847219104812  pid=831955  event=execve   src=sess_B:"":""
event N+2 ts=1780002847219152033  pid=831955  event=execve   src=sess_B:mcp_postgres:""
...
```

The predictor sees only the kernel envelope (ts, pid, tid, event,
args, cgroup_id). The `src_*` columns exist on a wrapper struct
but the prediction function never reads them.

## Prediction mechanism — incremental graph construction

The prediction code does a single-pass walk of the merged stream
in `ts_ns` order. It builds the provenance graph **incrementally**,
one event at a time, and at each step looks up the predicted
attribution for the current event by graph reachability from its
process vertex.

### State (the in-memory graph)

```python
# Process vertices and the child_of edges between them, kept as a
# cached parent map for O(1) ancestor lookups
process_parent: dict[int, int]              # pid → parent_pid

# Session and MCP entity vertices, identified by their anchor pid;
# member_of edges are cached as direct lookups for O(1) read.
pid_session: dict[int, str]                 # pid → session vertex id
pid_mcp:     dict[int, str]                 # pid → mcp vertex id

# Pending clone-edge state (the new pid hasn't been observed yet)
last_clone_caller: tuple[int, int] | None   # (caller_pid, ts_ns)

# Tool-call vertices, one per (mcp_pid, request_id), with lifetime
# bookended by request and response sendtos
active_tool_call: dict[int, str]            # mcp_pid → currently-open tool_call vertex id
```

After the walk completes, every pid the trace ever saw has a
process vertex, and every Session/MCP/ToolCall vertex that was
opened has been recorded.

### Per-event rules — how the graph grows

**Adding a Session vertex.** When we see an `execve` whose
`argv[0]` basename is `claude` and whose `argv` contains `-p` or
`--print` (the per-session invocation marker), we instantiate a
new Session vertex anchored at the calling pid. The pid is bound
into `pid_session`.

**Adding an MCP vertex.** When we see an `execve` whose `argv[0]`
basename matches the pattern `mcp[-_]server[-_]…`, or a wrapper
invocation `node|python|uvx <script>` where the script's basename
contains both `mcp` and `server` (or starts with `mcp-`), AND the
calling pid is already bound to a Session, we instantiate an MCP
vertex as a child of that Session, anchored at the calling pid.
The pid is bound into `pid_mcp`.

**Adding a Process vertex and a `child_of` edge.** When a
clone/clone3 fires, we record `(caller_pid, ts)`. The next event
from a previously-unseen pid within 200ms creates a new Process
vertex with a `child_of` edge to the recorded caller. The new pid
inherits its parent's session and MCP through the cached
`pid_session` / `pid_mcp` maps.

**Adding a ToolCall vertex.** When a `sendto` from a session-bound
pid carries a buffer that decodes to JSON containing
`"method":"tools/call"`, we parse the tool name and the agent's
`tool_use_id` from the payload, instantiate a ToolCall vertex as a
child of the most recently opened MCP in the calling pid's
session, and mark that MCP pid as having an active tool call.

**Closing a ToolCall vertex.** When the same MCP pid emits a
`sendto` whose buffer contains a JSON-RPC response frame
(`"jsonrpc"` + `"id"`), we close the active tool call on that MCP
pid (its `during` window terminates).

### The 200ms inheritance window

The 200ms threshold is chosen to be much larger than realistic
clone-to-first-event latency (~ms on a healthy host) and much
smaller than the inter-session gap (minutes between captured
sessions in the corpus). It is a hyperparameter, not a learned
value.

### Per-event attribution = three graph reachability queries

For each event in the merged stream:

- `predicted_session = pid_session.get(event.pid, "")`
  (the cached answer to "ancestor-reachable Session vertex")
- `predicted_mcp = pid_mcp.get(event.pid, "")`
  (the cached answer to "ancestor-reachable MCP vertex")
- `predicted_tool_call = active_tool_call.get(<mcp_pid for event.pid>, "")`
  (the cached answer to "open ToolCall vertex on the MCP this event
  belongs to, at this ts")

Empty string at any level means "no entity vertex reachable" —
which is a real prediction (it has a precision/recall meaning),
not a sentinel.

## Scoring

For each level (session / MCP / tool_call) and each layer (L2 / L3):

### Greedy 1-to-1 class mapping

The predicted vertex ids (`sess_0`, `mcp_3_mcp-server-puppeteer`,
`toolu_bdrk_01abc...`) don't match the ground-truth ids
(`18361994762148a09454d995b5979834`,
`anthropic_ref_servers/puppeteer`, the agent's tool_use_id) by
string. Standard remedy: build a contingency table and find the
predicted-to-true assignment that maximizes co-occurrence count.
We use a greedy 1-to-1 match; for the class cardinalities here
(3–10 vertices per trial) this is optimal.

### Per-event precision / recall / F1

With the class mapping fixed:

- **TP**: event has non-empty true label *and* its predicted
  vertex maps to the same true vertex.
- **FP**: event has non-empty predicted vertex that maps to
  something other than its true vertex (or the true label is
  empty).
- **FN**: event has non-empty true label but the predicted vertex
  is empty or maps elsewhere.

Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 =
harmonic mean of the two.

Events with empty true *and* empty predicted are excluded —
they're "both sides correctly say not relevant" and would inflate
scores trivially.

### Adjusted Rand Index (ARI)

ARI is a clustering-comparison metric. It asks: *of all pairs of
events, do the two partitions agree on whether each pair is in the
same group or in different groups?* The raw Rand Index is just
`agreements / total pairs`; ARI subtracts the expected agreement
under random labeling so chance scores 0.

| ARI value | Meaning |
|---|---|
| 1.0 | partitions are identical |
| 0.0 | partitions agree no better than chance |
| < 0 | partitions agree worse than chance (rare) |

ARI doesn't require a class-id mapping (it cares only about which
events are *grouped together*, not what the groups are called),
so we report it alongside F1 as a sanity check that doesn't depend
on the greedy mapping above.

## Trial design

```
n_trials      = 10
n_sessions    = 3                      # sessions merged per trial
sampling      = distinct MCPs only     # forces multi-MCP merge
seed          = 42                     # reproducible
layers        = [L2, L3]               # scored independently
levels        = [session, mcp, tool_call]
```

Pool: 200 captured sessions. From each trial's pool, we randomly
sample 3 MCPs without replacement, then randomly pick one captured
session per chosen MCP. This guarantees multi-MCP merges (the
interesting test case for MCP attribution disambiguation).

10 trials × 2 layers × 3 levels = 60 score cells; each cell is
the mean of one F1, one Precision, one Recall, one ARI across the
10 trials.

## Results (n=10 trials × 3 sessions, 2 layers)

| Layer | Level | F1 (mean) | F1 (range) | Precision | Recall | ARI |
|---|---|---:|---|---:|---:|---:|
| L2 | session   | 0.923 | 0.915 – 0.930 | 0.999 | 0.857 | 0.765 |
| L2 | **mcp**   | **0.997** | 0.996 – 0.997 | **1.000** | 0.993 | 0.996 |
| L2 | tool_call | 0.553 | 0.000 – 0.857 | 0.786 | 0.437 | 0.293 |
| L3 | session   | 0.924 | 0.916 – 0.931 | 0.999 | 0.859 | 0.766 |
| L3 | **mcp**   | **0.997** | 0.996 – 0.997 | **1.000** | 0.993 | 0.996 |
| L3 | tool_call | 0.564 | 0.000 – 1.000 | 0.792 | 0.448 | 0.317 |

### Reading

- **Session attribution.** Near-perfect precision (when we
  predict an event is reachable from session-vertex X, it
  actually is). Recall is bounded by the pre-`claude -p` window
  of each session — Docker runtime, container entrypoint, and the
  preliminary `claude mcp add` registration call all fire before
  the Session vertex's anchor execve, so they have no Session
  vertex in their ancestor chain. In a deployment without that
  runtime preamble, recall would be higher.
- **MCP attribution.** Essentially solved at F1 = 0.997. The
  MCP-vertex anchor execve is unambiguous, and ancestor
  reachability is deterministic. This is the strongest result.
- **Tool-call attribution.** Bimodal — best trials reach 1.0,
  worst reach 0.0. Failure modes for the ToolCall vertex anchor:
  `sendto` buffer truncation (long argument arrays clipped by the
  256B kernel buffer), JSON-RPC frame fragmentation across
  multiple sendtos, MCPs that use TLS-wrapped transport for tool
  calls. When the JSON-RPC frame *is* visible in `sendto`,
  attribution is ~80% precise. The recall gap is "couldn't
  instantiate enough ToolCall vertices," not "attached to the
  wrong ones."

### What this answers

| Question | Answer |
|---|---|
| Identify session events in an arbitrary host trace? | Yes, F1 = 0.92 with near-perfect precision |
| Identify per-MCP partitioning? | Yes, F1 = 0.997 |
| Identify per-tool-call partitioning, sequential? | Partially, F1 = 0.56 — bounded by sendto buffer fidelity |
| Identify per-tool-call partitioning, concurrent on same MCP? | No — this is the **execution-unit attribution problem** (BEEP, ProTracer, MPI, OmegaLog). The kernel doesn't see the JSON-RPC request id once it crosses into the MCP's worker threads. |
| Are the results an artifact of a specific sensor? | No — L2 and L3 produce identical numbers within noise |

## Method caveats

1. **Tool-call ground truth comes from agent-transcript windows**,
   which are loose (cover the gap between consecutive tool calls,
   not just the active call). This depresses the recall
   denominator — events that ground-truth as belonging to call X
   may actually be in the inter-call gap. Tightening this
   requires per-request JSON-RPC timestamps from the host eBPF
   emitter, which the current capture does not yet populate.
2. **Sessions in the corpus are sequential, not concurrent.** The
   merged stream sorts on each event's original ts, which
   produces sequential ordering of interleaved sessions rather
   than true temporal overlap. A "time-shifted" merge —
   re-stamping ts to force overlap — would stress the prediction
   mechanism more aggressively and is a follow-up.
3. **Distinct-MCP sampling.** The trials enforce one of each MCP
   per merge. Stress conditions to consider: repeated MCPs (two
   instances of the same MCP) — does the matcher disambiguate by
   pid? 5+ sessions per merge — does Session-vertex tracking
   degrade?
4. **Pre-claude noise (~14% of session events) is currently
   scored against the predictor**, which is the conservative
   choice. A "fair" version would exclude pre-`claude -p` events
   from recall; we report the conservative number.

## Possible extensions

The graph we construct today is **minimal** — only Session, MCP,
ToolCall, and Process vertices, with `child_of`, `member_of`, and
`during` edges. A short list of natural extensions, in order of
how much they add to the analysis surface:

### 1. Add file and socket entity vertices

The kernel events we already capture (`openat`, `connect`,
`sendto`, `recvfrom`, `unlinkat`, `read`, `write`) describe
interactions with **files** and **sockets** — but we treat them
as flat events on a process vertex, never materializing the file
or socket itself as a vertex. CamFlow-style provenance graphs
materialize:

- A **File** vertex per opened path, with `read` / `write` /
  `unlink` edges from the process vertex.
- A **Socket** vertex per connected endpoint, with `connect` /
  `sendto` / `recvfrom` edges.

Adding these vertices unlocks **data-flow questions** that the
current minimal graph cannot express:

| Question | Today | With file/socket vertices |
|---|---|---|
| "Did MCP X read `~/.aws/credentials`?" | Scan all events with mcp=X and event=openat; aggregate. | Graph query: edge from any process in X's subtree to the file vertex. |
| "Which tool calls touched the network?" | Group connect/sendto events by tool_call. | Graph query: ToolCall vertices with outgoing path to a Socket vertex. |
| "Did MCP X's behavior depend causally on file F's contents?" | **Cannot express** — needs read→use causality. | Direct: forward-trace from F. |
| "Is the observed sub-graph for tool-call T anomalous?" | Hard — engineer per-call feature vectors manually. | Direct: feed into a PIDS detector (Kairos, FLASH, PROGRAPHER). |

Detection of the canonical credential-exfiltration scenario
(MCP reads ~/.aws/credentials, later sends to a side-channel
network destination) becomes a single forward-trace query
instead of a manual cross-event correlation.

### 2. Emit `mcp_jsonrpc` events from the host sensor

ToolCall-vertex creation today depends on parsing
`sendto.buf_b64` for JSON-RPC frames. Buffer truncation, frame
fragmentation, and TLS-wrapped transport all reduce recall. The
v1 envelope schema reserves an `mcp_jsonrpc` event type for
framed JSON-RPC parsing inside the sensor (which can reassemble
across multiple syscalls, decode TLS plaintext via the existing
uprobes, and emit one event per request/response with no
buffer-size limits). Emitting this event type from L2 would:

- Raise tool-call recall toward 1.0.
- Give us per-request timestamps for tightening tool-call ground
  truth.
- Make the ToolCall vertex anchor independent of `sendto` buffer
  fidelity.

### 3. Materialize the graph to disk in a standard schema

The graph is currently held in memory as a set of Python dicts.
Emitting it to disk in a standard provenance-graph format
(W3C PROV-JSON, SPADE JSON, or DARPA CDM-Avro) would:

- Let us evaluate against the PIDS detection toolchain
  (PIDSMaker, Kairos, FLASH) without a translation layer.
- Let us publish the captured corpus as a public dataset in a
  format the field already consumes — useful both as a benchmark
  artifact and as forensic-record format for long retention.
- Make storage-aware compression schemes from the literature
  (SEAL) directly applicable for any production deployment.

### 4. Track six-namespace attribution per process vertex

CamFlow records all six Linux namespace inodes (utsns, ipcns,
mntns, pidns, netns, cgroupns) on every vertex, not just
cgroupns. Adding this to the L2 emitter is cheap (kernel
exposes them all) and gives the graph robustness against any
single-namespace-stripping adversary. Particularly relevant if
we ever evaluate against attackers who deliberately reuse
cgroups across sessions.

### 5. Time-shifted merge variant

The current merge interleaves sessions in original-capture-time
order; sessions never *truly* overlap. A "time-shifted" merge
that re-stamps ts to force genuine overlap would test the
clone-inheritance window and ToolCall open/close ordering under
real concurrency stress. This is an experiment-side extension,
not a sensor-side one.

### 6. Native concurrent-session capture

A small fresh capture run with 4–8 simultaneous agent processes
on the same host would validate that the synthetic-merge
results hold under real overlap — and would produce data with
naturally-overlapping ToolCall windows that today must be
synthesized.

---

The minimal provenance graph framing answers the original
attribution question with the numbers reported in §Results. The
extensions above each unlock a specific additional capability
(data-flow detection, PIDS compatibility, public-corpus
release, robustness, harder stress conditions) without changing
the underlying mechanism.
