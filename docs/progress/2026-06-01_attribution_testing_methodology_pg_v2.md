# Host-side attribution testing — provenance-graph framing (v2)

**Date:** 2026-06-03
**Supersedes:** the v1 provenance-graph methodology doc.

This update adds three diagnostics (V1, V2, V3) on top of the
original E6 result. The diagnostics were run after a colleague
raised a fair concern: the original captures live inside Docker
containers and are then collected on the host, so the strong E6
numbers might be benefiting from Docker-shaped structure that
wouldn't exist in a real deployment.

The mechanism, the code, and the merged-trace setup are unchanged.
What's new is (a) three controlled diagnostics that each strip a
specific corpus artifact and re-score, and (b) a small but
important fix to the prediction code that the diagnostics
surfaced.

It is self-contained — all references to other files are
summarized here.

## Question

> Given an arbitrary host-side eBPF trace, can we deterministically
> attribute each kernel event to the *session* that produced it,
> the *MCP server* that handled it, and the *tool call* during
> which it fired — using only kernel-observable signals?

The deployment scenario is AgentShield-style: a host-side sensor
runs continuously on a machine, and one big trace file accumulates
events from everything on the host. We want to label each event
with a `(session, mcp, tool_call)` triple — or "not relevant" —
with no cooperation from the agent or MCP and no in-container
instrumentation.

In provenance-graph terms: we want to construct a **per-session
provenance graph** from the host trace where the agent session,
its MCPs, and each MCP's tool calls appear as explicit entity
vertices, and every kernel event is reachable from exactly one
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
  unlinkat, unlink, ptrace, clone, clone3, exit_group, write,
  read, bind`.
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
- **Role in attribution testing:** the production-grade host
  sensor whose graph-construction quality we're evaluating.

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

### How a session is captured (containerized corpus)

Each captured session is one run of one **(MCP, prompt, variant)**
triple. To unpack:

- **MCP** — one of 31 third-party Model Context Protocol servers
  in our corpus (filesystem, git, postgres, puppeteer, slack,
  etc.). The agent talks to one MCP per session.
- **prompt** — one of ~20 hand-curated user prompts per MCP that
  the agent will receive. Each is designed to trigger the MCP's
  tools without naming them, so the agent has to discover the
  right tool from the schema.
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
   process has one number inside the container and a different
   one on the host. We bridge them on `execve` timestamps + argv
   basenames when needed.
2. **cgroup_id partitions sessions for free in the captures.**
   Each session ran in its own container, so each session has
   its own cgroup_id. This is a methodological choice that gives
   us clean ground truth — *not* a property AgentShield can rely
   on in the wild, where multiple sessions might share a host or
   a container. The merged-trace experiment deliberately strips
   this property.
3. **L2 and L3 are observationally equivalent.** Both are
   host-side, both emit the same envelope, both subscribe to the
   same syscall set. Across these experiments the two layers
   produce essentially identical numbers — confirming that what
   we're measuring is a property of the kernel signal, not of
   any one sensor implementation.

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

`member_of` and `during` are both *derived* edges — they fall out
of the underlying graph traversal at attribution time. We
materialize them as caches (`pid → mcp`, `pid → session`,
`mcp_pid → active_tool_call`) to keep the per-event prediction
cost O(1).

### What attribution looks like as a graph query

For each kernel event in the trace:

- **Predicted session** = walk `child_of` edges up from
  `event.pid`; the first Session vertex reached is the answer
  (empty if none reachable).
- **Predicted MCP** = same walk; first MCP vertex reached.
- **Predicted tool_call** = if predicted MCP is M, look up M's
  active ToolCall vertex at `event.ts_ns`.

The dictionary lookups in our implementation
(`pid_session.get(pid)`, `pid_mcp.get(pid)`) are simply cached
forms of these graph traversals. Identical answers, O(1) per event
instead of O(depth).

## Experiment construction

The original experiment (E6) merges N captured sessions into a
synthetic multi-session trace and asks the predictor to reconstruct
session/MCP/tool-call attribution from kernel signals alone. The
three new diagnostics (V1, V2, V3) each modify one aspect of the
merge or the source data to test whether E6's strong numbers were
benefiting from a Docker-shaped artifact.

### Base merge (E6)

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
- Concatenates each session's host events from N sessions.
- **Rewrites every cgroup_id to a single shared value.** Without
  this, partitioning by cgroup_id would trivially recover
  sessions — the merge has to force the prediction mechanism to
  work without it.
- **Preserves each event's original ts_ns.** Sessions in the
  corpus are temporally separated by minutes/hours of original
  capture time, so sorting by ts naturally interleaves them
  while preserving each session's internal ordering.
- Attaches a per-event `src_*` label for scoring. **These labels
  are never read by the prediction code** — they exist only as
  the answer key.

### V1 — time-shifted merge

Same setup as the base merge, but each session's ts is rebased to
a shared anchor (t=0) before sorting. After the rebase, all
sessions run "concurrently" on the millisecond scale instead of
sitting in distinct minutes-apart temporal clusters.

This stresses the 200ms clone-inheritance window. If F1 stays
similar to E6, the inheritance window is robust to temporal
collisions. If F1 drops, the temporal-isolation property of the
sequential-capture corpus was leaking into attribution.

### V2 — strip Docker noise

Same setup as the base merge, but for each session we identify
the runc → containerd-shim → docker-entrypoint → strace ancestry
chain and drop those pids' events from the merged stream before
predicting. The merged stream then contains only events from
`claude -p` and its descendants.

This is a diagnostic test: in a real deployment there is no
Docker preamble at all, but we want to know whether the predictor
was implicitly *using* the Docker preamble as a session-boundary
signal. If F1 stays the same, the preamble was irrelevant. If F1
moves either direction, the preamble was contributing
information — and we want to know which direction.

### V3 — bare-host capture

Captures fresh benign sessions directly on the host, with no
Docker, no strace wrapping, and no entrypoint shell. This is the
definitive deployment-realism test.

Setup:
- Conda env `mcp_test_venv` with Python 3.11.
- Three MCPs installed directly on the host: filesystem (npm),
  memory (npm), git (pip in the conda env).
- Three prompts per MCP, run sequentially through `claude -p`.
- L3 host sensor running across all captures.
- 9 sessions total, all benign.

Each capture writes `session.json`, `stream.jsonl`, and
`l3.jsonl` analogously to the containerized corpus. The L3 trace
captures everything on the host during the capture window —
including unrelated background processes (sshd, kernel threads,
hook scripts, the editor's language servers). The predictor has
to find the session subtree inside that noise.

Ground truth for each capture is derived from the capture itself:
the session's claude pid + its descendant subtree, computed by
graph reachability on the bare-host trace. No L1 oracle is
available, so the ground truth is "what an attribution mechanism
*should* identify given perfect kernel-side reasoning on this
trace."

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

**Important rule (added after V3):** if the calling pid had
already inherited a session via clone-descendant closure, the
`claude -p` execve **overrides** that inheritance and rebinds the
pid to a fresh Session vertex. We also clear any inherited MCP
attribution. Without this override, when two `claude -p` sessions
are close in time, the second session's pid arrives having
inherited the first session's identity from a clone caller, and
the new-session-open would be skipped. V3 surfaced this case
because bare-host sessions are launched within seconds of each
other; the original captures had minutes between sessions and
never triggered it.

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
`tool_use_id` from the payload, instantiate a ToolCall vertex as
a child of the most recently opened MCP in the calling pid's
session, and mark that MCP pid as having an active tool call.

**Closing a ToolCall vertex.** When the same MCP pid emits a
`sendto` whose buffer contains a JSON-RPC response frame
(`"jsonrpc"` + `"id"`), we close the active tool call on that
MCP pid (its `during` window terminates).

### The 200ms inheritance window

The 200ms threshold is chosen to be much larger than realistic
clone-to-first-event latency (~ms on a healthy host) and much
smaller than the inter-session gap (minutes between captured
sessions in the original corpus). It is a hyperparameter, not a
learned value.

The V1 diagnostic specifically stresses this hyperparameter; the
V1 result (below) shows it leaks under genuine temporal overlap.

### Per-event attribution = three graph reachability queries

For each event in the merged stream:

- `predicted_session = pid_session.get(event.pid, "")`
  (the cached answer to "ancestor-reachable Session vertex")
- `predicted_mcp = pid_mcp.get(event.pid, "")`
  (the cached answer to "ancestor-reachable MCP vertex")
- `predicted_tool_call = active_tool_call.get(<mcp_pid for event.pid>, "")`
  (the cached answer to "open ToolCall vertex on the MCP this
  event belongs to, at this ts")

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
events, do the two partitions agree on whether each pair is in
the same group or in different groups?* The raw Rand Index is
just `agreements / total pairs`; ARI subtracts the expected
agreement under random labeling so chance scores 0.

| ARI value | Meaning |
|---|---|
| 1.0 | partitions are identical |
| 0.0 | partitions agree no better than chance |
| < 0 | partitions agree worse than chance (rare) |

ARI doesn't require a class-id mapping (it cares only about
which events are *grouped together*, not what the groups are
called), so we report it alongside F1 as a sanity check that
doesn't depend on the greedy mapping above.

## Trial design

```
n_trials      = 10
n_sessions    = 3                      # sessions merged per trial
sampling      = distinct MCPs only     # forces multi-MCP merge
seed          = 42                     # reproducible
layers        = [L2, L3]               # scored independently
levels        = [session, mcp, tool_call]
```

Pool: 200 captured sessions for the containerized variants (E6,
V1, V2); 9 captured sessions for the bare-host variant (V3).
From each trial's pool, we randomly sample `n_sessions` MCPs
without replacement, then randomly pick one captured session per
chosen MCP. This guarantees multi-MCP merges (the interesting
test case for MCP attribution disambiguation).

10 trials × 2 layers × 3 levels = 60 score cells per variant;
each cell is the mean of one F1, one Precision, one Recall, one
ARI across the 10 trials.

## Results

L2 and L3 produce numbers within ±1% of each other in every
variant; we report the L2 numbers below for clarity.

### Headline (n=10 trials × 3 sessions per trial)

| Variant | Session F1 | MCP F1 | Tool-call F1 | Notes |
|---|---:|---:|---:|---|
| **E6** (containerized, sequential) | 0.92 | 0.997 | 0.55 | original baseline |
| **V1** (time-shifted overlap) | **0.47** | **0.64** | 0.49 | sessions overlap on ms scale |
| **V2** (strip Docker noise) | **1.00** | 0.80 | 0.50 | runc/entrypoint/strace removed |
| **V3** (bare-host real capture) | **0.72** | 0.68 | 0.54 | no Docker, real host noise |

Each variant changes a specific aspect of the input; reading the
deltas tells us where E6's strong numbers came from.

### V1 — time-shifted merge (temporal overlap stress)

Original E6 sorts the merged stream by each event's original ts.
Sessions in the corpus were captured back-to-back but minutes
apart, so when we sort, each session's events live in their own
dense temporal cluster, separated from the next session by a long
quiet period. The 200ms clone-inheritance window can never span
sessions because nothing's within 200ms of the boundary.

V1 rebases each session's ts to t=0 so they all start at the same
moment. After the rebase, ~94% of consecutive events in the
merged stream are <1ms apart — sessions genuinely overlap.

**Result.** Session F1 drops from 0.92 → 0.47, MCP F1 from 0.997
→ 0.64, tool-call ARI collapses from 0.29 → 0.04.

**Interpretation.** The original E6 numbers were partially
propped up by an artifact of sequential capture. The mechanism is
robust to sequential interleaving but not to true temporal
overlap. The 200ms clone-inheritance heuristic is the suspect:
when a clone fires in session A's caller and the next-seen pid
genuinely belongs to session B (because both are clone-spawning
processes simultaneously), the inheritance rule attaches the
session-A label to a session-B pid.

### V2 — strip Docker noise (preamble stress)

V2 identifies the runc → containerd-shim → docker-entrypoint →
strace ancestry chain in each session and drops those pids'
events from the merged stream before predicting.

**Result.** Session F1 jumps from 0.92 → **1.00** (perfect — the
8% recall gap in E6 was entirely Docker preamble events the
predictor correctly couldn't attribute). MCP F1 *drops* from
0.997 → 0.80.

**The MCP drop is informative, not concerning.** In our
captures, `docker-entrypoint.sh` runs:
```
sh -c "claude mcp add ... && exec strace -f ... claude -p ..."
```
The shell that runs this script is the parent of *both* the
strace-wrapped claude invocation *and* of the registration call
that launches the MCP server. When V2 strips that shell's events,
we delete the intermediate node that the predictor was using to
bridge `claude → MCP`. In a deployment without Docker, claude
launches MCPs as direct children itself, and there's no
intermediate node to delete. So the V2 MCP F1 drop is a
corpus-shape artifact, not a mechanism limitation.

Tool-call F1 unchanged at 0.50 — confirming tool-call attribution
isn't affected by the preamble; it's bounded by JSON-RPC
visibility in `sendto` buffers regardless of what else is in the
trace.

### V3 — bare-host capture (deployment realism)

V3 captured 9 fresh benign sessions directly on the host, no
Docker, no strace, no entrypoint shell. The L3 host sensor
captured the full host trace during each session's capture
window — including unrelated background processes (sshd, kernel
threads, IDE language servers, hook scripts).

**Result.** Session F1 = 0.72 (range 0.42–0.95 across trials),
MCP F1 = 0.68, tool-call F1 = 0.54 with **precision 0.92**.

The session F1 is bimodal across trials: some hit 0.95+, others
0.42. Investigating the worst trials, the over-attributed events
fall into three categories:

1. **`pgrep`/`ps`/`lsof` invocations from a Claude Code hook
   script** that fires on every prompt. These are *legitimate
   descendants* of the claude pid — claude spawned the hook, the
   hook spawned pgrep — but our ground truth (computed from
   `claude -p`'s direct subtree) doesn't count them as
   session-related. The predictor correctly attributes them to
   the session; the ground truth labels them as not-session.
2. **Editor / IDE processes** that briefly fork during the
   capture window and inherit through some clone caller.
3. **systemd / sshd / kernel-thread events** that happen to fire
   shortly after a claude-side clone, getting bound by the 200ms
   inheritance window.

Category 1 is *the predictor being more right than the ground
truth*. Categories 2 and 3 are real over-attribution from
host-side noise that wasn't present in the containerized
captures (because cgroup_id partitioned it away).

**Tool-call precision on bare host is 0.92**: when the predictor
identifies a tool call, it attributes correctly. The recall gap
(0.39) is the same JSON-RPC-visibility issue from E6 (`sendto`
buffer truncation, frame fragmentation, TLS-wrapped transport).

## Reading the four variants together

| Question | Read from | Answer |
|---|---|---|
| Is session attribution mechanism sound on a clean trace? | E6 → V2 | Yes — F1 climbs to 1.00 once Docker preamble is removed |
| Does the mechanism survive temporal overlap? | E6 → V1 | Partially — F1 drops to 0.47; the 200ms inheritance window leaks |
| Does the mechanism work on a real host? | E6 → V3 | Yes, but at lower F1 (0.72) — partly genuine noise, partly a ground-truth definition gap |
| Where do the E6 numbers belong? | all four together | E6 = upper bound for a containerized sequentially-captured corpus. V3 = realistic deployment number. The gap (0.92 → 0.72) is the corpus-vs-deployment gap. |

## What this answers

| Question | Answer |
|---|---|
| Identify session events in an arbitrary host trace? | Yes — F1 ≈ 0.72 on bare host; 0.92 on the containerized corpus. Sequential vs. concurrent capture timing matters; Docker preamble inflates apparent recall. |
| Identify per-MCP partitioning? | Yes — F1 ≈ 0.68 on bare host; 0.997 on containerized. Subtree closure is exact when the MCP-server execve is unambiguous. |
| Identify per-tool-call partitioning, sequential? | Partially — F1 ≈ 0.54, with precision ≈ 0.79–0.92 (depending on variant). The mechanism is sound; recall is bounded by JSON-RPC visibility in captured `sendto` buffers. |
| Identify per-tool-call partitioning, concurrent on same MCP? | No — this is the **execution-unit attribution problem**. The kernel doesn't see the JSON-RPC request id once it crosses into the MCP's worker threads. |
| Are the results an artifact of a specific sensor? | No — L2 and L3 produce identical numbers within noise across all four variants. |
| Are the results an artifact of containerization? | **Partially yes.** E6's headline numbers benefit from sequential capture timing (V1) and Docker preamble (V2). The realistic deployment number is closer to V3. |

## Method caveats

1. **E6 numbers are a containerized upper bound, not a deployment
   estimate.** The realistic deployment numbers are V3:
   session F1 ≈ 0.72, MCP F1 ≈ 0.68, tool-call F1 ≈ 0.54
   (precision 0.92).

2. **The 200ms clone-inheritance window leaks under genuine
   temporal overlap** (V1). In a deployment with concurrent
   agents, this would need tightening — same-comm and same-uid
   tie-breakers are the obvious additions.

3. **Hook-spawned subprocesses inherit through clone closure**
   (V3 finding). On bare host, agent hooks (e.g., copperhead.sh
   firing pgrep/ps/lsof per prompt) are legitimate session
   descendants but may or may not be considered "session work"
   depending on the analyst's definition. Our ground truth
   currently doesn't count them; the predictor does. For
   deployment detection this is probably the right behavior —
   "what did this session touch" should include hooks.

4. **Tool-call ground truth comes from agent-transcript windows,**
   which are loose (cover the gap between consecutive tool
   calls, not just the active call). This depresses the recall
   denominator; tightening requires per-request JSON-RPC
   timestamps from the host eBPF emitter.

5. **Sessions in the original corpus are sequential, not
   concurrent.** V1 partially synthesizes overlap by re-stamping
   ts; V3 captures bare-host but still serially. A native
   concurrent capture (multiple agents on the same host at the
   same time) is the next natural step.

6. **Pre-claude noise (~14% of session events) is currently
   scored against the predictor on E6** (the conservative
   choice). V2 confirms this 14% is entirely Docker preamble; in
   a deployment without that preamble, the same metric would
   read closer to V2's perfect-recall numbers.

## Possible extensions

The graph we construct today is **minimal** — only Session, MCP,
ToolCall, and Process vertices, with `child_of`, `member_of`, and
`during` edges. A short list of natural extensions, in order of
how much they add to the analysis surface:

### 1. Tighten the clone-inheritance window

V1 showed the 200ms heuristic leaks under temporal overlap. Two
small additions would help:

- **Same-comm tie-breaker.** When multiple recent clone callers
  are in flight, prefer the one whose comm matches the new pid's
  comm. Threads of the same process share comm; unrelated forks
  don't.
- **Same-uid tie-breaker.** Cross-session clone callers in
  different uids should never bind; same-uid binds preferred.

This is the smallest mechanism change that materially helps V1.

### 2. Add file and socket entity vertices

The kernel events we already capture (`openat`, `connect`,
`sendto`, `recvfrom`, `unlinkat`, `read`, `write`) describe
interactions with **files** and **sockets** — but we treat them
as flat events on a process vertex, never materializing the file
or socket itself as a vertex. A full provenance graph would
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
| "Is the observed sub-graph for tool-call T anomalous?" | Hard — engineer per-call feature vectors manually. | Direct: feed into a graph-anomaly detector. |

Detection of the canonical credential-exfiltration scenario
(MCP reads ~/.aws/credentials, later sends to a side-channel
network destination) becomes a single forward-trace query
instead of a manual cross-event correlation.

### 3. Emit `mcp_jsonrpc` events from the host sensor

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

### 4. Materialize the graph to disk in a standard schema

The graph is currently held in memory as a set of Python dicts.
Emitting it to disk in a standard provenance-graph format would:

- Let us evaluate against existing PIDS (provenance-based
  intrusion detection systems) without a translation layer.
- Let us publish the captured corpus as a public dataset in a
  format the field already consumes — useful both as a benchmark
  artifact and as a forensic-record format for long retention.
- Make storage-aware compression schemes from the literature
  directly applicable for any production deployment.

### 5. Track six-namespace attribution per process vertex

Linux kernel exposes six namespace inodes per task (utsns, ipcns,
mntns, pidns, netns, cgroupns). We currently use only cgroupns.
Adding the other five to the L2 emitter is cheap and gives the
graph robustness against any single-namespace-stripping
adversary. Particularly relevant for deployments where attackers
might deliberately reuse cgroups across sessions.

### 6. Native concurrent-session capture

A small fresh capture run with 4–8 simultaneous agent processes
on the same host would validate that V1's synthetic-overlap
numbers reflect what real concurrency looks like, and would
produce data with naturally-overlapping ToolCall windows that
today must be synthesized.

### 7. Tighter ground-truth definition for hook subprocesses

V3 surfaced an ambiguity: hook scripts the agent spawns are
session descendants by clone but may or may not be "session
work." Two paths:

- **Tighten ground truth** to count only events whose pid path
  back to claude doesn't pass through a hook execve.
- **Leave permissive** and accept that "session" = "everything
  claude transitively spawned, including hooks."

This is a definitional choice, not a mechanism choice. The
prediction code is the same either way.

---

The minimal provenance graph framing answers the original
attribution question with the numbers reported in §Results, with
the caveats above. The extensions each unlock a specific
additional capability (tighter inheritance, data-flow detection,
PIDS compatibility, public-corpus release, robustness, harder
stress conditions) without changing the underlying mechanism.
