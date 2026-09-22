# Host-side attribution testing — methodology and results

**Date:** 2026-06-01

This doc is the formal writeup of the attribution-testing pipeline:
how the source data is collected, how it's transformed for the
experiment, what the prediction mechanism does, and what the results
say. It is self-contained — all references to other files are
summarized here.

## Question

> Given an arbitrary host-side eBPF trace, can we deterministically
> attribute each event to the *session* that produced it, the *MCP
> server* that handled it, and the *tool call* during which it
> fired — using only kernel-observable signals?

The deployment scenario is AgentShield-style: a host-side sensor runs
continuously on a machine, and one big trace file accumulates events
from everything on the host. We want to color each event with
`(session, mcp, tool_call)` or "not relevant," with no cooperation
from the agent or MCP and no in-container instrumentation.

## Source data — three sensor layers

Every captured session writes traces from three concurrent sensor
stacks running against the same workload. The three layers exist for
different purposes; this section summarizes what each one is.

### L1 — strace inside the container (oracle ground truth)

- **Vantage:** ptrace-based, runs as PID 1's child *inside* the session
  container. Sees every syscall every process in the container makes.
- **Filter:** `execve, openat, open, connect, sendto, recvfrom,
  unlinkat, unlink, ptrace, clone, clone3, exit_group, write, read,
  bind`.
- **Format:** strace text output, one line per syscall, timestamped
  with wall-clock time to microsecond resolution.
- **Pid namespace:** container-internal. The leftmost integer in each
  strace line is the *thread id (tid)*, not the process id (pid).
- **Role in attribution testing:** ground-truth oracle for what
  *really* happened in the container. Used in the in-container
  experiments for measuring host-side recall, and in the merged
  experiment to construct ground-truth subprocess subtrees.

### L2 — extended AgentShield host eBPF

- **Vantage:** host-side, attaches to kernel tracepoints + uprobes via
  the Aya eBPF runtime in Rust. Sees every cgroup on the host.
- **Filter (tampering profile):** `openat`, `unlinkat`, `clone`,
  `clone3`, `execve` with full argv up to 16 entries × 256 bytes,
  `connect`, `sendto`, `recvfrom`. Plus the existing AgentShield
  streams: TLS plaintext payloads, JSON-RPC frames, DNS queries,
  legacy agent-activity records.
- **Format:** unified JSONL envelope, one event per line, fields
  `event, ts_ns, pid, tid, comm, cgroup_id, args, …`.
- **Pid namespace:** host. `pid` and `tid` are kernel-host values.
- **Role in attribution testing:** the production-grade host sensor
  whose attribution we're evaluating.

### L3 — standalone libbpf-C host sensor

- **Vantage:** host-side, separate codebase from L2 (no shared
  dependencies, intended as the open-source prototype that ships with
  the paper).
- **Filter:** identical event set to L2. Reads up to 256B path
  strings; emits clone3 distinctly from clone where L2 currently
  collapses them.
- **Format:** same unified JSONL envelope as L2.
- **Pid namespace:** host.
- **Role in attribution testing:** second host-side layer scored
  alongside L2. If the two produce the same numbers, the result is a
  property of the kernel signal, not an artifact of one sensor's
  implementation.

### How a session is captured

Each captured session is one run of one **(MCP, prompt, variant)**
triple. To unpack:

- **MCP** — one of 31 third-party Model Context Protocol servers in
  our corpus (filesystem, git, postgres, puppeteer, slack, etc.). The
  agent talks to one MCP per session.
- **prompt** — one of ~20 hand-curated user prompts per MCP that the
  agent will receive. Each is designed to trigger the MCP's tools
  without naming them, so the agent has to discover the right tool
  from the schema.
- **variant** — either *benign* (unmodified MCP source) or
  *malicious* (MCP source mutated by one hand-authored patch
  simulating a supply-chain compromise).

So one (MCP, prompt, variant) triple is "this MCP, this user prompt,
this benign-or-malicious source state." Capture loop per triple:

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
7. Cut per-session slices from the global L2 / L3 logs by cgroup_id
   (the cgroup the container ran in is unique to the session).
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
   container-namespace pids (and emits *tid*, not pid, as its leftmost
   field); L2 and L3 use host-namespace pids. The same process
   has one number inside the container and a different one on the
   host. We bridge them on `execve` timestamps + argv basenames when
   needed.
2. **cgroup_id partitions sessions for free in the captures.** Each
   session ran in its own container, so each session has its own
   cgroup_id. This is a methodological choice that gives us clean
   ground truth — *not* a property AgentShield can rely on in the
   wild, where multiple sessions might share a host or a container.
   The merged-trace experiment deliberately strips this property.
3. **L2 and L3 are observationally equivalent.** Both are host-side,
   both emit the same envelope, both subscribe to the same syscall
   set. Across these experiments the two layers produce essentially
   identical numbers — confirming that what we're measuring is a
   property of the kernel signal, not of any one sensor implementation.

## Experiment construction — the merged-trace setup

To test "extract a session out of host noise," we synthesize a host
trace that contains multiple sessions running in what looks like a
single big eBPF capture.

The capture corpus has 567 sessions but they ran sequentially during
capture — no two sessions naturally overlap in time. So we synthesize
the multi-session host trace by merging captured slices.

### Merge procedure

```
def merge_sessions(sessions, layer):
  for each session s in sessions:
    ground_truth = compute_subtrees(s.l1, s.host_layer, s.stream_jsonl)
    for each event e in s.<layer>.jsonl:
      e.cgroup_id = SHARED_CGROUP   # strip cgroup-per-session shortcut
      label e with src_session, src_mcp, src_tool_call from ground_truth
      append (e, labels) to merged

  sort merged by e.ts_ns               # interleave events by timestamp
  return merged
```

The merge:
- Concatenates each session's host events (L2 events, or L3 events,
  scored separately) from N sessions.
- **Rewrites every cgroup_id to a single shared value.** Without
  this, partitioning by cgroup_id would trivially recover sessions —
  the merge has to force the prediction mechanism to work without it.
- **Preserves each event's original ts_ns.** Sessions in the corpus
  are temporally separated by minutes/hours of original capture time,
  so sorting by ts naturally interleaves them while preserving each
  session's internal ordering.
- Attaches a per-event `src_*` label for scoring. **These labels are
  never read by the prediction code** — they exist only as the answer
  key.

### Ground-truth label construction

For each event we compute three ground-truth labels per source
session, before merging:

- `src_session`: the source session id, but only for events whose pid
  is in that session's claude-execve descendant subtree. Pre-`claude`
  events (Docker runtime, container entrypoint shell) get
  `src_session = ""`.
- `src_mcp`: the MCP name, but only for events whose pid is in the
  session's MCP-server descendant subtree. Agent-process events that
  aren't part of an MCP get `src_mcp = ""`.
- `src_tool_call`: the agent's tool-call id from the agent transcript,
  but only for events that are inside an MCP subtree AND fall in a
  tool-call window from the transcript. Otherwise empty.

The descendant subtrees are computed from the **source session's own
host trace**, independently of the merge. This ensures the ground
truth is "the answer the predictor should produce if it had perfect
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
args, cgroup_id). The `src_*` columns exist on a wrapper struct but
the prediction function never reads them.

## Prediction mechanism

The prediction code does a single-pass walk of the merged stream in
`ts_ns` order, maintaining two dictionaries and a small tool-call
state machine.

### State

```python
pid_session: dict[int, str]            # host pid → session_id
pid_mcp:     dict[int, str]            # host pid → mcp_id
last_clone_caller: tuple[int, int]     # (caller_pid, ts_ns)
active_tool_call: dict[mcp_pid, str]   # mcp pid → currently-active tool_call_id
```

`pid_session` and `pid_mcp` are the running attribution state. After
the walk completes, every pid the trace ever saw has an entry (or
the empty string if the pid never inherited from a session/MCP root).

### Per-level rules

**Session.** A new session opens when we see an `execve` whose
`argv[0]` basename is `claude` and whose `argv` contains `-p` or
`--print` (the per-session invocation marker). The calling pid is
bound to a fresh `sess_<n>`. Descendants inherit via the clone-caller
rule below.

**MCP.** A new MCP opens when we see an `execve` whose `argv[0]`
basename matches the pattern `mcp[-_]server[-_]…`, or a wrapper
invocation `node|python|uvx <script>` where the script's basename
contains both `mcp` and `server` (or starts with `mcp-`). The
calling pid must already be bound to a session. Descendants inherit.

**Tool call.** When a `sendto` from a session-bound pid carries a
buffer that decodes to JSON containing `"method":"tools/call"`, we
parse the tool name and the agent's tool_use_id from the payload,
and bind that call to the most recently opened MCP in the calling
pid's session. The call closes when the same MCP pid emits a `sendto`
whose buffer contains a JSON-RPC response frame
(`"jsonrpc"` + `"id"`).

### Inheritance rule

When a clone or clone3 fires, we record `(caller_pid, ts)`. The next
event from a previously-unseen pid within 200ms inherits the caller's
session and MCP attribution. This is the only mechanism by which
descendants of a session/MCP root pick up the right labels — clone
events themselves don't carry the new pid in the v1 envelope; the
new pid first surfaces on its own first event.

The 200ms threshold is chosen to be much larger than realistic
clone-to-first-event latency (~ms on a healthy host) and much smaller
than the inter-session gap (minutes between captured sessions in the
corpus). It is a hyperparameter, not a learned value.

### Per-event prediction

For each event in the merged stream:
- `predicted_session = pid_session.get(event.pid, "")`
- `predicted_mcp     = pid_mcp.get(event.pid, "")`
- `predicted_tool_call = active_tool_call.get(<mcp_pid_for_this_event>, "")`

Empty string at any level means "not attributed." This is treated as
a real prediction (it has a precision/recall meaning), not a sentinel.

## Scoring

For each level (session / MCP / tool_call) and each layer (L2 / L3):

### Greedy 1-to-1 class mapping

The predicted class ids (`sess_0`, `mcp_3_mcp-server-puppeteer`,
`toolu_bdrk_01abc...`) don't match the ground-truth ids
(`18361994762148a09454d995b5979834`,
`anthropic_ref_servers/puppeteer`, the agent's tool_use_id) by
string. Standard remedy: build a contingency table and find the
predicted-to-true assignment that maximizes co-occurrence count. We
use a greedy 1-to-1 match; for the class cardinalities here (3–10
classes per trial) this is optimal.

### Per-event precision / recall / F1

With the class mapping fixed:

- **TP**: event has non-empty true label *and* its predicted class
  maps to the same true label.
- **FP**: event has non-empty predicted class that maps to something
  other than its true label (or the true label is empty).
- **FN**: event has non-empty true label but the predicted class is
  empty or maps elsewhere.

Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 = harmonic
mean of the two.

Events with empty true *and* empty predicted are excluded — they're
"both sides correctly say not relevant" and would inflate scores
trivially.

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
events are *grouped together*, not what the groups are called), so
we report it alongside F1 as a sanity check that doesn't depend on
the greedy mapping above.

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

10 trials × 2 layers × 3 levels = 60 score cells; each cell is the
mean of one F1, one Precision, one Recall, one ARI across the 10
trials.

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

- **Session attribution.** Near-perfect precision (when we say it's
  session X, it is). Recall is bounded by the pre-`claude -p` window
  of each session — Docker runtime, container entrypoint, and the
  preliminary `claude mcp add` registration call all fire before the
  session root and don't inherit a session label. In a deployment
  without that runtime preamble, recall would be higher.
- **MCP attribution.** Essentially solved at F1 = 0.997. The
  MCP-server execve is unambiguous, and subtree closure works
  without qualification. This is the strongest result.
- **Tool-call attribution.** Bimodal — best trials reach 1.0, worst
  reach 0.0. Failure modes: `sendto` buffer truncation (long argument
  arrays clipped by the 256B kernel buffer), JSON-RPC frame
  fragmentation across multiple sendtos, MCPs that use TLS-wrapped
  transport for tool calls. When the JSON-RPC frame *is* visible in
  `sendto`, attribution is ~80% precise. The recall gap is "couldn't
  extract enough boundary events," not "attributed the wrong ones."

### What this answers

| Question | Answer |
|---|---|
| Identify session events in an arbitrary host trace? | Yes, F1 = 0.92 with near-perfect precision |
| Identify per-MCP partitioning? | Yes, F1 = 0.997 |
| Identify per-tool-call partitioning, sequential? | Partially, F1 = 0.56 — bounded by sendto buffer fidelity |
| Identify per-tool-call partitioning, concurrent on same MCP? | No — information-theoretic ceiling, the kernel doesn't see the JSON-RPC request id once it crosses into the MCP's worker threads |
| Are the results an artifact of a specific sensor? | No — L2 and L3 produce identical numbers within noise |

## Method caveats

1. **Tool-call ground truth comes from agent-transcript windows**,
   which are loose (cover the gap between consecutive tool calls,
   not just the active call). This depresses the recall denominator —
   events that ground-truth as belonging to call X may actually be in
   the inter-call gap. Tightening this requires per-request JSON-RPC
   timestamps from the host eBPF emitter, which the current capture
   does not yet populate.
2. **Sessions in the corpus are sequential, not concurrent.** The
   merged stream sorts on each event's original ts, which produces
   sequential ordering of interleaved sessions rather than true
   temporal overlap. A "time-shifted" merge — re-stamping ts to force
   overlap — would stress the prediction mechanism more aggressively
   and is a follow-up.
3. **Distinct-MCP sampling.** The trials enforce one of each MCP per
   merge. Stress conditions to consider: repeated MCPs (e.g., two
   filesystem-server instances) — does the matcher disambiguate by
   pid; 5+ sessions per merge — does session-root tracking degrade.
4. **Pre-claude noise (~14% of session events) is currently scored
   against the predictor**, which is the conservative choice. A
   "fair" version would exclude pre-`claude -p` events from recall;
   we report the conservative number.
