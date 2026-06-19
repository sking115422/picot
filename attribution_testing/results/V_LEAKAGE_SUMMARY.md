# V1/V2/V3 — Diagnostics for E6 leakage hypothesis

**Date:** 2026-06-03
**Question:** Were E6's strong attribution numbers (Session F1 0.92, MCP F1 0.997, Tool-call F1 0.56) inflated by Docker-specific structure in the captures?

We ran three diagnostics:
- **V1** — time-shifted merge: rebase each session's ts to a shared anchor so sessions truly overlap on millisecond scales.
- **V2** — strip Docker noise: drop runc/containerd/docker-entrypoint/strace events before merging.
- **V3** — bare-host capture: run benign agent sessions directly on the host (no Docker), score the same prediction code on real host eBPF.

## Headline

| Variant | Session F1 | MCP F1 | Tool-call F1 | Notes |
|---|---:|---:|---:|---|
| **E6 (baseline)** | 0.923 | 0.997 | 0.553 | original captures, sequential merge |
| **V1** time-shifted | **0.474** | **0.643** | 0.486 | sessions overlap on ms scale |
| **V2** strip Docker noise | **1.000** | 0.797 | 0.498 | runc/entrypoint/strace removed |
| **V3** bare-host | **0.722** | 0.682 | 0.540 | real bare-host, hook noise included |

Numbers are L2 layer; L3 is within ±1% across all variants.

## What the numbers mean

### V1 — temporal isolation was doing real work

Original E6 sorts the merged stream by each event's original ts.
Sessions in the corpus were captured back-to-back but minutes apart,
so when we sort, each session's events live in their own dense
temporal cluster, separated from the next session by a long quiet
period. The 200ms clone-inheritance window can never span sessions
because nothing's within 200ms of the boundary.

V1 rebases each session's ts so they all start at t=0. After the
rebase, 4719 of the first 5000 events have <1ms gaps to the next.
The 200ms clone window now binds pids across sessions: a clone in
session A's caller leaks the session-A label to the next-seen pid,
which might actually belong to session B.

**Result:** session F1 drops from 0.92 → 0.47, MCP F1 from 0.997 →
0.64, tool-call ARI collapses from 0.29 → 0.04.

**Interpretation:** the original E6 numbers were partially propped
up by an artifact of sequential capture. The mechanism is robust to
sequential interleaving but not to true temporal overlap. The 200ms
clone-inheritance heuristic is the suspect; tighter inheritance
(e.g., requiring same-comm or same-uid) would help.

### V2 — Docker noise had a mixed effect

V2 identifies the runc → containerd-shim → docker-entrypoint → strace
ancestry chain in each session and drops those pids' events from
the merged stream before predicting. The merged stream then contains
only events from `claude -p` and its descendants.

**Result:** session F1 jumps from 0.92 → 1.00 (perfect — the 8%
recall gap in E6 was entirely Docker preamble). MCP F1 *drops*
from 0.997 → 0.80.

**The MCP drop is informative, not concerning.** In our captures,
`docker-entrypoint.sh` does:
```
sh -c "claude mcp add ... && exec strace -f ... claude -p ..."
```
So the *shell* is the parent of both the strace-wrapped claude and
of the registration call that launches the MCP server. When V2
strips that shell's events, we delete the intermediate node that
the predictor was using to bridge claude → MCP. In a deployment
without Docker, claude launches MCPs as direct children itself,
and there's no intermediate node to delete. **The V2 MCP F1 drop
is a corpus-shape artifact, not a mechanism limitation.**

**Tool-call F1 unchanged at 0.50** — confirms tool-call attribution
isn't affected by the preamble; it's bounded by JSON-RPC visibility
in `sendto` buffers regardless of what else is in the trace.

### V3 — bare-host result is honest and lower than E6

V3 captured 9 fresh benign sessions directly on the host with no
Docker, no strace wrapping. Three MCPs (filesystem, memory, git),
three prompts each, all installed on a `mcp_test_venv` conda env
with python 3.11.

**Result:** session F1 = 0.722, MCP F1 = 0.682, tool-call F1 = 0.540
with **precision 0.92, recall 0.39**.

The session F1 is bimodal across trials (0.42–0.95). Investigating:
the worst trials are when the predictor over-attributes events to
session A. Looking at the over-attributed events, they fall into
three categories:

1. **`pgrep`/`ps`/`lsof` invocations from a Claude Code hook script**
   (`copperhead.sh`). These are *legitimate descendants* of the
   claude pid — claude spawned the hook, the hook spawned pgrep.
   The "ground truth" labels them as not-session-related because
   our `_source_subtrees` function only counts claude's *direct*
   subtree from the `claude -p` execve, but the hook subprocesses
   do live in claude's subtree.
2. **VSCode and editor processes** that briefly fork during the
   capture window and inherit through some clone caller.
3. **systemd / sshd / kernel-thread events** that are unrelated
   but happen to fire shortly after a claude-side clone.

Category 1 is **the predictor being more right than the ground
truth**. Categories 2 and 3 are real over-attribution (false positives).

**Interpretation:** session attribution mechanism works on bare host
with real numbers ≈ 0.72 F1, ARI ≈ 0.73. The 20% drop from E6's
0.92 reflects (a) hook-spawned descendants the ground truth
doesn't count and (b) genuine over-attribution from background
host noise. MCP attribution at 0.68 is real — without the Docker
intermediate-shell artifact, MCP attribution depends on the
predictor finding `mcp-server-*` execves under a session, which it
does, but with more variance than in the controlled Docker setup.

## What should change

### About the E6 numbers

E6's session F1 of 0.92 and MCP F1 of 0.997 should be **clearly
labeled as "containerized, sequentially-captured corpus" results**,
not as deployment estimates. The bare-host numbers (0.72 / 0.68 /
0.54) are the realistic ones to quote externally for the question
"how well does this work on a real host?"

The mechanism is the same; what changes is what the corpus looks
like. The methodology doc should call out:

- E6 result is an upper bound; deployment will be lower.
- The 200ms clone-inheritance window leaks under true concurrency
  (V1 finding).
- Hook-spawned subprocesses inherit through clone closure even
  when they're "not really" session work — depends on how we
  define "session."

### About the prediction mechanism

Two specific improvements warranted by V1 and V3:

1. **Tighten clone-inheritance.** Currently any clone within 200ms
   binds the next-seen pid. Adding tie-breakers — same comm-name,
   same uid, parent's namespace match — would close the V1 leakage.
   In bare-host data the inheritance also picks up unrelated
   background pids; the same tie-breakers would help.

2. **Override prior inheritance on session-root execve** —
   *already done* in this round. When a `claude -p` execve fires
   on a pid that previously inherited a session (via a prior
   clone caller), we now rebind it as a fresh session. Without
   this fix, V3 only opened 1 of 3 sessions.

### About ground truth

V3 also exposes a **ground-truth definition issue** that didn't
matter in E6: hook-spawned subprocesses are technically in claude's
clone subtree but aren't part of "the agent's session work" by
intent. Two options:

- **Tighten ground truth** to count only events whose pid path
  back to claude doesn't pass through a hook execve. This is what
  the predictor *should* match.
- **Leave ground truth permissive** and accept that "session" =
  "everything claude transitively spawned, including hooks." Then
  V3 is reporting honest attribution (the predictor was right).

In a deployment-detection context the second framing is probably
more useful — analysts want to know "what did this session touch,"
and a hook subprocess running pgrep counts as session-related work.

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/attribution_testing

# V1 — time-shifted merge
python3 v1_time_shifted_merge.py --n-trials 10 --n-sessions 3 --limit 200

# V2 — strip Docker noise
python3 v2_strip_docker_noise.py --n-trials 10 --n-sessions 3 --limit 200

# V3 — bare-host capture (requires sudo for L3 sensor + Bedrock token)
source /tmp/bedrock_env.sh
export AWS_REGION=us-east-2
python3 v3_bare_host_capture.py --prompts-per-mcp 3
python3 v3_score.py --captures-dir v3_captures --n-sessions 3 --n-trials 10
```

Per-variant outputs land in `results/{v1,v2,v3}{,_summary}.json`.

## Files

- [v1_time_shifted_merge.py](../v1_time_shifted_merge.py) — V1
- [v2_strip_docker_noise.py](../v2_strip_docker_noise.py) — V2
- [v3_bare_host_capture.py](../v3_bare_host_capture.py) — V3 capture
- [v3_score.py](../v3_score.py) — V3 scoring
- [results/v1.jsonl](v1.jsonl), [v1_summary.json](v1_summary.json)
- [results/v2.jsonl](v2.jsonl), [v2_summary.json](v2_summary.json)
- [results/v3.jsonl](v3.jsonl), [v3_summary.json](v3_summary.json)
- [v3_captures/](../v3_captures/) — 9 bare-host benign captures
