# E6 — Multi-level attribution under cross-session merge

**Date:** 2026-06-01
**Setup:** 10 trials, each merging 3 captured sessions with **distinct
MCPs** into one host trace stream. cgroup_id rewritten to a single
shared value so the cgroup-per-session shortcut doesn't apply. Events
sorted by ts to interleave. L2_ext and L3 scored separately.

The attribution mechanism uses **only kernel-observable signals**:

- **Session**: detect `execve` of `claude -p ...` → root pid; descendants
  inherit via clone/clone3/execve.
- **MCP**: detect `execve` whose argv0 basename matches `mcp-server-*`
  (or wrapper `node|python|uvx <mcp-script>`) → MCP root scoped to the
  session of the calling pid; descendants inherit.
- **Tool call**: parse `sendto` `buf_b64` for `"method":"tools/call"`
  JSON-RPC frames; tool-call window opens at the request, closes at
  the next response from the MCP pid. The tool's
  `claudecode/toolUseId` field is extracted as the predicted id.

**No use** of `session.json`, `stream.jsonl`, source-of-record
timestamps, or any per-source-session metadata during prediction. The
mechanism sees only the merged JSONL.

## Headline numbers

| Layer | Level | F1 (mean) | Precision | Recall | ARI |
|---|---|---:|---:|---:|---:|
| L2_ext | session | 0.924 | 0.999 | 0.859 | 0.766 |
| L2_ext | **mcp** | **0.997** | **1.000** | 0.993 | 0.996 |
| L2_ext | tool_call | 0.553 | 0.786 | 0.437 | 0.293 |
| L3 | session | 0.924 | 0.999 | 0.859 | 0.766 |
| L3 | **mcp** | **0.997** | **1.000** | 0.993 | 0.996 |
| L3 | tool_call | 0.564 | 0.792 | 0.448 | 0.317 |

Aggregated over 10 trials. L2_ext and L3 produce essentially
identical numbers — both layers see the same kernel-observable
signals once tampering-mode probes are enabled.

## Reading

**Session level — clean precision, soft recall.** When we predict
session X, we're right essentially always (P ≈ 1.0). What we miss
(R ≈ 0.86) is pre-`claude -p` events: runc, docker-entrypoint, and
the `claude mcp add ...` registration call all fire before the
session root and don't get attributed to a session. In a real
deployment without the runc preamble this gap should narrow.

**MCP level — essentially perfect.** F1 = 0.997, ARI = 0.996. Once
we have the right session, attributing events to the right MCP via
subtree closure is deterministic and the captures cooperate (every
MCP server has a recognizable execve). This is the strongest
attribution result in the experiment.

**Tool-call level — works when JSON-RPC is visible in sendto, fails
otherwise.** F1 = 0.56 (mean) but with bimodal behavior: best trials
hit 1.0, worst trials hit 0.0. The 0.0 cases are sessions where:

1. The `sendto` buffers carrying the tools/call frame are truncated
   beyond the JSON envelope (long argument arrays).
2. Or the JSON-RPC frame happens via a transport our regex doesn't
   match (e.g., framed length-prefixed instead of newline-terminated).
3. Or the per-session ground-truth tool-call windows from
   `stream.jsonl` don't overlap with any sendto-detected request
   (some MCPs use TLS uprobes for their dispatch, which our `sendto`
   parser doesn't see).

Even with these caveats, P = 0.79 says: when we *do* extract a
tool-call boundary, we attribute it to the right call about 80% of
the time. The recall gap is "we didn't extract enough boundaries,"
not "we attributed the wrong ones."

## What this answers for the original question

> *Given an arbitrary host trace (multiple sessions, different MCPs,
> no cgroup-per-session shortcut), can we pick out which events
> belong to which session, MCP, and tool call, using only host
> eBPF signals?*

| Level | Answer | Confidence |
|---|---|---|
| Session | **Yes, with ~86% recall and near-perfect precision.** Pre-claude noise is the residual gap, mostly a corpus artifact. | high |
| MCP | **Yes, essentially perfectly (F1 = 0.997).** Subtree closure from the MCP-server execve is the cleanest layer. | high |
| Tool call | **Partial — bounded by whether JSON-RPC frames are visible in kernel-captured sendto buffers.** When visible, attribution is ~80% precise; recall depends on sensor-side buffer fidelity. Concurrent calls into the same MCP would still hit the structural ceiling from E5. | medium |

## Method caveats

1. **Tool-call ground truth comes from `stream.jsonl` windows**, which
   are loose (cover the gap between consecutive tool calls, not just
   the active call). This hurts the recall denominator — events
   "ground-truthed" as belonging to a tool call may actually be in
   the inter-call gap. A tighter ground truth would come from
   `mcp_jsonrpc` events on the source-session's own trace, which
   we don't currently emit.
2. **Pre-`claude` events are scored as `src_session=""`**, so they
   contribute to neither precision nor recall directly, but they do
   appear as `pred_session=""` and depress the recall-like metric
   when their pids never get bound.
3. **"Distinct MCPs" sampling guaranteed one of each MCP per trial.**
   Sessions with repeated MCPs (e.g., two `mcp-server-filesystem`
   instances) would test whether the matcher disambiguates by pid.
   Worth a follow-up.

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/attribution_testing
python3 e6_merged_attribution.py --n-trials 10 --n-sessions 3 --limit 200
# Per-trial rows in results/e6.jsonl
# Aggregate in results/e6_summary.json
```
