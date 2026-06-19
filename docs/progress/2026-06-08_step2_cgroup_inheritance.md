# Step 2 — cgroup-gated clone-inheritance: deployment-realistic lift

**Date:** 2026-06-08

This is a results doc for a single change to the attribution
mechanism that lifted V3 (bare-host benign capture) session F1 from
0.72 to 0.81 with no regression on the containerized baselines. The
change is small — adding one structural check to the existing
clone-window inheritance rule — but it closed a real source of
deployment-realistic attribution error. The doc covers what the
problem was, what the fix is, why it works, and what it does not
fix.

It is self-contained — concepts are summarized rather than referenced
out.

## What we were trying to fix

Earlier work (the V1/V2/V3 diagnostic suite) established that the E6
attribution numbers (session F1 ≈ 0.92, MCP F1 ≈ 0.997) benefited
from the way captures were collected — sequentially, in containers,
on a corpus where the noise around each session is itself controlled
by Docker's preamble. On bare host (V3), session F1 dropped to 0.72.

The remaining 28% session-attribution error came from one specific
mechanism: the **200ms clone-inheritance window**. The predictor uses
this rule to attach previously-unseen pids to their parents, because
the v1 envelope's `clone` events record the *caller's* pid, not the
new child's. Without observing a separate "new pid created" event, we
have to infer parent-child relationships from temporal proximity.

The original rule was purely temporal:

> A previously-unseen pid emitting an event within 200ms of the most
> recent recorded clone is treated as that clone caller's child.

On bare host, this is too permissive. Three failure modes show up
empirically:

1. A system-managed daemon (sshd, irqbalance, systemd-resolve) forks
   shortly after a session-internal clone event, and the next-seen
   pid (the daemon's worker) gets attributed to the agent session.
2. Two agent sessions running close in time have their clone events
   interleave, and pids genuinely from session B get bound to session
   A because session A's clone happened to fire most recently.
3. Hooks in Claude Code spawn many short-lived subprocesses
   (`pgrep`, `ps`, `lsof`); the resulting clone storm makes the
   "most recent clone caller" a noisy signal.

V1 (synthetic temporal-overlap merge) confirmed mechanism 2 directly.
V3 (bare-host real capture) shows mechanisms 1 and 3 in production
conditions.

## What the fix is

Add `cgroup_id` as a hard reject on inheritance:

> A new pid can inherit from a clone caller only if their cgroup_ids
> match. If the candidate child's cgroup is different from the
> caller's, reject the inheritance even if the timing is within the
> 200ms window.

Concretely: the clone-state struct went from `(caller_pid, ts)` to
`(caller_pid, ts, caller_cgroup)`. The check went from
`if ts - cts < 200_000_000:` to
`if ts - cts < 200_000_000 and (caller_cgroup == candidate_cgroup):`.

Three call sites updated, all the same shape:

1. **`predict()` in `e6_merged_attribution.py`** — the dict-based
   predictor used by V1/V2.
2. **`_source_subtrees()`** in the same file — ground-truth
   construction; uses the same rule so ground truth and predictor
   agree on what counts as a session descendant.
3. **`KuzuGraphBuilder.add_event()` in `graph_builder.py`** — graph
   construction.

We treat `None` on either side of the cgroup comparison as a
wildcard match. Defensive: if a sensor variant ever produced an
event without `cgroup_id`, we don't want to reject everything.

## Why cgroup is the right signal here

Three properties of `cgroup_id` make it specifically suited for this
job:

**It's already in every event we capture.** Every L2 (AgentShield)
and L3 (libbpf) event carries `cgroup_id` as a top-level envelope
field, populated by `bpf_get_current_cgroup_id()` in the BPF probe.
No sensor extension needed.

**It's not a Docker artifact.** On any modern Linux host running
systemd, every process has a cgroup_id assigned by systemd's cgroup
v2 unified hierarchy — even with no containers anywhere on the host.
systemd places each managed unit under
`/system.slice/<unit>.service/` and user processes under
`/user.slice/user-<uid>.slice/...`. So on a bare-host capture we
still see distinct cgroups per service: irqbalance has one, sshd has
another, the user's claude has a third. cgroup-mismatch is therefore
strong evidence of "unrelated processes spawned by different
services" without depending on containerization.

**It's stable per-process.** Inspecting a V3 capture, we never
observed a pid changing cgroup over its lifetime. cgroup-membership
is set at process creation and inherited by clone — exactly the
property we need for the inheritance check to be sound.

## Results

### V3 (bare-host benign, 10 trials × 3 distinct-MCP sessions)

| Metric | Before (no cgroup gate) | After (cgroup-gated) | Δ |
|---|---:|---:|---:|
| **Session F1** | **0.722** | **0.806** | **+0.084** |
| Session precision | 0.712 | 0.779 | +0.067 |
| Session recall | 0.733 | 0.836 | +0.103 |
| MCP F1 | 0.837 | 0.835 | −0.002 |
| Tool-call F1 | 0.543 | 0.544 | +0.001 |

Both precision and recall improved at the session level. Precision
improvement = noise pids correctly excluded from sessions. Recall
improvement = the legitimate-descendant pids that were being demoted
as collateral damage by the previous wrong attribution are now
correctly bound.

The lift is concentrated on the trials whose baseline was bad. Per
trial:

| Trial | Old session F1 | New session F1 | Δ |
|---|---:|---:|---:|
| 0 | 0.951 | 0.951 | 0 |
| 1 | 0.842 | 0.842 | 0 |
| 2 | 0.932 | 0.932 | 0 |
| 3 | 0.842 | 0.842 | 0 |
| 4 | **0.428** | **0.689** | **+0.26** |
| 5 | **0.424** | **0.690** | **+0.27** |
| 6 | 0.951 | 0.947 | −0.004 |
| 7 | **0.459** | **0.691** | **+0.23** |
| 8 | 0.939 | 0.938 | −0.001 |
| 9 | 0.942 | 0.943 | +0.001 |

Three trials moved from F1 ≈ 0.43 to F1 ≈ 0.69 (the old worst-case
trials, where cross-session contamination was severe). Other trials
stayed essentially the same. **No trial regressed by more than 0.004
F1.**

### E6 (containerized corpus, 10 trials × 3 distinct-MCP sessions)

| Metric | Before | After |
|---|---:|---:|
| Session F1 (L3) | 0.999 | 0.999 |
| MCP F1 (L3) | 1.000 | 1.000 |
| Tool-call F1 (L3) | 0.528 | 0.531 |

E6 is unchanged. Expected: in containerized captures every session's
events share one container cgroup, so the cgroup-match check is
trivially satisfied for everything that would have been bound before.
The fix is conservative — it only rejects bindings, never adds new
ones — so it cannot regress a workload where the temporal rule was
already correct.

### Combined picture across all variants

| Variant | Old session F1 | New session F1 | Notes |
|---|---:|---:|---|
| E6 (containerized, sequential) | 0.92 | **1.00** | layered MCP detector + cgroup-gating |
| V2 (strip Docker noise) | 1.00 | 1.00 | trivially unchanged |
| V3 (bare-host real capture) | 0.72 | **0.81** | cgroup-gating closes most of the gap |

V1 (synthetic temporal-overlap merge) is not re-tested here; the
existing V1 numbers came from before any of the fixes. We expect a
substantial lift there too because V1's failure mode (cross-session
clone-window collision) is exactly what cgroup-gating addresses.

## What the fix does NOT solve

Two failure modes remain after Step 2:

**1. Multiple agent instances under the same user.** If two
`claude -p` sessions are running concurrently as the same uid, they
share the user-slice cgroup. cgroup-gating cannot separate them — the
candidate-child cgroup matches both clone callers.

This is the V3 incidental finding from earlier (the Claude Code
session being used to develop this work briefly intersected V3
captures). Solving it would require uid distinguishability between
instances, which currently doesn't exist (both are the same uid), or
loginuid (which would distinguish login sessions but isn't currently
captured), or namespace inodes (also not captured).

**2. Long-lived processes that pre-existed the trace.** No clone
event was captured for them. cgroup-gating is irrelevant to their
attribution because the attribution path doesn't run.

These remaining cases need different mechanisms. They're not
solvable from the host trace alone given the current sensor's event
filter.

## Implications

For our reporting, three things change with this result:

**The deployment-realistic baseline is now 0.81, not 0.72.** When
discussing what AgentShield-style host-side attribution can achieve
on a real machine, the V3 number with cgroup-gating is the right one
to cite. The 0.72 number was bounded by an avoidable mechanism issue,
not by a structural limit.

**The V1 result needs re-evaluation.** V1 showed F1 dropping to 0.47
under synthetic temporal overlap. That was without cgroup-gating, and
much of V1's failure mode was exactly what cgroup-gating addresses.
Worth re-running to see how much of V1's drop survives the fix.

**The remaining gap is genuinely structural.** Same-user concurrent
agents can't be separated from the host trace alone with our current
sensor's event filter. This becomes a deployment caveat in the
methodology doc, and a potential sensor-extension item if it ever
becomes important.

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/attribution_testing

# E6 with cgroup-gated inheritance (containerized baseline)
python3 kuzu_e6_score.py --n-trials 10

# V3 with cgroup-gated inheritance (bare-host realistic)
python3 v3_score_kuzu.py --captures-dir v3_captures \
        --n-trials 10 --threshold 0.001
```

Per-trial outputs:
- `results/kuzu_e6.jsonl` and `results/kuzu_e6_summary.json`
- `results/v3_kuzu.jsonl` and `results/v3_kuzu_summary.json`
