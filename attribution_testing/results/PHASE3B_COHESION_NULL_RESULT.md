# Phase 3b — cohesion-based descendant filtering: null result

**Date:** 2026-06-03

This is the writeup for Phase 3b of the Kuzu provenance-graph
attribution work. We expected cohesion-based filtering to lift V3
(bare-host) session F1 by trimming low-cohesion descendants that
inherited spurious session-membership through clone-window
collisions. It didn't. This doc explains what we tried, why it
didn't work, and what the finding tells us about the underlying
problem.

## Hypothesis

V3 attribution numbers (bare-host benign captures) sit at session
F1 ≈ 0.72, partly because Claude's clone-descendant subtree includes
processes that don't really belong to the agent's tool-related work:

- Hook subprocesses (`pgrep`, `ps`, `lsof` spawned by `copperhead.sh`
  or similar Claude Code hooks).
- Other claude instances running on the host that briefly intersect
  the capture's clone topology.
- Background system processes (sshd, systemd-resolve, irqbalance)
  that happen to fork shortly after a claude-side clone.

The hypothesis: a **real** session descendant — one doing work on
behalf of the agent's tool calls — should touch some of the same
files and sockets the session's MCP touches. A drive-by descendant
won't. So we can compute per-pid cohesion against the session's
touch-set and demote pids that fall below a threshold.

## Mechanism

For each session in the merged graph:

1. Compute the session's touch-set: every File and Socket vertex
   reachable from a Process bound to that session via a `read`,
   `write`, `unlink`, `connect`, `send`, `recv`, or `bind` edge.
2. For each candidate pid (member of session, but not member of any
   MCP under that session, and not the session anchor pid itself),
   compute its own touch-set.
3. Compute cohesion = |overlap with rest-of-session touch-set| /
   |pid's own touch-set|.
4. If cohesion < threshold, demote: remove the
   `member_of_session` edge, add a tracked
   `demoted_session_membership` edge for visibility.

We tried two definitions of the rest-of-session touch-set:

- **v1:** MCP-only touch-set. The cohesion test asks "is this pid
  touching the same files/sockets as the MCP server?"
- **v2:** Whole-session touch-set, excluding the candidate pid
  itself. The cohesion test asks "is this pid touching files/sockets
  that the rest of the session also touches?"

We tried two thresholds: 0.10 (loose) and 0.001 (tight).

## Results (10 trials, 3 V3 bare-host sessions per trial)

| Configuration | Session F1 | Session P | Session R |
|---|---:|---:|---:|
| Baseline (no filter)               | 0.722 | 0.712 | 0.733 |
| Cohesion v1 (MCP-only, thr=0.10)   | 0.521 | 0.752 | 0.400 |
| Cohesion v2 (whole-session, thr=0.10) | 0.459 | 0.585 | 0.382 |
| Cohesion v2 (whole-session, thr=0.001) | 0.722 | 0.713 | 0.733 |

**The filter either harms substantially (loose thresholds) or has
no measurable effect (tight thresholds).** No threshold setting we
tried produces a meaningful F1 lift over baseline.

## Per-trial breakdown is informative

Looking at v1 (MCP-only cohesion, thr=0.10) per trial:

| Trial | Baseline F1 | Cohesion F1 | Δ |
|---|---:|---:|---:|
| 0 | 0.951 | 0.503 | **−0.45** |
| 1 | 0.842 | 0.842 | 0 |
| 2 | 0.932 | 0.932 | 0 |
| 3 | 0.842 | 0.842 | 0 |
| 4 | 0.428 | 0.595 | +0.17 |
| 5 | 0.424 | 0.595 | +0.17 |
| 6 | 0.951 | 0.503 | **−0.45** |
| 7 | 0.459 | 0.624 | +0.17 |
| 8 | 0.939 | 0.486 | **−0.45** |
| 9 | 0.942 | 0.561 | **−0.38** |

The pattern: **trials with high baseline F1 lose, trials with low
baseline F1 gain.** Cohesion filtering brings every trial toward
the same middle band (≈ 0.5–0.6), regardless of whether the
baseline was right or wrong. It's not improving attribution; it's
flattening the distribution.

## What the diagnostic shows

Inspecting trial 0 (baseline 0.951 → cohesion 0.503), the demoted
pids on v1 include:

| pid | comm | cohesion | edges contributed |
|---|---|---:|---:|
| 1366 | systemd-resolve | 0.000 | 29 |
| 1560 | irqbalance      | 0.000 | 24 |
| 1989 | ssm-agent-worke | 0.000 | small |
| 820  | systemd-journal | 0.025 | 201 |
| 101917 | sh            | 0.008 | **4080** |
| 102159 | sh            | 0.008 | **4096** |
| 102127 | sudo          | 0.000 | 2 |
| 102197 | git           | 0.067 | 60+ |

The system-process demotions (`systemd-resolve`, `irqbalance`,
`systemd-journal`, `ssm-agent-worke`) are correct — they're noise
that briefly inherited via clone-window collision.

The **sh and git demotions are wrong** — these are shell processes
the agent spawned for `Bash` tool calls, doing legitimate session
work. They each contribute 4000+ edges. Demoting them removes
thousands of correctly-attributed events and tanks F1.

Why do legitimate Bash/git invocations get low cohesion? Because
they operate on **workspace files** (`/home/ubuntu/work/...`) while
the **MCP server** operates on **its own state** (registry files,
internal data, stdio sockets). The two touch-sets are largely
disjoint by design.

## The conceptual flaw

Cohesion-based filtering rests on an assumption that turns out to
be false: **that all session work is co-located in the same
file/socket touch-set.** It isn't. A session's work distributes
across multiple semantic domains:

| Domain | Process | Files touched |
|---|---|---|
| MCP server | `mcp-server-X` | MCP-internal state, JSON-RPC stdio |
| Agent direct ops | `claude` itself | model API responses, transcript files |
| Tool: Bash | `sh -c "..."` | workspace files, shell builtins |
| Tool: Read/Write | `claude` (in-process) | workspace files |
| Hooks | `bash`, `pgrep`, `ps` | varies — could be anything user wrote |

Each domain has a distinct file/socket profile. Cross-domain
overlap within a session is naturally low — they're doing different
kinds of work.

A drive-by system process (irqbalance, systemd-resolve) also has
zero overlap with any of these. The cohesion metric can't
distinguish "drive-by noise" from "legitimate non-MCP work" because
both have the same shape from a file-touch-set perspective: low
overlap with the dominant in-session pids.

## The filter is also operating after the wrong decision

Even if cohesion *could* distinguish noise from legitimate work,
it's a post-hoc fix on the wrong side of the problem. The clone
events that bound the noise pids to the session happened earlier
in the trace. By the time we're in the graph computing cohesion,
the wrong attribution has already happened, and the filter is
trying to correct it after the fact.

The right place to intervene is **at the binding decision** — the
200ms clone-window inheritance rule. V1 already showed that this
rule is the source of cross-session leakage when sessions overlap
on millisecond scales. A tighter inheritance rule (same-comm,
same-uid tie-breakers; tighter time window when multiple session
roots are in scope) would prevent the wrong binding from happening
in the first place. That fix is in the predictor, not in a graph
post-process.

## What the null result tells us

Three things, in order of importance:

**1. Session work is structurally heterogeneous.** A session's
file-touch profile is the union of multiple disjoint sub-profiles
(MCP, Bash, hooks, direct agent ops). No single coherence metric
captures "session-ness" — and any threshold-based filter will
either be too aggressive (demoting legitimate non-MCP work) or too
permissive (failing to demote noise).

**2. Filtering wrong attributions after the fact is harder than
making the right attribution decision in the first place.** The
clone-window inheritance is the load-bearing mechanism for
descendant binding. If it's wrong, downstream filters are working
against more authoritative state than the noise they're trying to
remove. The predictor, not the graph, is where the fix lives.

**3. The bare-host F1 of 0.72 is real and not easily liftable
without changes to the predictor or sensor.** Cohesion isn't going
to get us from 0.72 to 0.85+ on V3. To improve V3 numbers we'd
need either: tighter clone-inheritance (predictor change), an
expanded sensor (read-syscall capture for config-content
attribution, which is option 3 from the layered detector
discussion), or a richer descendant-validation signal (e.g., does
this pid receive bytes from a session-bound parent over a pipe).

## Implications for Phase 3c

Phase 3c (pipe-fd-based MCP attribution) is structurally different
from Phase 3b — it works on **creation** of MCP vertices, not on
**filtering** session-descendant attributions. The lesson from 3b
(post-hoc filtering doesn't generalize) doesn't directly apply.
But the deeper observation — that the better fix is at the binding
decision — does apply. Phase 3c should be evaluated against the
question "does it produce better MCP attribution at creation," not
"does it correct mistaken MCP attribution after the fact."

## Code

- [cohesion_filter.py](../cohesion_filter.py) — implementation
  retained for documentation and possible reuse, but not enabled
  in the default scoring path.
- [v3_score_kuzu.py](../v3_score_kuzu.py) — V3 scoring with
  optional cohesion filter (controlled by `--threshold`).

## Recommendation

Drop cohesion-filtering as a default mechanism. Document the null
result. Move on to Phase 3c (pipe-fd-based MCP attribution) and,
separately, prioritize a predictor-side fix to the
clone-inheritance window (V1's recommendation: same-comm /
same-uid tie-breakers).
