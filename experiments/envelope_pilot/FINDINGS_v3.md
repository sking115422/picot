# Envelope Pilot — v3 (attribution-filtered)

## What v3 changed

v3 adds ONE thing to the pipeline: before scoring events against the
envelope, filter the events to only those that belong to the MCP
server's process subtree. Everything outside the subtree (Claude Code
CLI's own bookkeeping, wrapper HTTP calls to Bedrock, containerd/runc
init noise) is excluded.

v3 does NOT include the dotfile-in-scratch rule from v2. It's isolated
purely to measure the effect of attribution filtering.

## Subtree identifier

For each session's l3.jsonl:

1. **Path-based root**: find the pid where `comm="claude"` execs a
   non-claude binary under `/usr/local/bin/`. That's Claude Code
   spawning the stdio MCP server.
2. **Fallback for sessions with missing path fields**: use the busiest
   pid whose comm history contains a non-ancestor identity (a comm
   that isn't `claude`, `strace`, `sh`, `runc:*`, etc., nor a purely
   distinctive-worker comm like `Bun Pool N`).
3. Include additional pids whose comm history has a distinctive
   MCP-runtime identity (`libuv-worker`, `HTTP Client`, `V8Worker`,
   `MainThread`) without any ancestor identity.

The identifier works on all 10 pilot sessions (both benign and
malicious variants).

## Results

| Metric | v1 baseline | v2 (v1 + dotfile rule) | v3 (v1 + attribution) |
|---|---:|---:|---:|
| Coverage strict | 21.6% | 21.6% | 6.7% |
| Coverage noise-floor | 68.5% | 68.5% | **80.0%** |
| Rejection | 40.0% | 80.0% | 33.3% |

## Reading these numbers honestly

**Coverage noise-floor went UP** (68.5 → 80.0). Attribution filtering
removed a bunch of driver-caused syscalls the envelope shouldn't have
been penalized for — the envelope now scores against a cleaner target.

**Coverage strict went DOWN** (21.6 → 6.7). This is misleading and
expected: attribution filtering removes the read-heavy driver
bookkeeping which by pure count made "some fraction" of the envelope
match. Once you narrow to MCP-only syscalls, most of those are also
outside the envelope (because the envelope grammar can't enumerate
Python interpreter internals). Strict-whitelist without noise-floor
is not a viable enforcement semantics regardless.

**Rejection went DOWN** (40 → 33). This is the sharpest finding of the
run, and it reveals that the v1/v2 numbers were partly wrong for
subtle reasons:

- **`dc_cmd_injection`** used to reject at 100%. Under attribution,
  0/5 predicate matches are in the MCP subtree — the execve happened
  in some other process (probably Claude Code shell'd out to something
  after the desktop-commander tool returned data telling it to). The
  attack that "rejected cleanly" in v1/v2 was actually being caught
  because Claude Code itself made an unusual syscall, not because the
  MCP tool did anything wrong. **Attribution reveals this was NOT the
  MCP misbehaving.**

- **`aws_doc_redirect`** (124 sig matches in v1) reduces to 5 sig
  matches under attribution. The other 119 events came from Claude
  Code's Bun-based HTTP client making its own connect() calls, which
  the naive predicate-matching in v1 was counting as "attack events."
  These aren't MCP-caused; they're the agent driver's own network
  activity.

- **`zcaceres_fetch_redirect`** (110 → 34) — same story. Most of the
  supposed "attack connects" were Claude Code's own Bedrock/API
  traffic. Only 34 came from the MCP subtree.

## What v3 actually proved

**The v1/v2 "rejection rates" were partly measuring the wrong thing.**
When the enforcement compiler was scoring events across the whole
cgroup, some rejections were happening on events the MCP didn't cause,
and some "signature matches" were counting events that had nothing to
do with the MCP tool. Both directions.

Under attribution:

- Signature matches drop from 314 → 108 total in these 10 attacks
  (65% were previously mis-attributed)
- Rejections drop from 63 → 27 total (57% were previously catching
  events that weren't MCP-caused)

**The 40% v1 rejection number and the 80% v2 number were both
inflated** by ambiguity about what "the MCP is doing" means.

## Where this leaves the pilot

The honest state after v3:

- **Envelope framing does something real**: 33% of attacks are
  correctly rejected by a blind Opus-generated envelope with proper
  attribution and no compiler rules or IOC hand-tuning.
- **Coverage improved (80% noise-floor)** because we're no longer
  penalizing the envelope for driver-caused reads.
- **A separate signal-source finding**: my predicate-matcher was
  missing the `ip_prefix` predicate type (used by 3 connect-based
  attacks). The path_redirect number in v1/v2 was inflated because
  syscall-type-only matches were counted. Fixing this would drop v1
  and v2 rejection rates too, since those 234 events were mostly
  Claude Code's own connects. **Once you fix both the predicate
  matcher AND apply attribution, path_redirect signature-matches
  would drop to ~0** because our L3 sensor doesn't emit destination
  IP so the corrected predicate can't fire.

## What this means for the paper story

v1 → v3 delta says: **the envelope framing is a smaller signal than
we initially claimed, but the failure to see it earlier was a
measurement artifact, not a design flaw.**

What we can now say honestly:
- Attribution IS load-bearing. Without it, envelopes are being scored
  against driver noise and IOC-lookalikes are inflating numbers.
- The 33% v3 rejection rate is a real baseline against KERNEL-primary
  attacks on 10 sessions.
- Getting from 33% to a defensible number requires better envelope
  quality or additional signal sources — NOT compiler rules layered
  on top, which we now know were hiding attribution errors.

## Next honest step

The v2 dotfile rule needs to be re-evaluated in the attribution-filtered
world. Two ways it could go:

1. **v4 = v3 + dotfile rule.** If dotfile rule improves v3 baseline
   from 33% → some higher number, then the rule is doing real work
   *inside the MCP subtree*, not just fitting driver-side noise.
2. If the dotfile rule doesn't help (because the attack write-events
   were captured by attribution already), the rule was truly just
   an IOC.

That's the direct next comparison — one more evaluator run, no code
changes.
