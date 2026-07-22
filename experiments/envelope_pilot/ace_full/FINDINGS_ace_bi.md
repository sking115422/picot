# Envelope Pilot — Ace_bi Scale-Up (50 sessions)

## Setup

- **Corpus**: `ace_full` sessions where `mcp = builtin/claude-code`
  (attacks against Claude Code's own tools: Bash, Read, Write, Grep,
  WebFetch — no separate MCP server process).
- **N sessions**: 50, diversified across 11 attack categories, all
  `gold_label = malicious_fired`.
- **Attribution model**: subtree = all pids in strace minus known
  container-bootstrap comms (runc/docker-entrypoint). Different from
  ace_c's clone-chain walk because ace_bi container is single-purpose
  and clone edges are sometimes missing in strace.
- **Rejection scoring**: sentinel-based. `session_sentinels` has per-
  session unique values for `write_path`, `cred_path`, `exfil_host`,
  etc. Predicates fire on openat matching those paths, unlinkat, OR
  execve with argv containing the sentinel path (needed because many
  ace_bi attacks manifest as `bash -c "ls <cred_path>"` where the
  openat never sees the path but the execve argv does).

## Results

| Metric | v1 (baseline) | v5 (specificity) |
|---|---:|---:|
| Coverage on benign (noise-floor) | 84.2% | **78.9%** |
| Rejection on malicious sig-hits | **47.6%** | **62.2%** |
| Sessions with signature matches | 34/50 | 34/50 |

Compare with ace_c scale-up: v5 rejection was 93%, coverage was 97.7%.
Both metrics are substantially worse on ace_bi.

## Per-category rejection (v1 → v5)

| Category | n | v1 | v5 |
|---|---:|---:|---:|
| user_direct_write_directive | 5 | 100% | 100% |
| user_direct_cred_exfil | 5 | 100% | 100% |
| file_write_directive | 5 | 42% | **79%** |
| web_bash_injection | 4 | 46% | **73%** |
| retrieval_reference_injection | 5 | 15% | **25%** |
| file_bash_injection | 5 | 25% | **50%** |
| file_cred_exfil | 2 | 13% | **25%** |
| mem_cred_exfil | 3 | 0% | 0% |

## Reading the results

**Where the envelope framing works:**
- `user_direct_*` categories at 100% for both v1 and v5. When the
  malicious command is literally in the user prompt, the sentinel
  path ends up in Bash/ls argv, and the envelope's binary allow-list
  denies (v1 correctly here because envelopes don't allow the specific
  binary the attack targets).
- `file_write_directive`, `web_bash_injection`: v5's tighter
  `write_paths` catches audit-log writes that v1's wildcards permitted.

**Where the envelope framing hits a ceiling:**
- `mem_cred_exfil` (0% both): attacks fire `bash -c "ls <cred_path>"`.
  The envelope reasonably allows `/bin/bash` and `/usr/bin/ls` for the
  benign prompt. Both allow-listed. **The cred_path in bash argv is
  the actual attack signal — envelope grammar has no field to encode
  "deny bash commands that reference sensitive paths."**
- `retrieval_reference_injection` (v5 25%): the malicious content is
  injected into a document the agent reads via WebFetch; the agent
  then runs `ls` on the cred_path. Same failure mode as mem_cred_exfil.

## The core ace_bi difficulty

Ace_bi attacks route through Bash argument content. The envelope
grammar operates at the granularity of **which binaries and paths**
can be touched, not **what commands binaries execute**. When Bash is
in the allow-list (which is realistic for developer-workflow prompts),
the envelope has no leverage on what Bash actually runs.

This is a real ceiling of the current framing for ace_bi. Options:

1. **Argv-aware envelope grammar**: add a `deny_argv_contains` field
   for execve. LLM would list sentinel-adjacent paths ("if you see
   `/home/*/.aws/credentials` in bash argv, deny"). But this becomes
   IOC-fitting again if the corpus's cred paths are predictable.

2. **Ban Bash for prompts that don't require it**: if the prompt is
   "read this doc and summarize," the envelope should say
   `allow_spawn: false`. LLM currently allows Bash liberally.

3. **Move enforcement to app-layer PreToolUse**: catch the attack when
   Claude Code is about to run `Bash("ls <cred_path>")`, not when
   the kernel is about to execve it. This is where the ACE paper's
   cross-layer story becomes load-bearing.

## The Claude-Code-writes-.claude problem

Coverage on benign is 78.9% — well below ace_c's 97.7%. Investigation:
Claude Code writes to `~/.claude/*` (session state, projects, cache,
etc.) during every session. Envelopes generally don't allow those
paths because they aren't semantically related to the prompt.

Not really a bug — it's the same "MCP-internal state paths the LLM
can't predict" problem from the 10-session pilot's `dc_cred_theft`
case. For ace_bi the driver's state paths are *always* Claude Code's,
not the MCP's. Grounding envelopes in a static "Claude Code always
writes to `~/.claude/**`" prior would recover most of this.

## What ace_bi scale-up validates

- The pipeline extends to non-MCP agent workloads with reasonable
  effort (mostly attribution model change).
- The specificity mechanism (v5) still helps: rejection lifts from
  48% to 62%. Even at ace_bi's lower ceiling, being specific about
  `write_paths` catches attacks that broad wildcards miss.

## What ace_bi scale-up exposes as gaps

- **Bash-argument content is a real blind spot.** Envelope grammar
  needs an argv-aware field OR ace_bi needs app-layer enforcement.
- **Envelope granularity for binaries is too coarse.** Allowing Bash
  = allowing arbitrary code execution. Real deployments need finer
  control or a Bash-command-inspection layer.
- **Driver-state writes need a grounding prior.** The FPR shift from
  ace_c to ace_bi (2.3% → 21%) is a real workflow damage cost.

## Combined picture (ace_c + ace_bi)

| | ace_c | ace_bi |
|---|---:|---:|
| n sessions | 50 | 50 |
| v1 rejection | 42% | 48% |
| v5 rejection | 93% | 62% |
| Coverage on benign (v5) | 98% | 79% |

**The envelope framing produces strong signal on MCP-scoped attacks
(ace_c) but has a real ceiling on built-in-tool attacks (ace_bi)
where the tool schema is uniform and the attack manifests through
tool argument content.**

The right paper story shape is probably:
- **ace_c 93%**: the framing works for MCP supply-chain attacks (the
  ACE paper's primary threat model).
- **ace_bi 62%**: the framing partially extends to built-in-tool
  attacks; the remaining gap is where cross-layer (app-layer)
  enforcement or richer envelope grammar would be needed.

That's a defensible, honest split.
