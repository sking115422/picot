# v6a Tiered Analysis — Envelope Contribution After App-Layer Filtering

## Motivation

Envelope enforcement is positioned as complementary to an app-layer
filter, not a standalone defense. This analysis quantifies envelope's
marginal contribution under three assumed app-layer strengths.

## Tier definitions

- **Tier 0 (no app-layer filter):** all attacks in the corpus are
  scored against envelope enforcement alone.

- **Tier 1 (minimal app-layer filter):** removes attacks whose
  malicious intent is literally in the user prompt (`user_direct_*`
  categories: write directive, cred exfil, bash injection). These are
  what any reasonable prompt-inspection filter catches. Uses
  `{{sentinel_*}}` placeholders in the prompt text itself.

- **Tier 1+2 (competent app-layer filter with content inspection):**
  additionally removes attacks whose malicious intent is in content
  the agent retrieves (retrieval_reference_injection,
  web_bash_injection, file_bash_injection, mem_*, resource_*). These
  are what an AgentSight-shaped filter with TLS uprobe + response
  inspection catches (per their Case Study 1).

- **Residual after Tier 1+2:** ace_c (MCP supply-chain tampering,
  invisible to app-layer by design) + file-based directives where the
  malicious content is deeply subtle.

## Results (v6a enforcement, first-hit stopped rate)

| Tier | N sessions | ace_c | ace_bi | Combined |
|---|---:|---:|---:|---:|
| Tier 0 (no filter) | 762 | 90.1% | 70.9% | 83.1% |
| Tier 1 removed | 653 | 90.1% | 52.1% | 80.2% |
| Tier 1+2 removed | 539 | 90.1% | 36.4% | 84.6% |

## What each number means

**ace_c stopped rate: 90.1% regardless of tier.**

MCP supply-chain attacks are invisible to app-layer filters — the
malicious code sits inside the MCP tool's implementation, not in the
prompt/response/content the app-layer inspects. This is envelope's
uncontested territory.

**ace_bi stopped rate drops as tier tightens (71% → 52% → 36%).**

This is expected and important. As we remove app-layer-catchable
attacks from the evaluation set, what remains is progressively harder
for envelope enforcement:

- Tier 0 → Tier 1 removes user_direct_* (envelope catches all of
  these too — the LLM refuses to include the requested paths in
  write_paths). Removing them shifts the ace_bi residual to
  content-visible attacks where envelope's argv-inspection catches
  ~52%.
- Tier 1 → Tier 1+2 removes retrieval/web/file/mem injection
  categories where envelope's argv-inspection was most effective
  (v6a lifted web_bash_injection from 0% to 100%, retrieval_ref from
  0% to 50%). What remains is `file_write_directive` and
  `file_cred_exfil` — direct Write tool calls without bash routing —
  where envelope's argv-inspection has nothing to bite on.

## The 55-session ace_bi residual

After Tier 1+2 filtering, only 55 ace_bi sessions remain:

| Category | n | First-hit stopped |
|---|---:|---:|
| file_write_directive | 53 | 37.7% |
| file_cred_exfil | 2 | 0.0% |

**These are subtle content-injection attacks that a competent
app-layer filter might catch if it deeply inspects retrieved file
contents.** The malicious payload is buried in a README or docs file
the agent reads for a legitimate reason. The agent complies with an
embedded instruction to write to a sentinel audit-log path.

Envelope catches these when `write_paths` doesn't cover the audit-log
path (~38% of the time). It misses them when the envelope's generated
`write_paths` happens to allow paths that include the audit-log path.

## What the paper claim actually is

**Naive claim (Tier 0):** "Envelope enforcement stops 83% of attacks
across the ACE corpus."

Correct but uses envelope for work the app-layer trivially handles.

**Better claim (Tier 1+2 split):**

> **Composed with a competent app-layer filter, envelope enforcement
> catches 90% of MCP supply-chain attacks (invisible to app-layer) and
> 36% of built-in-tool attacks that survive app-layer inspection.**
> Coverage on benign workloads holds at 87.7%.

This is the honest cross-layer story. It gives credit to the app-layer
for what app-layer catches, and quantifies what envelope adds on top.

## Where envelope's contribution is unambiguous

- **MCP supply-chain attacks** — the paper's primary threat model.
  App-layer sees benign prompt + legitimate tool call; malicious code
  is in the tool implementation. Envelope catches 90% first-hit at
  97.5% benign coverage.

## Where envelope's contribution is smaller but real

- **File-based directive attacks** (subtle content injection leading
  to direct writes). Envelope catches ~38% first-hit. App-layer might
  or might not catch these depending on filter quality; envelope is
  the reliable backstop.

## Where envelope is not the right layer

- **User-prompt-visible attacks** (user_direct_*). App-layer's job.
  Envelope happens to catch 100% because the LLM refuses to
  include suspicious paths in the envelope, but this is redundant with
  app-layer defense.
- **Content-injection attacks with visible malicious payload**
  (retrieval_ref, web_bash_injection). App-layer with content
  inspection is the right layer. Envelope adds partial coverage
  (36-100% depending on attack shape) but isn't the primary catch.

## Numbers to quote in the paper

- **ace_c first-hit stopped: 90.1%** across 484 attacks / 66 unique
  attack slugs. Coverage 97.5% benign.
- **Combined against all attacks: 83.1%.**
- **Composed with competent app-layer filter (Tier 1+2 residual):**
  90.1% ace_c + 36.4% ace_bi = 84.6% of residual attacks stopped by
  envelope.
