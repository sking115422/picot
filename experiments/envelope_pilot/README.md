# Envelope Prediction Pilot

**Question:** Can an LLM produce a useful syscall envelope from a user
prompt + MCP tool schemas alone (blind — no observed syscalls), such
that the envelope (a) covers what benign agents actually do, and (b)
rejects the distinctive syscalls that malicious variants make?

## Design

- **Corpus:** 10 diverse benign+malicious pairs from ACE-C, spread
  across `anthropic_ref_servers`, `anthropic_awesome_mcp_servers`,
  and `rand_github`, covering file-heavy, exec-heavy, network,
  database, and mixed-I/O MCPs.
- **Generator:** Claude Opus 4.7 via Bedrock, given a JSON schema
  for the envelope grammar and 3 hand-written few-shot examples.
- **Envelope grammar:** semantic-capability schema —
  `file_ops.{read,write,delete}_paths`, `network.{allow_egress,
  allow_hosts, allow_ports}`, `process.{allow_spawn, allow_binaries}`,
  plus a one-sentence `rationale` field.
- **Blind mode:** the LLM sees the prompt + list of available MCP tool
  names. It does NOT see any actual syscalls.
- **Enforcement semantics evaluated:**
  - *strict*: any syscall not matched by an envelope rule is
    out-of-envelope.
  - *noise-floor*: reads under `/etc, /usr, /lib, /proc, /sys, /dev,
    /System, /opt, /root, /var/lib, /run, /tmp` always pass. These are
    Python/glibc/loader/SSL bookkeeping the envelope cannot be
    expected to enumerate.

## Findings (run 20260713_170724)

| Metric | Value | Note |
|---|---|---|
| Mean coverage (strict) | **15.3%** | expected — noise floor swamps envelope |
| Mean coverage (noise-floor) | **71.8%** | below the 95% target |
| Mean rejection on malicious signature-matches | **16.7%** | only 6 of 27 attacks had signature-matches in the trace |

### What the results actually mean

**Envelope generation itself works.** Opus produces well-scoped
envelopes: the `time` MCP gets a tight zoneinfo-only envelope; the
`git` MCP gets a git-spawn-with-.git-lockfile envelope; the
filesystem MCP gets exact-path allow-lists matching the two files
named in the prompt. Rationales are coherent, structure is clean,
grammar is respected.

**Coverage is bottlenecked by three things:**
1. Python/glibc bootstrap noise the envelope can't enumerate
   (mitigated by the noise-floor semantics)
2. Legitimate SSL cert reads that the noise floor covers but only
   with a prefix match — richer glob support would help
3. A handful of legitimate reads outside the noise-floor prefixes
   (e.g., agent config paths, `/home/ubuntu/...`)

**Rejection fails for architectural, not envelope-quality reasons:**
1. `/tmp/**` catch-all writes are correctly allowed for legitimate
   scratch usage — envelope grammar can't distinguish "legitimate
   scratch" from "credential exfil to `/tmp/.cred_log`". Needs finer
   granularity (e.g., filename-shape rules, "no dotfiles under
   `/tmp`", or path-content restrictions).
2. `connect` events in the L3 v2 sensor don't carry destination IP —
   the envelope can allow-list `docs.aws.amazon.com` but the sensor
   only tells us "some connect happened." The envelope can't gate on
   IP without a sensor extension.
3. Of 27 attacks tested, only 6 had signature-matches in the actual
   traces. The rest are APP-layer signals (e.g.,
   `app_tool_description_contains`) that l1_syscall predicates don't
   fire on. This is expected — many ACE-C attacks are meant to be
   detected at layers above kernel.

## Where the framing lands

The pilot **validates the shape of the design** — LLMs produce
sensible envelopes; envelopes compile into fast per-syscall checks;
noise floor is real and manageable — but **surfaces two concrete
gaps** before this becomes a working enforcement layer:

1. **Envelope granularity needs to be finer than one glob.**
   `/tmp/**` catches both good and bad; envelopes need to express
   "yes to `/tmp/scratch_*`, no to `/tmp/.dotfiles`" or similar.
   This is a grammar redesign, not a modeling limitation — the LLM
   is capable of expressing finer rules if the schema asks for them.
2. **Sensor needs to carry richer args, especially connect
   destination.** Otherwise network-layer enforcement is
   unenforceable regardless of envelope quality.

Neither is a showstopper. Both are v2 work.

## Files

- `select_sessions.py` — pick the 10 diverse benign+malicious pairs
- `extract_syscalls.py` — l3.jsonl → normalized events
- `envelope_schema.json` — envelope grammar (JSON Schema)
- `few_shot/examples.json` — 3 hand-written envelope demonstrations
- `generate_envelopes.py` — Opus 4.7 caller, produces envelopes
- `evaluate.py` — coverage + rejection metrics
- `results/run_<ts>/` — per-run artefacts
