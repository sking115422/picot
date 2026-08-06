# Envelope prompt versions

## Terminology (important)

There are **two dimensions** of versioning, easy to confuse:

- **Prompt style (v1, v5, ...)** — controls what the LLM outputs
  (envelope shape / grammar / specificity).
- **Enforcement rule (v5, v6a, ...)** — controls how the compiler
  turns the envelope into kernel decisions.

The two dimensions are independent. The full-corpus run used:
  prompt style **v5** + enforcement rule **v6a**.

## v6a is an enforcement rule, not a prompt

There is no `SYS_PROMPT_V6` in `generate_envelopes.py`. What we call
"v6a" is a compiler upgrade that lands entirely in the enforcement
supervisor:

- v5 enforcement: at execve, only check whether the binary is in
  `allow_binaries`.
- v6a enforcement: same binary check PLUS extract path-like and
  host-like tokens from `argv` (shell-decomposing `bash -c` payloads)
  and require each token to be covered by the envelope's declared
  positive surface (`read_paths ∪ write_paths ∪ delete_paths` for
  paths, `allow_hosts` for hosts).

v6a reuses the same v5-generated envelopes with no LLM changes. Our
C supervisor already implements v6a
(`enforcement/supervisor/envelope_supervisor.c:288-326`), which is
why the corpus run hit 96.8%.

See `../ace_full/FINDINGS_v6a.md` for the v6a design and its impact
in the observation-only pilot (+17.7 pts ace_bi first-hit-stopped).

## Files here

- `v5_system_prompt.txt` — **the LLM prompt currently in use.**
  Exactly what `generate_envelopes.py --style v5` sends. Full
  corpus run of 2026-07-27 used this + v6a enforcement.
  Result: 1306/1349 (96.8%) attacks stopped. All 43 misses trace
  to a permissive `**/*.log` write glob.

- `v7_system_prompt_PROPOSED.txt` — **proposal, not built.**
  Tightens the v5 SPECIFICITY REQUIREMENT so extension-only
  recursive globs (`**/*.log`, `**/*.json`, ...) are also
  rejected, and caps write_paths at 12 entries. Named v7 to avoid
  clashing with the existing v6a enforcement-side naming.

## What running v7 would look like

1. Add `SYS_PROMPT_V7` and a `--style v7` branch in
   `generate_envelopes.py`.
2. Regenerate envelopes for the 10 failing keys (cheap) or all
   446 keys (~$5-15 of Opus/Bedrock).
3. Rerun `batch_replay.py` under existing v6a enforcement.
4. Compare the miss rate; misses should drop from 43 → near-zero
   if the diagnosis is correct.

## Placeholders

Both prompt files contain `{schema_json}` and `{examples_block}` —
Python format-string placeholders that `build_system_prompt()` in
`generate_envelopes.py` substitutes at call time with:

- `{schema_json}` → contents of `envelope_pilot/envelope_schema.json`
- `{examples_block}` → contents of `envelope_pilot/few_shot/examples.json`
  formatted as `Example N: PROMPT / TOOLS AVAILABLE / ENVELOPE: {...}`

The fully-rendered v5 prompt Opus actually saw is saved verbatim at
`envelope_pilot/ace_full/results/run_20260721_172946_full_v5/system_prompt.txt`.
