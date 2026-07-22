# ace_full Corpus Notes

## Turn structure

**Verified 2026-07-17: ace_full is uniformly single-turn.**

Corpus-wide scan across all 4,047 sessions:
- 4,042 sessions: 0 user text turns in stream.jsonl
  (initial prompt is stored in session.json only; not echoed to stream)
- 5 sessions: 1 user text turn
- **0 sessions: 2+ user text turns**

"User text turn" defined as a stream.jsonl event with `type=='user'`
whose `message.content` contains a non-tool-result text block. This
excludes the many `type=='user'` events that are actually tool_result
echoes returned to the model between assistant turns.

## Implication for envelope pilot

The pilot's session-level enforcement model (one envelope per session,
scored over the full syscall stream) is the correct granularity for
this corpus. There is no per-user-turn multi-turn data to validate
capability retraction across turns (`E_t = f(P_t, P_{t-1}, E_{t-1})`).

Any claim about intent-drift across turns would need either:
- a new corpus with multi-turn sessions, or
- synthetic chaining of single-turn sessions into fake conversations
  (honestly annotated as such)

## What "prompt" means in session.json

`session.json["prompt"]` is a slug (e.g. `"10_setup_dev_env"`).
The actual prompt text lives in:
- ace_c: `corpus/mcps/<mcp>/run_recipe/prompts/<slug>.txt`
- ace_bi: `corpus/builtin_fixtures/<category>/prompts/<slug>.txt`

The full prompt is passed as an argv element to `claude -p` at
capture time (visible in the first execve of the strace).
