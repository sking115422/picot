#!/usr/bin/env bash
# Install the attribution-testing hooks for Claude Code.
#
# What this does:
#   1. Backs up ~/.claude/settings.json to settings.json.bak.<timestamp>
#   2. Replaces any existing 'hooks' block with one that registers our
#      attribution_hook.sh for SessionStart, UserPromptSubmit, PreToolUse,
#      PostToolUse, and Stop events.
#   3. Prints what changed and how to revert.
#
# Run with no arguments. Set ATTR_HOOKS_DRY_RUN=1 to preview without
# modifying anything.

set -euo pipefail

HOOKS_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
HOOK_SH="$HOOKS_DIR/attribution_hook.sh"

SETTINGS="$HOME/.claude/settings.json"
BACKUP="$SETTINGS.bak.$(date +%Y%m%d_%H%M%S)"

if [ ! -f "$SETTINGS" ]; then
    echo "error: $SETTINGS does not exist; nothing to patch" >&2
    exit 1
fi

if [ ! -x "$HOOK_SH" ]; then
    echo "error: $HOOK_SH not executable" >&2
    exit 1
fi

# Build the new hooks block as JSON. Five events all routed to one
# hook script — the script dispatches based on hook_event_name.
NEW_HOOKS=$(python3 - "$HOOK_SH" <<'PY'
import json, sys
hook_cmd = sys.argv[1]
events = ["SessionStart", "UserPromptSubmit", "PreToolUse",
          "PostToolUse", "Stop", "SessionEnd"]
block = {}
for ev in events:
    block[ev] = [{
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": hook_cmd,
            "timeout": 5000,
        }],
    }]
print(json.dumps(block))
PY
)

# Merge: load existing settings, replace .hooks, write back.
DRY_RUN="${ATTR_HOOKS_DRY_RUN:-0}"

if [ "$DRY_RUN" = "1" ]; then
    echo "DRY RUN — would write the following hooks block to $SETTINGS:"
    echo "$NEW_HOOKS" | python3 -m json.tool
    echo
    echo "DRY RUN — no changes made."
    exit 0
fi

cp "$SETTINGS" "$BACKUP"
echo "backed up $SETTINGS -> $BACKUP"

python3 - "$SETTINGS" "$NEW_HOOKS" <<'PY'
import json, sys
settings_path, new_hooks_json = sys.argv[1], sys.argv[2]
with open(settings_path) as f:
    settings = json.load(f)
settings["hooks"] = json.loads(new_hooks_json)
with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
print("hooks block in", settings_path, "replaced.")
PY

echo
echo "installed. To revert: cp $BACKUP $SETTINGS"
echo
echo "Hooks are registered for: SessionStart, UserPromptSubmit,"
echo "PreToolUse, PostToolUse, Stop, SessionEnd."
echo
echo "Events will be written to ~/.cache/agenttrace/attribution_testing/"
echo "Restart any active Claude Code session to pick up the new hooks."
