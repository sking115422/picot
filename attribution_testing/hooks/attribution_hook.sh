#!/usr/bin/env bash
# Attribution-testing hook entrypoint. Thin bash wrapper that delegates
# to the python hook script. Uses the venv if present, otherwise falls
# back to system python3.
PY="$HOME/.cache/agenttrace/attribution_testing/.venv/bin/python3"
[ -x "$PY" ] || PY="$(command -v python3)"
exec "$PY" "$(dirname "$(readlink -f "$0")")/attribution_hook.py" "$@"
