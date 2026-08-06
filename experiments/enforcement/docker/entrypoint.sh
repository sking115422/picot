#!/bin/bash
# entrypoint.sh — wrapper that runs a command under envelope_supervisor.
#
# Usage:
#   docker run ... image [--envelope /work/envelopes/foo.json] -- <cmd> [args...]
#
# If --envelope is omitted, supervisor runs in observation mode
# (all syscalls allowed, syscalls logged).
#
# Requires the container to be started with:
#   --security-opt seccomp=unconfined --cap-add=SYS_PTRACE
# so we can install a new seccomp filter and read /proc/<pid>/mem.

set -eu

ENV_ARG=()
if [ "${1:-}" = "--envelope" ]; then
  ENV_ARG=(--envelope "$2")
  shift 2
fi

# Peel off a leading `--` if present (docker convention).
if [ "${1:-}" = "--" ]; then
  shift
fi

if [ $# -eq 0 ]; then
  echo "usage: $0 [--envelope PATH] [--] CMD [ARGS...]" >&2
  exit 2
fi

exec /opt/supervisor/envelope_supervisor "${ENV_ARG[@]}" "$@"
