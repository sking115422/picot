#!/usr/bin/env bash
# Launch Kuzu Explorer against one of our captured graphs.
#
# Usage:
#   ./explorer.sh                       # uses default graph (cgroup_smoke)
#   ./explorer.sh path/to/graph.kz      # explicit path
#
# Then open http://localhost:8000 in a browser.
# Stops with Ctrl-C.
#
# The Kuzu file gets mounted RO into the container at /database. The
# container exposes the explorer UI on port 8000 by default.

set -euo pipefail

GRAPH="${1:-kuzu_graphs/cgroup_smoke.kz}"

if [ ! -e "$GRAPH" ]; then
    echo "graph file not found: $GRAPH" >&2
    exit 1
fi

GRAPH_ABS="$(realpath "$GRAPH")"
GRAPH_DIR="$(dirname "$GRAPH_ABS")"
GRAPH_FILE="$(basename "$GRAPH_ABS")"

echo "Mounting $GRAPH_DIR as /data (read-only)"
echo "Database file: /data/$GRAPH_FILE"
echo "Open http://localhost:8000 to use the Explorer UI."
echo "Press Ctrl-C to stop."
echo

# --rm: clean up after exit
# -p 8000:8000: expose explorer's HTTP UI
# -v: bind-mount the parent directory so the kuzu single-file DB is
#     accessible at /data/<name>.kz inside the container.
# KUZU_FILE points the explorer's loader at the .kz file inside the
# mounted directory.
# MODE=READ_ONLY: tells explorer to open the DB read-only.
docker run --rm -p 8000:8000 \
    -v "$GRAPH_DIR":/data:ro \
    -e KUZU_DIR=/data \
    -e KUZU_FILE="$GRAPH_FILE" \
    -e MODE=READ_ONLY \
    kuzudb/explorer:latest
