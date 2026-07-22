#!/usr/bin/env bash
# run_benign_session.sh — one benign session with paired L1 + host traces.
#
# Sequence:
#   1. build image (idempotent)
#   2. start bpftrace host wildcard trace in background, capture PID
#   3. wait for bpftrace to attach (probe count > 0)
#   4. record wall-clock <-> monotonic offset
#   5. `docker run` the agent script; container stays alive until script exits
#   6. capture container id, host pid of dockerd child, cgroup path
#   7. wait for container exit
#   8. copy l1.strace out of container
#   9. stop bpftrace, gzip its output
#  10. write meta.json
#
# All artefacts land under captures/benign_<N>_<yyyyMMdd_hhmmss>/.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CAPTURES="$HERE/captures"
IMAGE="picot-layer1-agent:latest"
N="${1:-1}"

TS="$(date +%Y%m%d_%H%M%S)"
OUT="$CAPTURES/benign_${N}_${TS}"
mkdir -p "$OUT"

echo "[launcher] output dir: $OUT"

# --- build image (fast if cached) ---
echo "[launcher] building docker image $IMAGE"
docker build -q -t "$IMAGE" -f "$HERE/docker/Dockerfile" "$HERE" > "$OUT/docker_build.log"

# --- start container first (paused with `create + start` idiom) ---
# We need the container's cgroup id BEFORE launching bpftrace so we can
# filter in-kernel. `docker create` sets everything up without starting
# the entrypoint; we grab the cgroup, launch bpftrace, then `docker start`.
CONTAINER_NAME="picot_l1_agent_${N}_${TS}"
# Sentinel directory: host-side dir bind-mounted into container so we can
# create the sentinel file from the host without needing `docker exec`
# (which spawns runc:INIT + touch and adds ~600 events of container-
# mechanic overhead to our capture).
SENTINEL_HOST_DIR="$OUT/sentinel"
mkdir -p "$SENTINEL_HOST_DIR"

echo "[launcher] creating container $CONTAINER_NAME (not started)"
CID=$(docker create --name "$CONTAINER_NAME" \
    -v "$SENTINEL_HOST_DIR:/sentinel" \
    "$IMAGE")

# Start the container so we get a real pid+cgroup
docker start "$CID" > /dev/null

# capture pid + cgroup path
CPID=$(docker inspect -f '{{.State.Pid}}' "$CID")
CGROUP_PATH=$(awk -F: '{print $3}' /proc/"$CPID"/cgroup | head -1)
CGROUP_ID=$(stat -c%i "/sys/fs/cgroup${CGROUP_PATH}")
echo "[launcher] container pid=$CPID cgroup_path=$CGROUP_PATH cgroup_id=$CGROUP_ID"

# --- start host bpftrace ---
# Note: container has ALREADY started, so we miss the very first ~few ms
# of its syscalls. That's a known cost; acceptable for a diagnostic
# because the agent workload runs for hundreds of ms and the process
# tree is stable by the time we attach.
echo "[launcher] starting host bpftrace, cgroup=$CGROUP_ID"
HOST_TRACE="$OUT/l3_host.trace"
# Boost per-CPU perf ring buffer to 4096 pages (~16MB/CPU) so bursts of
# thousands of syscalls per ms don't drop events silently.
sudo -n env BPFTRACE_PERF_RB_PAGES=4096 \
    bpftrace -B full "$HERE/host_wildcard_trace.bt" "$CGROUP_ID" \
    > "$HOST_TRACE" 2> "$OUT/bpftrace.stderr" &
BT_PID=$!
echo "[launcher] bpftrace pid=$BT_PID"

# wait for BOOT line — signals probes are attached (tight poll to keep
# wall-clock capture within a few ms of BOOT so the offset is accurate)
for _ in $(seq 1 500); do
    if grep -q '^BOOT|' "$HOST_TRACE" 2>/dev/null; then break; fi
    sleep 0.01
done
if ! grep -q '^BOOT|' "$HOST_TRACE"; then
    echo "[launcher] ERROR: bpftrace did not attach within 5s"
    kill "$BT_PID" 2>/dev/null || true
    docker rm -f "$CID" > /dev/null || true
    exit 1
fi

# --- record wall-clock alignment ---
# Grab wall AS FAST AS POSSIBLE after BOOT line appears, then also read the
# monotonic nsecs from BOOT. Any delay between the two inflates offset.
WALL_EPOCH_NS="$(date +%s%N)"
MONO_NSECS="$(awk -F= '/^BOOT/{print $NF; exit}' "$HOST_TRACE")"
echo "[launcher] wall=$WALL_EPOCH_NS mono=$MONO_NSECS offset=$((WALL_EPOCH_NS - MONO_NSECS))"

# --- signal the agent to proceed ---
# Create sentinel file on host in the bind-mounted /sentinel dir. Agent's
# wait_for_sentinel is polling /sentinel/go. This avoids the runc:INIT +
# touch overhead of `docker exec` which would add ~600 events to our
# capture during the workload window.
sleep 0.1
echo "[launcher] signaling agent to run"
touch "$SENTINEL_HOST_DIR/go"

# --- wait for container exit ---
echo "[launcher] waiting for container to finish..."
docker wait "$CID" > "$OUT/exit_code.txt"

# --- copy L1 strace out ---
docker cp "$CID:/work/l1.strace" "$OUT/l1_container.strace" || echo "[launcher] WARN: no l1.strace found"

# --- container logs ---
docker logs "$CID" > "$OUT/container.stdout" 2> "$OUT/container.stderr"

# --- stop bpftrace ---
echo "[launcher] stopping bpftrace"
sudo -n kill -SIGINT "$BT_PID" 2>/dev/null || true
wait "$BT_PID" 2>/dev/null || true

# --- write meta.json ---
cat > "$OUT/meta.json" <<EOF
{
  "session_id": "benign_${N}_${TS}",
  "wall_epoch_ns": ${WALL_EPOCH_NS},
  "mono_boot_ns_at_wall_capture": ${MONO_NSECS},
  "offset_ns": $((WALL_EPOCH_NS - MONO_NSECS)),
  "container_id": "${CID}",
  "container_pid": ${CPID},
  "container_cgroup_path": "${CGROUP_PATH}",
  "container_cgroup_id": ${CGROUP_ID},
  "note": "host trace was filtered in-kernel to cgroup_id, so all events belong to the container subtree by construction"
}
EOF

# --- cleanup container ---
docker rm "$CID" > /dev/null || true

# --- compress the big one ---
gzip -f "$HOST_TRACE"

echo "[launcher] done. artefacts:"
ls -lh "$OUT/"
