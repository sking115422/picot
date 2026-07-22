# Layer 1 discrepancy diagnostic

**Question:** if we capture container syscalls (via `strace -f`
inside the container, treated as ground truth) and host syscalls
(via wildcard `raw_syscalls:sys_enter` bpftrace, cgroup-filtered
to the target container), how much of the container's syscall
stream is actually visible on the host?

This is the necessary first-order test before we build Layer 1 —
a learned filter that classifies host syscall events as agent- or
non-agent-attributable. If the host can't see what the container
sees, Layer 1 is trying to learn something that isn't there.

## Result (3 benign sessions, aggregated)

**Host and container syscall counts match at ~1.02 ratio across
3 sessions.** Per-session: 1.006, 1.006, 1.041.

Total host syscalls in the container's cgroup subtree during the
~50ms agent workloads (excluding strace and docker-exec artifacts):
**2,820**. Total container-side strace syscalls in the same windows:
**2,769**. Per-syscall breakdown matches at exactly 1.000 for every
common syscall (openat, close, read, write, mmap, socket, connect,
bind, sendto, etc.) with occasional ±2 event drift near workload
boundaries.

### Iteration path — what broke and how it was fixed

Getting to this number was NOT straightforward. Several artifacts
had to be identified and removed:

1. **strace's own overhead.** strace runs *inside* the container's
   cgroup, so its own `ptrace` / `wait4` / `process_vm_readv` /
   `write` syscalls (used to record the tracee's activity) get
   captured by the host bpftrace but do NOT appear in strace's own
   log. This is ~93% of the raw host trace volume. Exclude by
   `comm=="strace"`.

2. **docker exec artifacts.** Our original sentinel-file signaling
   used `docker exec touch /work/go`, which spawned `runc:[2:INIT]`
   and `touch` inside the container's cgroup, adding ~600 syscalls
   of pure container-mechanic overhead. Fixed by bind-mounting a
   `/sentinel` directory from the host and touching the sentinel
   file directly from the host launcher.

3. **bpftrace event loss under strace load.** With the default 64
   pages of perf ring buffer (~256KB/CPU), bpftrace silently
   drops events during high-load bursts. Fixed by
   `BPFTRACE_PERF_RB_PAGES=4096` (16MB/CPU).

4. **Wall-clock offset drift.** The launcher's naive
   `date +%s%N - $(bpftrace BOOT nsecs)` derivation gave an offset
   that was systematically ~70ms wrong due to the delay between
   bpftrace emitting BOOT and the launcher reading it back. Fixed
   in the analyzer by post-hoc offset recovery: match the first
   post-sentinel python3 execve on both sides and compute the true
   offset from that pair. Also widened the workload window to
   ±20ms of jitter buffer to absorb residual clock drift.

5. **Interpreter startup phase.** Python's interpreter init makes
   ~2100 syscalls before user code runs. These happen before the
   sentinel wait loop and are excluded from the workload-phase
   comparison.

### What this means for Layer 1

- The information-theoretic upper bound for host-based attribution
  of container syscalls is **~100%** for every syscall type we
  exercised: openat, read, write, close, socket, connect, bind,
  listen, accept4, recvfrom, sendto, execve, unlinkat, mmap,
  mprotect, futex, brk, ioctl, getpid, etc.
- The Layer 1 filter task is **well-posed**: for every syscall in
  the container, there is a corresponding host event with the same
  syscall number, timestamp (mod tracing overhead), and tgid.
- The task now is: distinguish agent-cgroup syscalls from
  everything else on the host. That's a much narrower problem
  than "reconstruct what the container did from partial signal."

### Follow-ups to consider

- Run *without strace* to remove strace as a variable and confirm
  the same 1.0 ratio holds. This is the true test — Layer 1 will be
  deployed against agents that aren't running under strace. The
  concern: does strace running perturb the host's syscall
  observability?
- Longer, more diverse workloads (5-10s, LLM-driven Claude Code
  session with hooks). This diagnostic uses a 50ms scripted
  workload; real MCP sessions are seconds long and syscall-heavier.
- The 2 syscalls we saw in host-not-strace (`clock_nanosleep`,
  `rt_sigreturn`) are boundary artifacts of the ±20ms jitter buffer.
  Not indicative of a real gap.

## Files

- `run_benign_session.sh` — launcher
- `container_agent_script.py` — scripted agent (10 tool-like ops)
- `host_wildcard_trace.bt` — bpftrace probe, cgroup-filtered
- `docker/Dockerfile` — minimal python + strace image
- `analysis/coarse_compare.py` — single-session per-syscall counter
- `analysis/aggregate_compare.py` — multi-session with offset recovery
- `captures/benign_<N>_<ts>/` — per-session artefacts

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/experiments/layer1_discrepancy
./run_benign_session.sh 1
./run_benign_session.sh 2
./run_benign_session.sh 3
python3 analysis/aggregate_compare.py captures
```

Requires: docker, bpftrace, sudo -n bpftrace working, /usr/include/x86_64-linux-gnu/asm/unistd_64.h.
