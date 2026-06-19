# Host-side attribution experiments

Five experiments answering: *can a host-only eBPF sensor (AgentShield-style)
recover per-session subprocess attribution and per-tool-call attribution as
reliably as in-container strace?*

L1 in-container strace is the oracle. L2_ext and L3 are host-side traces.

## Layout

```
attribution_testing/
├── common.py              shared trace loaders + namespace-aware comparators
├── e1_process_forest.py   pid-set / forest-shape recovery vs. L1
├── e2_syscall_attr.py     per-pid syscall counts vs. L1
├── e3_session_part.py     session boundaries without cgroup-per-session
├── e4_toolcall_attr.py    tool-call → pid/tid attribution
├── e5_concurrency.py      concurrent tool-call disambiguation
├── run_all.py             entry point that runs E1–E5 on a sample
└── results/               per-experiment metric JSON + summary markdown
```

## Reproduce

```bash
cd /lts/ai_sec_exp/picot/attribution_testing
python3 run_all.py --sample 50
```

Outputs land in `results/`. Headline numbers go in
`results/SUMMARY.md`.

## Key gotcha

L1 strace runs *inside* the container; its pids are container-namespace
pids. Host eBPF emits host-namespace pids. We bridge them by matching
clone/execve events on `ts_ns` (wall clock from `strace -ttt` aligns
with `CLOCK_REALTIME` from eBPF). The bridge itself is one of the things
under test in E1.
