"""E6 — Multi-level attribution under cross-session merge.

Test the mechanism Spencer/Mikhail asked about: given an arbitrary host
trace (multiple sessions, different MCPs, no cgroup-per-session shortcut),
can we pick out which events belong to which session, MCP, and tool call?

The attribution mechanism uses ONLY kernel-observable signals — no
ground-truth timestamps, no source-file labels, no peeking at session.json
or stream.jsonl from the source sessions during prediction.

Mechanism per level:

- **Session**: walk events in ts order; every `execve` whose argv contains
  "claude" and "-p" opens a new session. pids inherit session via
  clone/clone3/execve from their parent.

- **MCP**: same shape, one level deeper. `execve` whose argv0 basename
  matches `mcp-server-*` (or `node|python|uvx <script>` where the script
  name contains mcp+server) opens a new MCP node, scoped to the current
  session of the calling pid. Descendants inherit.

- **Tool call**: `sendto` events whose `buf_b64` decodes to JSON
  containing `"method":"tools/call"` open a tool-call boundary. The tool
  name and the agent's `tool_use_id` are extracted from the JSON. The
  end of the tool call is the next sendto from the MCP server pid back
  to the agent containing `"id":<request_id>`.

Ground truth (NOT used during prediction, only for scoring):
- For each event in the merged stream we know its source session id
  (from which captured slice the event came), the source's MCP name,
  and a tool-call id range determined by the source session's
  stream.jsonl (used only for scoring, never for prediction).

Output: per-trial scores at session/MCP/tool-call levels, aggregated
across 10 trials.
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import re
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime
from math import comb
from pathlib import Path

from common import find_sessions, load_session

RESULTS = Path(__file__).parent / "results"
RESULTS.mkdir(exist_ok=True)


# ----- merging ------------------------------------------------------

@dataclass
class MergedEvent:
    event: dict          # the v1 envelope event
    src_session: str     # ground-truth session id (for scoring)
    src_mcp: str         # ground-truth MCP name
    src_tool_call: str   # ground-truth tool-call id, or "" if not in any


def _source_subtrees(events: list[dict],
                       enable_claude_mcp_add: bool = True
                       ) -> tuple[set[int], dict[int, set[int]]]:
    """For a single source session's host events, return:

    - session_pids: pid set in the session subtree (rooted at the
      claude execve, descendants via clone/clone3/execve).
    - mcp_subtrees: {mcp_root_pid -> descendant pid set}.

    This is computed from the source's own host trace for use as
    GROUND TRUTH only (not used during prediction)."""
    # Walk events in ts order, maintain pid->parent and execve-history.
    by_ts = sorted(events, key=lambda e: e.get("ts_ns", 0))
    # (caller_pid, ts, caller_cgroup) — cgroup is the load-bearing
    # tightening signal: we reject clone-window inheritance whose
    # candidate child has a different cgroup than the caller.
    last_clone_caller: tuple[int, int, int | None] | None = None
    parent: dict[int, int] = {}
    pid_execve_history: dict[int, list[str]] = defaultdict(list)
    # Track which pids have an authoritative parent edge from a v2
    # sched_fork event in the trace. These pids skip the timing-window
    # heuristic so we don't second-guess the kernel.
    parent_authoritative: set[int] = set()

    for e in by_ts:
        ev = e.get("event")
        pid = e.get("pid")
        ts = e.get("ts_ns", 0)
        cgid = e.get("cgroup_id")
        if pid is None:
            continue
        # v2 path: sched_fork carries authoritative parent->child.
        if ev == "sched_fork":
            args = e.get("args") or {}
            ppid = int(args.get("parent_pid", 0))
            cpid = int(args.get("child_pid", 0))
            if ppid and cpid and ppid != cpid:
                parent[cpid] = ppid
                parent_authoritative.add(cpid)
            continue
        # v1 path / fallback: timing-window inheritance, but skip if
        # the pid already has an authoritative parent.
        if (pid not in parent
                and pid not in parent_authoritative
                and last_clone_caller is not None):
            ccpid, cts, ccg = last_clone_caller
            if (ts - cts < 200_000_000
                    and (ccg is None or cgid is None or ccg == cgid)):
                parent[pid] = ccpid
        if ev == "execve":
            args = e.get("args") or {}
            argv = args.get("argv") or []
            argv0 = argv[0] if argv else args.get("path", "")
            pid_execve_history[pid].append(argv0)
            # Also accumulate argv1 for wrapper-bin patterns
            if len(argv) > 1:
                pid_execve_history[pid].append(argv[1])
        if ev in ("clone", "clone3"):
            last_clone_caller = (pid, ts, cgid)

    # Find session root pids — any execve into claude bin
    session_roots: set[int] = set()
    mcp_roots: set[int] = set()

    # Layered MCP detection on this source session: walk all execves
    # in ts order, feed them through the detector. Promotes registered
    # binaries to mcp_roots; broadened-regex matches also count as
    # roots (we don't have structural verification here since this is
    # ground-truth construction).
    from mcp_detector import StructuralState, layered_is_mcp_root
    state = StructuralState(enable_claude_mcp_add=enable_claude_mcp_add)
    by_ts_execves = sorted(
        (e for e in events if e.get("event") == "execve"),
        key=lambda e: e.get("ts_ns", 0),
    )
    for e in by_ts_execves:
        args = e.get("args") or {}
        argv = args.get("argv") or []
        if argv and argv[0].rsplit("/", 1)[-1] == "claude":
            # Treat any claude execve (with -p) as session root,
            # consistent with predict()'s session-root rule.
            if any(a in ("-p", "--print") for a in argv):
                session_roots.add(e.get("pid"))
        ok, label, layer = layered_is_mcp_root(args, state)
        if ok:
            mcp_roots.add(e.get("pid"))

    # Build descendant closure
    children: dict[int, set[int]] = defaultdict(set)
    for c, p in parent.items():
        children[p].add(c)

    def descendants(root: int) -> set[int]:
        out: set[int] = {root}
        frontier = {root}
        while frontier:
            nxt: set[int] = set()
            for p in frontier:
                nxt |= children.get(p, set()) - out
            out |= nxt
            frontier = nxt
        return out

    session_pids: set[int] = set()
    for r in session_roots:
        session_pids |= descendants(r)
    mcp_subtrees: dict[int, set[int]] = {
        r: descendants(r) for r in mcp_roots
    }
    return session_pids, mcp_subtrees


def _stream_tool_windows(stream_path: Path) -> list[tuple[int, int, str]]:
    """Read stream.jsonl and produce [(t_lower_ns, t_end_ns, tool_use_id)]
    for ground-truth tool-call windowing of the source session.

    LOOSE definition: each window runs from the previous tool_result
    timestamp (or 10s before this tool_result for the first call) to
    this tool_result timestamp. This includes agent reasoning time and
    LLM API traffic between calls, so the recall denominator is
    inflated relative to the actual tool-execution period.

    Use _hook_tool_windows() instead when hook data is available.

    Used only for ground-truth labeling, never for prediction.
    """
    out: list[tuple[int, int, str]] = []
    if not stream_path.exists():
        return out
    last_boundary = 0
    pending: dict[str, tuple[int, str]] = {}
    for line in stream_path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
        contents = (msg.get("content") or []) if msg else []
        for c in contents:
            if c.get("type") == "tool_use":
                pending[c.get("id")] = (last_boundary, c.get("id"))
            elif c.get("type") == "tool_result":
                tu_id = c.get("tool_use_id")
                ts_iso = rec.get("timestamp")
                if tu_id in pending and ts_iso:
                    lo, _ = pending.pop(tu_id)
                    dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                    t_end = int(dt.timestamp() * 1_000_000_000)
                    out.append((lo if lo > 0 else t_end - 10_000_000_000, t_end, tu_id))
                    last_boundary = t_end
    return out


def _hook_tool_windows(session_dir: Path) -> list[tuple[int, int, str]]:
    """Tight tool-call windows from PreToolUse/PostToolUse hook events.

    Each window is exactly (PreToolUse.ts, PostToolUse.ts) for a given
    tool_use_id. This is the actual kernel-visible tool-execution
    period — no agent reasoning time, no LLM API traffic.

    Returns [] if no hook events file exists for this session.
    """
    from agent_layer_hooks import HOOK_OUT_ROOT, _claude_session_id
    hook_sid = _claude_session_id(session_dir)
    if not hook_sid:
        return []
    hp = HOOK_OUT_ROOT / f"{hook_sid}.events.jsonl"
    if not hp.exists():
        return []
    pending: dict[str, int] = {}
    out: list[tuple[int, int, str]] = []
    for line in hp.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        h = ev.get("hook", "")
        ts_ns = int(float(ev.get("ts", 0)) * 1_000_000_000)
        tu_id = ev.get("tool_use_id", "")
        if not tu_id:
            continue
        if h in ("PreToolUse", "preToolUse"):
            pending[tu_id] = ts_ns
        elif h in ("PostToolUse", "postToolUse"):
            t0 = pending.pop(tu_id, None)
            if t0 is not None:
                out.append((t0, ts_ns, tu_id))
    return out


def _tool_windows(session_dir: Path,
                  prefer: str = "auto") -> tuple[list[tuple[int, int, str]], str]:
    """Unified ground-truth tool-call window builder.

    Returns (windows, source) where source is "hooks" or "stream".

    prefer:
      "auto"   -> hooks if available, else stream (default)
      "hooks"  -> hooks only; [] if no hook data
      "stream" -> stream-only loose definition
    """
    if prefer == "stream":
        return _stream_tool_windows(session_dir / "stream.jsonl"), "stream"
    hw = _hook_tool_windows(session_dir)
    if hw:
        return hw, "hooks"
    if prefer == "hooks":
        return [], "hooks"
    return _stream_tool_windows(session_dir / "stream.jsonl"), "stream"


def merge_sessions(sessions: list, layer: str,
                     enable_claude_mcp_add: bool = True) -> list[MergedEvent]:
    """Concat N sessions' host events into one stream, sorted by ts.

    Ground-truth labels are tight:
    - src_session: the session id, ONLY for events whose pid is in
      that session's claude-execve subtree. Pre-claude noise (runc,
      docker-entrypoint) gets src_session="".
    - src_mcp: the MCP name, ONLY for events whose pid is in the
      session's mcp-server subtree. Agent-process events get
      src_mcp="".
    - src_tool_call: the tool_use_id, ONLY for events that are in
      an MCP subtree AND fall in a stream.jsonl tool-call window.
    """
    SHARED = 999_999
    merged: list[MergedEvent] = []
    for s in sessions:
        events = s.l3 if layer == "l3" else s.l2ext
        sid = s.meta.get("session_id", s.session_dir.name)
        mcp_name = s.meta.get("mcp", "")
        windows = _stream_tool_windows(s.session_dir / "stream.jsonl")
        session_pids, mcp_subtrees = _source_subtrees(
            events, enable_claude_mcp_add=enable_claude_mcp_add,
        )
        # Flatten MCP pid set for quick lookup
        mcp_pids: set[int] = set()
        for st in mcp_subtrees.values():
            mcp_pids |= st

        for e in events:
            ev = dict(e)
            ev["cgroup_id"] = SHARED
            ts = ev.get("ts_ns", 0)
            pid = ev.get("pid")
            in_session = pid in session_pids
            in_mcp = pid in mcp_pids
            tc_id = ""
            if in_mcp:
                for lo, hi, tu in windows:
                    if lo <= ts <= hi:
                        tc_id = tu
                        break
            merged.append(MergedEvent(
                event=ev,
                src_session=sid if in_session else "",
                src_mcp=mcp_name if in_mcp else "",
                src_tool_call=tc_id,
            ))
    merged.sort(key=lambda m: m.event.get("ts_ns", 0))
    return merged


# ----- predicted attribution (no ground-truth knowledge) ------------

CLAUDE_AGENT_ARGV0 = re.compile(r"(?:^|/)claude$")
MCP_SERVER_BASENAME = re.compile(r"^mcp[-_]server[-_]")
WRAPPER_BINS = {"node", "python", "python3", "uv", "uvx"}


def is_session_root(args: dict) -> bool:
    """True iff this execve looks like an agent invocation."""
    argv = args.get("argv") or []
    path = args.get("path", "")
    argv0 = argv[0] if argv else path
    base = argv0.rsplit("/", 1)[-1] if argv0 else ""
    if base != "claude":
        return False
    # require the per-session marker `-p` or `--print`
    return any(a in ("-p", "--print") for a in argv)


def is_mcp_root(args: dict) -> tuple[bool, str]:
    """True iff this execve looks like an MCP server start.
    Returns (is_root, predicted_mcp_label)."""
    argv = args.get("argv") or []
    path = args.get("path", "")
    argv0 = argv[0] if argv else path
    base = (argv0.rsplit("/", 1)[-1] if argv0 else "").lower()
    if MCP_SERVER_BASENAME.match(base):
        return True, base
    if base in WRAPPER_BINS and len(argv) > 1:
        argv1 = argv[1].rsplit("/", 1)[-1].lower()
        if "mcp" in argv1 and ("server" in argv1 or argv1.startswith("mcp-")):
            return True, argv1
    return False, ""


_TOOLS_CALL_RE = re.compile(rb'"method"\s*:\s*"tools/call"')
_NAME_RE = re.compile(rb'"name"\s*:\s*"([^"]+)"')
_TOOL_USE_ID_RE = re.compile(rb'claudecode/toolUseId"\s*:\s*"([^"]+)"')


def parse_tools_call(buf_b64: str) -> tuple[str, str] | None:
    """Decode a sendto buffer; if it carries a JSON-RPC tools/call,
    return (tool_name, tool_use_id_or_empty)."""
    try:
        data = base64.b64decode(buf_b64)
    except Exception:
        return None
    if _TOOLS_CALL_RE.search(data) is None:
        return None
    name_m = _NAME_RE.search(data)
    tu_m = _TOOL_USE_ID_RE.search(data)
    if not name_m:
        return None
    name = name_m.group(1).decode("utf-8", errors="replace")
    tu_id = tu_m.group(1).decode("utf-8", errors="replace") if tu_m else ""
    return name, tu_id


def predict(merged: list[MergedEvent]) -> list[dict]:
    """Walk the merged stream once; predict (session, mcp, tool_call)
    per event using only kernel-observable signals."""
    pid_session: dict[int, str] = {}
    pid_mcp: dict[int, str] = {}
    # (caller_pid, ts, caller_cgroup) — cgroup match is required for
    # clone-window inheritance. See Step 2 writeup.
    last_clone_caller: tuple[int, int, int | None] | None = None
    # v2 path: pids whose parent is known authoritatively from a
    # sched_fork event in the trace. These pids skip the timing-window
    # heuristic so we don't overwrite an authoritative binding with an
    # inferred one.
    pid_parent_authoritative: set[int] = set()

    sessions_open: list[str] = []
    mcps_open: dict[str, str] = {}  # session_id → current open mcp_id
    next_session = 0
    next_mcp = 0
    tool_call_seq = 0
    active_tool_call: dict[str, str] = {}   # mcp_pid_str → current tool_call_id
    tool_call_owner_pid: dict[str, int] = {}  # mcp pid for each tool call

    preds: list[dict] = []

    for me in merged:
        e = me.event
        ev = e.get("event")
        pid = e.get("pid")
        ts = e.get("ts_ns", 0)
        tid = e.get("tid", pid)
        cgid = e.get("cgroup_id")

        # --- v2 sched_fork: authoritative parent->child binding ---
        if ev == "sched_fork":
            args = e.get("args") or {}
            ppid = int(args.get("parent_pid", 0))
            cpid = int(args.get("child_pid", 0))
            if ppid and cpid and ppid != cpid:
                pid_parent_authoritative.add(cpid)
                if ppid in pid_session:
                    pid_session[cpid] = pid_session[ppid]
                if ppid in pid_mcp:
                    pid_mcp[cpid] = pid_mcp[ppid]

        # --- session attribution (timing-window fallback) ---
        if (pid is not None
                and pid not in pid_session
                and pid not in pid_parent_authoritative):
            # try inherit from recent clone caller (cgroup-gated)
            if last_clone_caller is not None:
                cpid, cts, ccg = last_clone_caller
                cgroup_ok = (ccg is None or cgid is None or ccg == cgid)
                if (ts - cts < 200_000_000 and cgroup_ok
                        and cpid in pid_session):
                    pid_session[pid] = pid_session[cpid]
                    if cpid in pid_mcp:
                        pid_mcp[pid] = pid_mcp[cpid]
        if ev == "execve":
            args = e.get("args") or {}
            # A pid can re-execve multiple times (sh -> env -> mcp-server).
            # Each execve is checked; the last matching one wins.
            # Session-root execve overrides any prior inheritance — the
            # `claude -p` invocation is a definitive new-session signal,
            # so even if the pid had inherited from a clone caller we
            # rebind it to a fresh session here.
            if is_session_root(args) and pid is not None:
                sid = f"sess_{next_session}"
                next_session += 1
                pid_session[pid] = sid
                # Also clear any inherited MCP attribution — a fresh
                # claude -p starts a fresh session with no MCPs yet.
                pid_mcp.pop(pid, None)
                sessions_open.append(sid)
            ok, label = is_mcp_root(args)
            if ok and pid is not None and pid in pid_session:
                if pid not in pid_mcp:  # only first mcp-server exec opens
                    mcp_id = f"mcp_{next_mcp}_{label}"
                    next_mcp += 1
                    pid_mcp[pid] = mcp_id

        if ev in ("clone", "clone3"):
            last_clone_caller = (pid, ts, cgid)

        # --- tool-call attribution via sendto JSON-RPC parse ---
        # When the agent (claude pid) sends a tools/call to an MCP,
        # the next sendto from any MCP pid back is the response. We
        # use a simple state machine keyed on the MCP pid.
        if ev == "sendto" and pid in pid_session:
            args = e.get("args") or {}
            buf = args.get("buf_b64")
            if buf:
                parsed = parse_tools_call(buf)
                if parsed is not None:
                    name, tu_id = parsed
                    # The receiving MCP is whichever MCP pid is currently
                    # open in this session. Pick the most recently opened.
                    sid = pid_session.get(pid)
                    candidate_mcps = [
                        (mp, mid) for mp, mid in pid_mcp.items()
                        if pid_session.get(mp) == sid
                    ]
                    if candidate_mcps:
                        mcp_pid, mcp_id = candidate_mcps[-1]
                        tc_id = tu_id or f"tc_{tool_call_seq}"
                        tool_call_seq += 1
                        active_tool_call[str(mcp_pid)] = tc_id
                        tool_call_owner_pid[tc_id] = mcp_pid

        # When MCP sends back a response, close the active tool call
        if ev == "sendto" and pid in pid_mcp:
            args = e.get("args") or {}
            buf = args.get("buf_b64")
            if buf and str(pid) in active_tool_call:
                try:
                    decoded = base64.b64decode(buf)
                    if b'"id"' in decoded and b'"jsonrpc"' in decoded:
                        # Heuristic: any non-tools/call JSON-RPC frame
                        # from MCP back is a response. Close the call.
                        active_tool_call.pop(str(pid), None)
                except Exception:
                    pass

        # --- record prediction for this event ---
        sid_pred = pid_session.get(pid, "")
        mcp_pred = pid_mcp.get(pid, "")
        tc_pred = ""
        if mcp_pred:
            # Walk up: which mcp_pid is the open tool-call owner with
            # this same mcp_id?
            for mpid_str, tc_id in active_tool_call.items():
                if pid_mcp.get(int(mpid_str)) == mcp_pred:
                    # check pid is in the mcp subtree (already guaranteed
                    # by mcp_pred non-empty)
                    tc_pred = tc_id
                    break

        preds.append({
            "session": sid_pred,
            "mcp": mcp_pred,
            "tool_call": tc_pred,
        })
    return preds


# ----- scoring -----------------------------------------------------

def _hungarian_map(true_labels: list[str], pred_labels: list[str]
                    ) -> dict[str, str]:
    """Greedy 1-to-1 map predicted-class → true-class that maximizes
    the count of co-occurring (pred, true) pairs. Empty string is
    treated as the same class on both sides ('unattributed')."""
    co: dict[tuple[str, str], int] = Counter(zip(pred_labels, true_labels))
    pairs = sorted(co.items(), key=lambda kv: -kv[1])
    mapping: dict[str, str] = {}
    used_true: set[str] = set()
    for (p, t), _ in pairs:
        if p in mapping:
            continue
        if t in used_true:
            continue
        mapping[p] = t
        used_true.add(t)
    return mapping


def _pr_f1(true_labels: list[str], pred_labels: list[str]) -> dict:
    """Per-event precision/recall/F1 over non-empty true labels.

    We map predicted classes to true classes via a greedy 1-to-1
    matching (Hungarian-lite). An event is 'correct' iff its
    predicted class maps to its true class. Empty string ("") is
    the 'unattributed' bucket and is excluded from scoring.
    """
    if not true_labels:
        return {"precision": None, "recall": None, "f1": None,
                "n_scored": 0}
    n = len(true_labels)
    # Map pred → true for non-empty pred classes
    nonempty_idx = [i for i in range(n) if pred_labels[i] or true_labels[i]]
    mapping = _hungarian_map(
        [true_labels[i] for i in nonempty_idx],
        [pred_labels[i] for i in nonempty_idx],
    )
    # An event is TP iff it has a non-empty true label AND its
    # predicted-class-mapped-to-true equals the true label.
    tp = 0
    fp = 0  # pred non-empty, but mapped class != true (or true empty)
    fn = 0  # true non-empty, pred empty or mapped class != true
    for i in range(n):
        t = true_labels[i]
        p = pred_labels[i]
        mapped = mapping.get(p, "")
        if t and mapped == t:
            tp += 1
        elif p and mapped != t:
            fp += 1
        if t and (not p or mapped != t):
            fn += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return {
        "precision": prec, "recall": rec, "f1": f1,
        "n_scored": sum(1 for t in true_labels if t),
        "n_classes_true": len({t for t in true_labels if t}),
        "n_classes_pred": len({p for p in pred_labels if p}),
        "tp": tp, "fp": fp, "fn": fn,
    }


def adjusted_rand_index(true_labels: list, pred_labels: list) -> float:
    if not true_labels or len(true_labels) != len(pred_labels):
        return 0.0
    n = len(true_labels)
    cont = Counter(zip(true_labels, pred_labels))
    a = Counter(true_labels); b = Counter(pred_labels)
    sum_c = sum(comb(v, 2) for v in cont.values())
    sum_a = sum(comb(v, 2) for v in a.values())
    sum_b = sum(comb(v, 2) for v in b.values())
    expected = sum_a * sum_b / comb(n, 2) if n >= 2 else 0
    max_idx = (sum_a + sum_b) / 2
    if max_idx == expected:
        return 1.0
    return (sum_c - expected) / (max_idx - expected)


# ----- trial driver ------------------------------------------------

def pick_distinct_mcp_sessions(pool: list, n: int, rng: random.Random):
    """Pick n sessions with distinct MCPs."""
    by_mcp: dict[str, list] = defaultdict(list)
    for sd in pool:
        meta = json.loads((sd / "session.json").read_text())
        by_mcp[meta["mcp"]].append(sd)
    mcps = [m for m in by_mcp.keys() if by_mcp[m]]
    if len(mcps) < n:
        return None
    chosen_mcps = rng.sample(mcps, n)
    return [rng.choice(by_mcp[m]) for m in chosen_mcps]


def run_trial(sessions: list, layer: str) -> dict:
    merged = merge_sessions(sessions, layer)
    preds = predict(merged)

    sess_true = [m.src_session for m in merged]
    sess_pred = [p["session"] for p in preds]
    mcp_true = [m.src_mcp for m in merged]
    mcp_pred = [p["mcp"] for p in preds]
    tc_true = [m.src_tool_call for m in merged]
    tc_pred = [p["tool_call"] for p in preds]

    return {
        "n_events": len(merged),
        "session": {
            **_pr_f1(sess_true, sess_pred),
            "ari": adjusted_rand_index(sess_true, sess_pred),
        },
        "mcp": {
            **_pr_f1(mcp_true, mcp_pred),
            "ari": adjusted_rand_index(mcp_true, mcp_pred),
        },
        "tool_call": {
            **_pr_f1(tc_true, tc_pred),
            "ari": adjusted_rand_index(tc_true, tc_pred),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-trials", type=int, default=10)
    ap.add_argument("--n-sessions", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    pool = find_sessions(limit=args.limit)
    rng = random.Random(args.seed)

    rows = []
    for t in range(args.n_trials):
        chosen_dirs = pick_distinct_mcp_sessions(pool, args.n_sessions, rng)
        if not chosen_dirs:
            print(f"trial {t}: not enough distinct-MCP sessions, skipping")
            continue
        chosen = [load_session(sd) for sd in chosen_dirs]
        for layer in ("l2ext", "l3"):
            row = run_trial(chosen, layer)
            row.update({
                "trial": t,
                "layer": layer,
                "mcps": [s.meta["mcp"] for s in chosen],
            })
            rows.append(row)
            print(f"trial {t} {layer}: "
                  f"sess F1={row['session']['f1']:.3f} ARI={row['session']['ari']:.3f}; "
                  f"mcp F1={row['mcp']['f1']:.3f} ARI={row['mcp']['ari']:.3f}; "
                  f"tc F1={row['tool_call']['f1']:.3f} ARI={row['tool_call']['ari']:.3f}")

    (RESULTS / "e6.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    # Aggregate per layer × level
    def agg(layer: str):
        sub = [r for r in rows if r["layer"] == layer]
        out = {"n_trials": len(sub)}
        for level in ("session", "mcp", "tool_call"):
            ms = [r[level]["f1"] for r in sub if r[level]["f1"] is not None]
            ps = [r[level]["precision"] for r in sub if r[level]["precision"] is not None]
            rs = [r[level]["recall"] for r in sub if r[level]["recall"] is not None]
            ars = [r[level]["ari"] for r in sub]
            out[level] = {
                "f1_mean": sum(ms)/len(ms) if ms else None,
                "f1_min": min(ms) if ms else None,
                "f1_max": max(ms) if ms else None,
                "precision_mean": sum(ps)/len(ps) if ps else None,
                "recall_mean": sum(rs)/len(rs) if rs else None,
                "ari_mean": sum(ars)/len(ars) if ars else None,
                "n_scored": len(ms),
            }
        return out

    summary = {"l2ext": agg("l2ext"), "l3": agg("l3")}
    (RESULTS / "e6_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
