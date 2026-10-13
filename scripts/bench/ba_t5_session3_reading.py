#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Read BA-T5 session 3, the SH-3 confirming block: the shipped thread-level
priority mechanism beside a syncing daemon, in two scheduler topologies.

    python3 scripts/bench/ba_t5_session3_reading.py PREFIX

reads, for each topology `t1` and `t2p`, the four files
`PREFIX_<topology>_{obs,env,sync,ctx}.tsv`. What is read, and how, is fixed
in the session's record (`docs/benchmarks/ba_t5_serve_floor_device_<date>.md`,
"Registered before the run"). This script applies it and adds nothing. It
grades nothing as a pass or a fail: it prints each registered prediction
beside the measurement it is read against and marks it held or missed,
says which of P2's two hypotheses the captured scheduling context selects
before it prints what was measured, and prints the figure the ledger row
`serving_priority_nice` takes. It exits 0 whatever it finds, and 2, before
printing any figure, if the files do not hold the complete registered
session.

Row formats are session 2's (`ba_t5_session2_reading.py`) with two
additions from the probe — an `outcome` word on `OBS` rows (served,
refused, cut) and a `cut` count on `BLOCK` rows, a cut being a response
the endpoint's 30 s write-stall timeout dropped mid-way — plus:

  CTX    utc topology tag key value        (scheduling context, run script)

Labels are `<topology>.<pass>.<cell>`: topology `t1` or `t2p`; cell
`mech8`, `mech64` (the mechanism, 8 or 64 in flight), `ctrl8` (the control,
same runtime and budget at the inherited priority), `quiet` (the no-serve
window before the pass's first cell) or `quiet<cell>` (the no-serve window
after that cell).

A sync window is read from its SYNCH points stamped at or after the
environment row written when the window opened, as session 2's corrected
reading does. A serving block's share is its window's rate over the mean
of its two adjacent no-serve windows — the one that ended as it started
and the one that began as it ended — so the denominator is the daemon's
own rate at the same height; a block beside one void window takes the
other alone, and beside two is void. The session-2 denominator, the
topology's median no-serve rate, is printed beside it for comparison.
"""

from __future__ import annotations

import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ba_t5_reading import fmt_ms, med, rows  # noqa: E402
from ba_t5_session2_reading import (  # noqa: E402
    SYNC_POINTS_MIN,
    Window,
    utc_seconds,
    window_rate,
)

# The registered session.
TOPOLOGIES = ("t1", "t2p")
PASSES = (1, 2, 3)
CELLS = ("mech8", "mech64", "ctrl8")
MECH_CELLS = ("mech8", "mech64")
IN_FLIGHT_OF = {"mech8": 8, "mech64": 64, "ctrl8": 8}
BLOCKS_PER_CELL = len(PASSES)
# One no-serve window before the first cell and one after each cell, per pass.
QUIET_PER_TOPOLOGY = BLOCKS_PER_CELL * (len(CELLS) + 1)
STORE_BLOCK = "prep.store"
SERVING_THREAD_COMM = "sk-serving-prob"
SERVING_NICE = 19
CTX_TAGS = ("before", "after")
CTX_KEYS = (
    "sched_autogroup_enabled",
    "daemon.cgroup",
    "daemon.parent.subtree_control",
    "serving.cgroup",
    "serving.parent.subtree_control",
)

# The registered predictions, as numbers.
P1_SHARE_LOW, P1_SHARE_HIGH = 0.90, 1.00
# P2 (a) holds when T2' with the mechanism sits nearer its own control than T1's mechanism share;
# (b) holds when it sits within this of T1's mechanism share.
P2_B_WITHIN = 0.10
P3_RATE_LOW, P3_RATE_HIGH = 5.0, 17.0
P4_P99_LOW_US, P4_P99_HIGH_US = 50_000, 800_000


def topology_of(label: str) -> str:
    return label.split(".", 1)[0]


def cell_of(label: str) -> str:
    return label.rsplit(".", 1)[-1]


def block_labels(topology: str) -> list[str]:
    return [f"{topology}.{pas}.{cell}" for pas in PASSES for cell in CELLS]


def quiet_labels(topology: str) -> list[str]:
    out = []
    for pas in PASSES:
        out.append(f"{topology}.{pas}.quiet")
        out += [f"{topology}.{pas}.quiet{cell}" for cell in CELLS]
    return out


def registered_env_tags(topology: str) -> list[str]:
    tags = [f"start.{STORE_BLOCK}", f"end.{STORE_BLOCK}"]
    for label in block_labels(topology):
        tags += [f"start.{label}", f"end.{label}"]
    for pas in PASSES:
        tags += [f"pass.{topology}.{pas}.start", f"pass.{topology}.{pas}.end"]
    return tags


def window_start_tag(label: str) -> str:
    """The environment tag written when this window's poll began."""
    topology, pas, cell = label.split(".")
    if cell in CELLS:
        return f"start.{label}"
    if cell == "quiet":
        return f"pass.{topology}.{pas}.start"
    return f"end.{topology}.{pas}.{cell[len('quiet'):]}"


def neighbours(label: str, order: list[str]) -> tuple[str, str]:
    """The no-serve windows that end as this block starts and begin as it ends."""
    topology, pas, cell = label.split(".")
    k = order.index(cell)
    before = f"{topology}.{pas}.quiet" if k == 0 else f"{topology}.{pas}.quiet{order[k - 1]}"
    return before, f"{topology}.{pas}.quiet{cell}"


def windows(sync_path: Path, env_path: Path) -> dict[str, Window]:
    opened_at = {e[1]: utc_seconds(e[0]) for e in rows(env_path, "ENV")}
    points: dict[str, list[tuple[float, int, int]]] = defaultdict(list)
    for utc, label, _state, height, target in rows(sync_path, "SYNCH"):
        points[label].append((utc_seconds(utc), int(height), int(target)))
    out: dict[str, Window] = {}
    for label, ps in points.items():
        start = opened_at.get(window_start_tag(label))
        kept = ps if start is None else [p for p in ps if p[0] >= start]
        out[label] = Window(label, kept, len(ps) - len(kept))
    return out


def pass_orders(obs_path: Path) -> dict[int, list[str]]:
    """The cell order of each pass, from the run script's NOTE rows."""
    orders: dict[int, list[str]] = {}
    for note in rows(obs_path, "NOTE"):
        text = note[0]
        if text.startswith("pass ") and " order " in text:
            pas, order = text[len("pass "):].split(" order ")
            orders[int(pas)] = order.split()
    return orders


def thread_histogram(value: str) -> dict[tuple[str, int], int]:
    """`comm:nice=count comm:nice=count …` as a map."""
    out: dict[tuple[str, int], int] = {}
    for item in value.split():
        name, count = item.rsplit("=", 1)
        comm, nice = name.rsplit(":", 1)
        out[(comm, int(nice))] = int(count)
    return out


def mechanism_took(ctx: list[list[str]], label: str) -> bool | None:
    """Whether every serving-runtime thread of this block's probe read nice 19.

    None when the block has no thread reading."""
    for _utc, _topology, tag, key, value in ctx:
        if tag == label and key == "probe.threads":
            hist = thread_histogram(value)
            serving = {nice: n for (comm, nice), n in hist.items() if comm == SERVING_THREAD_COMM}
            if not serving:
                return False
            return set(serving) == {SERVING_NICE}
    return None


def incomplete(prefix: Path) -> list[str]:
    found: list[str] = []
    for topology in TOPOLOGIES:
        paths = files(prefix, topology)
        for kind, path in paths.items():
            if not path.is_file():
                found.append(f"{topology}: no {kind} file at {path}")
        if any(not p.is_file() for p in paths.values()):
            continue
        obs, env, sync, ctx = (rows(paths[k], kind) for k, kind in (("obs", "EXIT"), ("env", "ENV"), ("sync", "SYNCH"), ("ctx", "CTX")))
        exits: dict[str, list[str]] = defaultdict(list)
        for label, _mode, code in obs:
            exits[label].append(code)
        for label in [STORE_BLOCK] + block_labels(topology):
            codes = exits.get(label, [])
            if not codes:
                found.append(f"{label}: no exit row; the probe's final status is unknown")
            elif codes != ["0"]:
                found.append(f"{label}: exit code(s) {', '.join(codes)}, registered one exit of 0")
        blocks = {b[0] for b in rows(paths["obs"], "BLOCK") if b[1] == "load"}
        late = {r[0] for r in rows(paths["obs"], "LATE") if r[1] == "load"}
        synch_labels = {r[1] for r in sync}
        for label in block_labels(topology):
            if label not in blocks:
                found.append(f"{label}: no BLOCK row")
            if label not in late:
                found.append(f"{label}: no LATE row")
            if label not in synch_labels:
                found.append(f"{label}: no sync window")
        quiet = [q for q in quiet_labels(topology) if q in synch_labels]
        if len(quiet) != QUIET_PER_TOPOLOGY:
            found.append(f"{topology}: {len(quiet)} no-serve window(s), registered {QUIET_PER_TOPOLOGY}")
        tags = {e[1] for e in env}
        missing = [tag for tag in registered_env_tags(topology) if tag not in tags]
        if missing:
            shown = ", ".join(missing[:4]) + (", …" if len(missing) > 4 else "")
            found.append(f"{topology}: {len(missing)} registered environment row(s) missing ({shown})")
        for e in env:
            if len(e) < 16 or not e[2].isdigit() or not e[11].isdigit():
                found.append(f"{topology}: environment row {e[:2]} lacks a temperature or memory reading")
                break
        have = {(c[2], c[3]) for c in ctx}
        for tag in CTX_TAGS:
            for key in CTX_KEYS:
                if (tag, key) not in have:
                    found.append(f"{topology}: no scheduling-context row {key} at {tag}")
        for label in block_labels(topology):
            if (label, "probe.threads") not in have:
                found.append(f"{label}: no thread reading of the probe")
    return found


def files(prefix: Path, topology: str) -> dict[str, Path]:
    return {kind: Path(f"{prefix}_{topology}_{kind}.tsv") for kind in ("obs", "env", "sync", "ctx")}


def p2_hypothesis(ctx: list[list[str]]) -> tuple[str, str]:
    """Which of P2's hypotheses the captured context selects, and why.

    (a) when the daemon and the serving process are in different cgroups
    with the `cpu` controller enabled in a parent of either, or in
    different sessions with autogroup on: nice does not cross groups.
    (b) otherwise: one scheduling group, nice applies across the two."""
    before = {key: value for _utc, _topology, tag, key, value in ctx if tag == "before"}
    daemon, serving = before.get("daemon.cgroup", ""), before.get("serving.cgroup", "")
    # The groups the scheduler weighs, when the capture names them: the
    # nearest ancestor whose parent enables the cpu controller. Two different
    # ones are the split; otherwise fall back to the parents' subtree_control.
    daemon_cpu, serving_cpu = before.get("daemon.cpu_cgroup"), before.get("serving.cpu_cgroup")
    if daemon_cpu and serving_cpu and daemon_cpu != serving_cpu:
        return "a", f"different cpu cgroups ({daemon_cpu} vs {serving_cpu}); nice does not cross them"
    if daemon_cpu and serving_cpu and daemon_cpu == serving_cpu and daemon != serving:
        return "b", f"one cpu cgroup ({daemon_cpu}) over both; nice orders the two processes' threads against each other"
    cpu_split = any("cpu" in before.get(k, "").split() for k in ("daemon.parent.subtree_control", "serving.parent.subtree_control"))
    autogroup = before.get("sched_autogroup_enabled", "0") == "1"
    daemon_ag, serving_ag = before.get("daemon.autogroup", ""), before.get("serving.autogroup", "")
    if daemon != serving and cpu_split:
        return "a", f"different cgroups ({daemon} vs {serving}) with cpu in a parent's subtree_control"
    if daemon != serving and autogroup and daemon_ag.split()[:1] != serving_ag.split()[:1]:
        return "a", f"different cgroups and different autogroups ({daemon_ag} vs {serving_ag}) with autogroup on"
    if daemon == serving:
        return "b", f"one cgroup ({daemon}); nice orders the two processes' threads against each other"
    return "b", "different cgroups, but no cpu controller between them and no autogroup split"


def mark(held: bool) -> str:
    return "held" if held else "missed"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    prefix = Path(sys.argv[1])
    problems = incomplete(prefix)
    if problems:
        print("NOT A COMPLETE REGISTERED SESSION; nothing is read from it:")
        for problem in problems:
            print("  " + problem)
        return 2

    share: dict[str, dict[str, list[float]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    share_s2: dict[str, dict[str, list[float]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    rate: dict[str, dict[str, list[float]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    p99: dict[str, dict[str, list[float]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    cut: dict[str, dict[str, list[int]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    took: dict[str, dict[str, list[bool]]] = {t: defaultdict(list) for t in TOPOLOGIES}
    hypothesis: dict[str, tuple[str, str]] = {}
    env_all: dict[str, list[list[str]]] = {}
    ctx_all: dict[str, list[list[str]]] = {}
    for topology in TOPOLOGIES:
        paths = files(prefix, topology)
        blocks = rows(paths["obs"], "BLOCK")
        late = {r[0]: r for r in rows(paths["obs"], "LATE") if r[1] == "load"}
        env = rows(paths["env"], "ENV")
        ctx = rows(paths["ctx"], "CTX")
        env_all[topology], ctx_all[topology] = env, ctx
        orders = pass_orders(paths["obs"])
        wins = windows(paths["sync"], paths["env"])
        rates = {label: window_rate(w, SYNC_POINTS_MIN) for label, w in wins.items()}
        stale = sum(1 for w in wins.values() if w.dropped)
        quiet_rates = [r for label, r in rates.items() if cell_of(label).startswith("quiet") and r is not None]
        quiet_median = med(quiet_rates) if quiet_rates else float("nan")
        hypothesis[topology] = p2_hypothesis(ctx)
        # Every no-serve window can be void under the validity rule (a daemon
        # that reached its target, or stalled, through a whole topology);
        # the windows are present, so the session is complete, and the
        # reading says so rather than failing on an empty range.
        quiet_text = (f"no-serve rate median {quiet_median:.2f} blocks/s over {len(quiet_rates)} valid windows "
                      f"(range {min(quiet_rates):.2f} to {max(quiet_rates):.2f})" if quiet_rates
                      else "NO VALID no-serve window under the registered rule; every share in this topology is void")
        print(f"\n== {topology}: sync windows {len(wins)}, pre-window points dropped from {stale}; {quiet_text} ==")
        void = sorted(label for label, r in rates.items() if r is None)
        if void:
            print(f"  void under the registered rule: {', '.join(void)}")
        print(f"  P2 hypothesis selected by the context captured before the first block: ({hypothesis[topology][0]}) — {hypothesis[topology][1]}")
        print("  serving blocks (rate over the responses served; share over the adjacent no-serve windows, "
              "then over the topology's median no-serve rate):")
        for b in blocks:
            label = b[0]
            if b[1] != "load" or topology_of(label) != topology:
                continue
            cell = cell_of(label)
            pas = int(label.split(".")[1])
            served, wall_ms = int(b[7]), int(b[5])
            cut_here = int(b[9]) if len(b) > 9 else 0
            cut[topology][cell].append(cut_here)
            r = served / (wall_ms / 1000)
            lat = late.get(label)
            p99_us = float(lat[7]) if lat else float("nan")
            rate[topology][cell].append(r)
            p99[topology][cell].append(p99_us)
            ok = mechanism_took(ctx, label)
            took[topology][cell].append(bool(ok))
            own = rates.get(label)
            before, after = neighbours(label, orders.get(pas, list(CELLS)))
            adjacent = [rates[q] for q in (before, after) if rates.get(q) is not None]
            s = s2 = None
            if own is not None and adjacent:
                s = own / statistics.fmean(adjacent)
                share[topology][cell].append(s)
            if own is not None and quiet_rates:
                s2 = own / quiet_median
                share_s2[topology][cell].append(s2)
            share_text = (f"share {s * 100:3.0f} % (s2 method {s2 * 100:3.0f} %)" if s is not None else
                          ("VOID window" if own is None else "VOID: both adjacent no-serve windows void"))
            print(f"    {label:14s} {r:6.1f}/s  cut {cut_here:3d}  p99 {p99_us / 1000:6.1f} ms  sync {own if own is None else round(own, 2)!s:>5} blocks/s  "
                  f"{share_text}  threads at nice {SERVING_NICE}: {'yes' if ok else 'NO' if ok is False else 'unread'}")
        print("  cell medians:")
        for cell in CELLS:
            sh = med(share[topology][cell]) if share[topology][cell] else float("nan")
            sh2 = med(share_s2[topology][cell]) if share_s2[topology][cell] else float("nan")
            print(f"    {cell:7s} share {sh * 100:4.0f} % over {len(share[topology][cell])} valid (s2 method {sh2 * 100:4.0f} %)  "
                  f"rate {med(rate[topology][cell]):6.1f}/s  p99 {med(p99[topology][cell]) / 1000:6.1f} ms  "
                  f"cut {sum(cut[topology][cell])} of {len(cut[topology][cell]) * (512 if cell != 'ctrl8' else 4096)} responses")

    def cell_share(topology: str, cell: str) -> float:
        v = share[topology][cell]
        return med(v) if v else float("nan")

    print("\n== the mechanism took ==")
    for topology in TOPOLOGIES:
        mech = all(all(v) for cell in MECH_CELLS for v in [took[topology][cell]])
        ctrl = not any(took[topology]["ctrl8"])
        print(f"  {topology}: every mechanism block's serving threads at nice {SERVING_NICE}: {'yes' if mech else 'NO'}; "
              f"no control block's serving threads at nice {SERVING_NICE}: {'yes' if ctrl else 'NO'}")

    print("\n== the predictions, against the measurements ==")
    t1_8, t1_64 = cell_share("t1", "mech8"), cell_share("t1", "mech64")
    p1 = all(P1_SHARE_LOW <= v <= P1_SHARE_HIGH for v in (t1_8, t1_64))
    print(f"  P1 T1 with the mechanism keeps {P1_SHARE_LOW * 100:.0f} to {P1_SHARE_HIGH * 100:.0f} % of the no-serve sync rate "
          f"at N=8 and N=64: {t1_8 * 100:.0f} % and {t1_64 * 100:.0f} %: {mark(p1)}")
    t2_8, t2_ctrl = cell_share("t2p", "mech8"), cell_share("t2p", "ctrl8")
    hyp, why = hypothesis["t2p"]
    toward_control = abs(t2_8 - t2_ctrl) < abs(t2_8 - t1_8)
    matches_t1 = abs(t2_8 - t1_8) <= P2_B_WITHIN
    observed = "a" if toward_control and not matches_t1 else "b" if matches_t1 else "neither"
    print(f"  P2 T2' with the mechanism, hypothesis ({hyp}) selected from the context ({why}): "
          f"T2' mech8 {t2_8 * 100:.0f} %, T2' control {t2_ctrl * 100:.0f} %, T1 mech8 {t1_8 * 100:.0f} %: "
          f"observed ({observed}): {mark(observed == hyp)}")
    rates_mech = {(t, c): med(rate[t][c]) for t in TOPOLOGIES for c in MECH_CELLS}
    p3 = all(P3_RATE_LOW <= v <= P3_RATE_HIGH for v in rates_mech.values())
    print(f"  P3 serving throughput with the mechanism {P3_RATE_LOW:.0f} to {P3_RATE_HIGH:.0f} responses/s: "
          + ", ".join(f"{t} {c} {v:.1f}" for (t, c), v in rates_mech.items()) + f": {mark(p3)}")
    p99_mech = {(t, c): med(p99[t][c]) for t in TOPOLOGIES for c in MECH_CELLS}
    p4 = all(P4_P99_LOW_US <= v <= P4_P99_HIGH_US for v in p99_mech.values())
    print(f"  P4 serving executor p99 wake lateness with the mechanism {P4_P99_LOW_US // 1000} to {P4_P99_HIGH_US // 1000} ms: "
          + ", ".join(f"{t} {c} {v / 1000:.0f} ms" for (t, c), v in p99_mech.items()) + f": {mark(p4)}")

    print("\n== the ledger row serving_priority_nice ==")
    measured = min(t1_8, t1_64)
    print(f"  measured on T1 (the lower of the two mechanism cells): {measured:.2f} share of the no-serve sync rate; "
          f"estimate band {P1_SHARE_LOW:.2f} to {P1_SHARE_HIGH:.2f}: {'inside' if P1_SHARE_LOW <= measured <= P1_SHARE_HIGH else 'OUTSIDE'}")

    print("\n== environment ==")
    for topology in TOPOLOGIES:
        env = env_all[topology]
        temps = [int(e[2]) for e in env]
        freqs = [int(e[4]) for e in env]
        srss = [int(e[8]) for e in env if e[8].isdigit()]
        print(f"  {topology}: board {min(temps) / 1000:.1f} to {max(temps) / 1000:.1f} C over {len(env)} samples; "
              f"clock at the sample {min(freqs) // 1000} to {max(freqs) // 1000} MHz, "
              f"{sum(1 for f in freqs if f < max(freqs))} below {max(freqs) // 1000}; "
              f"MemAvailable lowest {min(int(e[11]) for e in env) // 1024} MB; "
              f"syncing daemon RSS {min(srss) // 1024 if srss else 'na'} to {max(srss) // 1024 if srss else 'na'} MB")
        before = {key: value for _u, _t, tag, key, value in ctx_all[topology] if tag == "before"}
        print(f"    daemon cgroup {before.get('daemon.cgroup')} (parent subtree_control: {before.get('daemon.parent.subtree_control')}); "
              f"serving cgroup {before.get('serving.cgroup')} (parent subtree_control: {before.get('serving.parent.subtree_control')}); "
              f"autogroup {before.get('sched_autogroup_enabled')}")
    return 0


# --- selftest ---------------------------------------------------------------


def _stamp(seconds: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _synthetic(root: Path, **tweak: object) -> Path:
    """A complete registered session in which every prediction holds, with
    tweaks that make one thing come out otherwise. Returns the prefix."""
    share_at = dict(tweak.get("share", {}))  # type: ignore[arg-type]
    rate_at = dict(tweak.get("rate", {}))  # type: ignore[arg-type]
    p99_at = dict(tweak.get("p99_us", {}))  # type: ignore[arg-type]
    drop_exit = set(tweak.get("drop_exit", ()))  # type: ignore[arg-type]
    drop_window = set(tweak.get("drop_window", ()))  # type: ignore[arg-type]
    drop_ctx = set(tweak.get("drop_ctx", ()))  # type: ignore[arg-type]
    untaken = set(tweak.get("untaken", ()))  # type: ignore[arg-type]
    # Topologies whose no-serve windows all stall twice: void under the rule.
    quiet_void = set(tweak.get("quiet_void", ()))  # type: ignore[arg-type]
    no_stale = bool(tweak.get("no_stale", False))
    t2_context = str(tweak.get("t2_context", "split"))
    quiet_rate = 2.5
    point_every = 4.0
    quiet_seconds = 45.0
    # T1 keeps the rate; T2' is predicted (a) by a split context and reads
    # near its control. The control serves at normal priority and takes the
    # daemon down to a third.
    default_share = {"t1": {"mech8": 0.96, "mech64": 0.92, "ctrl8": 0.32},
                     "t2p": {"mech8": 0.40, "mech64": 0.36, "ctrl8": 0.32}}
    default_rate = {"mech8": 6.0, "mech64": 8.0, "ctrl8": 38.0}
    default_p99 = {"mech8": 75_000, "mech64": 640_000, "ctrl8": 7_000}
    prefix = root / "ba_t5_s3"
    for topology in TOPOLOGIES:
        obs: list[str] = []
        env: list[str] = []
        syn: list[str] = []
        ctx: list[str] = []
        clock = utc_seconds("2026-10-12T15:00:00Z")
        height = 61
        last_point: tuple[float, int] | None = (clock - 5.0, 60)
        target = 4800

        def env_row(tag: str) -> None:
            env.append(f"ENV\t{_stamp(clock)}\t{tag}\t60000\tondemand\t1800000\t1.0\t1000\t500\t366000"
                       f"\t{height}\tfalse\t6000000\t1\t380000\t0\t0")

        def ctx_row(tag: str, key: str, value: str) -> None:
            if (topology, tag, key) in drop_ctx:
                return
            ctx.append(f"CTX\t{_stamp(clock)}\t{topology}\t{tag}\t{key}\t{value}")

        def window(label: str, seconds: float, blocks_per_s: float, stalls: int = 0) -> None:
            nonlocal height, last_point
            if label in drop_window:
                return
            if last_point is not None and not no_stale:
                syn.append(f"SYNCH\t{_stamp(last_point[0])}\t{label}\t{topology}\t{last_point[1]}\t{target}")
            k = 0
            first = height
            while k * point_every <= seconds:
                at = clock + k * point_every
                h = first if 0 < k <= stalls else first + int(round(blocks_per_s * k * point_every))
                syn.append(f"SYNCH\t{_stamp(at)}\t{label}\t{topology}\t{h}\t{target}")
                last_point = (at, h)
                height = h
                k += 1

        def context(tag: str) -> None:
            ctx_row(tag, "sched_autogroup_enabled", "1")
            if topology == "t1" or t2_context == "same":
                cg = "/user.slice/user-1004.slice/session-9.scope"
                ctx_row(tag, "daemon.cgroup", cg)
                ctx_row(tag, "serving.cgroup", cg)
                sub = "cpu memory pids"
            else:
                ctx_row(tag, "daemon.cgroup", "/user.slice/user-1004.slice/user@1004.service/app.slice/run-1.scope")
                ctx_row(tag, "serving.cgroup", "/user.slice/user-1004.slice/session-9.scope")
                sub = "cpu memory pids" if t2_context == "split" else "memory pids"
            ctx_row(tag, "daemon.parent.subtree_control", sub)
            ctx_row(tag, "serving.parent.subtree_control", sub)
            if t2_context == "split" and topology == "t2p":
                ctx_row(tag, "daemon.cpu_cgroup", "/user.slice/user-1004.slice/user@1004.service/app.slice")
                ctx_row(tag, "serving.cpu_cgroup", "/user.slice/user-1004.slice/user@1004.service/tmux-spawn-1.scope")
            ctx_row(tag, "daemon.autogroup", "/autogroup-100 nice 0")
            own_session = topology == "t2p" and t2_context != "nocpu-sameag"
            ctx_row(tag, "serving.autogroup", "/autogroup-200 nice 0" if own_session else "/autogroup-100 nice 0")

        env_row(f"start.{STORE_BLOCK}")
        obs.append(f"BLOCK\t{STORE_BLOCK}\tload\tfull-store\t8\t8\t176\t625\t8\t0")
        obs.append(f"LATE\t{STORE_BLOCK}\tload\tfull-store\t8\t3\t3\t4\t50\t50\t50")
        if STORE_BLOCK not in drop_exit:
            obs.append(f"EXIT\t{STORE_BLOCK}\tload\t0")
        clock += 1
        env_row(f"end.{STORE_BLOCK}")
        context("before")
        orders = {1: ["mech8", "mech64", "ctrl8"], 2: ["ctrl8", "mech8", "mech64"], 3: ["mech64", "ctrl8", "mech8"]}
        for pas in PASSES:
            obs.append(f"NOTE\tpass {pas} order {' '.join(orders[pas])}")
            env_row(f"pass.{topology}.{pas}.start")
            quiet_stalls = 2 if topology in quiet_void else 0
            window(f"{topology}.{pas}.quiet", quiet_seconds, quiet_rate, quiet_stalls)
            clock += quiet_seconds
            for cell in orders[pas]:
                label = f"{topology}.{pas}.{cell}"
                n = IN_FLIGHT_OF[cell]
                fetches = 4096 if cell == "ctrl8" else 512
                r = rate_at.get((topology, cell), default_rate[cell])
                wall_ms = int(fetches / r * 1000)
                p = p99_at.get((topology, cell), default_p99[cell])
                env_row(f"start.{label}")
                cut_n = int(tweak.get("cut", {}).get((topology, cell), 0))  # type: ignore[union-attr]
                obs.append(f"BLOCK\t{label}\tload\tfull-store\t{n}\t{fetches}\t{wall_ms}\t15000\t{fetches - cut_n}\t0\t{cut_n}")
                obs.append(f"LATE\t{label}\tload\tfull-store\t{n}\t9000\t1000\t2000\t{p}\t{p}\t{p}")
                if label not in drop_exit:
                    obs.append(f"EXIT\t{label}\tload\t0")
                nice = 0 if cell == "ctrl8" or label in untaken else SERVING_NICE
                ctx_row(label, "probe.threads", f"{SERVING_THREAD_COMM}:{nice}=4 tokio-runtime-w:0=2 ba_t5_floor_pro:0=2")
                window(label, wall_ms / 1000, quiet_rate * share_at.get((topology, cell), default_share[topology][cell]))
                clock += wall_ms / 1000
                env_row(f"end.{label}")
                window(f"{topology}.{pas}.quiet{cell}", quiet_seconds, quiet_rate, quiet_stalls)
                clock += quiet_seconds
            env_row(f"pass.{topology}.{pas}.end")
        context("after")
        for kind, lines in (("obs", obs), ("env", env), ("sync", syn), ("ctx", ctx)):
            Path(f"{prefix}_{topology}_{kind}.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return prefix


def selftest() -> int:
    import contextlib
    import io
    import tempfile

    failures: list[str] = []

    def run(name: str, want_rc: int, needles: tuple[str, ...], **tweak: object) -> None:
        with tempfile.TemporaryDirectory() as raw:
            prefix = _synthetic(Path(raw), **tweak)
            sys.argv = ["reading", str(prefix)]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main()
            text = out.getvalue()
            problems = [f"rc {rc}, wanted {want_rc}"] if rc != want_rc else []
            problems += [f"missing {needle!r}" for needle in needles if needle not in text]
            if problems:
                failures.append(f"{name}: " + "; ".join(problems))

    run("control: every prediction holds, T2' predicted (a) and observed (a)", 0, (
        "P1 T1 with the mechanism keeps 90 to 100 % of the no-serve sync rate at N=8 and N=64: 96 % and 92 %: held",
        "hypothesis (a) selected from the context (different cpu cgroups (/user.slice/user-1004.slice/user@1004.service/app.slice vs",
        "observed (a): held",
        "P3 serving throughput with the mechanism 5 to 17 responses/s: t1 mech8 6.0, t1 mech64 8.0, t2p mech8 6.0, t2p mech64 8.0: held",
        "P4 serving executor p99 wake lateness with the mechanism 50 to 800 ms: t1 mech8 75 ms, t1 mech64 640 ms",
        ": held",
        "t1: every mechanism block's serving threads at nice 19: yes; no control block's serving threads at nice 19: yes",
        "measured on T1 (the lower of the two mechanism cells): 0.92 share",
        "estimate band 0.90 to 1.00: inside",
        "pre-window points dropped from 18",
    ))
    run("P1 missed: T1 keeps less than 90 %", 0, ("80 % and 92 %: missed", "0.80 share", "OUTSIDE"),
        share={("t1", "mech8"): 0.80})
    run("P2 (b) predicted from one cgroup, and observed", 0, (
        "hypothesis (b) selected from the context (one cgroup", "observed (b): held"),
        t2_context="same", share={("t2p", "mech8"): 0.95, ("t2p", "mech64"): 0.91})
    run("P2 (a) predicted, (b) observed: missed", 0, ("hypothesis (a) selected", "observed (b): missed"),
        share={("t2p", "mech8"): 0.95, ("t2p", "mech64"): 0.91})
    run("P2 (a) predicted from autogroup alone, with no cpu controller between the cgroups", 0, (
        "hypothesis (a) selected from the context (different cgroups and different autogroups",),
        t2_context="nocpu")
    run("P2 (b) predicted from different cgroups with neither a cpu controller nor an autogroup split", 0, (
        "hypothesis (b) selected from the context (different cgroups, but no cpu controller", "observed (b): held"),
        t2_context="nocpu-sameag", share={("t2p", "mech8"): 0.95, ("t2p", "mech64"): 0.91})
    run("P3 missed: the mechanism serves faster than the nice arm did", 0, ("t1 mech8 30.0", ": missed"),
        rate={("t1", "mech8"): 30.0})
    run("P4 missed: lateness over 0.8 s", 0, ("t2p mech64 1200 ms: missed",),
        p99_us={("t2p", "mech64"): 1_200_000})
    run("the mechanism did not take in one block, and it is said", 0, (
        "t1.2.mech8", "threads at nice 19: NO",
        "t1: every mechanism block's serving threads at nice 19: NO"),
        untaken={"t1.2.mech8"})
    run("incomplete: a block without its exit row", 2, ("t2p.3.ctrl8: no exit row",), drop_exit={"t2p.3.ctrl8"})
    run("incomplete: a no-serve window missing", 2, ("t1: 11 no-serve window(s), registered 12",),
        drop_window={"t1.2.quietmech8"})
    run("incomplete: a scheduling-context row missing", 2, ("t2p: no scheduling-context row daemon.cgroup at before",),
        drop_ctx={("t2p", "before", "daemon.cgroup")})
    run("incomplete: a block without its thread reading", 2, ("t1.1.mech64: no thread reading of the probe",),
        drop_ctx={("t1", "t1.1.mech64", "probe.threads")})
    run("cut responses are counted per block and per cell", 0, (
        "t1.1.mech64     ", "cut   3", "mech64  share", "cut 9 of 1536 responses"),
        cut={("t1", "mech64"): 3})
    run("every no-serve window void: said, not a crash, and every share in that topology void", 0, (
        "t2p: sync windows 21", "NO VALID no-serve window under the registered rule", "t2p.1.mech8", "VOID",
        "T2' mech8 nan %"), quiet_void={"t2p"})
    run("a capture with no pre-window points reads the same", 0, (
        "pre-window points dropped from 0", "96 % and 92 %: held"), no_stale=True)
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("selftest: 16 cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
