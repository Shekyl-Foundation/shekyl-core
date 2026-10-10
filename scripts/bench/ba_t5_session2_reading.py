#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Read BA-T5 session 2, a discovery run: serving beside a syncing daemon,
the in-flight sweep, the same sweep at nice 19, and time to first byte.

    python3 scripts/bench/ba_t5_session2_reading.py OBS.tsv ENV.tsv SYNC.tsv

What is read, and how, is fixed in the session's record
(`docs/benchmarks/ba_t5_serve_floor_device_<date>.md`, "Registered before
the run"). This script applies it and adds nothing. It grades nothing as a
pass or a fail: it prints each registered prediction beside the
measurement it is read against and marks it held or missed, prints each
curve against N with the knee as registered, and says whether the
time-to-first-byte figure settles or replaces the open pre-head estimate.
It exits 0 whatever it finds. It exits 2, before printing any figure, if
the files do not hold the complete registered session: every registered
block with its zero exit, every no-serve window, every environment row.

Row formats (tab-separated; the first column is the kind):

  OBS    label mode size in_flight micros bytes        (probe)
  BLOCK  label mode size in_flight n wall_ms cpu_ms served refused
  LATE   label mode size in_flight n p50 p90 p99 p999 max_us
  TTFB   label size n p50 p90 p99 max_us
  EXIT   label mode rc
  ENV    utc tag temp_mC governor freq_kHz load1 busy_jiffies
         sync_daemon_jiffies sync_daemon_rss_kB sync_height sync_synced
         mem_available_kB sync_daemon_pid system_daemon_rss_kB
         swap_total_kB swap_free_kB                    (environment)
  SYNC   label state first_height last_height seconds points stalls last_target
  SYNCH  utc label state height target             (sync poll, from the daemon's log)

Labels are `<state>.<pass>.<cell>`: state `idle`, `sync` or `nice`; cell
`N<k>` for a serving block at k in flight, `quiet` or `quiet<k>` for a
no-serve window, `ttfb` for the time-to-first-byte block.

A sync window is read from its SYNCH points, not from the poll's own SYNC
summary. The poll of the 2026-10-09 capture recorded, as each window's
first point, the newest log line at the moment it started — a line the
daemon had written during the previous window — so every SYNC summary
spans time from before its window opened. The point is identifiable: its
timestamp precedes the window's start, which the environment file
records (`start.<label>` for a serving block, `pass.<state>.<pass>.start`
for the first no-serve window, `end.<state>.<pass>.N<k>` for the no-serve
window after block k). This reading drops every point stamped before its
window's start and derives the rate from what remains, under the
registered validity rule. The poll script has since been fixed to seed its
"seen" line at start, so a later capture carries no such point and reads
the same either way.
"""

from __future__ import annotations

import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ba_t5_reading import fmt_ms, med, rows  # noqa: E402

# The registered session.
STATES = ("idle", "sync", "nice")
SYNCING = ("sync", "nice")
PASSES = (1, 2, 3)
IN_FLIGHT = (8, 16, 32, 64)
BLOCKS_PER_CELL = len(PASSES)
TTFB_STATES = ("idle", "sync")
TTFB_SAMPLES = 300
SYNC_STALL_POINTS_MAX = 1
# The registered validity rule: at least three points in the window.
SYNC_POINTS_MIN = 3
# One interval. Not the registered rule; printed beside it, labelled, for
# a cell the registered rule leaves with fewer valid windows than blocks.
SYNC_POINTS_ONE_INTERVAL = 2
# One no-serve window before the sweep and one after each cell, per pass.
QUIET_PER_STATE = BLOCKS_PER_CELL * (len(IN_FLIGHT) + 1)
STORE_BLOCK = "prep.store"

# The registered predictions, as numbers.
P1_P99_US = 100_000
P1_BY_N = 16
P2_TEMP_MILLI_C = 80_000
P2_MEM_KB = 512 * 1024
P3_SHARE = 0.75
P3_BY_N = 16
P4_KNEE_N = 16
P5_SHARE = 0.90
P5_THROUGHPUT_FRACTION = 0.5
P6_P50_US = 1_000
P6_P99_US = 5_000
P7_SESSION1_P99_US = 5_600
P7_FACTOR = 2.0

# The registered knee steps, per doubling of N.
KNEE_THROUGHPUT_GAIN_BELOW = 0.10
KNEE_RISE_ABOVE = 0.50
KNEE_SYNC_FALL_ABOVE = 0.25

# The open estimate TTFB settles or replaces.
PREHEAD_ESTIMATE_HIGH_US = 1_000


def state_of(label: str) -> str:
    return label.split(".", 1)[0]


def cell_of(label: str) -> str:
    return label.rsplit(".", 1)[-1]


def block_labels() -> list[str]:
    """Every registered serving block, by label."""
    return [f"{state}.{pas}.N{n}" for state in STATES for pas in PASSES for n in IN_FLIGHT]


def ttfb_labels() -> list[str]:
    return [f"{state}.1.ttfb" for state in TTFB_STATES]


def registered_env_tags() -> list[str]:
    """The environment rows the run script writes: one before and after
    every block, and one at each pass's start and end."""
    tags = [f"start.{STORE_BLOCK}", f"end.{STORE_BLOCK}"]
    for label in block_labels() + ttfb_labels():
        tags += [f"start.{label}", f"end.{label}"]
    for state in STATES:
        for pas in PASSES:
            tags += [f"pass.{state}.{pas}.start", f"pass.{state}.{pas}.end"]
    return tags


def utc_seconds(stamp: str) -> float:
    """`2026-10-09T02:13:32Z` or with a fraction, as seconds since the epoch."""
    base, _, frac = stamp.rstrip("Z").partition(".")
    seconds = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    return seconds + (float(f"0.{frac}") if frac else 0.0)


def window_start_tag(label: str) -> str:
    """The environment tag written at the moment this window's poll began."""
    state, pas, cell = label.split(".")
    if cell.startswith("N") or cell == "ttfb":
        return f"start.{label}"
    if cell == "quiet":
        return f"pass.{state}.{pas}.start"
    return f"end.{state}.{pas}.N{cell[len('quiet'):]}"


@dataclass
class Window:
    label: str
    # (seconds since the epoch, height, target), in log order, inside the window.
    points: list[tuple[float, int, int]]
    # Points the poll recorded that were logged before the window opened.
    dropped: int


def windows(sync_path: Path, env_path: Path) -> dict[str, Window]:
    """Every sync window, from its SYNCH points stamped at or after its start."""
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


def window_rate(window: Window, points_min: int) -> float | None:
    """Blocks per second across the window, or None if it is void under a
    rule of `points_min` points: fewer points than that, a height that did
    not advance over the window, more than one point at which it did not
    advance from the previous one, or the target reached at the last
    point. The span is between the first and the last point's own log
    timestamps, so the rate is the daemon's, not the window's."""
    ps = window.points
    if len(ps) < points_min:
        return None
    stalls = sum(1 for a, b in zip(ps, ps[1:]) if b[1] == a[1])
    if ps[-1][1] <= ps[0][1] or stalls > SYNC_STALL_POINTS_MAX:
        return None
    if ps[-1][1] >= ps[-1][2]:
        return None
    span = ps[-1][0] - ps[0][0]
    if span <= 0:
        return None
    return (ps[-1][1] - ps[0][1]) / span


def incomplete(obs_path: Path, env_path: Path, sync_path: Path) -> list[str]:
    """Why these files are not the complete registered session, if they are not."""
    found: list[str] = []
    exits: dict[str, list[str]] = defaultdict(list)
    for label, _mode, code in rows(obs_path, "EXIT"):
        exits[label].append(code)
    for label in [STORE_BLOCK] + block_labels() + ttfb_labels():
        codes = exits.get(label, [])
        if not codes:
            found.append(f"{label}: no exit row; the probe's final status is unknown")
        elif codes != ["0"]:
            found.append(f"{label}: exit code(s) {', '.join(codes)}, registered one exit of 0")
    blocks = rows(obs_path, "BLOCK")
    late = rows(obs_path, "LATE")
    ttfb = rows(obs_path, "TTFB")
    env = rows(env_path, "ENV")
    synch_labels = {r[1] for r in rows(sync_path, "SYNCH")}
    for state in STATES:
        for n in IN_FLIGHT:
            cell = f"N{n}"
            have_b = sum(1 for b in blocks if state_of(b[0]) == state and cell_of(b[0]) == cell and b[1] == "load")
            have_l = sum(1 for r in late if state_of(r[0]) == state and cell_of(r[0]) == cell and r[1] == "load")
            if have_b < BLOCKS_PER_CELL:
                found.append(f"{state} N{n}: {have_b} BLOCK row(s), registered at least {BLOCKS_PER_CELL}")
            if have_l < BLOCKS_PER_CELL:
                found.append(f"{state} N{n}: {have_l} LATE row(s), registered at least {BLOCKS_PER_CELL}")
            if state in SYNCING:
                have_s = sum(1 for s in synch_labels if state_of(s) == state and cell_of(s) == cell)
                if have_s < BLOCKS_PER_CELL:
                    found.append(f"{state} N{n}: {have_s} sync window(s), registered at least {BLOCKS_PER_CELL}")
        if state in SYNCING:
            quiet = sum(1 for s in synch_labels if state_of(s) == state and cell_of(s).startswith("quiet"))
            if quiet != QUIET_PER_STATE:
                found.append(f"{state}: {quiet} no-serve window(s), registered {QUIET_PER_STATE}")
    for state in TTFB_STATES:
        t = [r for r in ttfb if state_of(r[0]) == state]
        if len(t) != 1:
            found.append(f"{state}: {len(t)} TTFB row(s), registered 1")
        elif int(t[0][2]) < TTFB_SAMPLES:
            found.append(f"{state}: TTFB over {t[0][2]} samples, registered at least {TTFB_SAMPLES}")
    tags = {e[1] for e in env}
    missing = [tag for tag in registered_env_tags() if tag not in tags]
    if missing:
        shown = ", ".join(missing[:4]) + (", …" if len(missing) > 4 else "")
        found.append(f"environment: {len(missing)} registered row(s) missing ({shown})")
    for e in env:
        if len(e) < 16 or not e[2].isdigit() or not e[11].isdigit() or not e[14].isdigit() or not e[15].isdigit():
            found.append(f"environment row {e[:2]} lacks a temperature, memory or swap reading")
            break
    return found


def rate_per_s(block: list[str]) -> float:
    """Responses served per second: over `served`, not over the fetches
    attempted. A refused connection costs the endpoint nothing and must not
    count as a response."""
    return int(block[7]) / (int(block[5]) / 1000)


def mark(held: bool) -> str:
    return "held" if held else "missed"


def knee(curve: dict[int, float], kind: str) -> str:
    """The first doubling at which the curve moves by more than its step."""
    for a, b in zip(IN_FLIGHT, IN_FLIGHT[1:]):
        if a not in curve or b not in curve or curve[a] != curve[a] or curve[a] == 0:
            continue
        change = (curve[b] - curve[a]) / curve[a]
        if kind == "throughput" and change < KNEE_THROUGHPUT_GAIN_BELOW:
            return f"knee at N={a} (gain {change * 100:+.0f} % to N={b})"
        if kind == "rise" and change > KNEE_RISE_ABOVE:
            return f"knee at N={a} (rise {change * 100:+.0f} % to N={b})"
        if kind == "fall" and change < -KNEE_SYNC_FALL_ABOVE:
            return f"knee at N={a} (fall {change * 100:+.0f} % to N={b})"
    return "no knee inside the sweep"


def print_curve(name: str, unit: str, curve: dict[int, float], kind: str, scale: float = 1.0) -> None:
    cells = "  ".join(f"N={n}: {curve[n] / scale:6.1f}" for n in IN_FLIGHT if n in curve)
    print(f"  {name:28s} {cells}  {unit}; {knee(curve, kind)}")


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    obs_path, env_path, sync_path = (Path(a) for a in sys.argv[1:4])
    problems = incomplete(obs_path, env_path, sync_path)
    if problems:
        print("NOT A COMPLETE REGISTERED SESSION; nothing is read from it:")
        for problem in problems:
            print("  " + problem)
        return 2
    exits = rows(obs_path, "EXIT")
    print(f"blocks: {len(exits)}, all exited 0; every registered cell, window and environment row is present")

    blocks = rows(obs_path, "BLOCK")
    late = rows(obs_path, "LATE")
    env = rows(env_path, "ENV")
    obs = rows(obs_path, "OBS")

    wins = windows(sync_path, env_path)
    with_stale = sum(1 for w in wins.values() if w.dropped)
    print(
        f"\n== sync windows: {len(wins)}, read from their points stamped after each window opened; "
        f"pre-window points dropped from {with_stale} of {len(wins)} windows =="
    )
    rate: dict[str, float | None] = {label: window_rate(w, SYNC_POINTS_MIN) for label, w in wins.items()}
    one_interval: dict[str, float | None] = {
        label: window_rate(w, SYNC_POINTS_ONE_INTERVAL) for label, w in wins.items()
    }
    quiet: dict[str, list[float]] = defaultdict(list)
    for label, r in rate.items():
        if cell_of(label).startswith("quiet") and r is not None:
            quiet[state_of(label)].append(r)
    print("\n== no-serve sync rate, per state (median over valid windows) ==")
    for state in SYNCING:
        print(
            f"  {state:5s} {med(quiet[state]):.2f} blocks/s over {len(quiet[state])} window(s), "
            f"range {min(quiet[state]):.2f} to {max(quiet[state]):.2f}"
        )
    void = sorted(label for label, r in rate.items() if r is None)
    if void:
        print(f"  void under the registered rule (excluded): {', '.join(void)}")
        thin = [label for label in void if one_interval.get(label) is not None]
        if thin:
            print(
                "  of which hold one interval (two points), read outside the registered rule below: "
                + ", ".join(thin)
            )

    late_by_label = {r[0]: r for r in late if r[1] == "load"}
    per: dict[str, dict[str, dict[int, list[float]]]] = {
        q: {state: defaultdict(list) for state in STATES}
        for q in ("rate", "cpu_ms", "p99_us", "refused", "sync_share", "sync_share_one_interval")
    }
    # A refusal seen from outside: a load fetch that got 0 bytes. The
    # endpoint's own count is on the BLOCK row; the two must agree, and
    # served plus refused must be the fetches attempted. A disagreement is
    # reported, not fatal: the capture is still read.
    zero_seen: dict[str, int] = defaultdict(int)
    for r in obs:
        if r[1] == "load" and r[5] == "0":
            zero_seen[r[0]] += 1
    disagree: list[str] = []
    print("\n== serving blocks (rate over the responses served) ==")
    for b in blocks:
        # The store-writing block (`prep.store`) is a load block too, but
        # it belongs to no state and is not a cell.
        if b[1] != "load" or state_of(b[0]) not in STATES:
            continue
        state, n = state_of(b[0]), int(b[3])
        lat = late_by_label.get(b[0])
        p99 = float(lat[7]) if lat else float("nan")
        attempted, served, refused = int(b[4]), int(b[7]), int(b[8])
        if served + refused != attempted or zero_seen[b[0]] != refused:
            disagree.append(
                f"{b[0]}: {attempted} attempted, {served} served, {refused} refused by the endpoint, "
                f"{zero_seen[b[0]]} empty close(s) seen by the probe"
            )
        per["rate"][state][n].append(rate_per_s(b))
        per["cpu_ms"][state][n].append(int(b[6]) / served)
        per["p99_us"][state][n].append(p99)
        per["refused"][state][n].append(float(refused))
        share = ""
        if state in SYNCING:
            base = med(quiet[state]) if quiet[state] else None
            r = rate.get(b[0])
            r1 = one_interval.get(b[0])
            if r1 is not None and base:
                per["sync_share_one_interval"][state][n].append(r1 / base)
            if r is not None and base:
                per["sync_share"][state][n].append(r / base)
                share = f"  sync {r:.2f} blocks/s = {r / base * 100:.0f} % of no-serve"
            elif r1 is not None and base:
                share = f"  sync window VOID under the registered rule (one interval: {r1:.2f} blocks/s = {r1 / base * 100:.0f} %)"
            else:
                share = "  sync window VOID"
        print(
            f"  {b[0]:16s} {rate_per_s(b):6.1f}/s  cpu/resp {int(b[6]) / served:5.0f} ms  "
            f"refused {refused:3d}  p99 {p99 / 1000:6.1f} ms{share}"
        )
    print("\n== refusals (the endpoint drops a connection past MAX_INFLIGHT without a byte) ==")
    for state in STATES:
        for n in IN_FLIGHT:
            counts = per["refused"][state][n]
            if any(counts):
                print(f"  {state} N{n}: " + ", ".join(f"{int(c)}" for c in counts) + " over its blocks")
    if not any(any(per["refused"][state][n]) for state in STATES for n in IN_FLIGHT):
        print("  none in any block")
    if disagree:
        print("  the probe's count and the endpoint's DISAGREE:")
        for line in disagree:
            print(f"    {line}")
    else:
        print("  the probe's count of empty closes agrees with the endpoint's count in every block")
    curve: dict[str, dict[str, dict[int, float]]] = {
        q: {state: {n: med(v) for n, v in per[q][state].items() if v} for state in STATES} for q in per
    }

    print("\n== the curves against N, per state (cell medians), and where each bends ==")
    for state in STATES:
        print(f"  [{state}]")
        print_curve("responses per second", "/s", curve["rate"][state], "throughput")
        print_curve("CPU per response", "ms", curve["cpu_ms"][state], "rise")
        print_curve("p99 wake lateness", "ms", curve["p99_us"][state], "rise", scale=1000)
        if state in SYNCING:
            print_curve("sync rate, share of no-serve", "%", curve["sync_share"][state], "fall", scale=0.01)
            thin_cells = [n for n in IN_FLIGHT if len(per["sync_share"][state][n]) < BLOCKS_PER_CELL]
            if thin_cells:
                print(
                    "  " + f"{'':28s} "
                    + "valid windows per cell under the registered rule: "
                    + ", ".join(f"N={n}: {len(per['sync_share'][state][n])}" for n in IN_FLIGHT)
                    + " — the one-interval reading of every window, outside the registered rule:"
                )
                print_curve(
                    "  sync share, one interval", "%", curve["sync_share_one_interval"][state], "fall", scale=0.01
                )

    print("\n== the predictions, against the measurements ==")
    p99_sync = curve["p99_us"]["sync"]
    first_over = next((n for n in IN_FLIGHT if p99_sync.get(n, 0) > P1_P99_US), None)
    print(
        f"  P1 p99 wake lateness under sync above {P1_P99_US // 1000} ms by N={P1_BY_N}: "
        + (f"first above at N={first_over}" if first_over else "never above inside the sweep")
        + f": {mark(first_over is not None and first_over <= P1_BY_N)}"
    )
    temps = [int(e[2]) for e in env]
    mem_low = min(int(e[11]) for e in env)
    swap_free = [int(e[15]) for e in env]
    swap_grew = any(b < a for a, b in zip(swap_free, swap_free[1:]))
    p2 = max(temps) < P2_TEMP_MILLI_C and mem_low >= P2_MEM_KB and not swap_grew
    print(
        f"  P2 board under 80 C, MemAvailable over 512 MB, swap not growing: hottest {max(temps) / 1000:.1f} C, "
        f"lowest {mem_low / 1024:.0f} MB, swap {'grew' if swap_grew else 'did not grow'} "
        f"(SwapTotal {int(env[0][14]) // 1024} MB): {mark(p2)}"
    )
    share_sync = curve["sync_share"]["sync"]
    first_below = next((n for n in IN_FLIGHT if share_sync.get(n, 1.0) < P3_SHARE), None)
    print(
        f"  P3 sync rate below {P3_SHARE * 100:.0f} % of no-serve by N={P3_BY_N}: "
        + (f"first below at N={first_below}" if first_below else "never below inside the sweep")
        + f": {mark(first_below is not None and first_below <= P3_BY_N)}"
    )
    k4 = knee(curve["rate"]["sync"], "throughput")
    print(f"  P4 serving throughput under sync has its knee at N={P4_KNEE_N}: {k4}: {mark(f'N={P4_KNEE_N} ' in k4)}")
    share_nice = curve["sync_share"]["nice"]
    nice_share_ok = all(share_nice.get(n, 0) >= P5_SHARE for n in IN_FLIGHT)
    frac = {n: curve["rate"]["nice"].get(n, 0) / curve["rate"]["sync"][n] for n in IN_FLIGHT if curve["rate"]["sync"].get(n)}
    nice_rate_ok = all(f <= P5_THROUGHPUT_FRACTION for f in frac.values())
    print(
        f"  P5 at nice 19: sync rate at least {P5_SHARE * 100:.0f} % at every N ("
        + ", ".join(f"N={n}: {share_nice.get(n, float('nan')) * 100:.0f} %" for n in IN_FLIGHT)
        + f"): {mark(nice_share_ok)}; serving throughput at most half of normal priority ("
        + ", ".join(f"N={n}: {frac[n] * 100:.0f} %" for n in IN_FLIGHT if n in frac)
        + f"): {mark(nice_rate_ok)}"
    )
    ttfb = {state_of(r[0]): r for r in rows(obs_path, "TTFB")}
    t_idle = ttfb["idle"]
    p50, p99 = int(t_idle[3]), int(t_idle[5])
    print(
        f"  P6 TTFB at idle p50 under 1 ms and p99 under 5 ms: p50 {fmt_ms(p50)}, p90 {fmt_ms(int(t_idle[4]))}, "
        f"p99 {fmt_ms(p99)}, max {fmt_ms(int(t_idle[6]))}, n={t_idle[2]}: {mark(p50 < P6_P50_US and p99 < P6_P99_US)}"
    )
    if "sync" in ttfb:
        t = ttfb["sync"]
        print(f"     TTFB under sync (recorded): p50 {fmt_ms(int(t[3]))}, p99 {fmt_ms(int(t[5]))}, max {fmt_ms(int(t[6]))}")
    p99_idle_8 = curve["p99_us"]["idle"].get(8, float("nan"))
    rising = all(
        curve["p99_us"]["idle"].get(b, 0) >= curve["p99_us"]["idle"].get(a, 0) for a, b in zip(IN_FLIGHT, IN_FLIGHT[1:])
    )
    p7 = p99_idle_8 <= P7_SESSION1_P99_US * P7_FACTOR and rising
    print(
        f"  P7 idle p99 at N=8 within 2x of session 1's 5.6 ms, and rising with N: "
        f"N=8 {p99_idle_8 / 1000:.1f} ms, {'rising' if rising else 'not rising'}: {mark(p7)}"
    )

    print("\n== the open pre-head estimate (0 to 1 ms per request) ==")
    if p50 < PREHEAD_ESTIMATE_HIGH_US:
        print(f"  SETTLED: TTFB p50 at idle is {fmt_ms(p50)}, a bound from above inside the band")
    else:
        print(f"  REPLACED: TTFB p50 at idle is {fmt_ms(p50)}, a bound from above outside the band; the measured figure stands")

    print("\n== environment ==")
    print(f"  board temperature: {min(temps) / 1000:.1f} to {max(temps) / 1000:.1f} C over {len(env)} samples")
    print(f"  governor: {sorted({e[3] for e in env})}")
    freqs = [int(e[4]) for e in env]
    top = max(freqs)
    below = [(e[0], e[1], int(e[4]) // 1000, int(e[2]) / 1000) for e in env if int(e[4]) < top]
    print(
        f"  CPU clock at the sample: {min(freqs) // 1000} to {top // 1000} MHz; "
        f"{len(below)} of {len(freqs)} samples below {top // 1000} MHz"
    )
    for utc, tag, mhz, deg in below:
        print(f"    {utc} {tag:22s} {mhz} MHz at {deg:.1f} C")
    srss = [int(e[8]) for e in env if e[8].isdigit()]
    if srss:
        print(f"  syncing daemon RSS kB: {min(srss)} to {max(srss)}")
    sysrss = [int(e[13]) for e in env if len(e) > 13 and e[13].isdigit()]
    if sysrss:
        print(f"  resident daemon RSS kB: {min(sysrss)} to {max(sysrss)}")
    ttfb_obs = [int(r[4]) for r in obs if r[1] == "ttfb" and state_of(r[0]) == "idle"]
    if ttfb_obs:
        print(f"  TTFB at idle, mean of the samples: {fmt_ms(statistics.fmean(ttfb_obs))}, n={len(ttfb_obs)}")
    return 0


# --- selftest ---------------------------------------------------------------


def _stamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _synthetic(root: Path, **tweak: object) -> tuple[Path, Path, Path]:
    """A complete registered session in which every prediction holds, with
    optional tweaks that make one thing come out otherwise.

    The session has a clock: every window's points are stamped against the
    environment row written when it opened, and, as in the 2026-10-09
    capture, every sync window's first recorded point is the last line of
    the previous window unless `no_stale` says otherwise."""
    obs: list[str] = []
    env: list[str] = []
    syn: list[str] = []
    p99_at = dict(tweak.get("p99_us", {}))  # type: ignore[arg-type]
    rate_at = dict(tweak.get("rate", {}))  # type: ignore[arg-type]
    share_at = dict(tweak.get("share", {}))  # type: ignore[arg-type]
    stalls_at = dict(tweak.get("stalls", {}))  # type: ignore[arg-type]
    drop = set(tweak.get("drop", ()))  # type: ignore[arg-type]
    drop_exit = set(tweak.get("drop_exit", ()))  # type: ignore[arg-type]
    drop_window = set(tweak.get("drop_window", ()))  # type: ignore[arg-type]
    drop_env = set(tweak.get("drop_env", ()))  # type: ignore[arg-type]
    no_stale = bool(tweak.get("no_stale", False))
    temp = int(tweak.get("temp_mC", 55_000))  # type: ignore[arg-type]
    swap = list(tweak.get("swap_free", [0, 0]))  # type: ignore[arg-type]
    ttfb = dict(tweak.get("ttfb", {}))  # type: ignore[arg-type]
    refused_at = dict(tweak.get("refused", {}))  # type: ignore[arg-type]
    # The probe sees one empty close fewer than the endpoint counted.
    probe_short = bool(tweak.get("probe_short", False))
    # Ten blocks per point when the daemon is alone, so a share that is a
    # multiple of a tenth gives whole heights and an exact rate.
    quiet_rate = 2.5
    quiet_seconds = 45.0
    point_every = 4.0
    # Defaults chosen so every prediction holds: lateness over 100 ms from
    # N=16 under sync, sync share under 75 % from N=16, throughput flat
    # past 16, nice keeps 95 % of the rate at a third of the throughput.
    default_p99 = {"idle": {8: 5_000, 16: 8_000, 32: 12_000, 64: 20_000},
                   "sync": {8: 40_000, 16: 150_000, 32: 200_000, 64: 250_000},
                   "nice": {8: 30_000, 16: 60_000, 32: 90_000, 64: 120_000}}
    default_rate = {"idle": {8: 52, 16: 60, 32: 62, 64: 62},
                    "sync": {8: 20, 16: 30, 32: 31, 64: 31},
                    "nice": {8: 6, 16: 9, 32: 10, 64: 10}}
    default_share = {"sync": {8: 0.80, 16: 0.60, 32: 0.50, 64: 0.40},
                     "nice": {8: 0.97, 16: 0.95, 32: 0.94, 64: 0.93}}

    clock = utc_seconds("2026-10-09T02:00:00Z")
    height = 100
    last_point: tuple[float, int] | None = None
    target = 2240

    def env_row(tag: str) -> None:
        if tag in drop_env:
            return
        free = swap[min(len(env), len(swap) - 1)]
        env.append(
            f"ENV\t{_stamp(clock)}\t{tag}\t{temp}\tondemand\t1800000\t1.0\t1000\t500\t366000"
            f"\t{height}\tfalse\t6000000\t1\t380000\t0\t{free}"
        )

    def window(label: str, state: str, seconds: float, blocks_per_s: float, stalls: int = 0) -> None:
        """Points for one window opening now and lasting `seconds`."""
        nonlocal height, last_point
        if label in drop_window:
            return
        if last_point is not None and not no_stale:
            syn.append(f"SYNCH\t{_stamp(last_point[0])}\t{label}\t{state}\t{last_point[1]}\t{target}")
        k = 0
        first = height
        while k * point_every <= seconds:
            at = clock + k * point_every
            if 0 < k <= stalls:
                h = first
            else:
                h = first + int(round(blocks_per_s * k * point_every))
            syn.append(f"SYNCH\t{_stamp(at)}\t{label}\t{state}\t{h}\t{target}")
            last_point = (at, h)
            height = h
            k += 1

    env_row(f"start.{STORE_BLOCK}")
    obs.append(f"OBS\t{STORE_BLOCK}\tload\tfull-store\t8\t171518\t3330449")
    obs.append(f"BLOCK\t{STORE_BLOCK}\tload\tfull-store\t8\t8\t176\t625\t8\t0")
    obs.append(f"LATE\t{STORE_BLOCK}\tload\tfull-store\t8\t3\t3\t4\t50\t50\t50")
    if STORE_BLOCK not in drop_exit:
        obs.append(f"EXIT\t{STORE_BLOCK}\tload\t0")
    clock += 1
    env_row(f"end.{STORE_BLOCK}")
    for state in STATES:
        for pas in PASSES:
            if state in SYNCING:
                # A fresh daemon has already logged a line before the pass's
                # first window opens, as on the device.
                height = 61
                last_point = (clock - 5.0, 60)
            env_row(f"pass.{state}.{pas}.start")
            if state in SYNCING:
                window(f"{state}.{pas}.quiet", state, quiet_seconds, quiet_rate)
                clock += quiet_seconds
            for n in IN_FLIGHT:
                label = f"{state}.{pas}.N{n}"
                if label in drop:
                    continue
                p99 = p99_at.get((state, n), default_p99[state][n])
                rate = rate_at.get((state, n), default_rate[state][n])
                refused = refused_at.get((state, n), 0)
                served = 256 - refused
                wall_ms = int(served / rate * 1000)
                env_row(f"start.{label}")
                obs.append(f"OBS\t{label}\tload\tfull-store\t{n}\t60000\t3330449")
                for _ in range(refused - (1 if probe_short and refused else 0)):
                    obs.append(f"OBS\t{label}\tload\tfull-store\t{n}\t900\t0")
                obs.append(f"BLOCK\t{label}\tload\tfull-store\t{n}\t256\t{wall_ms}\t15000\t{served}\t{refused}")
                obs.append(f"LATE\t{label}\tload\tfull-store\t{n}\t9000\t1000\t2000\t{p99}\t{p99}\t{p99}")
                if label not in drop_exit:
                    obs.append(f"EXIT\t{label}\tload\t0")
                if state in SYNCING:
                    share = share_at.get((state, n), default_share[state][n])
                    window(label, state, wall_ms / 1000, quiet_rate * share, stalls_at.get((state, n), 0))
                clock += wall_ms / 1000
                env_row(f"end.{label}")
                if state in SYNCING:
                    window(f"{state}.{pas}.quiet{n}", state, quiet_seconds, quiet_rate)
                    clock += quiet_seconds
            if pas == 1 and state in TTFB_STATES:
                label = f"{state}.1.ttfb"
                p50, p99 = ttfb.get(state, (600, 3_000))
                env_row(f"start.{label}")
                obs.append(f"TTFB\t{label}\tfull-store\t300\t{p50}\t900\t{p99}\t4000")
                if label not in drop_exit:
                    obs.append(f"EXIT\t{label}\tttfb\t0")
                for _ in range(300):
                    obs.append(f"OBS\t{label}\tttfb\tfull-store\t1\t{p50}\t3326976")
                if state in SYNCING:
                    window(label, state, 12.0, quiet_rate)
                clock += 12.0
                env_row(f"end.{label}")
            env_row(f"pass.{state}.{pas}.end")
            clock += 1
    paths = (root / "obs.tsv", root / "env.tsv", root / "sync.tsv")
    for path, lines in zip(paths, (obs, env, syn)):
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return paths


def selftest() -> int:
    import contextlib
    import io
    import tempfile

    failures: list[str] = []

    def run(name: str, want_rc: int, needles: tuple[str, ...], **tweak: object) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = _synthetic(Path(raw), **tweak)
            sys.argv = ["reading", *(str(p) for p in paths)]
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main()
            text = out.getvalue()
            problems = [f"rc {rc}, wanted {want_rc}"] if rc != want_rc else []
            problems += [f"missing {needle!r}" for needle in needles if needle not in text]
            if problems:
                failures.append(f"{name}: " + "; ".join(problems))

    run("control: every prediction holds", 0, (
        "P1 p99 wake lateness under sync above 100 ms by N=16: first above at N=16: held",
        "P3 sync rate below 75 % of no-serve by N=16: first below at N=16: held",
        "P4 serving throughput under sync has its knee at N=16: knee at N=16",
        "P6 TTFB at idle p50 under 1 ms and p99 under 5 ms: p50 0.6 ms",
        "P7 idle p99 at N=8 within 2x", "rising: held",
        "SETTLED: TTFB p50 at idle is 0.6 ms",
        "sync  2.50 blocks/s over 15 window(s)",
    ))
    run("P1 missed: lateness stays low under sync", 0, ("never above inside the sweep: missed",),
        p99_us={("sync", 8): 20_000, ("sync", 16): 30_000, ("sync", 32): 40_000, ("sync", 64): 50_000})
    run("P2 missed on temperature", 0, ("hottest 81.0 C", "did not grow (SwapTotal 0 MB): missed"), temp_mC=81_000)
    run("P2 missed on swap growth", 0, ("swap grew (SwapTotal 0 MB): missed",), swap_free=[1000, 500])
    run("P3 missed: the daemon keeps its rate", 0, ("never below inside the sweep: missed",),
        share={("sync", 8): 0.9, ("sync", 16): 0.85, ("sync", 32): 0.8, ("sync", 64): 0.78})
    run("void windows are excluded and named", 0, ("void under the registered rule (excluded): sync.1.N16",),
        stalls={("sync", 16): 2})
    run("P4 missed: throughput keeps growing", 0, ("no knee inside the sweep: missed",),
        rate={("sync", 8): 20, ("sync", 16): 30, ("sync", 32): 40, ("sync", 64): 50})
    run("P5 missed: nice does not give the rate back", 0, ("N=32: 50 %", "): missed; serving throughput"),
        share={("nice", 32): 0.5})
    run("P6 missed on p50, and the estimate is REPLACED", 0, ("p50 1.2 ms", "REPLACED: TTFB p50 at idle is 1.2 ms"),
        ttfb={"idle": (1_200, 3_000)})
    run("P7 missed: idle lateness far above session 1", 0, ("N=8 30.0 ms, not rising: missed",),
        p99_us={("idle", 8): 30_000})
    run("the knee of p99 under sync is reported", 0, ("knee at N=8 (rise +275 % to N=16)",))
    run("incomplete: a missing cell", 2, ("NOT A COMPLETE REGISTERED SESSION", "nice N32: 2 BLOCK row(s)"),
        drop={"nice.2.N32"})
    run("incomplete: a whole cell missing", 2, ("idle N8: 0 BLOCK row(s)",),
        drop={"idle.1.N8", "idle.2.N8", "idle.3.N8"})
    run("incomplete: a block without its exit row", 2, ("idle.1.N16: no exit row; the probe's final status is unknown",),
        drop_exit={"idle.1.N16"})
    run("incomplete: the store block without its exit row", 2, ("prep.store: no exit row",),
        drop_exit={STORE_BLOCK})
    run("incomplete: a no-serve window missing", 2, ("sync: 14 no-serve window(s), registered 15",),
        drop_window={"sync.2.quiet8"})
    run("incomplete: an environment row missing", 2, ("environment: 1 registered row(s) missing (end.nice.2.N32)",),
        drop_env={"end.nice.2.N32"})
    # 253 served over the wall of 253 at 31/s: the rate is over served, so
    # it reads 31.0 and not 30.6.
    run("refusals are recorded, the rate is over served, and the counts agree", 0, (
        "refused   3", "sync N64: 3, 3, 3 over its blocks", "sync.1.N64         31.0/s",
        "agrees with the endpoint's count in every block",
    ), refused={("sync", 64): 3})
    run("the probe's and the endpoint's refusal counts disagree, and it is reported", 0, (
        "DISAGREE", "sync.2.N64: 256 attempted, 253 served, 3 refused by the endpoint, 2 empty close(s) seen by the probe",
    ), refused={("sync", 64): 3}, probe_short=True)
    run("no refusals is said", 0, ("none in any block",))
    # The 2026-10-09 capture's shape: every window's first recorded point
    # was logged before it opened. It is dropped, and the window reads at
    # its own rate: N=8 under sync at 80 % of no-serve exactly.
    run("a point logged before the window opened is dropped, and the rate is the window's", 0, (
        "pre-window points dropped from 55 of 55 windows",
        "sync.1.N8          20.0/s  cpu/resp    59 ms  refused   0  p99   40.0 ms  sync 2.00 blocks/s = 80 % of no-serve",
    ))
    run("a capture with no pre-window points reads the same", 0, (
        "pre-window points dropped from 0 of 55 windows",
        "sync 2.00 blocks/s = 80 % of no-serve",
    ), no_stale=True)
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("selftest: 22 cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
