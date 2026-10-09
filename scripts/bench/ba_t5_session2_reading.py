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
the files do not hold the complete registered session.

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
"""

from __future__ import annotations

import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ba_t5_reading import fmt_ms, med, rows  # noqa: E402

# The registered session.
STATES = ("idle", "sync", "nice")
SYNCING = ("sync", "nice")
IN_FLIGHT = (8, 16, 32, 64)
BLOCKS_PER_CELL = 3
TTFB_STATES = ("idle", "sync")
TTFB_SAMPLES = 300
SYNC_STALL_POINTS_MAX = 1
SYNC_POINTS_MIN = 3

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


def incomplete(obs_path: Path, env_path: Path, sync_path: Path) -> list[str]:
    """Why these files are not the complete registered session, if they are not."""
    found: list[str] = []
    exits = rows(obs_path, "EXIT")
    for label, mode, code in exits:
        if code != "0":
            found.append(f"block {label} ({mode}) exited {code}")
    blocks = rows(obs_path, "BLOCK")
    late = rows(obs_path, "LATE")
    ttfb = rows(obs_path, "TTFB")
    env = rows(env_path, "ENV")
    sync = rows(sync_path, "SYNC")
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
                have_s = sum(1 for s in sync if state_of(s[0]) == state and cell_of(s[0]) == cell)
                if have_s < BLOCKS_PER_CELL:
                    found.append(f"{state} N{n}: {have_s} SYNC window(s), registered at least {BLOCKS_PER_CELL}")
        if state in SYNCING:
            quiet = sum(1 for s in sync if state_of(s[0]) == state and cell_of(s[0]).startswith("quiet"))
            if quiet < BLOCKS_PER_CELL:
                found.append(f"{state}: {quiet} no-serve window(s), registered at least {BLOCKS_PER_CELL}")
    for state in TTFB_STATES:
        t = [r for r in ttfb if state_of(r[0]) == state]
        if len(t) != 1:
            found.append(f"{state}: {len(t)} TTFB row(s), registered 1")
        elif int(t[0][2]) < TTFB_SAMPLES:
            found.append(f"{state}: TTFB over {t[0][2]} samples, registered at least {TTFB_SAMPLES}")
    if not env:
        found.append("no environment rows")
    for e in env:
        if len(e) < 16 or not e[2].isdigit() or not e[11].isdigit() or not e[14].isdigit() or not e[15].isdigit():
            found.append(f"environment row {e[:2]} lacks a temperature, memory or swap reading")
            break
    return found


def rate_per_s(block: list[str]) -> float:
    return int(block[4]) / (int(block[5]) / 1000)


def sync_rate(window: list[str]) -> float | None:
    """Blocks per second across one SYNC window, or None if it is void.

    The points are the daemon's own "Synced H/T" log lines, about eight
    seconds apart; `seconds` is the span between the first and the last
    point's timestamps. Void: fewer than three points, a point at which the
    height did not advance beyond one, no advance over the window, or the
    target reached at the last point."""
    first, last, seconds, points, stalls = window[2], window[3], float(window[4]), int(window[5]), int(window[6])
    target = window[7] if len(window) > 7 else "na"
    if first == "na" or last == "na" or seconds <= 0 or points < SYNC_POINTS_MIN:
        return None
    if int(last) <= int(first) or stalls > SYNC_STALL_POINTS_MAX:
        return None
    if target != "na" and int(last) >= int(target):
        return None
    return (int(last) - int(first)) / seconds


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
    print(f"blocks: {len(exits)}, all exited 0; every registered cell is present")

    blocks = rows(obs_path, "BLOCK")
    late = rows(obs_path, "LATE")
    sync = rows(sync_path, "SYNC")
    env = rows(env_path, "ENV")
    obs = rows(obs_path, "OBS")

    windows: dict[str, float | None] = {s[0]: sync_rate(s) for s in sync}
    quiet: dict[str, list[float]] = defaultdict(list)
    for label, r in windows.items():
        if cell_of(label).startswith("quiet") and r is not None:
            quiet[state_of(label)].append(r)
    print("\n== no-serve sync rate, per state (median over valid windows) ==")
    for state in SYNCING:
        print(f"  {state:5s} {med(quiet[state]):.2f} blocks/s over {len(quiet[state])} window(s)")
    void = sorted(label for label, r in windows.items() if r is None)
    if void:
        print(f"  void windows (excluded): {', '.join(void)}")

    late_by_label = {r[0]: r for r in late if r[1] == "load"}
    per: dict[str, dict[str, dict[int, list[float]]]] = {
        q: {state: defaultdict(list) for state in STATES}
        for q in ("rate", "cpu_ms", "p99_us", "refused", "sync_share")
    }
    print("\n== serving blocks ==")
    for b in blocks:
        if b[1] != "load":
            continue
        state, n = state_of(b[0]), int(b[3])
        lat = late_by_label.get(b[0])
        p99 = float(lat[7]) if lat else float("nan")
        per["rate"][state][n].append(rate_per_s(b))
        per["cpu_ms"][state][n].append(int(b[6]) / int(b[4]))
        per["p99_us"][state][n].append(p99)
        per["refused"][state][n].append(float(b[8]) if len(b) > 8 else 0.0)
        share = ""
        if state in SYNCING:
            r = windows.get(b[0])
            if r is not None and quiet[state]:
                per["sync_share"][state][n].append(r / med(quiet[state]))
                share = f"  sync {r:.2f} blocks/s = {r / med(quiet[state]) * 100:.0f} % of no-serve"
            else:
                share = "  sync window VOID"
        print(
            f"  {b[0]:16s} {rate_per_s(b):6.1f}/s  cpu/resp {int(b[6]) / int(b[4]):5.0f} ms  "
            f"refused {b[8] if len(b) > 8 else '-':>3s}  p99 {p99 / 1000:6.1f} ms{share}"
        )
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
            print_curve("sync rate, share of no-serve", "x", curve["sync_share"][state], "fall")

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
    srss = [int(e[9]) for e in env if e[9].isdigit()]
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


def _synthetic(root: Path, **tweak: object) -> tuple[Path, Path, Path]:
    """A complete registered session in which every prediction holds, with
    optional tweaks that make one thing come out otherwise."""
    obs: list[str] = []
    env: list[str] = []
    syn: list[str] = []
    p99_at = dict(tweak.get("p99_us", {}))  # type: ignore[arg-type]
    rate_at = dict(tweak.get("rate", {}))  # type: ignore[arg-type]
    share_at = dict(tweak.get("share", {}))  # type: ignore[arg-type]
    stalls_at = dict(tweak.get("stalls", {}))  # type: ignore[arg-type]
    drop = set(tweak.get("drop", ()))  # type: ignore[arg-type]
    temp = int(tweak.get("temp_mC", 55_000))  # type: ignore[arg-type]
    swap = list(tweak.get("swap_free", [0, 0]))  # type: ignore[arg-type]
    ttfb = dict(tweak.get("ttfb", {}))  # type: ignore[arg-type]
    quiet_rate = 2.9
    # Defaults chosen so every prediction holds: lateness over 100 ms from
    # N=16 under sync, sync share under 75 % from N=16, throughput flat
    # past 16, nice keeps 95 % of the rate at a third of the throughput.
    default_p99 = {"idle": {8: 5_000, 16: 8_000, 32: 12_000, 64: 20_000},
                   "sync": {8: 40_000, 16: 150_000, 32: 200_000, 64: 250_000},
                   "nice": {8: 30_000, 16: 60_000, 32: 90_000, 64: 120_000}}
    default_rate = {"idle": {8: 52, 16: 60, 32: 62, 64: 62},
                    "sync": {8: 20, 16: 30, 32: 31, 64: 31},
                    "nice": {8: 6, 16: 9, 32: 10, 64: 10}}
    default_share = {"sync": {8: 0.80, 16: 0.60, 32: 0.50, 64: 0.45},
                     "nice": {8: 0.97, 16: 0.95, 32: 0.94, 64: 0.93}}
    for state in STATES:
        for pas in ("1", "2", "3"):
            if state in SYNCING:
                syn.append(f"SYNC\t{state}.{pas}.quiet\t{state}\t100\t{100 + int(quiet_rate * 40)}\t40.0\t5\t0\t2240")
            for n in IN_FLIGHT:
                label = f"{state}.{pas}.N{n}"
                if label in drop:
                    continue
                p99 = p99_at.get((state, n), default_p99[state][n])
                rate = rate_at.get((state, n), default_rate[state][n])
                wall_ms = int(256 / rate * 1000)
                obs.append(f"OBS\t{label}\tload\tfull-store\t{n}\t60000\t3330449")
                obs.append(f"BLOCK\t{label}\tload\tfull-store\t{n}\t256\t{wall_ms}\t15000\t256\t0")
                obs.append(f"LATE\t{label}\tload\tfull-store\t{n}\t9000\t1000\t2000\t{p99}\t{p99}\t{p99}")
                obs.append(f"EXIT\t{label}\tload\t0")
                if state in SYNCING:
                    share = share_at.get((state, n), default_share[state][n])
                    stalls = stalls_at.get((state, n), 0)
                    syn.append(f"SYNC\t{label}\t{state}\t200\t{200 + int(quiet_rate * share * 56)}\t56.0\t7\t{stalls}\t2240")
        if state in TTFB_STATES:
            p50, p99 = ttfb.get(state, (600, 3_000))
            obs.append(f"TTFB\t{state}.1.ttfb\tfull-store\t300\t{p50}\t900\t{p99}\t4000")
            obs.append(f"EXIT\t{state}.1.ttfb\tttfb\t0")
            for _ in range(300):
                obs.append(f"OBS\t{state}.1.ttfb\tttfb\tfull-store\t1\t{p50}\t3326976")
    for i, free in enumerate(swap):
        env.append(
            f"ENV\t2026-10-09T01:0{i}:00Z\ttick\t{temp}\tondemand\t1800000\t1.0\t1000\t500\t366000"
            f"\t500\tfalse\t6000000\t1\t380000\t0\t{free}"
        )
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
    ))
    run("P1 missed: lateness stays low under sync", 0, ("never above inside the sweep: missed",),
        p99_us={("sync", 8): 20_000, ("sync", 16): 30_000, ("sync", 32): 40_000, ("sync", 64): 50_000})
    run("P2 missed on temperature", 0, ("hottest 81.0 C", "did not grow (SwapTotal 0 MB): missed"), temp_mC=81_000)
    run("P2 missed on swap growth", 0, ("swap grew (SwapTotal 0 MB): missed",), swap_free=[1000, 500])
    run("P3 missed: the daemon keeps its rate", 0, ("never below inside the sweep: missed",),
        share={("sync", 8): 0.9, ("sync", 16): 0.85, ("sync", 32): 0.8, ("sync", 64): 0.78})
    run("void windows are excluded and named", 0, ("void windows (excluded): sync.1.N16",),
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
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("selftest: 13 cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
