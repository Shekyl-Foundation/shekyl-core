#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Read a BA-T5 floor run: the figures, and the four registered lines.

    python3 scripts/bench/ba_t5_reading.py OBS.tsv ENV.tsv

The lines and how each is read are fixed in the run's record
(`docs/benchmarks/ba_t5_serve_floor_device_*.md`, "Registered before the
run"). This script applies them and adds nothing: it prints every figure
the record quotes, per arm, and a result per line per arm. It exits 0
whatever the verdict; a verdict is a result, not an error. It exits 2,
before printing any line, if the files do not hold the complete registered
run: a block that exited non-zero, or a registered cell that is missing.

Line (a) is read twice and both are printed. As registered, against the
one-leaf frame. And against the frames the production store serves, which
are full segments only: the one-leaf body is a size production cannot
serve, a projection. While (a) as registered stands failed, lines (b) to
(d) are labelled ungraded, which is the registered rule.

Line (d) has a clause this capture cannot evaluate: swap use not growing.
The environment rows carry no swap counter. The script says so on the
line instead of passing it silently.
"""

from __future__ import annotations

import statistics
import sys
from collections import defaultdict
from pathlib import Path

ABANDON_RATIO_LINE = 1.5
ABANDON_CPU_LINE_US = 5_000
THROUGHPUT_LINE_PER_S = 0.5
LATENESS_P99_LINE_US = 100_000
THROTTLE_TEMP_MILLI_C = 80_000
MEM_AVAILABLE_FLOOR_KB = 512 * 1024
ARMS = ("A", "B")

# The registered run, as (mode, label suffix, blocks per arm).
REGISTERED_BLOCKS = {
    "idle": 1,
    "phase": 4,
    "load": 7,  # six graded blocks and the one that leaves the cold store behind
    "cold": 20,  # ten with the store's pages dropped, ten without
    "abandon": 2,
    "sustain": 1,
}
ABANDON_CELLS = ("not-held", "one-leaf", "full-memory", "full-store")
PHASE_SIZES = ("full-store", "eighth", "one-leaf")


def incomplete(exits: list[list[str]], obs_path: Path, env_path: Path) -> list[str]:
    """Why these files are not the complete registered run, if they are not.

    Every row class the report reads is counted here, before anything is
    printed: a figure computed from a capture with a hole in it is worse
    than no figure.
    """
    found: list[str] = []
    for label, mode, code in exits:
        if code != "0":
            found.append(f"block {label} ({mode}) exited {code}")
    obs = rows(obs_path, "OBS")
    phase = rows(obs_path, "PHASE")
    blocks = rows(obs_path, "BLOCK")
    late = rows(obs_path, "LATE")
    abandon = rows(obs_path, "ABANDON")
    env = rows(env_path, "ENV")

    def want(arm: str, what: str, have: int, registered: int, at_least: bool = False) -> None:
        if have < registered or (have != registered and not at_least):
            bound = "at least " if at_least else ""
            found.append(f"arm {arm}: {have} {what}, registered {bound}{registered}")

    for arm in ARMS:
        def mine(row: list[str], arm: str = arm) -> bool:
            return arm_of(row[0]) == arm

        def graded_load(row: list[str]) -> bool:
            return mine(row) and row[1] == "load" and ".load." in row[0]

        for mode, registered in REGISTERED_BLOCKS.items():
            want(arm, f"{mode} block exit(s)", sum(1 for e in exits if e[1] == mode and mine(e)), registered)
        for cell in ABANDON_CELLS:
            want(arm, f"abandon row(s) for {cell}", sum(1 for a in abandon if mine(a) and a[1] == cell), 2)
        for size in PHASE_SIZES:
            want(
                arm, f"phase observations at {size}",
                sum(1 for r in obs if mine(r) and r[1] == "phase" and r[2] == size), 200,
            )
            for name in ("read", "hash"):
                want(
                    arm, f"{name} timings at {size}",
                    sum(1 for r in phase if mine(r) and r[1] == size and r[2] == name), 100,
                )
        want(arm, "sign timings", sum(1 for r in phase if mine(r) and r[2] == "sign"), 100)
        for kind in ("cold", "fresh"):
            want(
                arm, f"{kind} fetch(es)",
                sum(1 for r in obs if r[1] == "cold" and r[0].startswith(f"{arm}.{kind}.")), 10,
            )
        want(arm, "eight-in-flight BLOCK row(s)", sum(1 for b in blocks if graded_load(b)), 6)
        want(arm, "eight-in-flight LATE row(s)", sum(1 for r in late if graded_load(r)), 6)
        want(arm, "idle LATE row(s)", sum(1 for r in late if mine(r) and r[1] == "idle"), 1)
        want(arm, "sustained BLOCK row(s)", sum(1 for b in blocks if mine(b) and b[1] == "sustain"), 1)
        want(
            arm, "minute(s) of sustained LATE rows",
            sum(1 for r in late if mine(r) and r[1] == "sustain"), 59, at_least=True,
        )
        hour = [e for e in env if e[1] in (f"tick.{arm}.sustain", f"start.{arm}.sustain", f"end.{arm}.sustain")]
        # One sample at each end and one every 30 s of an hour.
        want(arm, "environment sample(s) of the sustained hour", len(hour), 110, at_least=True)
        for edge in ("start", "end"):
            want(arm, f"{edge} sample of the sustained hour", sum(1 for e in hour if e[1].startswith(edge)), 1)
    if not env:
        found.append("no environment rows")
    for e in env:
        if len(e) < 13 or not e[2].isdigit() or not e[11].isdigit() or not e[8].isdigit():
            found.append(f"environment row {e[:2]} lacks a temperature, a memory reading or the daemon's size")
            break
    return found


def rows(path: Path, kind: str) -> list[list[str]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = line.split("\t")
        if cells[0] == kind:
            out.append(cells[1:])
    return out


def arm_of(label: str) -> str:
    return label.split(".", 1)[0]


def med(values: list[float]) -> float:
    return statistics.median(values) if values else float("nan")


def pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    return ordered[int((len(ordered) - 1) * q)]


def fmt_ms(us: float) -> str:
    return f"{us / 1000:.1f} ms"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    obs_path, env_path = Path(sys.argv[1]), Path(sys.argv[2])
    exits = rows(obs_path, "EXIT")
    problems = incomplete(exits, obs_path, env_path)
    if problems:
        print("NOT A COMPLETE REGISTERED RUN; nothing is read from it:")
        for problem in problems:
            print("  " + problem)
        return 2
    print(f"blocks: {len(exits)}, all exited 0; every registered cell is present")

    obs = rows(obs_path, "OBS")  # label mode size in_flight micros bytes
    print("\n== per-response time, one in flight (median / mean / p95, n) ==")
    for arm in ARMS:
        for size in ("full-store", "eighth", "one-leaf"):
            v = [float(r[4]) for r in obs if arm_of(r[0]) == arm and r[1] == "phase" and r[2] == size]
            if v:
                print(
                    f"  {arm} {size:11s} {fmt_ms(med(v))} / {fmt_ms(statistics.fmean(v))} / "
                    f"{fmt_ms(pct(v, 0.95))}  n={len(v)}"
                )

    print("\n== phases alone (median, n) ==")
    phase = rows(obs_path, "PHASE")  # label size phase micros
    for arm in ARMS:
        for size in ("full-store", "eighth", "one-leaf", "any"):
            for name in ("read", "hash", "sign"):
                v = [float(r[3]) for r in phase if arm_of(r[0]) == arm and r[1] == size and r[2] == name]
                if v:
                    print(f"  {arm} {size:11s} {name:5s} {fmt_ms(med(v))}  n={len(v)}")
    for arm in ARMS:
        whole = med([float(r[4]) for r in obs if arm_of(r[0]) == arm and r[1] == "phase" and r[2] == "full-store"])
        parts = {
            name: med([float(r[3]) for r in phase if arm_of(r[0]) == arm and r[2] == name and r[1] in ("full-store", "any")])
            for name in ("read", "hash", "sign")
        }
        rest = whole - sum(parts.values())
        print(
            f"  {arm} full segment: whole {fmt_ms(whole)} = read {fmt_ms(parts['read'])} + hash "
            f"{fmt_ms(parts['hash'])} + sign {fmt_ms(parts['sign'])} + write and the rest {fmt_ms(rest)}"
        )

    print("\n== cold (fresh process, store pages dropped) against fresh process alone ==")
    checks = rows(obs_path, "COLDCHECK")
    for arm in ARMS:
        cold = [float(r[4]) for r in obs if r[1] == "cold" and r[0].startswith(f"{arm}.cold.")]
        fresh = [float(r[4]) for r in obs if r[1] == "cold" and r[0].startswith(f"{arm}.fresh.")]
        resident = [c[1] for c in checks if c[0].startswith(f"{arm}.cold.")]
        if cold:
            print(
                f"  {arm} cold {fmt_ms(med(cold))} (n={len(cold)}; resident bytes after drop: "
                f"{sorted(set(resident))}); fresh process, warm {fmt_ms(med(fresh))} (n={len(fresh)})"
            )

    blocks = rows(obs_path, "BLOCK")  # label mode size in_flight n wall_ms cpu_ms served
    late = rows(obs_path, "LATE")  # label mode size in_flight n p50 p90 p99 p999 max
    print("\n== eight in flight: responses per second and CPU per response, per block ==")
    rate: dict[str, list[float]] = defaultdict(list)
    for b in blocks:
        if b[1] == "load" and ".load." in b[0]:
            per_s = int(b[4]) / (int(b[5]) / 1000)
            rate[arm_of(b[0])].append(per_s)
            print(f"  {b[0]:10s} {per_s:6.1f}/s  cpu/response {int(b[6]) / int(b[4]):.0f} ms")
    for arm in ARMS:
        if rate[arm]:
            print(f"  {arm}: min {min(rate[arm]):.1f}  median {med(rate[arm]):.1f}  max {max(rate[arm]):.1f} per second")

    print("\n== wake lateness on the endpoint's executor (us): n p50 p90 p99 p99.9 max ==")
    worst_p99: dict[str, float] = defaultdict(float)
    for row in late:
        arm = arm_of(row[0])
        graded = (row[1] == "load" and ".load." in row[0]) or row[1] == "sustain"
        if graded:
            worst_p99[arm] = max(worst_p99[arm], float(row[7]))
        if row[1] in ("idle", "load") and "coldprep" not in row[0]:
            print(f"  {row[0]:12s} {row[1]:5s} " + " ".join(row[4:]))
    for arm in ARMS:
        minutes = [r for r in late if arm_of(r[0]) == arm and r[1] == "sustain"]
        if minutes:
            p99s = [float(r[7]) for r in minutes]
            print(
                f"  {arm} sustained hour: {len(minutes)} minutes; p99 median {med(p99s):.0f}, "
                f"worst {max(p99s):.0f}; worst max {max(float(r[9]) for r in minutes):.0f}"
            )

    print("\n== abandoned requests: CPU us/request, loopback bytes/request, n ==")
    abandon = rows(obs_path, "ABANDON")  # label size provider n cpu_us bytes served
    cell: dict[tuple[str, str], list[tuple[float, float, int]]] = defaultdict(list)
    for a in abandon:
        cell[(arm_of(a[0]), a[1])].append((float(a[4]), float(a[5]), int(a[3])))
    for (arm, size), v in sorted(cell.items()):
        print(
            f"  {arm} {size:12s} cpu {statistics.fmean(x[0] for x in v):7.0f}  bytes "
            f"{statistics.fmean(x[1] for x in v):9.0f}  n={sum(x[2] for x in v)}  per block: "
            + ", ".join(f"{x[0]:.0f}" for x in v)
        )

    env = rows(env_path, "ENV")  # utc tag temp gov freq load busy djiff drss height synced memavail dpid
    temps = [int(e[2]) for e in env]
    print("\n== environment ==")
    print(f"  board temperature: {min(temps) / 1000:.1f} to {max(temps) / 1000:.1f} C over {len(env)} samples")
    print(f"  governor: {sorted({e[3] for e in env})}")
    heights = [int(e[9]) for e in env if e[9].isdigit()]
    print(f"  daemon height: {heights[0]} -> {heights[-1]}; synced: {sorted({e[10] for e in env})}; pids: {sorted({e[12] for e in env})}")
    print(f"  daemon RSS kB: {min(int(e[8]) for e in env)} to {max(int(e[8]) for e in env)}")
    print(f"  MemAvailable kB: min {min(int(e[11]) for e in env)}")
    rss = rows(env_path, "RSS")
    probe_rss = [int(r[2]) for r in rss if r[2].isdigit()]
    if probe_rss:
        print(f"  probe RSS kB over the sustained hours: {min(probe_rss)} to {max(probe_rss)}")

    print("\n== the four lines ==")
    for arm in ARMS:
        s_cpu = statistics.fmean(x[0] for x in cell[(arm, "one-leaf")])
        f_cpu = statistics.fmean(x[0] for x in cell[(arm, "full-store")])
        ratio = f_cpu / s_cpu
        ok_a = ratio <= ABANDON_RATIO_LINE and s_cpu < ABANDON_CPU_LINE_US and f_cpu < ABANDON_CPU_LINE_US
        print(
            f"  {arm} (a) as registered: one leaf {s_cpu:.0f} us, full segment {f_cpu:.0f} us, "
            f"ratio {ratio:.2f} (line <= {ABANDON_RATIO_LINE}, each < {ABANDON_CPU_LINE_US} us): "
            f"{'PASS' if ok_a else 'FAIL'}"
        )
        # The store serves full segments only, so on production's frames the
        # smallest frame is the full segment and the ratio is 1 by identity.
        ok_production = f_cpu < ABANDON_CPU_LINE_US
        print(
            f"  {arm} (a) on the frames the store serves (full segments only): {f_cpu:.0f} us, "
            f"ratio 1.00: {'HOLDS' if ok_production else 'FAILS'}; the one-leaf figure is a projection"
        )
        word = "PASS" if ok_a else "WOULD PASS (UNGRADED: line (a) as registered failed)"
        fail = "FAIL" if ok_a else "WOULD FAIL (UNGRADED: line (a) as registered failed)"
        ok_b = min(rate[arm]) >= THROUGHPUT_LINE_PER_S
        print(f"  {arm} (b) lowest block {min(rate[arm]):.1f}/s (line >= {THROUGHPUT_LINE_PER_S}): {word if ok_b else fail}")
        ok_c = worst_p99[arm] <= LATENESS_P99_LINE_US
        print(
            f"  {arm} (c) worst p99 wake lateness {worst_p99[arm] / 1000:.1f} ms "
            f"(line <= {LATENESS_P99_LINE_US / 1000:.0f} ms): {word if ok_c else fail}"
        )
        hour = [e for e in env if e[1] in (f"tick.{arm}.sustain", f"start.{arm}.sustain", f"end.{arm}.sustain")]
        hot = max(int(e[2]) for e in hour)
        low = min(int(e[11]) for e in hour)
        ok_d = hot < THROTTLE_TEMP_MILLI_C and low >= MEM_AVAILABLE_FLOOR_KB
        print(
            f"  {arm} (d) sustained hour: hottest {hot / 1000:.1f} C (line < 80), lowest MemAvailable "
            f"{low / 1024:.0f} MB (line >= 512): {word if ok_d else fail}; "
            "swap clause NOT EVALUATED (no swap counter in the capture)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
