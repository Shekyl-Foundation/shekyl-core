#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Read BA-T5 session 2: serving beside a syncing daemon, the in-flight
sweep that answers BA-Q4, and time to first byte.

    python3 scripts/bench/ba_t5_session2_reading.py OBS.tsv ENV.tsv SYNC.tsv

The lines and how each is read are fixed in the session's record
(`docs/benchmarks/ba_t5_serve_floor_device_<date>.md`, "Registered before
the run"). This script applies them and adds nothing. It exits 0 whatever
the verdict; a verdict is a result, not an error. It exits 2, before
printing any figure, if the files do not hold the complete registered
session.

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
  SYNC   label state start_height end_height seconds polls stalls
  SYNCH  utc label state height target synchronized   (sync poll)

Labels are `<state>.<pass>.<cell>`: state `idle` or `sync`; cell `N<k>` for
a serving block at k in flight, `quiet` for a no-serve window, `ttfb` for
the time-to-first-byte block.
"""

from __future__ import annotations

import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ba_t5_reading import fmt_ms, med, rows  # noqa: E402

# The registered lines.
LATENESS_P99_LINE_US = 100_000  # (c)
THROTTLE_TEMP_MILLI_C = 80_000  # (d)
MEM_AVAILABLE_FLOOR_KB = 512 * 1024  # (d)
DAEMON_HARM_LINE = 0.75  # (e): serving-window sync rate over no-serve rate
TTFB_P50_LINE_US = 1_000  # pre-head
TTFB_P99_LINE_US = 5_000  # pre-head

# The registered session.
STATES = ("idle", "sync")
IN_FLIGHT = (8, 16, 32, 64)
BLOCKS_PER_CELL = 3
QUIET_WINDOWS_PER_PASS_MIN = 1
TTFB_SAMPLES = 300
# A syncing block counts only if the daemon's height advanced throughout
# its window: at most this many one-second polls at which it did not move,
# and it must not have reached its target inside the window.
SYNC_STALL_POLLS_MAX = 2


def state_of(label: str) -> str:
    return label.split(".", 1)[0]


def cell_of(label: str) -> str:
    return label.rsplit(".", 1)[-1]


def pass_of(label: str) -> str:
    parts = label.split(".")
    return parts[1] if len(parts) >= 3 else ""


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
            if state == "sync":
                have_s = sum(1 for s in sync if state_of(s[0]) == state and cell_of(s[0]) == cell)
                if have_s < BLOCKS_PER_CELL:
                    found.append(f"sync N{n}: {have_s} SYNC window(s), registered at least {BLOCKS_PER_CELL}")
    quiet = [s for s in sync if state_of(s[0]) == "sync" and cell_of(s[0]) == "quiet"]
    passes = {pass_of(s[0]) for s in sync if state_of(s[0]) == "sync"}
    for p in sorted(passes):
        if sum(1 for s in quiet if pass_of(s[0]) == p) < QUIET_WINDOWS_PER_PASS_MIN:
            found.append(f"sync pass {p}: no no-serve window, so line (e) has no denominator for it")
    if not passes:
        found.append("no sync pass at all")
    for state in STATES:
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
    """Blocks per second across one SYNC window, or None if it is void."""
    start, end, seconds, stalls = window[2], window[3], int(window[4]), int(window[6])
    if start == "na" or end == "na" or seconds <= 0:
        return None
    if int(end) <= int(start) or stalls > SYNC_STALL_POLLS_MAX:
        return None
    return (int(end) - int(start)) / seconds


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

    # Sync windows by label; void ones are reported and excluded.
    windows: dict[str, float | None] = {s[0]: sync_rate(s) for s in sync}
    void = sorted(label for label, r in windows.items() if r is None and state_of(label) == "sync")
    print("\n== sync windows ==")
    for s in sync:
        if state_of(s[0]) != "sync":
            continue
        r = windows[s[0]]
        shown = f"{r:.2f} blocks/s" if r is not None else "VOID (did not advance throughout, or reached its target)"
        print(f"  {s[0]:18s} {s[2]:>5s} -> {s[3]:>5s} in {s[4]:>4s} s, {s[6]} stall(s): {shown}")
    quiet_by_pass: dict[str, list[float]] = defaultdict(list)
    for label, r in windows.items():
        if state_of(label) == "sync" and cell_of(label) == "quiet" and r is not None:
            quiet_by_pass[pass_of(label)].append(r)
    all_quiet = [r for v in quiet_by_pass.values() for r in v]
    print(f"  no-serve sync rate: median {med(all_quiet):.2f} blocks/s over {len(all_quiet)} window(s)")

    print("\n== serving blocks: responses/s, CPU per response, refusals, p99 wake lateness, sync rate ==")
    per_cell: dict[tuple[str, int], dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    late_by_label = {r[0]: r for r in late if r[1] == "load"}
    for b in blocks:
        if b[1] != "load":
            continue
        state, n = state_of(b[0]), int(b[3])
        lat = late_by_label.get(b[0])
        p99 = float(lat[7]) if lat else float("nan")
        sr = windows.get(b[0])
        cell = per_cell[(state, n)]
        cell["rate"].append(rate_per_s(b))
        cell["cpu_ms"].append(int(b[6]) / int(b[4]))
        cell["refused"].append(float(b[8]) if len(b) > 8 else 0.0)
        cell["p99"].append(p99)
        if state == "sync":
            cell["sync_rate"].append(sr if sr is not None else float("nan"))
        sr_shown = "" if state != "sync" else (f"  sync {sr:.2f} blocks/s" if sr is not None else "  sync VOID")
        print(
            f"  {b[0]:18s} {rate_per_s(b):6.1f}/s  cpu/resp {int(b[6]) / int(b[4]):5.0f} ms  "
            f"refused {b[8] if len(b) > 8 else '-':>3s}  p99 {p99 / 1000:6.1f} ms{sr_shown}"
        )

    print("\n== the lines ==")
    swap_free = [int(e[15]) for e in env]
    swap_grew = any(b < a for a, b in zip(swap_free, swap_free[1:]))
    temps = [int(e[2]) for e in env]
    mem_low = min(int(e[11]) for e in env)
    ok_d_session = max(temps) < THROTTLE_TEMP_MILLI_C and mem_low >= MEM_AVAILABLE_FLOOR_KB and not swap_grew
    print(
        f"  (d) across the session: hottest {max(temps) / 1000:.1f} C (line < 80), lowest MemAvailable "
        f"{mem_low / 1024:.0f} MB (line >= 512), swap {'grew' if swap_grew else 'did not grow'} "
        f"(SwapTotal {int(env[0][14]) // 1024} MB): {'HOLDS' if ok_d_session else 'FAILS'}"
    )
    verdict: dict[int, dict[str, bool]] = {}
    for n in IN_FLIGHT:
        cell = per_cell[("sync", n)]
        worst_p99 = max(cell["p99"])
        ok_c = worst_p99 <= LATENESS_P99_LINE_US
        valid_sync = [r for r in cell["sync_rate"] if r == r]  # drop NaN (void)
        if len(valid_sync) < BLOCKS_PER_CELL or not all_quiet:
            ok_e = False
            e_shown = f"only {len(valid_sync)} valid sync window(s) of {BLOCKS_PER_CELL} registered"
        else:
            ratio = med(valid_sync) / med(all_quiet)
            ok_e = ratio >= DAEMON_HARM_LINE
            e_shown = f"sync {med(valid_sync):.2f} / {med(all_quiet):.2f} blocks/s = {ratio:.2f} (line >= {DAEMON_HARM_LINE})"
        idle = per_cell[("idle", n)]
        verdict[n] = {"c": ok_c, "d": ok_d_session, "e": ok_e}
        print(
            f"  N={n:<3d} (c) worst p99 {worst_p99 / 1000:6.1f} ms under sync (idle {max(idle['p99']) / 1000:.1f}): "
            f"{'HOLDS' if ok_c else 'FAILS'}; (e) {e_shown}: {'HOLDS' if ok_e else 'FAILS'}; "
            f"throughput under sync {med(cell['rate']):.1f}/s (idle {med(idle['rate']):.1f}/s)"
        )

    print("\n== BA-Q4, as registered ==")
    # The sweep is read upward and stops at the first N that fails: the
    # constant is the last N before it. A higher N that holds after a lower
    # one failed is not counted; it is a non-monotone result, which is
    # reported as a finding and not as a value.
    largest: int | None = None
    first_failure: int | None = None
    for n in IN_FLIGHT:
        if all(verdict[n].values()):
            if first_failure is None:
                largest = n
        elif first_failure is None:
            first_failure = n
    non_monotone = [n for n in IN_FLIGHT if first_failure is not None and n > first_failure and all(verdict[n].values())]
    if first_failure == IN_FLIGHT[0]:
        print(f"  N={IN_FLIGHT[0]} FAILS under sync: the headline finding. MAX_INFLIGHT is not derived by this session.")
    elif first_failure is None:
        print(
            f"  every tested N holds, up to {largest}. CPU does not bind at or below {largest}; "
            "not searched beyond. The constant is set by BA-Q4's other half, slow-reader permit exhaustion."
        )
    else:
        print(
            f"  MAX_INFLIGHT = {largest}: the largest N at which (c), (d) and (e) all hold under sync "
            f"before the first N that fails, N={first_failure}"
        )
    for n in IN_FLIGHT:
        if not all(verdict[n].values()):
            failed = ", ".join(k for k, ok in verdict[n].items() if not ok)
            print(f"    N={n}: fails ({failed})")
    if non_monotone:
        print(
            f"    NON-MONOTONE: {', '.join(f'N={n}' for n in non_monotone)} hold(s) above a failing N; "
            "not counted toward the constant, and a finding in its own right"
        )

    print("\n== time to first byte, one in flight, full segment ==")
    for r in rows(obs_path, "TTFB"):
        state = state_of(r[0])
        p50, p99 = int(r[3]), int(r[5])
        ok = p50 < TTFB_P50_LINE_US and p99 < TTFB_P99_LINE_US
        graded = "graded" if state == "idle" else "reported, not graded"
        print(
            f"  {state:5s} n={r[2]} p50 {fmt_ms(p50)} (line < 1 ms) p90 {fmt_ms(int(r[4]))} p99 {fmt_ms(p99)} "
            f"(line < 5 ms) max {fmt_ms(int(r[6]))}: {'HOLDS' if ok else 'FAILS'} ({graded})"
        )
    ttfb_obs = [int(r[4]) for r in obs if r[1] == "ttfb" and state_of(r[0]) == "idle"]
    if ttfb_obs:
        print(f"  idle, from the samples: mean {fmt_ms(statistics.fmean(ttfb_obs))}, n={len(ttfb_obs)}")

    print("\n== environment ==")
    print(f"  board temperature: {min(temps) / 1000:.1f} to {max(temps) / 1000:.1f} C over {len(env)} samples")
    print(f"  governor: {sorted({e[3] for e in env})}")
    srss = [int(e[9]) for e in env if e[9].isdigit()]
    if srss:
        print(f"  syncing daemon RSS kB: {min(srss)} to {max(srss)}")
    sysrss = [int(e[13]) for e in env if len(e) > 13 and e[13].isdigit()]
    if sysrss:
        print(f"  system daemon RSS kB: {min(sysrss)} to {max(sysrss)}")
    if void:
        print(f"  void sync windows: {', '.join(void)}")
    return 0


# --- selftest ---------------------------------------------------------------


def _synthetic(root: Path, **tweak: object) -> tuple[Path, Path, Path]:
    """A complete registered session in which every line holds, with
    optional tweaks that make one thing fail."""
    obs: list[str] = []
    env: list[str] = []
    syn: list[str] = []
    p99_at = dict(tweak.get("p99_us", {}))  # type: ignore[arg-type]
    sync_rate_at = dict(tweak.get("sync_rate", {}))  # type: ignore[arg-type]
    stalls_at = dict(tweak.get("stalls", {}))  # type: ignore[arg-type]
    drop = set(tweak.get("drop", ()))  # type: ignore[arg-type]
    temp = int(tweak.get("temp_mC", 55_000))  # type: ignore[arg-type]
    swap = list(tweak.get("swap_free", [0, 0]))  # type: ignore[arg-type]
    ttfb = dict(tweak.get("ttfb", {}))  # type: ignore[arg-type]
    quiet_rate = 2.9
    for state in STATES:
        for pas in ("1", "2", "3"):
            if state == "sync":
                label = f"sync.{pas}.quiet"
                syn.append(f"SYNC\t{label}\tsync\t100\t{100 + int(quiet_rate * 30)}\t30\t30\t0")
            for n in IN_FLIGHT:
                label = f"{state}.{pas}.N{n}"
                if label in drop:
                    continue
                p99 = p99_at.get((state, n), 5_000)
                obs.append(f"OBS\t{label}\tload\tfull-store\t{n}\t60000\t3330449")
                obs.append(f"BLOCK\t{label}\tload\tfull-store\t{n}\t256\t10000\t15000\t256\t0")
                obs.append(f"LATE\t{label}\tload\tfull-store\t{n}\t9000\t1000\t2000\t{p99}\t{p99}\t{p99}")
                obs.append(f"EXIT\t{label}\tload\t0")
                if state == "sync":
                    r = sync_rate_at.get(n, 2.6)
                    stalls = stalls_at.get(n, 0)
                    syn.append(f"SYNC\t{label}\tsync\t200\t{200 + int(r * 20)}\t20\t20\t{stalls}")
        p50, p99 = ttfb.get(state, (600, 3_000))
        obs.append(f"TTFB\t{state}.1.ttfb\tfull-store\t300\t{p50}\t900\t{p99}\t4000")
        obs.append(f"EXIT\t{state}.1.ttfb\tttfb\t0")
        for i in range(300):
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

    run("control: everything holds", 0, ("every tested N holds, up to 64", "(c) worst p99    5.0 ms under sync", "HOLDS (graded)"))
    run("(c) fails at 64 -> MAX_INFLIGHT = 32", 0, ("MAX_INFLIGHT = 32", "N=64: fails (c)"), p99_us={("sync", 64): 150_000})
    run("(c) fails at 8 -> the headline", 0, ("N=8 FAILS under sync: the headline finding", "NON-MONOTONE: N=16, N=32, N=64"), p99_us={("sync", 8): 120_000})
    run("a higher N holding above a failure is not counted", 0, ("MAX_INFLIGHT = 8", "NON-MONOTONE: N=32, N=64"), p99_us={("sync", 16): 120_000})
    run("(e) fails at 32 -> MAX_INFLIGHT = 16", 0, ("MAX_INFLIGHT = 16", "N=32: fails (e)"), sync_rate={32: 1.5})
    run("(e) fails on void windows at 16", 0, ("MAX_INFLIGHT = 8", "N=16: fails (e)", "VOID"), stalls={16: 5})
    run("(d) fails on temperature", 0, ("(d) across the session: hottest 81.0 C", "FAILS", "N=8 FAILS under sync"), temp_mC=81_000)
    run("(d) fails on swap growth", 0, ("swap grew", "N=8 FAILS under sync"), swap_free=[1000, 500])
    run("TTFB p50 fails", 0, ("p50 1.2 ms (line < 1 ms)", "FAILS (graded)"), ttfb={"idle": (1_200, 3_000)})
    run("TTFB p99 fails", 0, ("p99 6.0 ms (line < 5 ms)", "FAILS (graded)"), ttfb={"idle": (600, 6_000)})
    run("TTFB under sync is reported, not graded", 0, ("FAILS (reported, not graded)",), ttfb={"sync": (1_200, 9_000)})
    run("incomplete: a missing cell", 2, ("NOT A COMPLETE REGISTERED SESSION", "sync N32: 2 BLOCK row(s)"), drop={"sync.2.N32"})
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print("selftest: 12 cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
