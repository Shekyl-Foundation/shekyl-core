#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The fsync probe: an independent view of the disk's flush latency, as the
# performance budget's control channel (DAEMON_REDB_STORE.md §1.3a rule 2).
#
# One 4 KiB pwrite and fdatasync per second to a file of the probe's own on
# the filesystem under test, each latency recorded with the wall clock. A
# stall of the device or its journal shows whether or not a daemon runs, so a
# measured row whose window holds a stall measures the host, not the daemon,
# and does not count. The same samples qualify a host before any row runs:
# thirty minutes at rest, no stall above STALL_MS, and the median, p99 and
# maximum recorded. A median flush in the microseconds is not a failure: it
# is the signal to verify the storage's write-cache posture (rule 2's
# durability question), which this probe cannot observe.
#
# Commands:
#   run      --dir D --out F [--samples N]   sample once a second, JSON lines
#   summary  F [--start T --end T]           summarise a window of samples
#   qualify  --dir D --out F [--minutes M]   the at-rest soak and its verdict
#   --selftest                               build each refusal and verdict
#
# Python under scripts/bench/, beside drs_bench.py, which starts it beside a
# measured row and reads its window back.

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

# A flush slower than this is a stall (rule 2: "no stall above 1.5 s").
STALL_MS = 1500.0
# The qualification soak: thirty minutes at rest.
QUALIFY_MINUTES = 30
# Below this median the write-cache posture is to be verified, not assumed.
POSTURE_MEDIAN_MS = 1.0
# The share of the soak's seconds that must carry a sample. A probe that
# could not keep its cadence (a host too loaded to schedule it) has not
# observed the window it claims to.
MIN_COVERAGE = 0.95


def covers_window(samples, window_s):
    """Whether `samples` is at least [`MIN_COVERAGE`] of one sample per second
    of `window_s`.

    The debt is the window's length in seconds. Truncating that length
    accepts a probe that missed more than the allowed share of a fractional
    window; rounding it up demands a sample the window does not have.
    """
    return window_s > 0 and samples >= MIN_COVERAGE * window_s


BLOCK = b"x" * 4096
SLOTS = 1024


def sample_forever(path, out, samples=None, clock=time.time, mono=time.monotonic):
    """Write one sample a second to `out` (an open text file) until `samples`
    have been taken, or forever when `samples` is None."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        i = 0
        while samples is None or i < samples:
            t = clock()
            t0 = mono()
            os.pwrite(fd, BLOCK, (i % SLOTS) * len(BLOCK))
            os.fdatasync(fd)
            ms = (mono() - t0) * 1000.0
            out.write(json.dumps({"t": round(t, 3), "ms": round(ms, 3)}) + "\n")
            out.flush()
            i += 1
            time.sleep(max(0.0, 1.0 - ms / 1000.0))
    finally:
        os.close(fd)


def read(path):
    """The samples in a probe file, in order. A line that does not parse is a
    refusal: a probe file is the evidence a row counted, and a damaged one
    is not evidence."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                s = json.loads(line)
                out.append((float(s["t"]), float(s["ms"])))
            except (ValueError, KeyError, TypeError) as e:
                raise ValueError(f"{path}:{n}: not a probe sample ({e})") from e
    return out


def window(samples, start, end):
    """The samples whose write began inside [start, end]."""
    return [(t, ms) for (t, ms) in samples if start <= t <= end]


def _p99(values):
    if len(values) < 2:
        return values[0] if values else None
    return statistics.quantiles(values, n=100, method="inclusive")[98]


def summary(samples):
    """Count, median, p99, maximum, and the stalls, of a list of samples."""
    ms = [m for (_, m) in samples]
    stalls = [(t, m) for (t, m) in samples if m > STALL_MS]
    return {
        "samples": len(ms),
        "median_ms": statistics.median(ms) if ms else None,
        "p99_ms": _p99(ms),
        "max_ms": max(ms) if ms else None,
        "stall_ms": STALL_MS,
        "stalls": len(stalls),
        "stalled_s": round(sum(m for (_, m) in stalls) / 1000.0, 3),
        "first_stall_t": stalls[0][0] if stalls else None,
    }


def row_refusal(samples, start, end):
    """Why a measured row over [start, end] does not count, or None.

    A row counts only with the probe beside it the whole time and no stall
    inside its window (rule 2)."""
    if end <= start:
        return f"the row's window [{start}, {end}] is empty"
    w = window(samples, start, end)
    owed = end - start
    if owed > 0 and not covers_window(len(w), owed):
        return (f"the probe took {len(w)} sample(s) in a {owed:g} s window "
                f"(under {MIN_COVERAGE:.0%}): it did not watch the row")
    s = summary(w)
    if s["stalls"]:
        return (f"{s['stalls']} probe stall(s) above {STALL_MS:.0f} ms inside the row "
                f"({s['stalled_s']} s stalled, the first at t={s['first_stall_t']}): "
                "the row measured the host, not the daemon")
    return None


def qualify(samples, minutes=QUALIFY_MINUTES):
    """The at-rest verdict over a soak: `qualified`, the summary, and the
    notes a reader must act on."""
    s = summary(samples)
    notes = []
    owed = minutes * 60
    if not covers_window(s["samples"], owed):
        notes.append(f"{s['samples']} sample(s) for a {minutes}-minute soak "
                     f"(under {MIN_COVERAGE:.0%} of {owed}): not qualified")
    if s["stalls"]:
        notes.append(f"{s['stalls']} stall(s) above {STALL_MS:.0f} ms at rest: not qualified")
    qualified = not notes
    if s["median_ms"] is not None and s["median_ms"] < POSTURE_MEDIAN_MS:
        notes.append(f"median flush {s['median_ms']:.3f} ms: verify and record the write-cache "
                     "posture (power-loss protected, or a volatile cache that voids DRS-D9)")
    return {"qualified": qualified, "minutes": minutes, "summary": s, "notes": notes}


def _selftest():
    fails = []
    passed = 0

    def check(name, got, want):
        nonlocal passed
        if got != want:
            fails.append(f"{name}: got {got!r}, want {want!r}")
        else:
            passed += 1

    calm = [(1000.0 + i, 2.0) for i in range(60)]
    check("a calm window counts", row_refusal(calm, 1000.0, 1059.0), None)
    stalled = calm[:30] + [(1030.0, 4000.0)] + calm[31:]
    r = row_refusal(stalled, 1000.0, 1059.0)
    check("a stall inside the window refuses the row", r is not None and "stall" in r, True)
    check("a stall outside the window does not", row_refusal(stalled, 1031.0, 1059.0), None)
    sparse = calm[::3]
    r = row_refusal(sparse, 1000.0, 1059.0)
    check("a probe that missed the window refuses the row", r is not None and "watch" in r, True)
    check("an empty window refuses", row_refusal(calm, 5.0, 5.0) is not None, True)
    # Ten samples in 10.9s is under 95% of the seconds. int(10.9) is 10 and
    # would have accepted them.
    short = [(float(i), 1.0) for i in range(10)]
    check("a fractional second counts in the window",
          row_refusal(short, 0.0, 10.9) is not None and "watch" in row_refusal(short, 0.0, 10.9),
          True)
    check("eleven samples cover a 10.9s window",
          row_refusal([(float(i), 1.0) for i in range(11)], 0.0, 10.9), None)

    soak = [(float(i), 2.0) for i in range(QUALIFY_MINUTES * 60)]
    q = qualify(soak)
    check("a calm soak qualifies", q["qualified"], True)
    check("a calm soak needs no posture check", q["notes"], [])
    q = qualify(soak[:-1] + [(9999.0, 1600.0)])
    check("one stall at rest disqualifies", q["qualified"], False)
    q = qualify(soak[: len(soak) // 2])
    check("half a soak disqualifies", q["qualified"], False)
    fast = [(float(i), 0.05) for i in range(QUALIFY_MINUTES * 60)]
    q = qualify(fast)
    check("a microsecond median still qualifies", q["qualified"], True)
    check("and asks for the posture", any("posture" in n for n in q["notes"]), True)

    s = summary([(0.0, 1.0), (1.0, 3.0), (2.0, 2000.0)])
    check("summary counts the stall", (s["stalls"], s["max_ms"], s["median_ms"]), (1, 2000.0, 3.0))

    if fails:
        for f in fails:
            print("FAIL", f, file=sys.stderr)
        sys.exit(1)
    print(f"fsync probe selftest: {passed} cases OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description="The budget's fsync probe (§1.3a rule 2)")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="sample once a second")
    r.add_argument("--dir", required=True, help="a directory on the filesystem under test")
    r.add_argument("--out", required=True, help="where to append the JSON-lines samples")
    r.add_argument("--samples", type=int, default=None, help="stop after this many")
    s = sub.add_parser("summary", help="summarise a window of samples")
    s.add_argument("file")
    s.add_argument("--start", type=float, default=None)
    s.add_argument("--end", type=float, default=None)
    q = sub.add_parser("qualify", help="the at-rest soak and its verdict")
    q.add_argument("--dir", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--minutes", type=int, default=QUALIFY_MINUTES)
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return
    if args.cmd == "run":
        os.makedirs(args.dir, exist_ok=True)
        with open(args.out, "a", encoding="utf-8") as out:
            sample_forever(os.path.join(args.dir, "fsync-probe.dat"), out, args.samples)
    elif args.cmd == "summary":
        samples = read(args.file)
        if args.start is not None or args.end is not None:
            samples = window(samples, args.start or float("-inf"), args.end or float("inf"))
        print(json.dumps(summary(samples), indent=2))
    elif args.cmd == "qualify":
        os.makedirs(args.dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as out:
            sample_forever(os.path.join(args.dir, "fsync-probe.dat"), out, args.minutes * 60)
        verdict = qualify(read(args.out), args.minutes)
        print(json.dumps(verdict, indent=2))
        sys.exit(0 if verdict["qualified"] else 1)
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
