#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RT-P6: summarise a run of the handshake-cost harness
# (rust/shekyl-rpc-channel/examples/rt_p6_handshake_cost.rs).
#
#   rt_p6_summary.py RUN_DIR    Markdown on stdout
#
# The statistics are the ones registered in
# docs/benchmarks/rt_p6_handshake_cost_20261018.md: per step and side, the
# median, 90th and 99th percentiles and the maximum of wall and CPU time;
# the same for each side's total per handshake and for both together; the
# daemon's CPU for a stranger's message 1, honest and random; and the cost
# of sealing and opening one record at each class. Percentiles are
# nearest-rank.

import csv
import math
import os
import sys
from collections import defaultdict


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list, p in (0, 100]."""
    if not sorted_values:
        raise ValueError("no samples")
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def stats(values):
    v = sorted(values)
    return {
        "n": len(v),
        "median": percentile(v, 50),
        "p90": percentile(v, 90),
        "p99": percentile(v, 99),
        "max": v[-1],
    }


def us(ns):
    return f"{ns / 1000:,.1f}"


def read(run_dir, name):
    with open(os.path.join(run_dir, name), newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


STEP_ORDER = [
    ("client", "start"),
    ("daemon", "read_message1"),
    ("daemon", "write_message2"),
    ("client", "read_message2"),
    ("client", "write_message3"),
    ("daemon", "read_message3"),
    ("daemon", "write_message4"),
    ("client", "read_message4"),
    ("client", "first_record"),
    ("daemon", "open_first_message"),
]


def summarise(run_dir):
    steps = read(run_dir, "steps.tsv")
    per_step = defaultdict(lambda: ([], []))
    per_side = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in steps:
        key = (r["side"], r["step"])
        w, c = int(r["wall_ns"]), int(r["cpu_ns"])
        per_step[key][0].append(w)
        per_step[key][1].append(c)
        totals = per_side[int(r["iteration"])]
        totals[r["side"]][0] += w
        totals[r["side"]][1] += c
    missing = [k for k in STEP_ORDER if k not in per_step]
    if missing:
        raise SystemExit(f"steps.tsv lacks {missing}")

    print("## Each step (µs)\n")
    print("| Side | Step | n | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p99 |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for key in STEP_ORDER:
        w, c = stats(per_step[key][0]), stats(per_step[key][1])
        print(f"| {key[0]} | `{key[1]}` | {w['n']} | {us(w['median'])} | {us(w['p90'])} | "
              f"{us(w['p99'])} | {us(w['max'])} | {us(c['median'])} | {us(c['p99'])} |")

    print("\n## Per handshake (µs)\n")
    print("| Total | Wall median | Wall p90 | Wall p99 | Wall max | CPU median | CPU p99 |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for label, pick in [
        ("client", lambda t: t["client"]),
        ("daemon", lambda t: t["daemon"]),
        ("both", lambda t: [t["client"][0] + t["daemon"][0], t["client"][1] + t["daemon"][1]]),
    ]:
        w = stats([pick(t)[0] for t in per_side.values()])
        c = stats([pick(t)[1] for t in per_side.values()])
        print(f"| {label} | {us(w['median'])} | {us(w['p90'])} | {us(w['p99'])} | {us(w['max'])} | "
              f"{us(c['median'])} | {us(c['p99'])} |")

    m1 = read(run_dir, "message1.tsv")
    print("\n## A stranger's message 1: the daemon's `read_message1` (µs)\n")
    print("| Kind | n | Accepted | CPU median | CPU p90 | CPU p99 | CPU max | Wall median |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    for kind in ("honest", "random"):
        rows = [r for r in m1 if r["kind"] == kind]
        c = stats([int(r["cpu_ns"]) for r in rows])
        w = stats([int(r["wall_ns"]) for r in rows])
        accepted = sum(1 for r in rows if r["accepted"] == "true")
        print(f"| {kind} | {c['n']} | {accepted} | {us(c['median'])} | {us(c['p90'])} | "
              f"{us(c['p99'])} | {us(c['max'])} | {us(w['median'])} |")

    rec = read(run_dir, "records.tsv")
    print("\n## One record at each class (µs)\n")
    print("| Class (bytes) | Op | n | Wall median | Wall p99 | CPU median | CPU p99 | ns per byte (CPU median) |")
    print("|---:|---|---:|---:|---:|---:|---:|---:|")
    for cls in sorted({int(r["class"]) for r in rec}):
        for op in ("seal", "open"):
            rows = [r for r in rec if int(r["class"]) == cls and r["op"] == op]
            w = stats([int(r["wall_ns"]) for r in rows])
            c = stats([int(r["cpu_ns"]) for r in rows])
            print(f"| {cls:,} | {op} | {c['n']} | {us(w['median'])} | {us(w['p99'])} | "
                  f"{us(c['median'])} | {us(c['p99'])} | {c['median'] / cls:.2f} |")


def main(argv):
    if len(argv) != 2:
        print("usage: rt_p6_summary.py RUN_DIR", file=sys.stderr)
        return 2
    summarise(argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
