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
# The registered shape is docs/benchmarks/rt_p6_handshake_cost_20261018.md.
# A file that is not that shape is refused before any table is written.
# The handshake step names are HandshakeStep in the harness.

import csv
import math
import os
import sys
from dataclasses import dataclass


STEPS_FILE = "steps.tsv"
MESSAGE1_FILE = "message1.tsv"
RECORDS_FILE = "records.tsv"

# Chronological order. The side is part of the step.
HANDSHAKE_STEPS = (
    ("client", "start"),
    ("daemon", "new"),
    ("daemon", "read_message1"),
    ("daemon", "write_message2"),
    ("client", "read_message2"),
    ("client", "write_message3"),
    ("daemon", "read_message3"),
    ("daemon", "write_message4"),
    ("client", "read_message4"),
    ("client", "first_record"),
    ("daemon", "open_first_message"),
)

MESSAGE1_KINDS = ("honest", "tag_flipped")
# With mac1 on message 1 (RPC_CHANNEL.md section 4.3, 2026-10-20) the harness
# adds a third kind, a sender without the daemon's bundle. A capture is read
# with the kinds its registration names: `--mac1` for that one.
MESSAGE1_KINDS_MAC1 = ("honest", "tag_flipped", "no_bundle")
# What read_message1 must report. honest completed; tag_flipped failed the
# tag; no_bundle failed mac1.
MESSAGE1_ACCEPTED = {"honest": True, "tag_flipped": False, "no_bundle": False}
MESSAGE1_PARTS = ("new", "read_message1", "attempt")

# RT-O6, ruled 2026-10-18.
RECORD_CLASSES = (512, 16_384, 65_535)
RECORD_OPS = ("seal", "open")

CLOCKS = ("median", "p90", "p99", "max")


def refuse(message):
    raise SystemExit(message)


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list, p in (0, 100]."""
    if not sorted_values:
        raise ValueError("no samples")
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def stats(values):
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "median": percentile(ordered, 50),
        "p90": percentile(ordered, 90),
        "p99": percentile(ordered, 99),
        "max": ordered[-1],
    }


def us(ns):
    return f"{ns / 1000:,.1f}"


def clock_cells(values):
    summary = stats(values)
    return " | ".join(us(summary[name]) for name in CLOCKS)


def clock_heading(prefix):
    return " | ".join(f"{prefix} {name}" for name in CLOCKS)


@dataclass(frozen=True)
class Clocks:
    wall_ns: int
    cpu_ns: int

    def __add__(self, other):
        return Clocks(self.wall_ns + other.wall_ns, self.cpu_ns + other.cpu_ns)


@dataclass(frozen=True)
class Message1Attempt:
    accepted: bool
    new: Clocks
    read: Clocks

    @property
    def attempt(self):
        return self.new + self.read


@dataclass(frozen=True)
class Run:
    """One complete capture. Every iteration carries the registered shape."""

    steps: dict
    message1: dict
    records: dict


def read_rows(run_dir, name):
    path = os.path.join(run_dir, name)
    if not os.path.isfile(path):
        refuse(f"{name} is missing")
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def field(row, column, filename):
    value = row.get(column)
    if value is None or value == "":
        refuse(f"{filename} lacks {column}")
    return value


def parse_u64(text, filename, column):
    try:
        value = int(text)
    except ValueError:
        refuse(f"{filename} {column} is {text!r}")
    if value < 0:
        refuse(f"{filename} {column} is {value}")
    return value


def clocks_from(row, filename, wall_column, cpu_column):
    return Clocks(
        parse_u64(field(row, wall_column, filename), filename, wall_column),
        parse_u64(field(row, cpu_column, filename), filename, cpu_column),
    )


def same_iterations(groups, filename, what):
    sets = {frozenset(group) for group in groups}
    if len(sets) != 1:
        refuse(f"{filename} {what} cover different iterations")


def load_steps(rows):
    expected = set(HANDSHAKE_STEPS)
    by_iteration = {}
    for row in rows:
        side = field(row, "side", STEPS_FILE)
        step = field(row, "step", STEPS_FILE)
        key = (side, step)
        if key not in expected:
            refuse(f"{STEPS_FILE} has unexpected step {side}/{step}")
        iteration = parse_u64(field(row, "iteration", STEPS_FILE), STEPS_FILE, "iteration")
        slot = by_iteration.setdefault(iteration, {})
        if key in slot:
            refuse(f"{STEPS_FILE} repeats {side}/{step} in iteration {iteration}")
        slot[key] = clocks_from(row, STEPS_FILE, "wall_ns", "cpu_ns")
    if not by_iteration:
        refuse(f"{STEPS_FILE} has no handshakes")
    for iteration, slot in by_iteration.items():
        missing = [f"{side}/{step}" for side, step in HANDSHAKE_STEPS if (side, step) not in slot]
        if missing:
            refuse(f"{STEPS_FILE} iteration {iteration} lacks {', '.join(missing)}")
    return by_iteration


def parse_accepted(text):
    if text == "true":
        return True
    if text == "false":
        return False
    refuse(f"{MESSAGE1_FILE} accepted is {text!r}")


def load_message1(rows, kinds):
    by_kind = {kind: {} for kind in kinds}
    for row in rows:
        kind = field(row, "kind", MESSAGE1_FILE)
        if kind not in by_kind:
            refuse(f"{MESSAGE1_FILE} has unexpected kind {kind}")
        iteration = parse_u64(field(row, "iteration", MESSAGE1_FILE), MESSAGE1_FILE, "iteration")
        if iteration in by_kind[kind]:
            refuse(f"{MESSAGE1_FILE} repeats {kind} iteration {iteration}")
        accepted = parse_accepted(field(row, "accepted", MESSAGE1_FILE))
        if accepted != MESSAGE1_ACCEPTED[kind]:
            written = field(row, "accepted", MESSAGE1_FILE)
            refuse(f"{MESSAGE1_FILE} {kind} iteration {iteration} accepted is {written}")
        by_kind[kind][iteration] = Message1Attempt(
            accepted=accepted,
            new=clocks_from(row, MESSAGE1_FILE, "new_wall_ns", "new_cpu_ns"),
            read=clocks_from(row, MESSAGE1_FILE, "read_wall_ns", "read_cpu_ns"),
        )
    for kind, attempts in by_kind.items():
        if not attempts:
            refuse(f"{MESSAGE1_FILE} lacks {kind}")
    same_iterations(by_kind.values(), MESSAGE1_FILE, "kinds")
    return by_kind


def load_records(rows):
    by_cell = {(cls, op): {} for cls in RECORD_CLASSES for op in RECORD_OPS}
    for row in rows:
        cls = parse_u64(field(row, "class", RECORDS_FILE), RECORDS_FILE, "class")
        op = field(row, "op", RECORDS_FILE)
        key = (cls, op)
        if key not in by_cell:
            refuse(f"{RECORDS_FILE} has unexpected class {cls} {op}")
        iteration = parse_u64(field(row, "iteration", RECORDS_FILE), RECORDS_FILE, "iteration")
        if iteration in by_cell[key]:
            refuse(f"{RECORDS_FILE} repeats class {cls} {op} iteration {iteration}")
        by_cell[key][iteration] = clocks_from(row, RECORDS_FILE, "wall_ns", "cpu_ns")
    for cls in RECORD_CLASSES:
        for op in RECORD_OPS:
            if not by_cell[(cls, op)]:
                refuse(f"{RECORDS_FILE} lacks class {cls} {op}")
    same_iterations(by_cell.values(), RECORDS_FILE, "classes")
    return by_cell


def load(run_dir, kinds=MESSAGE1_KINDS):
    return Run(
        steps=load_steps(read_rows(run_dir, STEPS_FILE)),
        message1=load_message1(read_rows(run_dir, MESSAGE1_FILE), kinds),
        records=load_records(read_rows(run_dir, RECORDS_FILE)),
    )


def side_series(steps, side):
    walls, cpus = [], []
    for slot in steps.values():
        chosen = [
            sample
            for (step_side, _), sample in slot.items()
            if side == "both" or step_side == side
        ]
        walls.append(sum(sample.wall_ns for sample in chosen))
        cpus.append(sum(sample.cpu_ns for sample in chosen))
    return walls, cpus


def render(run):
    lines = ["## Each step (µs)", ""]
    lines.append(
        "| Side | Step | n | "
        + clock_heading("Wall")
        + " | "
        + clock_heading("CPU")
        + " |"
    )
    lines.append("|---|---|---:|" + "---:|" * (2 * len(CLOCKS)))
    for key in HANDSHAKE_STEPS:
        samples = [slot[key] for slot in run.steps.values()]
        walls = [sample.wall_ns for sample in samples]
        cpus = [sample.cpu_ns for sample in samples]
        lines.append(
            f"| {key[0]} | `{key[1]}` | {len(samples)} | {clock_cells(walls)} | {clock_cells(cpus)} |"
        )

    lines += ["", "## Per handshake (µs)", ""]
    lines.append("| Total | n | " + clock_heading("Wall") + " | " + clock_heading("CPU") + " |")
    lines.append("|---|---:|" + "---:|" * (2 * len(CLOCKS)))
    for side in ("client", "daemon", "both"):
        walls, cpus = side_series(run.steps, side)
        lines.append(f"| {side} | {len(walls)} | {clock_cells(walls)} | {clock_cells(cpus)} |")

    lines += ["", "## A stranger's message 1 (µs)", ""]
    lines.append(
        "| Kind | Part | n | Accepted | "
        + clock_heading("Wall")
        + " | "
        + clock_heading("CPU")
        + " |"
    )
    lines.append("|---|---|---:|---:|" + "---:|" * (2 * len(CLOCKS)))
    for kind in run.message1:
        attempts = list(run.message1[kind].values())
        accepted = sum(1 for attempt in attempts if attempt.accepted)
        parts = {
            "new": [attempt.new for attempt in attempts],
            "read_message1": [attempt.read for attempt in attempts],
            "attempt": [attempt.attempt for attempt in attempts],
        }
        for part in MESSAGE1_PARTS:
            samples = parts[part]
            walls = [sample.wall_ns for sample in samples]
            cpus = [sample.cpu_ns for sample in samples]
            lines.append(
                f"| {kind} | `{part}` | {len(samples)} | {accepted} | "
                f"{clock_cells(walls)} | {clock_cells(cpus)} |"
            )

    lines += ["", "## One record at each class (µs)", ""]
    lines.append(
        "| Class (bytes) | Op | n | "
        + clock_heading("Wall")
        + " | "
        + clock_heading("CPU")
        + " | ns per byte (CPU median) |"
    )
    lines.append("|---:|---|---:|" + "---:|" * (2 * len(CLOCKS)) + "---:|")
    for cls in RECORD_CLASSES:
        for op in RECORD_OPS:
            samples = list(run.records[(cls, op)].values())
            walls = [sample.wall_ns for sample in samples]
            cpus = [sample.cpu_ns for sample in samples]
            per_byte = stats(cpus)["median"] / cls
            lines.append(
                f"| {cls:,} | {op} | {len(samples)} | {clock_cells(walls)} | "
                f"{clock_cells(cpus)} | {per_byte:.2f} |"
            )
    return "\n".join(lines) + "\n"


def summarise(run_dir, kinds=MESSAGE1_KINDS):
    return render(load(run_dir, kinds))


def main(argv):
    args = argv[1:]
    kinds = MESSAGE1_KINDS
    if args[:1] == ["--mac1"]:
        kinds = MESSAGE1_KINDS_MAC1
        args = args[1:]
    if len(args) != 1:
        print("usage: rt_p6_summary.py [--mac1] RUN_DIR", file=sys.stderr)
        return 2
    print(summarise(args[0], kinds), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
