#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# RT-W10: summarise a request-cost run and derive the bounded-request caps.
# The method is docs/benchmarks/rt_w10_request_cost_20261102.md.
# A file that is not that shape is refused before any cap is written.
#
#   rt_w10_summary.py RUN_DIR

import csv
import math
import os
import sys

SAMPLES = 100
HEADER_BYTES = 136
MAX_BYTES = 33_000_128
WALL_OVER_CPU = 4

HASH_SERIES = ("header", "max")
COINBASE_SERIES = ("block", "block_info", "tx_get")
PARSE_SERIES = ("pruned",)
CONSTANT_KEYS = (
    "min_block_weight",
    "coinbase_reserve",
    "pruned_len",
    "penalty_multiple",
)


def refuse(message):
    raise SystemExit(message)


def percentile(sorted_values, p):
    """Nearest-rank percentile of an ascending list, p in (0, 100]."""
    if not sorted_values:
        raise ValueError("no samples")
    rank = max(1, math.ceil(p / 100 * len(sorted_values)))
    return sorted_values[rank - 1]


def stats(samples):
    wall = sorted(sample[0] for sample in samples)
    cpu = sorted(sample[1] for sample in samples)
    return {
        "n": len(samples),
        "wall_p99": percentile(wall, 99),
        "cpu_p99": percentile(cpu, 99),
        "wall_median": percentile(wall, 50),
        "cpu_median": percentile(cpu, 50),
        "wall_p90": percentile(wall, 90),
        "cpu_p90": percentile(cpu, 90),
        "wall_max": wall[-1],
        "cpu_max": cpu[-1],
    }


def cost_of(summary):
    """The series' cost: the greater of its wall and thread-CPU 99th percentiles."""
    if summary["cpu_p99"] == 0 or summary["wall_p99"] > WALL_OVER_CPU * summary["cpu_p99"]:
        refuse(
            "a series is void: its 99th-percentile wall is more than "
            f"{WALL_OVER_CPU} times its 99th-percentile thread CPU, or the CPU is 0"
        )
    return max(summary["wall_p99"], summary["cpu_p99"])


def load_samples(path, expected_series, expected_bytes):
    if not os.path.isfile(path):
        refuse(f"missing {os.path.basename(path)}")
    found = {series: [] for series in expected_series}
    with open(path, newline="") as handle:
        rows = csv.DictReader(handle, delimiter="\t")
        if rows.fieldnames != ["series", "iteration", "bytes", "wall_ns", "cpu_ns"]:
            refuse(f"{os.path.basename(path)} header is not the registered header")
        for row in rows:
            series = row["series"]
            if series not in found:
                refuse(f"{os.path.basename(path)} has an unexpected series {series}")
            try:
                iteration = int(row["iteration"])
                nbytes = int(row["bytes"])
                wall = int(row["wall_ns"])
                cpu = int(row["cpu_ns"])
            except ValueError:
                refuse(f"{os.path.basename(path)} has a non-integer field")
            if nbytes != expected_bytes[series]:
                refuse(f"{series} recorded {nbytes} bytes; the registration says {expected_bytes[series]}")
            if wall < 0 or cpu < 0:
                refuse(f"{series} has a negative sample")
            found[series].append((iteration, wall, cpu))
    out = {}
    for series, rows in found.items():
        if len(rows) != SAMPLES:
            refuse(f"{series} has {len(rows)} samples; the registration says {SAMPLES}")
        iterations = [row[0] for row in rows]
        if iterations != list(range(1, SAMPLES + 1)):
            refuse(f"{series} iterations are not 1..{SAMPLES} once each")
        out[series] = stats([(row[1], row[2]) for row in rows])
    return out


def load_constants(path):
    if not os.path.isfile(path):
        refuse("missing constants.tsv")
    found = {}
    with open(path, newline="") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            key, value = line.split("\t")
            if key not in CONSTANT_KEYS or key in found:
                refuse(f"constants.tsv has an unexpected or repeated key {key}")
            found[key] = int(value)
    for key in CONSTANT_KEYS:
        if key not in found:
            refuse(f"constants.tsv is missing {key}")
    if found["penalty_multiple"] != 2:
        refuse("penalty_multiple is not 2")
    if found["pruned_len"] <= 0 or found["min_block_weight"] <= 0:
        refuse("a constant length is not positive")
    if found["coinbase_reserve"] < 0:
        refuse("coinbase_reserve is negative")
    return found


def derive(hashes, coinbase, parse, constants):
    """The caps in the registration. Every input is a 99th-percentile cost in nanoseconds, except the constants."""
    header = cost_of(hashes["header"])
    maximum = cost_of(hashes["max"])
    ceiling = header
    if maximum <= ceiling:
        calc_pow_bytes = MAX_BYTES
    else:
        calc_pow_bytes = HEADER_BYTES
    if header == 0:
        refuse("the header hash costs nothing")
    fill_headers = ceiling // header
    listed = constants["penalty_multiple"] * constants["min_block_weight"] - constants["coinbase_reserve"]
    if listed <= 0:
        refuse("the zone penalty limit does not leave room for a listed transaction")
    parses = math.ceil(listed / constants["pruned_len"])
    per_height = cost_of(coinbase["block"]) + parses * (
        cost_of(coinbase["tx_get"]) + cost_of(parse["pruned"])
    )
    overhead = 2 * cost_of(coinbase["block_info"])
    if per_height <= 0:
        refuse("one height costs nothing")
    if ceiling <= overhead:
        span = 0
    else:
        span = (ceiling - overhead) // per_height
    return {
        "ceiling_ns": ceiling,
        "calc_pow_bytes": calc_pow_bytes,
        "fill_pow_hash_headers": fill_headers,
        "listed_weight": listed,
        "parses_per_height": parses,
        "per_height_ns": per_height,
        "overhead_ns": overhead,
        "coinbase_span": span,
    }


def ns(value):
    return f"{value:,}"


def main(argv):
    if len(argv) != 2:
        refuse("usage: rt_w10_summary.py RUN_DIR")
    run = argv[1]
    hashes = load_samples(
        os.path.join(run, "hashes.tsv"),
        HASH_SERIES,
        {"header": HEADER_BYTES, "max": MAX_BYTES},
    )
    coinbase = load_samples(
        os.path.join(run, "coinbase.tsv"),
        COINBASE_SERIES,
        {"block": 0, "block_info": 0, "tx_get": 0},
    )
    constants = load_constants(os.path.join(run, "constants.tsv"))
    parse = load_samples(
        os.path.join(run, "parse.tsv"),
        PARSE_SERIES,
        {"pruned": constants["pruned_len"]},
    )
    caps = derive(hashes, coinbase, parse, constants)
    print("# RT-W10 request-cost summary")
    print()
    print(f"- ceiling (header p99, ns): {ns(caps['ceiling_ns'])}")
    print(f"- calc_pow blob bound (bytes): {ns(caps['calc_pow_bytes'])}")
    print(f"- fill_pow_hash headers: {caps['fill_pow_hash_headers']}")
    print(f"- listed weight at the zone (bytes): {ns(caps['listed_weight'])}")
    print(f"- pruned parses per height: {caps['parses_per_height']}")
    print(f"- per height (ns): {ns(caps['per_height_ns'])}")
    print(f"- endpoint overhead (ns): {ns(caps['overhead_ns'])}")
    print(f"- coinbase span (heights): {caps['coinbase_span']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
