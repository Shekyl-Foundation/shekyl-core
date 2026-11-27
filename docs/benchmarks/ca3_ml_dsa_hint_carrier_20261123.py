# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""CA-3 ML-DSA, Step 1: does the public hint count carry the floor's crossing?

Reads the per-signature dumps of `ca3_pq_sign_timing ml-dsa-dump` (pair, null
and control) and answers by rules fixed before the run. Standard library only.

Windows, on the measured entries (the calibration batch is left out):
- first-attempt: time below FIRST_ATTEMPT_CUT_NS, a fixed time inside the gap
  between the first-attempt and second-attempt modes on the floor device;
- lowest sub-mode: time below a boundary set once, blind to class, from the
  NULL comparison's pooled first-attempt times (`lowest_boundary`).

No sample inside a window is removed. Interrupt-hit samples stay, and the
standard errors are heteroskedasticity-robust (HC1) for that reason.

Per window and comparison:
- each key's slope of time on hint count (ns per hint) with its standard error;
- the pooled model time ~ key + hints: the key term (A - B, ns) with its t, and
  the shared slope with its t;
- the unadjusted A - B difference with its Welch t.

Reading, on the pair:
- VOID: a validity check failed (`validity`).
- VACUOUS: the unadjusted |t| is below 4.5 in both windows, so this build shows
  no difference for the hint count to carry. Go to Step 2.
- CARRIER: a difference is present, and in BOTH windows the shared slope is at
  least 100 ns per hint with |t| >= 4.5 and the key term's |t| is below 4.5.
- NOT-CARRIER: anything else. Go to Step 2.
"""

import argparse
import math
import pathlib
import random
import re
import sys

FIRST_ATTEMPT_CUT_NS = 1_500_000
FALLBACK_LOWEST_CUT_NS = 1_250_000
BIN_NS = 500
VALLEY_FRACTION = 0.2
PEAK_FLOOR_FRACTION = 0.2
HISTOGRAM_SPAN_NS = 60_000
MAX_LOWEST_MODE_WIDTH_NS = 30_000
MIN_PER_CLASS = 100
T_LINE = 4.5
HUNDREDS_NS_PER_HINT = 100.0
CONTROL_RECOVERY_TOLERANCE = 0.25

# The registered attempt's hint statistics. Hint counts do not depend on the
# device or the build, so the same seed must reproduce them exactly.
REGISTERED_HINTS = {
    "pair": ("37.40", "38.42", "396.87"),
    "null": ("37.35", "37.36", "21.58"),
    "control": ("37.41", "37.40", "42.05"),
}
REGISTERED_PAIR_N = (25134, 24866)


def load_dump(path):
    """Return the measured entries of one dump as (class, time_ns, hint)."""
    with open(path, encoding="ascii") as handle:
        header = handle.readline()
        match = re.search(r"calibration=(\d+)", header)
        if not match:
            raise ValueError(f"{path}: no calibration in the header")
        calibration = int(match.group(1))
        if handle.readline().strip() != "index,class,time_ns,hint":
            raise ValueError(f"{path}: unexpected column line")
        rows = []
        for line in handle:
            index, cls, time_ns, hint = line.strip().split(",")
            if int(index) >= calibration:
                rows.append((int(cls), int(time_ns), int(hint)))
    return rows


def invert(matrix):
    """Invert a small square matrix by Gauss-Jordan with partial pivoting."""
    size = len(matrix)
    work = [row[:] + [float(i == j) for j in range(size)] for i, row in enumerate(matrix)]
    for col in range(size):
        pivot = max(range(col, size), key=lambda r: abs(work[r][col]))
        if abs(work[pivot][col]) < 1e-12:
            raise ValueError("singular design")
        work[col], work[pivot] = work[pivot], work[col]
        divisor = work[col][col]
        work[col] = [value / divisor for value in work[col]]
        for row in range(size):
            if row != col and work[row][col] != 0.0:
                factor = work[row][col]
                work[row] = [a - factor * b for a, b in zip(work[row], work[col])]
    return [row[size:] for row in work]


def ols_hc1(design, response):
    """OLS with HC1 standard errors. Returns (coefficients, standard errors)."""
    n = len(design)
    k = len(design[0])
    xtx = [[0.0] * k for _ in range(k)]
    xty = [0.0] * k
    for row, y in zip(design, response):
        for i in range(k):
            xty[i] += row[i] * y
            for j in range(k):
                xtx[i][j] += row[i] * row[j]
    inverse = invert(xtx)
    beta = [sum(inverse[i][j] * xty[j] for j in range(k)) for i in range(k)]
    meat = [[0.0] * k for _ in range(k)]
    for row, y in zip(design, response):
        residual = y - sum(b * x for b, x in zip(beta, row))
        square = residual * residual
        for i in range(k):
            for j in range(k):
                meat[i][j] += square * row[i] * row[j]
    scale = n / (n - k)
    errors = []
    for a in range(k):
        variance = sum(
            inverse[a][i] * meat[i][j] * inverse[j][a] for i in range(k) for j in range(k)
        )
        errors.append(math.sqrt(max(variance * scale, 0.0)))
    return beta, errors


def welch(first, second):
    """Return (mean difference, Welch t)."""
    def moments(values):
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return mean, variance

    mean_a, var_a = moments(first)
    mean_b, var_b = moments(second)
    error = math.sqrt(var_a / len(first) + var_b / len(second))
    difference = mean_a - mean_b
    return difference, (difference / error if error > 0 else 0.0)


def lowest_boundary(null_rows):
    """The lowest sub-mode's upper boundary, blind to class.

    Histogram the null's pooled first-attempt times in BIN_NS bins from the
    0.1st percentile. Start at the first local maximum holding at least
    PEAK_FLOOR_FRACTION of the histogram's largest bin and follow the rising
    peak. The valley is the run of bins at or below VALLEY_FRACTION of that
    peak; the boundary is the centre of the valley's lowest bins. A boundary on
    the mode's shoulder would cut on the time a hint slope moves, and so hide
    the effect under test. If the valley does not begin within
    MAX_LOWEST_MODE_WIDTH_NS, use FALLBACK_LOWEST_CUT_NS.
    Returns (boundary, how it was found).
    """
    times = sorted(t for _, t, _ in null_rows if t < FIRST_ATTEMPT_CUT_NS)
    if not times:
        return FALLBACK_LOWEST_CUT_NS, "fallback (no first-attempt times)"
    start = times[len(times) // 1000]
    bins = [0] * (HISTOGRAM_SPAN_NS // BIN_NS)
    for t in times:
        if start <= t < start + HISTOGRAM_SPAN_NS:
            bins[(t - start) // BIN_NS] += 1
    largest = max(bins)
    first = None
    for i, count in enumerate(bins):
        before = bins[i - 1] if i else 0
        after = bins[i + 1] if i + 1 < len(bins) else 0
        if count >= PEAK_FLOOR_FRACTION * largest and count >= before and count >= after:
            first = i
            break
    if first is None:
        return FALLBACK_LOWEST_CUT_NS, "fallback (no peak)"
    peak = bins[first]
    for j in range(first, len(bins)):
        peak = max(peak, bins[j])
        if bins[j] <= VALLEY_FRACTION * peak:
            if (j - first) * BIN_NS > MAX_LOWEST_MODE_WIDTH_NS:
                break
            end = j
            while end + 1 < len(bins) and bins[end + 1] <= VALLEY_FRACTION * peak:
                end += 1
            lowest = min(bins[j : end + 1])
            at = [i for i in range(j, end + 1) if bins[i] == lowest]
            return start + (at[0] + at[-1] + 1) * BIN_NS // 2, "valley centre"
    return FALLBACK_LOWEST_CUT_NS, "fallback (no valley)"


def analyse(rows, cut):
    """The window's figures, or None if a class holds too few entries."""
    window = [row for row in rows if row[1] < cut]
    key_a = [row for row in window if row[0] == 0]
    key_b = [row for row in window if row[0] == 1]
    if len(key_a) < MIN_PER_CLASS or len(key_b) < MIN_PER_CLASS:
        return {"n": (len(key_a), len(key_b)), "empty": True}
    centre = sum(row[2] for row in window) / len(window)

    def slope(rows_of_key):
        beta, errors = ols_hc1(
            [[1.0, row[2] - centre] for row in rows_of_key],
            [float(row[1]) for row in rows_of_key],
        )
        return beta[1], errors[1]

    beta, errors = ols_hc1(
        [[1.0, float(row[0] == 0), row[2] - centre] for row in window],
        [float(row[1]) for row in window],
    )
    difference, welch_t = welch([float(r[1]) for r in key_a], [float(r[1]) for r in key_b])
    return {
        "n": (len(key_a), len(key_b)),
        "empty": False,
        "slope_a": slope(key_a),
        "slope_b": slope(key_b),
        "key_ns": beta[1],
        "key_t": beta[1] / errors[1] if errors[1] > 0 else 0.0,
        "shared_slope": beta[2],
        "shared_slope_t": beta[2] / errors[2] if errors[2] > 0 else 0.0,
        "unadjusted_ns": difference,
        "unadjusted_t": welch_t,
    }


def read_pair(first, lowest):
    """The pair's reading from its two windows."""
    windows = [first, lowest]
    if any(w["empty"] for w in windows):
        return "NOT-CARRIER (a window is too small to read)"
    if all(abs(w["unadjusted_t"]) < T_LINE for w in windows):
        return "VACUOUS (this build shows no difference to carry)"
    carried = all(
        w["shared_slope"] >= HUNDREDS_NS_PER_HINT
        and abs(w["shared_slope_t"]) >= T_LINE
        and abs(w["key_t"]) < T_LINE
        for w in windows
    )
    return "CARRIER" if carried else "NOT-CARRIER"


def validity(results, planted_ns, harness_text):
    """The checks that void the diagnostic. Returns the list of failures."""
    failures = []
    for window in ("first", "lowest"):
        null = results["null"][window]
        if null["empty"]:
            failures.append(f"null {window}: too few entries")
        elif abs(null["key_t"]) >= T_LINE:
            failures.append(f"null {window}: key term t {null['key_t']:.2f}")
    control = results["control"]["first"]
    if control["empty"]:
        failures.append("control: too few entries")
    elif planted_ns is not None:
        recovered = -control["key_ns"]
        if abs(recovered - planted_ns) > CONTROL_RECOVERY_TOLERANCE * planted_ns:
            failures.append(
                f"control: key term {recovered:.0f} ns against {planted_ns:.0f} ns planted"
            )
    if harness_text is not None:
        hint_lines = re.findall(
            r"hints mean0=([\d.]+) mean1=([\d.]+) chi2=([\d.]+)", harness_text
        )
        for name, found in zip(("pair", "null", "control"), hint_lines):
            if found != REGISTERED_HINTS[name]:
                failures.append(f"{name}: hints {found}, registered {REGISTERED_HINTS[name]}")
        if len(hint_lines) < 3:
            failures.append("harness output: fewer than three hint lines")
        if "VOID" in harness_text:
            failures.append("harness: result is VOID")
        pair_line = re.search(r"diagnostic=sign-fixed-a-vs-fixed-b .*n0=(\d+) n1=(\d+)", harness_text)
        if not pair_line or (int(pair_line[1]), int(pair_line[2])) != REGISTERED_PAIR_N:
            failures.append("pair: class sizes differ from the registered attempt")
    return failures


def run(dump_dir, planted_ns, harness_text):
    """Analyse one dump directory and print its figures and reading."""
    directory = pathlib.Path(dump_dir)
    rows = {name: load_dump(directory / f"{name}.csv") for name in ("pair", "null", "control")}
    boundary, how = lowest_boundary(rows["null"])
    print(f"first_attempt_cut_ns={FIRST_ATTEMPT_CUT_NS} lowest_boundary_ns={boundary} ({how})")
    results = {}
    for name, comparison in rows.items():
        between = sum(1 for _, t, _ in comparison if 1_400_000 <= t < 1_600_000)
        print(f"{name}: measured={len(comparison)} entries_in_1.4_to_1.6_ms={between}")
        results[name] = {
            "first": analyse(comparison, FIRST_ATTEMPT_CUT_NS),
            "lowest": analyse(comparison, boundary),
        }
        for window, figures in results[name].items():
            if figures["empty"]:
                print(f"  {window}: n={figures['n']} too few to read")
                continue
            print(
                f"  {window}: n={figures['n']} "
                f"slope_A={figures['slope_a'][0]:.1f}±{figures['slope_a'][1]:.1f} "
                f"slope_B={figures['slope_b'][0]:.1f}±{figures['slope_b'][1]:.1f} ns/hint | "
                f"key(A-B)={figures['key_ns']:.1f} ns t={figures['key_t']:.2f} "
                f"shared_slope={figures['shared_slope']:.1f} t={figures['shared_slope_t']:.2f} | "
                f"unadjusted(A-B)={figures['unadjusted_ns']:.1f} ns "
                f"welch_t={figures['unadjusted_t']:.2f}"
            )
    failures = validity(results, planted_ns, harness_text)
    if failures:
        print("reading=VOID")
        for failure in failures:
            print(f"  void: {failure}")
        return "VOID"
    reading = read_pair(results["pair"]["first"], results["pair"]["lowest"])
    print(f"reading={reading}")
    return reading


def synthetic(directory, slope, key_ns, seed, hint_gap=1.0):
    """Write a synthetic dump with a known hint slope and key term."""
    rng = random.Random(seed)
    directory.mkdir(parents=True, exist_ok=True)

    def write(name, gap, key, planted):
        lines = [f"# label={name} samples=50000 calibration=500", "index,class,time_ns,hint"]
        for index in range(50_500):
            cls = rng.getrandbits(1)
            hint = max(0, min(55, round(rng.gauss(37.4 + (gap if cls else 0.0), 5.0))))
            attempts = 1
            while rng.random() > 0.2:
                attempts += 1
            sub_mode = 13_000 if rng.random() > 0.35 else 0
            time = 1_241_000 + 490_000 * (attempts - 1) + sub_mode + rng.gauss(0, 700)
            time += slope * (hint - 37.4)
            time += key if cls == 0 else 0.0
            time += planted if cls == 1 else 0.0
            if rng.random() < 0.01:
                time += rng.expovariate(1 / 20_000)
            lines.append(f"{index},{cls},{int(time)},{hint}")
        (directory / f"{name}.csv").write_text("\n".join(lines) + "\n", encoding="ascii")

    write("pair", hint_gap, key_ns, 0.0)
    write("null", 0.0, 0.0, 0.0)
    write("control", 0.0, 0.0, 13_500.0)


def self_test(work):
    """Each reading must come out of data built to produce it."""
    cases = [
        ("carrier", 300.0, 0.0, "CARRIER", 2.0),
        ("key-effect", 30.0, -400.0, "NOT-CARRIER", 1.0),
        ("no-effect", 0.0, 0.0, "VACUOUS", 0.0),
    ]
    failed = False
    for name, slope, key_ns, expected, gap in cases:
        directory = pathlib.Path(work) / name
        synthetic(directory, slope, key_ns, seed=20261123, hint_gap=gap)
        print(f"== synthetic {name}: slope={slope} key={key_ns} expected={expected}")
        got = run(directory, 13_500.0, None)
        if not got.startswith(expected):
            print(f"SELF-TEST FAILED: {name} read {got}")
            failed = True
    print("self-test=" + ("FAILED" if failed else "passed"))
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dump_dir", help="directory holding pair.csv, null.csv, control.csv")
    parser.add_argument("--harness-output", help="the run's stdout; checks the hint counts")
    parser.add_argument("--self-test", action="store_true", help="dump_dir is a scratch directory")
    args = parser.parse_args()
    if args.self_test:
        return self_test(args.dump_dir)
    harness_text = None
    planted_ns = None
    if args.harness_output:
        harness_text = pathlib.Path(args.harness_output).read_text(encoding="ascii")
        match = re.search(r"control=sign-planted-leak planted_ns=(\d+)", harness_text)
        planted_ns = float(match.group(1)) if match else None
    reading = run(args.dump_dir, planted_ns, harness_text)
    return 2 if reading == "VOID" else 0


if __name__ == "__main__":
    sys.exit(main())
