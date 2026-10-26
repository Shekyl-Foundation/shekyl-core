# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Fill-time model for the Tor connector's in-flight bound.

One launch per wake, wakes spaced 0.5 s + U(0, 1 s) (R3). A live draw's dial
time is drawn from the measured cold-contact sessions (2026-10-14 rerun, 189
sessions) and is kept. A dead draw is an onion that never answers: each of
its attempts runs to the 120 s deadline and fails (Tor's reply 0x06, or our
dial deadline). Time to fill = the first time kept sessions reach the
12-session target. Median and p90 over seeded runs.

Three lifecycles (`--lifecycle`):

- `pre-merge`: one attempt per test; a test ends with its attempt. The
  dialer before the gray lifecycle merged into #1190.
- `head`: the #1190 head. A full-window failure is worth a retry, so a dead
  test makes three attempts, with waits of 5 s + U(0, 5 s) and
  20 s + U(0, 10 s) between them. An attempt holds an in-flight slot; a wait
  does not. A `Keep` test holds its target place from draw to outcome,
  waits included (`Attempts::kept_count`). A due retry runs ahead of any new
  draw when a slot is free.
- `full-window-final`: the head, with a full-window timeout final within the
  test (proposed 2026-10-26, pending Rick's ruling): a dead test is one
  attempt again. Fast failures, which this model does not draw, keep their
  retries.

Every draw is a `Keep`: gray holds at least the diversity floor, so rule (b)
keeps. Run with `python3 -I`; `--grid` prints the TSV the record keeps.
"""
import argparse
import csv
import os
import random

BASE = os.path.dirname(os.path.abspath(__file__)) + "/"
LIVE = []
for name in ("p2p_tor_gap_cold_20261014_rerunA.tsv", "p2p_tor_gap_cold_20261014_rerunB.tsv"):
    for row in csv.DictReader(open(BASE + name), delimiter="\t"):
        if row["outcome"] == "session" and row["c_dial_ns"] not in ("", "-"):
            LIVE.append(int(row["c_dial_ns"]) / 1e9)
DEADLINE = 120.0
TARGET = 12
ATTEMPTS = {"pre-merge": 1, "head": 3, "full-window-final": 1}


def fill(bound, dead, lifecycle, rng):
    attempts = ATTEMPTS[lifecycle]
    t, kept = 0.0, 0
    flying = []   # (end, live, attempt)
    waiting = []  # (due, attempt)
    while True:
        t += 0.5 + rng.random()
        for dial in [d for d in flying if d[0] <= t]:
            flying.remove(dial)
            if dial[1]:
                kept += 1
            elif dial[2] < attempts:
                nxt = dial[2] + 1
                wait = 5 + 5 * rng.random() if nxt == 2 else 20 + 10 * rng.random()
                waiting.append((dial[0] + wait, nxt))
        if kept >= TARGET:
            return t
        if len(flying) >= bound:
            continue
        due = [w for w in waiting if w[0] <= t]
        if due:
            retry = min(due)
            waiting.remove(retry)
            flying.append((t + DEADLINE, False, retry[1]))
            continue
        # The target counts kept sessions and every open Keep test.
        if kept + len(flying) + len(waiting) < TARGET:
            if rng.random() < dead:
                flying.append((t + DEADLINE, False, 1))
            else:
                flying.append((t + rng.choice(LIVE), True, 1))
        if t > 8 * 3600:
            return float("inf")


def quantiles(bound, dead, lifecycle, runs):
    rng = random.Random(1000 * bound + int(100 * dead) + 7 * len(lifecycle))
    xs = sorted(fill(bound, dead, lifecycle, rng) for _ in range(runs))
    return xs[runs // 2], xs[runs * 9 // 10]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lifecycle", choices=sorted(ATTEMPTS), default="head")
    parser.add_argument("--runs", type=int, default=2000)
    parser.add_argument("--grid", action="store_true")
    args = parser.parse_args()
    if args.grid:
        print("lifecycle\tbound\tdead_fraction\tmedian_s\tp90_s\truns")
    for bound in range(1, 13):
        for dead in (0.0, 0.25, 0.5, 0.75, 0.9):
            median, p90 = quantiles(bound, dead, args.lifecycle, args.runs)
            if args.grid:
                print(f"{args.lifecycle}\t{bound}\t{dead:.2f}\t{median:.0f}\t{p90:.0f}\t{args.runs}", flush=True)


if __name__ == "__main__":
    main()
