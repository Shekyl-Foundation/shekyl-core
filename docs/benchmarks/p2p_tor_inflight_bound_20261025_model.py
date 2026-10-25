# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Fill-time model for the Tor connector's in-flight bound.

One launch per wake, wakes spaced 0.5 s + U(0, 1 s) (R3). A launch needs a
free slot (in flight < B) and kept + pending keeps < T. A live draw's dial
time is drawn from the measured cold-contact sessions (2026-10-14 rerun,
189 sessions); a dead draw runs to the 120 s deadline and fails. Time to
fill = the first time kept sessions reach T. Median over seeded runs.
"""
import csv, random, statistics, sys
import os
BASE = os.path.dirname(os.path.abspath(__file__)) + "/"
live = []
for f in ("p2p_tor_gap_cold_20261014_rerunA.tsv", "p2p_tor_gap_cold_20261014_rerunB.tsv"):
    for r in csv.DictReader(open(BASE + f), delimiter="\t"):
        if r["outcome"] == "session" and r["c_dial_ns"] not in ("", "-"):
            live.append(int(r["c_dial_ns"]) / 1e9)
DEAD = 120.0
T = 12

def fill(bound, dead, rng):
    t, kept, inflight = 0.0, 0, []   # inflight: list of (end, live)
    while True:
        t += 0.5 + rng.random()
        done = [d for d in inflight if d[0] <= t]
        inflight = [d for d in inflight if d[0] > t]
        kept += sum(1 for d in done if d[1])
        if kept >= T:
            return t
        # A free slot, and the target counts pending keeps (every draw
        # here is a keep: gray holds at least the floor).
        if len(inflight) < bound and kept + len(inflight) < T:
            if rng.random() < dead:
                inflight.append((t + DEAD, False))
            else:
                inflight.append((t + rng.choice(live), True))
        if t > 6 * 3600:
            return float("inf")

def median_fill(bound, dead, runs=400):
    rng = random.Random(bound * 1000 + int(dead * 100))
    return statistics.median(fill(bound, dead, rng) for _ in range(runs))

print("n live samples", len(live), "mean %.1f" % statistics.mean(live))
fracs = [0.0, 0.25, 0.5, 0.75, 0.9]
print("B  " + "  ".join("f=%.2f" % f for f in fracs))
for b in range(1, 13):
    print("%2d " % b + "  ".join("%7.0f" % median_fill(b, f) for f in fracs))
