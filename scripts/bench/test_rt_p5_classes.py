#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Tests for rt_p5_classes.py: the record split, the optimal tables (against
# an exhaustive search, since the fast search relies on a monotone split
# point), and the determinism comparison.

import itertools
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rt_p5_classes as rc  # noqa: E402


def brute(records, K):
    """Least padding with K classes, the largest fixed, by trying every
    choice of the other K - 1 classes among the distinct sizes."""
    sizes = sorted(set(records))
    lower = [s for s in sizes if s < rc.MAX_RECORD_PLAINTEXT]
    best = None
    for n in range(0, K):
        for pick in itertools.combinations(lower, n):
            classes = list(pick) + [rc.MAX_RECORD_PLAINTEXT]
            pad = sum(rc.class_of(r, classes) - r for r in records)
            best = pad if best is None else min(best, pad)
    return best


class RecordSplit(unittest.TestCase):
    def test_a_small_message_is_one_record_with_its_occupancy(self):
        self.assertEqual(rc.records_of(10), [12])

    def test_a_message_of_exactly_one_payload_is_one_full_record(self):
        self.assertEqual(rc.records_of(rc.RECORD_PAYLOAD_MAX), [rc.MAX_RECORD_PLAINTEXT])

    def test_a_larger_message_splits_into_full_records_and_a_tail(self):
        out = rc.records_of(2 * rc.RECORD_PAYLOAD_MAX + 5)
        self.assertEqual(out, [rc.MAX_RECORD_PLAINTEXT, rc.MAX_RECORD_PLAINTEXT, 7])
        self.assertEqual(sum(r - rc.OCCUPANCY_LEN for r in out), 2 * rc.RECORD_PAYLOAD_MAX + 5)

    def test_an_empty_message_is_refused(self):
        with self.assertRaises(ValueError):
            rc.records_of(0)


class OptimalTables(unittest.TestCase):
    def test_matches_exhaustive_search(self):
        rng = random.Random(5)
        for _ in range(40):
            records = [rng.choice([40, 300, 301, 2_000, 9_000, 30_000, 65_000, 65_535])
                       for _ in range(rng.randint(3, 25))]
            records += [rng.randint(2, rc.MAX_RECORD_PLAINTEXT) for _ in range(rng.randint(0, 6))]
            tables = rc.optimal_tables(records, k_max=5)
            for K in range(1, 6):
                classes, pad = tables[K]
                self.assertEqual(pad, brute(records, K), (records, K))
                self.assertEqual(classes[-1], rc.MAX_RECORD_PLAINTEXT)
                self.assertEqual(sum(rc.class_of(r, classes) - r for r in records), pad)

    def test_more_classes_never_cost_more(self):
        records = [12, 500, 500, 4_000, 65_535, 700]
        tables = rc.optimal_tables(records)
        pads = [tables[K][1] for K in range(1, rc.K_MAX + 1)]
        self.assertEqual(pads, sorted(pads, reverse=True))


class Compare(unittest.TestCase):
    def write_run(self, root, name, totals):
        d = os.path.join(root, name)
        os.makedirs(d)
        with open(os.path.join(d, "messages.csv"), "w") as f:
            f.write("cell,wallet,conn,seq,direction,label,head,body,framing,total\n")
            for i, t in enumerate(totals):
                f.write(f"x,wallet,0,{i},request,/a,10,{t - 10},0,{t}\n")
        with open(os.path.join(d, "transactions.csv"), "w") as f:
            f.write("cell,tx,wallet,inputs,outputs,tx_len,fee,built_depth,depth,predicted_tx_len\n")
        with open(os.path.join(d, "run.json"), "w") as f:
            f.write('{"cell": "x", "chain_height": 1, "curve_tree_info": {}}')
        return d

    def test_within_tolerance_passes_and_beyond_fails(self):
        with tempfile.TemporaryDirectory() as root:
            a = self.write_run(root, "a", [1_000, 50_000])
            b = self.write_run(root, "b", [1_040, 50_400])
            c = self.write_run(root, "c", [1_100, 50_000])
            d = self.write_run(root, "d", [1_000])
            self.assertEqual(rc.compare(a, b), 0)
            self.assertEqual(rc.compare(a, c), 1)
            self.assertEqual(rc.compare(a, d), 1)


if __name__ == "__main__":
    unittest.main()
