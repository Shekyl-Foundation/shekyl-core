#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Tests for rt_p6_summary.py: the nearest-rank percentile the registration
# names, and that a run missing a registered step is refused.

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rt_p6_summary as s  # noqa: E402


class Percentile(unittest.TestCase):
    def test_nearest_rank(self):
        v = list(range(1, 101))
        self.assertEqual(s.percentile(v, 50), 50)
        self.assertEqual(s.percentile(v, 90), 90)
        self.assertEqual(s.percentile(v, 99), 99)
        self.assertEqual(s.percentile(v, 100), 100)
        self.assertEqual(s.percentile([7], 99), 7)

    def test_no_samples_is_refused(self):
        with self.assertRaises(ValueError):
            s.percentile([], 50)


class MissingStep(unittest.TestCase):
    def test_a_run_without_every_step_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "steps.tsv"), "w") as f:
                f.write("iteration\tside\tstep\twall_ns\tcpu_ns\n0\tclient\tstart\t1\t1\n")
            with self.assertRaises(SystemExit):
                s.summarise(d)


if __name__ == "__main__":
    unittest.main()
