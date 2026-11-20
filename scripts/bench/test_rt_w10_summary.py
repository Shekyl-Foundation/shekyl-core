#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Tests for rt_w10_summary.py. A complete run is summarised first, and the
# caps are computed here from the fixture. Each other test breaks one
# thing and requires the refusal to name it.

import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rt_w10_summary as s  # noqa: E402


def write_samples(directory, name, series_rows):
    path = os.path.join(directory, name)
    with open(path, "w", newline="") as handle:
        handle.write("series\titeration\tbytes\twall_ns\tcpu_ns\n")
        for series, nbytes, wall_of, cpu_of in series_rows:
            for iteration in range(1, s.SAMPLES + 1):
                handle.write(
                    f"{series}\t{iteration}\t{nbytes}\t{wall_of(iteration)}\t{cpu_of(iteration)}\n"
                )


def write_constants(directory, pruned_len=1500):
    text = (
        "min_block_weight\t300000\n"
        "coinbase_reserve\t20000\n"
        f"pruned_len\t{pruned_len}\n"
        "penalty_multiple\t2\n"
    )
    with open(os.path.join(directory, "constants.tsv"), "w") as handle:
        handle.write(text)


def equal(value):
    return lambda _iteration: value


class SummaryTest(unittest.TestCase):
    def test_a_complete_run_derives_the_caps_the_fixture_computes(self):
        with tempfile.TemporaryDirectory() as directory:
            write_samples(
                directory,
                "hashes.tsv",
                (
                    ("header", 136, lambda i: 1_000_000 + i, lambda i: 1_000_000 + i),
                    ("max", 33_000_128, lambda i: 2_000_000 + i, lambda i: 2_000_000 + i),
                ),
            )
            write_samples(
                directory,
                "coinbase.tsv",
                (
                    ("block", 0, equal(1000), equal(1000)),
                    ("block_info", 0, equal(100), equal(100)),
                    ("tx_get", 0, equal(50), equal(50)),
                ),
            )
            write_samples(
                directory,
                "parse.tsv",
                (("pruned", 1500, equal(20), equal(20)),),
            )
            write_constants(directory)
            caps = s.derive(
                s.load_samples(
                    os.path.join(directory, "hashes.tsv"),
                    s.HASH_SERIES,
                    {"header": 136, "max": 33_000_128},
                ),
                s.load_samples(
                    os.path.join(directory, "coinbase.tsv"),
                    s.COINBASE_SERIES,
                    {"block": 0, "block_info": 0, "tx_get": 0},
                ),
                s.load_samples(
                    os.path.join(directory, "parse.tsv"),
                    s.PARSE_SERIES,
                    {"pruned": 1500},
                ),
                s.load_constants(os.path.join(directory, "constants.tsv")),
            )
        ceiling = 1_000_000 + 99
        listed = 2 * 300_000 - 20_000
        parses = math.ceil(listed / 1500)
        per_height = 1000 + parses * (50 + 20)
        overhead = 2 * 100
        self.assertEqual(caps["ceiling_ns"], ceiling)
        self.assertEqual(caps["calc_pow_bytes"], 136)
        self.assertEqual(caps["fill_pow_hash_headers"], 1)
        self.assertEqual(caps["listed_weight"], listed)
        self.assertEqual(caps["parses_per_height"], parses)
        self.assertEqual(caps["per_height_ns"], per_height)
        self.assertEqual(caps["coinbase_span"], (ceiling - overhead) // per_height)
        self.assertGreater(caps["coinbase_span"], 0)

    def test_a_max_blob_inside_the_ceiling_is_served_whole(self):
        hashes = {
            "header": s.stats([(100, 100)] * s.SAMPLES),
            "max": s.stats([(40, 40)] * s.SAMPLES),
        }
        coinbase = {
            "block": s.stats([(10, 10)] * s.SAMPLES),
            "block_info": s.stats([(1, 1)] * s.SAMPLES),
            "tx_get": s.stats([(1, 1)] * s.SAMPLES),
        }
        parse = {"pruned": s.stats([(1, 1)] * s.SAMPLES)}
        constants = {
            "min_block_weight": 300_000,
            "coinbase_reserve": 20_000,
            "pruned_len": 1500,
            "penalty_multiple": 2,
        }
        caps = s.derive(hashes, coinbase, parse, constants)
        self.assertEqual(caps["calc_pow_bytes"], 33_000_128)

    def test_a_series_whose_cpu_was_not_seen_is_void(self):
        summary = s.stats([(500, 0)] * s.SAMPLES)
        with self.assertRaises(SystemExit) as raised:
            s.cost_of(summary)
        self.assertIn("void", str(raised.exception))

    def test_a_missing_file_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit) as raised:
                s.load_samples(
                    os.path.join(directory, "hashes.tsv"),
                    s.HASH_SERIES,
                    {"header": 136, "max": 33_000_128},
                )
        self.assertIn("missing", str(raised.exception))

    def test_a_short_series_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "hashes.tsv")
            with open(path, "w") as handle:
                handle.write("series\titeration\tbytes\twall_ns\tcpu_ns\n")
                handle.write("header\t1\t136\t10\t10\n")
            with self.assertRaises(SystemExit) as raised:
                s.load_samples(path, s.HASH_SERIES, {"header": 136, "max": 33_000_128})
        self.assertIn("samples", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
