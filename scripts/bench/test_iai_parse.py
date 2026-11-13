#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""Tests for `scripts/bench/iai_parse.py`, the capture's gungraun parse.

The fixtures are gungraun's own lines: the cache derive as a named case
prints it, the same function unnamed as #1359's first capture printed it
(the row ran, and the parse dropped it), and the relay-admission row
from that capture.

Run: `python3 scripts/bench/test_iai_parse.py`.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import iai_parse  # noqa: E402

METRICS = """\
  Instructions:                  2351031131|N/A                  (*********)
  L1 Hits:                       2950197726|N/A                  (*********)
  LL Hits:                          2419755|N/A                  (*********)
  RAM Hits:                        26811930|N/A                  (*********)
  Total read+write:              2979429411|N/A                  (*********)
  Estimated Cycles:              3900714051|N/A                  (*********)
"""

NAMED = (
    "==== shekyl-pow-randomx::cache_derive_iai ====\n"
    "     Running benches/cache_derive_iai.rs (target/release/deps/x)\n"
    "cache_derive_iai::cache_derive_group::hot_path_bench_cache_derive "
    "fixed_seed:(Seedhash :: from_bytes(SEED))\n" + METRICS +
    "\nGungraun result: Ok. 1 without regressions; 0 regressed; "
    "0 filtered; 1 benchmarks finished in 45.4484s\n")

UNNAMED_HEADER = (
    "cache_derive_iai::cache_derive_group::hot_path_bench_cache_derive\n")

UNNAMED = (
    "==== shekyl-pow-randomx::cache_derive_iai ====\n"
    + UNNAMED_HEADER + METRICS)

RELAY = (
    "==== shekyl-verify-cost::relay_admission_verify_iai ====\n"
    "relay_admission_verify_iai::relay_admission_verify_group::"
    "crypto_bench_relay_admission_verify modal:(modal_shape())\n"
    "  Instructions:                   384111664|384111827            "
    "(-0.00004%) [-1.00000x]\n"
    "  L1 Hits:                        501605859|501608081            "
    "(-0.00044%) [-1.00000x]\n"
    "\nGungraun result: Ok. 1 without regressions; 0 regressed; "
    "0 filtered; 1 benchmarks finished in 164.709s\n")

ROWS = [
    ("shekyl-verify-cost", "relay_admission_verify_iai"),
    ("shekyl-pow-randomx", "cache_derive_iai"),
]


class ParseTests(unittest.TestCase):
    def test_a_named_case_is_an_entry_with_its_run_id_and_metrics(self) -> None:
        entries = iai_parse.parse(RELAY + NAMED, ROWS)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["run_id"], "modal")
        self.assertEqual(entries[0]["metrics"]["instructions"], 384111664)
        derive = entries[-1]
        self.assertEqual(derive["crate"], "shekyl-pow-randomx")
        self.assertEqual(derive["function"], "hot_path_bench_cache_derive")
        self.assertEqual(derive["run_id"], "fixed_seed")
        self.assertEqual(derive["metrics"]["instructions"], 2351031131)
        self.assertEqual(len(derive["metrics"]), 6)

    def test_a_header_without_a_run_id_is_refused_not_dropped(self) -> None:
        """Red edit: drop the `HEADER_SHAPE_RE` problem in `parse`. The
        relay section still yields its entries, so only this check sees
        the unread header in it."""
        text = RELAY + UNNAMED_HEADER + METRICS + NAMED
        with self.assertRaises(iai_parse.CaptureError) as caught:
            iai_parse.parse(text, ROWS)
        self.assertEqual(len(caught.exception.problems), 1)
        self.assertIn("does not read", caught.exception.problems[0])
        self.assertIn("relay_admission_verify_iai",
                      caught.exception.problems[0])

    def test_a_registered_row_whose_section_yields_no_entry_is_refused(self) -> None:
        """#1359's first capture: the derive row ran, printed its one
        unnamed header, and the envelope never held it.

        Red edit: drop the `found == 0` problem in `parse`. The header
        check still refuses this capture, but this problem is what names
        the missing row."""
        with self.assertRaises(iai_parse.CaptureError) as caught:
            iai_parse.parse(RELAY + UNNAMED, ROWS)
        problems = caught.exception.problems
        self.assertTrue(any("yields no entry" in p for p in problems),
                        problems)

    def test_an_empty_section_is_refused(self) -> None:
        """Red edit: drop the `found == 0` problem in `parse`."""
        empty = ("==== shekyl-pow-randomx::cache_derive_iai ====\n"
                 "error: no benchmark ran\n")
        with self.assertRaises(iai_parse.CaptureError) as caught:
            iai_parse.parse(RELAY + empty, ROWS)
        self.assertEqual(caught.exception.problems,
                         ["shekyl-pow-randomx::cache_derive_iai: registered, "
                          "but its section yields no entry"])

    def test_a_registered_row_with_no_section_is_refused(self) -> None:
        """Red edit: drop the `found is None` problem in `parse`."""
        with self.assertRaises(iai_parse.CaptureError) as caught:
            iai_parse.parse(RELAY, ROWS)
        self.assertEqual(caught.exception.problems,
                         ["shekyl-pow-randomx::cache_derive_iai: registered, "
                          "but the capture has no section for it"])

    def test_the_rows_are_read_from_the_benches_array(self) -> None:
        rows = iai_parse.rows_from_benches([
            "shekyl-pow-randomx:cache_derive:cache_derive_iai",
            "shekyl-verify-cost::relay_admission_verify_iai",
            "shekyl-p-serve::serve_response_iai:bench-internals",
            "",
        ])
        self.assertEqual(rows, [
            ("shekyl-pow-randomx", "cache_derive_iai"),
            ("shekyl-verify-cost", "relay_admission_verify_iai"),
            ("shekyl-p-serve", "serve_response_iai"),
        ])

    def test_the_capture_registers_its_rows_with_the_parse(self) -> None:
        """The capture passes every row it selected to the parse: a row it
        did not pass could go missing unseen."""
        script = (pathlib.Path(__file__).resolve().parent
                  / "capture_rust_baseline.sh").read_text()
        self.assertIn('PARSE_ROWS="$(printf \'%s\\n\' "${SELECTED[@]}")"',
                      script)
        self.assertIn('os.environ["PARSE_ROWS"]', script)
        self.assertIn("iai_parse.parse(iai_text, rows)", script)


if __name__ == "__main__":
    unittest.main()
