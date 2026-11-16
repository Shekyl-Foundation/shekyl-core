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
import re
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


RUST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "rust")

# The integer-valued right-hand sides the record constants are written
# with. A form not listed here fails the test by name rather than being
# guessed at.
RUST_INTEGER_FORMS = {"u16::MAX as usize": 0xFFFF}


def rust_const(path, name):
    """The right-hand side of `const NAME: T = ...;` in a Rust source file,
    its whitespace collapsed: the definition read by its shape, so layout,
    visibility and the code around it do not matter."""
    with open(os.path.join(RUST, *path), encoding="utf-8") as f:
        text = f.read()
    found = re.findall(r"\bconst\s+%s\s*:[^=;]+=\s*(.+?)\s*;" % re.escape(name), text, re.S)
    if len(found) != 1:
        raise AssertionError("%s defines %s %d times" % ("/".join(path), name, len(found)))
    return " ".join(found[0].split())


def rust_integer(rhs):
    """A constant's value from its right-hand side: a literal, or a form in
    `RUST_INTEGER_FORMS`."""
    if rhs in RUST_INTEGER_FORMS:
        return RUST_INTEGER_FORMS[rhs]
    try:
        return int(rhs.replace("_", ""), 0)
    except ValueError:
        raise AssertionError("no value is known for the Rust expression %r" % rhs)


class RecordConstants(unittest.TestCase):
    """The script cannot import the Rust constants, so it reads their
    definitions in `shekyl-noise` and compares the values. Red edit: set
    `OCCUPANCY_LEN = 3` in the script, and this test fails."""

    def test_the_record_constants_are_the_noise_crates(self):
        classed = ("shekyl-noise", "src", "classed.rs")
        self.assertEqual(rust_integer(rust_const(classed, "OCCUPANCY_LEN")), rc.OCCUPANCY_LEN)
        self.assertEqual(rust_integer(rust_const(classed, "MAX_RECORD_PLAINTEXT")),
                         rc.MAX_RECORD_PLAINTEXT)

    def test_a_constant_is_read_whatever_its_layout(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "k.rs"), "w", encoding="utf-8") as f:
                f.write("pub(crate)  const\n    OCCUPANCY_LEN :\n usize =\n 0x2 ;\n")
            here = os.path.relpath(d, RUST).split(os.sep) + ["k.rs"]
            self.assertEqual(rust_integer(rust_const(here, "OCCUPANCY_LEN")), 2)

    def test_an_unknown_form_is_refused_by_name(self):
        with self.assertRaisesRegex(AssertionError, "u32::MAX"):
            rust_integer("u32::MAX as usize")


class RunKeys(unittest.TestCase):
    """run.json's curve key is the instrument's: the instrument writes the
    file under its `RUN_CURVE_KEY`, and the script reads it under its own.
    Red edit: set `RUN_CURVE_KEY = "curve_tree_info"` in the script, and
    this test fails."""

    INSTRUMENT = ("shekyl-engine-core", "src", "engine", "regtest_e2e_rt_p5.rs")

    def test_the_curve_key_is_the_instruments(self):
        self.assertEqual(rust_const(self.INSTRUMENT, "RUN_CURVE_KEY"),
                         '"%s"' % rc.RUN_CURVE_KEY)

    def test_the_instrument_writes_run_json_under_its_constant(self):
        with open(os.path.join(RUST, *self.INSTRUMENT), encoding="utf-8") as f:
            self.assertRegex(f.read(), r"\bRUN_CURVE_KEY\s*:\s*\w+\s*,")


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


class Report(unittest.TestCase):
    def msg(self, label, direction, total, wallet="w"):
        return {"wallet": wallet, "label": label, "direction": direction, "total": total}

    def test_a_record_that_crosses_a_boundary_is_counted_as_moved(self):
        classes = [300, 65_535]
        a = [self.msg("/a", "response", 290), self.msg("/a", "response", 100)]
        b = [self.msg("/a", "response", 297), self.msg("/a", "response", 101)]
        pairs, unmatched = rc.counterparts(a, b)
        moved, total = rc.falls_into(pairs, classes)
        self.assertEqual((unmatched, total), (0, 2))
        # 290 + 2 = 292 fits 300; 297 + 2 = 299 still fits: nothing moves.
        self.assertEqual(moved, {})
        b[0]["total"] = 299  # 301 bytes with its occupancy: the next class
        moved, _ = rc.falls_into(rc.counterparts(a, b)[0], classes)
        self.assertEqual(moved, {("/a", "response"): 1})

    def test_a_message_that_splits_differently_moves_all_its_records(self):
        pairs, _ = rc.counterparts(
            [self.msg("/a", "request", rc.RECORD_PAYLOAD_MAX)],
            [self.msg("/a", "request", rc.RECORD_PAYLOAD_MAX + 1)],
        )
        moved, total = rc.falls_into(pairs, [rc.MAX_RECORD_PLAINTEXT])
        self.assertEqual((moved, total), ({("/a", "request"): 2}, 2))

    def test_a_submission_alone_in_its_direction_is_reported_alone(self):
        classes = [500, 65_535]
        recs = [(30_000, rc.SUBMIT, "request"), (200, "json_rpc:chain_height", "request"),
                (40_000, "json_rpc:block_header_show", "response")]
        standing = rc.submission_standing(recs, classes)
        n, same, either = standing[65_535]
        self.assertEqual(n, 1)
        self.assertEqual(rc.verdict(same), "stands alone")
        self.assertEqual(rc.verdict(either), "shares with wallet sync (1 records)")


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
            f.write('{"cell": "x", "chain_height": 1, "%s": {}}' % rc.RUN_CURVE_KEY)
        return d

    def test_derive_reads_a_run_the_instrument_wrote(self):
        """`derive` runs over a whole run directory. Red edit: read
        `run['curve_tree_info']` in `derive`, as the script did before the
        4.0 rename's key reached it, and this fails."""
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as root:
            d = self.write_run(root, "a", [1_000, 70_000])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc.derive(d)
            self.assertIn("# RT-P5 classes: `x` cell", out.getvalue())

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
