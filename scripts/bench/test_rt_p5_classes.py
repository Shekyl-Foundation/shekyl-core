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

# The committed 4.x trace the bytes-kind pin reads. A missing directory
# fails the test: the subject is this registration's capture.
REGISTERED_TRACE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "benchmarks",
    "rt_p5_rpc_message_sizes_20261115_captures", "registered_1",
)


def rust_text(path):
    with open(os.path.join(RUST, *path), encoding="utf-8") as f:
        return f.read()


def rust_rhs(path, name):
    """The right-hand side of `const NAME`, whitespace collapsed.

    Layout and visibility do not matter. The comparison is against the
    expression as written: this does not evaluate Rust, so an equivalent
    expression the test has not named fails, and a reflow does not."""
    found = re.findall(
        r"\bconst\s+%s\s*:[^=;]+=\s*(.+?)\s*;" % re.escape(name), rust_text(path), re.S)
    if len(found) != 1:
        raise AssertionError("%s defines %s %d times" % ("/".join(path), name, len(found)))
    return " ".join(found[0].split())


def rust_fn(path, name):
    """The text of the top-level function `name`, through its closing brace.

    Visibility and qualifiers before `fn` do not matter. rustfmt closes a
    top-level item with `}` at column 0, so the body ends at the first such
    line: whatever follows it, of any shape, is not read."""
    text = rust_text(path)
    found = [m.start() for m in re.finditer(
        r"(?m)^(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+%s\b"
        % re.escape(name), text)]
    if len(found) != 1:
        raise AssertionError("%s defines fn %s %d times" % ("/".join(path), name, len(found)))
    rest = text[found[0]:]
    end = re.search(r"(?m)^\}", rest)
    if end is None:
        raise AssertionError("%s: fn %s has no closing brace" % ("/".join(path), name))
    return rest[:end.end()]


class RecordConstants(unittest.TestCase):
    """The script cannot import the Rust constants, so it reads each
    definition's right-hand side and compares that, and compares its own
    number separately. Red edit: set `OCCUPANCY_LEN = 3` in the script, and
    this test fails. A reflow of the Rust definition does not."""

    def test_the_record_constants_are_the_noise_crates(self):
        classed = ("shekyl-noise", "src", "classed.rs")
        self.assertEqual(rust_rhs(classed, "OCCUPANCY_LEN"), "2")
        self.assertEqual(rc.OCCUPANCY_LEN, 2)
        self.assertEqual(rust_rhs(classed, "MAX_RECORD_PLAINTEXT"), "u16::MAX as usize")
        self.assertEqual(rc.MAX_RECORD_PLAINTEXT, 0xFFFF)


class RunKeys(unittest.TestCase):
    """The script's labels and curve key are the instrument's constants.
    Red edit: set `RUN_CURVE_KEY = "curve_tree_info"` in the script, and
    this test fails. Red edit: write run.json's key as the literal
    `"curve"` inside `write_outputs`, and the write-site test fails."""

    INSTRUMENT = ("shekyl-engine-core", "src", "engine", "regtest_e2e_rt_p5.rs")

    def test_the_labels_are_the_instruments(self):
        pairs = (
            ("LABEL_TX_SUBMIT", rc.LABEL_TX_SUBMIT),
            ("LABEL_BLOCK_SHOW", rc.LABEL_BLOCK_SHOW),
            ("LABEL_FEE", rc.LABEL_FEE),
            ("RUN_CURVE_KEY", rc.RUN_CURVE_KEY),
        )
        for name, value in pairs:
            self.assertEqual(rust_rhs(self.INSTRUMENT, name), '"%s"' % value, name)

    def test_run_json_is_written_under_the_constant(self):
        # One use, inside the function. The constant's own definition is
        # outside it; a reader that returns the whole file counts two and
        # fails. A comment carrying the same shape inside the function does
        # too.
        body = rust_fn(self.INSTRUMENT, "write_outputs")
        self.assertEqual(len(re.findall(r"\bRUN_CURVE_KEY\s*:", body)), 1)


class BytesKind(unittest.TestCase):
    """A submission body on the 4.x wire is the client's envelope plus
    padded base64. `derive` does not use this; the registered rule is the
    whole-factor fit. Red edit: set `BASE64_CHARS = 5` in the script, and
    both tests fail."""

    def test_the_empty_transaction_is_the_envelope(self):
        # RFC 4648 §4: a short group still occupies 4 characters, and no
        # bytes occupy none. The envelope's 66 is the client's empty body.
        self.assertEqual(rc.base64_padded_len(0), 0)
        self.assertEqual(rc.base64_padded_len(1), 4)
        self.assertEqual(rc.base64_padded_len(3), 4)
        self.assertEqual(rc.base64_padded_len(4), 8)
        self.assertEqual(len(rc.TX_SUBMIT_ENVELOPE), 66)
        self.assertEqual(rc.tx_submit_body(0), 66)
        self.assertEqual(rc.tx_submit_body(1), 70)
        with self.assertRaises(ValueError):
            rc.base64_padded_len(-1)

    def test_the_registered_trace_is_that_encoding(self):
        messages, txs, _ = rc.load(REGISTERED_TRACE)
        tx_len = {}
        predicted = {}
        for t in txs:
            index = int(t["tx"])
            tx_len[index] = int(t["tx_len"])
            predicted.setdefault(index, {})[int(t["depth"])] = int(t["predicted_tx_len"])
        subs = sorted(
            (m for m in messages
             if m["label"] == rc.LABEL_TX_SUBMIT and m["direction"] == "request"),
            key=lambda m: m["body"],
        )
        order = sorted(tx_len, key=lambda i: (tx_len[i], i))
        self.assertEqual(len(subs), len(order))
        ref = min(subs, key=lambda m: m["body"])
        # The head aside from content-length's digits. The registration
        # records it as 100.
        base_head = ref["head"] - len(str(ref["body"]))
        self.assertEqual(base_head, 100)
        largest = 0
        for message, index in zip(subs, order):
            self.assertEqual(message["body"], rc.tx_submit_body(tx_len[index]))
            for _depth, nbytes in predicted[index].items():
                body = rc.tx_submit_body(nbytes)
                total = base_head + len(str(body)) + body
                largest = max(largest, total)
                if nbytes == tx_len[index]:
                    self.assertEqual(total, message["total"], index)
        # The registration's largest cell: 8 inputs, 16 outputs, depth 8.
        self.assertEqual(largest, 108_860)


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
        recs = [(30_000, rc.LABEL_TX_SUBMIT, "request"), (200, "json_rpc:chain_height", "request"),
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
