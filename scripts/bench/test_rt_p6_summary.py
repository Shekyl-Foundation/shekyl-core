#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Tests for rt_p6_summary.py.
#
# A green control comes first: a complete run, with the medians computed
# here from the fixture, must be reported. Each other test breaks one
# thing and requires the refusal to name it. A refusal with no control
# stays green when the loader rejects everything.

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rt_p6_summary as s  # noqa: E402


SAMPLES = 10


def clock_cells(values):
    summary = s.stats(values)
    return " | ".join(s.us(summary[name]) for name in s.CLOCKS)


def series(scale):
    return [(i + 1) * scale for i in range(SAMPLES)]


def write_tsv(directory, name, header, rows):
    path = os.path.join(directory, name)
    with open(path, "w", newline="") as handle:
        handle.write(header + "\n")
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


def step_rows():
    rows = []
    for i, ns in enumerate(series(1000)):
        for side, name in s.HANDSHAKE_STEPS:
            rows.append((i, side, name, ns, ns))
    return rows


def message1_rows(with_no_bundle=False):
    rows = []
    kinds = [("honest", 1000, 3000), ("tag_flipped", 2000, 4000)]
    if with_no_bundle:
        kinds.append(("no_bundle", 500, 700))
    for kind, new_scale, read_scale in kinds:
        accepted = "true" if s.MESSAGE1_ACCEPTED[kind] else "false"
        for i in range(SAMPLES):
            new_ns = (i + 1) * new_scale
            read_ns = (i + 1) * read_scale
            rows.append((i, kind, accepted, new_ns, new_ns, read_ns, read_ns))
    return rows


def record_rows(classes=None):
    classes = s.RECORD_CLASSES if classes is None else classes
    rows = []
    for cls in classes:
        for op in s.RECORD_OPS:
            for i in range(SAMPLES):
                ns = (i + 1) * cls
                rows.append((i, cls, op, ns, ns))
    return rows


def write_run(directory, *, steps=None, message1=None, records=None, skip=()):
    if "steps" not in skip:
        write_tsv(
            directory,
            s.STEPS_FILE,
            "iteration\tside\tstep\twall_ns\tcpu_ns",
            step_rows() if steps is None else steps,
        )
    if "message1" not in skip:
        write_tsv(
            directory,
            s.MESSAGE1_FILE,
            "iteration\tkind\taccepted\tnew_wall_ns\tnew_cpu_ns\tread_wall_ns\tread_cpu_ns",
            message1_rows() if message1 is None else message1,
        )
    if "records" not in skip:
        write_tsv(
            directory,
            s.RECORDS_FILE,
            "iteration\tclass\top\twall_ns\tcpu_ns",
            record_rows() if records is None else records,
        )


def refusal(test, directory):
    with test.assertRaises(SystemExit) as caught:
        s.summarise(directory)
    return str(caught.exception)


class Percentile(unittest.TestCase):
    def test_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual(s.percentile(values, 50), 50)
        self.assertEqual(s.percentile(values, 90), 90)
        self.assertEqual(s.percentile(values, 99), 99)
        self.assertEqual(s.percentile(values, 100), 100)
        self.assertEqual(s.percentile([7], 99), 7)

    def test_no_samples_is_refused(self):
        with self.assertRaises(ValueError):
            s.percentile([], 50)


class Control(unittest.TestCase):
    def test_a_complete_run_reports_the_registered_statistics(self):
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory)
            text = s.summarise(directory)

        step = series(1000)
        self.assertIn(
            f"| client | `start` | {SAMPLES} | {clock_cells(step)} | {clock_cells(step)} |",
            text,
        )
        self.assertIn("CPU p90", text)
        self.assertIn("CPU max", text)

        client_n = sum(1 for side, _ in s.HANDSHAKE_STEPS if side == "client")
        daemon_n = sum(1 for side, _ in s.HANDSHAKE_STEPS if side == "daemon")
        client = [client_n * ns for ns in step]
        daemon = [daemon_n * ns for ns in step]
        both = [client_n * ns + daemon_n * ns for ns in step]
        self.assertIn(
            f"| client | {SAMPLES} | {clock_cells(client)} | {clock_cells(client)} |",
            text,
        )
        self.assertIn(
            f"| daemon | {SAMPLES} | {clock_cells(daemon)} | {clock_cells(daemon)} |",
            text,
        )
        self.assertIn(
            f"| both | {SAMPLES} | {clock_cells(both)} | {clock_cells(both)} |",
            text,
        )

        honest_attempt = [(i + 1) * 4000 for i in range(SAMPLES)]
        self.assertIn(f"| honest | `attempt` | {SAMPLES} | {SAMPLES} |", text)
        self.assertIn(clock_cells(honest_attempt), text)
        self.assertIn(f"| tag_flipped | `read_message1` | {SAMPLES} | 0 |", text)

        record = series(512)
        self.assertIn(
            f"| 512 | seal | {SAMPLES} | {clock_cells(record)} | "
            f"{clock_cells(record)} | 5.00 |",
            text,
        )
        self.assertIn("| 65,535 | open |", text)


class Mac1Shape(unittest.TestCase):
    """A capture taken with mac1 on message 1 has a third kind, no_bundle.
    The kind column names the set. There is no flag beside it."""

    def test_a_mac1_capture_reads_with_its_kinds(self):
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=message1_rows(with_no_bundle=True))
            text = s.summarise(directory)
        self.assertIn(f"| no_bundle | `read_message1` | {SAMPLES} | 0 |", text)

    def test_a_kind_outside_both_registered_sets_is_refused(self):
        rows = message1_rows(with_no_bundle=True)
        rows.append(rows[-1][:1] + ("other",) + rows[-1][2:])
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("not a registered set", refusal(self, directory))

    def test_a_single_kind_is_not_a_registered_set(self):
        rows = [row for row in message1_rows() if row[1] == "honest"]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("not a registered set", refusal(self, directory))


class Refusals(unittest.TestCase):
    def test_missing_step_names_the_step(self):
        rows = [row for row in step_rows() if row[2] != "read_message1"]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, steps=rows)
            self.assertIn("read_message1", refusal(self, directory))

    def test_one_iteration_missing_a_step(self):
        rows = [row for row in step_rows() if not (row[0] == 1 and row[2] == "new")]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, steps=rows)
            message = refusal(self, directory)
        self.assertIn("iteration 1 lacks", message)
        self.assertIn("daemon/new", message)

    def test_repeated_step(self):
        rows = step_rows()
        rows.append((0, "client", "start", 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, steps=rows)
            self.assertIn("repeats client/start in iteration 0", refusal(self, directory))

    def test_unexpected_step(self):
        rows = step_rows()
        rows.append((0, "client", "nope", 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, steps=rows)
            self.assertIn("unexpected step client/nope", refusal(self, directory))

    def test_no_handshakes(self):
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, steps=[])
            self.assertIn("steps.tsv has no handshakes", refusal(self, directory))

    def test_missing_message1_kind(self):
        rows = [row for row in message1_rows() if row[1] != "tag_flipped"]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("not a registered set", refusal(self, directory))

    def test_tag_flipped_accepted_is_refused(self):
        rows = []
        for row in message1_rows():
            if row[1] == "tag_flipped" and row[0] == 0:
                row = (row[0], row[1], "true", *row[3:])
            rows.append(row)
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn(
                "tag_flipped iteration 0 accepted is true",
                refusal(self, directory),
            )

    def test_unexpected_message1_kind(self):
        rows = message1_rows()
        rows.append((0, "random", "false", 1, 1, 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("not a registered set", refusal(self, directory))

    def test_repeated_message1(self):
        rows = message1_rows()
        rows.append((0, "honest", "true", 1, 1, 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("repeats honest iteration 0", refusal(self, directory))

    def test_message1_kinds_cover_different_iterations(self):
        rows = [row for row in message1_rows() if not (row[1] == "tag_flipped" and row[0] == 3)]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, message1=rows)
            self.assertIn("kinds cover different iterations", refusal(self, directory))

    def test_empty_records(self):
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=[])
            self.assertIn("lacks class 512 seal", refusal(self, directory))

    def test_missing_record_class(self):
        rows = [row for row in record_rows() if row[1] != 65535]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=rows)
            self.assertIn("lacks class 65535 seal", refusal(self, directory))

    def test_unexpected_record_class(self):
        rows = record_rows()
        rows.append((0, 100, "seal", 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=rows)
            self.assertIn("unexpected class 100 seal", refusal(self, directory))

    def test_missing_record_op(self):
        rows = [row for row in record_rows() if not (row[1] == 512 and row[2] == "open")]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=rows)
            self.assertIn("lacks class 512 open", refusal(self, directory))

    def test_repeated_record(self):
        rows = record_rows()
        rows.append((0, 512, "seal", 1, 1))
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=rows)
            self.assertIn("repeats class 512 seal iteration 0", refusal(self, directory))

    def test_record_classes_cover_different_iterations(self):
        rows = [
            row
            for row in record_rows()
            if not (row[1] == 16384 and row[2] == "open" and row[0] == 4)
        ]
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, records=rows)
            self.assertIn("classes cover different iterations", refusal(self, directory))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            write_run(directory, skip=("records",))
            self.assertIn("records.tsv is missing", refusal(self, directory))


if __name__ == "__main__":
    unittest.main()
