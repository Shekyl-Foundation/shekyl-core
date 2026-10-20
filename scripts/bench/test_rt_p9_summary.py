#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Tests for rt_p9_summary.py.
#
# A green control comes first: a complete run, with the 99th percentiles
# and the deadlines computed here from the fixture, must be reported as met.
# Each other test breaks one thing and requires the refusal, or the VOID,
# to name it. A refusal with no control stays green when the loader
# rejects everything.

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rt_p9_summary as s  # noqa: E402


SAMPLES = 20
MS = 1_000_000


def server_stamps(base_ms):
    # accept → m1 at base, m2 1 ms later, m3 base later, m4 1 ms later,
    # first record base later, reply at once.
    m1 = base_ms * MS
    m2 = m1 + 1 * MS
    m3 = m2 + base_ms * MS
    m4 = m3 + 1 * MS
    first = m4 + base_ms * MS
    reply = first + MS // 10
    return [m1, m2, m3, m4, first, reply]


def client_stamps(base_ms):
    connected = 5 * base_ms * MS
    m1 = connected + MS // 10
    m2 = m1 + base_ms * MS + 1 * MS
    m3 = m2 + 1 * MS
    m4 = m3 + base_ms * MS + 1 * MS
    first = m4 + MS // 10
    reply = first + base_ms * MS
    return [connected, m1, m2, m3, m4, first, reply]


def base_for(leg, sample):
    # The onion leg's samples take 100..119 ms a hop, the LAN's 1..20.
    return (100 if leg == "onion" else 1) + sample


def write(path, columns, rows):
    with open(path, "w", newline="") as handle:
        handle.write("\t".join(columns) + "\n")
        for row in rows:
            handle.write("\t".join(str(cell) for cell in row) + "\n")


class Fixture:
    """A run directory; each leg's rows editable before writing."""

    def __init__(self):
        self.clients = {}
        self.servers = {}
        for leg in s.LEGS:
            self.clients[leg] = [
                [i, leg, "true"] + client_stamps(base_for(leg, i)) for i in range(SAMPLES)
            ]
            self.servers[leg] = [
                [i, i, "true"] + server_stamps(base_for(leg, i)) for i in range(SAMPLES)
            ]

    def write(self, directory):
        for leg in s.LEGS:
            os.makedirs(os.path.join(directory, leg))
            write(os.path.join(directory, leg, "client.tsv"), s.CLIENT_COLUMNS, self.clients[leg])
            write(os.path.join(directory, leg, "server.tsv"), s.SERVER_COLUMNS, self.servers[leg])
        return directory


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.fixture = Fixture()

    def tearDown(self):
        self.tmp.cleanup()

    def run_it(self):
        return s.summarise(self.fixture.write(self.dir), SAMPLES)

    def assert_refused(self, fragment):
        with self.assertRaises(SystemExit) as caught:
            self.run_it()
        self.assertIn(fragment, str(caught.exception))

    def assert_void(self, fragment):
        text, verdict = self.run_it()
        self.assertFalse(verdict.met)
        self.assertIn("**VOID.**", text)
        self.assertIn(fragment, text)
        self.assertNotIn("## The deadlines", text)


class Control(Base):
    def test_a_complete_run_is_met_and_derives_both_deadlines(self):
        text, verdict = self.run_it()
        self.assertTrue(verdict.met, verdict.void_reasons)
        # Nearest-rank p99 of 20 samples is the 20th: the onion leg's
        # largest base, 119 ms.
        onion_m1 = sorted(server_stamps(base_for("onion", i))[0] for i in range(SAMPLES))
        onion_first = sorted(server_stamps(base_for("onion", i))[4] for i in range(SAMPLES))
        self.assertEqual(s.percentile(onion_m1, 99), 119 * MS)
        # 2 × 119 ms rounds up to 1 s; 2 × (3 × 119 + 2) ms = 718 ms → 1 s.
        self.assertEqual(s.deadline_seconds(onion_m1[-1]), 1)
        self.assertIn(f"| message 1 | {s.ms(onion_m1[-1])} | 1 |", text)
        self.assertIn(f"| whole handshake | {s.ms(onion_first[-1])} | 1 |", text)
        self.assertIn("| onion | 20 | 20 | 100.0% | 0 |", text)


class Rounding(unittest.TestCase):
    def test_the_deadline_rounds_up_and_an_exact_second_stays(self):
        self.assertEqual(s.deadline_seconds(1_200 * MS), 3)
        self.assertEqual(s.deadline_seconds(1_500 * MS), 3)
        self.assertEqual(s.deadline_seconds(1_500 * MS + 1), 4)
        self.assertEqual(s.deadline_seconds(1), 1)


class Shape(Base):
    def test_a_missing_file_is_refused(self):
        self.fixture.write(self.dir)
        os.remove(os.path.join(self.dir, "lan", "server.tsv"))
        with self.assertRaises(SystemExit) as caught:
            s.summarise(self.dir, SAMPLES)
        self.assertIn("server.tsv is missing", str(caught.exception))

    def test_the_wrong_sample_count_is_refused(self):
        self.fixture.clients["onion"].pop()
        self.assert_refused(f"has {SAMPLES - 1} samples, not {SAMPLES}")

    def test_a_row_naming_another_leg_is_refused(self):
        self.fixture.clients["lan"][3][1] = "onion"
        self.assert_refused("names leg 'onion'")

    def test_a_daemon_row_naming_a_sample_twice_is_refused(self):
        self.fixture.servers["onion"][5][1] = 4
        self.assert_refused("names sample 4 a second time")

    def test_a_client_success_without_the_daemons_is_refused(self):
        self.fixture.servers["lan"][7][2] = "false"
        self.assert_refused("lan sample 7: the client says ok=True, the daemon ok=False")

    def test_stamps_going_backwards_are_refused(self):
        row = self.fixture.servers["onion"][2]
        row[4], row[5] = row[5], row[4]
        self.assert_refused("stamps go backwards")

    def test_an_ok_row_lacking_a_stamp_is_refused(self):
        self.fixture.clients["onion"][0][-1] = ""
        self.assert_refused("is ok but lacks reply_received_ns")


class Failures(Base):
    def fail_onion(self, count):
        # The client failed at its connect; the daemon never accepted.
        for i in range(count):
            self.fixture.clients["onion"][i] = [i, "onion", "false"] + [""] * 7
        self.fixture.servers["onion"] = [
            [n, i, "true"] + server_stamps(base_for("onion", i))
            for n, i in enumerate(range(count, SAMPLES))
        ]

    def test_one_failure_in_twenty_is_95_percent_and_met(self):
        self.fail_onion(1)
        text, verdict = self.run_it()
        self.assertTrue(verdict.met, verdict.void_reasons)
        self.assertIn("| onion | 20 | 19 | 95.0% | 0 |", text)

    def test_two_failures_in_twenty_void_the_run(self):
        self.fail_onion(2)
        self.assert_void("onion: 18 of 20 completed, below 95%")

    def test_an_accept_that_never_reached_the_first_record_is_counted(self):
        self.fixture.servers["lan"].append([SAMPLES, "", "false", 5 * MS] + [""] * 5)
        text, verdict = self.run_it()
        self.assertTrue(verdict.met, verdict.void_reasons)
        self.assertIn(f"| lan | {SAMPLES} | {SAMPLES} | 100.0% | 1 |", text)


class Agreement(Base):
    def test_a_client_round_trip_shorter_than_the_daemons_turn_voids(self):
        # The daemon spends 201 ms between message 1 and message 2; the
        # client saw the whole round trip in 104.
        row = self.fixture.servers["onion"][3]
        shift = 200 * MS
        for k in range(4, 9):
            row[k] += shift
        self.assert_void("onion: the two sides disagree on samples [3]")

    def test_a_daemon_round_trip_shorter_than_the_clients_turn_voids(self):
        row = self.fixture.clients["lan"][6]
        shift = 500 * MS
        for k in range(6, 10):
            row[k] += shift
        self.assert_void("lan: the two sides disagree on samples [6]")


class Slack(Base):
    # The registered slack, written here rather than read from the module,
    # so a change to the module's is seen.
    REGISTERED_NS = 1_000_000

    def shortfall(self, ns):
        # The daemon's turn between message 1 and message 2 made longer than
        # the client's whole round trip by `ns`.
        row = self.fixture.servers["onion"][0]
        client = self.fixture.clients["onion"][0]
        client_rt = client[5] - client[4]
        shift = client_rt - (row[4] - row[3]) + ns
        for k in range(4, 9):
            row[k] += shift

    def test_a_shortfall_within_the_slack_is_met(self):
        self.shortfall(self.REGISTERED_NS)
        _, verdict = self.run_it()
        self.assertTrue(verdict.met, verdict.void_reasons)

    def test_a_shortfall_beyond_the_slack_voids(self):
        self.shortfall(self.REGISTERED_NS + 1)
        self.assert_void("onion: the two sides disagree on samples [0]")


class Exit(Base):
    def test_main_exits_3_on_a_void_run_and_0_on_a_met_one(self):
        self.fixture.write(self.dir)
        devnull = open(os.devnull, "w")
        saved, sys.stdout = sys.stdout, devnull
        try:
            self.assertEqual(s.main(["x", "--samples", str(SAMPLES), self.dir]), 0)
        finally:
            sys.stdout = saved
            devnull.close()
        other = tempfile.TemporaryDirectory()
        try:
            fixture = Fixture()
            for i in range(3):
                fixture.clients["lan"][i] = [i, "lan", "false"] + [""] * 7
            fixture.servers["lan"] = [
                [n, i, "true"] + server_stamps(base_for("lan", i))
                for n, i in enumerate(range(3, SAMPLES))
            ]
            fixture.write(other.name)
            devnull = open(os.devnull, "w")
            saved, sys.stdout = sys.stdout, devnull
            try:
                self.assertEqual(s.main(["x", "--samples", str(SAMPLES), other.name]), 3)
            finally:
                sys.stdout = saved
                devnull.close()
        finally:
            other.cleanup()


if __name__ == "__main__":
    unittest.main()
