#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The log check in armed_lever.py. No daemon: the defect is a read that
# treats an earlier run's line as this spawn's announcement, or a check
# that passes when the line was never written.

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import armed_lever  # noqa: E402


class AnnouncedSince(unittest.TestCase):
    def test_reads_only_what_follows_the_offset(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "seed.log")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("shekyld: " + armed_lever.ANNOUNCEMENT + "\n")
            offset = armed_lever.log_size(log)
            self.assertTrue(armed_lever.announced_since(log, 0))
            self.assertFalse(
                armed_lever.announced_since(log, offset),
                "an earlier run's line is not this spawn's",
            )
            with open(log, "a", encoding="utf-8") as fh:
                fh.write("shekyld: " + armed_lever.ANNOUNCEMENT + "\n")
            self.assertTrue(armed_lever.announced_since(log, offset))

    def test_a_missing_log_has_announced_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "absent.log")
            self.assertEqual(armed_lever.log_size(log), 0)
            self.assertFalse(armed_lever.announced_since(log, 0))


class CheckLog(unittest.TestCase):
    def _run(self, log, *extra):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "armed_lever.py")
        return subprocess.run(
            [sys.executable, script, "--check-log", log, *extra],
            capture_output=True,
            text=True,
        )

    def test_exit_status_is_whether_this_spawn_announced(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "daemon.out")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write("noise\n")
            missing = self._run(log)
            self.assertEqual(missing.returncode, 1, missing.stderr)
            self.assertIn(armed_lever.ANNOUNCEMENT, missing.stderr)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(armed_lever.ANNOUNCEMENT + "\n")
            present = self._run(log)
            self.assertEqual(present.returncode, 0, present.stderr)

    def test_offset_ignores_an_earlier_line(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "daemon.out")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write(armed_lever.ANNOUNCEMENT + "\n")
            offset = armed_lever.log_size(log)
            stale = self._run(log, "--offset", str(offset))
            self.assertEqual(stale.returncode, 1, stale.stderr)
            with open(log, "a", encoding="utf-8") as fh:
                fh.write("again " + armed_lever.ANNOUNCEMENT + "\n")
            fresh = self._run(log, "--offset", str(offset))
            self.assertEqual(fresh.returncode, 0, fresh.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
