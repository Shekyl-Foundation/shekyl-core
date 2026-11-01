#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_wall_clock_waits.py -- no wait in the C++ is timed on the wall clock.
#
# THE DEFECT THIS EXISTS FOR. `epee::misc_utils::sleep_no_w(ms)` slept until
# `boost::get_system_time() + ms`: an absolute deadline on the wall clock.
# When the clock was set back a day, a 100 ms sleep lasted a day. The
# daemon's stop polled through it (`Daemon::run`), and the join at the end
# of `run()` then waited out the day: every stop hang on the Tor lane's clock
# VM came after the clock was moved back, with every thread asleep, and every
# stop on the floor device, whose clock was not touched, was clean
# (TOR_SUPERVISOR.md §7; FOLLOWUPS, the stop-hang row). The stop now signals
# the running daemon directly, and the one other caller sleeps with
# `std::this_thread::sleep_for`, which is monotonic.
#
# WHAT IT FAILS ON. Either token, anywhere under `src/` or `contrib/`:
# `sleep_no_w` (the deleted helper coming back) and `get_system_time` (the
# wall-clock deadline it was built on). Both directories must exist and at
# least one file must be read, so a moved tree fails here instead of passing
# with nothing scanned (rule 47).
#
# Run `--selftest` to prove the detector can fail; CI runs it before the scan.

import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOTS = ("src", "contrib")
TOKENS = ("sleep_no_w", "get_system_time")


def hits_in(text):
    """The tokens found in `text`, with their 1-based line numbers."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for token in TOKENS:
            if token in line:
                found.append((number, token))
    return found


def scan(repo):
    """Every hit under the roots, and how many files were read."""
    hits = []
    read = 0
    for root in ROOTS:
        base = os.path.join(repo, root)
        if not os.path.isdir(base):
            raise SystemExit(f"check_wall_clock_waits: {root}/ is missing at {repo}")
        for directory, _, files in os.walk(base):
            for name in files:
                path = os.path.join(directory, name)
                try:
                    with open(path, encoding="utf-8") as handle:
                        text = handle.read()
                except (UnicodeDecodeError, OSError):
                    continue
                read += 1
                for number, token in hits_in(text):
                    hits.append((os.path.relpath(path, repo), number, token))
    return hits, read


def selftest():
    sample = "void f() {\n  epee::misc_utils::sleep_no_w(100);\n  boost::get_system_time();\n}\n"
    found = hits_in(sample)
    assert found == [(2, "sleep_no_w"), (3, "get_system_time")], found
    assert hits_in("std::this_thread::sleep_for(std::chrono::milliseconds(100));\n") == []
    print("check_wall_clock_waits: selftest passed")


def main():
    if "--selftest" in sys.argv[1:]:
        selftest()
        return 0
    hits, read = scan(REPO)
    if read == 0:
        print("check_wall_clock_waits: no file was read under src/ or contrib/", file=sys.stderr)
        return 1
    if hits:
        for path, number, token in hits:
            print(f"{path}:{number}: {token} (a wait timed on the wall clock)", file=sys.stderr)
        print(
            "check_wall_clock_waits: FAIL. Sleep with std::this_thread::sleep_for or a "
            "steady_clock deadline; a wall-clock deadline lasts as long as the clock is set back.",
            file=sys.stderr,
        )
        return 1
    print(f"check_wall_clock_waits: {read} files under src/ and contrib/, no wall-clock wait")
    return 0


if __name__ == "__main__":
    sys.exit(main())
