#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The armed test-lever row, for every Python regtest spawn that calls one
# and for the shell harness that checks the same line.
#
# The producer is `dev_levers` in shekyl-daemon-config. The test
# `the_armed_lever_switch_announces_itself` pins the sentence. This module
# is the copy the spawners read. `scripts/ci/check_armed_lever_launchers.py`
# holds that copy, the Rust const in `regtest_e2e.rs`, and the producer
# test to one sentence, and fails a new regtest spawn that names a lever
# and does not arm the row.
#
# A spawn that calls generateblocks or pop_blocks puts FLAG on that
# process's argv and then calls announced_since on the bytes that process
# wrote. A later restart that calls no lever does not take the flag.

"""The armed dev-rpc row: the flag, the announcement, the log check."""

import argparse
import os
import sys

# The argv token that arms the row. The daemon's own flag.
FLAG = "--dev-rpc"

# The line `dev_levers` writes for that switch (IG-8). A start that also
# sets another lever writes a second line, so callers match this as a
# substring of the log, not as the whole log.
ANNOUNCEMENT = "development lever set: dev-rpc=true"


def log_size(path):
    """Bytes in the log now, so a later read sees only what follows."""
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def announced_since(path, offset, line=ANNOUNCEMENT):
    """Whether `path` names `line` in the bytes after `offset`.

    An appended log carries earlier runs. Only the bytes this spawn wrote
    count. Offset 0 is a log opened for this spawn.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            return line in fh.read()
    except OSError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-log",
        required=True,
        metavar="PATH",
        help="exit 0 when the bytes after --offset contain the announcement",
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="byte offset; only what follows counts (default 0, a fresh log)",
    )
    args = parser.parse_args(argv)
    if args.offset < 0:
        print("offset must be >= 0", file=sys.stderr)
        return 2
    if announced_since(args.check_log, args.offset):
        return 0
    print(
        f"the daemon did not announce {ANNOUNCEMENT!r} at start; see {args.check_log}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
