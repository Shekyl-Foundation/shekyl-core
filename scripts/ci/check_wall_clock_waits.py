#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_wall_clock_waits.py -- no blocking wait in the C++ is armed on the
# wall clock.
#
# THE DEFECT. `epee::misc_utils::sleep_no_w(ms)` slept until
# `boost::get_system_time() + ms`. With the clock set back a day, a 100 ms
# sleep lasted a day, and `Daemon::run` joined that sleep
# (`TOR_SUPERVISOR.md` §7).
#
# WHAT FAILS. A line under `src/` or `contrib/` that names one of `TOKENS`.
# Each token is a blocking wait whose deadline is the wall clock:
# `sleep_no_w` and `get_system_time` are the deleted sleep, `deadline_timer`
# is boost.asio's system-clock timer (`steady_timer` is the monotonic one),
# and `timed_wait` is the absolute wait on a condition. `sleep_for` and
# `universal_time` are not tokens. `universal_time` comparisons stall when
# the clock is set back, and they do not block a thread; that residual is
# a FOLLOWUPS row, not a hit here.
#
# A file that is not valid UTF-8 is still scanned. The tokens are ASCII, and
# decoding with replacement keeps them, so a non-UTF-8 byte cannot hide one.
# An I/O error fails the gate: a file that was not read is not a clean file.
# Both roots must exist and at least one file must be read (rule 47).
#
# `--selftest` plants each token, including one after a non-UTF-8 byte, and
# requires the scan to fail. A monotonic sleep passes. A missing root, an
# empty tree, and an unreadable file fail.

import os
import shutil
import stat
import sys
import tempfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ROOTS = ("src", "contrib")
TOKENS = ("sleep_no_w", "get_system_time", "deadline_timer", "timed_wait")

# Present in the tree, and not a blocking wall-clock wait. The selftest
# plants this and requires a clean scan, so a token that grows to cover it
# fails here.
MONOTONIC = """\
std::this_thread::sleep_for(std::chrono::milliseconds(100));
boost::asio::steady_timer timer;
auto seed = std::chrono::system_clock::now().time_since_epoch().count();
const auto now = boost::posix_time::microsec_clock::universal_time();
"""


class GateFailure(Exception):
    """The scan could not read its subject. The message is the verdict."""


def read_text(path):
    """The file as text. Replacement keeps an ASCII token past a bad byte."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        raise GateFailure(f"check_wall_clock_waits: {path}: {error}") from error
    return data.decode("utf-8", errors="replace")


def hits_in(text):
    """Tokens in `text`, with their 1-based line numbers."""
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
            raise GateFailure(
                f"check_wall_clock_waits: {root}/ is missing at {repo}"
            )
        for directory, _, files in os.walk(base):
            for name in files:
                path = os.path.join(directory, name)
                text = read_text(path)
                read += 1
                relative = os.path.relpath(path, repo)
                for number, token in hits_in(text):
                    hits.append((relative, number, token))
    return hits, read


def is_clean(hits, read):
    """Files were read, and none of them names a token."""
    return read != 0 and not hits


def report(hits, read):
    """0 when `is_clean`. The subject is named."""
    if not is_clean(hits, read):
        if read == 0:
            print(
                "check_wall_clock_waits: no file was read under src/ or contrib/",
                file=sys.stderr,
            )
        else:
            for path, number, token in hits:
                print(
                    f"{path}:{number}: {token} is a blocking wait armed on the wall clock",
                    file=sys.stderr,
                )
            print(
                "check_wall_clock_waits: FAIL. Sleep with std::this_thread::sleep_for "
                "or arm a boost::asio::steady_timer. A wall-clock deadline lasts as "
                "long as the clock is set back.",
                file=sys.stderr,
            )
        return 1
    print(
        f"check_wall_clock_waits: {read} files under src/ and contrib/, "
        "no wall-clock blocking wait"
    )
    return 0


def _fail(message):
    print(f"selftest FAIL: {message}", file=sys.stderr)
    return 1


def _plant(repo, relative, text):
    path = os.path.join(repo, relative)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def selftest():
    """The scan fails on each token and on a subject it cannot read."""
    with tempfile.TemporaryDirectory() as scratch:
        _plant(scratch, "src/monotonic.cpp", MONOTONIC)
        _plant(scratch, "contrib/keep.cpp", "\n")
        hits, read = scan(scratch)
        if not is_clean(hits, read):
            return _fail(f"a monotonic sleep was refused: {hits!r} read={read}")

        for token in TOKENS:
            _plant(scratch, "src/monotonic.cpp", f"void f() {{ {token}(100); }}\n")
            hits, _read = scan(scratch)
            if not any(hit[2] == token for hit in hits):
                return _fail(f"{token} was not reported: {hits!r}")
        _plant(scratch, "src/monotonic.cpp", MONOTONIC)

        odd = os.path.join(scratch, "src", "odd.cpp")
        with open(odd, "wb") as handle:
            handle.write(b"\xff not utf-8\n sleep_no_w(100);\n")
        hits, _read = scan(scratch)
        if not any(hit[2] == "sleep_no_w" and hit[0].endswith("odd.cpp") for hit in hits):
            return _fail(f"a token after a non-UTF-8 byte was not reported: {hits!r}")
        os.remove(odd)

        hits, read = scan(scratch)
        if not is_clean(hits, read):
            return _fail(f"the tree was dirty after the plant was removed: {hits!r}")

        os.remove(os.path.join(scratch, "contrib", "keep.cpp"))
        hits, read = scan(scratch)
        if not is_clean(hits, read):
            return _fail("a tree with only src/ files was treated as empty")
        _plant(scratch, "contrib/keep.cpp", "\n")

        # Both roots present and empty: absence of files is not a clean scan.
        os.remove(os.path.join(scratch, "src", "monotonic.cpp"))
        os.remove(os.path.join(scratch, "contrib", "keep.cpp"))
        hits, read = scan(scratch)
        if is_clean(hits, read):
            return _fail(f"an empty tree passed: read={read} hits={hits!r}")
        _plant(scratch, "src/monotonic.cpp", MONOTONIC)
        _plant(scratch, "contrib/keep.cpp", "\n")

        unreadable = os.path.join(scratch, "src", "unreadable.cpp")
        with open(unreadable, "w", encoding="utf-8") as handle:
            handle.write("sleep_no_w(100);\n")
        os.chmod(unreadable, 0)
        try:
            still_readable = os.access(unreadable, os.R_OK)
            if still_readable:
                print("selftest: unreadable-file case skipped (the file stayed readable)")
            else:
                try:
                    scan(scratch)
                except GateFailure as error:
                    if "unreadable.cpp" not in str(error):
                        return _fail(f"an unreadable file failed without its path: {error}")
                else:
                    return _fail("an unreadable file was scanned as clean")
        finally:
            os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)
            os.remove(unreadable)

        shutil.rmtree(os.path.join(scratch, "contrib"))
        try:
            scan(scratch)
        except GateFailure as error:
            if "contrib/" not in str(error):
                return _fail(f"a missing root failed without its name: {error}")
        else:
            return _fail("a missing contrib/ passed")

    print(
        "check_wall_clock_waits: selftest passed "
        f"({len(TOKENS)} tokens, a non-UTF-8 file, an empty tree, a missing root)"
    )
    return 0


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    try:
        hits, read = scan(REPO)
    except GateFailure as error:
        print(error, file=sys.stderr)
        return 1
    return report(hits, read)


if __name__ == "__main__":
    sys.exit(main())
