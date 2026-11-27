#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Every regtest spawn of `shekyld` chooses its configuration file, so no test
# or bench daemon reads the host it runs on.
#
# On Linux, FreeBSD and macOS the daemon's default configuration file is the
# machine's, `/etc/shekyl/shekyld-<network>.toml` (INPUT_GRAMMAR.md §5,
# `config-file`), whatever account or platform roots a harness gives it. A
# host that runs a regtest node of its own keeps that node's settings there,
# and a harness daemon that reads them takes that node's peers, listeners and
# levers as its own, or refuses to start when its account cannot read the
# file (`config.file.unreadable`, the tunnel's end_to_end on a fleet host).
# CI's runners have no /etc/shekyl, so no test there shows it; this gate
# does. A spawned binary therefore names its file
# (`--config-file <path>`, or `--config-file none` for the defaults alone),
# and a daemon run in-process loads with
# `shekyl_daemon_config::load_default_file_unread` (or builds its
# configuration with `after_file`, which opens no file).
#
# The subject is what `check_owner_socket_launchers.py`'s finder matches:
# adjacent `--network regtest` argv tokens and the binary's name, outside
# comments. Its REQUIRED launchers are this gate's too, with the in-process
# starts that gate leaves out; this gate's own NOT_A_SPAWN names the files
# that match and have no file step at all.
#
# What it does not see: it judges a file, not a spawn, so a file with one
# launcher that chooses its file and another that does not passes; and it
# reads regtest launches only, so a testnet daemon a test starts
# (`shekyl-cli`'s json_script) is outside it.
#
# Rule 47: the known launchers are asserted present, and `--selftest` shows
# that an empty set and a spawn that names no file fail. Rule 46: the exit
# status is the verdict.

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, HERE)
sys.path.insert(0, SCRIPTS)
import check_armed_lever_launchers as L  # noqa: E402
import check_owner_socket_launchers as S  # noqa: E402

# The owner-socket gate's launchers, and the in-process starts it leaves
# out because they serve no socket: they must choose their file too.
REQUIRED = S.REQUIRED + (
    "rust/shekyl-daemon/src/run_tests.rs",
    "rust/shekyl-daemon/src/verify.rs",
    "rust/shekyl-daemon/tests/config_file.rs",
)

# Files that match the shape and have no file step: no daemon starts, and no
# loader runs that could open the default file.
NOT_A_SPAWN = {
    "scripts/ci/check_armed_lever_launchers.py": "a gate; its fixtures are the patterns it matches",
    "scripts/ci/check_launcher_config_file.py": "this gate; its fixtures are the patterns it matches",
    "scripts/bench/test_drs_bench.py": "tests drs_bench's argv and artifact logic; spawns nothing",
    "rust/shekyl-daemon-config/src/announce.rs": "builds a configuration from parsed rows; no file step",
    "rust/shekyl-daemon-config/src/owner_socket.rs": "the socket plan's own tests; no file step",
    "rust/shekyl-daemon-config/src/sections/tests.rs": "builds configurations from parsed rows; no file step",
}

# A spawned binary names its file; an in-process daemon loads with the
# default file unread, or builds its configuration after the file step.
CHOSEN = ("--config-file", "load_default_file_unread", "after_file(")


def chooses_the_file(text, suffix):
    stripped = L.code(text, suffix)
    return any(token in stripped for token in CHOSEN)


def problems_of(found, required):
    problems = []
    if not found:
        problems.append("no regtest shekyld launcher found")
    for path in required:
        if path not in found:
            problems.append(f"subject absent: {path} is not a regtest shekyld launcher")
    for path in sorted(found):
        text, suffix = found[path]
        if not chooses_the_file(text, suffix):
            problems.append(
                f"{path}: starts a regtest shekyld that reads the machine's "
                "default configuration file (pass --config-file <path> or "
                "--config-file none; in process, load_default_file_unread)"
            )
    return problems


def selftest():
    failures = 0
    cases = [
        (
            "a spawn that names no file is refused",
            {"a.py": '["shekyld", "--network", "regtest"] + owner_socket.argv("a")'},
            ("a.py",),
            ["a.py: starts a regtest shekyld that reads"],
        ),
        (
            "a spawn that passes none passes",
            {"a.sh": 'BIN=shekyld\n"$BIN" --network regtest --config-file none\n'},
            ("a.sh",),
            [],
        ),
        (
            "a spawn that names a file passes",
            {"a.py": '["shekyld", "--network", "regtest", "--config-file", path]'},
            ("a.py",),
            [],
        ),
        (
            "an in-process daemon that leaves the default file unread passes",
            {
                "a.rs": 'let a = ["shekyld", "--network", "regtest"];\n'
                "run::main_loading(&a, &p, shekyl_daemon_config::load_default_file_unread);\n"
            },
            ("a.rs",),
            [],
        ),
        (
            "an in-process daemon through the production entry is refused",
            {"a.rs": 'let a = ["shekyld", "--network", "regtest"];\nrun::main(&a, &p);\n'},
            ("a.rs",),
            ["a.rs: starts a regtest shekyld that reads"],
        ),
        (
            "a flag only in a comment does not count",
            {"a.rs": 'let b = "shekyld"; cmd.args(["--network", "regtest"]); // --config-file none'},
            ("a.rs",),
            ["a.rs: starts a regtest shekyld that reads"],
        ),
        (
            "an empty subject is refused",
            {},
            (),
            ["no regtest shekyld launcher found"],
        ),
        (
            "a required launcher that went away is named",
            {"a.py": '["shekyld", "--network", "regtest", "--config-file", "none"]'},
            ("a.py", "gone.py"),
            ["subject absent: gone.py"],
        ),
    ]
    for title, files, required, expect in cases:
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            problems = problems_of(S.find_launchers(tmp, NOT_A_SPAWN), required)
        ok = (not problems) if not expect else len(problems) == len(expect) and all(
            any(e in p for p in problems) for e in expect
        )
        print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {problems}"))
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    found = S.find_launchers(ROOT, NOT_A_SPAWN)
    problems = problems_of(found, REQUIRED)
    for path in NOT_A_SPAWN:
        if not os.path.exists(os.path.join(ROOT, path)):
            problems.append(f"subject absent: {path} is listed as not a spawn and does not exist")
    if problems:
        L.report(problems)
        return 1
    print(f"config file: {len(found)} regtest shekyld launcher(s) choose their configuration file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
