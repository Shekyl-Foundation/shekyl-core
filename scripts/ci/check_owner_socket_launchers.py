#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Every regtest spawn of `shekyld` names a private directory for the
# daemon's owner socket.
#
# A daemon run as its user serves that user on a socket in a directory only
# that account can reach (RPC_CHANNEL.md §7.1). A CI runner has no session
# directory, so such a daemon refuses to start there unless it is named one
# (`rpc-socket-dir`, INPUT_GRAMMAR.md IG-Q104); and every regtest daemon of
# one account is the same network's default instance, so two of them in the
# session directory are one too many and the second refuses. A harness
# therefore names a private directory for each daemon it starts (Rick,
# 2026-11-12: "The harnesses create the directory and pass it").
#
# The subject is a source file that launches a regtest daemon: adjacent
# `--network regtest` argv tokens and the binary's name, outside comments,
# the shapes `check_armed_lever_launchers.py` reads. Naming the directory is
# the flag (`--rpc-socket-dir`) or the Python helper (`owner_socket.argv(`).
# A file that builds a daemon's argv without starting a process is listed in
# NOT_A_SPAWN with the reason.
#
# Rule 47: the known launchers are asserted present, and `--selftest` shows
# that an empty set and a spawn without the directory fail. Rule 46: the
# exit status is the verdict.

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)
ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, HERE)
sys.path.insert(0, SCRIPTS)
import check_armed_lever_launchers as L  # noqa: E402

GATE_REL = "scripts/ci/check_owner_socket_launchers.py"

# The launchers that exist today. A rename that drops one makes the gate
# fail until the list moves with it, so a detector that matches nothing
# cannot pass.
REQUIRED = (
    "rust/shekyl-engine-core/src/engine/regtest_e2e.rs",
    "rust/shekyl-cli/src/tx_show_regtest.rs",
    "rust/shekyl-levin/tests/dual_stack.rs",
    "rust/shekyl-levin/tests/socks_credentials.rs",
    "rust/shekyl-levin/tests/live_daemon/mod.rs",
    "rust/shekyl-daemon/tests/owner_socket.rs",
    "rust/shekyl-daemon/tests/interrupt_inherited_ignore.rs",
    "rust/shekyl-wire/tests/vectors/capture_coinbase.py",
    "rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py",
    "scripts/bench/drs_bench.py",
    "scripts/bench/capture_kept_chain.py",
    "scripts/bench/wss_q1b_regtest_open_edge.sh",
)

# Files that match the shape and start no daemon process.
NOT_A_SPAWN = {
    "scripts/ci/check_armed_lever_launchers.py": "a gate; its fixtures are the patterns it matches",
    "scripts/bench/test_drs_bench.py": "tests drs_bench's argv and artifact logic; spawns nothing",
    "rust/shekyl-daemon/src/run.rs": "runs the daemon in-process with a test platform whose session directory is private",
    "rust/shekyl-daemon/src/verify.rs": "runs the walk in-process with a test platform whose session directory is private",
    "rust/shekyl-daemon-config/src/announce.rs": "builds a configuration in-process; starts nothing",
    "rust/shekyl-daemon-config/src/owner_socket.rs": "the plan's own tests; start nothing",
    "rust/shekyl-daemon-config/src/sections/tests.rs": "builds configurations in-process; starts nothing",
}

NAMED = ("--rpc-socket-dir", "owner_socket.argv(")


def is_launcher(text, suffix):
    stripped = L.code(text, suffix)
    return L.SPAWN.search(stripped) is not None and "shekyld" in stripped


def names_the_directory(text, suffix):
    stripped = L.code(text, suffix)
    return any(token in stripped for token in NAMED)


def find_launchers(root):
    found = {}
    for path in L.iter_files(root, L.SOURCE_SUFFIXES):
        relative = L.rel(root, path)
        if relative == GATE_REL or relative in NOT_A_SPAWN:
            continue
        text = L.read(path)
        suffix = os.path.splitext(path)[1]
        if is_launcher(text, suffix):
            found[relative] = (text, suffix)
    return found


def problems_of(found, required):
    problems = []
    if not found:
        problems.append("no regtest shekyld launcher found")
    for path in required:
        if path not in found:
            problems.append(f"subject absent: {path} is not a regtest shekyld launcher")
    for path in sorted(found):
        text, suffix = found[path]
        if not names_the_directory(text, suffix):
            problems.append(
                f"{path}: starts a regtest shekyld without naming a private "
                "directory for its owner socket (--rpc-socket-dir, or "
                "owner_socket.argv(...))"
            )
    return problems


def selftest():
    failures = 0
    cases = [
        (
            "a spawn that names the directory passes",
            {"a.py": '["shekyld", "--network", "regtest"] + owner_socket.argv("a")'},
            ("a.py",),
            [],
        ),
        (
            "a spawn without the directory is named",
            {"a.sh": 'BIN=shekyld\n"$BIN" --network regtest --data-dir x\n'},
            ("a.sh",),
            ["a.sh: starts a regtest shekyld without naming"],
        ),
        (
            "a flag only in a comment does not count",
            {"a.rs": 'let b = "shekyld"; cmd.args(["--network", "regtest"]); // --rpc-socket-dir'},
            ("a.rs",),
            ["a.rs: starts a regtest shekyld without naming"],
        ),
        (
            "an empty subject is refused",
            {},
            (),
            ["no regtest shekyld launcher found"],
        ),
        (
            "a required launcher that went away is named",
            {"a.py": '["shekyld", "--network", "regtest", "--rpc-socket-dir", d]'},
            ("a.py", "gone.py"),
            ["subject absent: gone.py"],
        ),
    ]
    for title, files, required, expect in cases:
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                    fh.write(text)
            problems = problems_of(find_launchers(tmp), required)
        ok = (not problems) if not expect else len(problems) == len(expect) and all(
            any(e in p for p in problems) for e in expect
        )
        print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {problems}"))
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    found = find_launchers(ROOT)
    problems = problems_of(found, REQUIRED)
    for path in NOT_A_SPAWN:
        if not os.path.exists(os.path.join(ROOT, path)):
            problems.append(f"subject absent: {path} is listed as not a spawn and does not exist")
    if problems:
        L.report(problems)
        return 1
    print(f"owner socket: {len(found)} regtest shekyld launcher(s) name a private directory")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
