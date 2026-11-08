#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Every regtest spawn that calls an armed test lever arms the dev-rpc row
# and checks this spawn's announcement of it.
#
# The subject is a source file that both launches a daemon with
# `--network regtest` and names `generateblocks` or `pop_blocks` as a
# call. An RPC client that only names the method is not a subject. A
# comment that names both is not a subject. The checker itself is not a
# subject: its selftest fixtures are the patterns it matches, so it is
# excluded from the walk, and the selftest shows a fixture of that shape
# is still caught when it is a real file.
#
# Arming is the daemon flag (`--dev-rpc`, or `armed_lever.FLAG` for a
# Python spawn) and a check of this spawn's log (`announced_since(`,
# `--check-log`, or the Rust const `ARMED_ROW_ANNOUNCEMENT`).
#
# The announcement sentence has three owners and no others:
# `scripts/armed_lever.py`, the const in `regtest_e2e.rs`, and the
# producer test `the_armed_lever_switch_announces_itself`. The three
# must be the same sentence.
#
# Rule 47: the known launchers are asserted present, and `--selftest`
# shows that an empty set and an unarmed spawn fail. Rule 46: the exit
# status is the verdict.

import os
import re
import sys

SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(SCRIPTS)
sys.path.insert(0, SCRIPTS)
import armed_lever  # noqa: E402

GATE_REL = "scripts/ci/check_armed_lever_launchers.py"

# The launchers that exist today. A rename that drops one of these makes
# the gate fail until the list moves with it, so a detector that matches
# nothing cannot pass.
REQUIRED = (
    "rust/shekyl-engine-core/src/engine/regtest_e2e.rs",
    "scripts/bench/drs_bench.py",
    "scripts/bench/wss_q1b_regtest_open_edge.sh",
    "rust/shekyl-wire/tests/vectors/capture_coinbase.py",
    "rust/shekyl-curve-tree/tests/fixtures/gen_ct2_fixture.py",
)

OWNERS = (
    "scripts/armed_lever.py",
    "rust/shekyl-engine-core/src/engine/regtest_e2e.rs",
    "rust/shekyl-daemon-config/src/announce.rs",
)

SKIP_DIRS = {
    ".git",
    "target",
    "build",
    "external",
    "node_modules",
    "shekyl-oxide",
}

SOURCE_SUFFIXES = {".py", ".rs", ".sh"}
COPY_SUFFIXES = SOURCE_SUFFIXES | {".md", ".toml", ".yml", ".yaml", ".cpp", ".h"}

# Adjacent argv tokens, the shape a spawn actually passes. A `--network`
# and a `regtest` far apart are not a regtest launch.
SPAWN = re.compile(
    r"""["']--network["']\s*,\s*["']regtest["']|--network[ \t]+regtest"""
)
# The shell harness passes the method inside a double-quoted JSON string,
# so the source spells the closing quote as a backslash and a quote.
LEVER = re.compile(
    r"""["']generateblocks["']|["']generateblocks\\["']|["']/pop_blocks["']|["']pop_blocks["']"""
)

ASSIGNMENT = re.compile(r'^ANNOUNCEMENT = "([^"]*)"', re.M)
RUST_CONST = re.compile(r'const ARMED_ROW_ANNOUNCEMENT: &str = "([^"]*)";')
PRODUCER_FN = "fn the_armed_lever_switch_announces_itself"


def strip_hash_comments(text):
    """Drop `#` comments, leaving quoted text in place."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c in ('"', "'"):
            if text.startswith(c * 3, i):
                end = text.find(c * 3, i + 3)
                j = n if end < 0 else end + 3
            else:
                j = i + 1
                while j < n:
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == c or text[j] == "\n":
                        if text[j] == c:
                            j += 1
                        break
                    j += 1
            out.append(text[i:j])
            i = j
            continue
        if c == "#":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _raw_string(text, i):
    """End index of a Rust raw string starting at `r`, or None."""
    if text[i] != "r":
        return None
    j = i + 1
    hashes = 0
    while j < len(text) and text[j] == "#":
        hashes += 1
        j += 1
    if j >= len(text) or text[j] != '"':
        return None
    j += 1
    closer = '"' + ("#" * hashes)
    end = text.find(closer, j)
    return len(text) if end < 0 else end + len(closer)


def _cooked_string(text, i):
    j = i + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return len(text)


def strip_rust(text):
    """Drop `//` and `/* */` comments, leaving string literals in place."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if c == "r":
            raw = _raw_string(text, i)
            if raw is not None:
                out.append(text[i:raw])
                i = raw
                continue
        if c == '"':
            j = _cooked_string(text, i)
            out.append(text[i:j])
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_comments(text, suffix):
    if suffix == ".rs":
        return strip_rust(text)
    if suffix in {".py", ".sh"}:
        return strip_hash_comments(text)
    return text


def code(text, suffix):
    return strip_comments(text, suffix)


def is_launcher(text, suffix):
    stripped = code(text, suffix)
    return SPAWN.search(stripped) is not None and LEVER.search(stripped) is not None


def is_armed(text, suffix):
    """The flag is on the spawn, and this spawn's log is checked."""
    stripped = code(text, suffix)
    flag = "--dev-rpc" in stripped or "armed_lever.FLAG" in stripped
    checked = (
        "announced_since(" in stripped
        or "--check-log" in stripped
        or "ARMED_ROW_ANNOUNCEMENT" in stripped
    )
    return flag and checked


def iter_files(root, suffixes):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            suffix = os.path.splitext(name)[1]
            if suffix not in suffixes:
                continue
            yield os.path.join(dirpath, name)


def rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def find_launchers(root):
    found = {}
    for path in iter_files(root, SOURCE_SUFFIXES):
        relative = rel(root, path)
        if relative == GATE_REL:
            continue
        text = read(path)
        suffix = os.path.splitext(path)[1]
        if is_launcher(text, suffix):
            found[relative] = (text, suffix)
    return found


def launcher_problems(found, required):
    """Failures of the launcher subject. Empty is clean."""
    problems = []
    if not found:
        problems.append("no regtest lever launcher found")
    for path in required:
        if path not in found:
            problems.append(f"subject absent: {path} is not a regtest lever launcher")
    for path in sorted(found):
        text, suffix = found[path]
        if not is_armed(text, suffix):
            problems.append(
                f"{path}: spawns regtest and names a lever without arming "
                "dev-rpc and checking this spawn's announcement"
            )
    return problems


def producer_sentence(text):
    start = text.find(PRODUCER_FN)
    if start < 0:
        return None
    window = text[start:start + 600]
    match = re.search(r'vec!\["([^"]+)"\.to_owned\(\)\]', window)
    return match.group(1) if match else None


def sentences(root):
    """The three owned copies, or None where the owner no longer states one."""
    module = read(os.path.join(root, OWNERS[0]))
    rust = read(os.path.join(root, OWNERS[1]))
    producer = read(os.path.join(root, OWNERS[2]))
    assigned = ASSIGNMENT.search(module)
    const = RUST_CONST.search(rust)
    return (
        assigned.group(1) if assigned else None,
        const.group(1) if const else None,
        producer_sentence(producer),
    )


def copy_hits(root, needle):
    hits = []
    for path in iter_files(root, COPY_SUFFIXES):
        relative = rel(root, path)
        if relative == GATE_REL:
            continue
        if needle in read(path):
            hits.append(relative)
    return hits


def parity_problems(module, const, producer, hits, needle):
    problems = []
    named = (
        ("scripts/armed_lever.py ANNOUNCEMENT", module),
        ("regtest_e2e.rs ARMED_ROW_ANNOUNCEMENT", const),
        ("the_armed_lever_switch_announces_itself", producer),
    )
    for label, value in named:
        if value is None:
            problems.append(f"subject absent: {label} does not state the announcement")
    present = [value for _, value in named if value is not None]
    if len(set(present)) > 1:
        problems.append(
            "the announcement copies differ: "
            + ", ".join(f"{label}={value!r}" for label, value in named)
        )
    if needle is not None:
        extra = [path for path in hits if path not in OWNERS]
        if extra:
            problems.append(
                "the announcement sentence has a copy outside its three owners: "
                + ", ".join(sorted(extra))
            )
        for owner in OWNERS:
            if owner not in hits:
                problems.append(f"subject absent: {owner} does not contain the announcement")
    return problems


def report(problems):
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


def selftest():
    failures = []

    def check(name, cond):
        if cond:
            print(f"PASS: {name}")
        else:
            print(f"FAIL: {name}", file=sys.stderr)
            failures.append(name)

    armed_py = (
        'cmd = ["shekyld", "--network", "regtest", armed_lever.FLAG]\n'
        'rpc("generateblocks", {})\n'
        "armed_lever.announced_since(path, 0)\n"
    )
    check("an armed python spawn is a launcher", is_launcher(armed_py, ".py"))
    check("and it counts as armed", is_armed(armed_py, ".py"))

    bare = (
        'cmd = ["shekyld", "--network", "regtest"]\n'
        'rpc("generateblocks", {})\n'
    )
    check("an unarmed python spawn is still a launcher", is_launcher(bare, ".py"))
    check("and it is not armed", not is_armed(bare, ".py"))

    no_lever = 'cmd = ["shekyld", "--network", "regtest", "--dev-rpc"]\n'
    check("a regtest spawn that names no lever is not a subject", not is_launcher(no_lever, ".py"))

    client = 'def generateblocks(self):\n    return send("generateblocks")\n'
    check("an RPC client is not a launcher", not is_launcher(client, ".py"))

    comment = '# shekyld --network regtest\n# method "generateblocks"\n'
    check("a python comment is not a launcher", not is_launcher(comment, ".py"))

    shell = (
        '"$BIN" --network regtest --dev-rpc\n'
        "python3 scripts/armed_lever.py --check-log \"$DATA/daemon.out\"\n"
        "-d '{\"method\":\"generateblocks\"}'\n"
    )
    check("an armed shell spawn is a launcher", is_launcher(shell, ".sh") and is_armed(shell, ".sh"))

    shell_escaped = (
        '"$BIN" --network regtest --dev-rpc \\\n'
        '  -d "{\\"method\\":\\"generateblocks\\"}"\n'
        'python3 scripts/armed_lever.py --check-log "$DATA/daemon.out"\n'
    )
    check(
        "a shell JSON string with escaped quotes is a launcher",
        is_launcher(shell_escaped, ".sh") and is_armed(shell_escaped, ".sh"),
    )

    shell_bare = '"$BIN" --network regtest\n-d \'{"method":"generateblocks"}\'\n'
    check(
        "an unarmed shell spawn is not armed",
        is_launcher(shell_bare, ".sh") and not is_armed(shell_bare, ".sh"),
    )

    rust_comment = (
        '/// spawns `shekyld --network regtest` and calls "generateblocks"\n'
        "fn parse() {}\n"
    )
    check("a rust comment is not a launcher", not is_launcher(rust_comment, ".rs"))

    rust_after_comment = (
        '// "--network", "regtest" and "generateblocks" in a comment\n'
        'cmd.args(["--network", "regtest", "--dev-rpc"]);\n'
        'call("generateblocks");\n'
        "log.contains(ARMED_ROW_ANNOUNCEMENT);\n"
    )
    check(
        "rust code after a comment is still a launcher",
        is_launcher(rust_after_comment, ".rs") and is_armed(rust_after_comment, ".rs"),
    )

    pop = (
        'cmd = ["--network", "regtest", armed_lever.FLAG]\n'
        'other_rpc("pop_blocks", {})\n'
        "armed_lever.announced_since(path, 0)\n"
    )
    check("a pop_blocks spawn is a launcher", is_launcher(pop, ".py") and is_armed(pop, ".py"))

    found_ok = {"a.py": (armed_py, ".py")}
    check(
        "the required launcher present and armed passes",
        launcher_problems(found_ok, ("a.py",)) == [],
    )
    check(
        "a missing required launcher fails",
        any("subject absent" in p for p in launcher_problems(found_ok, ("a.py", "missing.py"))),
    )
    check(
        "an empty set fails",
        any("no regtest lever launcher" in p for p in launcher_problems({}, ("a.py",))),
    )
    check(
        "an unarmed found launcher fails",
        any("without arming" in p for p in launcher_problems({"a.py": (bare, ".py")}, ("a.py",))),
    )

    line = armed_lever.ANNOUNCEMENT
    drifted = line.replace("true", "false")
    check(
        "three equal copies pass",
        parity_problems(line, line, line, list(OWNERS), line) == [],
    )
    check(
        "a drifted copy fails",
        parity_problems(line, drifted, line, list(OWNERS), line) != [],
    )
    check(
        "a fourth copy fails",
        any(
            "outside its three owners" in p
            for p in parity_problems(line, line, line, list(OWNERS) + ["other.rs"], line)
        ),
    )
    check(
        "a missing owner fails",
        any("subject absent" in p for p in parity_problems(None, line, line, list(OWNERS), line)),
    )

    if failures:
        print(f"{len(failures)} selftest failure(s)", file=sys.stderr)
        return 1
    print(f"selftest passed ({line!r})")
    return 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(f"usage: {os.path.basename(__file__)} [--selftest]", file=sys.stderr)
        return 2
    found = find_launchers(ROOT)
    problems = launcher_problems(found, REQUIRED)
    module, const, producer = sentences(ROOT)
    needle = module or const or producer
    hits = copy_hits(ROOT, needle) if needle else []
    problems.extend(parity_problems(module, const, producer, hits, needle))
    if problems:
        return report(problems)
    print(f"armed-lever launchers: {len(found)}")
    for path in sorted(found):
        print(f"  {path}")
    print("announcement copies agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
