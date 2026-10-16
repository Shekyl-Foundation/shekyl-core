#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Every Rust file that builds a process command is classified: it takes the
# process-wide spawn lock, or it is exempt for a stated reason
# (docs/design/TOR_SUPERVISOR.md section 4.7; the lock is
# rust/shekyl-tor-control-client/src/spawn_lock.rs).
#
# WHY. On Windows the managed tor inherits its control socket: the launch marks
# tor's end inheritable, spawns, and clears the mark, under the spawn lock.
# CreateProcess hands every inheritable handle to whatever child starts, so any
# other spawn in the same process inside that window inherits tor's end, and a
# leaked copy hides tor's death for as long as that child lives (TSR-F16). The
# design rule is that every Rust spawn in a process that can launch a managed
# tor takes the same lock. A spawn added later does not know the rule; this
# gate makes it be classified before it lands.
#
# THE RULE. A file in rust/ (outside target/ and the vendored shekyl-oxide/)
# that builds a process command with `Command::new(` (std or tokio, under any
# alias ending in `Command`) must be listed below, and each listing is checked
# on the file's code with comments and string literals blanked out, so prose
# never satisfies it (rule 47).
#
#   LOCKED: every process start in the file is inside a `spawn_lock::` call. A
#   process start is `.spawn()`, `.output()` or `.status()` called on a command:
#   one chained on `Command::new(...)` in the same statement, or one named by a
#   binding or parameter that holds a command (`let cmd = Command::new(..)`,
#   `cmd: &mut Command`). Inside a `spawn_lock::` call means within its
#   parentheses: `spawn_lock::spawn(&mut cmd)`, or `spawn_lock::with(|| ..)`
#   around a spawn that must do more under the lock. So an unlocked spawn beside
#   a locked one fails, wherever it is in the file.
#   EXEMPT: carries its reason. The crate it is in cannot reach
#   shekyl-tor-control-client (checked when the entry was written with
#   `cargo tree -p <crate> -e normal,dev,build`), or the file runs in a process
#   of its own (a build script). An exemption for a crate that cannot reach the
#   client fails when that crate's manifest gains a direct `shekyl-tor-control*`
#   edge; a new transitive edge is not seen, so a dependency change re-opens the
#   classification for whoever makes it.
#
# A listed file with no `Command::new` left fails too, so the list does not
# outlive its subjects. Not seen: a command made by `Command::from`, or passed
# in by a name the file never binds from `Command::new` or types as `Command`.
#
# SUBJECT. The launch itself is LOCKED; if no file in the tree builds a command,
# this gate has nothing to check and fails.
#
# Usage:  check_spawn_sites_take_the_lock.py            # check the tree
#         check_spawn_sites_take_the_lock.py --selftest # bite each failure

import pathlib
import re
import sys
import tempfile

LOCKED = {
    "shekyl-tor-control-client/src/control/launch.rs",
    "shekyl-tor-control-client/src/control/actor.rs",
    "shekyl-tor-control-wallet/src/service.rs",
    "shekyl-tor-control-wallet/tests/circuit_isolation.rs",
    "shekyl-engine-core/src/engine/regtest_e2e.rs",
    "shekyl-cli/tests/json_script.rs",
    "shekyl-cli/tests/daemon_disclosure.rs",
    "shekyl-wss-q1b-bench/src/report.rs",
}

NO_TOR = "the crate cannot reach shekyl-tor-control-client"

EXEMPT = {
    "shekyl-crypto-pq/examples/fn_dsa_stack_ladder.rs": NO_TOR,
    "shekyl-levin/tests/dual_stack.rs": NO_TOR,
    "shekyl-levin/tests/inbound_cost_bench.rs": NO_TOR,
    "shekyl-logging/tests/c_ffi.rs": NO_TOR,
    "shekyl-p2p-harness/src/driver.rs": NO_TOR,
    "shekyl-pow-randomx/tests/crate_invariants.rs": NO_TOR,
    "shekyl-randomx-differential/tests/crate_invariants.rs": NO_TOR,
    "shekyl-shard-visual/examples/gen_goldens.rs": NO_TOR,
    "shekyl-shard-visual/tests/render_bin.rs": NO_TOR,
    "shekyl-timing-engine/src/service/tests.rs": NO_TOR,
    "shekyl-wss-q1b-bench/build.rs": "a build script runs in a process of its own",
}

# The launch: the gate's subject.
SUBJECT = "shekyl-tor-control-client/src/control/launch.rs"

SPAWN = re.compile(r"\b\w*Command::new\(")
LOCK = "spawn_lock::"
SKIPPED_DIRS = {"target", "shekyl-oxide"}


def spawn_files(root):
    found = set()
    for path in root.rglob("*.rs"):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in SKIPPED_DIRS:
            continue
        if SPAWN.search(code_of(path.read_text(encoding="utf-8", errors="replace"))):
            found.add(rel.as_posix())
    return found


def code_of(text):
    """`text` with comments and string, char and raw-string literals blanked to
    spaces, newlines kept, so offsets and line numbers still match."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and re.match(r'r(#*)"', text[i:]) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = re.match(r'r(#*)"', text[i:]).group(1)
            close = '"' + hashes
            j = text.find(close, i + 2 + len(hashes))
            j = n if j < 0 else j + len(close)
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, min(j + 1, n))
            i = j + 1
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", text[i:]):
            j = i + len(re.match(r"'(\\.|[^\\'])'", text[i:]).group(0))
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)


START = re.compile(r"\.\s*(spawn|output|status)\s*\(\s*\)")
BINDING = re.compile(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::[^=;]*)?=\s*[^;]*?\b\w*Command::new\(")
TYPED = re.compile(r"\b(\w+)\s*:\s*&?\s*(?:mut\s+)?(?:[\w:]+::)?\w*Command\b")
LOCK_CALL = re.compile(r"\bspawn_lock::\w+\s*\(")


def matching_paren(code, open_at):
    depth = 0
    for k in range(open_at, len(code)):
        if code[k] == "(":
            depth += 1
        elif code[k] == ")":
            depth -= 1
            if depth == 0:
                return k
    return len(code)


def statement_end(code, at):
    depth = 0
    for k in range(at, len(code)):
        ch = code[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return k
            depth -= 1
        elif ch == ";" and depth == 0:
            return k
    return len(code)


def unlocked_starts(code):
    """Line numbers of process starts outside every `spawn_lock::` call."""
    spans = []
    for m in LOCK_CALL.finditer(code):
        open_at = m.end() - 1
        spans.append((open_at, matching_paren(code, open_at)))
    names = {m.group(1) for m in BINDING.finditer(code)} | {m.group(1) for m in TYPED.finditer(code)}
    starts = set()
    for name in names:
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*" + START.pattern, code):
            starts.add(m.start())
    for m in SPAWN.finditer(code):
        end = statement_end(code, m.start())
        for s in START.finditer(code, m.end(), end):
            starts.add(s.start())
    return sorted(
        code.count("\n", 0, at) + 1
        for at in starts
        if not any(a <= at <= b for a, b in spans)
    )


TOR_EDGE = re.compile(r"^\s*shekyl-tor-control[\w-]*\s*=", re.MULTILINE)


def check(root, locked, exempt, subject):
    errors = []
    found = spawn_files(root)
    for rel, reason in sorted(exempt.items()):
        if reason != NO_TOR:
            continue
        manifest = root / rel.split("/", 1)[0] / "Cargo.toml"
        if manifest.exists() and TOR_EDGE.search(manifest.read_text(encoding="utf-8")):
            errors.append(
                f"{rel}: exempt because its crate cannot reach shekyl-tor-control-client, "
                f"but {manifest.relative_to(root)} names a shekyl-tor-control crate"
            )
    if subject not in found:
        errors.append(f"{subject}: the launch builds no command; the gate has no subject")
    for rel in sorted(found):
        if rel in locked:
            code = code_of((root / rel).read_text(encoding="utf-8", errors="replace"))
            for line in unlocked_starts(code):
                errors.append(f"{rel}:{line}: a process starts outside the spawn lock")
        elif rel not in exempt:
            errors.append(
                f"{rel}: builds a process command and is not classified; start it inside "
                f"a {LOCK}spawn/output/status/with call and list it as LOCKED, or list "
                f"it as EXEMPT with the reason"
            )
    for rel in sorted((locked | set(exempt)) - found):
        errors.append(f"{rel}: listed, but builds no process command; remove the entry")
    return errors


def selftest():
    def tree(files):
        root = pathlib.Path(tempfile.mkdtemp(prefix="spawn-lock-gate-"))
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    launch = "a/src/launch.rs"
    locked_text = "let mut c = Command::new(x); spawn_lock::spawn(&mut c);"
    cases = {
        "clean": ({launch: locked_text, "b/x.rs": "ProcCommand::new(y)"}, {launch}, {"b/x.rs": "r"}, 0),
        "unclassified spawn": ({launch: locked_text, "b/x.rs": "Command::new(y)"}, {launch}, {}, 1),
        "a locked file that starts a process raw": (
            {launch: "let c = Command::new(x);\nc.spawn();"}, {launch}, {}, 1,
        ),
        "an unlocked start beside a locked one": (
            {launch: locked_text + "\nlet b = Command::new(y);\nb.output();"}, {launch}, {}, 1,
        ),
        "a lock named only in a comment": (
            {launch: "let c = Command::new(x);\nc.spawn(); // spawn_lock::spawn(&mut c)"},
            {launch}, {}, 1,
        ),
        "a lock named only in a string": (
            {launch: 'let c = Command::new(x);\nlet s = "spawn_lock::spawn(c)";\nc.spawn();'},
            {launch}, {}, 1,
        ),
        "a chained start": ({launch: locked_text + "\nCommand::new(y).arg(z).status();"}, {launch}, {}, 1),
        "a typed parameter started raw": (
            {launch: locked_text + "\nfn f(cmd: &mut Command) { cmd.spawn(); }"}, {launch}, {}, 1,
        ),
        "a closure under the lock": (
            {launch: locked_text + "\nfn f(cmd: &mut Command) { spawn_lock::with(|| cmd.spawn()); }"},
            {launch}, {}, 0,
        ),
        "a status() that is not a process start": (
            {launch: locked_text + "\nassert_eq!(reply.status(), 250);"}, {launch}, {}, 0,
        ),
        "stale entry": ({launch: locked_text}, {launch}, {"gone.rs": "r"}, 1),
        "no subject": ({"b/x.rs": "Command::new(y)"}, {launch}, {"b/x.rs": "r"}, 2),
        "an exempt crate that gained a tor edge": (
            {
                launch: locked_text,
                "b/x.rs": "Command::new(y)",
                "b/Cargo.toml": 'shekyl-tor-control-client = { path = "../c" }\n',
            },
            {launch},
            {"b/x.rs": NO_TOR},
            1,
        ),
        "vendored and target skipped": (
            {launch: locked_text, "shekyl-oxide/v.rs": "Command::new(z)", "target/t.rs": "Command::new(z)"},
            {launch},
            {},
            0,
        ),
    }
    failed = False
    for name, (files, locked, exempt, want) in cases.items():
        got = len(check(tree(files), locked, exempt, launch))
        if got != want:
            print(f"selftest FAIL: {name}: {got} errors, wanted {want}")
            failed = True
    if failed:
        return 1
    print(f"selftest: {len(cases)} cases bite as expected")
    return 0


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    root = pathlib.Path(__file__).resolve().parents[2] / "rust"
    errors = check(root, LOCKED, EXEMPT, SUBJECT)
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"spawn sites: {len(LOCKED)} take the lock, {len(EXEMPT)} exempt with a reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
