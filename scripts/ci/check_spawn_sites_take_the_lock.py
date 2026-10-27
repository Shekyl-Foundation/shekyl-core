#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Rust process spawns in a crate whose image can launch a managed tor take
# the spawn lock (docs/design/TOR_SUPERVISOR.md section 4.7; the lock is
# rust/shekyl-tor-control-client/src/spawn_lock.rs).
#
# WHY. On Windows the managed tor inherits its control socket. The launch
# marks the parent's copy inheritable, spawns, and closes that copy, under
# the spawn lock. CreateProcess hands every inheritable handle to whatever
# child starts, so any other spawn in the same process inside that window
# inherits tor's end, and a leaked copy hides tor's death for as long as
# that child lives (TSR-F16). The socket exists only in a process that
# calls the launch. A process that does not — a test that spawns the CLI
# binary, a bench that asks git for a revision — has nothing to leak, and
# taking the lock there is feature logic in the wrong binary.
#
# THE RULE. WATCHED is the set of crates whose image can call the managed
# launch. In each of them, a file that builds a process command with
# `Command::new(` (std or tokio, under any alias ending in `Command`) must
# start every such process inside a `spawn_lock::` call. The check reads
# the file with comments and string literals blanked, so prose never
# satisfies it (rule 47).
#
#   A process start is `.spawn()`, `.output()` or `.status()` called on a
#   command: one chained on `Command::new(...)` in the same statement, or
#   one named by a binding or parameter that holds a command (`let cmd =
#   Command::new(..)`, `cmd: &mut Command`). Inside a `spawn_lock::` call
#   means within its parentheses. An unlocked spawn beside a locked one
#   fails. A `build.rs` at the crate root is exempt: it runs in a process
#   of its own, and the launch is not linked into it.
#
#   A crate outside WATCHED is not this gate's subject. Linking
#   shekyl-tor-control-client is not enough: the gate watches the image
#   that launches, not every crate that can name the client.
#
# A file the check does not see: a command made by `Command::from`, or
# passed in by a name the file never binds from `Command::new` or types as
# `Command`.
#
# SUBJECT. The launch itself builds a command. If it does not, this gate
# has nothing to check and fails. A watched crate with no spawn today
# (the daemon, the spikes) still fails closed the day one appears.
#
# Usage:  check_spawn_sites_take_the_lock.py            # check the tree
#         check_spawn_sites_take_the_lock.py --selftest # bite each failure

import atexit
import pathlib
import re
import shutil
import sys
import tempfile

# Crates whose process image can launch a managed tor. Integration tests of
# shekyl-cli spawn that binary as a child; the bench's `git` never calls the
# launch. Neither shares an address space with tor's socket.
WATCHED = {
    "shekyl-tor-control-client",
    "shekyl-tor-control-wallet",
    "shekyl-tor-control-daemon",
    # The daemon image: the Rust `main()` starts the managed Tor
    # (shekyl-daemon) and the notify runner spawns operator commands in the
    # same process (shekyl-ffi notify_ffi.rs).
    "shekyl-daemon",
    "shekyl-ffi",
    "shekyl-engine-core",
    "shekyl-sp-t3-spike",
    "shekyl-tor-transit-spike",
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


def is_build_script(rel):
    """A crate-root `build.rs`. It is its own process; the launch is not in it."""
    parts = pathlib.PurePosixPath(rel).parts
    return len(parts) == 2 and parts[1] == "build.rs"


def check(root, watched, subject):
    errors = []
    found = spawn_files(root)
    for crate in sorted(watched):
        if not (root / crate).is_dir():
            errors.append(
                f"{crate}: watched because its image can launch a managed tor, "
                "but the crate is not in the tree"
            )
    if subject not in found:
        errors.append(f"{subject}: the launch builds no command; the gate has no subject")
    locked = []
    for rel in sorted(found):
        crate = rel.split("/", 1)[0]
        if crate not in watched or is_build_script(rel):
            continue
        locked.append(rel)
        code = code_of((root / rel).read_text(encoding="utf-8", errors="replace"))
        for line in unlocked_starts(code):
            errors.append(f"{rel}:{line}: a process starts outside the spawn lock")
    return errors, locked


def selftest():
    def tree(files):
        root = pathlib.Path(tempfile.mkdtemp(prefix="spawn-lock-gate-"))
        # Removed when the selftest exits, whatever a case found.
        atexit.register(shutil.rmtree, root, True)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    launch = "a/src/launch.rs"
    locked_text = "let mut c = Command::new(x); spawn_lock::spawn(&mut c);"
    watched = {"a"}
    cases = {
        "clean": ({launch: locked_text, "b/x.rs": "ProcCommand::new(y)"}, watched, launch, 0),
        "an unwatched crate spawns raw": (
            {launch: locked_text, "b/src/x.rs": "Command::new(y).spawn();"},
            watched,
            launch,
            0,
        ),
        "a watched crate spawns raw": (
            {launch: locked_text, "a/src/other.rs": "let c = Command::new(y);\nc.spawn();"},
            watched,
            launch,
            1,
        ),
        "a locked file that starts a process raw": (
            {launch: "let c = Command::new(x);\nc.spawn();"},
            watched,
            launch,
            1,
        ),
        "an unlocked start beside a locked one": (
            {launch: locked_text + "\nlet b = Command::new(y);\nb.output();"},
            watched,
            launch,
            1,
        ),
        "a lock named only in a comment": (
            {launch: "let c = Command::new(x);\nc.spawn(); // spawn_lock::spawn(&mut c)"},
            watched,
            launch,
            1,
        ),
        "a lock named only in a string": (
            {launch: 'let c = Command::new(x);\nlet s = "spawn_lock::spawn(c)";\nc.spawn();'},
            watched,
            launch,
            1,
        ),
        "a chained start": (
            {launch: locked_text + "\nCommand::new(y).arg(z).status();"},
            watched,
            launch,
            1,
        ),
        "a typed parameter started raw": (
            {launch: locked_text + "\nfn f(cmd: &mut Command) { cmd.spawn(); }"},
            watched,
            launch,
            1,
        ),
        "a closure under the lock": (
            {launch: locked_text + "\nfn f(cmd: &mut Command) { spawn_lock::with(|| cmd.spawn()); }"},
            watched,
            launch,
            0,
        ),
        "a status() that is not a process start": (
            {launch: locked_text + "\nassert_eq!(reply.status(), 250);"},
            watched,
            launch,
            0,
        ),
        "a build script in a watched crate": (
            {launch: locked_text, "a/build.rs": 'Command::new("git").output();'},
            watched,
            launch,
            0,
        ),
        "a source file named build.rs": (
            {launch: locked_text, "a/src/build.rs": 'Command::new("git").output();'},
            watched,
            launch,
            1,
        ),
        "a watched crate that is not in the tree": (
            {launch: locked_text},
            {"a", "missing-crate"},
            launch,
            1,
        ),
        "no subject": ({"a/src/lib.rs": "fn f() {}"}, watched, launch, 1),
        "vendored and target skipped": (
            {
                launch: locked_text,
                "shekyl-oxide/v.rs": "Command::new(z)",
                "target/t.rs": "Command::new(z)",
            },
            watched,
            launch,
            0,
        ),
    }
    failed = False
    for name, (files, watch, subject, want) in cases.items():
        got = len(check(tree(files), watch, subject)[0])
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
    errors, locked = check(root, WATCHED, SUBJECT)
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"spawn sites: {len(WATCHED)} crates watched, {len(locked)} files take the lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
