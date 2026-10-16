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
# alias ending in `Command`) must be listed below. A command built some other
# way (`Command::from`, or one passed in already built) is not seen here; the
# file that calls `Command::new` for it is. A LOCKED file must call `spawn_lock::`. An
# EXEMPT file carries its reason: the crate it is in cannot reach
# shekyl-tor-control-client (checked when the entry was written with
# `cargo tree -p <crate> -e normal,dev,build`), or the file runs in a process of
# its own (a build script). A listed file with no spawn left fails too, so the
# list does not outlive its subjects. An exemption for a crate that cannot reach
# the client fails when that crate's manifest gains a direct
# `shekyl-tor-control*` edge; a new transitive edge is not seen, so a dependency
# change re-opens the classification for whoever makes it.
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
        if SPAWN.search(path.read_text(encoding="utf-8", errors="replace")):
            found.add(rel.as_posix())
    return found


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
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
            if LOCK not in text:
                errors.append(f"{rel}: listed as taking the spawn lock, but calls no {LOCK}")
        elif rel not in exempt:
            errors.append(
                f"{rel}: builds a process command and is not classified; take the spawn "
                f"lock ({LOCK}spawn/output/status/hold) and list it as LOCKED, or list it "
                f"as EXEMPT with the reason"
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
    locked_text = "let c = Command::new(x); spawn_lock::spawn(&mut c);"
    cases = {
        "clean": ({launch: locked_text, "b/x.rs": "ProcCommand::new(y)"}, {launch}, {"b/x.rs": "r"}, 0),
        "unclassified spawn": ({launch: locked_text, "b/x.rs": "Command::new(y)"}, {launch}, {}, 1),
        "locked without the lock": ({launch: "Command::new(x)"}, {launch}, {}, 1),
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
