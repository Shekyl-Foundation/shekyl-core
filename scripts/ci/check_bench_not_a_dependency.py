#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The WSS-Q1(b) bench crate must never enter the production dependency graph.
#
# WHY A GATE AND NOT A COMMENT. `shekyl-wss-q1b-bench` is a measurement
# harness: it carries a synthetic corpus, a rig gate keyed on `/proc`, and a
# fixture that mints curve points with known secrets. None of that belongs in a
# shipped wallet or daemon. The crate's own documentation says so -- and a
# crate-doc sentence is not a check (rule 47: a gate must assert its own
# subject). The failure this closes is ordinary: someone wants the depth ladder
# or the leaf-rate derivation, adds a dependency, and the harness ships.
#
# WHY THE DIRECTION MATTERS. The bench depending on production crates is the
# POINT -- it measures the production prover and the production fetch path.
# Only the reverse edge is forbidden. So this gate reads every OTHER crate's
# manifest and asks whether it names the bench; it never inspects the bench's
# own dependency list.
#
# WHAT COUNTS AS A DEPENDENCY. All three tables: `[dependencies]`,
# `[dev-dependencies]` and `[build-dependencies]`. A dev-dependency is still a
# reverse edge -- it puts the harness in a production crate's test graph, where
# its fixtures become available to copy, and it is the form the mistake is most
# likely to take.
#
# EXEMPT: the bench crate itself, and the workspace manifest (which must list
# the bench as a MEMBER -- that is registration, not a dependency edge).

from __future__ import annotations

import re
import sys
from pathlib import Path

BENCH_CRATE = "shekyl-wss-q1b-bench"
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")

# `[dependencies]`, `[dev-dependencies]`, `[target.'cfg(...)'.dependencies]`.
TABLE_RE = re.compile(r"^\s*\[(?:target\.[^\]]+\.)?([a-z-]+)\]\s*$")
# `shekyl-wss-q1b-bench = ...` or `shekyl-wss-q1b-bench.workspace = true`.
DEP_RE = re.compile(rf"^\s*{re.escape(BENCH_CRATE)}\s*(?:\.[a-z-]+)?\s*=")


def offending_tables(manifest_text: str) -> list[str]:
    """Return the dependency tables in which the bench crate appears."""
    found: list[str] = []
    table: str | None = None
    for line in manifest_text.splitlines():
        match = TABLE_RE.match(line)
        if match:
            table = match.group(1)
            continue
        if table in DEPENDENCY_TABLES and DEP_RE.match(line):
            found.append(table)
    return found


def scan(rust_root: Path) -> list[tuple[str, str]]:
    """Every (crate, table) pair that depends on the bench crate."""
    violations: list[tuple[str, str]] = []
    for manifest in sorted(rust_root.glob("*/Cargo.toml")):
        crate = manifest.parent.name
        if crate == BENCH_CRATE:
            continue
        for table in offending_tables(manifest.read_text(encoding="utf-8")):
            violations.append((crate, table))
    return violations


def selftest() -> int:
    """Prove the gate can fail, and that it does not fail on the legitimate edges.

    A gate that has never been shown to fire is indistinguishable from one that
    cannot.
    """
    cases: list[tuple[str, str, list[str]]] = [
        (
            "a plain dependency is caught",
            f'[dependencies]\n{BENCH_CRATE} = {{ path = "../{BENCH_CRATE}" }}\n',
            ["dependencies"],
        ),
        (
            "a dev-dependency is caught -- it is still a reverse edge",
            f'[dev-dependencies]\n{BENCH_CRATE} = {{ path = "../{BENCH_CRATE}" }}\n',
            ["dev-dependencies"],
        ),
        (
            "a build-dependency is caught",
            f'[build-dependencies]\n{BENCH_CRATE} = "3"\n',
            ["build-dependencies"],
        ),
        (
            "a target-gated dependency is caught",
            f"[target.'cfg(unix)'.dependencies]\n{BENCH_CRATE}.workspace = true\n",
            ["dependencies"],
        ),
        (
            "the bench depending on a production crate is NOT a violation",
            '[dependencies]\nshekyl-fcmp = { path = "../shekyl-fcmp" }\n',
            [],
        ),
        (
            "a crate merely mentioning the name in a comment is not a violation",
            f"[dependencies]\n# see {BENCH_CRATE} for the depth ladder\n",
            [],
        ),
        (
            "a workspace member listing is not a dependency edge",
            f'[workspace]\nmembers = [\n    "{BENCH_CRATE}",\n]\n',
            [],
        ),
    ]
    failures = 0
    for name, text, expected in cases:
        got = offending_tables(text)
        if got != expected:
            print(f"  FAIL {name}: expected {expected}, got {got}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"bench-dependency selftest FAILED ({failures} cases)", file=sys.stderr)
        return 1
    print(f"bench-dependency selftest: {len(cases)} cases OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    rust_root = Path(__file__).resolve().parents[2] / "rust"
    # Rule 47: the gate asserts its own subject exists. A moved or renamed
    # crate must fail loudly here, not pass by finding nothing to check.
    if not (rust_root / BENCH_CRATE / "Cargo.toml").is_file():
        print(
            f"{BENCH_CRATE} not found under {rust_root} -- the gate's subject is "
            "absent. If the crate was renamed or retired, update or delete this "
            "gate; do not leave it passing vacuously.",
            file=sys.stderr,
        )
        return 1

    violations = scan(rust_root)
    if violations:
        print(
            f"{BENCH_CRATE} is a measurement harness and must stay out of the "
            "production dependency graph. Depended on by:",
            file=sys.stderr,
        )
        for crate, table in violations:
            print(f"  {crate}  [{table}]", file=sys.stderr)
        print(
            "\nIf production needs something this crate holds, move THAT into a "
            "production crate; do not ship the harness.",
            file=sys.stderr,
        )
        return 1

    print(f"{BENCH_CRATE}: no production dependents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
