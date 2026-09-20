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
# `[dev-dependencies]` and `[build-dependencies]`, including `[target.*.]`
# forms. A dev-dependency is still a reverse edge -- it puts the harness in a
# production crate's test graph, where its fixtures become available to copy,
# and it is the form the mistake is most likely to take.
#
# WHY TOML AND NOT A REGEX. The first version matched the literal dependency
# KEY, which is not the only spelling of the edge. Cargo lets a dependency be
# RENAMED -- `bench = { package = "shekyl-wss-q1b-bench" }` -- and lets it be
# inherited from the workspace -- `bench.workspace = true`, resolved through
# `[workspace.dependencies]`. Both put this harness in a production crate while
# a key-matching gate reports no violation. The gate now parses manifests and
# compares the RESOLVED PACKAGE NAME, which is the thing that actually decides
# what gets linked. `tomllib` is already load-bearing in two sibling gates.
#
# EXEMPT: the bench crate itself, and the workspace manifest (which must list
# the bench as a MEMBER -- that is registration, not a dependency edge).

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

BENCH_CRATE = "shekyl-wss-q1b-bench"
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _dependency_tables(manifest: dict) -> list[tuple[str, dict]]:
    """Every (table name, table) pair, including `[target.*.<table>]` forms."""
    tables = [(name, manifest[name]) for name in DEPENDENCY_TABLES if name in manifest]
    for cfg in manifest.get("target", {}).values():
        if isinstance(cfg, dict):
            tables += [(name, cfg[name]) for name in DEPENDENCY_TABLES if name in cfg]
    return tables


def _resolves_to_bench(name: str, spec: object, workspace_aliases: set[str]) -> bool:
    """Whether one dependency entry resolves to the bench package.

    Three spellings, all equivalent to Cargo:
      - the literal key;
      - a rename carrying `package = "<bench>"`;
      - `workspace = true` under a key the workspace table aliases to it.
    """
    if name == BENCH_CRATE:
        return True
    if isinstance(spec, dict):
        if spec.get("package") == BENCH_CRATE:
            return True
        if spec.get("workspace") is True and name in workspace_aliases:
            return True
    return False


def workspace_aliases(root: dict) -> set[str]:
    """Keys in `[workspace.dependencies]` that resolve to the bench package."""
    deps = root.get("workspace", {}).get("dependencies", {})
    return {
        name
        for name, spec in deps.items()
        if _resolves_to_bench(name, spec, workspace_aliases=set())
    }


def offending_tables(manifest: dict, aliases: set[str] | None = None) -> list[str]:
    """Return the dependency tables in which the bench crate appears."""
    aliases = aliases or set()
    found: list[str] = []
    for table_name, table in _dependency_tables(manifest):
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if _resolves_to_bench(name, spec, aliases):
                found.append(table_name)
                break
    return found


def scan(rust_root: Path) -> list[tuple[str, str]]:
    """Every (crate, table) pair that depends on the bench crate."""
    with (rust_root / "Cargo.toml").open("rb") as fh:
        root = tomllib.load(fh)
    aliases = workspace_aliases(root)

    violations: list[tuple[str, str]] = []
    for manifest_path in sorted(rust_root.glob("*/Cargo.toml")):
        crate = manifest_path.parent.name
        if crate == BENCH_CRATE:
            continue
        with manifest_path.open("rb") as fh:
            manifest = tomllib.load(fh)
        for table in offending_tables(manifest, aliases):
            violations.append((crate, table))
    return violations


def selftest() -> int:
    """Prove the gate can fail, and that it does not fail on the legitimate edges.

    A gate that has never been shown to fire is indistinguishable from one that
    cannot.
    """
    cases: list[tuple[str, str, list[str], set[str]]] = [
        (
            "a plain dependency is caught",
            f'[dependencies]\n{BENCH_CRATE} = {{ path = "../{BENCH_CRATE}" }}\n',
            ["dependencies"],
            set(),
        ),
        (
            "a dev-dependency is caught -- it is still a reverse edge",
            f'[dev-dependencies]\n{BENCH_CRATE} = {{ path = "../{BENCH_CRATE}" }}\n',
            ["dev-dependencies"],
            set(),
        ),
        (
            "a build-dependency is caught",
            f'[build-dependencies]\n{BENCH_CRATE} = "3"\n',
            ["build-dependencies"],
            set(),
        ),
        (
            "a target-gated dependency is caught",
            f"[target.'cfg(unix)'.dependencies]\n{BENCH_CRATE} = {{ workspace = true }}\n",
            ["dependencies"],
            set(),
        ),
        (
            "a RENAMED dependency is caught -- the key is not the package",
            f'[dependencies]\nbench = {{ package = "{BENCH_CRATE}", path = "../x" }}\n',
            ["dependencies"],
            set(),
        ),
        (
            "a renamed DEV-dependency is caught",
            f'[dev-dependencies]\nharness = {{ package = "{BENCH_CRATE}" }}\n',
            ["dev-dependencies"],
            set(),
        ),
        (
            "a workspace-inherited alias is caught when the workspace aliases it",
            "[dependencies]\nbench = { workspace = true }\n",
            ["dependencies"],
            {"bench"},
        ),
        (
            "the same alias is NOT a violation when the workspace points elsewhere",
            "[dependencies]\nbench = { workspace = true }\n",
            [],
            set(),
        ),
        (
            "the bench depending on a production crate is NOT a violation",
            '[dependencies]\nshekyl-fcmp = { path = "../shekyl-fcmp" }\n',
            [],
            set(),
        ),
        (
            "a crate merely mentioning the name in a comment is not a violation",
            f"[dependencies]\n# see {BENCH_CRATE} for the depth ladder\n",
            [],
            set(),
        ),
        (
            "a workspace member listing is not a dependency edge",
            f'[workspace]\nmembers = [\n    "{BENCH_CRATE}",\n]\n',
            [],
            set(),
        ),
        (
            "a package NAMED like a prefix of the bench is not the bench",
            f'[dependencies]\n{BENCH_CRATE}-helper = {{ path = "../x" }}\n',
            [],
            set(),
        ),
    ]
    failures = 0
    for name, text, expected, aliases in cases:
        got = offending_tables(tomllib.loads(text), aliases)
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
