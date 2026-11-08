#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# A measurement crate must never enter the production dependency graph.
#
# WHY A GATE AND NOT A COMMENT. `shekyl-wss-q1b-bench` and
# `shekyl-verify-cost` are measurement harnesses: synthetic corpora, rig
# gates, fixtures that mint curve points with known secrets. None of that
# belongs in a shipped wallet or daemon. Each crate's own documentation says
# so -- and a crate-doc sentence is not a check (rule 47: a gate must assert
# its own subject). The failure this closes is ordinary: someone wants a
# helper the harness holds, adds a dependency, and the harness ships.
#
# WHY THE DIRECTION MATTERS. The harness depending on production crates is
# the POINT -- it measures them. Only the reverse edge is forbidden. So this
# gate reads every OTHER crate's manifest and asks whether it names a
# measurement crate; it never inspects that crate's own dependency list.
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
# `[workspace.dependencies]`. Both put a harness in a production crate while
# a key-matching gate reports no violation. The gate now parses manifests and
# compares the RESOLVED PACKAGE NAME, which is the thing that actually decides
# what gets linked. `tomllib` is already load-bearing in two sibling gates.
#
# EXEMPT: the measurement crates themselves, and the workspace manifest
# (which must list them as MEMBERS -- that is registration, not a dependency
# edge).
#
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

MEASUREMENT_CRATES = (
    "shekyl-wss-q1b-bench",
    "shekyl-verify-cost",
)
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def _dependency_tables(manifest: dict) -> list[tuple[str, dict]]:
    """Every (table name, table) pair, including `[target.*.<table>]` forms."""
    tables = [(name, manifest[name]) for name in DEPENDENCY_TABLES if name in manifest]
    for cfg in manifest.get("target", {}).values():
        if isinstance(cfg, dict):
            tables += [(name, cfg[name]) for name in DEPENDENCY_TABLES if name in cfg]
    return tables


def _resolves_to(name: str, spec: object, aliases: set[str], crate: str) -> bool:
    """Whether one dependency entry resolves to `crate`.

    Three spellings, all equivalent to Cargo:
      - the literal key;
      - a rename carrying `package = "<crate>"`;
      - `workspace = true` under a key the workspace table aliases to it.
    """
    if name == crate:
        return True
    if isinstance(spec, dict):
        if spec.get("package") == crate:
            return True
        if spec.get("workspace") is True and name in aliases:
            return True
    return False


def workspace_aliases(root: dict, crate: str) -> set[str]:
    """Keys in `[workspace.dependencies]` that resolve to `crate`."""
    deps = root.get("workspace", {}).get("dependencies", {})
    return {
        name
        for name, spec in deps.items()
        if _resolves_to(name, spec, aliases=set(), crate=crate)
    }


def offending_tables(manifest: dict, aliases_for: dict[str, set[str]] | None = None) -> list[str]:
    """Return the dependency tables in which a measurement crate appears."""
    aliases_for = aliases_for or {}
    found: list[str] = []
    for table_name, table in _dependency_tables(manifest):
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if any(
                _resolves_to(name, spec, aliases_for.get(crate, set()), crate)
                for crate in MEASUREMENT_CRATES
            ):
                found.append(table_name)
                break
    return found


def scan(rust_root: Path) -> list[tuple[str, str, str]]:
    """Every (crate, table, measurement crate) reverse edge."""
    with (rust_root / "Cargo.toml").open("rb") as fh:
        root = tomllib.load(fh)
    aliases_for = {crate: workspace_aliases(root, crate) for crate in MEASUREMENT_CRATES}

    # RECURSIVE. `*/Cargo.toml` saw only crates one level down and missed every
    # nested one -- `shekyl-*/fuzz/Cargo.toml`, `shekyl-oxide/crypto/*` -- so a
    # reverse edge added there was invisible while the gate reported clean over
    # "every other crate". A gate with an unchecked subtree is not a gate over
    # the graph it names.
    violations: list[tuple[str, str, str]] = []
    for manifest_path in sorted(rust_root.rglob("Cargo.toml")):
        if "target" in manifest_path.parts:
            continue
        crate_dir = str(manifest_path.parent.relative_to(rust_root))
        if crate_dir in MEASUREMENT_CRATES or manifest_path.parent == rust_root:
            continue
        with manifest_path.open("rb") as fh:
            manifest = tomllib.load(fh)
        for table_name, table in _dependency_tables(manifest):
            if not isinstance(table, dict):
                continue
            named: set[str] = set()
            for name, spec in table.items():
                for measurement in MEASUREMENT_CRATES:
                    if _resolves_to(name, spec, aliases_for.get(measurement, set()), measurement):
                        named.add(measurement)
            for measurement in sorted(named):
                violations.append((crate_dir, table_name, measurement))
    return violations


def selftest() -> int:
    """Prove the gate can fail, and that it does not fail on the legitimate edges.

    A gate that has never been shown to fire is indistinguishable from one that
    cannot. The cases name both measurement crates: a gate collapsed back to
    one constant fails the other crate's case.
    """
    first, second = MEASUREMENT_CRATES

    def aliases(names: set[str], crate: str = first) -> dict[str, set[str]]:
        return {crate: names}

    cases: list[tuple[str, str, list[str], dict[str, set[str]]]] = [
        (
            "a plain dependency is caught",
            f'[dependencies]\n{first} = {{ path = "../{first}" }}\n',
            ["dependencies"],
            aliases(set()),
        ),
        (
            "a dev-dependency is caught -- it is still a reverse edge",
            f'[dev-dependencies]\n{first} = {{ path = "../{first}" }}\n',
            ["dev-dependencies"],
            aliases(set()),
        ),
        (
            "a build-dependency is caught",
            f'[build-dependencies]\n{first} = "3"\n',
            ["build-dependencies"],
            aliases(set()),
        ),
        (
            "a target-gated dependency is caught",
            f"[target.'cfg(unix)'.dependencies]\n{first} = {{ workspace = true }}\n",
            ["dependencies"],
            aliases(set()),
        ),
        (
            "a RENAMED dependency is caught -- the key is not the package",
            f'[dependencies]\nbench = {{ package = "{first}", path = "../x" }}\n',
            ["dependencies"],
            aliases(set()),
        ),
        (
            "a renamed DEV-dependency is caught",
            f'[dev-dependencies]\nharness = {{ package = "{first}" }}\n',
            ["dev-dependencies"],
            aliases(set()),
        ),
        (
            "a workspace-inherited alias is caught when the workspace aliases it",
            "[dependencies]\nbench = { workspace = true }\n",
            ["dependencies"],
            aliases({"bench"}),
        ),
        (
            "the same alias is NOT a violation when the workspace points elsewhere",
            "[dependencies]\nbench = { workspace = true }\n",
            [],
            aliases(set()),
        ),
        (
            "the harness depending on a production crate is NOT a violation",
            '[dependencies]\nshekyl-fcmp = { path = "../shekyl-fcmp" }\n',
            [],
            aliases(set()),
        ),
        (
            "a crate merely mentioning the name in a comment is not a violation",
            f"[dependencies]\n# see {first} for the depth ladder\n",
            [],
            aliases(set()),
        ),
        (
            "a workspace member listing is not a dependency edge",
            f'[workspace]\nmembers = [\n    "{first}",\n    "{second}",\n]\n',
            [],
            aliases(set()),
        ),
        (
            "a package NAMED like a prefix of the harness is not the harness",
            f'[dependencies]\n{first}-helper = {{ path = "../x" }}\n{second}-helper = {{ path = "../y" }}\n',
            [],
            aliases(set()),
        ),
        (
            "the second measurement crate is caught too",
            f'[dependencies]\n{second} = {{ path = "../{second}" }}\n',
            ["dependencies"],
            aliases(set()),
        ),
        (
            "an alias of the second crate is caught only when that crate is the alias",
            "[dependencies]\nbench = { workspace = true }\n",
            ["dependencies"],
            aliases({"bench"}, second),
        ),
    ]
    failures = 0
    for name, text, expected, alias_map in cases:
        got = offending_tables(tomllib.loads(text), alias_map)
        if got != expected:
            print(f"  FAIL {name}: expected {expected}, got {got}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"bench-dependency selftest FAILED ({failures} cases)", file=sys.stderr)
        return 1
    print(f"bench-dependency selftest: {len(cases)} cases OK")
    return 0


def _manifest_count(rust_root: Path) -> int:
    """Manifests actually inspected — printed so a silent narrowing is visible."""
    return sum(
        1
        for m in rust_root.rglob("Cargo.toml")
        if "target" not in m.parts and m.parent != rust_root
    )


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    rust_root = Path(__file__).resolve().parents[2] / "rust"
    # Rule 47: the gate asserts its own subjects exist. A moved or renamed
    # crate must fail loudly here, not pass by finding nothing to check.
    missing = [
        crate
        for crate in MEASUREMENT_CRATES
        if not (rust_root / crate / "Cargo.toml").is_file()
    ]
    if missing:
        print(
            f"{', '.join(missing)} not found under {rust_root} -- the gate's "
            "subject is absent. If the crate was renamed or retired, update "
            "or delete this gate; do not leave it passing vacuously.",
            file=sys.stderr,
        )
        return 1

    violations = scan(rust_root)
    if violations:
        print(
            "a measurement harness must stay out of the production dependency "
            "graph. Depended on by:",
            file=sys.stderr,
        )
        for crate, table, measurement in violations:
            print(f"  {crate}  [{table}]  -> {measurement}", file=sys.stderr)
        print(
            "\nIf production needs something a harness holds, move THAT into a "
            "production crate; do not ship the harness.",
            file=sys.stderr,
        )
        return 1

    named = ", ".join(MEASUREMENT_CRATES)
    print(f"{named}: no production dependents across {_manifest_count(rust_root)} manifests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
