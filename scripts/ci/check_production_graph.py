#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""No shipped binary's graph holds the harness, the forge, or a test-only feature.

# What is held

`CHAIN_FORGE.md` §11.1, item 2 (`CF-1b`). For every binary the release
builds (`cmake/BuildRust.cmake`: `shekyld`, `shekyl-cli`,
`shekyl-wallet-rpc`), over its resolved normal and build graph:

  1. **No harness or forge crate.** `shekyl-harness-spender`,
     `shekyl-harness-wallet` and `shekyl-chain-forge` are not activated in
     the resolved graph (`HARNESS`). An optional edge to one counts only
     when a feature the build turns on activates it: `shekyl-chain-rules`
     names `shekyl-harness-wallet` optionally, under its TEST_ONLY
     `harness`, and no shipped build turns that on.
  2. **No test-only feature on.** After Cargo's feature unification from
     the root's own defaults, no feature registered TEST_ONLY in
     `check_test_only_features.py` is enabled on any member: every
     `seeded-rng` (§5.3's seams), the driver's `forge`, and the rest of that
     table, read from it so the two never drift.

`check_test_only_features.py` already holds each TEST_ONLY feature to dev
edges by edge kind. This check proves the consequence on the graphs that
ship: the seeded signers and provers, the harness id and the driver are
compiled into none of them, whatever forwards a future manifest adds.

The manifests are read and resolved the way `check_p_fetch_dep_cut.py`
reads them (its parser and resolver, imported), so the bundled grep-gates
job needs no Rust toolchain and the two checks read one graph.

# Rule 47

The roots come from `BuildRust.cmake` and must include `shekyld` (the parse
read the file it meant to). Each root must be a workspace member, and its
graph must be non-empty. `--selftest` plants a harness crate on a normal
edge, a forwarded `seeded-rng`, a TEST_ONLY feature enabled only on a dev
edge (green), and a missing root sentinel, and checks each verdict.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_p_fetch_dep_cut import (  # noqa: E402
    BUILD_RUST,
    ROOT_SENTINEL,
    closure,
    resolve_features,
    shipped_roots,
    workspace_members,
)

REPO = Path(__file__).resolve().parents[2]

# Crates no shipped graph may reach: the test-support spender and wallet, and
# the chain forge (CHAIN_FORGE.md §11.1).
HARNESS = ("shekyl-harness-spender", "shekyl-harness-wallet", "shekyl-chain-forge")


def test_only_rows() -> set[tuple[str, str]]:
    """(crate, feature) for every TEST_ONLY row of check_test_only_features.py."""
    path = REPO / "scripts" / "ci" / "check_test_only_features.py"
    spec = importlib.util.spec_from_file_location("check_test_only_features", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(module.TEST_ONLY)


def check(
    roots: list[str],
    members: dict[str, dict],
    workspace_deps: dict,
    test_only: set[tuple[str, str]],
) -> list[str]:
    errors: list[str] = []
    if ROOT_SENTINEL not in roots:
        return [
            f"{ROOT_SENTINEL} is not among the shipped roots read from BuildRust.cmake "
            f"({roots}): the parse did not read the file it meant to (rule 47)"
        ]
    for root in roots:
        if root not in members:
            errors.append(f"shipped root {root} is not a workspace member")
            continue
        if len(closure(root, members, workspace_deps)) < 2:
            errors.append(f"{root}: its shipped graph is empty, so this check has no subject")
        resolved = resolve_features(root, members, workspace_deps)
        for crate in HARNESS:
            if crate in resolved:
                errors.append(
                    f"{root}: its shipped graph activates {crate}, which is test support and "
                    "must never ship (CHAIN_FORGE.md §11.1)"
                )
        for crate, features in sorted(resolved.items()):
            for feature in sorted(features):
                if (crate, feature) in test_only:
                    errors.append(
                        f"{root}: resolves {crate}/{feature} on, a TEST_ONLY feature "
                        "(check_test_only_features.py), so a shipped build would carry it"
                    )
    return errors


def selftest() -> int:
    def manifest(name: str, deps: dict, features: dict | None = None, dev: dict | None = None) -> dict:
        m = {"package": {"name": name}, "dependencies": deps, "features": features or {}}
        if dev:
            m["dev-dependencies"] = dev
        return m

    base = {
        "shekyld": manifest("shekyld", {"lib": {"path": "../lib"}}),
        "lib": manifest("lib", {}, {"seeded-rng": []}),
        "shekyl-harness-spender": manifest("shekyl-harness-spender", {}),
    }
    rows = {("lib", "seeded-rng")}
    cases = [
        ("clean graph: green", base, ["shekyld"], False),
        (
            "a harness crate on a normal edge: red",
            {**base, "shekyld": manifest("shekyld", {
                "lib": {"path": "../lib"},
                "shekyl-harness-spender": {"path": "../x"},
            })},
            ["shekyld"],
            True,
        ),
        (
            "seeded-rng forwarded on: red",
            {**base, "shekyld": manifest(
                "shekyld",
                {"lib": {"path": "../lib"}},
                {"default": ["lib/seeded-rng"]},
            )},
            ["shekyld"],
            True,
        ),
        (
            "seeded-rng on a dev edge only: green",
            {**base, "shekyld": manifest(
                "shekyld",
                {"lib": {"path": "../lib"}},
                dev={"lib": {"path": "../lib", "features": ["seeded-rng"]}},
            )},
            ["shekyld"],
            False,
        ),
        (
            "a harness crate optional and not activated: green",
            {**base, "lib": manifest(
                "lib",
                {"shekyl-harness-spender": {"path": "../x", "optional": True}},
                {"seeded-rng": [], "harness": ["dep:shekyl-harness-spender"]},
            )},
            ["shekyld"],
            False,
        ),
        (
            "a harness crate optional and activated by default: red",
            {**base, "lib": manifest(
                "lib",
                {"shekyl-harness-spender": {"path": "../x", "optional": True}},
                {"seeded-rng": [], "default": ["dep:shekyl-harness-spender"]},
            )},
            ["shekyld"],
            True,
        ),
        ("the root sentinel is missing: red", base, ["other"], True),
    ]
    failed = 0
    for name, members, roots, want in cases:
        errors = check(roots, members, {}, rows)
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")
    return failed


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    members, workspace_deps = workspace_members()
    roots = shipped_roots(BUILD_RUST.read_text())
    rows = test_only_rows()
    if not rows:
        print("FAIL: no TEST_ONLY row read: the feature check has no subject", file=sys.stderr)
        return 1
    errors = check(roots, members, workspace_deps, rows)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    print(
        f"PASS: {len(roots)} shipped root(s) ({', '.join(roots)}) reach none of "
        f"{', '.join(HARNESS)} and resolve none of {len(rows)} TEST_ONLY feature(s) on"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
