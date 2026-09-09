#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Assert that test-only Cargo features are enabled on dev-dependency edges only.

# Why this gate exists

A `#[cfg(test)]` item is unreachable outside its own crate's test build — the
compiler enforces that, with no help from us. When code moves across a crate
boundary, a test-only escape hatch that used to be `cfg(test)`-private has to
become `pub` behind a feature, because `cfg(test)` does not cross a crate wall.
That trade is sound only while the feature stays on dev-dependency edges:

  * `resolver = "2"` (pinned in `rust/Cargo.toml`) unifies a dev-dependency's
    features only when dev-dependency targets are actually being built, and
  * the release path never builds test targets (`cmake/BuildRust.cmake` invokes
    cargo with no `--all-targets` / `--tests`),

so a shipped binary cannot contain the arm. One normal-dependency edge enabling
the feature dissolves both of those, silently: the code still compiles, the
tests still pass, and a forge for a security witness is now in the release
build. Nothing in the compiler notices. This gate is what notices.

# What it asserts

For every `(package, feature)` in `TEST_ONLY`, over `cargo metadata`:

  1. **Negative limb** — no dependency edge of `kind` `normal` or `build`
     enables the feature. This is the property the gate is for.
  2. **Positive limb** — the feature exists in the owning package's feature
     map, *and* at least one dev-kind edge enables it. Without this, renaming
     or deleting the feature makes limb 1 pass vacuously: a gate that cannot
     fail is worse than no gate, because it reports a property nobody holds
     (rule 47 — a gate asserts its own subject exists).

Reads `cargo metadata`, not the manifest text: a `Cargo.toml` grep cannot see
inherited workspace dependencies, renamed edges (`package = "..."`), or
platform-specific tables, and would report clean on all three.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# (owning crate, feature) → why it is test-only. Registering a row here is the
# declaration that the feature must never reach a shipped binary; adding the
# feature without a row leaves it ungated, so add both in the same commit.
TEST_ONLY: dict[tuple[str, str], str] = {
    (
        "shekyl-tor-control",
        "unpinned-tor-for-tests",
    ): "forges VerifiedTorBinary, the SP-T0c hash-pin witness, for lifecycle "
    "tests that inject an arbitrary unpinned tor",
}

RUST_DIR = Path(__file__).resolve().parents[2] / "rust"


def cargo_metadata() -> dict:
    """Workspace members and their declared dependency edges (no resolve graph)."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=RUST_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        sys.exit(f"cargo metadata failed ({out.returncode}):\n{out.stderr}")
    return json.loads(out.stdout)


def main() -> int:
    meta = cargo_metadata()
    packages = {p["name"]: p for p in meta["packages"]}

    failures: list[str] = []

    for (owner, feature), why in sorted(TEST_ONLY.items()):
        # Subject assertion: the feature must exist where it is claimed to.
        pkg = packages.get(owner)
        if pkg is None:
            failures.append(
                f"{owner}: registered in TEST_ONLY but is not a workspace member — "
                f"stale row, or the crate was renamed"
            )
            continue
        if feature not in pkg.get("features", {}):
            failures.append(
                f"{owner}: no feature `{feature}` — TEST_ONLY names a feature this "
                f"crate does not declare, so every edge check below is vacuous"
            )
            continue

        dev_enablers: list[str] = []
        for consumer in meta["packages"]:
            for dep in consumer["dependencies"]:
                if dep["name"] != owner or feature not in dep.get("features", []):
                    continue
                # `kind` is null for a normal dependency, else "dev" / "build".
                kind = dep.get("kind") or "normal"
                if kind == "dev":
                    dev_enablers.append(consumer["name"])
                else:
                    failures.append(
                        f"{consumer['name']}: enables `{owner}/{feature}` on a "
                        f"{kind} dependency edge — this feature {why}, and a "
                        f"non-dev edge puts it in builds that ship. Move the "
                        f"feature to the [dev-dependencies] edge."
                    )

        if not dev_enablers:
            failures.append(
                f"{owner}/{feature}: no dev-dependency edge enables it. Either the "
                f"consumer stopped needing it (delete the feature and this row) or "
                f"the edge was renamed — until one is true, the non-dev check above "
                f"passes without a subject."
            )

    if failures:
        print("Test-only feature gate FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    checked = ", ".join(f"{o}/{f}" for o, f in sorted(TEST_ONLY))
    print(f"Test-only feature gate OK: {checked} (dev-dependency edges only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
