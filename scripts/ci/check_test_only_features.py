#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Assert that test-only Cargo features are enabled on dev-dependency edges only,
and that consumer-owned Cargo features die with their one consumer.

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

  1. **Negative limb (edges)** — no dependency edge of `kind` `normal` or
     `build` enables the feature. This is the property the gate is for.
  2. **Negative limb (owner)** — the owning crate's `default` feature, and
     every other feature it declares, do not enable it. A consumer-edge-only
     check is vacuous against `default = ["unpinned-tor-for-tests"]`: no
     consumer names the feature, every consumer still compiles it in.
  3. **Positive limb** — the feature exists in the owning package's feature
     map, *and* at least one dev-kind edge enables it. Without this, renaming
     or deleting the feature makes limbs 1–2 pass vacuously: a gate that cannot
     fail is worse than no gate, because it reports a property nobody holds
     (rule 47 — a gate asserts its own subject exists).

# The second limb — consumer-owned features (`CONSUMER_OWNED`)

A different class with the same file as its subject. Some code exists for
exactly one consumer and must not outlive it — the canonical case is a field
the DRS-E2 comparator needs for column-completeness of its LMDB parity diff
and nothing else ever should (`DRS_E1_STX.md` STX-9: `TxHeader.unlock_time`
behind `shekyl-chain-store/comparator-parity`). Putting such code behind a
cfg feature that the consumer alone enables makes its *expiry a consequence
of the event*: retire the consumer, delete the feature, and the code cannot
compile. What that construction still rests on is one link — someone
noticing that the feature is declared with no enabler left — and this limb
is that link, so the whole mechanism is structural rather than one
remembered grep (the escalation `compile_fail` → `cargo tree` and
holder-grep → rejection-test took).

For every `(owner, feature) → (enabler, why)` in `CONSUMER_OWNED`:

  1. **Subject** — the owner is a workspace member and declares the feature.
  2. **Self-expiry** — the named enabler is still a workspace member. If it is
     gone, the feature outlived its consumer: red, with the instruction to
     delete the feature, every `#[cfg(feature = ...)]` item under it, and the
     row, in one commit. This is `DEFERRED_DOCS`' self-expiry and the
     bijection allowlist's missing-item leg, in this file's vocabulary.
  3. **Sole enabler** — exactly the named crate enables it, on any edge kind
     (these are not test-only; the comparator is a normal consumer). A second
     enabler is red: that is a second crate quietly taking a dependency on
     code that dies with the first, which is the failure the class exists to
     prevent. No enabler is red: declared, unowned.
  4. **Owner-side** — the owner's `default` and other features do not enable
     it, for the same reason as the test-only limb.

Registering a row is what makes a feature consumer-owned; the feature and its
row land in the same commit. The registry may be empty — today it is — and
`--selftest` exercises the limb on synthetic metadata so the gate asserts its
own subject with zero live rows (rule 47) rather than passing vacuously.

# The third limb — every feature a governed crate declares is categorized

Both registries above are keyed by row, so a feature that is *never
registered* is outside them: declared in the store's manifest, enabled by two
crates, no row — the sole-enabler check never runs on it, because it is keyed
by the row. That is exactly the shape the consumer-owned class exists to
prevent, arriving through the door without the check on it. So for every
crate in `GOVERNED_OWNERS`, **every feature it declares must be in exactly one
of `TEST_ONLY`, `CONSUMER_OWNED` or `PERMANENT`; an uncategorized feature is
red** (`default` is exempt — it is the feature table's entry point, and what
it enables is checked by the other limbs). The pattern the tree already uses
three times — the bijection gate's `{table: reason}`, `CXX_HOLDER_RE`,
`RUST_ONLY_TABLES`: the registry is exhaustive, not opt-in. Landed while
`shekyl-chain-store` declares no features at all, which is the one moment it
could be added for free.

# A limit this file does not close, named

The gate reads the manifest. It can see that a feature is declared, owned and
enabled; it cannot see whether anything is still *guarded* by it. Registry
row and feature intact, every `#[cfg(feature = "comparator-parity")]` item
deleted, and the row keeps asserting a construction that no longer exists —
and the next person to add an item under that cfg inherits an expiry they
did not choose. Detecting that needs a source scan, a different instrument
from `cargo metadata`, so it is not a fifth limb here. Whoever deletes the
last cfg'd item deletes the feature and the row with it; this sentence is
what tells them so.

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
        "shekyl-tor-control-client",
        "unpinned-tor-for-tests",
    ): "forges VerifiedTorBinary, the SP-T0c hash-pin witness, for lifecycle "
    "tests that inject an arbitrary unpinned tor",
}

# (owning crate, feature) → (the one crate that may enable it, why it exists).
# A row is the declaration that the feature dies with its enabler; the feature
# and its row land together. Empty today: the first candidate is
# `("shekyl-chain-store", "comparator-parity") → ("<the DRS-E2 comparator
# crate>", "TxHeader.unlock_time for the LMDB txindex parity diff")`, which
# lands only if E2 asks for the column (DRS_E1_STX.md STX-9 / STX-Q3).
CONSUMER_OWNED: dict[tuple[str, str], tuple[str, str]] = {}

# (owning crate, feature) → why it is an ordinary, permanent feature. The third
# category, so that a governed crate's feature table can be exhaustively
# categorized without forcing every feature into the two special classes.
PERMANENT: dict[tuple[str, str], str] = {}

# Crates whose feature table must be exhaustively categorized (third limb).
# Adding a crate here is the declaration that no feature of it may exist
# uncategorized; both listed crates are clean at registration
# (`shekyl-chain-store` declares none; `shekyl-tor-control-client` declares
# only its TEST_ONLY row).
#
# THE RESIDUAL, NAMED: this set is itself opt-in — two crates out of a
# workspace approaching seventy. Exhaustiveness holds *within* governance, and
# governance has the shape the third limb closed one level down: a crate that
# acquires a consumer-owned feature and never joins this set is outside the
# whole construction, and nothing here notices. It is deliberately not closed
# — governing every crate would force every feature in the workspace into
# three categories and generate churn for no safety on crates that will never
# have a consumer-owned feature. Instead the rule for joining is stated so it
# can be applied without asking: **a crate joins this set in the commit that
# first declares a feature another crate enables.** A feature only its own
# tests or its own `default` turn on does not trigger it; a feature that
# crosses a crate boundary does, because that is the edge every limb above is
# about.
GOVERNED_OWNERS: frozenset[str] = frozenset({"shekyl-chain-store", "shekyl-tor-control-client"})

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


def check_consumer_owned(
    meta: dict, registry: dict[tuple[str, str], tuple[str, str]]
) -> list[str]:
    """The consumer-owned limb, over one `cargo metadata` document."""
    packages = {p["name"]: p for p in meta["packages"]}
    failures: list[str] = []
    for (owner, feature), (enabler, why) in sorted(registry.items()):
        pkg = packages.get(owner)
        if pkg is None:
            failures.append(
                f"{owner}: registered in CONSUMER_OWNED but is not a workspace member"
            )
            continue
        features_map = pkg.get("features", {})
        if feature not in features_map:
            failures.append(
                f"{owner}: no feature `{feature}` — CONSUMER_OWNED names a feature "
                f"this crate does not declare; the row is stale or the feature was "
                f"renamed without it"
            )
            continue
        if enabler not in packages:
            failures.append(
                f"{owner}/{feature}: its one consumer `{enabler}` is no longer a "
                f"workspace member — the feature has outlived the thing it existed "
                f"for ({why}). Delete the feature, every `#[cfg(feature = "
                f"\"{feature}\")]` item under it, and this row, in one commit."
            )
            continue
        for other, enables in sorted(features_map.items()):
            if other != feature and feature in enables:
                failures.append(
                    f"{owner}: feature `{other}` enables `{feature}` — a "
                    f"consumer-owned feature is enabled from its consumer's edge "
                    f"only, never from the owner's own feature table"
                )
        enablers = sorted(
            {
                consumer["name"]
                for consumer in meta["packages"]
                for dep in consumer["dependencies"]
                if dep["name"] == owner and feature in dep.get("features", [])
            }
        )
        if not enablers:
            failures.append(
                f"{owner}/{feature}: declared, and no crate enables it — an "
                f"unowned feature whose cfg'd items no build compiles. Either "
                f"`{enabler}` dropped it (delete the feature and this row) or its "
                f"edge was renamed."
            )
        for extra in enablers:
            if extra != enabler:
                failures.append(
                    f"{extra}: enables `{owner}/{feature}`, which is owned by "
                    f"`{enabler}` alone ({why}) — a second consumer has taken a "
                    f"dependency on code that dies with the first. Give the "
                    f"second consumer its own read, or rule the feature "
                    f"permanent and delete this row."
                )
    return failures


def check_exhaustive(
    meta: dict,
    governed: frozenset[str],
    *registries: dict,
) -> list[str]:
    """Every feature a governed crate declares is in exactly one registry."""
    packages = {p["name"]: p for p in meta["packages"]}
    failures: list[str] = []
    categorized: dict[tuple[str, str], int] = {}
    for reg in registries:
        for key in reg:
            categorized[key] = categorized.get(key, 0) + 1
    for key, n in sorted(categorized.items()):
        if n > 1:
            failures.append(
                f"{key[0]}/{key[1]}: registered in {n} categories — a feature is "
                f"test-only, consumer-owned or permanent, never two of them"
            )
    for owner in sorted(governed):
        pkg = packages.get(owner)
        if pkg is None:
            failures.append(
                f"{owner}: named in GOVERNED_OWNERS but is not a workspace member"
            )
            continue
        for feature in sorted(pkg.get("features", {})):
            if feature == "default":
                continue
            if (owner, feature) not in categorized:
                failures.append(
                    f"{owner}: declares feature `{feature}` that no registry names — "
                    f"add it to TEST_ONLY, CONSUMER_OWNED or PERMANENT in the commit "
                    f"that declares it; an uncategorized feature is the door the "
                    f"consumer-owned checks do not stand at"
                )
    return failures


def _synthetic(
    owner_features: dict[str, list[str]],
    edges: dict[str, list[tuple[str, list[str]]]],
) -> dict:
    """A `cargo metadata --no-deps` document with one owner and the named consumers."""
    packages = [
        {"name": "owner", "features": owner_features, "dependencies": []},
    ]
    for consumer, deps in edges.items():
        packages.append(
            {
                "name": consumer,
                "features": {},
                "dependencies": [
                    {"name": dep, "features": feats, "kind": None} for dep, feats in deps
                ],
            }
        )
    return {"packages": packages}


def selftest() -> int:
    """Pin the consumer-owned limb on synthetic metadata: it must go red for
    each of the four ways the construction can rot, and green for the one
    shape it exists to allow."""
    reg = {("owner", "cfeat"): ("comparator", "a parity-only column")}
    cases = [
        (
            "sole enabler present: green",
            _synthetic({"cfeat": [], "default": []}, {"comparator": [("owner", ["cfeat"])]}),
            [],
        ),
        (
            "consumer retired: the feature outlived it",
            _synthetic({"cfeat": []}, {"unrelated": [("owner", [])]}),
            ["is no longer a workspace member"],
        ),
        (
            "second consumer took a dependency",
            _synthetic(
                {"cfeat": []},
                {"comparator": [("owner", ["cfeat"])], "wallet": [("owner", ["cfeat"])]},
            ),
            ["a second consumer has taken a dependency"],
        ),
        (
            "declared, no enabler",
            _synthetic({"cfeat": []}, {"comparator": [("owner", [])]}),
            ["no crate enables it"],
        ),
        (
            "owner enables it from default",
            _synthetic({"cfeat": [], "default": ["cfeat"]}, {"comparator": [("owner", ["cfeat"])]}),
            ["never from the owner's own feature table"],
        ),
        (
            "feature deleted, row kept",
            _synthetic({}, {"comparator": [("owner", [])]}),
            ["does not declare"],
        ),
    ]
    exhaustive_cases = [
        (
            "governed owner, every feature categorized: green",
            _synthetic({"cfeat": [], "default": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset({"owner"}),
            [],
        ),
        (
            "unregistered feature with two enablers — the uncovered door",
            _synthetic(
                {"cfeat": [], "stray": []},
                {"comparator": [("owner", ["cfeat"])], "wallet": [("owner", ["stray"])]},
            ),
            frozenset({"owner"}),
            ["no registry names"],
        ),
        (
            "governed owner missing from the workspace",
            _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset({"owner", "vanished"}),
            ["not a workspace member"],
        ),
    ]
    bad: list[str] = []
    for label, meta, governed, want in exhaustive_cases:
        got = check_exhaustive(meta, governed, {}, reg, {})
        if not want and got:
            bad.append(f"{label}: expected green, got {got!r}")
        for needle in want:
            if not any(needle in f for f in got):
                bad.append(f"{label}: expected a failure containing {needle!r}, got {got!r}")
    double = check_exhaustive(
        _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
        frozenset({"owner"}),
        {("owner", "cfeat"): "x"},
        reg,
    )
    if not any("registered in 2 categories" in f for f in double):
        bad.append(f"double registration: expected a failure, got {double!r}")
    for label, meta, want in cases:
        got = check_consumer_owned(meta, reg)
        if not want and got:
            bad.append(f"{label}: expected green, got {got!r}")
        for needle in want:
            if not any(needle in f for f in got):
                bad.append(f"{label}: expected a failure containing {needle!r}, got {got!r}")
    if bad:
        print("consumer-owned feature selftest FAILED:\n", file=sys.stderr)
        for b in bad:
            print(f"  - {b}", file=sys.stderr)
        return 1
    print(
        f"feature-gate selftest: {len(cases)} consumer-owned cases + "
        f"{len(exhaustive_cases) + 1} exhaustiveness cases held"
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    meta = cargo_metadata()
    packages = {p["name"]: p for p in meta["packages"]}

    failures: list[str] = check_consumer_owned(meta, CONSUMER_OWNED)
    failures += check_exhaustive(meta, GOVERNED_OWNERS, TEST_ONLY, CONSUMER_OWNED, PERMANENT)

    for (owner, feature), why in sorted(TEST_ONLY.items()):
        # Subject assertion: the feature must exist where it is claimed to.
        pkg = packages.get(owner)
        if pkg is None:
            failures.append(
                f"{owner}: registered in TEST_ONLY but is not a workspace member — "
                f"stale row, or the crate was renamed"
            )
            continue
        features_map = pkg.get("features", {})
        if feature not in features_map:
            failures.append(
                f"{owner}: no feature `{feature}` — TEST_ONLY names a feature this "
                f"crate does not declare, so every edge check below is vacuous"
            )
            continue

        # Owner-side enablement ships the arm to every consumer, including
        # those whose edges never name it. `default` is the loud case;
        # any other feature that lists this one is the same hole with a
        # different name.
        for other, enables in sorted(features_map.items()):
            if other == feature:
                continue
            if feature in enables:
                failures.append(
                    f"{owner}: feature `{other}` enables `{feature}` — this "
                    f"feature {why}, and an intra-crate enablement puts it in "
                    f"every build that takes `{other}` (including `default`). "
                    f"Keep `{feature}` as a standalone empty feature enabled "
                    f"only from a consumer's [dev-dependencies] edge."
                )

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
    owned = ", ".join(f"{o}/{f}→{e}" for (o, f), (e, _) in sorted(CONSUMER_OWNED.items()))
    print(
        f"Test-only feature gate OK: {checked} (dev-dependency edges only); "
        f"consumer-owned: {owned or 'none registered (selftest is the subject)'}; "
        f"governed feature tables exhaustively categorized: {', '.join(sorted(GOVERNED_OWNERS))}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
