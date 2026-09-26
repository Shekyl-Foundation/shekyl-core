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

# The fourth limb — the trigger for joining governance is detected, not remembered

`GOVERNED_OWNERS` is opt-in, and the rule for joining it — *a crate joins in
the commit that first declares a feature another crate enables* — is exactly
the condition `cargo metadata` already shows: crate X declares F, some other
member's dependency edge on X enables F, X is not governed. So the rule is a
limb, not a memory: **an ungoverned crate that meets the trigger is red**,
with the instruction to join and categorize. It fires only on crates that
actually cross a boundary; the sixty-odd that never will are untouched, which
was the whole objection to governing everything. Governing all crates and
*detecting the trigger* are different things, and the second is nearly free.

Fifteen crates already met the trigger when this limb was written
(2026-09-19, with feature forwarding counted; a crate's edge on itself
crosses no boundary and does not count), and categorizing their features is
not the S-TX pre-flight's scope, so they sit in
`MET_TRIGGER_UNGOVERNED_AT_REGISTRATION` — a dated, shrink-only list of the
DEFERRED_DOCS / bijection-allowlist shape that records each crate's **exact
hit set** (feature, consumer, edge kind). A new feature or a new enabler on a
listed crate is red (an owner-keyed exemption would have covered it
silently); a recorded hit that vanished is red until deleted; a crate that
has joined `GOVERNED_OWNERS` may not also be listed. Three of the fifteen are
findings rather than chores — a feature whose name says test-only, enabled
on a **normal** edge. Two are hygiene (move the edge, or rule PERMANENT with
the reason) and share the governance FOLLOWUPS row; the third,
`shekyl-crypto-pq/test-utils` enabled by `shekyl-ffi` directly and by
`shekyl-p-serve` through forwarding, is **FOLLOWUPS F-7**'s — its exports are unconditional
`extern "C"` in the production header, so categorizing the feature changes
nothing and the fix is the structural gate that row already names.

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
    (
        "shekyl-chain-rules",
        "harness",
    ): "exposes the negative-fixture harness (MockChain, MockSubstrate) as a "
    "library surface for the store's mock-vs-BatchView conformance test "
    "(E6 slice 2 F11); its own manifest says 'test-only in effect, never "
    "from a normal dependency' — this row is that sentence as a gate. Since "
    "E6 slice 5 the feature also enables an optional curve25519-dalek edge "
    "for one fixture function (fixture::point_at = k·G, the computed form of "
    "the pinned point table); this limb is what keeps that edge off every "
    "normal consumer — the crate's production surface only verifies, "
    "through shekyl-ct-balance, and never derives",
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
# (`shekyl-chain-store` declares none; `shekyl-tor-control-client` and
# `shekyl-chain-rules` declare only their TEST_ONLY row — the latter joined
# 2026-09-19 when the fourth limb fired on `harness` in CI, the first
# cross-crate feature declared after the limb landed).
#
# This set is opt-in — two crates out of a workspace approaching seventy — so
# exhaustiveness holds *within* governance. The rule for joining: **a crate
# joins this set in the commit that first declares a feature another crate
# enables.** A feature only its own tests or its own `default` turn on does
# not trigger it; one that crosses a crate boundary does, because that edge
# is what every limb above is about. The rule is not remembered: the fourth
# limb (`check_trigger`) reads it off `cargo metadata` and goes red on an
# ungoverned crate that meets it. (The first draft named this as a residual
# left open, on the argument that governing everything is churn; detecting
# the trigger is a different, nearly free thing, and it is what landed.)
GOVERNED_OWNERS: frozenset[str] = frozenset(
    {"shekyl-chain-store", "shekyl-tor-control-client", "shekyl-chain-rules"}
)

Hit = tuple[str, str, str]  # feature, consumer, edge kind

# Crates that met the governance trigger before the fourth limb existed
# (measured 2026-09-19 on the S-TX pre-flight, PR #786, forwarding included)
# and are not yet governed. Each entry records its EXACT hit set — (feature,
# consumer, edge kind) — so a new feature or enabler on a listed crate is red,
# and a vanished hit is red until deleted. Shrink-only: a crate leaves this
# list by joining GOVERNED_OWNERS
# with its features categorized (FOLLOWUPS "Fourteen crates meet the feature-
# governance trigger ungoverned", Target: pre-genesis; the fifteenth entry,
# shekyl-crypto-pq, leaves via FOLLOWUPS F-7). Entries marked FINDING enable
# a test-named feature on a NORMAL edge — the very shape TEST_ONLY refuses —
# and are governed first. Forwarding raised the count from twelve to fifteen
# (shekyl-curve-io, shekyl-curve-primitives, shekyl-fcmp are reached only by
# forwarded `std` / `multisig` features) and added the two forwarded
# normal-edge test paths named in the FINDING notes.
MET_TRIGGER_UNGOVERNED_AT_REGISTRATION: dict[str, tuple[str, frozenset[Hit]]] = {
    "shekyl-crypto-pq": (
        "FINDING owned by FOLLOWUPS F-7, not the governance row: test-utils reaches "
        "shekyl-ffi on a NORMAL edge directly and shekyl-p-serve on a NORMAL edge by "
        "forwarding (its test-signer feature); the FFI exports that call it are "
        "unconditional extern \"C\" in the production header, so categorizing changes "
        "nothing. Leaves this list when F-7 lands.",
        frozenset({
            ("test-utils", "shekyl-archival-retention", "dev"),
            ("test-utils", "shekyl-ffi", "normal"),
            ("test-utils", "shekyl-p-fetch", "dev"),
            ("test-utils", "shekyl-p-serve", "normal"),
            ("test-utils", "shekyl-tx-builder", "dev"),
        }),
    ),
    "shekyl-curve-generators": (
        "categorization only",
        frozenset({
            ("std", "shekyl-bulletproofs", "build"),
            ("std", "shekyl-curve-primitives", "normal"),
            ("std", "shekyl-fcmp-proofs", "build"),
            ("std", "shekyl-scanner", "normal"),
        }),
    ),
    "shekyl-curve-io": (
        "categorization only",
        frozenset({
            ("std", "shekyl-bulletproofs", "normal"),
            ("std", "shekyl-curve-generators", "normal"),
            ("std", "shekyl-rpc-client", "normal"),
            ("std", "shekyl-scanner", "normal"),
        }),
    ),
    "shekyl-curve-primitives": (
        "categorization only",
        frozenset({
            ("std", "shekyl-bulletproofs", "normal"),
            ("std", "shekyl-scanner", "normal"),
        }),
    ),
    "shekyl-curve-tree": (
        "categorization only",
        frozenset({
            ("test-tamper", "shekyl-p-host", "dev"),
        }),
    ),
    "shekyl-engine-core": (
        "categorization only",
        frozenset({
            ("test-helpers", "shekyl-wallet-rpc", "dev"),
        }),
    ),
    "shekyl-fcmp": (
        "categorization only",
        frozenset({
            ("multisig", "shekyl-ffi", "normal"),
        }),
    ),
    "shekyl-fcmp-proofs": (
        "categorization only",
        frozenset({
            ("compile-time-generators", "shekyl-engine-core", "dev"),
            ("compile-time-generators", "shekyl-engine-core", "normal"),
            ("compile-time-generators", "shekyl-fcmp", "normal"),
            ("multisig", "shekyl-fcmp", "normal"),
            ("std", "shekyl-engine-core", "dev"),
            ("std", "shekyl-engine-core", "normal"),
            ("std", "shekyl-fcmp", "normal"),
        }),
    ),
    "shekyl-p-serve": (
        "FINDING: test-signer enabled on NORMAL edges by shekyl-sp-t3-spike (direct) and shekyl-p-host (forwarded via its own test-signer)",
        frozenset({
            ("test-signer", "shekyl-p-fetch", "dev"),
            ("test-signer", "shekyl-p-host", "normal"),
            ("test-signer", "shekyl-sp-t3-spike", "normal"),
        }),
    ),
    "shekyl-pow-randomx": (
        "FINDING: test-internals enabled on a NORMAL edge by shekyl-randomx-differential",
        frozenset({
            ("test-internals", "shekyl-randomx-differential", "normal"),
        }),
    ),
    "shekyl-rpc-client": (
        "categorization only",
        frozenset({
            ("std", "shekyl-daemon-rpc", "normal"),
            ("std", "shekyl-engine-core", "normal"),
            ("std", "shekyl-rpc-transport", "normal"),
            ("std", "shekyl-scanner", "normal"),
            ("std", "shekyl-wallet-rpc", "normal"),
        }),
    ),
    "shekyl-scanner": (
        "categorization only",
        frozenset({
            ("test-utils", "shekyl-engine-core", "dev"),
            ("test-utils", "shekyl-wallet-rpc", "dev"),
        }),
    ),
    "shekyl-standoff": (
        "categorization only",
        frozenset({
            ("conformance", "shekyl-engine-core", "normal"),
            ("conformance", "shekyl-staking-sim", "dev"),
            ("gf7-hooks", "shekyl-engine-core", "normal"),
            ("gf7-hooks", "shekyl-staking-sim", "normal"),
        }),
    ),
    "shekyl-types": (
        "categorization only",
        frozenset({
            ("schema", "shekyl-engine-state", "normal"),
        }),
    ),
    "shekyl-units": (
        "categorization only",
        frozenset({
            ("schema", "shekyl-engine-state", "normal"),
        }),
    ),
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


# One enablement: `consumer` turns on `feature` of `owner` over a dependency
# edge of `kind`, either directly (`via = "edge"`) or by **feature forwarding**
# — an entry `"<dep>/<feature>"` or `"<dep>?/<feature>"` in the consumer's own
# feature table (`via = "feature:<name>"`). Cargo activates the forwarded
# feature whenever the consumer's feature is on, so a forwarded activation is
# an enablement for every limb here (PR #786 review round 4: the direct-edge
# view let a forwarded second consumer bypass the sole-enabler check, and hid
# a cross-crate feature from the trigger). The dep name in a forward is the
# consumer's *alias* for it (`package = "..."` renames), resolved through the
# consumer's dependency list; `"dep:<name>"` entries enable an optional
# dependency and no feature, and are not enablements.
Enablement = tuple[str, str, str, str, str]  # owner, feature, consumer, kind, via


def enablements(meta: dict) -> list[Enablement]:
    """Every (owner, feature, consumer, kind, via) in one `cargo metadata`
    document — direct edges and forwarded features alike."""
    members = {p["name"] for p in meta["packages"]}
    out: list[Enablement] = []
    for consumer in meta["packages"]:
        alias_to_edge: dict[str, tuple[str, str]] = {}
        for dep in consumer["dependencies"]:
            kind = dep.get("kind") or "normal"
            alias = dep.get("rename") or dep["name"]
            alias_to_edge[alias] = (dep["name"], kind)
            for feature in dep.get("features", []):
                out.append((dep["name"], feature, consumer["name"], kind, "edge"))
        for fname, entries in consumer.get("features", {}).items():
            for entry in entries:
                if "/" not in entry or entry.startswith("dep:"):
                    continue
                alias, feature = entry.split("/", 1)
                alias = alias.rstrip("?")
                edge = alias_to_edge.get(alias)
                if edge is None:
                    continue
                owner, kind = edge
                if owner in members:
                    out.append((owner, feature, consumer["name"], kind, f"feature:{fname}"))
    return out


def check_consumer_owned(
    meta: dict, registry: dict[tuple[str, str], tuple[str, str]]
) -> list[str]:
    """The consumer-owned limb, over one `cargo metadata` document."""
    packages = {p["name"]: p for p in meta["packages"]}
    all_enablements = enablements(meta)
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
            {c for (o, f, c, _k, _v) in all_enablements if o == owner and f == feature}
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


def crates_meeting_trigger(meta: dict) -> dict[str, set[tuple[str, str, str]]]:
    """Owner → {(feature, enabling crate, edge kind)} for every workspace
    feature some *other* member's edge enables — the governance trigger."""
    members = {p["name"]: p for p in meta["packages"]}
    hits: dict[str, set[tuple[str, str, str]]] = {}
    for owner, feature, consumer, kind, _via in enablements(meta):
        # A crate's edge on itself is how it turns a feature on for its own
        # tests; it crosses no boundary and is not the trigger.
        if owner == consumer or owner not in members:
            continue
        if feature in members[owner].get("features", {}):
            hits.setdefault(owner, set()).add((feature, consumer, kind))
    return hits


def check_trigger(
    meta: dict,
    governed: frozenset[str],
    grandfathered: dict[str, tuple[str, frozenset[Hit]]],
) -> list[str]:
    """The fourth limb: a crate that meets the trigger is governed, or every
    one of its hits is grandfathered **exactly** — (feature, consumer, kind).
    An owner-keyed exemption would silently cover every future feature and
    enabler of a listed crate, and stay green when the recorded hit vanished
    while another remained (PR #786 review round 4); the exact set is what
    makes the list genuinely shrink-only."""
    failures: list[str] = []
    hits = crates_meeting_trigger(meta)
    for owner in sorted(hits):
        if owner in governed:
            continue
        recorded = grandfathered.get(owner)
        if recorded is None:
            edges = ", ".join(f"{f} ← {c} ({k})" for f, c, k in sorted(hits[owner]))
            failures.append(
                f"{owner}: declares a feature another crate enables ({edges}) and is "
                f"not in GOVERNED_OWNERS — that is the trigger for joining. Add it, "
                f"and categorize each of its features (TEST_ONLY / CONSUMER_OWNED / "
                f"PERMANENT) in the same commit."
            )
            continue
        _note, recorded_hits = recorded
        for f, c, k in sorted(hits[owner] - recorded_hits):
            failures.append(
                f"{owner}: new cross-crate enablement `{f} ← {c} ({k})` on a "
                f"grandfathered crate — the exception covers only the hits it "
                f"recorded. Join GOVERNED_OWNERS and categorize, or record the hit "
                f"with its reason (the list may not grow by omission)."
            )
    for owner, (_note, recorded_hits) in sorted(grandfathered.items()):
        if owner in governed:
            failures.append(
                f"{owner}: both in GOVERNED_OWNERS and in the grandfather list — "
                f"it has joined; delete its grandfather entry"
            )
            continue
        current = hits.get(owner, set())
        for f, c, k in sorted(recorded_hits - current):
            failures.append(
                f"{owner}: grandfathered hit `{f} ← {c} ({k})` no longer exists — "
                f"delete it from the entry (the list only shrinks); if that empties "
                f"the entry, delete the entry"
            )
        if not recorded_hits:
            failures.append(f"{owner}: grandfather entry records no hits — delete it")
    return failures


def _synthetic_forwarded() -> dict:
    """An owner with `cfeat`; `comparator` enables it on a direct edge, and a
    second crate `forwarder` enables it only through its own feature table
    (`x = ["owner/cfeat"]`) over a normal edge that lists no features."""
    return {
        "packages": [
            {"name": "owner", "features": {"cfeat": []}, "dependencies": []},
            {
                "name": "comparator",
                "features": {},
                "dependencies": [{"name": "owner", "features": ["cfeat"], "kind": None}],
            },
            {
                "name": "forwarder",
                "features": {"x": ["owner/cfeat"]},
                "dependencies": [{"name": "owner", "features": [], "kind": None}],
            },
        ]
    }


def _synthetic_self_edge() -> dict:
    """One crate whose only feature is enabled by its own dev-dependency on itself."""
    return {
        "packages": [
            {
                "name": "owner",
                "features": {"cfeat": []},
                "dependencies": [{"name": "owner", "features": ["cfeat"], "kind": "dev"}],
            }
        ]
    }


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
    trigger_cases = [
        (
            "ungoverned crate meets the trigger: red",
            _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset(),
            {},
            ["trigger for joining"],
        ),
        (
            "governed crate meets the trigger: green",
            _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset({"owner"}),
            {},
            [],
        ),
        (
            "grandfathered exact hit meets the trigger: green",
            _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset(),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            [],
        ),
        (
            "grandfather hit gone (no enabler left): red, delete the hit",
            _synthetic({"cfeat": []}, {"comparator": [("owner", [])]}),
            frozenset(),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            ["no longer exists"],
        ),
        (
            "new enabler on a grandfathered crate: red (owner-keyed exemption would hide it)",
            _synthetic(
                {"cfeat": []},
                {"comparator": [("owner", ["cfeat"])], "wallet": [("owner", ["cfeat"])]},
            ),
            frozenset(),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            ["new cross-crate enablement"],
        ),
        (
            "new feature on a grandfathered crate: red",
            _synthetic(
                {"cfeat": [], "other": []},
                {"comparator": [("owner", ["cfeat", "other"])]},
            ),
            frozenset(),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            ["new cross-crate enablement"],
        ),
        (
            "recorded hit vanished while a different hit remains: red (stale substitution)",
            _synthetic({"cfeat": []}, {"wallet": [("owner", ["cfeat"])]}),
            frozenset(),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            ["no longer exists", "new cross-crate enablement"],
        ),
        (
            "grandfathered and governed at once: red",
            _synthetic({"cfeat": []}, {"comparator": [("owner", ["cfeat"])]}),
            frozenset({"owner"}),
            {"owner": ("note", frozenset({("cfeat", "comparator", "normal")}))},
            ["delete its grandfather entry"],
        ),
        (
            "a crate's dev-edge on itself crosses no boundary: green",
            _synthetic_self_edge(),
            frozenset(),
            {},
            [],
        ),
        (
            "forwarded feature (`consumer.features.x = [\"owner/cfeat\"]`) is the trigger too: red",
            _synthetic_forwarded(),
            frozenset(),
            {},
            ["trigger for joining"],
        ),
    ]
    # Forwarding through the consumer's own feature table must count as an
    # enablement for the sole-enabler and the test-only limbs as well.
    fwd = _synthetic_forwarded()
    fwd_owned = check_consumer_owned(fwd, {("owner", "cfeat"): ("comparator", "why")})
    if not any("second consumer" in f for f in fwd_owned):
        bad_pre = [f"forwarded second consumer not seen by the sole-enabler check: {fwd_owned!r}"]
    else:
        bad_pre = []
    fwd_en = enablements(fwd)
    if ("owner", "cfeat", "forwarder", "normal", "feature:x") not in fwd_en:
        bad_pre.append(f"enablements() did not record the forwarded activation: {fwd_en!r}")
    bad: list[str] = list(bad_pre)
    for label, meta, governed, grand, want in trigger_cases:
        got = check_trigger(meta, governed, grand)
        if not want and got:
            bad.append(f"{label}: expected green, got {got!r}")
        for needle in want:
            if not any(needle in f for f in got):
                bad.append(f"{label}: expected a failure containing {needle!r}, got {got!r}")
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
        f"{len(exhaustive_cases) + 1} exhaustiveness cases + "
        f"{len(trigger_cases)} trigger cases held"
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    meta = cargo_metadata()
    packages = {p["name"]: p for p in meta["packages"]}
    all_enablements = enablements(meta)

    failures: list[str] = check_consumer_owned(meta, CONSUMER_OWNED)
    failures += check_exhaustive(meta, GOVERNED_OWNERS, TEST_ONLY, CONSUMER_OWNED, PERMANENT)
    failures += check_trigger(meta, GOVERNED_OWNERS, MET_TRIGGER_UNGOVERNED_AT_REGISTRATION)

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
        for o, f, consumer, kind, via in all_enablements:
            if o != owner or f != feature:
                continue
            if kind == "dev":
                dev_enablers.append(consumer)
            else:
                how = "on a" if via == "edge" else f"by forwarding (`{via}`) over a"
                failures.append(
                    f"{consumer}: enables `{owner}/{feature}` {how} {kind} "
                    f"dependency edge — this feature {why}, and a non-dev edge puts "
                    f"it in builds that ship. Move the feature to the "
                    f"[dev-dependencies] edge."
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
        f"governed feature tables exhaustively categorized: {', '.join(sorted(GOVERNED_OWNERS))}; "
        f"trigger met and grandfathered (shrink-only): "
        f"{len(MET_TRIGGER_UNGOVERNED_AT_REGISTRATION)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
