#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `SF-D4` dependency cut, held as a gate rather than a comment.

# What was ruled

`ARCHIVAL_SHARD_FETCH.md` SF-D4 splits the shard-fetch client out as its own
crate, `shekyl-p-fetch`, and rules where its edges may and may not run:

  * the codec is **shared, not mirrored** — the client reads the same
    `serving_route` / frame grammar the server does, from `shekyl-curve-tree`;
  * the client depends on **none of** `shekyl-engine-core`, `shekyl-p-serve`,
    `shekyl-p-host`, or `shekyl-p-transport` (wallet-side; the client is the
    daemon's), and none of them depends on it — the two ends of the route are
    siblings under one grammar, never each other's dependency;
  * the SOCKS dial (`tokio-socks`) enters **no consensus, chain-store, or RPC
    crate** — a daemon that could not fetch would still validate, store, and
    answer;
  * `shekyl-p-serve`'s `test-signer` feature (an ephemeral attestation key
    that signs for anyone) is **unreachable from every graph that ships**.

Each of those is one wrong `Cargo.toml` line away from being false, the code
compiles either way, and nothing else in CI would notice. This gate notices.

# How it reads the graph

Manifests, not `cargo metadata`: the bundled grep-gates job has no Rust
toolchain, and the properties above are all statements about *declared*
workspace-internal edges, which the manifests carry in full. Path
dependencies are followed transitively over `[dependencies]`,
`[build-dependencies]`, and every `[target.*]` variant of both;
`[dev-dependencies]` are **not** followed — a test build is not a shipped
graph, and `resolver = "2"` keeps dev-only feature unification out of release
targets (the premise `check_test_only_features.py` documents). External
crates (`tokio-socks`) are matched by name on the same edges.

The shipped roots are the packages `cmake/BuildRust.cmake` actually builds:
`shekyl-ffi`, `shekyl-daemon-image`, `shekyl-cli`, `shekyl-wallet-rpc`. A
workspace member outside every shipped closure (the `SP-T3` measurement rig
enables `test-signer` on a normal edge, and is allowed to: it is a binary
nothing installs) is not a shipped graph, which is why `test-signer` is held
here rather than in `check_test_only_features.py`'s edge-kind rule.

Rule 47 throughout: every negative limb is paired with a positive one that
would fail if the subject it protects went missing — `shekyl-p-fetch` exists
and does depend on the shared codec and on `tokio-socks`; `test-signer` is
declared and at least one dev edge enables it. A cut that cannot be observed
holding is not a cut.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

RUST_DIR = Path(__file__).resolve().parents[2] / "rust"

CLIENT = "shekyl-p-fetch"
SERVER = "shekyl-p-serve"
SOCKS = "tokio-socks"

# The client reaches the grammar here and nowhere else (codec shared, not
# mirrored). The positive limb of the cut.
CLIENT_MUST_REACH = ("shekyl-curve-tree", "shekyl-archival-retention", SOCKS)

# Serving-side and wallet-side crates the client must not reach, and which
# must not reach the client. Named, not inferred: a new serving crate is added
# here deliberately, with the SF-D4 amendment that admits it.
CLIENT_CUT = (
    "shekyl-engine-core",
    SERVER,
    "shekyl-p-host",
    "shekyl-p-transport",
    "shekyl-tor-control-client",
    "shekyl-tor-control-wallet",
    "shekyl-tor-control-daemon",
)

# Crates whose closure must never carry a SOCKS dial at all. Consensus, the
# store, the shared grammar, and the server: a daemon that cannot fetch still
# validates, stores, and serves.
NO_SOCKS = (
    "shekyl-consensus",
    "shekyl-chain-store",
    "shekyl-curve-tree",
    "shekyl-archival-retention",
    SERVER,
)

# Crates whose closure must never carry the fetch *client*. The RPC crates are
# here and not in NO_SOCKS on purpose: `shekyl-daemon-rpc` already reaches
# `tokio-socks` through `shekyl-rpc-transport`'s own SOCKS5h connector (RT-1,
# ruled long before SF-D4), so "no SOCKS" there would fail on a pre-existing
# edge that is not this cut's subject. What SF-D4 keeps out of RPC is the
# shard-fetch client and its dial.
NO_CLIENT = (*NO_SOCKS, "shekyl-daemon-rpc", "shekyl-rpc-types")

# What `cmake/BuildRust.cmake` builds. Adding a shipped package there means
# adding it here in the same change; a root this list does not name is a
# graph this gate does not read.
SHIPPED_ROOTS = ("shekyl-ffi", "shekyl-daemon-image", "shekyl-cli", "shekyl-wallet-rpc")

# (crate, feature) pairs that must not be enabled on any edge inside a shipped
# closure. `shekyl-p-host/test-signer` forwards to `shekyl-p-serve/test-signer`,
# so both spellings are held.
TEST_ONLY = ((SERVER, "test-signer"), ("shekyl-p-host", "test-signer"))

Edge = tuple[str, str, tuple[str, ...]]  # (kind, dep name, enabled features)


def load_manifest(name: str) -> dict:
    path = RUST_DIR / name / "Cargo.toml"
    if not path.is_file():
        sys.exit(f"FAIL: {path} is missing; the cut cannot be read without it (rule 47).")
    with path.open("rb") as f:
        return tomllib.load(f)


def workspace_members() -> tuple[dict[str, dict], dict]:
    """Members by package name, and the root `[workspace.dependencies]` table."""
    with (RUST_DIR / "Cargo.toml").open("rb") as f:
        root = tomllib.load(f)
    members: dict[str, dict] = {}
    for member in root["workspace"]["members"]:
        manifest = load_manifest(member)
        members[manifest["package"]["name"]] = manifest
    return members, root["workspace"].get("dependencies", {})


def dep_tables(manifest: dict, kinds: tuple[str, ...]) -> list[tuple[str, dict]]:
    """Every dependency table of the given kinds, including `[target.*]` ones."""
    out: list[tuple[str, dict]] = []
    for kind in kinds:
        out.append((kind, manifest.get(kind, {})))
        for target_table in manifest.get("target", {}).values():
            out.append((kind, target_table.get(kind, {})))
    return out


def edges(manifest: dict, kinds: tuple[str, ...], workspace_deps: dict) -> list[Edge]:
    result: list[Edge] = []
    for kind, table in dep_tables(manifest, kinds):
        for key, spec in table.items():
            if isinstance(spec, str):
                spec = {"version": spec}
            if spec.get("workspace"):
                inherited = workspace_deps.get(key, {})
                if isinstance(inherited, str):
                    inherited = {"version": inherited}
                merged = dict(inherited)
                merged["features"] = tuple(inherited.get("features", ())) + tuple(
                    spec.get("features", ())
                )
                spec = merged
            name = spec.get("package", key)
            result.append((kind, name, tuple(spec.get("features", ()))))
    return result


SHIPPED_KINDS = ("dependencies", "build-dependencies")


def closure(root: str, members: dict[str, dict], workspace_deps: dict) -> dict[str, list[Edge]]:
    """Workspace-internal transitive closure over shipped-kind edges.

    Maps each reached member to its own shipped-kind edges (internal and
    external), so callers can ask both "is X reached?" and "does any edge in
    the closure enable feature F?".
    """
    seen: dict[str, list[Edge]] = {}
    stack = [root]
    while stack:
        name = stack.pop()
        if name in seen or name not in members:
            continue
        own = edges(members[name], SHIPPED_KINDS, workspace_deps)
        seen[name] = own
        stack.extend(dep for _, dep, _ in own if dep in members)
    return seen


def reaches(root: str, dep: str, members: dict[str, dict], workspace_deps: dict) -> bool:
    cl = closure(root, members, workspace_deps)
    if dep in cl:
        return True
    return any(name == dep for own in cl.values() for _, name, _ in own)


def main() -> int:
    members, workspace_deps = workspace_members()
    fail = 0

    def failed(msg: str) -> None:
        nonlocal fail
        fail = 1
        print(f"FAIL: {msg}")

    # ── Rule 47: the subjects exist ──────────────────────────────────────
    for name in (CLIENT, SERVER, *CLIENT_MUST_REACH[:-1], *NO_CLIENT, *SHIPPED_ROOTS):
        if name not in members:
            failed(f"{name} is not a workspace member; every limb naming it would pass vacuously.")
    if fail:
        return fail

    # ── Positive limb: the client depends on the shared codec and the dial ──
    for dep in CLIENT_MUST_REACH:
        if not reaches(CLIENT, dep, members, workspace_deps):
            failed(
                f"{CLIENT} no longer depends on {dep}. SF-D4 rules the codec shared, "
                "not mirrored, and the SOCKS dial lives in this crate; a client that "
                "reaches neither is either a copy or not a client."
            )

    # ── The cut, both directions ─────────────────────────────────────────
    for other in CLIENT_CUT:
        if other in members and reaches(CLIENT, other, members, workspace_deps):
            failed(f"{CLIENT} reaches {other}; SF-D4 cuts the client from the serving/wallet side.")
        if other in members and reaches(other, CLIENT, members, workspace_deps):
            failed(f"{other} reaches {CLIENT}; the two ends of the route are siblings, not dependencies.")

    # ── No SOCKS in consensus / store / RPC ──────────────────────────────
    for crate in NO_SOCKS:
        if reaches(crate, SOCKS, members, workspace_deps):
            failed(f"{crate} reaches {SOCKS}; SF-D4 keeps the dial out of consensus, the store, and the server.")
    for crate in NO_CLIENT:
        if reaches(crate, CLIENT, members, workspace_deps):
            failed(f"{crate} reaches {CLIENT}; the fetch client is the scheduler's, not consensus's, the store's, or RPC's.")

    # ── test-signer: declared, dev-enabled somewhere, and out of every shipped graph ──
    for crate, feature in TEST_ONLY:
        if feature not in members[crate].get("features", {}):
            failed(f"{crate} no longer declares `{feature}`; the shipped-graph limb below is vacuous.")
        default = members[crate].get("features", {}).get("default", [])
        if any(feature in entry for entry in default):
            failed(f"{crate}'s `default` feature enables `{feature}`; every consumer would ship it.")
    dev_enables = any(
        (dep, feature) in TEST_ONLY and feature in feats
        for m in members.values()
        for _, dep, feats in edges(m, ("dev-dependencies",), workspace_deps)
        for _, feature in TEST_ONLY
    )
    if not dev_enables:
        failed("no dev-dependency edge enables `test-signer`; a feature nothing tests is a feature nothing guards.")
    for root in SHIPPED_ROOTS:
        for member, own in closure(root, members, workspace_deps).items():
            for kind, dep, feats in own:
                for crate, feature in TEST_ONLY:
                    if dep == crate and feature in feats:
                        failed(
                            f"shipped root {root}: {member}'s [{kind}] edge to {dep} enables "
                            f"`{feature}`. An ephemeral key that signs for anyone is now in a "
                            "release graph."
                        )

    if not fail:
        print(
            f"PASS: SF-D4 holds — {CLIENT} reaches the shared codec and the dial, neither end "
            f"of the route reaches the other, {SOCKS} is out of consensus/store/RPC, and "
            "`test-signer` is out of every shipped graph."
        )
    return fail


if __name__ == "__main__":
    sys.exit(main())
