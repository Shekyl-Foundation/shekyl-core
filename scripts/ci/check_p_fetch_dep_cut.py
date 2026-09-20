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

Features are **resolved, not grepped**. `test-signer` can be enabled by its
own name on an edge, by a consumer's `default`, by an alias
(`integration = ["shekyl-p-serve/test-signer"]`), by an optional dependency
activated through `dep:` or its implicit feature, or by a weak `dep?/feat`
once the dep is otherwise on. A literal search finds the first of those and
none of the rest, and a valid manifest refactor would walk straight past it.
So the gate runs Cargo's feature-unification rules over the workspace members
from each shipped root and asks what the resolved set for `shekyl-p-serve`
and `shekyl-p-host` actually contains. `--selftest` proves the resolver sees
each of those paths on synthetic manifests, so the negative limb here is
never a grep that happened to find nothing.

The shipped roots are **read from `cmake/BuildRust.cmake`** — the `-p`
packages of its cargo invocations and the `_shekyl_rust_bins` list — not a
second copy held here; a new shipped package added there is inspected here
without a paired edit, and the gate refuses if the parse finds nothing or
finds a name the workspace does not have. A workspace member outside every
shipped closure (the `SP-T3` measurement rig enables `test-signer` on a
normal edge, and is allowed to: it is a binary nothing installs) is not a
shipped graph, which is why `test-signer` is held here rather than in
`check_test_only_features.py`'s edge-kind rule. The RPC crates, likewise,
are every member whose name says `rpc`, anchored by sentinels so a rename
cannot quietly empty the set.

Rule 47 throughout: every negative limb is paired with a positive one that
would fail if the subject it protects went missing — `shekyl-p-fetch` exists
and does depend on the shared codec and on `tokio-socks`; `test-signer` is
declared and at least one dev edge enables it; the resolver detects a planted
forward. A cut that cannot be observed holding is not a cut.
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUST_DIR = REPO / "rust"
BUILD_RUST = REPO / "cmake" / "BuildRust.cmake"

CLIENT = "shekyl-p-fetch"
SERVER = "shekyl-p-serve"
SOCKS = "tokio-socks"

# The client reaches the grammar here and nowhere else (codec shared, not
# mirrored). The positive limb of the cut.
CLIENT_MUST_REACH = (
    "shekyl-curve-tree",
    "shekyl-archival-retention",
    "shekyl-onion-v3",
    SOCKS,
)

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
    # The value contract both stores share (CTS-Q2). Named as its own root,
    # not left to `shekyl-chain-store`'s closure: the wallet store adopts it
    # next, and a root here is what keeps the assertion local to the crate
    # rather than to whichever consumer happens to be listed.
    "shekyl-store-codec",
    "shekyl-curve-tree",
    "shekyl-archival-retention",
    SERVER,
)

# RPC crates are derived (every member whose name carries `rpc`), and these
# two must be among them or the derivation has drifted from the tree. They
# are held out of `NO_SOCKS` on purpose: `shekyl-daemon-rpc` already reaches
# `tokio-socks` through `shekyl-rpc-transport`'s own SOCKS5h connector (RT-1,
# ruled long before SF-D4), so "no SOCKS" there would fail on a pre-existing
# edge that is not this cut's subject. What SF-D4 keeps out of RPC is the
# shard-fetch *client*.
RPC_SENTINELS = ("shekyl-daemon-rpc", "shekyl-rpc-transport")

# The one shipped root that cannot leave `BuildRust.cmake` without the file
# being rewritten: the wallet-side image. Its presence in the parsed set is
# how the gate knows the parse read the file it thinks it read.
ROOT_SENTINEL = "shekyl-ffi"

# (crate, feature) pairs that must not be in any shipped root's resolved
# feature set. `shekyl-p-host/test-signer` forwards to
# `shekyl-p-serve/test-signer`, so both are held.
TEST_ONLY = ((SERVER, "test-signer"), ("shekyl-p-host", "test-signer"))

SHIPPED_KINDS = ("dependencies", "build-dependencies")


@dataclass(frozen=True)
class Edge:
    kind: str
    key: str  # the name used in the manifest (and in `[features]` entries)
    name: str  # the package name (`package = ...` rename honoured)
    features: tuple[str, ...]
    default_features: bool
    optional: bool


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
                if "default-features" in spec:
                    merged["default-features"] = spec["default-features"]
                spec = merged
            result.append(
                Edge(
                    kind=kind,
                    key=key,
                    name=spec.get("package", key),
                    features=tuple(spec.get("features", ())),
                    default_features=bool(spec.get("default-features", True)),
                    optional=bool(spec.get("optional", False)),
                )
            )
    return result


def closure(root: str, members: dict[str, dict], workspace_deps: dict) -> dict[str, list[Edge]]:
    """Workspace-internal transitive closure over shipped-kind edges.

    Maps each reached member to its own shipped-kind edges (internal and
    external), so callers can ask "is X reached?" for members and for
    external crates alike. Optional edges are included: this is the
    *reachability* question, answered conservatively.
    """
    seen: dict[str, list[Edge]] = {}
    stack = [root]
    while stack:
        name = stack.pop()
        if name in seen or name not in members:
            continue
        own = edges(members[name], SHIPPED_KINDS, workspace_deps)
        seen[name] = own
        stack.extend(e.name for e in own if e.name in members)
    return seen


def reaches(root: str, dep: str, members: dict[str, dict], workspace_deps: dict) -> bool:
    cl = closure(root, members, workspace_deps)
    if dep in cl:
        return True
    return any(e.name == dep for own in cl.values() for e in own)


def resolve_features(root: str, members: dict[str, dict], workspace_deps: dict) -> dict[str, set[str]]:
    """Cargo feature unification over the workspace members reachable from `root`.

    Returns, per activated member, the set of its features that end up
    enabled when `root` is built with its own defaults. Follows:

      * plain forwards        `a = ["b"]`
      * dep forwards          `a = ["dep/feat"]` — enables `feat` on `dep`,
                              and turns an optional `dep` on
      * weak dep forwards     `a = ["dep?/feat"]` — enables `feat` on `dep`
                              only if `dep` is otherwise on
      * explicit optional     `a = ["dep:dep"]`
      * implicit optional     an optional dep `dep` is a feature named `dep`
                              unless some entry names it as `dep:dep`
      * per-edge defaults     `default-features = false` on the edge

    External crates are activated by name but have no manifest here, so
    their feature sets are recorded but never expanded. That is sufficient:
    `TEST_ONLY` names workspace members only.
    """
    enabled: dict[str, set[str]] = {}
    weak: list[tuple[str, str, str]] = []  # (member, dep key, feature)

    def own_edges(member: str) -> list[Edge]:
        return edges(members[member], SHIPPED_KINDS, workspace_deps)

    def explicit_dep_keys(member: str) -> set[str]:
        table = members[member].get("features", {})
        return {
            entry[4:]
            for entries in table.values()
            for entry in entries
            if entry.startswith("dep:")
        }

    def activate(member: str, feats: set[str], use_default: bool) -> None:
        first = member not in enabled
        have = enabled.setdefault(member, set())
        todo = set(feats)
        if use_default:
            todo.add("default")
        if member not in members:
            have |= todo
            return
        table = members[member].get("features", {})
        by_key = {e.key: e for e in own_edges(member)}
        explicit = explicit_dep_keys(member)
        if first:
            for e in by_key.values():
                if not e.optional:
                    activate(e.name, set(e.features), e.default_features)
        while todo:
            f = todo.pop()
            if f in have:
                continue
            if f not in table and f not in by_key:
                # `default` absent from the table is the empty feature.
                have.add(f)
                continue
            have.add(f)
            if f in by_key and by_key[f].optional and f not in explicit:
                e = by_key[f]  # implicit optional-dep feature
                activate(e.name, set(e.features), e.default_features)
            for entry in table.get(f, []):
                if entry.startswith("dep:"):
                    e = by_key.get(entry[4:])
                    if e is not None:
                        activate(e.name, set(e.features), e.default_features)
                elif "/" in entry:
                    dep_key, sub = entry.split("/", 1)
                    is_weak = dep_key.endswith("?")
                    dep_key = dep_key.rstrip("?")
                    e = by_key.get(dep_key)
                    if e is None:
                        continue
                    if e.optional and is_weak:
                        weak.append((member, dep_key, sub))
                    elif e.optional:
                        activate(e.name, set(e.features) | {sub}, e.default_features)
                    else:
                        activate(e.name, {sub}, False)
                else:
                    todo.add(entry)

    activate(root, set(), True)
    # Weak forwards settle at a fixpoint: a dep turned on by a later
    # activation picks up every `dep?/feat` that was waiting for it.
    changed = True
    while changed:
        changed = False
        for member, dep_key, sub in list(weak):
            e = {x.key: x for x in own_edges(member)}[dep_key]
            if e.name in enabled and sub not in enabled[e.name]:
                activate(e.name, {sub}, False)
                changed = True
    return enabled


def shipped_roots(text: str) -> list[str]:
    """The packages `BuildRust.cmake` builds: literal `-p <pkg>` arguments and
    the `_shekyl_rust_bins` list. `-p "${var}"` forms are not roots themselves;
    the list they expand from is."""
    roots: list[str] = []
    roots += re.findall(r"(?<![\w-])-p\s+(shekyl-[a-z0-9-]+)", text)
    for group in re.findall(r"set\(\s*_shekyl_rust_bins\s+([^)]*)\)", text):
        roots += re.findall(r"shekyl-[a-z0-9-]+", group)
    return sorted(set(roots))


def rpc_crates(members: dict[str, dict]) -> tuple[str, ...]:
    return tuple(sorted(name for name in members if "rpc" in name))


# ────────────────────────────────────────────────────────────── selftest ──


def selftest() -> int:
    """Synthetic manifests, one per forwarding path the resolver must see."""
    server = {
        "package": {"name": SERVER},
        "features": {"test-signer": ["pq/test-utils"]},
        "dependencies": {"pq": {"path": "../pq"}},
    }
    cases = {
        "direct edge": {
            "package": {"name": "root"},
            "dependencies": {SERVER: {"path": "x", "features": ["test-signer"]}},
        },
        "alias": {
            "package": {"name": "root"},
            "features": {"integration": [f"{SERVER}/test-signer"], "default": ["integration"]},
            "dependencies": {SERVER: {"path": "x"}},
        },
        "consumer default through a middle crate": {
            "package": {"name": "root"},
            "dependencies": {"mid": {"path": "x"}},
            "__extra": {
                "mid": {
                    "package": {"name": "mid"},
                    "features": {"default": ["signing"], "signing": [f"{SERVER}/test-signer"]},
                    "dependencies": {SERVER: {"path": "x"}},
                }
            },
        },
        "explicit optional dep": {
            "package": {"name": "root"},
            "features": {"default": ["dep:srv"]},
            "dependencies": {"srv": {"path": "x", "package": SERVER, "optional": True, "features": ["test-signer"]}},
        },
        "implicit optional dep": {
            "package": {"name": "root"},
            "features": {"default": [SERVER]},
            "dependencies": {SERVER: {"path": "x", "optional": True, "features": ["test-signer"]}},
        },
        "weak forward once the dep is on": {
            "package": {"name": "root"},
            "features": {"default": [f"{SERVER}?/test-signer", "later"], "later": [f"dep:{SERVER}"]},
            "dependencies": {SERVER: {"path": "x", "optional": True}},
        },
        "renamed edge with default-features off": {
            "package": {"name": "root"},
            "dependencies": {"s": {"path": "x", "package": SERVER, "default-features": False, "features": ["test-signer"]}},
        },
    }
    negatives = {
        "plain dependency": {
            "package": {"name": "root"},
            "dependencies": {SERVER: {"path": "x"}},
        },
        "weak forward with the dep never on": {
            "package": {"name": "root"},
            "features": {"default": [f"{SERVER}?/test-signer"]},
            "dependencies": {SERVER: {"path": "x", "optional": True}},
        },
        "dev edge only": {
            "package": {"name": "root"},
            "dependencies": {SERVER: {"path": "x"}},
            "dev-dependencies": {SERVER: {"path": "x", "features": ["test-signer"]}},
        },
    }
    bad = 0
    for expect, table in ((True, cases), (False, negatives)):
        for label, root in table.items():
            members = {SERVER: server, "root": root, **root.pop("__extra", {})}
            got = "test-signer" in resolve_features("root", members, {}).get(SERVER, set())
            if got != expect:
                bad = 1
                print(f"FAIL selftest [{label}]: expected detected={expect}, got {got}")
    cmake = 'cargo build -p shekyl-ffi\n  -p shekyl-daemon-image\nset(_shekyl_rust_bins shekyl-cli shekyl-wallet-rpc)\n-p "${_bin}"\n'
    if shipped_roots(cmake) != ["shekyl-cli", "shekyl-daemon-image", "shekyl-ffi", "shekyl-wallet-rpc"]:
        bad = 1
        print(f"FAIL selftest [cmake parse]: {shipped_roots(cmake)}")
    if not bad:
        print(
            f"PASS selftest: resolver sees {len(cases)} forwarding paths and rejects "
            f"{len(negatives)} non-paths; BuildRust parse yields the four roots."
        )
    return bad


# ────────────────────────────────────────────────────────────────── main ──


def main() -> int:
    members, workspace_deps = workspace_members()
    fail = 0

    def failed(msg: str) -> None:
        nonlocal fail
        fail = 1
        print(f"FAIL: {msg}")

    # ── Rule 47: the subjects exist, and the derived sets read what they claim ──
    for name in (CLIENT, SERVER, *CLIENT_MUST_REACH[:-1], *NO_SOCKS, *RPC_SENTINELS):
        if name not in members:
            failed(f"{name} is not a workspace member; every limb naming it would pass vacuously.")
    rpc = rpc_crates(members)
    for sentinel in RPC_SENTINELS:
        if sentinel not in rpc:
            failed(f"RPC derivation no longer includes {sentinel}; the set has drifted from the tree.")
    if not BUILD_RUST.is_file():
        failed(f"{BUILD_RUST} is missing; the shipped roots cannot be read (rule 47).")
        return fail
    roots = shipped_roots(BUILD_RUST.read_text())
    if not roots:
        failed(f"no shipped roots parsed from {BUILD_RUST.name}; the shipped-graph limb would be vacuous.")
    if ROOT_SENTINEL not in roots:
        failed(f"{ROOT_SENTINEL} not among the roots parsed from {BUILD_RUST.name}: {roots}. The parse no longer reads the build.")
    for root in roots:
        if root not in members:
            failed(f"{BUILD_RUST.name} builds `{root}`, which is not a workspace member.")
    if fail:
        return fail

    # ── Positive limb: the client's *resolved default* graph contains the
    # shared codec, the onion transform, and the dial. `reaches` is
    # conservative (it counts disabled optional edges) and is the right
    # tool for the negative cuts below; here it would stay green if
    # tokio-socks were made optional-and-off. Rule 47: a subject that is
    # not in the default graph is a subject this limb cannot see.
    client_resolved = resolve_features(CLIENT, members, workspace_deps)
    for dep in CLIENT_MUST_REACH:
        if dep not in client_resolved:
            failed(
                f"{CLIENT}'s default graph no longer contains {dep}. SF-D4 rules the "
                "codec shared, not mirrored, the onion hostname is one transform, "
                "and the SOCKS dial lives in this crate; a client that resolves "
                "none of them is either a copy or not a client."
            )

    # ── The cut, both directions ─────────────────────────────────────────
    for other in CLIENT_CUT:
        if other in members and reaches(CLIENT, other, members, workspace_deps):
            failed(f"{CLIENT} reaches {other}; SF-D4 cuts the client from the serving/wallet side.")
        if other in members and reaches(other, CLIENT, members, workspace_deps):
            failed(f"{other} reaches {CLIENT}; the two ends of the route are siblings, not dependencies.")

    # ── No SOCKS in consensus / store / server; no client in those or in RPC ──
    for crate in NO_SOCKS:
        if reaches(crate, SOCKS, members, workspace_deps):
            failed(f"{crate} reaches {SOCKS}; SF-D4 keeps the dial out of consensus, the store, and the server.")
    for crate in (*NO_SOCKS, *rpc):
        if reaches(crate, CLIENT, members, workspace_deps):
            failed(f"{crate} reaches {CLIENT}; the fetch client is the scheduler's, not consensus's, the store's, or RPC's.")

    # ── test-signer: declared, dev-enabled somewhere, and resolved off in every shipped graph ──
    for crate, feature in TEST_ONLY:
        if feature not in members[crate].get("features", {}):
            failed(f"{crate} no longer declares `{feature}`; the shipped-graph limb below is vacuous.")
    # One positive limb per guarded subject (rule 47): a feature nothing
    # tests is a feature nothing guards, and "some test enables one of
    # them" would let one subject go dark while the other keeps the limb lit.
    for crate, feature in TEST_ONLY:
        dev_enables = any(
            e.name == crate and feature in e.features
            for m in members.values()
            for e in edges(m, ("dev-dependencies",), workspace_deps)
        )
        if not dev_enables:
            failed(f"no dev-dependency edge enables `{crate}/{feature}`; a feature nothing tests is a feature nothing guards.")
    for root in roots:
        resolved = resolve_features(root, members, workspace_deps)
        for crate, feature in TEST_ONLY:
            if feature in resolved.get(crate, set()):
                failed(
                    f"shipped root {root}: `{crate}/{feature}` resolves ON. An ephemeral key "
                    "that signs for anyone is in a release graph — follow the forward from "
                    f"{root}'s manifest through defaults and aliases to {crate}."
                )

    if not fail:
        print(
            f"PASS: SF-D4 holds — {CLIENT} reaches the shared codec and the dial, neither end "
            f"of the route reaches the other, {SOCKS} is out of consensus/store/server, the "
            f"client is out of {len(rpc)} RPC crates, and `test-signer` resolves off in all "
            f"{len(roots)} roots {BUILD_RUST.name} builds ({', '.join(roots)})."
        )
    return fail


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
