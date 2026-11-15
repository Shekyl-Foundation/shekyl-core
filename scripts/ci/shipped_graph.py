# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The crates the shipped binaries build: one set, read by every gate that
needs it.

# What the set is

`CHAIN_FORGE.md` §5.5 (`CF-R26`, Rick, 2026-11-15): production code is the
crates the shipped binaries build. Two release builds link shekyl-core
crates:

  1. **This repository's release.** `cmake/BuildRust.cmake` builds its roots
     (`shekyld`, `shekyl-cli`, `shekyl-wallet-rpc`) in one cargo invocation,
     with the features that file passes outside the measurement build.
  2. **The GUI wallet's release.** `shekyl-gui-wallet` links shekyl-core
     crates by path. Its manifest lives in another repository, so the
     shekyl-core crates it names, with each edge's features, are pinned in
     `gui_wallet_core_deps.toml` beside this file, together with the
     cargo features its release build passes. `gui-drift.yml`'s
     `gui-pin` job compares the pin with the GUI wallet's own manifest and
     release workflow at the wallet branch that job resolves, and fails
     when they differ.

Each build is resolved as a release resolves it: Cargo's feature
unification (`check_p_fetch_dep_cut.py`'s resolver, imported) from a root
that depends on every package of the invocation, with the release
features on. Every `[target.*]` dependency table is followed, so a crate
one platform alone pulls in is in the set: the union over the platforms
the releases build for. Dev-dependencies are not followed; a test build is
not a shipped graph.

A crate is in the set when either build activates it. Its feature set is
reported per build; the gates that read the set decide what to do with it.

# Failing closed

A `set(_shekyl_rust_bin_features ...)` this reading cannot place (inside
the measurement block or outside every conditional) is an error, as is a
release feature naming a package neither the roots nor their graph reach.
A guess there would quietly drop or add a crate.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_p_fetch_dep_cut import (  # noqa: E402
    BUILD_RUST,
    ROOT_SENTINEL,
    closure,
    resolve_features,
    shipped_roots,
)

REPO = Path(__file__).resolve().parents[2]
RUST_DIR = REPO / "rust"
GUI_PIN = Path(__file__).resolve().parent / "gui_wallet_core_deps.toml"

# The name the GUI wallet's package has in the pin and in the set's reports.
GUI_ROOT = "shekyl-gui-wallet"
# The synthetic roots standing for each release invocation. Neither is a
# crate name cargo accepts, so neither can collide with a member.
CORE_RELEASE = "<core release>"
GUI_RELEASE = "<gui release>"

# The CMake option whose block holds the measurement build's features
# (BuildRust.cmake), never a release's.
MEASUREMENT_OPTION = "SHEKYL_MEASUREMENT_SPANS"
FEATURES_VAR = "_shekyl_rust_bin_features"


class GraphError(ValueError):
    """The set cannot be computed without guessing."""


def member_dirs() -> dict[str, Path]:
    """Each workspace member's package name and directory, read from the
    manifests (no toolchain: the grep-gates job has none)."""
    with (RUST_DIR / "Cargo.toml").open("rb") as f:
        root = tomllib.load(f)
    out: dict[str, Path] = {}
    for member in root["workspace"]["members"]:
        path = RUST_DIR / member
        with (path / "Cargo.toml").open("rb") as f:
            out[tomllib.load(f)["package"]["name"]] = path
    return out


def release_features(text: str) -> list[str]:
    """The `--features` BuildRust.cmake passes in a release build.

    Every `set(_shekyl_rust_bin_features ...)` is placed by the `if()`
    blocks around it. One inside an `if(SHEKYL_MEASUREMENT_SPANS)` block is
    the measurement build's and is skipped (`check_measurement_spans.py`
    refuses that option on a release path). One under no conditional, or
    only under `if(NOT IOS)` (no release targets iOS, so every release takes
    that branch), is the release's. One under any other conditional is
    refused: this reading cannot say whether a release takes that branch.
    """
    found: list[str] = []
    placed = 0
    stack: list[str] = []
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip()
        opener = re.match(r"(?i)if\s*\((.*)\)\s*$", code)
        if opener:
            stack.append(opener.group(1))
            continue
        if re.match(r"(?i)endif\s*\(", code):
            if stack:
                stack.pop()
            continue
        setter = re.match(rf"set\(\s*{FEATURES_VAR}\b(.*)\)\s*$", code)
        if not setter:
            continue
        placed += 1
        if any(MEASUREMENT_OPTION in cond for cond in stack):
            continue
        conditions = [c for c in stack if not re.fullmatch(r"\s*NOT\s+IOS\s*", c)]
        if conditions:
            raise GraphError(
                f"BuildRust.cmake sets {FEATURES_VAR} under `if({conditions[-1]})`: "
                "whether a release takes that branch is not read here, so the release's "
                "features cannot be known"
            )
        args = setter.group(1).replace('"', " ").split()
        it = iter(args)
        for arg in it:
            if arg == "--features":
                found += next(it, "").split(",")
            elif arg.startswith("--features="):
                found += arg.split("=", 1)[1].split(",")
            elif arg:
                raise GraphError(f"BuildRust.cmake: {FEATURES_VAR} carries {arg!r}, not read here")
    if placed == 0:
        raise GraphError(
            f"BuildRust.cmake sets no {FEATURES_VAR}: the release's features were not read "
            "from the file meant (rule 47)"
        )
    return [f for f in found if f]


def load_gui_pin(path: Path = GUI_PIN) -> dict:
    with path.open("rb") as f:
        pin = tomllib.load(f)
    if pin.get("package", {}).get("name") != GUI_ROOT:
        raise GraphError(f"{path.name}: [package] name must be {GUI_ROOT!r}")
    return pin


def release_root(name: str, roots: list[str], features: list[str], members: dict,
                 workspace_deps: dict) -> dict:
    """A manifest standing for one cargo invocation: it depends on every
    root, and carries each `pkg/feat` (or a root's own `feat`) on the edge
    to that package, as `--features` would set it."""
    deps: dict[str, dict] = {root: {"features": []} for root in roots}
    reached: set[str] = set()
    for root in roots:
        reached |= set(closure(root, members, workspace_deps))
    for feature in features:
        if "/" in feature:
            package, sub = feature.split("/", 1)
        elif len(roots) == 1:
            package, sub = roots[0], feature
        else:
            raise GraphError(
                f"release feature {feature!r} names no package, and the invocation builds "
                f"{len(roots)}: cargo would refuse it"
            )
        if package not in reached:
            raise GraphError(
                f"release feature {feature!r} names {package}, which no root of the "
                "invocation reaches"
            )
        deps.setdefault(package, {"features": []})["features"].append(sub)
    return {"package": {"name": name}, "dependencies": deps, "features": {}}


def graphs(
    members: dict[str, dict],
    workspace_deps: dict,
    roots: list[str],
    core_features: list[str],
    gui_pin: dict,
) -> dict[str, dict[str, set[str]]]:
    """Each release build's resolved graph: crate -> its features on."""
    if ROOT_SENTINEL not in roots:
        raise GraphError(
            f"{ROOT_SENTINEL} is not among the shipped roots ({roots}): the parse did not "
            "read the file it meant to (rule 47)"
        )
    for root in roots:
        if root not in members:
            raise GraphError(f"shipped root {root} is not a workspace member")
    if GUI_ROOT in members:
        raise GraphError(f"{GUI_ROOT} is a workspace member here; the pin would shadow it")
    every = dict(members)
    every[CORE_RELEASE] = release_root(CORE_RELEASE, roots, core_features, members, workspace_deps)
    every[GUI_ROOT] = gui_pin
    every[GUI_RELEASE] = release_root(
        GUI_RELEASE, [GUI_ROOT], list(gui_pin.get("release-features", [])), every, workspace_deps
    )
    out: dict[str, dict[str, set[str]]] = {}
    for build in (CORE_RELEASE, GUI_RELEASE):
        resolved = resolve_features(build, every, workspace_deps)
        out[build] = {
            crate: feats for crate, feats in resolved.items()
            if crate in members
        }
    return out


def shipped_crates(graph_by_build: dict[str, dict[str, set[str]]]) -> set[str]:
    """Every workspace member any release build activates."""
    return {crate for graph in graph_by_build.values() for crate in graph}


def live_graphs() -> dict[str, dict[str, set[str]]]:
    """The two release graphs of this tree."""
    from check_p_fetch_dep_cut import workspace_members

    members, workspace_deps = workspace_members()
    text = BUILD_RUST.read_text()
    return graphs(members, workspace_deps, shipped_roots(text), release_features(text),
                  load_gui_pin())


# ─────────────────────────────────────────────── the GUI pin's currency ──

CORE_PATH = re.compile(r"(^|/)shekyl-core/rust/")
DEP_KINDS = ("dependencies", "build-dependencies")


def _core_deps(table: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for key, spec in table.items():
        if isinstance(spec, dict) and CORE_PATH.search(str(spec.get("path", ""))):
            out[key] = {k: v for k, v in spec.items() if k != "path"}
    return out


def gui_projection(manifest: dict) -> dict:
    """What of the GUI wallet's manifest the pin must equal: its shekyl-core
    path dependencies on shipped edges (every target's too), each with its
    spec less the path, and its feature table, keeping in each feature only
    the entries that name another feature or a shekyl-core dependency."""
    projection: dict = {"package": {"name": GUI_ROOT}}
    kept_keys: set[str] = set()
    for kind in DEP_KINDS:
        deps = _core_deps(manifest.get(kind, {}))
        if deps:
            projection[kind] = deps
            kept_keys |= set(deps)
    for target, tables in manifest.get("target", {}).items():
        for kind in DEP_KINDS:
            deps = _core_deps(tables.get(kind, {}))
            if deps:
                projection.setdefault("target", {}).setdefault(target, {})[kind] = deps
                kept_keys |= set(deps)
    features: dict[str, list[str]] = {}
    for name, entries in manifest.get("features", {}).items():
        kept = []
        for entry in entries:
            dep = entry[4:] if entry.startswith("dep:") else entry.split("/", 1)[0].rstrip("?")
            if "/" not in entry and not entry.startswith("dep:"):
                kept.append(entry)
            elif dep in kept_keys:
                kept.append(entry)
        features[name] = kept
    projection["features"] = features
    return projection


def gui_release_features(workflow: str, configs: list[dict]) -> set[str]:
    """The cargo features the GUI wallet's release passes: every
    `--features` in its release workflow, and tauri's `build.features` in
    each config the release reads."""
    found: set[str] = set()
    for m in re.finditer(r"--features[ =]+[\"']?([\w,/:?-]+)", workflow):
        found |= {f for f in m.group(1).split(",") if f}
    for config in configs:
        found |= set(config.get("build", {}).get("features", []) or [])
    return found


def pin_drift(pin: dict, manifest: dict, workflow: str, configs: list[dict]) -> list[str]:
    errors: list[str] = []
    want = gui_projection(manifest)
    have = {k: v for k, v in pin.items() if k != "release-features"}
    if have != want:
        for key in sorted(set(have) | set(want)):
            if have.get(key) != want.get(key):
                errors.append(
                    f"gui_wallet_core_deps.toml [{key}] differs from the GUI wallet's manifest: "
                    f"pinned {have.get(key)!r}, manifest {want.get(key)!r}"
                )
    released = gui_release_features(workflow, configs)
    pinned = set(pin.get("release-features", []))
    if released != pinned:
        errors.append(
            f"the GUI wallet's release passes features {sorted(released)}; the pin's "
            f"release-features are {sorted(pinned)}"
        )
    return errors
