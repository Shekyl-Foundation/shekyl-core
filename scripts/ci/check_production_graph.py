#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""No shipped build's graph holds the harness, the forge, or a test-only feature.

# What is held

`CHAIN_FORGE.md` §11.1, item 2 (`CF-1b`), over the shipped build graphs
`shipped_graph.py` computes (`CF-R26`): this repository's release
(`cmake/BuildRust.cmake`'s roots in one invocation, with its release
features) and the GUI wallet's (its pinned shekyl-core edges). Every
`[target.*]` table is followed, so the union over the release platforms is
read.

  1. **No harness or forge crate.** `shekyl-harness-spender`,
     `shekyl-harness-wallet` and `shekyl-chain-forge` are not activated in
     either graph (`HARNESS`). An optional edge to one counts only when a
     feature the build turns on activates it: `shekyl-chain-rules` names
     `shekyl-harness-wallet` optionally, under its TEST_ONLY `harness`,
     and no shipped build turns that on.
  2. **No test-only feature on.** After Cargo's feature unification, no
     feature registered TEST_ONLY in `check_test_only_features.py` is
     enabled on any member: every `seeded-rng` (§5.3's seams), the driver's
     `forge`, and the rest of that table, read from it so the two never
     drift.

`check_test_only_features.py` already holds each TEST_ONLY feature to dev
edges by edge kind. This check proves the consequence on the graphs that
ship: the seeded signers and provers, the harness id and the driver are
compiled into none of them, whatever forwards a future manifest adds.

# Every member outside the set is classified

`shipped_graph.classify()`: each member outside both graphs is headed for
production or not shipped, with a reason, and neither table names a crate
a shipped graph links (`CF-R26`). A headed crate is not held here (no
shipped graph has it); the seedable-RNG gate reads it as production code.

# The GUI pin's currency

`--gui-wallet DIR` compares `gui_wallet_core_deps.toml` with the GUI
wallet checked out at `DIR`: its `src-tauri/Cargo.toml`, its release
workflow's `--features` and tauri's `build.features`. `gui-drift.yml`'s
`gui-pin` job runs it at the wallet branch that workflow resolves.

# Rule 47

`shipped_graph.py` asserts its roots (`shekyld` among them, each a member)
and the release features' reading. Here each graph must be non-empty, and
the GUI graph must activate every crate its pin names. `--selftest` plants a
harness crate on a normal edge, a forwarded `seeded-rng`, a TEST_ONLY
feature enabled only on a dev edge (green), a missing root sentinel, and a
harness crate or TEST_ONLY feature reached only through the GUI pin, and
checks each verdict. It also holds the set itself: a crate one platform
alone pulls in, one only a release feature pulls in, and one only the GUI
wallet pulls in must each be in the set, and a measurement-only feature
must not.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from shipped_graph import (  # noqa: E402
    CORE_RELEASE,
    GUI_RELEASE,
    GUI_ROOT,
    GraphError,
    classify,
    graphs,
    live_graphs,
    load_gui_pin,
    member_dirs,
    pin_drift,
    release_features,
    shipped_crates,
)

REPO = Path(__file__).resolve().parents[2]

# Crates no shipped graph may reach: the test-support spender and wallet, and
# the chain forge (CHAIN_FORGE.md §11.1).
HARNESS = ("shekyl-harness-spender", "shekyl-harness-wallet", "shekyl-chain-forge")

BUILD_NAMES = {CORE_RELEASE: "this repository's release", GUI_RELEASE: "the GUI wallet's release"}


def test_only_rows() -> set[tuple[str, str]]:
    """(crate, feature) for every TEST_ONLY row of check_test_only_features.py."""
    path = REPO / "scripts" / "ci" / "check_test_only_features.py"
    spec = importlib.util.spec_from_file_location("check_test_only_features", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return set(module.TEST_ONLY)


def check(
    by_build: dict[str, dict[str, set[str]]],
    gui_pin: dict,
    test_only: set[tuple[str, str]],
) -> list[str]:
    errors: list[str] = []
    for build, graph in by_build.items():
        name = BUILD_NAMES[build]
        if not graph:
            errors.append(f"{name}: its graph is empty, so this check has no subject")
        for crate in HARNESS:
            if crate in graph:
                errors.append(
                    f"{name} activates {crate}, which is test support and must never ship "
                    "(CHAIN_FORGE.md §11.1)"
                )
        for crate, features in sorted(graph.items()):
            for feature in sorted(features):
                if (crate, feature) in test_only:
                    errors.append(
                        f"{name} resolves {crate}/{feature} on, a TEST_ONLY feature "
                        "(check_test_only_features.py), so a shipped build would carry it"
                    )
    pinned = set(gui_pin.get("dependencies", {}))
    missing = sorted(pinned - set(by_build.get(GUI_RELEASE, {})))
    if missing:
        errors.append(
            f"the GUI wallet's graph lacks {missing}, which its pin names: the pin was not "
            "read as a root (rule 47)"
        )
    return errors


def selftest() -> int:
    def manifest(name: str, deps: dict, features: dict | None = None, dev: dict | None = None,
                 target: dict | None = None) -> dict:
        m = {"package": {"name": name}, "dependencies": deps, "features": features or {}}
        if dev:
            m["dev-dependencies"] = dev
        if target:
            m["target"] = target
        return m

    base = {
        "shekyld": manifest("shekyld", {"lib": {"path": "../lib"}}),
        "lib": manifest("lib", {}, {"seeded-rng": []}),
        "shekyl-harness-spender": manifest("shekyl-harness-spender", {}),
        "wallet-core": manifest("wallet-core", {}),
    }
    pin = {"package": {"name": GUI_ROOT}, "dependencies": {"wallet-core": {}}}
    rows = {("lib", "seeded-rng")}
    roots = ["shekyld"]
    cases = [
        ("clean graphs: green", base, roots, pin, False),
        (
            "a harness crate on a normal edge: red",
            {**base, "shekyld": manifest("shekyld", {
                "lib": {"path": "../lib"},
                "shekyl-harness-spender": {"path": "../x"},
            })},
            roots, pin, True,
        ),
        (
            "seeded-rng forwarded on: red",
            {**base, "shekyld": manifest(
                "shekyld", {"lib": {"path": "../lib"}}, {"default": ["lib/seeded-rng"]},
            )},
            roots, pin, True,
        ),
        (
            "seeded-rng on a dev edge only: green",
            {**base, "shekyld": manifest(
                "shekyld", {"lib": {"path": "../lib"}},
                dev={"lib": {"path": "../lib", "features": ["seeded-rng"]}},
            )},
            roots, pin, False,
        ),
        (
            "a harness crate optional and not activated: green",
            {**base, "lib": manifest(
                "lib", {"shekyl-harness-spender": {"path": "../x", "optional": True}},
                {"seeded-rng": [], "harness": ["dep:shekyl-harness-spender"]},
            )},
            roots, pin, False,
        ),
        (
            "a harness crate optional and activated by default: red",
            {**base, "lib": manifest(
                "lib", {"shekyl-harness-spender": {"path": "../x", "optional": True}},
                {"seeded-rng": [], "default": ["dep:shekyl-harness-spender"]},
            )},
            roots, pin, True,
        ),
        (
            "a harness crate reached only through the GUI pin: red",
            base, roots,
            {**pin, "dependencies": {"wallet-core": {}, "shekyl-harness-spender": {}}},
            True,
        ),
        (
            "seeded-rng turned on only by the GUI pin's edge: red",
            base, roots,
            {**pin, "dependencies": {"wallet-core": {}, "lib": {"features": ["seeded-rng"]}}},
            True,
        ),
        ("the root sentinel is missing: red", base, ["other"], pin, True),
    ]
    failed = 0
    for name, members, rs, p, want in cases:
        try:
            errors = check(graphs(members, {}, rs, [], p), p, rows)
        except GraphError as e:
            errors = [str(e)]
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")

    # The set itself: what must be in it, and what must not.
    members = {
        "shekyld": manifest(
            "shekyld",
            {"lib": {"path": "../lib"}, "feature-only": {"path": "../f", "optional": True}},
            {"extra": ["dep:feature-only"]},
            target={"cfg(windows)": {"dependencies": {"windows-only": {"path": "../w"}}}},
        ),
        "lib": manifest("lib", {"measure-only": {"path": "../m", "optional": True}},
                        {"measure": ["dep:measure-only"]}),
        "windows-only": manifest("windows-only", {}),
        "feature-only": manifest("feature-only", {}),
        "measure-only": manifest("measure-only", {}),
        "wallet-core": manifest("wallet-core", {}),
    }
    cmake = (
        "if(NOT IOS)\n"
        "  set(_shekyl_rust_bin_features --features shekyld/extra)\n"
        "  if(SHEKYL_MEASUREMENT_SPANS)\n"
        "    set(_shekyl_rust_bin_features --features lib/measure)\n"
        "  endif()\n"
        "endif()\n"
    )
    in_set = [
        ("a crate one platform alone pulls in", "windows-only"),
        ("a crate only a release feature pulls in", "feature-only"),
        ("a crate only the GUI wallet pulls in", "wallet-core"),
    ]
    try:
        shipped = shipped_crates(graphs(members, {}, ["shekyld"], release_features(cmake), pin))
    except GraphError as e:
        print(f"selftest FAIL: the set's own case raised: {e}")
        return 1
    for name, crate in in_set:
        if crate in shipped:
            print(f"selftest ok: {name} is in the set")
        else:
            print(f"selftest FAIL: {name} ({crate}) dropped out of the set")
            failed = 1
    if "measure-only" in shipped:
        print("selftest FAIL: a measurement-only feature's crate is in the release set")
        failed = 1
    else:
        print("selftest ok: a measurement-only feature's crate is not in the release set")
    refused = [
        ("a features set under another conditional",
         "if(FOO)\n  set(_shekyl_rust_bin_features --features shekyld/extra)\nendif()\n"),
        ("no features set at all", "set(_other x)\n"),
    ]
    for name, text in refused:
        try:
            release_features(text)
            print(f"selftest FAIL: {name} was read, not refused")
            failed = 1
        except GraphError:
            print(f"selftest ok: {name} is refused")
    try:
        graphs(members, {}, ["shekyld"], ["nowhere/x"], pin)
        print("selftest FAIL: a release feature naming an unreached package was accepted")
        failed = 1
    except GraphError:
        print("selftest ok: a release feature naming an unreached package is refused")

    # Every member outside the set is classified (CF-R26).
    in_graph = {"shekyld", "lib"}
    classify_cases = [
        ("every outsider classified: green", {"shekyld", "lib", "soon", "tool"},
         {"soon": "ships later"}, {"tool": "a harness"}, False),
        ("a headed crate already in the graph: red", {"shekyld", "lib", "tool"},
         {"lib": "ships later"}, {"tool": "a harness"}, True),
        ("a not-shipped crate now in the graph: red", {"shekyld", "lib"},
         {}, {"lib": "a harness"}, True),
        ("an unclassified outsider: red", {"shekyld", "lib", "new"}, {}, {}, True),
        ("a row for a crate that is not a member: red", {"shekyld", "lib"},
         {"gone": "ships later"}, {}, True),
        ("a crate in both tables: red", {"shekyld", "lib", "x"},
         {"x": "ships later"}, {"x": "a harness"}, True),
    ]
    for name, all_members, headed, not_shipped, want in classify_cases:
        errors = classify(all_members, in_graph, headed, not_shipped)
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")

    # The pin's currency.
    gui = {
        "package": {"name": "shekyl-wallet"},
        "dependencies": {
            "serde": "1",
            "wallet-core": {"path": "../../shekyl-core/rust/wallet-core"},
        },
        "dev-dependencies": {"lib": {"path": "../../shekyl-core/rust/lib"}},
        "features": {"default": [], "multisig": []},
    }
    gui_pin = {"release-features": [], **pin, "features": {"default": [], "multisig": []}}
    drift = [
        ("the pin equals the manifest: green", gui, "", [], False),
        ("the manifest adds a shekyl-core edge: red",
         {**gui, "dependencies": {**gui["dependencies"],
                                  "lib": {"path": "../../shekyl-core/rust/lib"}}}, "", [], True),
        ("the manifest re-features an edge: red",
         {**gui, "dependencies": {**gui["dependencies"], "wallet-core": {
             "path": "../../shekyl-core/rust/wallet-core", "features": ["x"]}}}, "", [], True),
        ("the release passes a feature: red", gui, "npx tauri build --features multisig", [],
         True),
        ("tauri's build.features names one: red", gui, "",
         [{"build": {"features": ["multisig"]}}], True),
    ]
    for name, manifest_, workflow, configs, want in drift:
        errors = pin_drift(gui_pin, manifest_, workflow, configs)
        if bool(errors) != want:
            print(f"selftest FAIL: {name}: {errors}")
            failed = 1
        else:
            print(f"selftest ok: {name}")
    return failed


def gui_drift(wallet: Path) -> int:
    with (wallet / "src-tauri" / "Cargo.toml").open("rb") as f:
        manifest = tomllib.load(f)
    workflow = (wallet / ".github" / "workflows" / "release.yml").read_text()
    configs = [
        json.loads(p.read_text()) for p in sorted((wallet / "src-tauri").glob("tauri*.conf.json"))
    ]
    if not configs:
        print("FAIL: no tauri config read: the release's features have no subject")
        return 1
    errors = pin_drift(load_gui_pin(), manifest, workflow, configs)
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        print("Update scripts/ci/gui_wallet_core_deps.toml with the GUI wallet's change.")
        return 1
    pinned = load_gui_pin().get("dependencies", {})
    print(f"PASS: the pin matches the GUI wallet's manifest ({len(pinned)} shekyl-core edge(s)) "
          f"and its release's features ({len(configs)} tauri config(s) read)")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "--selftest" in args:
        return selftest()
    if "--gui-wallet" in args:
        return gui_drift(Path(args[args.index("--gui-wallet") + 1]))
    rows = test_only_rows()
    if not rows:
        print("FAIL: no TEST_ONLY row read: the feature check has no subject", file=sys.stderr)
        return 1
    try:
        by_build = live_graphs()
    except GraphError as e:
        print(f"FAIL: {e}")
        return 1
    errors = check(by_build, load_gui_pin(), rows)
    errors += classify(set(member_dirs()), shipped_crates(by_build))
    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1
    sizes = ", ".join(f"{BUILD_NAMES[b]} {len(g)}" for b, g in by_build.items())
    print(
        f"PASS: the shipped graphs ({sizes} members; {len(shipped_crates(by_build))} in all) "
        f"reach none of {', '.join(HARNESS)} and resolve none of {len(rows)} TEST_ONLY "
        "feature(s) on; every member outside them is classified headed for production or "
        "not shipped"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
