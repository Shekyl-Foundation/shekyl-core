#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Core's lock is the authority for every package the GUI wallet shares with it.

# What is held

The GUI wallet path-depends on shekyl-core crates and resolves them with its
own `src-tauri/Cargo.lock`. Ruled 2026-11-19: for every registry package
the two locks share, core's `rust/Cargo.lock` is the authority; the GUI lock
pins only what core does not carry. A package the GUI lock carries on a
compatibility line (`1.x`, `0.y`, `0.0.z`) that core's lock also carries
must be at core's version. Each difference is printed with the package,
both versions and both locks.

There is no exclusion list. A package on a line only the GUI carries (the
GTK3 compile-time chain's toml 0.8, say) is not shared and is not compared;
a package on a shared line is compared, whoever pulls it.

Lockfiles only: no cargo, no compile.

  check_gui_lock_shared.py --core rust/Cargo.lock --gui <wallet>/src-tauri/Cargo.lock
  check_gui_lock_shared.py --selftest
"""

from __future__ import annotations

import sys
import tomllib


def compat_line(version: str) -> str:
    core = version.split("+", 1)[0].split("-", 1)[0].split(".")
    if core[0] != "0":
        return core[0]
    if len(core) > 1 and core[1] != "0":
        return "0." + core[1]
    return "0.0." + (core[2] if len(core) > 2 else "0")


def registry_packages(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for p in tomllib.loads(text).get("package", []):
        if str(p.get("source", "")).startswith("registry+"):
            out.setdefault(p["name"], set()).add(p["version"])
    return out


def differences(core: dict[str, set[str]], gui: dict[str, set[str]],
                core_label: str, gui_label: str) -> tuple[list[str], int]:
    """(difference lines, number of shared name+line pairs compared)."""
    errors = []
    shared = 0
    for name in sorted(set(core) & set(gui)):
        by_line = {compat_line(v): v for v in core[name]}
        for got in sorted(gui[name]):
            want = by_line.get(compat_line(got))
            if want is None:
                continue
            shared += 1
            if got != want:
                errors.append(f"{gui_label}: {name} is {got}; {core_label} holds {want}")
    return errors, shared


def selftest() -> int:
    def lock(*pkgs: tuple[str, str]) -> dict[str, set[str]]:
        return registry_packages("".join(
            f'[[package]]\nname = "{n}"\nversion = "{v}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            for n, v in pkgs))

    core = lock(("tokio", "1.54.1"), ("toml", "1.2.1"), ("rand", "0.8.6"))
    cases = [
        ("agreeing shared packages pass", lock(("tokio", "1.54.1"), ("rand", "0.8.6")), 0),
        ("a GUI-only package is not compared", lock(("tokio", "1.54.1"), ("tauri", "2.10.0")), 0),
        ("a GUI-only compat line is not compared", lock(("toml", "0.8.2"), ("toml", "1.2.1")), 0),
        ("a shared package ahead of core fails", lock(("tokio", "1.55.0")), 1),
        ("a shared package behind core fails", lock(("rand", "0.8.5")), 1),
    ]
    failed = 0
    for name, gui, want in cases:
        got = len(differences(core, gui, "core", "gui")[0])
        if got != want:
            print(f"selftest FAIL: {name}: {got} difference(s), expected {want}")
            failed += 1
        else:
            print(f"selftest ok: {name}")
    msg = differences(core, lock(("tokio", "1.55.0")), "rust/Cargo.lock", "src-tauri/Cargo.lock")[0]
    if msg != ["src-tauri/Cargo.lock: tokio is 1.55.0; rust/Cargo.lock holds 1.54.1"]:
        print(f"selftest FAIL: the message names the package, both versions and both locks: {msg}")
        failed += 1
    print("selftest:", "FAIL" if failed else "ok")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    args = dict(zip(argv[::2], argv[1::2]))
    if set(args) != {"--core", "--gui"} or len(argv) != 4:
        print(__doc__)
        return 2
    core = registry_packages(open(args["--core"], encoding="utf-8").read())
    gui = registry_packages(open(args["--gui"], encoding="utf-8").read())
    # Rule 47: both subjects exist. An empty parse compares nothing and passes.
    for label, pkgs in ((args["--core"], core), (args["--gui"], gui)):
        if not pkgs:
            print(f"shared lock: {label} has no registry package")
            return 1
    errors, shared = differences(core, gui, args["--core"], args["--gui"])
    if shared == 0:
        print("shared lock: the two locks share no package; one of them is not the lock it names")
        return 1
    for e in errors:
        print(e)
    if errors:
        print(f"shared lock: {len(errors)} of {shared} shared package(s) differ from core's lock")
        return 1
    print(f"shared lock: {shared} shared package(s) at core's versions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
