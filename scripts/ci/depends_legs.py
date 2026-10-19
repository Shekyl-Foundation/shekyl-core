#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Choose the depends.yml cross-build legs a run takes.

The legs are contrib/depends/ci-toolchains.json. A pull request runs:

- every leg when it touches the depends tree, the Makefile, depends.yml or
  this script;
- the MinGW leg (x86_64-w64-mingw32) alone when it touches what decides how
  an executable links (Rick, 2026-10-19): any CMakeLists.txt, anything under
  cmake/, a C header under src/shekyl/ (where every C-callable export is
  declared), or a file of a Rust crate that defines a C export. A crate
  defines one when a source file under its src/ holds `#[no_mangle]`; that
  is read from the tree at the head, not listed by hand, so a crate's first
  export brings it in. MinGW is the one linker the release builds with that
  keeps unreferenced sections: GNU ld on Linux and ld64 on macOS run with
  --gc-sections / -dead_strip, and MSVC with /OPT:REF, so an executable that
  links code it does not resolve fails only there (the shekyl-blockchain-import
  link of 2026-10-19);
- no leg otherwise.

A schedule or a manual dispatch runs every leg.

FAILS CLOSED. An unreadable change set, an unknown event or any error runs
every leg: a wrong "none" skips the build that would have caught a broken
link; a wrong "all" costs runner minutes.

Usage:
  depends_legs.py --event <name> [--base <sha> --head <sha>]
      writes legs=<json list> to $GITHUB_OUTPUT (or stdout)
  depends_legs.py --selftest
"""

import argparse
import fnmatch
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLCHAINS = "contrib/depends/ci-toolchains.json"
MINGW = "x86_64-w64-mingw32"
SELF = "scripts/ci/depends_legs.py"

# Every leg.
FULL = ("contrib/depends/*", "Makefile", ".github/workflows/depends.yml", SELF)
# The MinGW leg: how an executable links.
LINK = ("CMakeLists.txt", "*/CMakeLists.txt", "cmake/*", "src/shekyl/*.h")


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def export_crates(root):
    """Rust crates under rust/ whose src/ defines a C export."""
    crates = set()
    rust = root / "rust"
    for source in rust.glob("*/src/**/*.rs"):
        rel = source.relative_to(rust)
        if rel.parts[0] == "shekyl-oxide":
            continue
        if "#[no_mangle]" in source.read_text(encoding="utf-8", errors="replace"):
            crates.add(rel.parts[0])
    return crates


def scope(changed, crates):
    """'all', 'mingw' or 'none' for a pull request's changed paths."""
    if not changed:
        return "all"
    if any(matches(p, FULL) for p in changed):
        return "all"
    for path in changed:
        if matches(path, LINK):
            return "mingw"
        parts = pathlib.PurePosixPath(path).parts
        if len(parts) >= 2 and parts[0] == "rust" and parts[1] in crates:
            return "mingw"
    return "none"


def legs(choice, toolchains):
    if choice == "all":
        return toolchains
    if choice == "mingw":
        return [t for t in toolchains if t["host"] == MINGW]
    return []


def changed_files(base, head):
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


def write(chosen, why):
    line = f"legs={json.dumps(chosen, separators=(',', ':'))}"
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as out:
            out.write(line + "\n")
    print(f"depends legs: {why}: {[t['name'] for t in chosen]}")


def selftest():
    toolchains = [
        {"name": "ARM v8", "host": "aarch64-linux-gnu"},
        {"name": "Win64", "host": MINGW},
        {"name": "x86_64 Linux", "host": "x86_64-unknown-linux-gnu"},
    ]
    crates = {"shekyl-ffi", "shekyl-daemon"}
    cases = {
        "a depends package": (["contrib/depends/packages/boost.mk"], "all"),
        "the Makefile": (["Makefile"], "all"),
        "this workflow": ([".github/workflows/depends.yml"], "all"),
        "this script": ([SELF], "all"),
        "the root CMakeLists.txt": (["CMakeLists.txt"], "mingw"),
        "a nested CMakeLists.txt": (["src/blockchain_utilities/CMakeLists.txt"], "mingw"),
        "a cmake module": (["cmake/BuildRust.cmake"], "mingw"),
        "an FFI header": (["src/shekyl/shekyl_ffi.h"], "mingw"),
        "an export crate's file": (["rust/shekyl-daemon/src/run.rs"], "mingw"),
        "an export crate's manifest": (["rust/shekyl-ffi/Cargo.toml"], "mingw"),
        "a crate with no export": (["rust/shekyl-dialer/src/lib.rs"], "none"),
        "docs only": (["docs/FOLLOWUPS.md"], "none"),
        "C++ outside the headers": (["src/p2p/net_node.inl"], "none"),
        "depends beats link": (["CMakeLists.txt", "Makefile"], "all"),
        "an empty change set runs everything": ([], "all"),
    }
    failed = False
    for name, (changed, want) in cases.items():
        got = scope(changed, crates)
        if got != want:
            print(f"selftest FAIL: {name}: {got}, wanted {want}")
            failed = True
    if [t["name"] for t in legs("mingw", toolchains)] != ["Win64"]:
        print("selftest FAIL: the mingw choice is not the Win64 leg alone")
        failed = True
    if legs("none", toolchains) or len(legs("all", toolchains)) != 3:
        print("selftest FAIL: none or all do not select what they name")
        failed = True
    # Rule 47: the census reads this tree and finds the FFI crate, and the
    # toolchain file holds the MinGW leg the narrow choice selects.
    found = export_crates(ROOT)
    if "shekyl-ffi" not in found:
        print(f"selftest FAIL: the export census misses shekyl-ffi: {sorted(found)}")
        failed = True
    real = json.loads((ROOT / TOOLCHAINS).read_text(encoding="utf-8"))
    if len(legs("mingw", real)) != 1:
        print(f"selftest FAIL: {TOOLCHAINS} does not hold exactly one {MINGW} leg")
        failed = True
    if failed:
        return 1
    print(f"selftest: {len(cases)} cases bite as expected; export crates {sorted(found)}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event")
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    toolchains = json.loads((ROOT / TOOLCHAINS).read_text(encoding="utf-8"))
    if args.event != "pull_request":
        write(toolchains, f"event {args.event}")
        return 0
    try:
        changed = changed_files(args.base, args.head)
        choice = scope(changed, export_crates(ROOT))
    except Exception as error:  # fail closed: every leg
        write(toolchains, f"the change set could not be read ({error})")
        return 0
    write(legs(choice, toolchains), f"pull request, {len(changed)} files, {choice}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
