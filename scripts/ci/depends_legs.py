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
  defines one when a source file under its src/ declares `#[no_mangle]` or
  `#[unsafe(no_mangle)]`. Comments are stripped first (`strip_c_comments`),
  so a crate that mentions the attribute, or forbids it, is not one. The
  declaration is read from the tree at both revisions, not listed by hand:
  a crate's first export brings it in, and removing its last export — or
  deleting the file that declared it — still selects the MinGW leg, because
  the base revision still declares it. MinGW is the one linker the release
  builds with that keeps unreferenced sections: GNU ld on Linux and ld64 on
  macOS run with
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
import re
import subprocess
import sys

from strip_c_comments import strip as strip_comments

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLCHAINS = "contrib/depends/ci-toolchains.json"
MINGW = "x86_64-w64-mingw32"
SELF = "scripts/ci/depends_legs.py"

# Every leg.
FULL = ("contrib/depends/*", "Makefile", ".github/workflows/depends.yml", SELF)
# The MinGW leg: how an executable links.
LINK = ("CMakeLists.txt", "*/CMakeLists.txt", "cmake/*", "src/shekyl/*.h")
# A declared export. The edition-2024 spelling is `#[unsafe(no_mangle)]`.
# A mention in a comment is not a declaration; comments are stripped first.
EXPORT_ATTR = re.compile(r"#\[\s*(?:no_mangle|unsafe\s*\(\s*no_mangle\s*\))\s*\]")
# Crates whose src/ declares an export today. The census reads the tree;
# this set is what `--selftest` pins, so a comment that starts matching, or
# a real export that appears, fails here instead of drifting.
EXPORT_CRATES = frozenset(
    {"shekyl-daemon", "shekyl-daemon-rpc", "shekyl-ffi", "shekyl-logging"}
)


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def declares_export(source):
    """True when `source` declares a C export, once comments are gone."""
    return EXPORT_ATTR.search(strip_comments(source, rust=True)) is not None


def crate_of(path):
    """The crate a `rust/<crate>/src/**/*.rs` path belongs to, or None.

    `shekyl-oxide` is the vendored tree, not a Shekyl export crate.
    """
    parts = pathlib.PurePosixPath(path).parts
    if (
        len(parts) >= 4
        and parts[0] == "rust"
        and parts[2] == "src"
        and parts[1] != "shekyl-oxide"
        and path.endswith(".rs")
    ):
        return parts[1]
    return None


def export_crates_in(sources):
    """Crates that declare an export, from `(path, text)` pairs."""
    crates = set()
    for path, text in sources:
        crate = crate_of(path)
        if crate is not None and declares_export(text):
            crates.add(crate)
    return crates


def export_crates(root):
    """Crates whose src/ declares an export in the working tree (the head)."""
    rust = root / "rust"
    sources = []
    for source in rust.glob("*/src/**/*.rs"):
        rel = pathlib.PurePosixPath("rust", *source.relative_to(rust).parts).as_posix()
        if crate_of(rel) is None:
            continue
        sources.append((rel, source.read_text(encoding="utf-8", errors="replace")))
    return export_crates_in(sources)


def export_crates_at(rev):
    """Crates whose src/ declares an export at `rev`.

    A file the later revision deletes is still here, so removing a crate's
    last export does not drop the crate from the selection.
    """
    listed = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--name-only", rev, "--", "rust"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in listed.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode()
        if crate_of(path) is not None:
            paths.append(path)
    if not paths:
        return set()
    proc = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=ROOT,
        input=b"".join(f"{rev}:{path}\n".encode() for path in paths),
        check=True,
        capture_output=True,
    )
    sources = []
    data = proc.stdout
    at = 0
    for path in paths:
        end = data.find(b"\n", at)
        if end < 0:
            raise RuntimeError(f"cat-file returned no header for {path}")
        header = data[at:end]
        at = end + 1
        parts = header.split()
        if len(parts) >= 2 and parts[1] == b"missing":
            continue
        if len(parts) != 3 or parts[1] != b"blob":
            raise RuntimeError(f"unexpected cat-file header for {path}: {header!r}")
        size = int(parts[2])
        sources.append((path, data[at : at + size].decode("utf-8", "replace")))
        at += size
        if at < len(data) and data[at : at + 1] == b"\n":
            at += 1
    return export_crates_in(sources)


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
    # A declaration counts. A comment that names the attribute, including a
    # crate doc that forbids it, does not.
    declarations = {
        "an attribute": ("#[no_mangle]\npub extern \"C\" fn f() {}\n", True),
        "the edition-2024 attribute": ("#[unsafe(no_mangle)]\nfn f() {}\n", True),
        "a doc that forbids it": ("//! No `#[no_mangle]`.\nfn f() {}\n", False),
        "a line comment": ("// #[no_mangle]\nfn f() {}\n", False),
        "a block comment": ("/* #[no_mangle] */\nfn f() {}\n", False),
    }
    for name, (text, want) in declarations.items():
        got = declares_export(text)
        if got != want:
            print(f"selftest FAIL: {name}: declares_export is {got}, wanted {want}")
            failed = True
    # Rule 47: the census reads this tree. shekyl-pow-randomx and
    # shekyl-daemon-image mention the attribute and do not declare one.
    found = export_crates(ROOT)
    if found != EXPORT_CRATES:
        print(f"selftest FAIL: export census {sorted(found)}, wanted {sorted(EXPORT_CRATES)}")
        failed = True
    # The pinned set is what the selector uses: a mention is not a leg, a
    # declaration is.
    pinned = {
        "a crate that forbids the attribute": (["rust/shekyl-pow-randomx/src/lib.rs"], "none"),
        "the link image, which only discusses the attribute": (
            ["rust/shekyl-daemon-image/src/lib.rs"],
            "none",
        ),
        "a crate that declares one": (["rust/shekyl-logging/src/lib.rs"], "mingw"),
    }
    for name, (changed, want) in pinned.items():
        got = scope(changed, EXPORT_CRATES)
        if got != want:
            print(f"selftest FAIL: {name}: {got}, wanted {want}")
            failed = True
    # Removing the last export, or deleting the file that declared it: the
    # head no longer has the crate, the base still does, and MinGW runs.
    removals = {
        "the last export is removed": (
            ["rust/shekyl-logging/src/lib.rs"],
            {"shekyl-ffi"} | {"shekyl-ffi", "shekyl-logging"},
            "mingw",
        ),
        "the exporting source is deleted": (
            ["rust/shekyl-logging/src/lib.rs"],
            set() | {"shekyl-logging"},
            "mingw",
        ),
        "neither revision declares an export": (
            ["rust/shekyl-dialer/src/lib.rs"],
            {"shekyl-ffi"} | {"shekyl-ffi"},
            "none",
        ),
    }
    for name, (changed, crates, want) in removals.items():
        got = scope(changed, crates)
        if got != want:
            print(f"selftest FAIL: {name}: {got}, wanted {want}")
            failed = True
    # The base reader sees the same crates the working tree does, at HEAD.
    at_head = export_crates_at("HEAD")
    if at_head != EXPORT_CRATES:
        print(f"selftest FAIL: HEAD census {sorted(at_head)}, wanted {sorted(EXPORT_CRATES)}")
        failed = True
    real = json.loads((ROOT / TOOLCHAINS).read_text(encoding="utf-8"))
    if len(legs("mingw", real)) != 1:
        print(f"selftest FAIL: {TOOLCHAINS} does not hold exactly one {MINGW} leg")
        failed = True
    if failed:
        return 1
    print(
        f"selftest: {len(cases)} path cases, {len(declarations)} declarations; "
        f"export crates {sorted(found)}"
    )
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
        # Head is the checkout. Base is read from git, so a deleted export
        # still selects the leg.
        crates = export_crates(ROOT) | export_crates_at(args.base)
        choice = scope(changed, crates)
    except Exception as error:  # fail closed: every leg
        write(toolchains, f"the change set could not be read ({error})")
        return 0
    write(legs(choice, toolchains), f"pull request, {len(changed)} files, {choice}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
