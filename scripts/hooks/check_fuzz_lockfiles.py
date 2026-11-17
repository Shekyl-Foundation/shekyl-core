#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The fuzz lockfiles still resolve, checked before a push (ruled 2026-11-16:
# a pre-push check, not a CI job).
#
# Each fuzz crate (`rust/<crate>/fuzz/`) is its own workspace with its own
# committed `Cargo.lock`. When a crate it depends on by path changes its
# dependencies, that lockfile goes stale: #1399 moved `shekyl-address`'s
# `bech32` to its dev-dependencies, four fuzz lockfiles kept the edge, and
# every fuzz build refused them (`cannot update the lock file ... because
# --locked was passed`). The version check in `check_fuzz_inventory.py`
# compares versions only, so a dropped edge passed it.
#
# `cargo metadata --locked` for each fuzz crate is the check: it resolves
# the crate against its lockfile and refuses to rewrite it. It runs only
# when the pushed range changes a `Cargo.lock` or a `Cargo.toml` under
# `rust/` (a manifest is where a dependency changes), and from a checkout
# of the pushed commit, not the working tree (rule 08: the tested tree is
# the shipped tree).
#
#   check_fuzz_lockfiles.py --range <base> <head>   the pre-push check
#   check_fuzz_lockfiles.py --tree <dir>            every fuzz crate in <dir>
#   check_fuzz_lockfiles.py --selftest              a planted stale lockfile
#
# Fix a red one with `python3 scripts/ci/check_fuzz_inventory.py
# --regenerate`, and commit the fuzz lockfiles.

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ZERO = "0" * 40
TRIGGER = re.compile(r"rust/(.+/)?Cargo\.(toml|lock)")


def git(root: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        raise SystemExit(f"FAIL: git {' '.join(args)}: {out.stderr.strip()}")
    return out.stdout


def triggered(paths: list[str]) -> list[str]:
    """The changed paths that can move a fuzz crate's resolution."""
    return [p for p in paths if TRIGGER.fullmatch(p)]


def fuzz_crates(tree: Path) -> list[Path]:
    return sorted(p.parent for p in tree.glob("rust/*/fuzz/Cargo.toml"))


def check_tree(tree: Path) -> list[str]:
    """Each fuzz crate under `tree` whose lockfile cargo would rewrite."""
    crates = fuzz_crates(tree)
    if not crates:
        raise SystemExit(f"FAIL: no rust/<crate>/fuzz/Cargo.toml under {tree} — missing subject (rule 47)")
    stale = []
    for crate in crates:
        done = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", str(crate / "Cargo.toml")],
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            why = done.stderr.strip().splitlines()
            stale.append(f"{crate.relative_to(tree)}: {why[0] if why else f'exit {done.returncode}'}")
    return stale


def report(stale: list[str], n: int) -> int:
    if stale:
        print("FAIL: a fuzz lockfile no longer resolves with --locked:")
        for line in stale:
            print("  " + line)
        print("Run python3 scripts/ci/check_fuzz_inventory.py --regenerate and commit the fuzz lockfiles.")
        return 1
    print(f"fuzz lockfiles: all {n} resolve with --locked")
    return 0


def run_range(root: Path, base: str, head: str) -> int:
    if base == ZERO:
        base = git(root, "merge-base", head, "origin/dev").strip()
    changed = git(root, "diff", "--name-only", base, head).splitlines()
    hits = triggered(changed)
    if not hits:
        return 0
    print(f"fuzz lockfiles: {len(hits)} manifest or lockfile change(s) in {base[:10]}..{head[:10]}; checking")
    with tempfile.TemporaryDirectory() as raw:
        tree = Path(raw) / "tree"
        git(root, "worktree", "add", "--detach", "--quiet", str(tree), head)
        try:
            stale = check_tree(tree)
            return report(stale, len(fuzz_crates(tree)))
        finally:
            git(root, "worktree", "remove", "--force", str(tree))


def plant(root: Path, stale: bool) -> None:
    """A workspace crate `shekyl-a` and its fuzz crate, with a lockfile cargo
    generated for them. `stale` puts back what #1399 left: the lockfile
    still lists a registry dependency (`bech32`) under `shekyl-a` that
    `shekyl-a`'s manifest no longer has."""
    crate = root / "rust/shekyl-a"
    fuzz = crate / "fuzz"
    for src in (crate / "src", fuzz / "src"):
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("")
    (crate / "Cargo.toml").write_text('[package]\nname = "shekyl-a"\nversion = "0.1.0"\nedition = "2021"\n')
    (fuzz / "Cargo.toml").write_text(
        '[package]\nname = "shekyl-a-fuzz"\nversion = "0.0.0"\nedition = "2021"\n'
        '[dependencies]\nshekyl-a = { path = ".." }\n[workspace]\n'
    )
    subprocess.run(
        ["cargo", "generate-lockfile", "--offline", "--manifest-path", str(fuzz / "Cargo.toml")],
        capture_output=True,
        check=True,
    )
    if stale:
        lock = fuzz / "Cargo.lock"
        entry = '[[package]]\nname = "shekyl-a"\nversion = "0.1.0"\n'
        text = lock.read_text()
        assert entry in text, "cargo's lockfile layout changed"
        lock.write_text(
            text.replace(
                entry,
                '[[package]]\nname = "bech32"\nversion = "0.11.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                'checksum = "d965446196e3b7decd44aa7ee49e31d630118f90ef12f97900f262eb915c951d"\n\n'
                + entry
                + 'dependencies = [\n "bech32",\n]\n',
            )
        )


def selftest() -> int:
    failures = []
    for why, want_stale in [
        ("a lockfile that matches its manifests", False),
        ("a lockfile that keeps a dependency the manifest dropped (#1399's bech32)", True),
    ]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plant(root, want_stale)
            stale = check_tree(root)
            if bool(stale) != want_stale:
                failures.append(f"{why}: wanted stale={want_stale}, got {stale}")
    for why, paths, want in [
        ("the workspace lockfile", ["rust/Cargo.lock"], True),
        ("a crate's manifest", ["rust/shekyl-address/Cargo.toml"], True),
        ("a fuzz crate's lockfile", ["rust/shekyl-proofs/fuzz/Cargo.lock"], True),
        ("source only", ["rust/shekyl-address/src/lib.rs", "docs/README.md"], False),
        ("a manifest outside rust/", ["Cargo.toml"], False),
    ]:
        if bool(triggered(paths)) != want:
            failures.append(f"trigger, {why}: wanted {want}")
    if failures:
        print("SELFTEST FAIL:")
        for line in failures:
            print("  " + line)
        return 1
    print("fuzz lockfile check selftest: a stale lockfile is red, a current one green, 5 trigger cases")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) == 3 and argv[1] == "--tree":
        tree = Path(argv[2]).resolve()
        return report(check_tree(tree), len(fuzz_crates(tree)))
    if len(argv) == 4 and argv[1] == "--range":
        root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").strip())
        return run_range(root, argv[2], argv[3])
    print(__doc__ or "usage: --range <base> <head> | --tree <dir> | --selftest")
    return 2


if __name__ == "__main__":
    if shutil.which("cargo") is None:
        print("FAIL: cargo is not on PATH")
        sys.exit(2)
    sys.exit(main(sys.argv))
