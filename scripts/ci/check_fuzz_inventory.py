#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The fuzz harness inventory, derived from the tree (the CI lane's fuzz
# brief, Part A, ruled 2026-11-12 and amended 2026-11-15).
#
# A fuzz crate is `rust/<crate>/fuzz/Cargo.toml`: its own workspace, outside
# the main one, so nothing else compiles it. This gate reads every one and
# holds:
#
#   - each `[[bin]]` names a file under `fuzz_targets/`, and each file there
#     is a `[[bin]]`;
#   - the crate's `Cargo.lock` is tracked, and every package it shares with
#     the workspace's `rust/Cargo.lock` is at a version the workspace locks:
#     a fuzzer exercises the dependency versions that ship, and `cargo audit`
#     (which reads only the workspace lockfile) sees every one of them;
#   - the compile workflow builds its matrix from this script
#     (`--matrix`), so a fuzz crate cannot exist without being compiled.
#
# Modes:
#   (none)        the check; exit 0, 1 on a finding, 2 when the question
#                 cannot be asked (no fuzz crate found: rule 47).
#   --matrix      the crates a change reaches, as a JSON list for the
#                 workflow's matrix (below).
#   --regenerate  rewrite every fuzz crate's `Cargo.lock` from the
#                 workspace's: copy it in, then `cargo update --workspace
#                 --offline` re-resolves the fuzz crate's own entries only,
#                 so a package the two share keeps the workspace's version.
#   --selftest    the check on planted trees.
#
# --matrix reads `RUST_TESTS` (change_scope.py's `rust_tests`: `all`, `none`
# or the members a change reaches through the reverse closure) and
# `CHANGED` (the changed paths, one per line). A fuzz crate is in the matrix
# when any crate it depends on by path is in `rust_tests`, when its own
# files changed, or when the change touches what every harness builds
# against (the workspace lockfile, the toolchain pin, this script, the
# workflow).

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/fuzz-harness.yml"
WORKSPACE_LOCK = "rust/Cargo.lock"
# A change to any of these reaches every harness.
EVERY_HARNESS = (
    WORKSPACE_LOCK,
    "rust/rust-toolchain.toml",
    "rust/Cargo.toml",
    WORKFLOW,
    "scripts/ci/check_fuzz_inventory.py",
    "scripts/ci/test_check_fuzz_inventory.py",
)


class GateError(Exception):
    """The question could not be asked (exit 2)."""


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise GateError(f"git ls-files failed: {out.stderr.strip()}")
    return out.stdout.splitlines()


def fuzz_crates(files: list[str]) -> list[str]:
    """`<crate>` for every tracked `rust/<crate>/fuzz/Cargo.toml`, sorted."""
    found = sorted(
        m.group(1)
        for f in files
        if (m := re.fullmatch(r"rust/([^/]+)/fuzz/Cargo\.toml", f))
    )
    if not found:
        raise GateError("no rust/<crate>/fuzz/Cargo.toml is tracked — missing subject (rule 47)")
    return found


def locked(lock_text: str) -> dict[str, set[str]]:
    """Registry and git packages of a lockfile: name -> versions. Path
    packages (no `source`) are the tree's own and are not compared."""
    data = tomllib.loads(lock_text)
    out: dict[str, set[str]] = {}
    for package in data.get("package", []):
        if "source" in package:
            out.setdefault(package["name"], set()).add(package["version"])
    return out


def path_deps(root: Path, crate: str, manifest: dict) -> set[str]:
    """The package names the fuzz crate depends on by path."""
    names: set[str] = set()
    base = root / "rust" / crate / "fuzz"
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dep in manifest.get(table, {}).values():
            if isinstance(dep, dict) and "path" in dep:
                dep_manifest = (base / dep["path"] / "Cargo.toml").resolve()
                try:
                    names.add(tomllib.loads(dep_manifest.read_text())["package"]["name"])
                except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
                    raise GateError(f"rust/{crate}/fuzz: path dependency {dep['path']}: {exc}") from exc
    return names


def check(root: Path) -> tuple[list[str], list[str], int]:
    """Findings, the crates, and the number of targets."""
    files = tracked(root)
    file_set = set(files)
    crates = fuzz_crates(files)
    lock_path = root / WORKSPACE_LOCK
    if not lock_path.is_file():
        raise GateError(f"{WORKSPACE_LOCK} is missing — missing subject (rule 47)")
    workspace = locked(lock_path.read_text())
    fails: list[str] = []
    targets = 0
    for crate in crates:
        base = f"rust/{crate}/fuzz"
        manifest = tomllib.loads((root / base / "Cargo.toml").read_text())
        bins = manifest.get("bin", [])
        named = set()
        for entry in bins:
            path = f"{base}/{entry.get('path', '')}"
            named.add(path)
            if path not in file_set:
                fails.append(f"{base}: [[bin]] {entry.get('name')!r} names {path}, which is not a tracked file")
        on_disk = {f for f in files if f.startswith(f"{base}/fuzz_targets/") and f.endswith(".rs")}
        fails.extend(
            f"{base}: {f} is a fuzz target no [[bin]] names, so nothing builds it"
            for f in sorted(on_disk - named)
        )
        if not bins:
            fails.append(f"{base}: no [[bin]] target")
        targets += len(bins)
        lock = f"{base}/Cargo.lock"
        if lock not in file_set:
            fails.append(
                f"{base}: Cargo.lock is not tracked. `--locked` is the point: commit the "
                "lockfile `--regenerate` writes"
            )
            continue
        own = locked((root / lock).read_text())
        for name, versions in sorted(own.items()):
            if name not in workspace:
                continue
            for version in sorted(versions - workspace[name]):
                fails.append(
                    f"{lock}: {name} {version}, where {WORKSPACE_LOCK} locks "
                    f"{', '.join(sorted(workspace[name]))}. Regenerate it "
                    "(scripts/ci/check_fuzz_inventory.py --regenerate)"
                )
    workflow = root / WORKFLOW
    if not workflow.is_file():
        fails.append(f"{WORKFLOW} is missing: nothing compiles the fuzz crates")
    elif "check_fuzz_inventory.py --matrix" not in workflow.read_text():
        fails.append(
            f"{WORKFLOW} does not build its matrix from `check_fuzz_inventory.py --matrix`, "
            "so a fuzz crate can exist that it does not compile"
        )
    return fails, crates, targets


def matrix(root: Path, rust_tests: str, changed: list[str]) -> list[str]:
    files = tracked(root)
    crates = fuzz_crates(files)
    if rust_tests == "all" or any(path in EVERY_HARNESS for path in changed):
        return crates
    reached = set(rust_tests.split()) if rust_tests != "none" else set()
    out = []
    for crate in crates:
        base = f"rust/{crate}/fuzz/"
        manifest = tomllib.loads((root / base / "Cargo.toml").read_text())
        if path_deps(root, crate, manifest) & reached or any(p.startswith(base) for p in changed):
            out.append(crate)
    return out


def regenerate(root: Path) -> int:
    for crate in fuzz_crates(tracked(root)):
        base = root / "rust" / crate / "fuzz"
        shutil.copyfile(root / WORKSPACE_LOCK, base / "Cargo.lock")
        done = subprocess.run(
            ["cargo", "update", "--workspace", "--offline"],
            cwd=base,
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            print(f"{crate}: cargo update failed:\n{done.stderr}", file=sys.stderr)
            return 1
        print(f"{crate}: Cargo.lock regenerated from {WORKSPACE_LOCK}")
    return 0


def run(root: Path) -> int:
    try:
        fails, crates, targets = check(root)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2
    if fails:
        print("FAIL: the fuzz harness inventory disagrees with the tree:")
        for finding in fails:
            print("  " + finding)
        return 1
    print(
        f"fuzz inventory: {len(crates)} fuzz crates, {targets} targets, every [[bin]] a file "
        f"and every file a [[bin]], every lockfile at the workspace's versions"
    )
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        import test_check_fuzz_inventory  # noqa: PLC0415

        return test_check_fuzz_inventory.selftest()
    if args == ["--matrix"]:
        changed = [line for line in os.environ.get("CHANGED", "").splitlines() if line]
        try:
            print(json.dumps(matrix(ROOT, os.environ.get("RUST_TESTS", "all"), changed)))
        except GateError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        return 0
    if args == ["--regenerate"]:
        return regenerate(ROOT)
    if args:
        print(f"usage: {sys.argv[0]} [--matrix | --regenerate | --selftest]", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
