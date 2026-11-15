#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_fuzz_inventory.py's selftest: throwaway trees, each planting one
# failure class, and the verdict each must get.

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_inventory as gate  # noqa: E402

WORKSPACE_LOCK = """version = 4

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shekyl-a"
version = "0.1.0"
"""

FUZZ_LOCK = """version = 4

[[package]]
name = "libfuzzer-sys"
version = "0.4.12"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "{rand}"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shekyl-a"
version = "0.1.0"
"""

WORKFLOW = "jobs:\n  scope:\n    steps:\n      - run: python3 scripts/ci/check_fuzz_inventory.py --matrix\n"


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def fuzz_manifest(bins: list[str]) -> str:
    text = (
        '[package]\nname = "shekyl-a-fuzz"\nversion = "0.0.0"\nedition = "2021"\n\n'
        '[dependencies]\nlibfuzzer-sys = "0.4"\nshekyl-a = { path = ".." }\n\n'
    )
    for name in bins:
        text += f'[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\n\n'
    return text + "[workspace]\n"


def tree(
    root: Path,
    *,
    bins=("fuzz_one",),
    files=("fuzz_one",),
    rand="0.8.5",
    lock=True,
    workflow=WORKFLOW,
    fuzz=True,
) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    write(root, "rust/Cargo.lock", WORKSPACE_LOCK)
    write(root, "rust/shekyl-a/Cargo.toml", '[package]\nname = "shekyl-a"\nversion = "0.1.0"\n')
    if fuzz:
        write(root, "rust/shekyl-a/fuzz/Cargo.toml", fuzz_manifest(list(bins)))
        for name in files:
            write(root, f"rust/shekyl-a/fuzz/fuzz_targets/{name}.rs", "fn main() {}\n")
        if lock:
            write(root, "rust/shekyl-a/fuzz/Cargo.lock", FUZZ_LOCK.format(rand=rand))
    if workflow is not None:
        write(root, gate.WORKFLOW, workflow)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failures: list[str] = []

    def expect(self, why: str, want: int, says: str = "", **planted) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree(root, **planted)
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = gate.run(root)
            out = buf.getvalue()
            if code != want or (says and says not in out):
                wanted = f"exit {want}" + (f" naming {says!r}" if says else "")
                self.failures.append(f"{why}: wanted {wanted}, got {code}\n{out}")
            else:
                self.passed += 1

    def expect_matrix(self, why: str, rust_tests: str, changed: list[str], want: list[str]) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tree(root)
            got = gate.matrix(root, rust_tests, changed)
            if got != want:
                self.failures.append(f"{why}: wanted {json.dumps(want)}, got {json.dumps(got)}")
            else:
                self.passed += 1


def selftest() -> int:
    r = Results()
    r.expect("a crate whose bins, files and lockfile agree", 0, "1 fuzz crates, 1 targets")
    r.expect("no fuzz crate at all", 2, "missing subject", fuzz=False)
    r.expect(
        "a [[bin]] that names no file", 1, "names rust/shekyl-a/fuzz/fuzz_targets/fuzz_two.rs",
        bins=("fuzz_one", "fuzz_two"),
    )
    r.expect(
        "a target file no [[bin]] names", 1, "fuzz_two.rs is a fuzz target no [[bin]] names",
        files=("fuzz_one", "fuzz_two"),
    )
    r.expect("an untracked lockfile", 1, "Cargo.lock is not tracked", lock=False)
    r.expect(
        "a shared package at a version the workspace does not lock", 1,
        "rand 0.8.6, where rust/Cargo.lock locks 0.8.5", rand="0.8.6",
    )
    r.expect("no compile workflow", 1, "is missing: nothing compiles", workflow=None)
    r.expect(
        "a workflow that lists its own matrix", 1, "does not build its matrix",
        workflow="jobs:\n  compile:\n    strategy:\n      matrix:\n        crate: [shekyl-a]\n",
    )
    r.expect_matrix("a change the closure reaches", "shekyl-a", ["rust/shekyl-a/src/lib.rs"], ["shekyl-a"])
    r.expect_matrix("a change it does not reach", "shekyl-b", ["rust/shekyl-b/src/lib.rs"], [])
    r.expect_matrix("the fuzz crate's own file", "none", ["rust/shekyl-a/fuzz/fuzz_targets/fuzz_one.rs"], ["shekyl-a"])
    r.expect_matrix("the workspace lockfile reaches every harness", "none", ["rust/Cargo.lock"], ["shekyl-a"])
    r.expect_matrix("the workflow reaches every harness", "none", [gate.WORKFLOW], ["shekyl-a"])
    r.expect_matrix("a classifier that says all", "all", [], ["shekyl-a"])
    if r.failures:
        print("SELFTEST FAIL:")
        for failure in r.failures:
            print("  " + failure)
        return 1
    print(f"fuzz inventory selftest: {r.passed} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(selftest())
