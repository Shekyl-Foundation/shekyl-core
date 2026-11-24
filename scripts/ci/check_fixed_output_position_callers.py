#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Only block producers name a fixed output position (R-34).

# Why this gate exists

A wallet that chose its outputs' positions could put its change last, or
its payees in the order it was handed them, and an observer would learn
which output came back to it (R-24). So the `shekyl-crypto-pq` output
constructors take an `OutputPosition`, and production code gets one only
from `TxKey::place`, which places the whole set by the key's order.
`TxKey::output_positions` is test-only. The one other way to make a
position is `OutputPosition::for_block_producer(tx_key, index)`:
block producers place their outputs themselves, because their outputs are
public by construction and their bytes are pinned. That constructor is
public, so the type alone cannot keep a wallet from calling it. This gate
does: it lists the files allowed to, each with the reason.

# What it asserts

Over every `.rs` file under `rust/` (the vendored `shekyl-oxide` tree and
build output aside), comment lines removed:

  1. The constructor exists where it is defined (`DEFINITION`), or the
     pattern names nothing and every scan below is vacuously green.
  2. Every file in `ALLOWED` exists and still calls the constructor. An
     allowance that matches nothing is a door nobody watches.
  3. No other file names `for_block_producer` at all: a call, a path, a
     re-export or an alias is the same door.

`--selftest` runs the scanner over synthetic sources first: a planted call
outside the list is refused, a mention in a comment is not a call, an
allowed file that stopped calling is refused, and the definition's absence
is refused (rule 47). The real check runs only after the selftest passes in
CI (`grep-gates.yml`).

# What it does not see

A block comment (`/* ... */`) that spans lines is read as code, so a call
hidden inside one fails closed rather than open. A macro that builds the
identifier from parts (`concat_idents!`) would pass; no such macro exists in
the tree, and writing one to dodge this gate is a review finding.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# The constructor's identifier. Distinct on purpose: a common name like
# `fixed` would collide with unrelated functions and make the scan useless.
IDENTIFIER = "for_block_producer"
PATTERN = re.compile(r"\b" + IDENTIFIER + r"\b")

# Where it is defined. The definition itself is not a call.
DEFINITION = "rust/shekyl-crypto-pq/src/output_order.rs"
DEFINITION_PATTERN = re.compile(r"pub fn " + IDENTIFIER + r"\(")

# The callers, each with why its positions are its own.
ALLOWED = {
    "rust/shekyl-genesis-tool/src/builder.rs": (
        "genesis places recipient i at output i; its outputs are public and "
        "its bytes are pinned by the golden KAT"
    ),
    "rust/shekyl-block-template/src/lib.rs": (
        "a coinbase's one output sits at position 0; it has no change to hide"
    ),
    "rust/shekyl-harness-wallet/src/coinbase.rs": (
        "the harness coinbase is shaped as the template's: one output at 0"
    ),
}

EXCLUDED_PREFIXES = ("rust/target", "rust/shekyl-oxide/")


def code_lines(text: str) -> list[tuple[int, str]]:
    """Lines that are not whole-line `//` comments, with 1-based numbers."""
    out = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("//"):
            continue
        out.append((number, line))
    return out


def rust_sources(root: Path) -> list[Path]:
    """Every first-party `.rs` file under `root/rust`. The excluded trees
    are pruned as the walk reaches them, not read and then dropped."""
    sources = []
    for directory, subdirs, files in os.walk(root / "rust"):
        rel_dir = Path(directory).relative_to(root).as_posix()
        subdirs[:] = sorted(
            d for d in subdirs if not f"{rel_dir}/{d}".startswith(EXCLUDED_PREFIXES)
        )
        sources.extend(Path(directory) / f for f in sorted(files) if f.endswith(".rs"))
    return sources


def check(root: Path) -> list[str]:
    """The gate's findings over the tree at `root`; empty is a pass."""
    findings = []

    definition = root / DEFINITION
    if not definition.is_file() or not DEFINITION_PATTERN.search(
        definition.read_text(encoding="utf-8")
    ):
        return [
            f"{DEFINITION}: `pub fn {IDENTIFIER}(` is not defined there; the "
            "gate names nothing. Re-anchor DEFINITION."
        ]

    sources = rust_sources(root)
    if not sources:
        return ["no Rust source under rust/: the scan would read nothing"]

    called_in: set[str] = set()
    for path in sources:
        rel = path.relative_to(root).as_posix()
        if rel == DEFINITION:
            continue
        for number, line in code_lines(path.read_text(encoding="utf-8")):
            if not PATTERN.search(line):
                continue
            if rel in ALLOWED:
                called_in.add(rel)
            else:
                findings.append(
                    f"{rel}:{number}: names OutputPosition::{IDENTIFIER} outside "
                    "the block producers. A wallet takes its positions from "
                    "TxKey::output_positions (R-24, R-34)."
                )

    for rel in ALLOWED:
        if not (root / rel).is_file():
            findings.append(f"{rel}: allowed file does not exist; update ALLOWED")
        elif rel not in called_in:
            findings.append(
                f"{rel}: allowed file no longer calls {IDENTIFIER}; remove it from ALLOWED"
            )
    return findings


def plant(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def selftest() -> int:
    """Each verdict on a synthetic tree (rule 47)."""
    definition = f"impl OutputPosition<'_> {{ pub fn {IDENTIFIER}(k: &TxKey, i: u64) -> Self {{ todo!() }} }}\n"
    call = f"let p = OutputPosition::{IDENTIFIER}(&k, 0);\n"
    good = {DEFINITION: definition, **{rel: call for rel in ALLOWED}}
    cases = [
        ("the allowed callers pass", good, False),
        (
            "a call outside the list is refused",
            {**good, "rust/shekyl-engine-core/src/send.rs": call},
            True,
        ),
        (
            "an alias outside the list is refused",
            {
                **good,
                "rust/shekyl-wallet/src/x.rs": f"use shekyl_crypto_pq::output_order::OutputPosition as P; fn f() {{ P::{IDENTIFIER}(&k, 1); }}\n",
            },
            True,
        ),
        (
            "a mention in a comment is not a call",
            {**good, "rust/shekyl-engine-core/src/send.rs": f"// never call {IDENTIFIER} here\n"},
            False,
        ),
        (
            "an allowed file that stopped calling is refused",
            {**good, next(iter(ALLOWED)): "fn nothing() {}\n"},
            True,
        ),
        ("a missing definition is refused", {rel: call for rel in ALLOWED}, True),
        (
            "the vendored tree is not first-party",
            {**good, "rust/shekyl-oxide/x/src/lib.rs": call},
            False,
        ),
    ]
    failed = 0
    for name, files, expect_red in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plant(root, files)
            red = bool(check(root))
        if red != expect_red:
            failed += 1
            print(f"selftest FAIL: {name}: expected {'red' if expect_red else 'green'}")
    if failed:
        return 1
    print(f"selftest OK: {len(cases)} cases")
    return 0


def repo_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        print(f"FAIL: not in a git checkout: {out.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return Path(out.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true", help="run the selftest only")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    findings = check(repo_root())
    if findings:
        print("FAIL: check_fixed_output_position_callers:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(f"OK: OutputPosition::{IDENTIFIER} is called only by: {', '.join(ALLOWED)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
