#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Schema ↔ class-table bijection.

The Rust table definitions are the denominator. `schema.rs` and
`pool/schema.rs` declare every table the store opens, and
`accumulator/class.rs`'s `TABLE_CLASSES` names each of them once.
A name on only one side is a table the digest classification forgot,
or a classification of a table that does not exist.

The LMDB X-macro, and the allowlists that explained how a definition
related to it, are not a side of this check. Ordering lives in
`lmdb_order`'s pinned vectors. This gate checks names.

Instance of 47-gate-subject-assertion.mdc: an empty definition set or
an empty class table fails. `--selftest` builds each refusal.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"
POOL_SCHEMA = ROOT / "rust/shekyl-chain-store/src/pool/schema.rs"
CLASSES = ROOT / "rust/shekyl-chain-store/src/accumulator/class.rs"

DEF_RE = re.compile(r'(?:Multimap)?TableDefinition::new\("([^"]+)"\)')


def dupes(names):
    seen, out = set(), []
    for name in names:
        if name in seen:
            out.append(name)
        seen.add(name)
    return out


def class_names(text: str) -> list[str]:
    start = text.find("pub const TABLE_CLASSES")
    if start < 0:
        return []
    block = text[start:]
    end = block.find("\n];")
    if end < 0:
        return []
    return re.findall(r'"([a-z_0-9]+)"', block[:end])


def compare(defined: list[str], classed: list[str]) -> list[str]:
    failures = []
    if not defined:
        failures.append("parsed ZERO table definitions — the denominator is missing")
    if not classed:
        failures.append("parsed ZERO class entries — the class table is missing")
    if failures:
        return failures
    for name in dupes(defined):
        failures.append(f"duplicate table definition {name}")
    for name in dupes(classed):
        failures.append(f"duplicate class row {name}")
    defined_set, classed_set = set(defined), set(classed)
    for name in sorted(defined_set - classed_set):
        failures.append(f"{name}: defined, absent from TABLE_CLASSES")
    for name in sorted(classed_set - defined_set):
        failures.append(f"{name}: in TABLE_CLASSES, not a table definition")
    return failures


def main() -> None:
    missing = [p for p in (SCHEMA, POOL_SCHEMA, CLASSES) if not p.is_file()]
    if missing:
        report([f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist"
                for p in missing])
    defined = DEF_RE.findall(SCHEMA.read_text(encoding="utf-8"))
    defined += DEF_RE.findall(POOL_SCHEMA.read_text(encoding="utf-8"))
    classed = class_names(CLASSES.read_text(encoding="utf-8"))
    failures = compare(defined, classed)
    report(failures)
    print(f"redb schema bijection: {len(set(defined))} table definitions "
          f"<-> {len(set(classed))} class rows")


def report(failures: list[str]) -> None:
    if failures:
        print("redb schema bijection FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        sys.exit(1)


def selftest() -> None:
    def expect(name, defined, classed, needle):
        failures = compare(defined, classed)
        if not any(needle in failure for failure in failures):
            raise SystemExit(
                f"selftest {name}: expected {needle!r}, got {failures or ['<clean>']}")

    expect("empty definitions", [], ["blocks"], "ZERO table definitions")
    expect("empty classes", ["blocks"], [], "ZERO class entries")
    expect("extra definition", ["blocks", "undo_log"], ["blocks"],
           "undo_log: defined, absent")
    expect("extra class", ["blocks"], ["blocks", "undo_log"],
           "undo_log: in TABLE_CLASSES")
    expect("duplicate definition", ["blocks", "blocks"], ["blocks"],
           "duplicate table definition")
    expect("duplicate class", ["blocks"], ["blocks", "blocks"],
           "duplicate class row")
    if compare(["blocks", "undo_log"], ["undo_log", "blocks"]):
        raise SystemExit("selftest clean pair refused")
    print("redb schema bijection selftest: 6 refusals fire")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        main()
