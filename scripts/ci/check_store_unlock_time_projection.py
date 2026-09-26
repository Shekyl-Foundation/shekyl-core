#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""No public read type under `shekyl-chain-store/src/store/` has an `unlock_time` field.

# Why this gate exists

`TxIndex.unlock_time` and `OutKey.unlock_time` are stored because LMDB's
`txindex` / `output_data_t` stored them. Under FCMP++ maturity is computed from
height and the miner flag; the C++ reader of the tx field is transitively
callerless (S-TX STX-1), and the field's fate — keep, or delete with a layout
bump — is census **U-2**'s ruling, not any read surface's. Until that ruling,
the store keeps writing the field and **no read hands it out**: a projection
nobody consumes is how a dead field acquires a second reason to exist, and a
field three crates have quietly taken a dependency on by the time someone
rules is a different problem from a field nobody uses (`DRS_E1_STX.md` §3.5,
STX-9).

The first form of that invariant — "no read projects the field" — was
ambiguous between *decodes a row containing it* and *returns it*, and the
ambiguity let a read return the stored row whole (PR #786 review round 3).
The checkable form is narrower: **no public read type under `store/` has an
`unlock_time` field.** Reads decode `TxIndex` and `OutKey` rows — the field is
in their bytes — but no type they return carries it.

# What it asserts

1. **Subject (rule 47):** the stored codec rows under `codec/` still declare
   `pub unlock_time` — at least one. If they do not, the field has been
   deleted from the layout and this gate has no subject: it fails so the row
   here is deleted with it rather than passing vacuously forever.
2. **The invariant:** no `.rs` file under `store/` declares a
   `pub unlock_time` field (public struct field; `pub(crate)` and `pub(super)`
   count — a crate-visible projection is still a projection). Test modules
   are excluded: a test may construct a stored row.

Line-shaped by design: the field declaration is one token in one position,
so a regex is exact here in a way it is not for expressions. A struct-parser
would be the wrong instrument for a check this narrow.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "rust/shekyl-chain-store/src/store"
CODEC = ROOT / "rust/shekyl-chain-store/src/codec"

FIELD_RE = re.compile(r"^\s*pub(?:\([^)]*\))?\s+unlock_time\s*:")


def rust_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.rs") if not p.name.endswith("_tests.rs"))


def declarations(files: list[Path]) -> list[tuple[Path, int, str]]:
    hits = []
    for path in files:
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if FIELD_RE.match(line):
                hits.append((path, i, line.strip()))
    return hits


def main() -> int:
    for d in (STORE, CODEC):
        if not d.is_dir():
            print(f"unlock_time projection gate: {d.relative_to(ROOT)} missing — subject absent", file=sys.stderr)
            return 1

    stored = declarations(rust_files(CODEC))
    if not stored:
        print(
            "unlock_time projection gate FAILED: no `pub unlock_time` field under codec/ — "
            "the stored field is gone (U-2 ruled?), so this gate has no subject; delete it "
            "with the field rather than let it pass vacuously.",
            file=sys.stderr,
        )
        return 1

    projected = declarations(rust_files(STORE))
    if projected:
        print("unlock_time projection gate FAILED:\n", file=sys.stderr)
        for path, line, text in projected:
            print(
                f"  - {path.relative_to(ROOT)}:{line}: `{text}` — a public read type under "
                f"store/ carries `unlock_time`. The field's fate is census U-2's; no read "
                f"projects it until U-2 rules (DRS_E1_STX.md STX-9). Drop the field from the "
                f"projection, or mint the read for the rule that needs it, by name.",
                file=sys.stderr,
            )
        return 1

    print(
        f"unlock_time projection gate OK: {len(stored)} stored codec field(s) declare it "
        f"({', '.join(sorted({p.name for p, _, _ in stored}))}); no public read type under "
        f"store/ carries it ({len(rust_files(STORE))} files scanned)"
    )
    return 0


def selftest() -> int:
    cases = [
        ("public field", "    pub unlock_time: Timelock,", True),
        ("crate-visible field", "    pub(crate) unlock_time: Timelock,", True),
        ("super-visible field", "    pub(super) unlock_time: u64,", True),
        ("private field is not a projection", "    unlock_time: Timelock,", False),
        ("a local named unlock_time", "        let unlock_time = row.unlock_time;", False),
        ("a field access", "        unlock_time: record.unlock_time,", False),
        ("a doc mention", "    /// pub unlock_time: what we no longer hand out", False),
        ("a differently named field", "    pub unlock_time_hint: u64,", False),
    ]
    bad = [f"{label}: expected {want}" for label, line, want in cases if bool(FIELD_RE.match(line)) != want]
    if bad:
        print("unlock_time projection selftest FAILED:\n  - " + "\n  - ".join(bad), file=sys.stderr)
        return 1
    print(f"unlock_time projection selftest: {len(cases)} cases held")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else main())
