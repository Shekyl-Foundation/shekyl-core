# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-0 slice B: the redb schema map is a BIJECTION with the censused LMDB
# inventory. Every table in `SHEKYL_LMDB_TABLES` has exactly one
# `redb::TableDefinition` (or `MultimapTableDefinition`), and every definition
# has exactly one X-macro table. Both directions, no duplicates on either side.
#
# WHY THE X-MACRO IS THE SOURCE. Walking `BlockchainDB`'s virtual interface
# would miss tables: the settlement pair exists only on `BlockchainLMDB` (zero
# occurrences in blockchain_db.h and testdb.h, five in db_lmdb.h), so a schema
# built from the abstract interface silently ships without a write path LMDB
# has. SO-D8 owns promoting it; this gate refuses to inherit the gap.
#
# THIS GATE CHECKS NAMES, NOT TYPES. Ordering is `check_redb_schema_key_types.py`
# in the same workflow; comparator evidence is in `lmdb_order`'s tests (pinned
# against a transcription of the C++ over 4 000 pairs); class evidence is
# per-row in LMDB_WRITE_ATOMICITY_AUDIT.md §12. "49/49 mapped" is a claim on
# one axis.
#
# Instance of 47-gate-subject-assertion.mdc: an empty parse on either side has
# an empty difference, which is indistinguishable from a clean run.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"
CLASSES = ROOT / "rust/shekyl-chain-store/src/accumulator/class.rs"

MACRO_RE = re.compile(r"#define SHEKYL_LMDB_TABLES\(X\)(.*?)\n\n", re.S)
ENTRY_RE = re.compile(r'X\(\s*\w+\s*,\s*"([^"]+)"\s*\)')
DEF_RE = re.compile(r'(?:Multimap)?TableDefinition::new\("([^"]+)"\)')


def dupes(names):
    seen, out = set(), []
    for n in names:
        if n in seen:
            out.append(n)
        seen.add(n)
    return out


def main():
    failures = []
    for p in (LMDB, SCHEMA, CLASSES):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    src = LMDB.read_text(encoding="utf-8")
    m = MACRO_RE.search(src)
    if not m:
        report([f"{LMDB.name}: SHEKYL_LMDB_TABLES macro did not parse — subject missing"])
    censused = ENTRY_RE.findall(m.group(1))

    schema = SCHEMA.read_text(encoding="utf-8")
    defined = DEF_RE.findall(schema)

    # Subject assertions: an empty side covers trivially.
    if not censused:
        failures.append(f"{LMDB.name}: parsed ZERO tables from SHEKYL_LMDB_TABLES")
    if not defined:
        failures.append(f"{SCHEMA.name}: parsed ZERO TableDefinitions")
    if failures:
        report(failures)

    for label, names in (("SHEKYL_LMDB_TABLES", censused), ("schema.rs", defined)):
        d = dupes(names)
        if d:
            failures.append(f"{label}: duplicate table name(s): {', '.join(sorted(set(d)))}")

    # THIRD SURFACE: slice A's accumulator class table. lib.rs requires slice B's
    # names to be bijection-pinned against it, and two lanes maintaining one
    # table list is precisely where drift lives — so it is checked here rather
    # than asserted in prose.
    ctext = CLASSES.read_text(encoding="utf-8")
    cstart = ctext.find("pub const TABLE_CLASSES")
    classed = []
    if cstart < 0:
        failures.append(f"{CLASSES.name}: TABLE_CLASSES did not parse — third surface missing")
    else:
        block = ctext[cstart:]
        block = block[: block.index("\n];")]
        classed = re.findall(r'"([a-z_0-9]+)"', block)
        if not classed:
            failures.append(f"{CLASSES.name}: parsed ZERO class entries — third surface missing")
        d = dupes(classed)
        if d:
            failures.append(f"TABLE_CLASSES: duplicate table name(s): {', '.join(sorted(set(d)))}")
        only_class = sorted(set(classed) - set(censused))
        only_macro = sorted(set(censused) - set(classed))
        if only_class:
            failures.append(
                f"{len(only_class)} name(s) in TABLE_CLASSES are NOT in the X-macro:\n    "
                + ", ".join(only_class))
        if only_macro:
            failures.append(
                f"{len(only_macro)} censused table(s) carry NO accumulator class:\n    "
                + ", ".join(only_macro)
                + "\n    Slice A assigns one of five tokens to every table; a gap here means "
                  "the two slices disagree about the inventory.")

    missing = sorted(set(censused) - set(defined))
    extra = sorted(set(defined) - set(censused))
    if missing:
        failures.append(
            f"{len(missing)} censused table(s) have NO redb TableDefinition:\n    "
            + ", ".join(missing)
            + "\n    Every table in the X-macro must be mapped; a gap here ships a store "
              "missing a table LMDB has.")
    if extra:
        failures.append(
            f"{len(extra)} TableDefinition(s) name a table that is NOT in the X-macro:\n    "
            + ", ".join(extra)
            + "\n    This is how a plausible concept becomes an invented table — check "
              "whether it is really a row inside another table.")

    report(failures)
    print(f"redb schema bijection: {len(censused)} censused LMDB tables <-> "
          f"{len(defined)} redb table definitions <-> {len(classed)} accumulator classes; "
          f"no duplicates, no gaps in any direction")


def report(failures):
    if failures:
        print("redb schema bijection FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
