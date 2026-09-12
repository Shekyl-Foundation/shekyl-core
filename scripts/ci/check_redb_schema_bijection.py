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
# THIS GATE HAS ALREADY EARNED ITSELF. The first draft of the schema map,
# written from familiarity with the subsystem rather than from the macro, had
# 52 entries: it invented `archival_claimed_epochs`, `archival_prune_watermark`,
# `archival_reward_paid` and `archival_bond_value` — all real concepts, none of
# them tables (the watermark is a `properties` key) — and omitted the real
# `output_metadata`.
#
# WHAT THIS GATE DOES NOT CHECK, stated because a green here is narrower than
# it looks: it checks NAMES, not types. It cannot tell whether a table's key
# type reproduces LMDB's ordering, whether a value encoding is canonical, or
# whether a set-shaped table's accumulator hook reads before deleting. The
# comparator evidence is in `hash_order.rs`'s tests (pinned against a
# transcription of the C++ over 4 000 pairs); the class evidence is per-row in
# LMDB_WRITE_ATOMICITY_AUDIT.md §12. "49/49 mapped" is a claim on one axis.
#
# Instance of 47-gate-subject-assertion.mdc: an empty parse on either side has
# an empty difference, which is indistinguishable from a clean run.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LMDB = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SCHEMA = ROOT / "rust/shekyl-chain-store/src/schema.rs"

MACRO_RE = re.compile(r"#define SHEKYL_LMDB_TABLES\(X\)(.*?)\n\n", re.S)
ENTRY_RE = re.compile(r'X\(\s*\w+\s*,\s*"([^"]+)"\s*\)')
DEF_RE = re.compile(r'(?:Multimap)?TableDefinition::new\("([^"]+)"\)')
LIST_RE = re.compile(r"ALL_TABLE_NAMES:\s*\[&str;\s*(\d+)\]\s*=\s*\[(.*?)\];", re.S)


def dupes(names):
    seen, out = set(), []
    for n in names:
        if n in seen:
            out.append(n)
        seen.add(n)
    return out


def main():
    failures = []
    for p in (LMDB, SCHEMA):
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

    # The module's own self-declaration must agree with its definitions.
    lm = LIST_RE.search(schema)
    if not lm:
        failures.append(f"{SCHEMA.name}: ALL_TABLE_NAMES did not parse — the module's self-claim is missing")
    else:
        declared_len = int(lm.group(1))
        listed = re.findall(r'"([^"]+)"', lm.group(2))
        if len(listed) != declared_len:
            failures.append(
                f"ALL_TABLE_NAMES declares [&str; {declared_len}] but contains {len(listed)} entries")
        if sorted(listed) != sorted(defined):
            only_list = sorted(set(listed) - set(defined))
            only_def = sorted(set(defined) - set(listed))
            failures.append(
                f"ALL_TABLE_NAMES disagrees with the TableDefinitions in the same module — "
                f"listed-only: {only_list or 'none'}; defined-only: {only_def or 'none'}")

    report(failures)
    print(f"redb schema bijection: {len(censused)} censused LMDB tables <-> "
          f"{len(defined)} redb table definitions, no duplicates, no gaps in either direction")


def report(failures):
    if failures:
        print("redb schema bijection FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
