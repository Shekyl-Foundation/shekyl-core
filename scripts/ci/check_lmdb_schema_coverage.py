# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# LMDB schema-reference coverage gate.
#
# Every table in the `SHEKYL_LMDB_TABLES` X-macro list (db_lmdb.cpp — the
# single source `mdb_env_set_maxdbs` is derived from, SO-D4) must have a
# section in docs/LMDB_SCHEMA.md, and the doc's stated sub-database total
# must equal the list's length.
#
# Why this exists. The schema reference presented itself as complete
# ("Total: 41 sub-databases") while NINE live tables had zero mentions —
# block_burn, both attestation-witness tables, all four bond/emission
# journals, and both budget tables — drift accumulated across the rounds
# that added them, found 2026-08-26 during the PC review round. A reader
# planning a migration or a range scan from the doc had no way to see the
# gap: absence of a section reads as absence of a table.
#
# Instance of `47-gate-subject-assertion.mdc`: the gate asserts its own
# subject exists (a parsed list of at least MIN_TABLES names, containing the
# sentinel "blocks") so an empty or mis-anchored parse fails loudly instead
# of passing vacuously over nothing.
#
# A section is recognized by the doc containing the exact backtick-quoted
# LMDB name (`"blocks"`) — the "LMDB name" property-row convention every
# existing section uses. The total is the `Total: **N sub-databases**` line.

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "blockchain_db" / "lmdb" / "db_lmdb.cpp"
DOC = ROOT / "docs" / "LMDB_SCHEMA.md"

# Subject assertion floor: the list held 49 names when this gate was written.
# A parse yielding fewer than this is a broken parse (or a mass table
# deletion, which deserves a deliberate edit here either way).
MIN_TABLES = 40


def parse_table_list(text: str) -> list[str]:
    m = re.search(r"^#define SHEKYL_LMDB_TABLES\(X\)(.*?)^\s*$", text,
                  re.MULTILINE | re.DOTALL)
    if not m:
        sys.exit("FAIL: SHEKYL_LMDB_TABLES macro not found in db_lmdb.cpp — "
                 "the gate's subject is missing (was the list renamed?)")
    names = re.findall(r'X\([A-Z0-9_]+,\s*"([a-z0-9_]+)"\)', m.group(1))
    return names


def main() -> None:
    tables = parse_table_list(SOURCE.read_text(encoding="utf-8"))
    if len(tables) < MIN_TABLES:
        sys.exit(f"FAIL: parsed only {len(tables)} table names from "
                 f"SHEKYL_LMDB_TABLES (floor {MIN_TABLES}) — broken parse or "
                 "mass deletion; both need a human")
    if "blocks" not in tables:
        sys.exit("FAIL: sentinel table 'blocks' missing from the parsed list "
                 "— the parse is not reading the real macro")
    if len(set(tables)) != len(tables):
        dupes = sorted({t for t in tables if tables.count(t) > 1})
        sys.exit(f"FAIL: duplicate names in SHEKYL_LMDB_TABLES: {dupes}")

    doc = DOC.read_text(encoding="utf-8")

    # Both directions compare against the parsed `LMDB name` property rows —
    # the one line a section cannot exist without. A bare substring test for
    # `"name"` would be satisfied by any prose mention (a migration note, a
    # cross-reference), letting the gate stay green for exactly the
    # undocumented-table drift it exists to catch.
    documented = set(re.findall(r'\| LMDB name \| `"([a-z0-9_]+)"` \|', doc))

    missing = [t for t in tables if t not in documented]
    errors = []
    if missing:
        errors.append(
            "these tables exist in SHEKYL_LMDB_TABLES but have no section in "
            "docs/LMDB_SCHEMA.md (no `| LMDB name | \"<name>\" |` property "
            "row):\n  " + "\n  ".join(missing))

    # Ghost check — the inverse direction. A section whose `LMDB name`
    # property row names a table absent from the list documents a table that
    # does not exist (found live: `staker_accrual` / `staker_claims` kept
    # their sections after the claim-era wire deletion removed the tables).
    ghosts = sorted(documented - set(tables))
    if ghosts:
        errors.append(
            "these tables have sections in docs/LMDB_SCHEMA.md but are NOT "
            "in SHEKYL_LMDB_TABLES (deleted table, surviving section?):\n  "
            + "\n  ".join(ghosts))

    m = re.search(r"Total: \*\*(\d+) sub-databases\*\*", doc)
    if not m:
        errors.append("the doc's 'Total: **N sub-databases**' line is missing "
                      "— the count claim this gate checks no longer exists")
    elif int(m.group(1)) != len(tables):
        errors.append(f"the doc claims {m.group(1)} sub-databases; "
                      f"SHEKYL_LMDB_TABLES has {len(tables)}")

    # Header version pin — the claim that drifted twice (header said v8
    # against VERSION 10; the properties row carried a third copy). The doc
    # header must name the same number the code defines.
    code_v = re.search(r"^#define VERSION (\d+)$",
                       SOURCE.read_text(encoding="utf-8"), re.MULTILINE)
    doc_v = re.search(r"^\*\*DB version:\*\* (\d+)", doc, re.MULTILINE)
    if not code_v:
        errors.append("#define VERSION not found in db_lmdb.cpp — the gate's "
                      "version subject is missing")
    elif not doc_v:
        errors.append("the doc's '**DB version:** N' header line is missing")
    elif doc_v.group(1) != code_v.group(1):
        errors.append(f"the doc header says DB version {doc_v.group(1)}; "
                      f"db_lmdb.cpp defines VERSION {code_v.group(1)}")

    if errors:
        sys.exit("FAIL: docs/LMDB_SCHEMA.md is out of step with the live "
                 "table list:\n" + "\n".join(errors))

    print(f"OK: all {len(tables)} LMDB tables documented; stated total and "
          "DB-version header match the code")


if __name__ == "__main__":
    main()
