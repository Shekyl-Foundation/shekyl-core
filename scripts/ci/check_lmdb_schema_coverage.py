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
#
# The heading leg (P0a, 2026-09-05) repairs an imprecision in that
# recognition rule: the property-row comparison deduplicates through set(),
# so a SECOND section heading claiming the same table is invisible to it —
# and the doc carried a duplicate `properties` heading from before the DRS
# Round-2 pin (42 headings over 41 property rows at `3247fe3b6`) without
# this gate ever seeing it. A reader navigates by headings, so the
# completeness claim the forward leg was already making is really a claim
# about headings; this leg states it at that layer: section headings must
# be a duplicate-free bijection with the table list.
#
# The registry leg (P0a, 2026-09-05) pins the DRS reconciliation registry
# (docs/design/DAEMON_REDB_STORE.md) to the same source: its per-table rows
# must be a bijection with SHEKYL_LMDB_TABLES, and its stated row count must
# match — the schema doc's own "Total: 41" drifted silently for exactly the
# want of such a pin.

import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "blockchain_db" / "lmdb" / "db_lmdb.cpp"
DOC = ROOT / "docs" / "LMDB_SCHEMA.md"
DRS = ROOT / "docs" / "design" / "DAEMON_REDB_STORE.md"
AUDIT = ROOT / "docs" / "LMDB_WRITE_ATOMICITY_AUDIT.md"

# Subject assertion floor: the list held 49 names when this gate was written.
# A parse yielding fewer than this is a broken parse (or a mass table
# deletion, which deserves a deliberate edit here either way).
MIN_TABLES = 40


def duplicates(names: list[str]) -> list[str]:
    """Names appearing more than once, sorted.

    Every leg below asks this question, so it is asked in one place: a
    per-name `list.count()` inside a comprehension is quadratic and, more to
    the point, invites the next leg to copy the wrong shape.
    """
    counts = collections.Counter(names)
    return sorted(name for name, n in counts.items() if n > 1)


def parse_table_list(text: str) -> list[str]:
    m = re.search(r"^#define SHEKYL_LMDB_TABLES\(X\)(.*?)^\s*$", text,
                  re.MULTILINE | re.DOTALL)
    if not m:
        sys.exit("FAIL: SHEKYL_LMDB_TABLES macro not found in db_lmdb.cpp — "
                 "the gate's subject is missing (was the list renamed?)")
    names = re.findall(r'X\([A-Z0-9_]+,\s*"([a-z0-9_]+)"\)', m.group(1))
    return names


def main() -> None:
    source_text = SOURCE.read_text(encoding="utf-8")
    tables = parse_table_list(source_text)
    if len(tables) < MIN_TABLES:
        sys.exit(f"FAIL: parsed only {len(tables)} table names from "
                 f"SHEKYL_LMDB_TABLES (floor {MIN_TABLES}) — broken parse or "
                 "mass deletion; both need a human")
    if "blocks" not in tables:
        sys.exit("FAIL: sentinel table 'blocks' missing from the parsed list "
                 "— the parse is not reading the real macro")
    dupes = duplicates(tables)
    if dupes:
        sys.exit(f"FAIL: duplicate names in SHEKYL_LMDB_TABLES: {dupes}")

    # The DECLARED table set, computed once: every leg below compares against
    # it in both directions. Declared, not runtime — a writable open() drops
    # `hf_starting_heights` (LMDB_WRITE_ATOMICITY_AUDIT.md, DRS-W5), so the
    # running store holds one fewer. This gate cannot see that difference by
    # construction, since both sides of every comparison it makes derive from
    # this same macro; naming the set precisely is the least it can do.
    table_set = set(tables)

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
    ghosts = sorted(documented - table_set)
    if ghosts:
        errors.append(
            "these tables have sections in docs/LMDB_SCHEMA.md but are NOT "
            "in SHEKYL_LMDB_TABLES (deleted table, surviving section?):\n  "
            + "\n  ".join(ghosts))

    # Heading leg. Same claim as the two directions above, stated at the
    # layer a reader actually navigates: `### `name`` section headings must
    # be a duplicate-free bijection with the table list. The property-row
    # legs dedupe through set(), so only this leg can see two sections
    # claiming the same table (live instance: the pre-pin duplicate
    # `properties` heading).
    headings = re.findall(r"^### `([a-z0-9_]+)`", doc, re.MULTILINE)
    if len(headings) < MIN_TABLES or "blocks" not in headings:
        sys.exit(f"FAIL: parsed only {len(headings)} '### `name`' section "
                 f"headings from docs/LMDB_SCHEMA.md (floor {MIN_TABLES}, "
                 "sentinel 'blocks') — the heading parse is not reading the "
                 "real doc")
    heading_set = set(headings)
    dup_headings = duplicates(headings)
    if dup_headings:
        errors.append(
            "these tables have MORE THAN ONE '### `name`' section heading in "
            "docs/LMDB_SCHEMA.md (two sections claiming one table — invisible "
            "to the property-row legs):\n  " + "\n  ".join(dup_headings))
    unheaded = [t for t in tables if t not in heading_set]
    if unheaded:
        errors.append(
            "these tables have an 'LMDB name' property row but no '### "
            "`name`' section heading in docs/LMDB_SCHEMA.md (or neither):\n  "
            + "\n  ".join(unheaded))
    stranded = sorted(heading_set - table_set)
    if stranded:
        errors.append(
            "these '### `name`' section headings in docs/LMDB_SCHEMA.md name "
            "tables absent from SHEKYL_LMDB_TABLES (deleted table, surviving "
            "heading?):\n  " + "\n  ".join(stranded))

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
    code_v = re.search(r"^#define VERSION (\d+)$", source_text, re.MULTILINE)
    doc_v = re.search(r"^\*\*DB version:\*\* (\d+)", doc, re.MULTILINE)
    if not code_v:
        errors.append("#define VERSION not found in db_lmdb.cpp — the gate's "
                      "version subject is missing")
    elif not doc_v:
        errors.append("the doc's '**DB version:** N' header line is missing")
    elif doc_v.group(1) != code_v.group(1):
        errors.append(f"the doc header says DB version {doc_v.group(1)}; "
                      f"db_lmdb.cpp defines VERSION {code_v.group(1)}")

    # Registry leg. The P0a reconciliation registry in the DRS design doc
    # claims one row per DECLARED table; that claim gets the same pin the schema
    # doc has, or it drifts the same way the schema doc's "Total: 41" did.
    # Subject assertion first (rule 47): the registry section itself must
    # exist and parse to a plausible row set before its content is compared.
    # Subject failures here still flush any errors already accumulated by
    # the earlier legs — a missing registry must not mask a heading defect
    # (the workflow runs these legs under one process, so masking would be
    # exactly the one-defect-hides-another failure docs-gates.yml avoids
    # between scripts).
    def _fail(msg: str) -> None:
        sys.exit("FAIL: " + msg + ("" if not errors else
                 "\n(also, from the earlier legs:)\n" + "\n".join(errors)))

    # This is the one read that runs after errors have accumulated, so an
    # unreadable file must take the flushing _fail path — a raw traceback
    # here would mask any heading-leg findings (the SOURCE/DOC reads above
    # run before anything can accumulate, so their tracebacks mask nothing).
    try:
        drs = DRS.read_text(encoding="utf-8")
    except OSError as e:
        _fail(f"cannot read docs/design/DAEMON_REDB_STORE.md ({e}) — the "
              "registry this gate pins is unreadable")
    reg_m = re.search(
        r"^### P0a reconciliation registry\b.*?(?=^#{2,3} |\Z)", drs,
        re.MULTILINE | re.DOTALL)
    if not reg_m:
        _fail("'### P0a reconciliation registry' section not found in "
              "docs/design/DAEMON_REDB_STORE.md — the registry this gate "
              "pins is missing (renamed heading? deleted section?)")
    reg_rows = re.findall(r"^\| `([a-z0-9_]+)` \|", reg_m.group(0),
                          re.MULTILINE)
    if len(reg_rows) < MIN_TABLES or "blocks" not in reg_rows:
        _fail(f"parsed only {len(reg_rows)} table rows from the P0a "
              f"reconciliation registry (floor {MIN_TABLES}, sentinel "
              "'blocks') — the registry parse is not reading real rows")
    reg_set = set(reg_rows)
    reg_dupes = duplicates(reg_rows)
    if reg_dupes:
        errors.append("duplicate rows in the P0a reconciliation registry "
                      "(DAEMON_REDB_STORE.md):\n  " + "\n  ".join(reg_dupes))
    reg_missing = [t for t in tables if t not in reg_set]
    if reg_missing:
        errors.append(
            "these tables exist in SHEKYL_LMDB_TABLES but have no row in the "
            "P0a reconciliation registry (DAEMON_REDB_STORE.md):\n  "
            + "\n  ".join(reg_missing))
    reg_ghosts = sorted(reg_set - table_set)
    if reg_ghosts:
        errors.append(
            "these P0a reconciliation registry rows name tables absent from "
            "SHEKYL_LMDB_TABLES (deleted table, surviving row?):\n  "
            + "\n  ".join(reg_ghosts))
    reg_count = re.search(r"\*\*(\d+) rows\*\*", reg_m.group(0))
    if not reg_count:
        errors.append("the P0a reconciliation registry's '**N rows**' count "
                      "line is missing — the row-count claim this gate "
                      "checks no longer exists")
    elif int(reg_count.group(1)) != len(tables):
        errors.append(f"the P0a reconciliation registry claims "
                      f"{reg_count.group(1)} rows; SHEKYL_LMDB_TABLES has "
                      f"{len(tables)} tables")

    # Audit leg (P0b, 2026-09-05). The atomicity audit's §10 coverage matrix
    # claims one row per DECLARED table — the DRS §9.1 leg-3 pin ("every MDB_dbi
    # in the audit"), stated at the table-name layer the macro owns. Same
    # subject-assertion and non-masking discipline as the registry leg.
    try:
        audit = AUDIT.read_text(encoding="utf-8")
    except OSError as e:
        _fail(f"cannot read docs/LMDB_WRITE_ATOMICITY_AUDIT.md ({e}) — the "
              "coverage matrix this gate pins is unreadable")
    mat_m = re.search(
        r"^## 10\. Coverage matrix\b.*?(?=^## |\Z)", audit,
        re.MULTILINE | re.DOTALL)
    if not mat_m:
        _fail("'## 10. Coverage matrix' section not found in "
              "docs/LMDB_WRITE_ATOMICITY_AUDIT.md — the audit no longer "
              "carries the per-table matrix this gate pins")
    mat_rows = re.findall(r"^\| `([a-z0-9_]+)` \|", mat_m.group(0),
                          re.MULTILINE)
    if len(mat_rows) < MIN_TABLES or "blocks" not in mat_rows:
        _fail(f"parsed only {len(mat_rows)} table rows from the audit "
              f"coverage matrix (floor {MIN_TABLES}, sentinel 'blocks') — "
              "the matrix parse is not reading real rows")
    mat_set = set(mat_rows)
    mat_dupes = duplicates(mat_rows)
    if mat_dupes:
        errors.append("duplicate rows in the audit coverage matrix "
                      "(LMDB_WRITE_ATOMICITY_AUDIT.md §10):\n  "
                      + "\n  ".join(mat_dupes))
    mat_missing = [t for t in tables if t not in mat_set]
    if mat_missing:
        errors.append(
            "these tables exist in SHEKYL_LMDB_TABLES but have no row in the "
            "audit coverage matrix (LMDB_WRITE_ATOMICITY_AUDIT.md §10):\n  "
            + "\n  ".join(mat_missing))
    mat_ghosts = sorted(mat_set - table_set)
    if mat_ghosts:
        errors.append(
            "these audit coverage matrix rows name tables absent from "
            "SHEKYL_LMDB_TABLES (deleted table, surviving row?):\n  "
            + "\n  ".join(mat_ghosts))
    mat_count = re.search(r"\*\*(\d+) rows\*\*", mat_m.group(0))
    if not mat_count:
        errors.append("the audit coverage matrix's '**N rows**' count line "
                      "is missing — the row-count claim this gate checks no "
                      "longer exists")
    elif int(mat_count.group(1)) != len(tables):
        errors.append(f"the audit coverage matrix claims "
                      f"{mat_count.group(1)} rows; SHEKYL_LMDB_TABLES has "
                      f"{len(tables)} tables")

    if errors:
        sys.exit("FAIL: the LMDB schema surface is out of step with the live "
                 "table list:\n" + "\n".join(errors))

    print(f"OK: all {len(tables)} LMDB tables documented (property rows and "
          "headings), reconciliation registry and atomicity-audit matrix "
          "match, stated totals and DB-version header match the code")


if __name__ == "__main__":
    main()
