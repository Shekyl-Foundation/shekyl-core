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

from __future__ import annotations

import collections
import os
import pathlib
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass

# The shared GFM splitter sits beside this script; do not depend on the
# caller's sys.path, which differs between `python3 scripts/ci/x.py` and
# an import (same pattern as check_index_table_shape.py).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _gfm_table import split_cells

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src" / "blockchain_db" / "lmdb" / "db_lmdb.cpp"
DOC = ROOT / "docs" / "LMDB_SCHEMA.md"
DRS = ROOT / "docs" / "design" / "DAEMON_REDB_STORE.md"
AUDIT = ROOT / "docs" / "LMDB_WRITE_ATOMICITY_AUDIT.md"

# Subject assertion floor: the list held 49 names when this gate was written.
# A parse yielding fewer than this is a broken parse (or a mass table
# deletion, which deserves a deliberate edit here either way).
MIN_TABLES = 40

DIGEST_V0_TABLES = {"blocks", "block_info", "spent_keys", "curve_tree_meta"}
DIGEST_STATES = frozenset({"v0", "v0-partial", "excluded", "uncovered"})
ACCUM_CLASSES = frozenset({
    "set-shaped", "append-mostly", "small", "derived", "excluded",
})

BACKTICK_NAME = re.compile(r"`([a-z0-9_]+)`")
ROW_STATED_COUNT = re.compile(r"\((\d+)\)")
COVERAGE_ROW = re.compile(
    r"^\| `([a-z0-9_]+)` \|.*\| ([a-z0-9-]+) \| ([a-z-]+) \|$",
    re.MULTILINE,
)


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
    return re.findall(r'X\([A-Z0-9_]+,\s*"([a-z0-9_]+)"\)', m.group(1))


def _heading_block(text: str, heading: str) -> str | None:
    """Body of an ATX heading through the next heading of the same or higher
    level. `heading` is the full line contents without the trailing newline,
    e.g. `'## 10. Coverage matrix'`."""
    hashes, _, rest = heading.partition(" ")
    if not hashes or set(hashes) != {"#"} or not rest:
        raise ValueError(f"not an ATX heading: {heading!r}")
    level = len(hashes)
    pat = (r"^" + re.escape(heading) + r"\b.*?"
           r"(?=^#{1," + str(level) + r"} |\Z)")
    m = re.search(pat, text, re.MULTILINE | re.DOTALL)
    return None if not m else m.group(0)


def _fail(msg: str, errors: list[str]) -> None:
    sys.exit("FAIL: " + msg + ("" if not errors else
             "\n(also, from the earlier legs:)\n" + "\n".join(errors)))


def _bijection_errors(
    *,
    source_names: list[str],
    listed: list[str],
    missing_fmt: str,
    ghost_fmt: str,
    duplicate_fmt: str,
) -> list[str]:
    """Both directions of a name-set bijection, plus duplicate detection."""
    errors: list[str] = []
    listed_set = set(listed)
    source_set = set(source_names)
    dupes = duplicates(listed)
    if dupes:
        errors.append(duplicate_fmt + "\n  " + "\n  ".join(dupes))
    missing = [t for t in source_names if t not in listed_set]
    if missing:
        errors.append(missing_fmt + "\n  " + "\n  ".join(missing))
    ghosts = sorted(listed_set - source_set)
    if ghosts:
        errors.append(ghost_fmt + "\n  " + "\n  ".join(ghosts))
    return errors


def _token_column_errors(
    *,
    tables: list[str],
    pairs: list[tuple[str, str]],
    allowed: frozenset[str],
    column: str,
    missing_fmt: str,
) -> tuple[dict[str, str], list[str]]:
    """Validate a per-table token column: known tokens, one per table."""
    errors: list[str] = []
    mapping = dict(pairs)
    if len(mapping) != len(pairs):
        errors.append(
            f"duplicate table rows while reading the {column} "
            "column of the audit coverage matrix")
    bad = sorted(f"{t} -> {v}" for t, v in mapping.items() if v not in allowed)
    if bad:
        errors.append(
            f"these audit coverage matrix rows carry an unknown {column} "
            "(allowed: " + ", ".join(sorted(allowed)) + "):\n  "
            + "\n  ".join(bad))
    missing = [t for t in tables if t not in mapping]
    if missing:
        errors.append(missing_fmt + "\n  " + "\n  ".join(missing))
    return mapping, errors


# ---------------------------------------------------------------------------
# Schema doc, version pin, P0a registry
# ---------------------------------------------------------------------------

def check_schema_doc(doc: str, tables: list[str]) -> list[str]:
    errors: list[str] = []
    table_set = set(tables)
    documented = set(re.findall(r'\| LMDB name \| `"([a-z0-9_]+)"` \|', doc))

    missing = [t for t in tables if t not in documented]
    if missing:
        errors.append(
            "these tables exist in SHEKYL_LMDB_TABLES but have no section in "
            "docs/LMDB_SCHEMA.md (no `| LMDB name | \"<name>\" |` property "
            "row):\n  " + "\n  ".join(missing))
    ghosts = sorted(documented - table_set)
    if ghosts:
        errors.append(
            "these tables have sections in docs/LMDB_SCHEMA.md but are NOT "
            "in SHEKYL_LMDB_TABLES (deleted table, surviving section?):\n  "
            + "\n  ".join(ghosts))

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
    return errors


def check_version_pin(source_text: str, doc: str) -> list[str]:
    errors: list[str] = []
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
    return errors


def check_registry(drs: str, tables: list[str], errors: list[str]) -> list[str]:
    reg_m = re.search(
        r"^### P0a reconciliation registry\b.*?(?=^#{2,3} |\Z)", drs,
        re.MULTILINE | re.DOTALL)
    if not reg_m:
        _fail("'### P0a reconciliation registry' section not found in "
              "docs/design/DAEMON_REDB_STORE.md — the registry this gate "
              "pins is missing (renamed heading? deleted section?)", errors)
    reg_rows = re.findall(r"^\| `([a-z0-9_]+)` \|", reg_m.group(0),
                          re.MULTILINE)
    if len(reg_rows) < MIN_TABLES or "blocks" not in reg_rows:
        _fail(f"parsed only {len(reg_rows)} table rows from the P0a "
              f"reconciliation registry (floor {MIN_TABLES}, sentinel "
              "'blocks') — the registry parse is not reading real rows",
              errors)
    errors.extend(_bijection_errors(
        source_names=tables,
        listed=reg_rows,
        duplicate_fmt="duplicate rows in the P0a reconciliation registry "
                      "(DAEMON_REDB_STORE.md):",
        missing_fmt="these tables exist in SHEKYL_LMDB_TABLES but have no "
                    "row in the P0a reconciliation registry "
                    "(DAEMON_REDB_STORE.md):",
        ghost_fmt="these P0a reconciliation registry rows name tables absent "
                  "from SHEKYL_LMDB_TABLES (deleted table, surviving row?):",
    ))
    reg_count = re.search(r"\*\*(\d+) rows\*\*", reg_m.group(0))
    if not reg_count:
        errors.append("the P0a reconciliation registry's '**N rows**' count "
                      "line is missing — the row-count claim this gate "
                      "checks no longer exists")
    elif int(reg_count.group(1)) != len(tables):
        errors.append(f"the P0a reconciliation registry claims "
                      f"{reg_count.group(1)} rows; SHEKYL_LMDB_TABLES has "
                      f"{len(tables)} tables")
    return errors


# ---------------------------------------------------------------------------
# Audit coverage matrix
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CoverageRow:
    name: str
    digest_state: str
    accum_class: str


def parse_coverage_rows(matrix: str) -> list[CoverageRow]:
    """Trailing two columns of the §10 matrix, by position.

    The pattern used to capture 'the last column' and would have started
    reading class tokens as digest states when the class column landed to
    its right. Both trailing columns are therefore positional.
    """
    return [
        CoverageRow(name=t, digest_state=state, accum_class=cls)
        for t, state, cls in COVERAGE_ROW.findall(matrix)
    ]


def check_audit_matrix(
    audit: str, tables: list[str], errors: list[str],
) -> tuple[str, list[CoverageRow]]:
    mat = _heading_block(audit, "## 10. Coverage matrix")
    if not mat:
        _fail("'## 10. Coverage matrix' section not found in "
              "docs/LMDB_WRITE_ATOMICITY_AUDIT.md — the audit no longer "
              "carries the per-table matrix this gate pins", errors)
    mat_rows = re.findall(r"^\| `([a-z0-9_]+)` \|", mat, re.MULTILINE)
    if len(mat_rows) < MIN_TABLES or "blocks" not in mat_rows:
        _fail(f"parsed only {len(mat_rows)} table rows from the audit "
              f"coverage matrix (floor {MIN_TABLES}, sentinel 'blocks') — "
              "the matrix parse is not reading real rows", errors)
    errors.extend(_bijection_errors(
        source_names=tables,
        listed=mat_rows,
        duplicate_fmt="duplicate rows in the audit coverage matrix "
                      "(LMDB_WRITE_ATOMICITY_AUDIT.md §10):",
        missing_fmt="these tables exist in SHEKYL_LMDB_TABLES but have no "
                    "row in the audit coverage matrix "
                    "(LMDB_WRITE_ATOMICITY_AUDIT.md §10):",
        ghost_fmt="these audit coverage matrix rows name tables absent from "
                  "SHEKYL_LMDB_TABLES (deleted table, surviving row?):",
    ))
    mat_count = re.search(r"\*\*(\d+) rows\*\*", mat)
    if not mat_count:
        errors.append("the audit coverage matrix's '**N rows**' count line "
                      "is missing — the row-count claim this gate checks no "
                      "longer exists")
    elif int(mat_count.group(1)) != len(tables):
        errors.append(f"the audit coverage matrix claims "
                      f"{mat_count.group(1)} rows; SHEKYL_LMDB_TABLES has "
                      f"{len(tables)} tables")
    rows = parse_coverage_rows(mat)
    return mat, rows


def check_digest_states(
    rows: list[CoverageRow], tables: list[str], errors: list[str],
) -> dict[str, str]:
    if not rows:
        _fail("the audit coverage matrix has no `Digest v0` state column "
              "(P0e leg) -- every row must carry exactly one of "
              + "/".join(sorted(DIGEST_STATES)), errors)
    states, col_errs = _token_column_errors(
        tables=tables,
        pairs=[(r.name, r.digest_state) for r in rows],
        allowed=DIGEST_STATES,
        column="Digest v0",
        missing_fmt="these tables exist in SHEKYL_LMDB_TABLES but carry no "
                    "Digest v0 state in the audit coverage matrix -- a table "
                    "cannot be silently outside the digest ledger "
                    "(DRS \u00a79.1 leg 4):",
    )
    errors.extend(col_errs)
    doc_digested = {t for t, v in states.items()
                    if v in ("v0", "v0-partial") and t in set(tables)}
    if doc_digested != DIGEST_V0_TABLES:
        only_doc = sorted(doc_digested - DIGEST_V0_TABLES)
        only_gate = sorted(DIGEST_V0_TABLES - doc_digested)
        detail = []
        if only_doc:
            detail.append("marked digested in the audit but absent from this "
                          "gate's transcription of the walker: "
                          + ", ".join(only_doc))
        if only_gate:
            detail.append("read by the digest walker but not marked digested "
                          "in the audit: " + ", ".join(only_gate))
        errors.append(
            "the audit's digested rows and this gate's DIGEST_V0_TABLES "
            "disagree -- one of the two copies has drifted from "
            "logical_state_digest.cpp:\n  " + "\n".join(detail))
    return states


def check_accumulator_classes(
    rows: list[CoverageRow], tables: list[str], errors: list[str],
) -> dict[str, str]:
    if not rows:
        _fail("the audit coverage matrix has no `Accumulator class` column "
              "(DRS-0 slice A leg) -- every row must carry exactly one of "
              + "/".join(sorted(ACCUM_CLASSES)), errors)
    classes, col_errs = _token_column_errors(
        tables=tables,
        pairs=[(r.name, r.accum_class) for r in rows],
        allowed=ACCUM_CLASSES,
        column="Accumulator class",
        missing_fmt="these tables exist in SHEKYL_LMDB_TABLES but carry no "
                    "Accumulator class in the audit coverage matrix -- "
                    "\u00a76.2 requires every table in inventory to "
                    "contribute to some accumulator or named exclusion, "
                    "with no silent sampling:",
    )
    errors.extend(col_errs)
    return classes


def check_axis_gap(
    audit: str,
    tables: list[str],
    states: dict[str, str],
    classes: dict[str, str],
) -> tuple[list[str], list[str]]:
    """v0-`excluded` tables that still carry a real accumulator class.

    The two columns are different axes. Derive the figure rather than
    trusting the prose: a stated count that no gate checks is the defect
    this file exists to prevent.
    """
    axis_gap = sorted(
        t for t in tables
        if states.get(t) == "excluded"
        and classes.get(t) not in (None, "excluded")
    )
    errors: list[str] = []
    sec12 = _heading_block(audit, "## 12. Accumulator class freeze")
    haystack = sec12 if sec12 is not None else ""
    if sec12 is None:
        errors.append("the audit \u00a712 is gone -- the axis-gap claim "
                      "this leg checks has no subject (rule 47)")
        return axis_gap, errors
    stated_gap = re.search(r"they disagree on \*\*(\d+)\*\* rows", haystack)
    if not stated_gap:
        errors.append("the audit \u00a712 no longer states how many rows the "
                      "Digest v0 and Accumulator class axes disagree on -- "
                      "the claim this leg checks has gone")
    elif int(stated_gap.group(1)) != len(axis_gap):
        errors.append(
            f"the audit states the two axes disagree on "
            f"{stated_gap.group(1)} rows; {len(axis_gap)} rows are "
            f"v0-`excluded` with a real accumulator class:\n  "
            + ", ".join(axis_gap))
    return axis_gap, errors


# ---------------------------------------------------------------------------
# Set-shaped write-pattern freeze
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FalsifierSets:
    """Named sets parsed from audit §12's four-row falsifier table.

    Membership is the instruction to DRS-E1. Cardinality is a consequence
    of the sets, not a substitute for them.
    """
    listed: frozenset[str]
    delete_alone: frozenset[str]
    blind_upsert: frozenset[str]


def _cell_is_yes(cell: str) -> bool:
    """Read the yes/none/NO flag from a falsifier-table cell.

    `none` is checked before `no` so a '**none**' blind-upsert cell is not
    mistaken for a '**NO**' delete-has-element cell.
    """
    stripped = cell.strip().lstrip("*").lower()
    if stripped.startswith("none"):
        return False
    if stripped.startswith("no"):
        return False
    if stripped.startswith("yes"):
        return True
    raise ValueError(f"falsifier cell is not yes/no/none: {cell!r}")


def parse_set_shaped_falsifier(section: str) -> tuple[FalsifierSets | None, list[str]]:
    """Parse the four-row set-shaped falsifier table into named sets."""
    errors: list[str] = []
    listed: list[str] = []
    delete_alone: list[str] = []
    blind: list[str] = []
    saw_header = False
    for line in section.splitlines():
        if "Delete has the element" in line and "Blind upsert" in line:
            saw_header = True
            continue
        if not saw_header or not line.startswith("|"):
            continue
        cells = [c.strip() for c in split_cells(line)]
        if len(cells) != 3:
            continue
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            continue
        names = BACKTICK_NAME.findall(cells[0])
        if not names:
            continue
        stated = ROW_STATED_COUNT.search(cells[0])
        if stated and int(stated.group(1)) != len(names):
            errors.append(
                f"the audit \u00a712 row {cells[0]!r} says "
                f"{stated.group(1)} tables but names {len(names)}: "
                + ", ".join(names))
        try:
            delete_has = _cell_is_yes(cells[1])
            is_blind = _cell_is_yes(cells[2])
        except ValueError as e:
            errors.append(str(e))
            continue
        for name in names:
            listed.append(name)
            if not delete_has:
                delete_alone.append(name)
            if is_blind:
                blind.append(name)
    if not saw_header:
        errors.append(
            "the audit \u00a712 falsifier subsection no longer carries the "
            "four-row table this leg checks (header 'Delete has the "
            "element' / 'Blind upsert' is gone)")
        return None, errors
    if not listed:
        errors.append(
            "the audit \u00a712 falsifier table named no tables -- the "
            "write-pattern leg has no subject (rule 47)")
        return None, errors
    dupes = duplicates(listed)
    if dupes:
        errors.append(
            "the audit \u00a712 falsifier table names a table more than "
            "once:\n  " + ", ".join(dupes))
    return FalsifierSets(
        listed=frozenset(listed),
        delete_alone=frozenset(delete_alone),
        blind_upsert=frozenset(blind),
    ), errors


def derive_write_sites(
    lmdb_src: str, set_shaped: Iterable[str],
) -> tuple[set[str], set[str]]:
    """Lexical write sites among `set_shaped` tables.

    `mdb_put(*m_write_txn, m_<table>, &k, &v, 0)` is blind upsert.
    `mdb_del(*m_write_txn, m_<table>, ...)` is a keyed delete. This does
    not decide whether a preceding `mdb_get` put the value in hand —
    `output_to_leaf` and `leaf_to_output` differ inside one function, and
    a regex that guessed it would erase the distinction it exists to
    expose.
    """
    shaped = set(set_shaped)
    blind = {
        t for t in shaped
        if re.search(r"mdb_put\(\*m_write_txn, m_" + re.escape(t)
                     + r", &\w+, &\w+, 0\)", lmdb_src)
    }
    keyed_del = {
        t for t in shaped
        if re.search(r"mdb_del\(\*m_write_txn, m_" + re.escape(t) + r",",
                     lmdb_src)
    }
    return blind, keyed_del


def _set_mismatch(label: str, expected: set[str], got: set[str]) -> str | None:
    if expected == got:
        return None
    only_expected = sorted(expected - got)
    only_got = sorted(got - expected)
    parts = [f"{label} disagree (set equality, not cardinality):"]
    if only_expected:
        parts.append("  in the audit, not in db_lmdb.cpp: "
                     + ", ".join(only_expected))
    if only_got:
        parts.append("  in db_lmdb.cpp, not in the audit: "
                     + ", ".join(only_got))
    return "\n".join(parts)


def check_write_patterns(
    *,
    lmdb_src: str,
    set_shaped: set[str],
    falsifier_section: str | None,
) -> tuple[set[str], set[str], list[str]]:
    """Pin the falsifier's named sets to the write sites in `db_lmdb.cpp`.

    A rotation that keeps the count and changes the members must go red:
    the sets are the instruction to the port.
    """
    errors: list[str] = []
    if falsifier_section is None:
        errors.append(
            "the audit \u00a712 falsifier subsection is gone -- the "
            "slice-A write-pattern leg has no subject to check "
            "(rule 47: a gate asserts its own subject exists)")
        return set(), set(), errors

    parsed, parse_errs = parse_set_shaped_falsifier(falsifier_section)
    errors.extend(parse_errs)
    derived_blind, derived_del = derive_write_sites(lmdb_src, set_shaped)
    if parsed is None:
        return derived_blind, derived_del, errors

    listed = set(parsed.listed)
    if listed != set_shaped:
        only_table = sorted(listed - set_shaped)
        only_class = sorted(set_shaped - listed)
        msg = ["the audit \u00a712 falsifier table is not a bijection "
               "with the set-shaped class:"]
        if only_table:
            msg.append("  named in the falsifier, not classed set-shaped: "
                       + ", ".join(only_table))
        if only_class:
            msg.append("  classed set-shaped, not named in the falsifier: "
                       + ", ".join(only_class))
        errors.append("\n".join(msg))

    mismatch = _set_mismatch(
        "blind-upsert sets", set(parsed.blind_upsert), derived_blind)
    if mismatch:
        errors.append(mismatch)

    # Delete-by-key-alone: every named table must have a keyed mdb_del.
    # The converse is NOT checked — output_to_leaf has one and is
    # correctly excluded, because it reads the value first.
    no_such_del = sorted(parsed.delete_alone - derived_del)
    if no_such_del:
        errors.append(
            "the audit \u00a712 says these delete by key alone, but "
            "db_lmdb.cpp has no keyed mdb_del on them:\n  "
            + ", ".join(no_such_del))
    return derived_blind, derived_del, errors


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

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

    doc = DOC.read_text(encoding="utf-8")
    errors = check_schema_doc(doc, tables)
    errors.extend(check_version_pin(source_text, doc))

    try:
        drs = DRS.read_text(encoding="utf-8")
    except OSError as e:
        _fail(f"cannot read docs/design/DAEMON_REDB_STORE.md ({e}) — the "
              "registry this gate pins is unreadable", errors)
    check_registry(drs, tables, errors)

    try:
        audit = AUDIT.read_text(encoding="utf-8")
    except OSError as e:
        _fail(f"cannot read docs/LMDB_WRITE_ATOMICITY_AUDIT.md ({e}) — the "
              "coverage matrix this gate pins is unreadable", errors)
    _mat, coverage_rows = check_audit_matrix(audit, tables, errors)
    states = check_digest_states(coverage_rows, tables, errors)
    classes = check_accumulator_classes(coverage_rows, tables, errors)
    axis_gap, gap_errs = check_axis_gap(audit, tables, states, classes)
    errors.extend(gap_errs)

    falsifier = _heading_block(audit, "### The per-table falsifier")
    set_shaped = {t for t, c in classes.items() if c == "set-shaped"}
    derived_blind, derived_del, wp_errs = check_write_patterns(
        lmdb_src=source_text,
        set_shaped=set_shaped,
        falsifier_section=falsifier,
    )
    errors.extend(wp_errs)

    if errors:
        sys.exit("FAIL: the LMDB schema surface is out of step with the live "
                 "table list:\n" + "\n".join(errors))

    ledger = collections.Counter(states[t] for t in tables if t in states)
    print(f"OK: all {len(tables)} LMDB tables documented (property rows and "
          "headings), reconciliation registry and atomicity-audit matrix "
          "match, stated totals and DB-version header match the code")
    print("    Digest v0 ledger (P0e): every table carries one state — "
          + ", ".join(f"{ledger[k]} {k}" for k in
                      ("v0", "v0-partial", "excluded", "uncovered")
                      if ledger.get(k))
          + ". This leg checks STATEHOOD, not coverage: "
          f"{ledger.get('uncovered', 0)} tables are in the oracle's domain "
          "and invisible to the digest (audit §11) — one of them, "
          "hf_starting_heights, holds no runtime rows to diverge (DRS-W5). "
          "That is a recorded measurement, not a failure.")
    cledger = collections.Counter(classes[t] for t in tables if t in classes)
    print(f"    Accumulator class freeze (DRS-0 slice A): every table carries "
          "one class \u2014 "
          + ", ".join(f"{cledger[k]} {k}" for k in
                      ("set-shaped", "append-mostly", "small", "derived",
                       "excluded")
                      if cledger.get(k))
          + ". This leg checks CLASSHOOD, not soundness: it cannot see "
          "whether a set-shaped table is actually pop-reversible. "
          f"The two axes disagree on {len(axis_gap)} rows (v0-excluded with "
          "a real class) \u2014 a v0 exclusion is not an accumulator "
          "exclusion (audit \u00a712).")
    print(f"    Write patterns (slice A): {len(derived_blind)} of "
          f"{len(set_shaped)} set-shaped tables blind-upsert "
          "(mdb_put flags 0) and so need a read-modify-write hook; "
          f"{len(derived_del)} carry a keyed mdb_del. Derived from "
          "db_lmdb.cpp and checked by set equality against the \u00a712 "
          "falsifier table — a rotation that keeps the count is red.")


if __name__ == "__main__":
    main()
