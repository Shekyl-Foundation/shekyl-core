# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The one parser for CONSENSUS_RULE_CENSUS.md §4, shared by the two gates that
# derive a denominator from it.
#
# ONE implementation, imported rather than copied. `check_drs_e6_partition.py`
# (DAEMON_REDB_STORE.md §7.5 against the census) and
# `check_chain_rules_coverage.py` (the `shekyl-chain-rules` registry against
# the census) both divide by "the enforced rows of flag F", and a census that
# parsed differently in the two would let §7.5's schedule and the crate's
# `implemented / enforced` figure disagree about what the denominator is —
# with neither gate red. Until 2026-09-15 the coverage gate imported this
# code out of the partition gate's module (CHAIN_RULES_CRATE.md §6.1, round-1
# ruling Q7: take the import now, extract once PR #751 merged); a gate
# importing a sibling gate is a hidden coupling — rename the sibling and the
# importer breaks confusingly — so the parser lives here, named for what it
# is, and the two gates are siblings of it rather than of each other.
#
# What is refused (rule 47 — the parser asserts its own subject): an
# unterminated code fence (everything after it would be hidden, so a prefix
# of the census would be derived), a §4 table whose header lacks a column the
# derivation reads (every table's own header — §4.J carries three under one
# heading), a header not followed by its GFM delimiter row of the same width
# (Markdown renders no table, so the rows are not on the page — rule 94 §7),
# a row too short for its header, an id cell that is not a well-formed `CEN-`
# id, a flag or bucket outside the vocabulary, a duplicate id, a census with
# no §4 tables, no rows, or zero bound rows. Each is a `Refused`, never a
# silent drop from the denominator. Both importing gates' `--selftest` runs
# exercise these refusals red through `parse_census`.

from __future__ import annotations

import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _gfm_table import fenced_lines, split_cells  # noqa: E402

# The one definition of "surface-bound". DAEMON_REDB_STORE.md §7.5.2 quotes
# this string in a code span and the partition gate checks the quote, so the
# doc cannot describe a different partition from the one the gates compute.
BOUND_RE_TEXT = r"blockchain_db|db_lmdb|src/blockchain_db|lmdb/"
BOUND_RE = re.compile(BOUND_RE_TEXT)

FLAGS = ("C", "P")
BUCKETS = (1, 2, 3, 4)

CENSUS_ROWS_HEADING = re.compile(r"^## 4\. ")
CENSUS_SUBSECTION = re.compile(r"^### (4\.[A-Z])\b")
H2 = re.compile(r"^## ")
ROW_ID = re.compile(r"^\**(CEN-[A-Z]+\d+[a-z]?)\**$")


@dataclass(frozen=True)
class Row:
    id: str
    subsystem: str
    flag: str
    bucket: int
    bound: bool
    # The `site(s)` cell verbatim — read by `check_chain_rules_coverage.py`
    # to refuse a `held_by_cxx` entry on a row whose census site is not C++.
    sites: str = ""


class Refused(Exception):
    """A checked property does not hold, or the subject is missing."""


# --------------------------------------------------------------------------
# GFM table shape — shared by the census side and by the partition gate's
# reading of the DRS doc, so the two documents are held to one notion of
# "this header is a table".
# --------------------------------------------------------------------------


def row_cells(line: str) -> list[str]:
    """The stripped cells of a `|`-delimited row (escape-aware split)."""
    return [c.strip() for c in split_cells(line)]


def is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r":?-{3,}:?", c) for c in cells)


def require_delimiter(lines: list[str], at: int, ncols: int, where: str) -> None:
    """Refuse unless `lines[at + 1]` is the GFM delimiter row for the header at `at`.

    GFM makes a table of a header only when the very next line is a delimiter
    row with the same number of cells. Anything else and Markdown renders the
    header as a paragraph — the rows under it do not exist on the page (rule
    94 §7), so a gate that read them would be checking text no reader sees.
    """
    nxt = lines[at + 1] if at + 1 < len(lines) else ""
    delim = row_cells(nxt) if nxt.startswith("|") else []
    if not is_separator(delim):
        raise Refused(
            f"{where}: header {lines[at].strip()!r} is not followed by a GFM "
            "delimiter row — Markdown does not render it as a table"
        )
    if len(delim) != ncols:
        raise Refused(
            f"{where}: delimiter row has {len(delim)} cells, its header has "
            f"{ncols} — Markdown does not render it as a table"
        )


def unfenced(text: str, what: str) -> tuple[list[str], set[int]]:
    """The document's lines and the indices inside closed code fences.

    An unterminated fence would make every line after it "fenced" and so
    invisible to the parse — a prefix of the census could then be derived,
    and a doc edited to the same prefix would pass. That is a missing subject
    (rule 47), refused at every entry rather than read as absence.
    """
    lines = text.splitlines()
    fenced, open_fence = fenced_lines(lines)
    if open_fence:
        raise Refused(
            f"{what}: a code fence is left open — everything after it is hidden "
            "from the parse, so the derivation would be over a prefix"
        )
    return lines, fenced


# --------------------------------------------------------------------------
# census §4
# --------------------------------------------------------------------------


def parse_census(text: str) -> list[Row]:
    """Every `CEN-` row of census §4, with the four columns the derivations read.

    Each table names its columns in its own header row; indices are taken from
    it rather than assumed, so a re-ordered census fails loudly instead of
    reading `b` out of the `C/P` column. A GFM table ends at its first
    non-table line, and a subsection may carry several tables (§4.J does), so
    the header is re-read at every table start — never inherited from the
    previous table under the same heading.
    """
    lines, fenced = unfenced(text, "census")
    rows: list[Row] = []
    in_rows = False
    subsystem: str | None = None
    columns: dict[str, int] | None = None
    width = 0
    seen_tables = 0
    delimiter_at = -1  # the one line after a header that GFM reads as its delimiter
    for n, raw in enumerate(lines):
        if n in fenced or n == delimiter_at:
            continue
        line = raw.rstrip()
        if CENSUS_ROWS_HEADING.match(line):
            in_rows = True
            continue
        if not in_rows:
            continue
        if H2.match(line):
            break
        m = CENSUS_SUBSECTION.match(line)
        if m:
            subsystem = m.group(1)
            columns = None
            continue
        if subsystem is None:
            continue  # §4's preamble legend table precedes the first subsection
        if not line.startswith("|"):
            columns = None  # the table (if any) ended; the next `|` line is a header
            continue
        cells = row_cells(line)
        if columns is None:
            header = [c.lower() for c in cells]
            needed = {"id", "site(s)", "c/p", "b"}
            if not needed <= set(header):
                raise Refused(
                    f"census §4 table under {subsystem} (line {n + 1}) lacks a "
                    f"column the derivation reads: header={cells!r}, "
                    f"needs {sorted(needed)}"
                )
            require_delimiter(
                lines, n, len(cells), f"census §4 table under {subsystem}"
            )
            delimiter_at = n + 1
            columns = {name: header.index(name) for name in needed}
            width = max(columns.values()) + 1
            seen_tables += 1
            continue
        # Past the header and its delimiter, every `|` line is a data row — a
        # second separator-looking line is a row whose id cell is `---`, and
        # is refused below rather than skipped.
        if len(cells) < width:
            raise Refused(
                f"census §4 table under {subsystem} (line {n + 1}): row has "
                f"{len(cells)} cells, fewer than the {width} its header's read "
                f"columns need: {cells!r}"
            )
        id_cell = cells[columns["id"]]
        rid_m = ROW_ID.match(id_cell)
        if not rid_m:
            # Every row of a §4 data table is a rule. A cell that is not a
            # well-formed `CEN-` id is a row the derivation would otherwise
            # drop from the denominator without a word.
            raise Refused(
                f"census §4 table under {subsystem} (line {n + 1}): id cell "
                f"{id_cell!r} is not a `CEN-` row id"
            )
        flag = cells[columns["c/p"]].strip("*")
        if flag not in FLAGS:
            raise Refused(
                f"{rid_m.group(1)} (line {n + 1}): C/P cell {flag!r} is not one of {FLAGS}"
            )
        bucket_text = cells[columns["b"]].strip("*")
        if not re.fullmatch(r"[1-4]", bucket_text):
            raise Refused(
                f"{rid_m.group(1)} (line {n + 1}): b cell {bucket_text!r} is not one of {BUCKETS}"
            )
        rows.append(
            Row(
                id=rid_m.group(1),
                subsystem=subsystem,
                flag=flag,
                bucket=int(bucket_text),
                bound=bool(BOUND_RE.search(cells[columns["site(s)"]])),
                sites=cells[columns["site(s)"]],
            )
        )
    if seen_tables == 0:
        raise Refused("census: no §4 rows tables found — subject missing")
    if not rows:
        raise Refused("census: §4 tables carry no CEN- rows — subject missing")
    dupes = [rid for rid, k in Counter(r.id for r in rows).items() if k > 1]
    if dupes:
        raise Refused(f"census: duplicate row ids {sorted(dupes)}")
    if not any(r.bound for r in rows):
        raise Refused(
            f"census: zero rows match the bound regex `{BOUND_RE_TEXT}` — the "
            "storage subsystem has no rows or the site column changed shape"
        )
    return rows
