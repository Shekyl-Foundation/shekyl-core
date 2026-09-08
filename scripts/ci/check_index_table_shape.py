# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Table cell-count shape for docs/design/IMPLEMENTATION_INDEX.md.
#
# GFM ignores cells past the header's column count when it renders a table, and
# a row with too few cells renders trailing columns blank. Either way the source
# says one thing and the page says another, and the invisible half stops being
# maintained precisely because nobody can see it. This gate is file-wide, not
# scoped to the §2 registry table: content has gone invisible in the two-column
# document tables as well, and a registry-scoped check would report clean while
# it did.
#
# Escape-awareness is the whole difficulty. GFM splits a row into cells on
# pipes BEFORE inline parsing, so a pipe inside a code span still splits the
# cell; only a backslash-escaped `\|` is literal. A naive split on every pipe
# reports well-formed rows as malformed, and a gate that cries wolf on the
# current tree is muted before it ever catches a real regression.
#
# Instance of 47-gate-subject-assertion.mdc: a missing index, or a file with no
# parseable tables, is a missing subject and fails rather than passing vacuously.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INDEX = os.path.join(ROOT, "docs", "design", "IMPLEMENTATION_INDEX.md")

# RECOGNITION IS SEPARATE FROM VALIDITY, and deliberately far weaker.
#
# A header/delimiter pair is RECOGNISED when a pipe-bearing line is followed by
# ANY non-blank line. Nothing is asked about the second line's content. That is
# the whole test — it asks "might these two lines be trying to be a table?",
# never "are they a valid one". Validity is decided afterwards by the strict
# cell check and the width check, which REPORT.
#
# The separation is the entire design, arrived at the hard way: SIX earlier
# versions tied recognition to some degree of validity — every cell well
# formed, then all-or-empty, then one well formed, then any pipe, then a wholly
# dashy line — and each one let a malformed table escape unexamined, because a
# table had to be well formed before it qualified to be examined for being well
# formed. Every hole was also invisible, since the file's other tables kept the
# subject counters nonzero and the gate exited 0. Any content test admits
# another typo; only a positional one admits none.
#
# The strict cell form requires three or more hyphens. The GFM spec is
# genuinely ambiguous — it says only "cells whose only content are hyphens",
# states no minimum, and every worked example uses three — so this is enforced
# as a house rule rather than a spec claim. Under either reading the behaviour
# is right: if the spec means three, a thinner cell renders no table and this
# is the invisible-table defect; if it means one, `| - |` is still not how this
# file writes a table, and a loud failure beats an ambiguous pass.
#
# Recognition never fabricates a table. A run of lines that fails these checks
# is not rendered as a table by GFM either — it becomes paragraph text, or a
# setext heading where a bare `---` follows a pipe row — which is precisely the
# invisible-content defect this gate exists to report.
DELIM_CELL_STRICT_RE = re.compile(r"^:?-{3,}:?$")


def has_pipe(line: str) -> bool:
    """True when the line carries an unescaped `|`.

    Used to identify a candidate HEADER and to tell a table row from the blank
    line that ends a table. It is deliberately NOT asked of the delimiter —
    see the recognition note at the top of the file: the delimiter is whatever
    line sits directly beneath the header, and its content is judged only by
    the checks that report.
    """
    i = 0
    while i < len(line):
        if line[i] == "\\":
            run = 0
            while i + run < len(line) and line[i + run] == "\\":
                run += 1
            i += run
            if run % 2 and i < len(line) and line[i] == "|":
                i += 1  # escaped pipe, not a delimiter
            continue
        if line[i] == "|":
            return True
        i += 1
    return False


def split_cells(line: str) -> list[str]:
    """Split a GFM table row on unescaped pipes; backticks do NOT protect.

    Escaping depends on the PARITY of the backslash run before the pipe:
    `\\|` is a literal pipe, but `\\\\|` is an escaped backslash followed by a
    live cell delimiter. Treating any preceding backslash as an escape would
    let a surplus cell slip past.
    """
    cells: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\":
            run = 0
            while i + run < len(line) and line[i + run] == "\\":
                run += 1
            cur.append("\\" * (run // 2))
            i += run
            if run % 2 and i < len(line) and line[i] == "|":
                cur.append("|")  # odd run: this pipe is escaped
                i += 1
            elif run % 2:
                cur.append("\\")
            continue
        if ch == "|":
            cells.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    cells.append("".join(cur))
    # A leading and/or trailing delimiter produces an empty edge cell.
    if cells and not cells[0].strip():
        cells = cells[1:]
    if cells and not cells[-1].strip():
        cells = cells[:-1]
    return cells


def main() -> int:
    if not os.path.isfile(INDEX):
        print("index shape: IMPLEMENTATION_INDEX.md is missing", file=sys.stderr)
        return 2
    with open(INDEX, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    problems: list[tuple[int, str]] = []
    tables = 0
    rows_checked = 0
    consumed: set[int] = set()

    # Positional parse. A table is a header line, the delimiter line directly
    # beneath it, then body rows until a BLANK line — every table in this file
    # is blank-separated, so nothing short of a blank ends one. Scanning for a
    # delimiter pattern anywhere instead would let a body row of bare dashes
    # silently restart the column count from whatever preceded it.
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        # See the recognition note at the top of the file. Recognition is now
        # PURELY POSITIONAL: a pipe-bearing line followed by any non-blank line
        # opens a candidate table. Nothing is asked about the delimiter's
        # CONTENT, because every content test tried here — all cells dashed,
        # all-or-empty, one dashed, any pipe, whole line dashy — excused some
        # malformed delimiter from examination, and the excused table then
        # vanished behind the other tables' counters.
        if not (stripped and has_pipe(stripped) and nxt):
            i += 1
            continue

        tables += 1
        consumed.add(i)
        consumed.add(i + 1)
        for ln, text, what in ((i + 1, stripped, "header"),
                               (i + 2, nxt, "delimiter row")):
            if not text.startswith("|"):
                # GFM allows the leading pipe to be omitted; this file does not.
                # Reported rather than skipped, so the house-style check cannot
                # be made unreachable by the very syntax it forbids.
                problems.append(
                    (ln, f"{what} does not start with '|' — the index writes "
                         f"tables with a leading delimiter: {text[:60]}…"))
        want = len(split_cells(stripped))
        delim_cells = split_cells(lines[i + 1].strip())
        delim = len(delim_cells)
        bad = [c.strip() for c in delim_cells
               if not DELIM_CELL_STRICT_RE.match(c.strip())]
        if bad:
            shown = ", ".join("(empty)" if not c else repr(c) for c in bad)
            problems.append(
                (i + 2, f"delimiter cell(s) {shown} are not `---` (three or more "
                        f"hyphens, optional leading/trailing colon) — GitHub "
                        f"renders no table here, so every row below it would "
                        f"go unchecked"))
        if delim != want:
            # GFM does not render a table at all when these disagree, so the
            # whole block is invisible — a stricter failure than a stray cell.
            problems.append(
                (i + 2, f"delimiter row has {delim} cells against a {want}-column "
                        f"header — GFM renders no table here at all"))
        j = i + 2
        while j < len(lines):
            body = lines[j].strip()
            if not body:
                break  # every table in this file is blank-separated
            if not has_pipe(body):
                # A row that has lost every pipe ends nothing: treating it as
                # the table's end would skip it and any row after it. Tables
                # here are separated by blank lines, so a non-blank pipe-free
                # line inside one is a malformed row, not a boundary.
                problems.append(
                    (j + 1, f"row inside a table carries no '|' — tables are "
                            f"blank-separated, so this is a malformed row "
                            f"rather than the end of the table: {body[:60]}…"))
                consumed.add(j)
                rows_checked += 1
                j += 1
                continue
            if not body.startswith("|"):
                # GFM permits omitting the leading pipe; this file does not.
                # Reported, then STILL CHECKED — breaking here would skip the
                # row and hide the very defect this gate looks for.
                problems.append(
                    (j + 1, f"row does not start with '|' — the index writes "
                            f"tables with a leading delimiter: {body[:60]}…"))
            consumed.add(j)
            n = len(split_cells(body))
            rows_checked += 1
            if n != want:
                verb = ("beyond the column count" if n > want
                        else "short of the column count")
                problems.append(
                    (j + 1, f"has {n} cells against a {want}-column header "
                            f"({verb}): {body[:70]}…"))
            j += 1
        i = j

    # CLOSING INVARIANT: every pipe-bearing line belongs to some table.
    # Recognition needs a header AND a following line, so a malformed block
    # whose header lost its pipes, or a lone row at end-of-file, is consumed by
    # nothing and would otherwise vanish while the other tables kept the
    # counters green. Counting what was NOT accounted for closes that by
    # construction rather than by another recognition case.
    #
    # Only PIPE-BEARING lines are swept. A bare `---` is a thematic break in
    # this file, used as a section separator eight times, and flagging those
    # would be a gate that fails on correct markdown. A malformed block whose
    # header and delimiter both lost their pipes is still caught here, through
    # whichever of its rows kept one.
    for n, line in enumerate(lines):
        text = line.strip()
        if not text or n in consumed:
            continue
        if has_pipe(text):
            problems.append(
                (n + 1, f"line carries table syntax but belongs to no table — "
                        f"a header, delimiter or row that GFM will not render "
                        f"as part of one: {text[:60]}…"))

    if tables == 0 or rows_checked == 0:
        print("index shape: no parseable tables in the index — subject missing",
              file=sys.stderr)
        return 2

    if problems:
        for ln, detail in problems:
            print(f"index shape: line {ln} {detail}")
        print(f"\n{len(problems)} malformed table row(s). GFM DROPS a surplus "
              f"cell and renders a missing trailing one as BLANK — either way the "
              f"source and the page disagree. Escape a literal pipe as \\|.",
              file=sys.stderr)
        return 1

    print(f"index shape: {rows_checked} rows across {tables} tables, "
          f"all matching their header column count")
    return 0


if __name__ == "__main__":
    sys.exit(main())
