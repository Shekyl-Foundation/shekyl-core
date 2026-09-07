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

# A GFM delimiter cell is one or more hyphens with an optional leading and/or
# trailing colon — `-` alone is legal, not just `---`. This pattern is only
# ever tested against the line DIRECTLY BELOW a header: the delimiter row is
# positional, so a body row that happens to hold bare dashes is content, not a
# new table.
DELIM_RE = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$")


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

    # Positional parse. A table is a header line, the delimiter line directly
    # beneath it, then body rows until a blank or pipe-free line. Scanning for
    # the delimiter pattern anywhere instead would let a body row of bare
    # dashes silently restart the column count from whatever preceded it.
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not (stripped.startswith("|")
                and i + 1 < len(lines)
                and DELIM_RE.match(lines[i + 1].strip())):
            i += 1
            continue

        tables += 1
        want = len(split_cells(stripped))
        delim = len(split_cells(lines[i + 1].strip()))
        if delim != want:
            # GFM does not render a table at all when these disagree, so the
            # whole block is invisible — a stricter failure than a stray cell.
            problems.append(
                (i + 2, f"delimiter row has {delim} cells against a {want}-column "
                        f"header — GFM renders no table here at all"))
        j = i + 2
        while j < len(lines):
            body = lines[j].strip()
            if not body or "|" not in body:
                break
            if not body.startswith("|"):
                # GFM permits omitting the leading pipe; this file does not.
                # Fail loudly rather than treating it as the end of the table,
                # which would skip the row and hide the very defect we check.
                problems.append(
                    (j + 1, f"row does not start with '|' — the index writes "
                            f"tables with a leading delimiter: {body[:60]}…"))
                j += 1
                continue
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

    if tables == 0 or rows_checked == 0:
        print("index shape: no parseable tables in the index — subject missing",
              file=sys.stderr)
        return 2

    if problems:
        for ln, detail in problems:
            print(f"index shape: line {ln} {detail}")
        print(f"\n{len(problems)} malformed table row(s). GFM renders neither a "
              f"surplus cell nor a missing one; escape a literal pipe as \\|.",
              file=sys.stderr)
        return 1

    print(f"index shape: {rows_checked} rows across {tables} tables, "
          f"all matching their header column count")
    return 0


if __name__ == "__main__":
    sys.exit(main())
