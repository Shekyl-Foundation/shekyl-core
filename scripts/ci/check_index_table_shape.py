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

DELIM_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def split_cells(line: str) -> list[str]:
    """Split a GFM table row on unescaped pipes; backticks do NOT protect."""
    cells: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cur.append("|")
            i += 2
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

    problems: list[tuple[int, int, int, str]] = []
    tables = 0
    rows_checked = 0
    header_cols: int | None = None

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped.startswith("|"):
            header_cols = None
            continue
        if DELIM_RE.match(stripped):
            # The delimiter row confirms the header above it opened a table.
            prev = lines[idx - 2].strip() if idx >= 2 else ""
            if prev.startswith("|"):
                header_cols = len(split_cells(prev))
                tables += 1
            continue
        if header_cols is None:
            # A header line: counted when its delimiter row is reached.
            continue
        n = len(split_cells(line))
        rows_checked += 1
        if n != header_cols:
            problems.append((idx, n, header_cols, stripped[:70]))

    if tables == 0 or rows_checked == 0:
        print("index shape: no parseable tables in the index — subject missing",
              file=sys.stderr)
        return 2

    if problems:
        for ln, got, want, preview in problems:
            verb = "beyond the column count" if got > want else "short of the column count"
            print(f"index shape: line {ln} has {got} cells against a "
                  f"{want}-column header ({verb}): {preview}…")
        print(f"\n{len(problems)} malformed table row(s). GFM renders neither a "
              f"surplus cell nor a missing one; escape a literal pipe as \\|.",
              file=sys.stderr)
        return 1

    print(f"index shape: {rows_checked} rows across {tables} tables, "
          f"all matching their header column count")
    return 0


if __name__ == "__main__":
    sys.exit(main())
