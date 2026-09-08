# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# GFM table-row splitting, shared by the index gates.
#
# ONE implementation, imported rather than copied. The two gates previously
# carried a splitter each: the shape gate's was escape-aware, and the prefix
# gate's was `line.strip("|").split("|")`, which truncates any Family cell
# containing an escaped `\|` and therefore reads the wrong family prefix out of
# it. Two copies of a parser cannot be kept in step by intention, and the gates
# are supposed to agree about what a row is — a disagreement between them is
# exactly the drift the prefix gate's `--prefix` mode promises cannot happen.

from __future__ import annotations


def has_pipe(line: str) -> bool:
    """True when the line carries an unescaped `|`."""
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

    GFM splits a row into cells BEFORE inline parsing, so a pipe inside a code
    span still ends the cell; only a backslash-escaped `\\|` is literal. And
    escaping depends on the PARITY of the backslash run: `\\|` is a literal
    pipe, but `\\\\|` is an escaped backslash followed by a live delimiter.
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
