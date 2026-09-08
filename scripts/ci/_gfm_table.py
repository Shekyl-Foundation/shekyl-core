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

import re

FENCE_RE = re.compile(r"^(`{3,}|~{3,})")


def fenced_lines(lines: list[str]) -> tuple[set[int], bool]:
    """Indices inside fenced code blocks, and whether a fence is left open.

    GFM closes a fence only with the SAME marker character and at least the
    opener's length, so a `~~~` line inside a ```-fence is content, not a
    close. Toggling on any fence marker mistakes that for a close, flips the
    state twice, and then reports an unterminated fence on a correct document.

    Computed ONCE and shared: the parse and the closing sweep must agree about
    which lines are verbatim, and two copies of this logic could not be kept
    in step by intention.
    """
    inside: set[int] = set()
    char: str | None = None
    length = 0
    for n, line in enumerate(lines):
        m = FENCE_RE.match(line.strip())
        if m:
            marker = m.group(1)
            if char is None:
                char, length = marker[0], len(marker)
                inside.add(n)          # the fence markers are not table rows
                continue
            if marker[0] == char and len(marker) >= length:
                inside.add(n)
                char, length = None, 0
                continue
        if char is not None:
            inside.add(n)
    return inside, char is not None


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
            # SOURCE-EXACT: keep the backslashes as written. Parity decides
            # only whether the NEXT pipe is a delimiter. Unescaping here would
            # be a quiet rewrite of the cell, and `registry_rows()` stores
            # these strings as row identities that `--replace` must match
            # byte-for-byte against what the document actually says.
            cur.append("\\" * run)
            i += run
            if run % 2 and i < len(line) and line[i] == "|":
                cur.append("|")  # escaped: part of the cell, not a delimiter
                i += 1
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
