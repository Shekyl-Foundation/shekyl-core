# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Identifier-family prefix uniqueness for docs/design/IMPLEMENTATION_INDEX.md §2.
#
# Rule 94: a family's prefix up to the first digit (with an optional
# hyphen-letter infix, so SP- and SP-T coexist, as do F- and FA-, CT- and
# CT-ACT-) must be unique among registered families. Parsed from the first
# identifier in column 0 of the §2 table.
#
# Instance of 47-gate-subject-assertion.mdc: a missing index, or a §2 table
# with fewer than two family rows, is a missing subject.
#
# Two modes:
#   (no args)            gate the registered §2 table, as CI runs it.
#   --prefix CELL [...]  print the prefix each candidate Family cell parses to
#                        and whether they collide. Rule 94 §6 requires this
#                        before splitting one row into per-sub-family rows:
#                        prefixes that stay distinct take branch (a), prefixes
#                        that collapse take branch (b). The grammar has exactly
#                        one implementation, so the answer the rule asks for and
#                        the answer CI enforces can never drift apart.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INDEX = os.path.join(ROOT, "docs", "design", "IMPLEMENTATION_INDEX.md")

# SP-0 → SP; SP-T0 → SP-T; Q12-D1 → Q12-D; Q12-R1 → Q12-R; GF-1 → GF;
# WI-RPC-1 → WI-RPC; CT-ACT-1 → CT-ACT; CT-1 → CT; Stage 0 → Stage.
TOKEN_RE = re.compile(
    r"^(\*\*)?"
    r"([A-Za-z]+)"
    r"(\d+)?"
    r"(?:-([A-Za-z]+))?"
)


def family_prefix(cell: str) -> str | None:
    cell = cell.strip().replace("`", "")
    m = TOKEN_RE.match(cell)
    if not m:
        return None
    letters, digits, infix = m.group(2), m.group(3), m.group(4)
    pref = letters + (digits or "")
    if infix:
        pref = f"{pref}-{infix}"
    return pref


def report_candidates(cells: list[str]) -> int:
    """Rule 94 §6: print what each proposed Family cell parses to, and whether
    the set stays distinct. Exit 0 when distinct (branch (a) is available),
    1 when two candidates collapse to one prefix (branch (b) is required)."""
    if not cells:
        print("index prefixes: --prefix needs at least one Family cell",
              file=sys.stderr)
        return 2
    seen: dict[str, str] = {}
    collisions = []
    width = max(len(c) for c in cells)
    for cell in cells:
        pref = family_prefix(cell)
        if pref is None:
            print(f"  {cell:<{width}}  -> (unparseable)")
            print("index prefixes: a candidate cell has no parseable prefix",
                  file=sys.stderr)
            return 2
        print(f"  {cell:<{width}}  -> {pref}")
        # Every argument is a PROPOSED SEPARATE ROW, so a repeated prefix is a
        # collision even when the two cells are byte-identical — identical text
        # means two rows registering one family, which the registry cannot
        # hold. Do not reuse a "same text is the same family" shortcut here.
        if pref in seen:
            collisions.append((pref, seen[pref], cell))
        else:
            seen[pref] = cell
    if collisions:
        for pref, a, b in collisions:
            if a == b:
                print(f"\nindex prefixes: {pref!r} claimed twice — the cell "
                      f"{a!r} was passed more than once")
            else:
                print(f"\nindex prefixes: {pref!r} is claimed by both {a!r} "
                      f"and {b!r}")
        print("COLLIDE — rule 94 §6 branch (b): keep one row and put per-lane "
              "status in the owning doc. Do NOT widen the grammar to separate "
              "them; that costs the check its power to catch a real duplicate.")
        return 1
    # Invariant worth stating out loud: branch (a) is available only when the
    # candidates and the prefixes they claim are in one-to-one correspondence.
    assert len(seen) == len(cells)
    print(f"\nDISTINCT ({len(cells)} candidates -> {len(seen)} prefixes) — "
          f"rule 94 §6 branch (a): one row per sub-family is available.")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--prefix":
        return report_candidates(argv[1:])
    if argv:
        print(f"usage: {os.path.basename(__file__)} [--prefix CELL ...]",
              file=sys.stderr)
        return 2
    if not os.path.isfile(INDEX):
        print("index prefixes: IMPLEMENTATION_INDEX.md is missing", file=sys.stderr)
        return 2
    with open(INDEX, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    rows = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("## 2."):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table:
            continue
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cols:
            continue
        if cols[0] in {"", "---"} or set(cols[0]) <= {"-", ":"}:
            continue
        if "Identifier" in cols[0] or cols[0].lower().startswith("family"):
            continue
        rows.append(cols[0])
    if len(rows) < 2:
        print("index prefixes: §2 family table missing or too small",
              file=sys.stderr)
        return 2
    seen: dict[str, str] = {}
    collisions = []
    skipped = 0
    for cell in rows:
        pref = family_prefix(cell)
        if not pref:
            skipped += 1
            continue
        # `rows` holds one entry per table LINE, so two entries can only be
        # byte-identical when two rows register the same family — itself a
        # rule 94 §1 violation. An earlier `and seen[pref] != cell` guard
        # excused exactly that case, suppressing the duplicate it was meant
        # to catch; a repeated prefix is a collision however the cells read.
        if pref in seen:
            collisions.append((pref, seen[pref], cell))
        else:
            seen[pref] = cell
    if collisions:
        for pref, a, b in collisions:
            if a == b:
                print(f"index prefixes: prefix {pref!r} registered by two "
                      f"identical rows: {a!r}")
            else:
                print(f"index prefixes: prefix {pref!r} collides: {a!r} vs {b!r}")
        print(f"\n{len(collisions)} prefix collision(s) in §2.", file=sys.stderr)
        return 1
    if skipped:
        print("index prefixes: some §2 rows had no parseable prefix",
              file=sys.stderr)
        return 2
    print(f"index prefixes: {len(seen)} unique prefixes across {len(rows)} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
