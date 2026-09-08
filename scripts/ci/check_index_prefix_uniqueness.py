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
#   --prefix CELL CELL…  print the prefix each candidate Family cell parses to,
#                        and whether they collide EITHER with each other OR with
#                        a family already registered in §2. Rule 94 §6 requires
#                        this before splitting one row into per-sub-family rows:
#                        distinct prefixes take branch (a), collapsing ones take
#                        branch (b). Both the grammar and the registry are read
#                        by the same code the gate uses, so the answer the rule
#                        asks for and the answer CI enforces cannot drift apart.
#                        Two cells minimum — one candidate cannot collide with
#                        anything, so a green verdict on it would assert nothing.
#   … --replace CELL…    Family cells of rows the proposal REMOVES, excluded
#                        from the registry comparison. Required whenever a
#                        family is being SPLIT, because the row being replaced
#                        still holds the prefix its successors want; without it
#                        the tool could only approve a split after that split
#                        had landed. A cell that matches no §2 row is refused
#                        rather than ignored. --replace is the ONLY way to
#                        exclude a row: passing a registered cell as a CANDIDATE
#                        proposes adding it a second time, which is a duplicate
#                        the gate rejects, so it is reported as a collision.
#
# Exit: 0 admissible; 1 collapse (branch (b)) OR registry collision (rename or
# --replace); 2 the question could not be asked at all.

from __future__ import annotations

import os
import re
import sys

# The shared helper sits beside this script; do not depend on the caller's
# sys.path, which differs between `python3 scripts/ci/x.py` and an import.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _gfm_table import split_cells

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


def registry_rows() -> list[str] | None:
    """Every §2 Family cell, or None when the index is missing.

    One reader for both modes: the gate and the `--prefix` precheck must see
    the same registry, or the precheck's verdict would be about a table that
    only it believes in.
    """
    if not os.path.isfile(INDEX):
        return None
    with open(INDEX, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    rows: list[str] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("## 2."):
            in_table = True
            continue
        if in_table and line.startswith("## "):
            break
        if not in_table or not line.startswith("|"):
            continue
        # Escape-aware, shared with the shape gate: a naive split on every
        # pipe truncates a Family cell containing `\|` and reads the wrong
        # prefix out of it.
        cols = [c.strip() for c in split_cells(line.strip())]
        if not cols:
            continue
        if cols[0] in {"", "---"} or set(cols[0]) <= {"-", ":"}:
            continue
        if "Identifier" in cols[0] or cols[0].lower().startswith("family"):
            continue
        rows.append(cols[0])
    return rows


def report_candidates(cells: list[str], replaced: list[str] | None = None) -> int:
    """Rule 94 §6: print what each proposed Family cell parses to, and whether
    the shape is admissible.

    `replaced` names Family cells of rows the proposal REMOVES. Without it the
    tool cannot answer its own motivating question: before the PWD split, the
    combined row's cell began `PWD-T1…` and so held `PWD-T`, which every
    proposed cluster cell then collided with — while passing that old cell as a
    candidate instead manufactured a pairwise `PWD-T` collision. Either way the
    answer was wrong until the split had already landed, which is exactly when
    nobody needs to ask. A removed row is a different thing from a proposed one
    and now says so.

    Exit codes, all three of which callers act on differently:
      0  distinct among themselves AND clear of the registry — §6 branch (a)
      1  candidates collapse into one prefix — §6 branch (b), do not split
      1  candidates are distinct but one wants a prefix another family holds —
         rename it, or name that row with `--replace`
      2  the question could not be asked: fewer than two candidates, an
         unparseable cell, or no registry to check against
    """
    if len(cells) < 2:
        # Rule 47: a single candidate cannot exercise the collision check, so
        # a green verdict on one cell asserts nothing. The question this mode
        # answers — may one row become several? — needs at least two rows.
        print("index prefixes: --prefix needs at least TWO Family cells; one "
              "candidate cannot collide with anything and would report a "
              "vacuous pass", file=sys.stderr)
        return 2
    # Compare against the REGISTERED families too, not just against each
    # other. Candidates that are distinct among themselves can still collide
    # with a family already in §2, and reporting only the pairwise answer
    # would contradict what CI then enforces.
    rows = registry_rows()
    if rows is None:
        print("index prefixes: IMPLEMENTATION_INDEX.md is missing",
              file=sys.stderr)
        return 2
    if len(rows) < 2:
        # Same subject assertion main() makes. An absent or stub registry must
        # not read as "nothing to collide with": that would be a vacuous pass
        # in the one mode whose whole job is detecting collisions.
        print("index prefixes: §2 family table missing or too small — cannot "
              "check candidates against a registry that was never read",
              file=sys.stderr)
        return 2
    # ONLY --replace excludes a registry row. Treating a byte-identical
    # candidate as a replacement was wrong in both directions: it approved
    # `--prefix '**OLD-A1**' '**NEW-B1**'`, which proposes ADDING a row that
    # already exists — a duplicate CI rejects — and it let a replacement stay
    # implicit, which §6 requires to be stated.
    removing = set(replaced or ())
    unknown = [r for r in removing if r not in rows]
    if unknown:
        for r in unknown:
            print(f"index prefixes: --replace {r!r} matches no §2 row",
                  file=sys.stderr)
        print("index prefixes: a replaced row must be quoted EXACTLY as the "
              "registry holds it, or the exclusion silently does nothing",
              file=sys.stderr)
        return 2
    # VALIDATE THE REGISTRY BEFORE ANSWERING ABOUT CANDIDATES. Skipping an
    # unparseable row, or letting setdefault swallow a duplicate registered
    # prefix, would let this mode return DISTINCT/0 against a registry on which
    # CI mode returns 1 or 2 — the precise drift this command promises cannot
    # happen. A broken registry means the question cannot be answered yet.
    registered: dict[str, str] = {}
    registry_bad = False
    for row in rows:
        if row in removing:
            continue
        pref = family_prefix(row)
        if not pref:
            print(f"index prefixes: registered row {row!r} has no parseable "
                  f"prefix — the registry itself does not pass the gate",
                  file=sys.stderr)
            registry_bad = True
            continue
        if pref in registered and registered[pref] != row:
            print(f"index prefixes: registered prefix {pref!r} is already held "
                  f"by {registered[pref]!r}, and {row!r} claims it too — the "
                  f"registry itself does not pass the gate", file=sys.stderr)
            registry_bad = True
        registered.setdefault(pref, row)
    if registry_bad:
        print("index prefixes: fix §2 first; a candidate verdict against a "
              "registry that CI rejects would not be CI's answer",
              file=sys.stderr)
        return 2
    seen: dict[str, str] = {}
    collisions = []
    registry_hits: list[tuple[str, str, str]] = []
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
        if pref in registered:
            registry_hits.append((pref, cell, registered[pref]))
    # THE PAIRWISE VERDICT COMES FIRST, because it is the question this mode
    # was built to answer: may one row become several? When candidates collapse
    # into one prefix, the answer is §6 branch (b) — and that is exactly the
    # case where a registry hit is EXPECTED rather than a separate fault, since
    # the prefix they collapse to is usually the family's own. Reporting the
    # registry first told the caller to "rename the family" for the canonical
    # C2-R shape, which is the wrong instruction for the right observation.
    if collisions:
        for pref, a, b in collisions:
            if a == b:
                print(f"\nindex prefixes: {pref!r} claimed twice — the cell "
                      f"{a!r} was passed more than once")
            else:
                print(f"\nindex prefixes: {pref!r} is claimed by both {a!r} "
                      f"and {b!r}")
        # Only a registry hit on a prefix the candidates COLLAPSE INTO is
        # explained by the split. A hit on any other prefix is an unrelated
        # family this proposal would tread on, and calling that "not a second
        # fault" would bury a real error under a correct one.
        collapsed = {p for p, _, _ in collisions}
        expected = {p: r for p, _, r in registry_hits if p in collapsed}
        unrelated = [(p, c, r) for p, c, r in registry_hits if p not in collapsed]
        for pref, row in expected.items():
            print(f"index prefixes: (and {pref!r} is already registered by "
                  f"{row!r} — consistent with this being that family's own "
                  f"split, not a second fault)")
        for pref, cand, row in unrelated:
            print(f"index prefixes: SEPARATELY, {pref!r} is registered by "
                  f"{row!r}, so candidate {cand!r} collides with an unrelated "
                  f"family — this one needs a rename or a --replace")
        print("COLLIDE — rule 94 §6 branch (b): keep one row and put per-lane "
              "status in the owning doc. Do NOT widen the grammar to separate "
              "them; that costs the check its power to catch a real duplicate.")
        if unrelated:
            print("…and fix the unrelated registry collision above as well; "
                  "branch (b) does not excuse it.")
        return 1
    # Only once the candidates are distinct among themselves does a registry
    # hit mean what it says: this shape wants a prefix another family holds.
    if registry_hits:
        for pref, cand, row in registry_hits:
            print(f"\nindex prefixes: {pref!r} is ALREADY REGISTERED in §2 by "
                  f"{row!r}, so candidate {cand!r} cannot take it")
        print("COLLIDES WITH THE REGISTRY — the candidates are distinct among "
              "themselves, but one wants a prefix another family already "
              "holds. Either rename the candidate, or, if this proposal "
              "REMOVES that row, name it after --replace, quoted exactly as "
              "§2 holds it. Do NOT pass it as another candidate: that proposes "
              "adding it a second time and manufactures a pairwise collision.")
        return 1
    # Invariant worth stating out loud: branch (a) is available only when the
    # candidates and the prefixes they claim are in one-to-one correspondence.
    assert len(seen) == len(cells)
    print(f"\nDISTINCT ({len(cells)} candidates -> {len(seen)} prefixes, and "
          f"none collide with the {len(registered)} other families registered in "
          f"§2) — rule 94 §6 branch (a): one row per sub-family is available.")
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--prefix":
        rest = argv[1:]
        if "--replace" in rest:
            cut = rest.index("--replace")
            return report_candidates(rest[:cut], rest[cut + 1:])
        return report_candidates(rest)
    if argv:
        print(f"usage: {os.path.basename(__file__)} "
              f"[--prefix CELL CELL… [--replace CELL…]]", file=sys.stderr)
        return 2
    rows = registry_rows()
    if rows is None:
        print("index prefixes: IMPLEMENTATION_INDEX.md is missing", file=sys.stderr)
        return 2
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
