#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""DRS-E1: derive the conformance register's per-row states, and cross-check.

The E1 comparator is a direct table diff whose output is graded per row
against CSR-3a (`DAEMON_REDB_STORE.md`, DRS-E2: "the acceptance condition is
per conformance state, NOT blanket digest identity").  This gate derives the
map that grading reads, so no figure reaches the comparator from prose.

WHY A CROSS-CHECK AND NOT JUST AN EXTRACTOR.  Reading this register wrong is
not hypothetical: two extractions of it were wrong in OPPOSITE directions
within an hour of each other, and each looked plausible alone.

  * UNANCHORED  - matching the state word anywhere in the row OVER-counts,
    because promoted rows carry history parentheticals such as
    "(was DIVERGENT, re-reviewed post-fix)".  A row that is CHECKED-CONFORMANT
    today reads as DIVERGENT to a substring match.
  * SLICED      - taking the section by heading UNDER-counts, because 5.4.1 is
    EIGHT sub-tables at different pins, not one.  A slice that stops at the
    next heading silently drops the rows that carry the live DIVERGENT states.

So the extractor is anchored to the start of the state cell, AND its result is
checked against the totals the document states about itself.  Either alone is
one instrument over one field; together they must agree or this fails.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "docs" / "design" / "CONSENSUS_STORE_RECONCILIATION.md"
CENSUS = ROOT / "docs" / "design" / "CONSENSUS_RULE_CENSUS.md"

STATES = ("CHECKED-CONFORMANT", "DIVERGENT", "UNREVIEWED")

# State ANCHORED to the start of the state cell -- never "the word appears".
ROW_RE = re.compile(
    r"^\| \*?\*?(CEN-[A-Za-z0-9]+)\*?\*?[^|]*\| *\*\*([A-Z-]+)\*\*", re.MULTILINE
)


def register_states(text: str) -> dict[str, str]:
    """Every row whose state cell BEGINS with a state token."""
    out: dict[str, str] = {}
    for rid, state in ROW_RE.findall(text):
        if state in STATES:
            out[rid] = state
    return out


def live_bucket_1_2(text: str) -> set[str]:
    """Census rows in buckets 1 or 2 -- the rules a store port must honour."""
    live = set()
    for rid, rest in re.findall(r"^\| (CEN-[A-Za-z0-9]+) \|(.*)$", text, re.MULTILINE):
        if any(cell.strip() in ("1", "2") for cell in rest.split("|")):
            live.add(rid)
    return live


def main() -> None:
    errors: list[str] = []
    for path in (REGISTER, CENSUS):
        if not path.is_file():
            sys.exit(f"FAIL: {path.relative_to(ROOT)} is missing -- the gate's subject does not exist")

    reg_text = REGISTER.read_text(encoding="utf-8")
    states = register_states(reg_text)
    if not states:
        sys.exit(
            "FAIL: parsed ZERO conformance rows from the register. The table "
            "shape changed and this extractor is reading nothing -- absence of "
            "signal is first evidence the subject is absent (rule 47)."
        )
    tally = Counter(states.values())

    # Cross-check 1: the anchoring must be LOAD-BEARING, demonstrated on the
    # live data rather than asserted. Rows promoted after a fix keep their
    # history in prose -- "(was DIVERGENT, re-reviewed post-fix)" -- so a
    # reader that matches the state word anywhere in the row grades a
    # long-fixed row as DIVERGENT. Under CSR-3a that inverts its acceptance:
    # DIVERGENT + identical = FAIL, so an unanchored reader would fail the
    # port for reproducing defects that are not there.
    #
    # This is not hypothetical and not vacuous: it is asserted against the
    # rows that actually carry the trap, so loosening the extractor flips
    # them and fails here.
    # MEASUREMENT, NOT A GUARD -- and labelled so because I could not make
    # it bite. The membership over-count is real and worth reporting: a
    # reader asking "does this row mention DIVERGENT" grades long-fixed rows
    # as divergent, which under CSR-3a FAILS the port for defects that are
    # not there. But as a check it only fires if the over-count vanishes
    # ENTIRELY: redacting the history words from ten of the fifteen trapped
    # rows left it green, because 135 pairs still exceeds 130 rows.
    #
    # A check that needs its whole subject deleted before it fails is not a
    # check. The thing that actually protects the anchoring is the extractor
    # regex plus cross-check 2 below, which does bite. This stays as a
    # printed figure so the hazard is visible to a reader.
    membership_pairs = 0
    trapped: list[str] = []
    for line in reg_text.splitlines():
        m = re.match(r"^\| \*?\*?(CEN-[A-Za-z0-9]+)", line)
        if not m:
            continue
        mentioned = [state for state in STATES if state in line]
        membership_pairs += len(mentioned)
        if m.group(1) in states and len(mentioned) > 1:
            trapped.append(m.group(1))

    # Cross-check 2: the register must STATE its current tally, and the
    # stated one must be the derived one.
    #
    # Not "every stated figure must match": the same sentence carries
    # historical tallies ("100 CHECKED-CONFORMANT" from an earlier era),
    # which are records-was and correct as written. Demanding those match
    # would fail on true sentences. What is checked is the live direction --
    # for each state, the derived count must appear next to that state name
    # somewhere in the document. If the register drifts from the rows, the
    # prose stops containing the derived number and this fires.
    for state in STATES:
        derived = tally.get(state, 0)
        if not re.search(rf"\b{derived} (?:rows? )?{re.escape(state)}\b", reg_text):
            errors.append(
                f"the register never states its current {state} count: the "
                f"rows derive {derived}, and no '{derived} {state}' appears "
                "in the prose. A register whose own summary has drifted from "
                "its rows is the defect this gate exists to catch."
            )

    # The by-absence UNREVIEWED set: computed, never read.
    live = live_bucket_1_2(CENSUS.read_text(encoding="utf-8"))
    by_absence = sorted(live - set(states))

    if errors:
        sys.exit("FAIL: the conformance join disagrees with its sources:\n  " + "\n  ".join(errors))

    print(
        f"OK: conformance register derived -- {len(states)} rows: "
        + ", ".join(f"{tally[s]} {s}" for s in STATES if tally.get(s))
    )
    div = sorted(r for r, s in states.items() if s == "DIVERGENT")
    print(
        f"    DIVERGENT rows (identity FAILS on these -- reproducing a known "
        f"defect is not parity): {', '.join(div) if div else 'none'}"
    )
    print(
        f"    UNREVIEWED by absence: {len(by_absence)} live bucket-1/2 rules "
        f"carry no conformance record. Derived as a set difference over IDs, "
        f"never read from prose."
    )
    print(
        f"    Anchoring (MEASURED, not guarded): {len(trapped)} row(s) mention a "
        f"state in history prose as well as in their state cell "
        f"({membership_pairs} membership pairs vs {len(states)} real rows). "
        "A membership reader grades those fixed rows DIVERGENT, which under "
        "CSR-3a FAILS the port for defects that are not there."
    )
    print(
        "    This gate checks the MAP the grading reads, not the grading: "
        "what a match MEANS per row is shekyl-chain-store::conformance."
    )


if __name__ == "__main__":
    main()
