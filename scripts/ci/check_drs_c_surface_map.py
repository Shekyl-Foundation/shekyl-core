# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-C (Tier-A A9): blockchain.cpp's `m_db->` vocabulary is partitioned into
# named validation surfaces, and the partition is a BIJECTION — every method in
# exactly one surface, every listed method real.
#
# WHY A GATE AND NOT A STAMP. §3.5 carried a verification stamp pinning it to
# `3247fe3b6` (2026-07-27) at 97 methods. That figure was correct when written
# and stayed correct in the document while the tree moved to 99 — and the
# membership moved by TWELVE (+7 / -5) to shift the total by two. A stamp
# records that someone looked once; it cannot notice the twelfth change. This
# gate re-derives the vocabulary from the tree it runs on.
#
# THE DENOMINATOR IS DERIVED, NEVER READ FROM THE PROSE. The count in the
# heading is checked against the derivation, not trusted as its source.
#
# Instance of 47-gate-subject-assertion.mdc: an empty vocabulary or an
# unparsed table would satisfy the bijection vacuously, so both are asserted.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/cryptonote_core/blockchain.cpp"
DOC = ROOT / "docs/design/DAEMON_REDB_STORE.md"

CALL_RE = re.compile(r"m_db->([a-zA-Z_][a-zA-Z0-9_]*)")
SECTION_RE = re.compile(r"^### 3\.5 ", re.M)
ROW_RE = re.compile(r"^\|\s*\*\*(S-[A-Z-]+)\*\*\s*\|([^|]*)\|\s*(\d+)\s*\|([^|]*)\|", re.M)
METHOD_RE = re.compile(r"`([a-zA-Z_][a-zA-Z0-9_]*)`")


def main():
    failures = []
    for p in (SOURCE, DOC):
        if not p.is_file():
            failures.append(f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist")
    if failures:
        report(failures)

    vocabulary = set(CALL_RE.findall(SOURCE.read_text(encoding="utf-8")))
    if not vocabulary:
        report([f"{SOURCE.name}: parsed ZERO `m_db->` calls — the derivation is broken, and an "
                "empty vocabulary is covered by any partition"])

    text = DOC.read_text(encoding="utf-8")
    m = SECTION_RE.search(text)
    if not m:
        report([f"{DOC.name}: §3.5 heading not found — subject missing"])
    section = text[m.start():]
    nxt = re.search(r"^### 3\.6 ", section, re.M)
    section = section[: nxt.start()] if nxt else section

    rows = ROW_RE.findall(section)
    if not rows:
        report([f"{DOC.name}: §3.5 has no surface rows — subject missing"])

    seen = {}
    counts_ok = True
    for surface, _role, declared, methods in rows:
        names = METHOD_RE.findall(methods)
        if len(names) != int(declared):
            failures.append(
                f"{surface}: the row declares {declared} methods and lists {len(names)}")
            counts_ok = False
        for name in names:
            if name in seen:
                failures.append(
                    f"`{name}` is assigned to BOTH {seen[name]} and {surface} — a method in two "
                    f"surfaces makes the extraction order ambiguous for it")
            else:
                seen[name] = surface

    uncovered = sorted(vocabulary - set(seen))
    phantom = sorted(set(seen) - vocabulary)
    if uncovered:
        failures.append(
            f"{len(uncovered)} method(s) reached from blockchain.cpp are in NO surface:\n    "
            + ", ".join(uncovered)
            + "\n    A9 requires the DB use to be partitioned; an unassigned method belongs to no "
              "rewrite increment and is scoped by nothing.")
    if phantom:
        failures.append(
            f"{len(phantom)} method(s) in §3.5 are NOT reached from blockchain.cpp:\n    "
            + ", ".join(phantom)
            + "\n    Either the method was removed and its row is stale, or the name is wrong. A "
              "surface row pointing at nothing scopes nothing.")

    # The heading's count is checked against the derivation, not believed.
    head = re.search(r"### 3\.5 DRS-C surface map \((\d+) methods", section)
    if not head:
        failures.append(f"{DOC.name}: §3.5 heading does not state a method count")
    elif int(head.group(1)) != len(vocabulary):
        failures.append(
            f"§3.5's heading says {head.group(1)} methods; the tree has {len(vocabulary)}. "
            f"Re-derive the SET, not just the number — the membership can move further than "
            f"the total (it moved +7/-5 for a net +2 between 3247fe3b6 and f103acd38).")

    report(failures)
    print(f"DRS-C surface map: {len(vocabulary)} `m_db->` methods derived from "
          f"{SOURCE.name} <-> {len(seen)} assigned across {len(rows)} surfaces; "
          f"every method in exactly one, counts{'' if counts_ok else ' NOT'} consistent")


def report(failures):
    if failures:
        print("DRS-C surface map FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
