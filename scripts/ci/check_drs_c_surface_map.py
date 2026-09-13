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

# Identifiers of type `BlockchainDB *` / `&` declared anywhere in the file —
# members, parameters of file-static helpers, visitor fields. The alias SET is
# derived, never hardcoded: this gate's first version matched the literal
# `m_db->` token, which is the same derivation that built the table it checks,
# so it was green BY CONSTRUCTION over every call made through any other name.
# Three live methods were missing and it could not see them.
# `(?:const\s+)?` so a cv-qualified declaration yields the identifier and not
# the literal token `const` as an "alias".
ALIAS_DECL_RE = re.compile(
    r"BlockchainDB\s*[*&]\s*(?:const\s+)?([a-zA-Z_][a-zA-Z0-9_]*)")

# Receiver shapes this derivation cannot follow. It reads `alias->method`, so a
# call written any other way is invisible to it — which is exactly the defect
# this gate was built green over. Each is REFUSED rather than silently missed:
# undercounting is the failure mode, and it must be loud. Zero of these are
# present today; they are refused so that the day one appears, the gate says so
# instead of quietly shrinking the vocabulary.
UNHANDLED_SHAPES = (
    (re.compile(r"get_db\(\)\s*(?:\.|->)\s*[a-zA-Z_]"),
     "reaches the store through `get_db()`"),
    (re.compile(r"\bauto\s*[*&]?\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\*?\s*"
                r"(?:m_db|db)\s*[;,)]"),
     "binds the store to an `auto` name, whose declaration carries no "
     "`BlockchainDB` token for the alias derivation to find"),
    (re.compile(r"\(\s*\*\s*(?:m_db|db)\s*\)\s*\."),
     "calls through a dereferenced pointer `(*db).method()` rather than `->`"),
)
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

    src = SOURCE.read_text(encoding="utf-8")
    aliases = sorted(set(ALIAS_DECL_RE.findall(src)))
    if not aliases:
        report([f"{SOURCE.name}: found no `BlockchainDB *` identifiers — the alias derivation is "
                "broken, and an empty vocabulary is covered by any partition"])
    vocabulary = set()
    for alias in aliases:
        vocabulary |= set(
            re.findall(rf"(?<![\w>]){re.escape(alias)}->([a-zA-Z_][a-zA-Z0-9_]*)", src))
    if not vocabulary:
        report([f"{SOURCE.name}: parsed ZERO store calls across aliases {aliases} — "
                "the derivation is broken"])
    for shape_re, what in UNHANDLED_SHAPES:
        hit = shape_re.search(src)
        if hit:
            line = src.count("\n", 0, hit.start()) + 1
            report([f"{SOURCE.name}:{line}: {what}, which this gate's alias derivation does not "
                    f"cover ({hit.group(0).strip()!r}). Extend the derivation to follow that "
                    "shape rather than letting the vocabulary silently undercount."])

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
            f"the total (alias-derived, it moved +7/-3 for a net +4 between 3247fe3b6 and "
            f"f103acd38), and re-derive it with THIS derivation: a delta measured between two "
            f"different instruments misfiles unchanged methods as births and deaths.")

    report(failures)
    print(f"DRS-C surface map: {len(vocabulary)} store methods derived from {SOURCE.name} "
          f"across aliases {aliases} <-> {len(seen)} assigned across {len(rows)} surfaces; "
          f"every method in exactly one, counts{'' if counts_ok else ' NOT'} consistent")


def report(failures):
    if failures:
        print("DRS-C surface map FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
