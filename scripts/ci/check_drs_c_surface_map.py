# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-C (Tier-A A9): blockchain.cpp's store vocabulary is partitioned into
# named validation surfaces, and the partition is a BIJECTION — every method in
# exactly one surface, every listed method real.
#
# WHY A GATE AND NOT A STAMP. §3.5 carried a verification stamp pinning it to
# `3247fe3b6` (2026-07-27) at 97 methods. A stamp records that someone looked
# once; it cannot notice the next change. Re-derived alias-aware, that pin holds
# 98 and the current tree holds 102 — and the membership moved further than the
# total (+7 / -3). This gate re-derives from the tree it runs on.
#
# WHY THE DERIVATION IS THE HARD PART. The first version matched the literal
# `m_db->` token — the same derivation that built the table it checks — so it
# was green BY CONSTRUCTION over every call made through any other name, and
# three live methods were in no surface at all. Re-deriving is only independent
# if the METHOD differs, not merely the run.
#
# THE STANDING RULE HERE: every receiver shape is either COLLECTED or REFUSED,
# never silently skipped. Undercounting is the failure mode, because a method
# that vanishes from the vocabulary is covered by any partition. When in doubt
# the derivation errs toward OVER-collecting: a phantom fails loudly and a human
# looks, where a missing method just goes green.
#
# THE DENOMINATOR IS DERIVED, NEVER READ FROM THE PROSE. The count in the
# heading is checked against the derivation, not trusted as its source.
#
# Instance of 47-gate-subject-assertion.mdc: an empty vocabulary or an
# unparsed table would satisfy the bijection vacuously, so both are asserted.
#
# Self-test: scripts/ci/test_check_drs_c_surface_map.py pins every shape below.
# A regex added here without a case added there is how round 2 happened.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/cryptonote_core/blockchain.cpp"
DOC = ROOT / "docs/design/DAEMON_REDB_STORE.md"

# The declaration's SIGIL is captured, not just the name: a `BlockchainDB *` is
# called through `->` and a `BlockchainDB &` through `.`, and collecting the
# wrong operator is how a reference alias gets derived, looks covered, and
# contributes nothing. `(?:const\s+)?` so a cv-qualified declaration yields the
# identifier and not the literal token `const`.
ALIAS_DECL_RE = re.compile(
    r"BlockchainDB\s*([*&])\s*(?:const\s+)?([a-zA-Z_][a-zA-Z0-9_]*)")

# Figures about this partition that live OUTSIDE §3.5. The heading's count was
# gated; these siblings were not, and every one of them drifted to 97 while the
# tree moved to 102 — in the design doc's own preamble, in the reconciliation
# doc's two tables, and in the tracking index. A gated number beside ungated
# restatements of itself is a number that disagrees with itself in public.
# Each file must state the figure at least once, and every occurrence must
# equal the derivation (rule 47: a file that has stopped stating it fails as a
# missing subject, rather than passing by absence).
CROSS_REF_FILES = (
    ROOT / "docs/design/DAEMON_REDB_STORE.md",
    ROOT / "docs/design/CONSENSUS_STORE_RECONCILIATION.md",
    ROOT / "docs/design/IMPLEMENTATION_INDEX.md",
)
# Every spelling of THIS figure, not the one phrasing this gate's author
# happened to write. Keying on `N store methods` alone meant the check only saw
# prose it had just been handed: two restatements survived in other wordings
# (`97 DB methods`, ``97 `m_db->` methods``) and the gate was green over exactly
# the drift it was added to catch. The qualifier is required, so unrelated
# method counts in the same documents are not swept in — `77 methods` is the
# archival gather shell (E-7) and `48 virtual archival methods` is the base
# class, neither of which this figure governs.
CROSS_REF_METHODS_RE = re.compile(
    r"(\d+)\s*(?:\*\*)?\s*(?:`m_db->`|`db->`|store|DB)\s+methods")
CROSS_REF_SITES_RE = re.compile(r"(\d+) store call sites")

SECTION_RE = re.compile(r"^### 3\.5 ", re.M)
ROW_RE = re.compile(r"^\|\s*\*\*(S-[A-Z-]+)\*\*\s*\|([^|]*)\|\s*(\d+)\s*\|([^|]*)\|", re.M)
METHOD_RE = re.compile(r"`([a-zA-Z_][a-zA-Z0-9_]*)`")
HEAD_RE = re.compile(r"### 3\.5 DRS-C surface map \((\d+) methods")


def derive_aliases(src):
    """Identifier -> the call operators it can legally be reached through.

    A name declared both ways (pointer in one scope, reference in another)
    carries both operators rather than whichever declaration was seen last.
    """
    aliases = {}
    for sigil, name in ALIAS_DECL_RE.findall(src):
        aliases.setdefault(name, set()).add("->" if sigil == "*" else ".")
    return aliases


def collect_vocabulary(src, aliases):
    """Every store method reached through any derived alias.

    The lookbehind excludes identifier characters ONLY. It deliberately does not
    exclude `>`, so `this->m_db->height()` is collected: treating `>` as a
    boundary dropped arrow-qualified receivers that the original `m_db->` token
    match had caught — a regression, and in the silent direction. Admitting
    `obj->db->x` for an unrelated member named `db` costs a phantom, which
    fails loudly; dropping `this->m_db->x` costs a method, which does not.
    """
    vocabulary = set()
    for name, operators in aliases.items():
        for op in operators:
            vocabulary |= set(re.findall(
                rf"(?<!\w){re.escape(name)}\s*{re.escape(op)}\s*([a-zA-Z_][a-zA-Z0-9_]*)", src))
    return vocabulary


def unhandled_shapes(src, aliases):
    """Receiver shapes this derivation cannot follow, as (line, what, snippet).

    Refused rather than silently missed. The patterns are built FROM the derived
    alias set, never from a hardcoded pair: a gate whose derivation is dynamic
    and whose refusals are hand-written reintroduces the original defect for
    every alias nobody remembered to add here.

    `get_db` is refused on sight anywhere in the file rather than only when a
    call follows it, because binding its result to a reference and calling
    through that is exactly the invisible path. Known and accepted: this also
    fires on a comment that merely mentions `get_db()`. That is a false positive
    in the loud direction, and stripping comments first has a worse edge (a `//`
    inside a string literal), so the noisier rule is the deliberate choice.
    """
    alternation = "|".join(re.escape(n) for n in sorted(aliases)) if aliases else r"(?!x)x"
    shapes = (
        (re.compile(r"\bget_db\b"),
         "reaches the store through `get_db()`, whose result this derivation "
         "cannot follow"),
        (re.compile(rf"\bauto\s*[*&]?\s*[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[*&]?\s*"
                    rf"(?:{alternation})\s*[;,)]"),
         "binds the store to an `auto` name, whose declaration carries no "
         "`BlockchainDB` token for the alias derivation to find"),
        (re.compile(rf"\(\s*\*\s*(?:{alternation})\s*\)\s*\."),
         "calls through a dereferenced pointer `(*db).method()` rather than `->`"),
    )
    found = []
    for shape_re, what in shapes:
        hit = shape_re.search(src)
        if hit:
            found.append((src.count("\n", 0, hit.start()) + 1, what, hit.group(0).strip()))
    return found


def check_cross_references(read, vocabulary_size, call_sites):
    """Figures restated outside §3.5 must equal the derivation.

    `read` maps a path to its text, so this is testable without a tree.
    """
    failures = []
    for path in CROSS_REF_FILES:
        text = read(path)
        if text is None:
            failures.append(f"{path.name}: missing — a cross-reference subject does not exist")
            continue
        stated = CROSS_REF_METHODS_RE.findall(text)
        if not stated:
            failures.append(
                f"{path.name}: states no `N store methods` figure. It is a declared "
                f"cross-reference for the DRS-C partition, so silence here is a stale figure "
                f"that got reworded, not a file with nothing to say.")
        for n in set(stated):
            if int(n) != vocabulary_size:
                failures.append(
                    f"{path.name}: says {n} store methods; the tree has {vocabulary_size}. "
                    f"A figure restated outside §3.5 drifts exactly as quietly as one inside it.")
        for n in set(CROSS_REF_SITES_RE.findall(text)):
            if int(n) != call_sites:
                failures.append(
                    f"{path.name}: says {n} store call sites; the tree has {call_sites}.")
    return failures


def count_call_sites(src, aliases):
    """Call SITES, not distinct methods — the tangle's size, restated in prose."""
    total = 0
    for name, operators in aliases.items():
        for op in operators:
            total += len(re.findall(
                rf"(?<!\w){re.escape(name)}\s*{re.escape(op)}\s*[a-zA-Z_]", src))
    return total


def slice_section(text):
    """The §3.5 block, or None when the gate's subject is absent."""
    m = SECTION_RE.search(text)
    if not m:
        return None
    section = text[m.start():]
    nxt = re.search(r"^### 3\.6 ", section, re.M)
    return section[: nxt.start()] if nxt else section


def check_partition(section, vocabulary):
    """Bijection between §3.5's rows and the derived vocabulary.

    Returns (failures, assigned, rows, counts_ok).
    """
    failures = []
    rows = ROW_RE.findall(section)
    if not rows:
        return ([f"§3.5 has no surface rows — subject missing"], {}, [], False)

    assigned = {}
    counts_ok = True
    for surface, _role, declared, methods in rows:
        names = METHOD_RE.findall(methods)
        if len(names) != int(declared):
            failures.append(
                f"{surface}: the row declares {declared} methods and lists {len(names)}")
            counts_ok = False
        for name in names:
            if name in assigned:
                failures.append(
                    f"`{name}` is assigned to BOTH {assigned[name]} and {surface} — a method in "
                    f"two surfaces makes the extraction order ambiguous for it")
            else:
                assigned[name] = surface

    uncovered = sorted(vocabulary - set(assigned))
    phantom = sorted(set(assigned) - vocabulary)
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
    head = HEAD_RE.search(section)
    if not head:
        failures.append("§3.5 heading does not state a method count")
    elif int(head.group(1)) != len(vocabulary):
        failures.append(
            f"§3.5's heading says {head.group(1)} methods; the tree has {len(vocabulary)}. "
            f"Re-derive the SET, not just the number — the membership can move further than "
            f"the total (alias-derived, it moved +7/-3 for a net +4 between 3247fe3b6 and "
            f"f103acd38), and re-derive it with THIS derivation: a delta measured between two "
            f"different instruments misfiles unchanged methods as births and deaths.")
    return (failures, assigned, rows, counts_ok)


def main():
    missing = [f"{p.relative_to(ROOT)}: missing — the gate's subject does not exist"
               for p in (SOURCE, DOC) if not p.is_file()]
    if missing:
        report(missing)

    src = SOURCE.read_text(encoding="utf-8")
    aliases = derive_aliases(src)
    if not aliases:
        report([f"{SOURCE.name}: found no `BlockchainDB *`/`&` identifiers — the alias derivation "
                "is broken, and an empty vocabulary is covered by any partition"])

    for line, what, snippet in unhandled_shapes(src, aliases):
        report([f"{SOURCE.name}:{line}: {what} ({snippet!r}). Extend the derivation to follow "
                "that shape rather than letting the vocabulary silently undercount."])

    vocabulary = collect_vocabulary(src, aliases)
    if not vocabulary:
        report([f"{SOURCE.name}: parsed ZERO store calls across aliases "
                f"{sorted(aliases)} — the derivation is broken"])

    section = slice_section(DOC.read_text(encoding="utf-8"))
    if section is None:
        report([f"{DOC.name}: §3.5 heading not found — subject missing"])

    failures, assigned, rows, counts_ok = check_partition(section, vocabulary)
    failures = [f"{DOC.name}: {f}" if f.startswith("§3.5 h") else f for f in failures]
    failures += check_cross_references(
        lambda p: p.read_text(encoding="utf-8") if p.is_file() else None,
        len(vocabulary), count_call_sites(src, aliases))
    report(failures)

    shown = {name: "".join(sorted(ops)) for name, ops in sorted(aliases.items())}
    print(f"DRS-C surface map: {len(vocabulary)} store methods derived from {SOURCE.name} "
          f"across aliases {shown} <-> {len(assigned)} assigned across {len(rows)} surfaces; "
          f"every method in exactly one, counts{'' if counts_ok else ' NOT'} consistent")


def report(failures):
    if failures:
        print("DRS-C surface map FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
