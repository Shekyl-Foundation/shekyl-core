# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Coverage gate: EVERY RATIFIED CONSENSUS RULE CARRIES A CONFORMANCE RECORD.
#
# CSR-3a (CONSENSUS_STORE_RECONCILIATION.md §5.4.1) makes the C++ a correctness
# oracle for a rule only when the rule is ratified on record AND someone checked
# that the C++ implements the spec it was ratified against. Absence from the
# register IS the UNREVIEWED state — deliberately fail-closed. This gate makes
# that semantics CHECKABLE rather than merely stated, in both directions:
#
#   census bucket 1/2  \  register  -> UNCOVERED: a ratified rule with no record
#   register  \  census bucket 1/2  -> OUTSIDE SCOPE: a record for a rule that
#                                      is not ratified (or an id that moved)
#
# WHY A GATE AND NOT A COUNT. Counting register rows proves the register is
# SELF-CONSISTENT; it cannot prove COVERAGE, because an absent row has no id to
# count. The denominator has already moved four times — 102 rows at 4b9807c5e,
# +9 from C2-R1b, +10 from C2-R1c, +1 for CEN-I19 — and every move was a
# promotion from unrelated consensus work that silently reopened a backlog
# someone had just called closed. That is how the register came to say
# "twenty-seven carry no conformance record" while reading as complete. A
# measurement decays; an invariant breaks loudly.
#
# SCOPE — the word "ratified" is load-bearing. Buckets 3 and 4 are absent from
# the register and therefore UNREVIEWED **by construction**: they carry no
# ratified spec to review against, which §5.4.1 already states. This gate must
# NOT demand rows for them, or it would demand a conformance verdict against
# nothing.
#
# Instance of 47-gate-subject-assertion.mdc, which this gate needs more than
# most: it reports a clean tree and an extractor that stopped extracting with
# the SAME output — two empty sets also have an empty difference. Every parse
# asserts its own subject below, and the register is read by two independent
# selectors that must agree.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CENSUS = ROOT / "docs/design/CONSENSUS_RULE_CENSUS.md"
REGISTER = ROOT / "docs/design/CONSENSUS_STORE_RECONCILIATION.md"

# The three conformance states of §5.4.1. This vocabulary is itself a selector:
# a register row's state cell must begin with one of them.
STATES = ("CHECKED-CONFORMANT", "DIVERGENT", "UNREVIEWED")
STATE_RE = re.compile(r"^\*{0,2}(" + "|".join(STATES) + r")")

# `**CEN-L8**` and `CEN-K1a` are both real spellings. CEN-L8 is bolded AND is
# the only UNREVIEWED row, so a selector that missed bolded ids would report a
# register with no exception in it at all.
ID_RE = re.compile(r"^\*{0,2}(CEN-[A-Za-z0-9]+)\*{0,2}$")

# A cell that is TRYING to be an id: it begins with `CEN-` (optionally bolded)
# but may not parse as one. The difference between this and ID_RE is the whole
# of the symmetric-recognition hazard below.
ID_ATTEMPT_RE = re.compile(r"^\*{0,2}CEN-")

# THE FAILURE A SET DIFFERENCE CANNOT SEE, and the reason both parses count
# their own drops. Every check in this gate compares two sets, so it catches
# an ASYMMETRIC defect — one side loses an id, the difference goes non-empty,
# something fires. But an id-RECOGNITION defect hits both sides equally: the
# same row vanishes from the census set and the register set, the difference
# stays empty, and the gate is green while that rule was never checked in
# either direction. The rule-47 zero-assertions do not see it either, because
# both sets are still large and non-empty — they are just both wrong by the
# same element. A narrower pattern (say `CEN-[A-Z][0-9]+`) would silently drop
# every alpha-suffixed id — CEN-F14b, CEN-G6b, CEN-K1a, CEN-K1b, CEN-K5b are
# all real row names today — and nothing here would have said so.
#
# Two mitigations, and the second is the load-bearing one:
#   (1) ONE recogniser, shared by both sides, so the two cannot drift apart;
#   (2) each side asserts `rows that tried to be an id == ids parsed`, so a
#       recogniser bug is loud on each side INDEPENDENTLY of the comparison.
# Credit: shekyl-core-8a, from the #704 post-mortem.

# The census §4 row: | id | rule | site(s) | C/P | bucket | class | evidence | notes |
# Splitting a leading-and-trailing-pipe row yields 10 fields.
CENSUS_FIELDS = 10
CENSUS_ID = 1
CENSUS_BUCKET = 5
RATIFIED_BUCKETS = {"1", "2"}

# Markdown escapes a literal pipe inside a cell as `\|`; splitting on it would
# shift every column right of the escape. Two rows of slice 10 quote C++ `||`.
CELL_SPLIT = re.compile(r"(?<!\\)\|")


def cells(line):
    return [c.strip() for c in CELL_SPLIT.split(line.rstrip("\n"))]


def read(path, failures):
    if not path.is_file():
        failures.append(f"{path.relative_to(ROOT)}: missing — the gate's subject does not exist")
        return None
    return path.read_text(encoding="utf-8").split("\n")


def census_ratified(lines, failures):
    """Ids whose DOCUMENTED bucket field is 1 or 2.

    Read from the bucket COLUMN, not an ad-hoc regex over the line: §9.2's
    adjudication rows mention CEN ids inside their cells while starting with a
    numeric first column, and counting those would inflate the required set with
    rows that are not census rows.
    """
    ids, buckets, shape_errors, unparsed = set(), {}, [], []
    attempts = 0
    for n, line in enumerate(lines, 1):
        if not line.startswith("| CEN-"):
            continue
        c = cells(line)
        if len(c) != CENSUS_FIELDS:
            # A stray unescaped pipe shifts the bucket column, and a shifted
            # bucket reads as "not ratified" — which drops a real rule out of
            # the required set and lets coverage pass while it is uncovered.
            # Refuse rather than guess.
            shape_errors.append(f"  {CENSUS.name}:{n}: {c[CENSUS_ID] if len(c) > 1 else '?'} "
                                f"has {len(c)} fields, expected {CENSUS_FIELDS} "
                                f"(an unescaped '|' shifts the bucket column)")
            continue
        attempts += 1
        m = ID_RE.match(c[CENSUS_ID])
        if not m:
            unparsed.append(f"  {CENSUS.name}:{n}: first cell {c[CENSUS_ID][:40]!r} begins with "
                            "'CEN-' but does not parse as a row id — it would be dropped in "
                            "silence, and a drop that hits both documents is invisible to the "
                            "set difference")
            continue
        bucket = c[CENSUS_BUCKET]
        buckets[bucket] = buckets.get(bucket, 0) + 1
        if bucket in RATIFIED_BUCKETS:
            ids.add(m.group(1))
    failures.extend(shape_errors)
    failures.extend(unparsed)
    # Subject assertions. A bucket column that stopped parsing yields an empty
    # required set, and an empty set covers trivially.
    if not ids:
        failures.append(f"{CENSUS.name}: parsed ZERO ratified (bucket 1/2) rules — "
                        "the census table or its bucket column did not parse")
    for b in sorted(RATIFIED_BUCKETS):
        if not buckets.get(b):
            failures.append(f"{CENSUS.name}: parsed no bucket-{b} rows at all — "
                            "the bucket column is not being read where it is written")
    return ids


def register_recorded(lines, failures):
    """Ids carrying a conformance state, by TWO independent selectors.

    Selector A trusts the state vocabulary and scans the whole document.
    Selector B trusts the section boundary and scans only §5.4.1.
    They answer the same question by different means, so a disagreement means
    one of them is wrong and the gate must not pick a winner silently.
    """
    by_state, by_section = set(), set()
    unstated, unparsed = [], []
    attempts = 0
    in_section = False
    for n, line in enumerate(lines, 1):
        if line.startswith("#### 5.4.1"):
            in_section = True
            continue
        # Any heading at the same or a shallower level closes the section;
        # `#####` slice headings are nested inside it and must not.
        if in_section and re.match(r"^#{1,4} ", line):
            in_section = False
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) < 4:
            continue
        if not ID_ATTEMPT_RE.match(c[CENSUS_ID]):
            continue
        # The "tried to be an id" assertion applies only INSIDE §5.4.1, because
        # only there is "first cell is a bare row id" the schema. Elsewhere the
        # document carries tables with their own first-cell shapes — the S-ALT /
        # S-ARCH tables spell theirs `**CEN-L11** (b1)`, id plus bucket — and
        # demanding this schema of them would be this gate asserting a contract
        # it does not own. Scope to the table, then index (shekyl-core-8a, #704).
        if in_section:
            attempts += 1
            m = ID_RE.match(c[CENSUS_ID])
            if not m:
                unparsed.append(f"  {REGISTER.name}:{n}: first cell {c[CENSUS_ID][:40]!r} begins "
                                "with 'CEN-' but does not parse as a row id — it would be dropped "
                                "in silence, and a drop that hits both documents is invisible to "
                                "the set difference")
                continue
        else:
            m = ID_RE.match(c[CENSUS_ID])
            if not m:
                continue
        stated = bool(STATE_RE.match(c[2]))
        if stated:
            by_state.add(m.group(1))
        if in_section:
            if stated:
                by_section.add(m.group(1))
            else:
                # A row inside the register that carries an id but no
                # recognisable state: the row schema changed under the gate.
                unstated.append(f"  {REGISTER.name}:{n}: {m.group(1)} has no recognised "
                                f"conformance state (found {c[2][:40]!r})")
    failures.extend(unstated)
    failures.extend(unparsed)

    if not by_state or not by_section:
        failures.append(f"{REGISTER.name}: parsed ZERO recorded rows — "
                        "§5.4.1 or its row schema did not parse")
        return by_state | by_section

    only_state = sorted(by_state - by_section)
    only_section = sorted(by_section - by_state)
    if only_state or only_section:
        failures.append(
            f"{REGISTER.name}: the two register selectors disagree, so neither can be "
            f"trusted — state-vocabulary found {len(by_state)}, §5.4.1-section found "
            f"{len(by_section)}; outside the section: {only_state or 'none'}; "
            f"inside but not state-matched: {only_section or 'none'}")
    return by_state | by_section


def main():
    failures = []
    census_lines = read(CENSUS, failures)
    register_lines = read(REGISTER, failures)

    # Each side is parsed even if the other failed, and BOTH sets of findings
    # are reported together. A gate that stops at the first problem hides every
    # later one in the same file, and the reader then fixes one thing and runs
    # again to discover the next (shekyl-core-8a, from #704 where an early
    # return masked the rest of the document).
    ratified = census_ratified(census_lines, failures) if census_lines is not None else set()
    recorded = register_recorded(register_lines, failures) if register_lines is not None else set()
    if failures:
        report(failures)

    uncovered = sorted(ratified - recorded)
    outside = sorted(recorded - ratified)

    if uncovered:
        failures.append(
            f"{len(uncovered)} RATIFIED consensus rule(s) carry no conformance record — "
            f"absence from the register IS the UNREVIEWED state (CSR-3a), so the backlog "
            f"has reopened:\n  " + ", ".join(uncovered) +
            "\n  Either review them into §5.4.1, or — if a promotion into bucket 1/2 was "
            "not intended — correct the census bucket.")
    if outside:
        failures.append(
            f"{len(outside)} register row(s) record a rule that is NOT ratified (census "
            f"bucket 1/2):\n  " + ", ".join(outside) +
            "\n  A conformance verdict needs a ratified spec to be a verdict ABOUT. "
            "Either the census bucket moved, or the row's id is stale.")

    report(failures)
    print(f"conformance coverage: {len(ratified)} ratified rules, {len(recorded)} recorded, "
          f"set-difference zero in both directions")


def report(failures):
    if failures:
        print("Conformance-coverage gate FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  {f}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
