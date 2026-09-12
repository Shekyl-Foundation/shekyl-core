# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_conformance_coverage.py.
#
# EVERY FIXTURE HERE IS DELIBERATELY MULTI-SHAPE, and that is the lesson rather
# than a style choice. PR #704's resolver gate shipped two defects that a green
# run could not show, and the root cause was not "untested": every fixture was
# SINGLE-SECTION, and in a single-section document the document-level question
# and the section-level question return the same answer. The limb was
# UNTESTABLE by the shape of the fixture, so no number of added single-section
# cases could have found it.
#
# The shapes this gate must survive, all present in the base fixture below so
# that no case silently exercises only one of them:
#   - census rows across MORE THAN ONE `####` section table;
#   - a §9.2-style adjudication table whose first column is numeric and whose
#     cells MENTION CEN ids — these are not census rows and must not count;
#   - register rows in BOTH shipped shapes: the 4-column form of slices 1-3
#     (trailing "Digest acceptance" cell) and the 3-column form of slices 4-10;
#   - ids BOTH bolded (`**CEN-L8**`) and bare (`CEN-K1a`);
#   - a register row quoting C++ `\|\|`, which must parse as one cell;
#   - buckets 3 and 4 present, which must NOT be demanded.

import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_conformance_coverage.py"

CENSUS = """# Census

#### 4.A First section

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | a ratified rule | src/a.cpp:1 | C | 2 | ratified | spec | note |
| CEN-A5 | an unratified rule | src/a.cpp:2 | C | 4 | none | — | note |

#### 4.B Second section, because one table cannot show that both are read

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-L8 | a bucket-1 rule | src/b.cpp:1 | C | 1 | spec | spec | note |
| CEN-K1a | another ratified rule | src/b.cpp:2 | C | 2 | ratified | spec | note |
| CEN-E3 | a removed rule | deleted | C | 3 | — | — | note |

### 9.2 Adjudication — NOT census rows

| # | finding | landed | folded |
| --- | --- | --- | --- |
| 1 | something about CEN-A1 and CEN-ZZ9 | yes | Folded: CEN-A1 |
"""

REGISTER = """# Register

#### 5.4.1 The conformance-exception register

| Row | Conformance state | Evidence | Digest acceptance |
| --- | --- | --- | --- |
| **CEN-A1** | **CHECKED-CONFORMANT** | Reviewed at `deadbeef`. Walked | Digest required |
| **CEN-L8** | **UNREVIEWED** — *partial findings* | Failed closed at `deadbeef` | Regression only |

##### P0f slice 9 — a nested slice heading must not close the section

| Row | State | Evidence (all at `deadbeef`) |
| --- | --- | --- |
| CEN-K1a | **CHECKED-CONFORMANT** | W-AD. A walk with a quoted `a \\|\\| b` in it |

### 5.5 A later section

| Row | Note |
| --- | --- |
| CEN-A5 | mentioned here, but with no conformance state |
"""


def run(tmp, census=CENSUS, register=REGISTER):
    root = Path(tmp)
    (root / "docs/design").mkdir(parents=True, exist_ok=True)
    (root / "scripts/ci").mkdir(parents=True, exist_ok=True)
    (root / "docs/design/CONSENSUS_RULE_CENSUS.md").write_text(census, encoding="utf-8")
    (root / "docs/design/CONSENSUS_STORE_RECONCILIATION.md").write_text(register, encoding="utf-8")
    gate = root / "scripts/ci" / GATE.name
    gate.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
    return subprocess.run([sys.executable, str(gate)], capture_output=True, text=True)


CASES = []


def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


@case("the base fixture is GREEN — otherwise every red below proves nothing")
def _(tmp):
    r = run(tmp)
    assert r.returncode == 0, r.stderr
    assert "3 ratified rules, 3 recorded" in r.stdout, r.stdout
    return "3 ratified / 3 recorded across two census sections and two register shapes"


@case("UNCOVERED direction: a ratified rule with no register row FATALs, naming it")
def _(tmp):
    reg = REGISTER.replace(
        "| CEN-K1a | **CHECKED-CONFORMANT** | W-AD. A walk with a quoted `a \\|\\| b` in it |\n", "")
    r = run(tmp, register=reg)
    assert r.returncode == 1, "a removed record must not pass"
    assert "CEN-K1a" in r.stderr and "carry no conformance record" in r.stderr, r.stderr
    return "names CEN-K1a"


@case("OUTSIDE-SCOPE direction: a record for an unratified id FATALs, naming it")
def _(tmp):
    reg = REGISTER.replace(
        "| **CEN-A1** | **CHECKED-CONFORMANT** |",
        "| **CEN-ZZ9** | **CHECKED-CONFORMANT** | Reviewed at `deadbeef` | Digest |\n"
        "| **CEN-A1** | **CHECKED-CONFORMANT** |")
    r = run(tmp, register=reg)
    assert r.returncode == 1, "a row outside the ratified set must not pass"
    assert "CEN-ZZ9" in r.stderr and "NOT ratified" in r.stderr, r.stderr
    return "names CEN-ZZ9"


@case("buckets 3 and 4 are NOT demanded — absent by construction, not uncovered")
def _(tmp):
    r = run(tmp)
    assert r.returncode == 0
    assert "CEN-A5" not in r.stderr and "CEN-E3" not in r.stderr
    return "CEN-A5 (b4) and CEN-E3 (b3) carry no row and the gate stays green"


@case("RULE 47: a census whose rows vanish FATALs instead of covering trivially")
def _(tmp):
    stripped = "\n".join(l for l in CENSUS.split("\n") if not l.startswith("| CEN-"))
    r = run(tmp, census=stripped)
    assert r.returncode == 1, "an empty required set must not read as covered"
    assert "ZERO ratified" in r.stderr, r.stderr
    return "empty census is a missing subject, not a clean run"


@case("RULE 47: a register whose rows vanish FATALs")
def _(tmp):
    stripped = REGISTER.replace("**CHECKED-CONFORMANT**", "pending").replace("**UNREVIEWED**", "pending")
    r = run(tmp, register=stripped)
    assert r.returncode == 1
    assert "ZERO recorded" in r.stderr or "no recognised" in r.stderr, r.stderr
    return "empty register is a missing subject"


@case("RULE 47: a bucket column that stops parsing FATALs, per bucket")
def _(tmp):
    # Every ratified row demoted to bucket 4: the required set empties without
    # the table itself disappearing, which is the subtler form of the failure.
    c = CENSUS.replace("| C | 2 |", "| C | 4 |").replace("| C | 1 |", "| C | 4 |")
    r = run(tmp, census=c)
    assert r.returncode == 1
    assert "no bucket-1 rows" in r.stderr or "ZERO ratified" in r.stderr, r.stderr
    return "a silently-emptied bucket column is caught"


@case("a census row with an unescaped pipe FATALs rather than shifting its bucket")
def _(tmp):
    c = CENSUS.replace("| CEN-A1 | a ratified rule |", "| CEN-A1 | a rule with a | pipe |")
    r = run(tmp, census=c)
    assert r.returncode == 1, "a shifted bucket column must not be guessed at"
    assert "fields, expected" in r.stderr, r.stderr
    return "shape is asserted, not assumed"


@case("an escaped pipe inside a register cell parses as ONE cell")
def _(tmp):
    # The base fixture's CEN-K1a row already quotes `a \|\| b`; if the splitter
    # broke on it the row's state cell would shift and the row would vanish.
    r = run(tmp)
    assert r.returncode == 0 and "3 recorded" in r.stdout, r.stdout
    return "the C++-quoting row is still counted"


@case("a nested ##### slice heading does not close §5.4.1")
def _(tmp):
    # CEN-K1a lives under a `#####` heading. If that closed the section, the
    # two selectors would disagree and the gate would refuse.
    r = run(tmp)
    assert r.returncode == 0, r.stderr
    assert "disagree" not in r.stderr
    return "slice headings stay inside the register"


@case("the two register selectors must AGREE — a row that drifted OUT of §5.4.1 FATALs")
def _(tmp):
    # The first version of this case re-stated CEN-A1, which is already inside
    # §5.4.1 — so both selectors still saw the SAME SET and nothing disagreed.
    # A cross-check between two selectors only bites on a set difference, so the
    # fixture has to MOVE a row rather than duplicate one. Kept as a comment
    # because the broken version passed the eye and failed the run.
    reg = REGISTER.replace(
        "| CEN-K1a | **CHECKED-CONFORMANT** | W-AD. A walk with a quoted `a \\|\\| b` in it |\n", "")
    reg += ("\n### 6 Some other section\n\n| Row | State | Evidence |\n| --- | --- | --- |\n"
            "| CEN-K1a | **CHECKED-CONFORMANT** | a row that drifted out of the register |\n")
    r = run(tmp, register=reg)
    assert r.returncode == 1, "selector disagreement must not be resolved silently"
    assert "disagree" in r.stderr, r.stderr
    return "neither selector is allowed to win by default"


@case("SYMMETRIC DROP: an id shape both sides lose equally is caught per-side")
def _(tmp):
    # The failure a set difference CANNOT see: make the id unparseable in BOTH
    # documents at once. The difference stays empty and every comparison in the
    # gate is satisfied; only the per-side "tried to be an id" assertion fires.
    c = CENSUS.replace("| CEN-K1a |", "| CEN-K1a(!) |")
    reg = REGISTER.replace("| CEN-K1a |", "| CEN-K1a(!) |")
    r = run(tmp, census=c, register=reg)
    assert r.returncode == 1, "a drop that hits both sides equally must still be loud"
    assert "does not parse as a row id" in r.stderr, r.stderr
    # And prove the comparison alone would NOT have caught it:
    assert "carry no conformance record" not in r.stderr, \
        "the set difference should be empty here — that is the whole point"
    return "caught by the per-side assertion, invisible to the difference"


@case("alpha-suffixed ids are real row names and must survive recognition")
def _(tmp):
    # CEN-F14b, CEN-G6b, CEN-K1a, CEN-K1b, CEN-K5b are all live. A narrower
    # pattern like CEN-[A-Z][0-9]+ drops them from BOTH sides — the symmetric
    # case above, in the shape it would actually ship.
    c = CENSUS.replace("| CEN-K1a |", "| CEN-K5b |")
    reg = REGISTER.replace("| CEN-K1a |", "| CEN-K5b |")
    r = run(tmp, census=c, register=reg)
    assert r.returncode == 0, r.stderr
    return "CEN-K5b recognised on both sides"


@case("PHANTOM ids: a sibling row cited in prose is not a register row")
def _(tmp):
    # Evidence cells cite sibling rows constantly. An unanchored id pattern
    # harvests those and reports false "outside scope" FATALs; measured on the
    # live register, prose-only tokens include CEN-D1b, CEN-K1 and CEN-x.
    reg = REGISTER.replace(
        "Reviewed at `deadbeef`. Walked",
        "Reviewed at `deadbeef`. Same contract as CEN-D1b and CEN-K1; see CEN-x's schema")
    r = run(tmp, register=reg)
    assert r.returncode == 0, r.stderr
    assert "CEN-D1b" not in r.stderr and "CEN-K1 " not in r.stderr
    return "prose citations do not become rows"


@case("EN-DASH ranges in prose invent no rows")
def _(tmp):
    # `CEN-I10–I13` and `CEN-L1–L6` both occur live, with an en-dash. Doing
    # nothing is correct here; expanding the range would invent recorded rows.
    reg = REGISTER.replace("Walked", "Walked; the CEN-I10–I13 family and CEN-L1–L6 agree")
    r = run(tmp, register=reg)
    assert r.returncode == 0, r.stderr
    for invented in ("CEN-I11", "CEN-I12", "CEN-L2", "CEN-L3"):
        assert invented not in r.stderr
    return "ranges are not expanded"


@case("INTERSECTION: a bolded alpha-suffixed id in a SECOND table of a section")
def _(tmp):
    # 8a's post-mortem: every #704 defect sat at an INTERSECTION of axes, not on
    # a single axis. This one fixture crosses four — bolded AND alpha-suffixed
    # AND in a section's second table AND under a nested ##### heading.
    c = CENSUS.replace(
        "| CEN-K1a | another ratified rule | src/b.cpp:2 | C | 2 | ratified | spec | note |",
        "| CEN-K1a | another ratified rule | src/b.cpp:2 | C | 2 | ratified | spec | note |\n"
        "| CEN-G6b | a suffixed ratified rule | src/b.cpp:3 | C | 2 | ratified | spec | note |")
    reg = REGISTER.replace(
        "| CEN-K1a | **CHECKED-CONFORMANT** | W-AD. A walk with a quoted `a \\|\\| b` in it |",
        "| CEN-K1a | **CHECKED-CONFORMANT** | W-AD. A walk with a quoted `a \\|\\| b` in it |\n"
        "\n##### P0f slice 10 — a second table under a second nested heading\n\n"
        "| Row | State | Evidence |\n| --- | --- | --- |\n"
        "| **CEN-G6b** | **DIVERGENT** | ratified S=4, shipped 50 |")
    r = run(tmp, census=c, register=reg)
    assert r.returncode == 0, r.stderr
    assert "4 ratified rules, 4 recorded" in r.stdout, r.stdout
    return "bolded + suffixed + second table + second nested heading, all at once"


@case("a register row with an id but no recognised state FATALs")
def _(tmp):
    reg = REGISTER.replace("| **CEN-A1** | **CHECKED-CONFORMANT** |", "| **CEN-A1** | **PROBABLY-FINE** |")
    r = run(tmp, register=reg)
    assert r.returncode == 1
    assert "no recognised" in r.stderr or "carry no conformance record" in r.stderr, r.stderr
    return "an unknown state is not silently dropped"


@case("§9.2 adjudication rows are not counted as census rows")
def _(tmp):
    # The base fixture's §9.2 table mentions CEN-ZZ9, which exists nowhere else.
    # If it were parsed as a census row the gate would demand a record for it.
    r = run(tmp)
    assert r.returncode == 0 and "CEN-ZZ9" not in r.stderr, r.stderr
    return "numeric-first-column rows are ignored"


@case("a missing document FATALs rather than reading as an empty set")
def _(tmp):
    root = Path(tmp)
    r = run(tmp)
    assert r.returncode == 0
    (root / "docs/design/CONSENSUS_RULE_CENSUS.md").unlink()
    gate = root / "scripts/ci" / GATE.name
    r = subprocess.run([sys.executable, str(gate)], capture_output=True, text=True)
    assert r.returncode == 1 and "missing" in r.stderr, r.stderr
    return "an absent subject is named"


def main():
    failed = 0
    for name, fn in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                detail = fn(tmp)
                print(f"  ok   {name}\n         -> {detail}")
            except AssertionError as e:
                failed += 1
                print(f"  FAIL {name}\n         {e}", file=sys.stderr)
    print(f"\n{len(CASES) - failed}/{len(CASES)} self-test cases passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
