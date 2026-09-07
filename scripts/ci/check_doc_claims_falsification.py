# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Falsification matrix for check_doc_claims.py — committed alongside the gate
# because a gate whose failure paths are only asserted in a PR body is a gate
# nobody can re-check after the next refactor. This is runnable: re-run it
# whenever the gate changes, exactly as the P0b review had to re-falsify a
# coverage gate after its legs were refactored.
#
# It builds a synthetic docs corpus in a temporary tree and runs the gate
# against THAT, so it never edits the repository. That choice is deliberate:
# an earlier mutation harness in this program truncated a 10,000-line source
# file to zero because `open(path, "w")` truncates before the transform that
# feeds it can raise. A matrix that cannot damage the tree cannot repeat it.
#
# Every case asserts a SPECIFIC message fragment, not merely a non-zero exit.
# A leg that fails for the wrong reason is a leg that is not being tested, and
# "it went red" is the weakest possible evidence that it went red on its own
# axis.

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

GATE = pathlib.Path(__file__).resolve().parent / "check_doc_claims.py"

# A declaring document that satisfies every leg. Each case below breaks
# exactly one thing in it (or in the corpus around it).
GOOD = """# Synthetic subject

**Status:** test fixture.

<!-- claim-audit: series XX-W -->
<!-- claim-audit: range XX-W -->
<!-- claim-audit: sections -->
<!-- claim-audit: numbered -->
<!-- claim-audit: counts -->
<!-- claim-audit: citations -->

See §2 for the table. The cite is `src/thing.cpp:3`.

## 1. First

1. one
2. two
3. three

## 2. Second

**3 rows** follow:

| ID | Note |
| --- | --- |
| XX-W1 | a |
| XX-W2 | b |
| XX-W3 | c |
"""

RESTATER = "# Restater\n\nThe range XX-W1…XX-W3 is complete.\n"


def build(tmp: pathlib.Path, doc: str = GOOD, restater: str = RESTATER,
          baseline: str | None = None) -> None:
    (tmp / "scripts" / "ci").mkdir(parents=True, exist_ok=True)
    shutil.copy(GATE, tmp / "scripts" / "ci" / GATE.name)
    (tmp / "src").mkdir(parents=True, exist_ok=True)
    (tmp / "src" / "thing.cpp").write_text("a\nb\nc\nd\n", encoding="utf-8")
    docs = tmp / "docs"
    (docs / "ci").mkdir(parents=True, exist_ok=True)
    (docs / "ci" / "doc-claims-baseline.txt").write_text(
        baseline if baseline is not None else
        "dead-citations: 0\ndeclares: docs/subject.md citations,counts\n",
        encoding="utf-8")
    for i in range(60):  # clear the corpus floor
        (docs / f"filler{i:02d}.md").write_text(f"# Filler {i}\n", encoding="utf-8")
    (docs / "subject.md").write_text(doc, encoding="utf-8")
    if restater is not None:
        (docs / "restater.md").write_text(restater, encoding="utf-8")


def run(tmp: pathlib.Path) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(tmp / "scripts" / "ci" / GATE.name)],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


def case(name: str, expect: str, doc: str = GOOD, restater: str = RESTATER,
         corpus=None, baseline: str | None = None) -> tuple[str, bool, str]:
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp, doc, restater, baseline)
        if corpus:
            corpus(tmp)
        rc, out = run(tmp)
        line = next((l.strip() for l in out.splitlines()
                     if expect.lower() in l.lower()), "")
        return name, (rc != 0 and bool(line)), (line or out.splitlines()[0][:90])


def sub(old: str, new: str) -> str:
    assert GOOD.count(old) == 1, f"fixture anchor not unique: {old!r}"
    return GOOD.replace(old, new)


def main() -> None:
    cases = [
        # corpus- and adoption-level subject assertion
        case("corpus floor (docs emptied)", "corpus this gate audits",
             corpus=lambda t: [p.unlink() for p in (t / "docs").glob("*.md")]),
        case("no declarations anywhere", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit:", "<!-- was-claim-audit:")),
        case("unknown declaration kind", "unknown claim-audit kind",
             doc=sub("<!-- claim-audit: sections -->", "<!-- claim-audit: rationale -->")),
        # series
        case("series: duplicate row", "duplicate rows",
             doc=sub("| XX-W3 | c |", "| XX-W2 | c |")),
        case("series: gap", "missing [2]",
             doc=sub("| XX-W2 | b |", "| XX-W4 | b |")),
        case("series: subject missing", "the subject this declaration names is missing",
             doc=sub("<!-- claim-audit: series XX-W -->", "<!-- claim-audit: series ZZ-Q -->")),
        case("series: no prefix given", "needs a prefix",
             doc=sub("<!-- claim-audit: series XX-W -->", "<!-- claim-audit: series -->")),
        # range
        case("range: restatement disagrees", "restates the XX-W range ending at",
             restater="# Restater\n\nThe range XX-W1…XX-W2 is complete.\n"),
        case("range: nothing restates it", "no document restates that range",
             restater=None),
        # sections
        case("sections: dangling reference", "which this document does not have",
             doc=sub("See §2 for the table.", "See §7 for the table.")),
        # Both numbered headings must go: removing one leaves §2 resolvable, so
        # the leg passes correctly and the case would be testing nothing. The
        # first attempt at this case did exactly that and reported a false green
        # for the matrix rather than for the gate.
        case("sections: no numbered headings", "has no numbered headings",
             doc=GOOD.replace("## 1. First", "## First").replace("## 2. Second", "## Second")),
        # numbered
        case("numbered: gap in the list", "numbered list runs",
             doc=sub("2. two", "3. two")),
        case("numbered: no list at all", "no numbered list of three",
             doc=sub("1. one\n2. two\n3. three", "- one\n- two\n- three")),
        # counts
        case("counts: figure disagrees with table", "over a table of",
             doc=sub("**3 rows** follow", "**4 rows** follow")),
        case("counts: no figure stated", "states no **N rows** figure",
             doc=sub("**3 rows** follow:", "The rows follow:")),
        # code-fence immunity: documenting the syntax must not declare it, and
        # the negative case matters as much as the positive — a fenced example
        # that still counted is how this gate first failed against its own
        # README section.
        case("declaration inside a fence is not one", "passes vacuously",
             doc=GOOD.replace("<!-- claim-audit: series XX-W -->",
                              "```\n<!-- claim-audit: series XX-W -->\n```")
                     .replace("<!-- claim-audit: range XX-W -->", "")
                     .replace("<!-- claim-audit: sections -->", "")
                     .replace("<!-- claim-audit: numbered -->", "")
                     .replace("<!-- claim-audit: counts -->", "")
                     .replace("<!-- claim-audit: citations -->", "")),
        # citations
        case("citations: file does not exist", "which does not exist",
             doc=sub("`src/thing.cpp:3`", "`src/absent.cpp:3`")),
        case("citations: line beyond end of file", "but that file has",
             doc=sub("`src/thing.cpp:3`", "`src/thing.cpp:99`")),
        case("citations: none present", "declares `citations` but makes none",
             doc=sub("The cite is `src/thing.cpp:3`.", "No cite here.")),
        # ratchet — opt-in without one is adoption theatre, so each direction
        # of the ratchet has to be able to bite.
        case("ratchet: dead citations rose", "rose to",
             doc=sub("`src/thing.cpp:3`", "`src/gone.cpp:3`")),
        case("ratchet: baseline left above the truth", "lower the `dead-citations:`",
             baseline="dead-citations: 4\ndeclares: docs/subject.md citations,counts\n"),
        case("ratchet: a declared leg was dropped", "has dropped the claim-audit",
             doc=sub("<!-- claim-audit: counts -->", "")),
        case("ratchet: baseline file missing", "has no baseline",
             corpus=lambda t: (t / "docs" / "ci" / "doc-claims-baseline.txt").unlink()),
    ]

    print(f"{'FAILURE PATH':<38} {'RED':<5} message")
    for name, ok, msg in cases:
        print(f"{name:<38} {'yes' if ok else 'NO':<5} {msg[:86]}")
    bad = [n for n, ok, _ in cases if not ok]

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp)
        rc, out = run(tmp)
    clean_ok = rc == 0 and "does not check rationales" in out
    print(f"\nclean synthetic tree: {'GREEN' if clean_ok else 'NOT GREEN'} — "
          f"{out.strip().splitlines()[0][:80] if out.strip() else '(no output)'}")

    if bad or not clean_ok:
        sys.exit(f"FAIL: {len(bad)} path(s) did not fire on their own axis: {bad}"
                 + ("" if clean_ok else "; and the clean tree did not pass"))
    print(f"\nOK: {len(cases)} failure paths each fired on its own axis, and the "
          "clean tree passes.")


if __name__ == "__main__":
    main()
