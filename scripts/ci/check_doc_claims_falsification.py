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


def green(name: str, doc: str = GOOD, restater: str = RESTATER,
          extra=None) -> tuple[str, bool, str]:
    """A negative control: the gate must PASS here.

    A check that cannot distinguish its subject from a lookalike is as useless
    as one that cannot fail. The records-was exclusion is exactly that kind of
    distinction, so it needs a case proving the exclusion excludes — otherwise
    "no error" could mean the leg simply never ran.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        build(tmp, doc, restater)
        if extra:
            extra(tmp)
        rc, out = run(tmp)
        return name, rc == 0, out.strip().splitlines()[0][:86] if out.strip() else ""


def with_submodule(populated: bool, gitlink: bool = False):
    """Give the synthetic tree a .gitmodules and an external/sub, or not.

    The distinction under test is between a file that was DELETED and one that
    is merely not checked out. Both look identical to `is_file()`, which is how
    the real baseline shipped one too high, so the matrix has to exercise a
    populated submodule and an empty one against the same citation.
    """
    def f(t: pathlib.Path) -> None:
        (t / ".gitmodules").write_text(
            '[submodule "external/sub"]\n\tpath = external/sub\n'
            "\turl = https://example.invalid/sub.git\n", encoding="utf-8")
        d = t / "external" / "sub"
        d.mkdir(parents=True, exist_ok=True)
        if populated:
            (d / "inc.h").write_text("one\ntwo\nthree\n", encoding="utf-8")
        elif gitlink:
            # What an interrupted `submodule update` leaves: the gitlink is
            # written before any content arrives, so the directory is non-empty
            # while holding none of the files a citation could resolve against.
            (d / ".git").write_text("gitdir: ../../.git/modules/external/sub\n",
                                    encoding="utf-8")
    return f


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
        # submodule discrimination — the defect this PR shipped and CI caught.
        # A path inside a submodule that is not checked out must STOP the run,
        # because a count taken against files that are merely absent locally
        # disagrees with CI by environment rather than by fact.
        case("citation into an uninitialised submodule", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=with_submodule(populated=False)),
        # ...and the branch must discriminate by PATH, not merely notice that
        # some submodule is empty. Same empty submodule, a dead citation that
        # has nothing to do with it: still ordinary rot, still reported as rot.
        case("dead citation elsewhere is still rot", "which does not exist",
             doc=sub("`src/thing.cpp:3`", "`src/absent.cpp:3`"),
             corpus=with_submodule(populated=False)),
        # A bare .git gitlink is not content: an interrupted update leaves the
        # directory non-empty and holding nothing a citation resolves against,
        # so a naive "is it empty" test would call the whole tree deleted.
        case("submodule holding only a gitlink", "not checked out here",
             doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
             corpus=with_submodule(populated=False, gitlink=True)),
        # ratchet — opt-in without one is adoption theatre, so each direction
        # of the ratchet has to be able to bite.
        case("ratchet: dead citations rose", "rose to",
             doc=sub("`src/thing.cpp:3`", "`src/gone.cpp:3`")),
        case("ratchet: baseline left above the truth", "lower the `dead-citations:`",
             baseline="dead-citations: 4\ndeclares: docs/subject.md citations,counts\n"),
        case("ratchet: a declared leg was dropped", "has dropped the claim-audit",
             doc=sub("<!-- claim-audit: counts -->", "")),
        # negative control: a stale range inside a records-was surface is
        # history, not a live claim, and must NOT fail the gate — otherwise a
        # register growing forces edits to closed round records.
        green("historical restatement is not a live claim",
              extra=lambda t: ((t / "docs" / "completed").mkdir(exist_ok=True),
                               (t / "docs" / "completed" / "old.md").write_text(
                                   "# Closed round\n\nIt held XX-W1…XX-W2 then.\n",
                                   encoding="utf-8"))),
        # negative control: a POPULATED submodule is ordinary tree, and its
        # citations resolve. Without this, "skip everything under a submodule"
        # would pass the matrix while silently retiring the leg for external/.
        green("populated submodule resolves normally",
              doc=sub("`src/thing.cpp:3`", "`external/sub/inc.h:2`"),
              extra=with_submodule(populated=True)),
        case("ratchet: baseline file missing", "has no baseline",
             corpus=lambda t: (t / "docs" / "ci" / "doc-claims-baseline.txt").unlink()),
    ]

    # Green negative controls are marked so the tally cannot claim a control
    # as a failure path — a matrix that miscounts its own cases is the first
    # thing a reader stops trusting.
    controls = {"historical restatement is not a live claim",
                "populated submodule resolves normally"}
    print(f"{'CASE':<44} {'AS EXPECTED':<12} message")
    for name, ok, msg in cases:
        kind = "green" if name in controls else "red"
        print(f"{name:<44} {('yes' if ok else 'NO') + f' ({kind})':<12} {msg[:74]}")
    bad = [n for n, ok, _ in cases if not ok]
    n_red = len([c for c in cases if c[0] not in controls])
    n_green = len(cases) - n_red

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
    print(f"\nOK: {n_red} failure paths each fired on its own axis, {n_green} "
          "negative control(s) stayed green, and the clean tree passes.")


if __name__ == "__main__":
    main()
