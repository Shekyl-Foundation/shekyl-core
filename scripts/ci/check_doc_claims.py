# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Documentation claim audit — a document declares the invariants it means to
# hold, and this gate holds it to them.
#
# WHY THIS EXISTS, and what the evidence was. PR #633 (DRS-P0b) took thirteen
# review rounds. The first nine were reactive: a reviewer found an instance,
# the instance was fixed, and the next round found another instance of the
# same class. From round ten the author ran a mechanical claim check before
# every push, and the character of the rounds changed — that pass caught three
# defects no reviewer had filed (a matrix row routed to a section that did not
# exist, a register that jumped W-3 to W-6, a stated writer count gone stale)
# and the later rounds found only things it could not see. A measured
# before-and-after on one PR is this gate's whole warrant.
#
# WHY DECLARED RATHER THAN UNIVERSAL. The first cut of this script inferred
# the same invariants corpus-wide and reported 991 findings against a clean
# tree. Almost all were false: `§17` usually cites *another* document's
# section, registers legitimately skip a retired number, and the CHANGELOG
# cites files that existed when it was written. A gate that fires 991 times
# on a clean tree is not a strict gate, it is an unusable one — convention
# theatre pointing the other way. So the unit is a DECLARATION: a document
# states, in its own text, which invariants it intends to satisfy, and the
# gate checks exactly those. False positives become impossible by
# construction, and each declaration is a promise a reviewer can read.
#
#     <!-- claim-audit: series DRS-W -->        register rows contiguous, no dupes
#     <!-- claim-audit: range DRS-W -->         "DRS-W1…DRS-Wn" restatements match it
#     <!-- claim-audit: sections -->            every §N names a section this doc has
#     <!-- claim-audit: numbered -->            numbered lists number themselves 1,2,3…
#     <!-- claim-audit: citations -->           every path:line cite resolves in the tree
#     <!-- claim-audit: counts -->              "**N rows**" matches the table beneath it
#
# WHAT IT CANNOT CHECK, stated in the pass line rather than left to inference:
# it audits VALUES AGAINST SOURCE, never RATIONALES AGAINST THE WORLD. Four
# premises were refuted by review in the two days before this was written — a
# doubling time, a parked-baseline frequency, an anonymity premise, and a
# "never live on the reachable grid" claim — and every one would have passed
# this gate green, because each was internally consistent and wrong about
# reality. Green here means "the numbers match their own tables and the tree",
# never "this document is right".
#
# WHAT IT DOES CATCH, as the worked example opposite those four: within an hour
# of the first declaration it found that V4_DESIGN_NOTES.md still restated the
# DRS-W finding range at its old upper bound — a fifth surface, updated in
# review round 7 and missed by the round-13 sweep of four. The rule generated
# the gate and the gate immediately caught the rule's own class in its own
# parent work.
#
# UNUSABLE AND ABSENT ARE THE SAME STATE. This is why the model is declaration
# rather than inference, and it is a rule rather than a preference: a 1.5x
# threshold that fires on thermal variation gets ignored, a flaky required
# check gets bypassed, a gate nobody can read gets disabled, and a claim audit
# with 991 findings on a clean tree gets scrolled past. A check that cannot be
# acted on has the same effect as no check, while costing the trust of the ones
# that can.
#
# SUBJECT ASSERTION (rule 47), per declaration rather than once. A document
# that declares an invariant whose subject this gate cannot find FAILS: the
# distinction that must never blur is CHECKED-AND-PASSED versus
# FOUND-NOTHING-TO-CHECK. This program has been bitten twice by an extraction
# that matched nothing and reported success (a whitespace-rigid regex that
# returned 45 names instead of 46; a macro grep that returned zero against an
# older tree) and twice by a documentation edit whose anchor silently matched
# nothing. A claim auditor that cannot find the table it was told to check and
# prints "no discrepancies" is that same defect wearing this script's name.

import functools
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

DECL = re.compile(r"<!--\s*claim-audit:\s*([a-z]+)(?:\s+([A-Za-z][\w-]*))?\s*-->")
# Every comment that MEANS to be a declaration, well-formed or not. A matcher
# that only sees valid markers cannot see a typo: `claim-audit: Citations` fails
# DECL's `[a-z]+`, matches nothing, and the document then looks opted in to a
# reader while no check runs against it — and the adoption floor stays satisfied
# by some other document, so nothing anywhere goes red. Absence of a match is
# first evidence the subject is malformed, not that it is absent (rule 47).
DECL_ANY = re.compile(r"<!--\s*claim-audit:[^>]*-->")
KINDS = {"series", "range", "sections", "numbered", "citations", "counts"}

# Floor on the corpus itself: this gate audits docs/, and a run that cannot
# find the corpus has lost its subject rather than found a tidy tree.
MIN_DOCS = 50
# Floor on adoption: the gate is pointless if nothing declares anything, and a
# run finding zero declarations means the marker syntax broke, not that every
# document opted out.
MIN_DECLARATIONS = 1

# Stated non-coverage. Not errors — a leg declining a subject it cannot judge
# is correct behaviour — but never silent either, because "checked and passed"
# and "not looked at" must not share an appearance. Printed on every run,
# green or red.
NOTES: list[str] = []


def rel(p: pathlib.Path) -> str:
    return str(p.relative_to(ROOT))


def decl_token(kind: str, arg: str | None) -> str:
    """`series DRS-W` -> "series:DRS-W"; `sections` -> "sections".

    The identity of a declaration is the pair, not the kind. One document here
    declares `series DRS-W` and `series R`, and a registry keyed on kind alone
    cannot tell which of the two it is holding.
    """
    return f"{kind}:{arg}" if arg else kind


def strip_code(text: str) -> str:
    """Blank out fenced and inline code, preserving line numbers.

    Documenting the marker syntax must not opt a document in. This gate's own
    README section and CHANGELOG entry show the markers as examples, and the
    first version read them as declarations — so the documentation of a check
    became a subject of it. Newlines are preserved so every reported line
    number still points where a reader would look.
    """
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def _series_rows(text: str, prefix: str) -> list[int]:
    return [int(m.group(1)) for m in
            re.finditer(rf"^\| {re.escape(prefix)}-?(\d+) \|", text, re.MULTILINE)]


def check_series(p, text, arg, errs):
    if not arg:
        errs.append(f"{rel(p)}: `claim-audit: series` needs a prefix, e.g. "
                    "`series DRS-W`")
        return 0
    nums = _series_rows(text, arg)
    if len(nums) < 2:
        errs.append(f"{rel(p)}: declares `series {arg}` but only {len(nums)} "
                    f"`| {arg}-N |` row(s) were found — the subject this "
                    "declaration names is missing, which is a broken check, "
                    "not a clean one")
        return 0
    dupes = sorted({n for n in nums if nums.count(n) > 1})
    if dupes:
        errs.append(f"{rel(p)}: series {arg} has duplicate rows {dupes}")
    span = range(min(nums), max(nums) + 1)
    missing = [n for n in span if n not in set(nums)]
    if missing:
        errs.append(f"{rel(p)}: series {arg} runs {min(nums)}..{max(nums)} but is "
                    f"missing {missing} — a declared-contiguous register with a "
                    "gap is either incomplete or renumbered")
    return len(nums)


def check_range(p, text, arg, errs, corpus):
    """The declaring doc owns the register; every live restatement must match."""
    if not arg:
        errs.append(f"{rel(p)}: `claim-audit: range` needs a prefix")
        return 0
    nums = _series_rows(text, arg)
    if not nums:
        errs.append(f"{rel(p)}: declares `range {arg}` but owns no "
                    f"`| {arg}-N |` rows — nothing to be the range of")
        return 0
    # BOTH endpoints. Matching only the upper one let `DRS-W2…DRS-W11` pass
    # against a register running 1..11: the restatement would be claiming the
    # series starts where it does not, which is the same class of false claim
    # as ending where it does not, and the declared contract is that the
    # restated range MATCHES. Every restatement in the corpus is a full-extent
    # one, so this tightens the check without inventing a constraint the
    # documents do not already meet.
    low, high = min(nums), max(nums)
    pat = re.compile(rf"{re.escape(arg)}-?(\d+)…(?:{re.escape(arg)}-?)?(\d+)")
    seen = 0
    for q, qtext in corpus:
        # Records-was surfaces are excluded for the same reason the citation
        # ratchet excludes them: a range quoted in a CHANGELOG entry or a
        # closed round doc is what was true when it was written. Checking it
        # as a live claim would mean rewriting history every time a register
        # grows — the document would be edited to satisfy the gate rather than
        # the gate serving the document.
        if is_records_was(q):
            continue
        for m in pat.finditer(qtext):
            seen += 1
            lo, hi = int(m.group(1)), int(m.group(2))
            if (lo, hi) != (low, high):
                line = qtext[: m.start()].count("\n") + 1
                errs.append(f"{rel(q)}:{line}: restates the {arg} range as "
                            f"{arg}{lo}…{arg}{hi}, but {rel(p)} holds "
                            f"{arg}{low}…{arg}{high}")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `range {arg}` but no document restates "
                    f"that range — the check has no subject")
    return seen


def check_sections(p, text, _arg, errs):
    """Every §N names a section this document has — and §N.M is another's.

    Dotted references are NOT silently dropped, they are deliberately out of
    scope, and the difference has to be visible. In the adopting audit all four
    `§6.6` references mean DRS §6.6 — a section of DAEMON_REDB_STORE.md, named
    as such at its own §6 heading. Checking them against this document's
    headings would fail four correct cross-document references, which is the
    expensive direction: a false constraint teaches readers to work around the
    gate. But leaving them unmentioned would let `§99.9` — a typo — pass as
    though it had been checked, so the count of skipped references is reported
    rather than assumed to be zero.

    Documents that DO use dotted headings get their dotted references checked,
    because there the ambiguity does not arise.
    """
    have = {m.group(1) for m in
            re.finditer(r"^#{2,4} (\d+[a-z]?(?:\.\d+)?)\.?\s", text, re.M)}
    if not have:
        errs.append(f"{rel(p)}: declares `sections` but has no numbered headings")
        return 0
    dotted_local = any("." in h for h in have)
    if not dotted_local:
        external = len(re.findall(r"§\d+[a-z]?\.\d+", text))
        if external:
            NOTES.append(f"{rel(p)}: {external} dotted §N.M reference(s) treated "
                         "as cross-document and NOT checked (this document has "
                         "no dotted headings of its own)")
    pat = (r"§(\d+[a-z]?(?:\.\d+)?)(?![\d.])" if dotted_local
           else r"§(\d+[a-z]?)(?![\d.])")
    seen = 0
    for m in re.finditer(pat, text):
        seen += 1
        if m.group(1) not in have:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: refers to §{m.group(1)}, which this "
                        f"document does not have")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `sections` but makes no §N reference")
    return seen


def _numbered_runs(text: str) -> list[list[tuple[int, int]]]:
    """Numbered runs, tracked PER INDENT LEVEL.

    A column-0-only matcher cannot see a nested list, and worse, it cannot see
    the list the nested one is inside: the indented children never match, the
    blank line after them closes the outer fragment, and a two-item remainder
    falls under the three-item floor and is discarded. The declaring document
    here has exactly that shape at §2, so the leg was reporting a tally while
    most of the structure it names went unchecked — checked-and-passed wearing
    the face of found-nothing-to-check.

    Blank lines do not close a run: a loose markdown list is separated by them
    and is still one list. Only prose at or left of a run's own indent closes
    it.

    A repeated `1.` at the same indent does NOT start a new list, though an
    earlier draft treated it as one. CommonMark continues an ordered list
    across a repeated number — only the first item's number is honoured — so
    `1, 2, 1, 2, 3` is one five-item list that has been mis-numbered, which is
    exactly the fault this leg exists to report. Splitting it dropped the
    two-item fragment under the three-item floor and passed the remainder.
    """
    runs: dict[int, list[tuple[int, int]]] = {}
    out: list[list[tuple[int, int]]] = []

    def close(pred) -> None:
        for d in sorted([d for d in runs if pred(d)], reverse=True):
            r = runs.pop(d)
            if len(r) >= 3:
                out.append(r)

    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^([ \t]*)(\d+)\. ", line)
        if m:
            ind, num = len(m.group(1).expandtabs()), int(m.group(2))
            close(lambda d, ind=ind: d > ind)      # children end at their parent
            runs.setdefault(ind, []).append((i, num))
        elif line.strip():
            ind = len(line[: len(line) - len(line.lstrip())].expandtabs())
            close(lambda d, ind=ind: ind <= d)
    close(lambda d: True)
    return sorted(out, key=lambda r: r[0][0])


def check_numbered(p, text, _arg, errs):
    runs = _numbered_runs(text)
    if not runs:
        errs.append(f"{rel(p)}: declares `numbered` but has no numbered list of "
                    "three or more items")
        return 0
    for run in runs:
        nums = [n for _, n in run]
        # From 1, not from whatever the first item happens to say. An earlier
        # round rejected this as a false constraint, citing a corpus run that
        # started at 3 — but that run was an artefact of the column-0 matcher
        # mis-parsing a nested list, and with the parser fixed every run in the
        # corpus starts at 1. The measurement was taken with a broken
        # instrument, so it could not support the conclusion drawn from it.
        if nums != list(range(1, len(nums) + 1)):
            errs.append(f"{rel(p)}:{run[0][0]}: numbered list runs {nums} — the "
                        "declared invariant is 1, 2, 3 …, so a gap, repeat, or "
                        "wrong start means a step was inserted or removed without "
                        "renumbering")
    return sum(len(r) for r in runs)


# Anchored at a path boundary: without the leading (?<![\w/-]) a token like
# `shekyl-economics-sim/src/record.rs:143` matches from its inner "src/" and the
# gate then reports a file that was never cited. Crate-relative paths are
# resolved under rust/ before being called missing, and a token under no known
# root is not this gate's subject rather than a failure.
#
# One regex and one resolver, deliberately. Both the declared `citations` leg
# and the ratchet's corpus-wide count need exactly this, and they carried
# verbatim copies until the submodule case below had to land in both — which is
# how the third copy starts. A duplicate gets deleted, not synchronised.
# The optional second endpoint is not decoration: `file.rs:81-127` is the house
# citation style and there are 143 of them in live documents. Matching only the
# start line meant a file truncated INSIDE a cited range still resolved, and the
# ratchet stayed green over a citation that no longer points at what it names.
CITE = re.compile(r"(?<![\w/-])((?:src|rust|scripts|tests|external|shekyl-[\w-]+)"
                  r"/[\w./-]+\.(?:cpp|h|rs|py|sh|inl)):(\d+)"
                  r"(?:\s*[-–—]\s*(\d+))?")
ROOTS = ("src/", "rust/", "scripts/", "tests/", "external/")


@functools.cache
def untrusted_submodules() -> tuple[str, ...]:
    """Submodule prefixes whose content is not provably the recorded content.

    Named for the question actually being asked. "Uninitialised" was too narrow
    once git's own status became the primary signal: a submodule at the WRONG
    commit is checked out, and still cannot answer what line 77 of one of its
    files says.

    A submodule that was never checked out looks exactly like a deleted file to
    anything that only asks `is_file()`, and this repository has already been
    bitten by that: the link gate reports every path under an uninitialised
    submodule as a dead link. Absence of the file is the first evidence that the
    SUBJECT is absent, not that the claim is wrong (rule 47).

    "Empty" ignores a lone `.git`, which is the state an interrupted or partial
    `submodule update` leaves behind: the gitlink is written before any content
    arrives. Counting that directory as populated would resolve every path under
    it to "deleted" and report a tree's worth of phantom rot — the same
    misattribution this function exists to prevent, reached by a narrower door.
    """
    out = []
    # Authoritative first: git reports "-" for not-initialised and "+" for
    # checked out at a commit other than the one the superproject records. A
    # non-empty directory proves neither — a stale or partial checkout has
    # files, they are simply not the recorded ones, and citations resolved
    # against them measure a different tree than CI does.
    gm = ROOT / ".gitmodules"
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "submodule", "status"],
                           capture_output=True, text=True, timeout=60)
        failed = r.returncode != 0
    except (OSError, subprocess.SubprocessError):
        r, failed = None, True
    # If this tree HAS submodules and git cannot say what state they are in,
    # stop. Falling back to "is the directory non-empty" would answer a
    # different question and call it the same answer: a populated directory
    # does not prove the recorded commit, which is the very thing the fallback
    # would be standing in for. An unavailable check is not a passed check.
    if failed and gm.is_file():
        sys.exit("FAIL: `git submodule status` could not be read, so this run "
                 "cannot establish whether cited submodule content is the "
                 "content this tree records. The directory test that remains "
                 "detects an empty checkout only, and would silently accept a "
                 "stale one — a weaker check wearing the stronger one's name.")
    if r is not None and not failed:
        for line in r.stdout.splitlines():
            if line[:1] in ("-", "+", "U") and len(line.split()) >= 2:
                out.append(line.split()[1].rstrip("/") + "/")
    # ...and the directory test as well, not instead: it still catches a tree
    # git cannot speak for at all, which is the state every synthetic corpus in
    # the falsification matrix is in. The two detectors cover different gaps,
    # so the answer is their union.
    if gm.is_file():
        for m in re.finditer(r"^\s*path\s*=\s*(\S+)",
                             gm.read_text(encoding="utf-8"), re.M):
            d = ROOT / m.group(1)
            if not d.is_dir() or not any(c.name != ".git" for c in d.iterdir()):
                out.append(m.group(1).rstrip("/") + "/")
    return tuple(dict.fromkeys(out))


_LENGTHS: dict[str, int] = {}


def resolve(path: str) -> int:
    """Lines in a cited file, or -1 if it genuinely does not exist.

    Refuses to answer for a path inside a submodule this tree cannot speak for,
    rather than calling it dead. The alternative — count it and carry on — was
    measured on this very PR: the baseline was taken in a worktree where
    external/miniupnp was not checked out, so a live citation read as rot and
    the figure shipped one too high. Counting it the other way is no better,
    because then a number that is supposed to mean one thing would mean "of what
    this checkout could see", and a genuinely dead submodule citation would pass
    locally and fail in CI — inverting this gate's premise that the local run is
    the mechanism and CI the backstop. So the run stops and says which command
    fixes it.

    The trust test runs BEFORE resolution, not only when the file is missing. A
    submodule sitting at the wrong commit still has the file; its line numbers
    are simply somebody else's, so the citation resolves and means nothing.
    Gating on `is_file()` could catch only the absent case, never that one.
    """
    if path not in _LENGTHS:
        for sm in untrusted_submodules():
            if path.startswith(sm):
                sys.exit(
                    f"FAIL: a live document cites {path}, which lies inside the "
                    f"submodule {sm.rstrip('/')} — and that submodule is either "
                    "not checked out here or sits at a commit other than the one "
                    "this tree records, so this run cannot tell a deleted file "
                    "from an absent one, nor a moved line from a stale one.\n"
                    f"       Run `git submodule update --init {sm.rstrip('/')}` "
                    "and re-run. This is a broken run, not a dirty tree: the "
                    "citation count is a ratchet, and a number measured against "
                    "files that are merely missing locally, or present at some "
                    "other commit, would disagree with CI by environment rather "
                    "than by fact.")
        # `..` never appears in a real citation, and `ROOT / path` would happily
        # resolve one outside the repository and report an unrelated host file
        # as a live citation. The token is not this gate's subject: it is not a
        # path into the tree at all.
        if ".." in pathlib.PurePosixPath(path).parts:
            _LENGTHS[path] = -1
            return _LENGTHS[path]
        f = ROOT / path
        if not f.is_file() and not path.startswith(ROOTS):
            f = ROOT / "rust" / path           # crate-relative citation
        _LENGTHS[path] = (len(f.read_text(encoding="utf-8", errors="replace")
                              .splitlines()) if f.is_file() else -1)
    return _LENGTHS[path]


def cite_fault(path: str, start: int, end: str | None, n: int) -> str | None:
    """Why this citation does not resolve, or None if it does.

    Line numbers are ONE-based, so `:0` is not a lenient citation but an
    impossible one — and rejecting only `want > n` accepted it silently at both
    call sites. Both endpoints are bounded, because a range is a claim about
    its whole span.
    """
    if n < 0:
        return "which does not exist"
    if start < 1:
        return f"but line numbers start at 1, so :{start} names nothing"
    if start > n:
        return f"but that file has {n} lines"
    if end is None:
        return None
    last = int(end)
    if last < start:
        return f"but that range ends ({last}) before it starts ({start})"
    if last > n:
        return f"but that file has {n} lines, so the range's end ({last}) is past it"
    return None


def check_citations(p, text, _arg, errs):
    seen = 0
    for m in CITE.finditer(text):
        seen += 1
        path, want = m.group(1), int(m.group(2))
        fault = cite_fault(path, want, m.group(3), resolve(path))
        if fault:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: cites {m.group(0)}, {fault}")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `citations` but makes none")
    return seen


def check_counts(p, text, _arg, errs):
    seen = 0
    for m in re.finditer(r"\*\*(\d+) (rows|sub-databases)\*\*", text):
        # Bounded to the claim's own neighbourhood. Scanning forward until the
        # first table found meant a claim whose table was DELETED bound to the
        # next unrelated one — possibly sections later — and passed whenever
        # that table's row count happened to match. A heading, or the next
        # count claim, ends the search: past either, any table belongs to
        # something else.
        rows, started = [], False
        for line in text[m.end():].splitlines():
            if line.startswith("|"):
                started = True
                if not re.match(r"^\|[\s:|-]+\|?\s*$", line):
                    rows.append(line)
            elif started:
                break
            elif line.startswith("#") or re.search(r"\*\*\d+ (rows|sub-databases)\*\*",
                                                   line):
                break
        if len(rows) < 2:
            # A claim with no table under it is the subject going missing, not
            # a claim that needs no checking. Skipping it meant a document with
            # one good table and one whose table was deleted passed on the
            # strength of the first.
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: states **{m.group(1)} {m.group(2)}** "
                        "but no table with data rows follows it — the subject "
                        "of this count is missing, which is a broken check")
            seen += 1
            continue
        seen += 1
        claimed, actual = int(m.group(1)), len(rows) - 1  # minus the header
        if claimed != actual:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: states **{claimed} {m.group(2)}** over a "
                        f"table of {actual} rows")
    if seen == 0:
        errs.append(f"{rel(p)}: declares `counts` but states no **N rows** figure "
                    "above a table")
    return seen


CHECKS = {"series": check_series, "range": check_range, "sections": check_sections,
          "numbered": check_numbered, "citations": check_citations,
          "counts": check_counts}


# Records-was surfaces: a round record or an archived plan states what was true
# when written, so a citation into a since-deleted file is history, not rot —
# its repair is to pin the sha, not to re-anchor. The ratchet counts live
# documents only.
# Directory components and exact filenames. A substring test classified any
# path merely CONTAINING one of these as historical, so `FOO_CHANGELOG.md` or a
# directory named `notcompleted/` would drop out of the ratchet and the range
# check — a live document could be excused from the gate by its name.
RECORDS_WAS_DIRS = ("completed", "audit_trail", "benchmarks")
RECORDS_WAS_FILES = ("CHANGELOG.md", "V3_WALLET_DECISION_LOG.md")
BASELINE = DOCS / "ci" / "doc-claims-baseline.txt"


def is_records_was(p: pathlib.Path) -> bool:
    parts = pathlib.PurePosixPath(rel(p)).parts
    return (any(d in parts[:-1] for d in RECORDS_WAS_DIRS)
            or parts[-1] in RECORDS_WAS_FILES)


def dead_citations(corpus) -> list[str]:
    """Every unresolvable `path:line` in a LIVE document."""
    out = []
    for p, text in corpus:
        if is_records_was(p):
            continue
        # Raw text, deliberately: citations are written INSIDE backticks by
        # convention (`src/foo.cpp:123`), so stripping inline code here hides
        # the very thing being counted — the first wiring of this ratchet
        # reported 1 dead citation against a measured 56 for exactly that
        # reason. strip_code() belongs on the DECLARATION scan, where a fenced
        # example must not opt a document in, and nowhere else.
        for m in CITE.finditer(text):
            path, want = m.group(1), int(m.group(2))
            if cite_fault(path, want, m.group(3), resolve(path)):
                out.append(f"{rel(p)}: {m.group(0)}")
    return out


def parse_baseline(text: str) -> tuple[int | None, dict[str, set[str]]]:
    """One parser, used for the working file and for the base revision.

    Both readers need the same two fields, and a second parser would be a
    second thing to keep in step — the duplication that this gate's own
    citation resolver had to have deleted rather than synchronised.
    """
    count, declares = None, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("dead-citations:"):
            count = int(line.split(":", 1)[1])
        elif line.startswith("declares:"):
            _, doc, legs = line.split(None, 2)
            declares[doc] = set(legs.split(","))
    return count, declares


def read_baseline() -> tuple[int, dict[str, set[str]]]:
    if not BASELINE.is_file():
        sys.exit(f"FAIL: {rel(BASELINE)} is missing — the ratchet this gate "
                 "enforces has no baseline, so nothing holds the count down. "
                 "That is a broken run, not a clean one.")
    count, declares = parse_baseline(BASELINE.read_text(encoding="utf-8"))
    if count is None:
        sys.exit(f"FAIL: {rel(BASELINE)} states no `dead-citations:` figure — "
                 "the ratchet cannot assert against a number that is not there")
    return count, declares


def base_baseline() -> tuple[int | None, dict[str, set[str]], str]:
    """The baseline recorded on the BASE revision, read via git.

    Without this the ratchet is honour-system: everything it asserts against
    lives in the same commit as the change being asserted, so one edit can add
    a dead citation and raise the figure to match, or drop a declaration and
    delete the line that recorded it, and the gate says green. A dial the
    caller can turn proves nothing about what it is supposed to hold. BOTH
    fields are read here for that reason — the count was the obvious half, and
    the registry has exactly the same shape of hole.

    Read from the base branch rather than a second copy, because two copies of
    a number drift and then one of them lies. When the ref cannot be resolved
    (no remote, shallow clone, or the file does not exist on the base yet, as
    on the change that introduces it) this returns None and the caller SAYS SO
    in its output rather than reporting a check it did not run.
    """
    ref = os.environ.get("DOC_CLAIMS_BASE_REF", "origin/dev")

    def git(*args):
        return subprocess.run(["git", "-C", str(ROOT), *args],
                              capture_output=True, text=True, timeout=30)

    try:
        resolves = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except (OSError, subprocess.SubprocessError) as e:      # pragma: no cover
        sys.exit(f"FAIL: git could not run ({e.__class__.__name__}), so the "
                 "base-revision ratchets cannot be evaluated. That is a broken "
                 "run, not a clean one.")
    # An UNRESOLVED ref is fatal. The two states this used to conflate are not
    # the same thing: a base that carries no baseline is the one-time bootstrap
    # of the change introducing the file, while a ref that does not resolve is
    # a missing prerequisite — and rule 47 says assert the prerequisite is
    # present rather than assume it. Left merged, the second would silently
    # disable BOTH base-backed ratchets and still exit zero.
    if resolves.returncode != 0:
        sys.exit(f"FAIL: the base ref {ref!r} does not resolve, so the ratchets "
                 "have nothing to compare against and would pass vacuously.\n"
                 "       Fetch it (`git fetch origin dev`) or point "
                 "DOC_CLAIMS_BASE_REF at a ref that exists. A ratchet with no "
                 "base is not a lenient ratchet, it is an absent one.")
    r = git("show", f"{ref}:{rel(BASELINE)}")
    if r.returncode != 0:
        # Bootstrap, and narrowly identifiable: the ref is good, the file is
        # simply not on it yet. True exactly once, for the change that adds it.
        return None, {}, f"{ref} carries no baseline yet (bootstrap)"
    count, declares = parse_baseline(r.stdout)
    if count is None:
        sys.exit(f"FAIL: the baseline on {ref} states no `dead-citations:` "
                 "figure. An established baseline that cannot be parsed is a "
                 "broken prerequisite, not a reason to skip the check.")
    return count, declares, ref


def main() -> None:
    files = sorted(p for p in DOCS.rglob("*.md") if p.is_file())
    if len(files) < MIN_DOCS:
        sys.exit(f"FAIL: found only {len(files)} markdown files under docs/ "
                 f"(floor {MIN_DOCS}) — the corpus this gate audits is missing or "
                 "mis-rooted. That is a broken run, not a clean tree.")
    corpus = [(p, p.read_text(encoding="utf-8")) for p in files]

    errors: list[str] = []
    tally: dict[str, int] = {}
    declarations = 0
    for p, text in corpus:
        stripped = strip_code(text)
        # Every marker that MEANS to be a declaration is a subject, including
        # the ones that are malformed. Checking only well-formed ones lets a
        # typo read as opted-in to a human and as absent to the gate.
        well_formed = {m.group(0) for m in DECL.finditer(stripped)}
        for m in DECL_ANY.finditer(stripped):
            if m.group(0) not in well_formed:
                line = stripped[: m.start()].count("\n") + 1
                errors.append(
                    f"{rel(p)}:{line}: malformed claim-audit marker "
                    f"{m.group(0)!r} — it reads as a declaration but matches no "
                    "known form, so it opts the document in to nothing. Kinds "
                    f"are lower-case ({', '.join(sorted(KINDS))}), with at most "
                    "one argument.")
        for m in DECL.finditer(stripped):
            kind, arg = m.group(1), m.group(2)
            if kind not in KINDS:
                errors.append(f"{rel(p)}: unknown claim-audit kind '{kind}' "
                              f"(known: {', '.join(sorted(KINDS))})")
                continue
            declarations += 1
            fn = CHECKS[kind]
            n = (fn(p, text, arg, errors, corpus) if kind == "range"
                 else fn(p, text, arg, errors))
            tally[kind] = tally.get(kind, 0) + n

    if declarations < MIN_DECLARATIONS:
        sys.exit(f"FAIL: {declarations} claim-audit declarations found in "
                 f"{len(files)} documents (floor {MIN_DECLARATIONS}) — either the "
                 "marker syntax has changed or the declarations were removed. An "
                 "audit with nothing to audit passes vacuously, so it fails here.")
    # ── ratchet ───────────────────────────────────────────────────────────
    baseline, must_declare = read_baseline()
    dead = dead_citations(corpus)
    if len(dead) > baseline:
        errors.append(
            f"dead citations in live documents rose to {len(dead)} against a "
            f"baseline of {baseline} — new rot:\n    "
            + "\n    ".join(dead[:12])
            + (f"\n    …and {len(dead) - 12} more" if len(dead) > 12 else ""))
    elif len(dead) < baseline:
        errors.append(
            f"dead citations in live documents fell to {len(dead)} from a "
            f"baseline of {baseline} — lower the `dead-citations:` figure in "
            f"{rel(BASELINE)} to {len(dead)} in this change. The ratchet "
            "tightens deliberately; a baseline left above the truth is slack "
            "the next regression hides in.")
    # Registry keyed on the FULL declaration, not its kind. Reducing
    # `series DRS-W` and `series R` to `series` meant one document holding both
    # could drop either and still satisfy the record — the registry would be
    # protecting a kind while the subject it was minted for walked away.
    base, base_declares, base_note = base_baseline()
    if base is not None and baseline > base:
        errors.append(
            f"the `dead-citations:` figure was RAISED from {base} to {baseline} "
            f"against {base_note}. The ratchet only tightens: a change that adds "
            "rot and lifts the bar to match is exactly what it exists to stop, "
            "and it would otherwise pass because the bar it asserts against "
            "travels in the same commit.")
    present = {rel(p): {decl_token(m.group(1), m.group(2))
                        for m in DECL.finditer(strip_code(t))}
               for p, t in corpus}
    for doc, legs in must_declare.items():
        if doc not in present:
            continue  # deleting the document is allowed; un-declaring is not
        dropped = sorted(legs - present[doc])
        if dropped:
            errors.append(
                f"{doc} has dropped the claim-audit declaration(s) {dropped}, "
                f"which {rel(BASELINE)} records it as holding. A document may "
                "add legs freely; removing one is an opt-out that has to be "
                "argued, not a silent edit.")
    # ...and the registry has to be COMPLETE, or the protection has a hole the
    # width of every leg added since it was written: a declaration that was
    # never registered can be removed later with nothing to notice. Adding a
    # leg therefore costs one line here, which is the same deliberate act the
    # rest of this file is built on.
    # ...and the registry LINE is itself base-checked, for the same reason the
    # count is. Dropping a declaration and deleting the token that recorded it
    # in one change satisfies both of the checks above — no drop, because the
    # candidate registry no longer claims the leg; no incompleteness, because
    # the document no longer declares it. The registry was the last reference
    # value the change under test could still edit.
    for doc, legs in sorted(base_declares.items()):
        if doc not in present:
            continue          # deleting the document takes its line with it
        shrunk = sorted(legs - must_declare.get(doc, set()))
        if shrunk:
            errors.append(
                f"the registry line for {doc} was SHRUNK against {base_note}: "
                f"{shrunk} no longer recorded. Un-declaring a leg and deleting "
                "the record of it in one change is the move this registry "
                "exists to catch, and it passes every check that reads only "
                "the tree in hand.")
    for doc, legs in sorted(present.items()):
        if not legs:
            continue
        missing = sorted(legs - must_declare.get(doc, set()))
        if missing:
            errors.append(
                f"{doc} declares {missing} but {rel(BASELINE)} does not record "
                f"it as holding them, so nothing would notice their removal. "
                f"Add to the baseline:\n    declares: {doc} "
                + ",".join(sorted(legs)))

    for n in NOTES:
        print(f"     Not checked: {n}")
    if errors:
        sys.exit(f"FAIL: {len(errors)} declared documentation claim(s) disagree "
                 "with what they describe:\n" + "\n".join("  " + e for e in errors))

    body = ", ".join(f"{tally[k]} {k}" for k in sorted(tally))
    print(f"OK: {declarations} declaration(s) across {len(files)} documents — "
          f"{body} — all consistent; dead citations in live documents at the "
          f"baseline of {baseline} (records-was surfaces excluded: a historical "
          f"citation is repaired by pinning its sha, not by re-anchoring).")
    print("     Scope: checks numeric and structural claims against source; "
          "does not check rationales.")
    # Said out loud, every run. A monotonicity check that quietly did not run
    # is indistinguishable from one that ran and passed, and this gate's whole
    # posture is that those two must never look alike.
    print("     Baseline monotonicity: "
          + (f"checked against {base_note} ({base})." if base is not None
             else f"NOT CHECKED HERE — {base_note}. CI resolves the base ref; "
                  "locally, `git fetch origin dev` enables it."))


if __name__ == "__main__":
    main()
