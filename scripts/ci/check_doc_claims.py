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
#     <!-- claim-audit: citations -->           rooted path:line cites resolve (scoped;
#                                               see docs/README.md for the roots and
#                                               extensions it recognises)
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
# WHAT A GREEN HERE IS NOT EVIDENCE FOR, second entry. Other gates read these
# same files and also go green — check_doc_links.py resolves relative links in
# docs/, for instance — and two instruments passing over one file are not two
# confirmations of one claim. Link RESOLUTION and citation LIVENESS are
# different properties: a document can have every internal link resolve while
# every `src/...:NNN` it cites points into deleted code, and the reverse. Do
# not cite a green run of another docs gate as corroboration of this baseline,
# or this one as corroboration of theirs.
#
# DEPTH SAFETY — this gate reads SINGLE REVISIONS, never history. Every git
# call it makes (`submodule status`, `rev-parse --verify`, `ls-tree`, `show`)
# answers a question about one named commit or the working tree, so it is
# correct in a shallow clone — which matters, because CI fetches the base with
# `--depth=1` deliberately: shallow is the NORMAL state here, not the broken
# one. Do not add `git log`, `rev-list`, a `-S` pickaxe or an ancestry walk
# without either dropping that or making the gate refuse to run when the
# repository is shallow. A one-commit history answers "no earlier version
# exists" for everything, and that reads as a clean negative rather than as a
# missing subject — a peer produced exactly that false negative on 2026-09-07
# while this repository was briefly shallow. The rule is enforced rather than
# trusted: check_doc_claims_falsification.py fails on any git subcommand
# outside the depth-safe allowlist.
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

# Anchored at line start with at most three leading spaces. Four or more is a
# CommonMark INDENTED CODE BLOCK, so a marker there is an example, not a
# declaration — and matching it opted a document into checks it never asked
# for. Requiring top-level placement is both the real convention ("put any of
# these near the top of the file") and far simpler than deciding, in general,
# whether an indented run is code or list continuation.
DECL = re.compile(r"<!--\s*claim-audit:\s*([a-z]+)"
                  r"(?:\s+([A-Za-z][\w-]*))?\s*-->")
# Every comment that MEANS to be a declaration, well-formed or not. A matcher
# that only sees valid markers cannot see a typo: `claim-audit: Citations` fails
# DECL's `[a-z]+`, matches nothing, and the document then looks opted in to a
# reader while no check runs against it — and the adoption floor stays satisfied
# by some other document, so nothing anywhere goes red. Absence of a match is
# first evidence the subject is malformed, not that it is absent (rule 47).
# No closing `-->` required. Demanding the terminator meant a truncated
# `<!-- claim-audit: citations` matched nothing and was silently ignored, while
# the adoption floor stayed satisfied by another document — the same vacuous
# pass this matcher exists to prevent, reached by leaving the marker unfinished
# instead of misspelling it.
# A marker is found ANYWHERE on a top-level line, not only at its start. The
# anchored version could not see a second marker on the same line at all, so
# `<!-- claim-audit: sections --><!-- claim-audit: Citations -->` reported
# neither the malformed second nor the missing declaration, and two VALID
# adjacent markers registered only the first — the silent opt-out this scan
# exists to prevent, reached by putting two markers on one line.
#
# The 0-3 space rule stays, but it now qualifies the LINE: four or more spaces
# is a CommonMark indented code block, and a marker there is an example.
TOP_LEVEL = re.compile(r"^ {0,3}\S")
MARKER = re.compile(r"<!--\s*claim-audit:.*?(?:-->|$)")


def markers(text: str):
    """(line number, marker text) for every claim-audit marker at top level."""
    for i, line in enumerate(text.splitlines(), 1):
        if TOP_LEVEL.match(line):
            for m in MARKER.finditer(line):
                yield i, m.group(0)


KINDS = {"series", "range", "sections", "numbered", "citations", "counts"}
# The only two kinds that name a subject; the rest are bare.
TAKES_ARG = {"series", "range"}

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
    """Repo-relative, POSIX-separated.

    `str(Path)` emits backslashes on Windows while the baseline's registry keys,
    the records-was directory names and every citation in the corpus are POSIX.
    On a Windows worktree the registry lookups would miss and `is_records_was`
    would stop recognising historical directories — the documented local command
    failing against a valid checkout.
    """
    return p.relative_to(ROOT).as_posix()


def decl_token(kind: str, arg: str | None) -> str:
    """`series DRS-W` -> "series:DRS-W"; `sections` -> "sections".

    The identity of a declaration is the pair, not the kind. One document here
    declares `series DRS-W` and `series R`, and a registry keyed on kind alone
    cannot tell which of the two it is holding.
    """
    return f"{kind}:{arg}" if arg else kind


def strip_code(text: str) -> str:
    """Blank out fenced and inline code, preserving line numbers.

    Handles both fence characters and arbitrary delimiter lengths, because
    CommonMark does: `~~~` opens a fence and a double-backtick span is a span.
    A marker surviving either would opt a document into checks it never asked
    for, and into the registry that then refuses to let it opt back out.

    Documenting the marker syntax must not opt a document in. This gate's own
    README section and CHANGELOG entry show the markers as examples, and the
    first version read them as declarations — so the documentation of a check
    became a subject of it. Newlines are preserved so every reported line
    number still points where a reader would look.
    """
    return strip_comments(_blank_spans(strip_fences(text)))


def strip_comments(text: str) -> str:
    """Blank ordinary HTML comments, preserving declarations and line numbers.

    Commented-out markdown is DISABLED markdown, and it was still feeding every
    structural leg: register rows left inside `<!-- ... -->` satisfied `series`
    after the rendered register was deleted — a vacuous green built out of text
    no reader can see. Declarations are themselves HTML comments, so they are
    the one form preserved.
    """
    def repl(m):
        body = m.group(0)
        return body if MARKER.search(body) else "\n" * body.count("\n")
    return re.sub(r"<!--.*?-->", repl, text, flags=re.S)


def strip_fences(text: str) -> str:
    """Blank fenced blocks only, preserving line numbers and inline code.

    Separate from strip_code because the two callers need different things: a
    DECLARATION must not be readable inside any code form, while a CITATION is
    written inside backticks by convention and would vanish if inline spans
    were stripped from the text the citation leg reads.
    """
    out, fence = [], None       # fence = (char, length, quote depth) while open
    for raw in text.splitlines():
        # The block-quote container is a DEPTH, not a string. Comparing raw
        # prefixes made `>` and `> ` different containers, so a closer written
        # either way never closed its fence; and nothing ended a fence when its
        # container did, so an unclosed `> ```text` blanked the rest of the
        # document. Both blanked declarations SILENTLY — the document simply
        # stopped being audited with nothing to say so, which is the direction
        # no other check here can see.
        #
        # Depth settles all four container shapes with one rule: equal depth is
        # the same container, greater depth is content nested inside it, and
        # LESS depth means the container closed and takes any open fence with
        # it. CommonMark models block quotes exactly this way.
        pre = re.match(r"(?:\s*>)+\s?", raw)
        prefix = pre.group(0) if pre else ""
        depth = prefix.count(">")
        line = raw[len(prefix):]
        if fence is not None:
            if depth < fence[2]:
                fence = None              # the container ended; so does the fence
            elif depth > fence[2]:
                out.append("")            # nested deeper: still fence content
                continue
        # 0-3 spaces: at four the line is indented code, not a fence. `\s*`
        # let a deeply indented ``` inside a list item open a fence and blank
        # the remainder of the document.
        m = re.match(r" {0,3}(`{3,}|~{3,})(.*)$", line)
        if m:
            ch, n, tail = m.group(1)[0], len(m.group(1)), m.group(2)
            if fence is None:
                # CommonMark forbids a backtick in the info string of a
                # BACKTICK fence, so ```lang`x is not a fence at all. Opening
                # one anyway blanked everything to EOF or the next fence and
                # silently swallowed any declaration in between.
                if ch == "`" and "`" in tail:
                    out.append(raw)
                    continue
                fence = (ch, n, depth)
                out.append("")
                continue
            # A CLOSING fence carries its delimiter and nothing else.
            if ch == fence[0] and n >= fence[1] and not tail.strip():
                fence = None
                out.append("")
                continue
        out.append("" if fence is not None else raw)
    return "\n".join(out)


def _blank_spans(text: str) -> str:
    """Blank inline code spans, INCLUDING those that cross line breaks.

    CommonMark code spans may span lines, and a per-line pass leaves a marker
    written inside one visible. Newlines inside a span are preserved so every
    reported line number still points where a reader would look.
    """
    # Exact-length runs on both sides. `(`+)(.+?)\1` let a two-backtick span
    # "close" on the first two of a three-backtick run, blanking through it and
    # dropping any declaration in between. The lookarounds require the opening
    # run to be whole and the closing run to be neither preceded nor followed
    # by another backtick, which is CommonMark's rule.
    return re.sub(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)",
                  lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)


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
    pat = (r"§(\d+[a-z]?(?:\.\d+)?)(?!\d)(?!\.\d)" if dotted_local
           else r"§(\d+[a-z]?)(?!\d)(?!\.\d)")
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
    falls under the run floor and is discarded. The declaring document
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
    two-item fragment under the old three-item floor and passed the remainder.
    The floor is two now, for the same reason: a two-item list is a list, and
    `1.` followed by `3.` beside an already-valid long list was unchecked.
    """
    runs: dict[int, list[tuple[int, int]]] = {}
    out: list[list[tuple[int, int]]] = []

    def close(pred) -> None:
        for d in sorted([d for d in runs if pred(d)], reverse=True):
            r = runs.pop(d)
            if len(r) >= 1:
                out.append(r)

    for i, raw in enumerate(text.splitlines(), 1):
        # Block-quote prefixes are containers here too. Matching digits at the
        # start of the RAW line skipped every quoted ordered list, and this
        # corpus uses them (docs/WALLET_PREFS.md:77-83 is a 1./2./3. list inside
        # a quote) — so the leg promised to check numbered lists while a whole
        # container class was invisible to it.
        line = re.sub(r"^(?:\s*>)+\s?", "", raw)
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
        errs.append(f"{rel(p)}: declares `numbered` but the document contains "
                    "no numbered item at all")
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
            parts = line.split()
            if len(parts) < 2:
                continue
            if line[:1] in ("-", "+", "U"):
                out.append(parts[1].rstrip("/") + "/")
                continue
            # A leading SPACE means "HEAD matches the gitlink" and NOTHING
            # about the worktree: `git submodule status` reports clean for a
            # submodule with modified tracked files, verified directly. Since
            # resolve() reads that worktree, a dirty submodule would resolve
            # citations against content the superproject does not record — the
            # local-vs-CI disagreement this whole guard exists to prevent,
            # reached from the one direction the commit check cannot see.
            d = ROOT / parts[1]
            try:
                dirty = subprocess.run(
                    ["git", "-C", str(d), "status", "--porcelain"],
                    capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.SubprocessError):    # pragma: no cover
                out.append(parts[1].rstrip("/") + "/")
                continue
            if dirty.returncode != 0 or dirty.stdout.strip():
                out.append(parts[1].rstrip("/") + "/")
    # `status --porcelain` omits IGNORED files, so a citation into a generated
    # artifact inside a submodule resolves locally and vanishes in a clean CI
    # checkout. The fix is NOT `--ignored`: that would call every submodule
    # dirty for anyone who has built the project, which is a false red on
    # ordinary work. The precise question is whether the CITED FILE is tracked,
    # and resolve() asks it per path rather than condemning the whole submodule.
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


@functools.cache
def _submodule_paths() -> tuple[str, ...]:
    gm = ROOT / ".gitmodules"
    if not gm.is_file():
        return ()
    return tuple(m.group(1).rstrip("/") + "/" for m in
                 re.finditer(r"^\s*path\s*=\s*(\S+)",
                             gm.read_text(encoding="utf-8"), re.M))


def _submodule_of(path: str) -> str | None:
    return next((s for s in _submodule_paths() if path.startswith(s)), None)


@functools.cache
def _tracked_in(sub: str, path: str) -> bool:
    """Is this file tracked by the submodule, or merely sitting in it?

    An IGNORED build artifact is present locally and absent from a clean CI
    checkout, so a citation into one resolves here and dies there — the
    environment disagreement this whole guard exists to prevent, arriving
    through the one door `status --porcelain` does not report.
    """
    d = ROOT / sub.rstrip("/")
    # Only ask a real submodule CHECKOUT. Without its own `.git` the directory
    # is not a submodule in this tree at all, and `-C` would run the query in
    # the SUPERPROJECT with the pathspec resolved relative to that directory —
    # answering a different question and condemning paths git has no submodule
    # opinion about. The uninitialised and dirty checks already own that state.
    if not (d / ".git").exists():
        return True
    try:
        r = subprocess.run(["git", "-C", str(d),
                            "ls-files", "--error-unmatch",
                            path[len(sub):]],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):           # pragma: no cover
        return True                 # cannot tell; the dirty check already ran
    # `ls-files --error-unmatch` exits 1 for a file git knows nothing about and
    # 128 when it cannot answer at all (the path is not a repository). Only the
    # first is evidence of an untracked file; treating the second as untracked
    # condemned every citation in a directory git has no opinion about, which
    # is a different claim entirely.
    return r.returncode != 1


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
                s = sm.rstrip("/")
                sys.exit(
                    f"FAIL: a live document cites {path}, which lies inside the "
                    f"submodule {s}, and this tree cannot vouch for that "
                    "submodule's content. One of three things is true:\n"
                    "         - it is not checked out here, or\n"
                    "         - it sits at a commit other than the one this "
                    "tree records, or\n"
                    "         - its worktree has local modifications or "
                    "untracked files.\n"
                    f"       For the first two: `git submodule update --init {s}`.\n"
                    "       For the third, that command will NOT help and is not "
                    "meant to — commit, stash or restore the changes inside "
                    f"{s} first, and nothing here will discard them for you.\n"
                    "       Either way this is a broken run rather than a "
                    "finding: the citation count is a ratchet, and a number "
                    "measured against content this tree does not record would "
                    "disagree with CI by environment rather than by fact.")
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
        if f.is_file():
            sub = _submodule_of(path)
            if sub and not _tracked_in(sub, path):
                _LENGTHS[path] = -1            # present locally, not recorded
                return _LENGTHS[path]
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
        # A markdown table is a header, a DELIMITER row, then data. Counting
        # pipe-prefixed lines without requiring the delimiter meant deleting it
        # left the header and every data line still counted: `len(rows) - 1`
        # was unchanged and the figure still matched, so the check passed over
        # a table that no longer existed as a table.
        rows, started, delim = [], False, False
        for line in text[m.end():].splitlines():
            if line.startswith("|"):
                if re.match(r"^\|[\s:|-]+\|?\s*$", line):
                    if len(rows) == 1:      # immediately after the header
                        delim = True
                    started = True
                    continue
                started = True
                rows.append(line)
            elif started:
                break
            elif line.startswith("#") or re.search(r"\*\*\d+ (rows|sub-databases)\*\*",
                                                   line):
                break
        if rows and not delim:
            line = text[: m.start()].count("\n") + 1
            errs.append(f"{rel(p)}:{line}: states **{m.group(1)} {m.group(2)}** "
                        "over pipe-prefixed lines with no delimiter row — that "
                        "is not a markdown table, so the subject of this count "
                        "does not exist as one")
            seen += 1
            continue
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
        # FENCE-STRIPPED, with inline spans intact. Both halves matter: a
        # citation is written INSIDE backticks by convention, so blanking
        # inline code would hide the very thing being counted (the first
        # wiring of this ratchet reported 1 against a measured 56 for exactly
        # that reason) — while a citation written in a fenced EXAMPLE is not a
        # claim this document makes, and counting it would inflate the
        # baseline and fail edits that never touched a real citation.
        # strip_fences() gives precisely that pair; strip_code() belongs on
        # the DECLARATION scan alone.
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
    a number drift and then one of them lies.

    THREE outcomes, deliberately distinct — conflating any two of them is how
    this function has been wrong twice already:

    - the ref does not resolve, or the baseline exists but cannot be read or
      parsed -> FATAL. A missing prerequisite is not a lenient check.
    - the ref resolves and the path is positively absent on it -> returns None,
      the bootstrap, true exactly once for the change that adds the file. The
      caller prints that state rather than implying a comparison happened.
    - otherwise -> the base figures, and the comparison runs.
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
    # Absence is established SEPARATELY from reading. Treating every `git show`
    # failure as bootstrap meant an unavailable object, a corrupt pack or a
    # timeout all disabled both base-backed ratchets on a zero exit while
    # reporting "no baseline yet" — a read failure wearing absence's name.
    listed = git("ls-tree", "--name-only", ref, rel(BASELINE))
    if listed.returncode != 0:
        sys.exit(f"FAIL: could not list {rel(BASELINE)} on {ref}, so this run "
                 "cannot tell whether the baseline is absent or merely "
                 "unreadable. Both ratchets depend on that answer, and a read "
                 "failure is not a bootstrap.")
    if not listed.stdout.strip():
        # Bootstrap, and now positively established: the ref is good and the
        # path genuinely does not exist on it. True exactly once, for the
        # change that adds the file.
        return None, {}, f"{ref} carries no baseline yet (bootstrap)"
    r = git("show", f"{ref}:{rel(BASELINE)}")
    if r.returncode != 0:
        sys.exit(f"FAIL: {rel(BASELINE)} exists on {ref} but could not be read "
                 f"({r.stderr.strip()[:200]}). An unreadable baseline is a "
                 "broken prerequisite, not an absent one.")
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
    # Structural legs read the corpus with FENCES BLANKED. Only declaration
    # discovery was stripped before, so every structural checker was reading
    # raw markdown and treating examples as document structure: a fenced
    # `1.`/`3.` snippet failed the `numbered` leg, fenced register rows could
    # satisfy or corrupt a `series` check, and a fenced range read as a live
    # restatement. An example of a defect is not a defect.
    #
    # Inline spans survive here on purpose. Citations are written inside
    # backticks by convention, so the citation leg keeps the RAW text — the
    # same split that made strip_code and strip_fences two functions.
    # Citations: fences and COMMENTS blanked, inline spans kept — a citation is
    # written inside backticks, and a citation inside `<!-- -->` is disabled
    # markdown like any other. Blanking comments only inside strip_code() left
    # the citation leg and the ratchet reading commented-out cites as live.
    fenced = {p: strip_comments(strip_fences(text)) for p, text in corpus}
    coded = {p: strip_code(text) for p, text in corpus}          # everything else
    corpus_fenced = [(p, fenced[p]) for p, _ in corpus]         # range restatements

    errors: list[str] = []
    tally: dict[str, int] = {}
    declarations = 0
    for p, text in corpus:
        stripped = strip_code(text)
        # Every marker that MEANS to be a declaration is a subject, including
        # the ones that are malformed. Checking only well-formed ones lets a
        # typo read as opted-in to a human and as absent to the gate.
        for line, text_of in markers(stripped):
            if not DECL.fullmatch(text_of):
                errors.append(
                    f"{rel(p)}:{line}: malformed claim-audit marker "
                    f"{text_of!r} — it reads as a declaration but matches no "
                    "known form, so it opts the document in to nothing. Kinds "
                    f"are lower-case ({', '.join(sorted(KINDS))}), with at most "
                    "one argument.")
                continue
            m = DECL.fullmatch(text_of)
            kind, arg = m.group(1), m.group(2)
            if kind not in KINDS:
                errors.append(f"{rel(p)}: unknown claim-audit kind '{kind}' "
                              f"(known: {', '.join(sorted(KINDS))})")
                continue
            # Arity. The grammar allowed an argument on every kind while only
            # two read one, so `claim-audit: citations typo` parsed clean and
            # registered as a DISTINCT declaration — a typo surviving the very
            # check added to catch typos, and then entrenched in the registry.
            if arg and kind not in TAKES_ARG:
                errors.append(f"{rel(p)}: `claim-audit: {kind}` takes no "
                              f"argument, but carries '{arg}'. Only "
                              f"{' and '.join(sorted(TAKES_ARG))} are "
                              "prefixed; anything else is a typo that would "
                              "otherwise register as its own declaration.")
                continue
            declarations += 1
            fn = CHECKS[kind]
            # Structural legs read FULLY code-stripped text, because a
            # document explaining a literal `§99` was failing the sections leg
            # for describing the syntax it documents — the same
            # documenting-it-declares-it bug, one layer down.
            #
            # TWO legs keep inline spans, and both were checked rather than
            # assumed. `citations` obviously: a citation IS written inside
            # backticks. `range` less obviously — IMPLEMENTATION_INDEX.md
            # states the register's extent as **`DRS-W1…DRS-W11`**, a real
            # claim that happens to be typeset as code. Stripping inline spans
            # for that leg silently dropped the identifier map from its
            # subject set: 4 restatements checked became 3, on the surface most
            # likely to go stale. A uniform rule would have been tidier and
            # would have cost coverage where it matters most.
            body = fenced[p] if kind in ("citations", "range") else coded[p]
            n = (fn(p, body, arg, errors, corpus_fenced) if kind == "range"
                 else fn(p, body, arg, errors))
            tally[kind] = tally.get(kind, 0) + n

    if declarations < MIN_DECLARATIONS:
        sys.exit(f"FAIL: {declarations} claim-audit declarations found in "
                 f"{len(files)} documents (floor {MIN_DECLARATIONS}) — either the "
                 "marker syntax has changed or the declarations were removed. An "
                 "audit with nothing to audit passes vacuously, so it fails here.")
    # ── ratchet ───────────────────────────────────────────────────────────
    baseline, must_declare = read_baseline()
    dead = dead_citations([(p, fenced[p]) for p, _ in corpus])
    if len(dead) > baseline:
        errors.append(
            f"dead citations in live documents rose to {len(dead)} against a "
            f"baseline of {baseline}. This run reads one tree, so it cannot "
            "say WHICH of these is the new one — the list below is the "
            "COMPLETE current set, not a delta, and the citation this change "
            "broke is somewhere in it:\n    "
            + "\n    ".join(dead)
            + "\n       (Labelled precisely because the earlier wording said "
              "'new rot' over the first twelve entries of the whole set: with "
              "a baseline in the fifties the newly broken citation usually "
              "sorts outside that window, so the message named pre-existing "
              "debt and never the defect that triggered it.)")
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
    present = {rel(p): {decl_token(*DECL.fullmatch(txt).groups())
                        for _, txt in markers(strip_code(t))
                        if DECL.fullmatch(txt)}
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
            # Deleting a document takes its registry line with it, and that is
            # legitimate. But a RENAME looks identical from one tree: move an
            # adopted document, strip its markers, drop its registry line, and
            # every check here passes while the declarations simply cease. This
            # run cannot tell those apart — rename detection needs git's
            # similarity index across two trees, which is follow-up work — so
            # it refuses to be silent about the event instead of pretending to
            # have judged it. The tokens that stopped being audited are named,
            # which is what a reviewer needs to tell deletion from evasion.
            orphaned = sorted(legs - {tok for toks in present.values()
                                      for tok in toks})
            if orphaned:
                NOTES.append(
                    f"{doc} was registered on {base_note} and is absent here, "
                    f"and no document declares {orphaned} any more. If it was "
                    "DELETED that is expected; if it was RENAMED the "
                    "declarations must move with it.")
            continue
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
