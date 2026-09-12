#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Code-citation resolver gate for the pinned review documents.
#
# The register documents cite code as evidence: a path, sometimes a symbol,
# usually a line range. Those citations are what later work grounds on, and
# an unresolvable one turns a grounded claim into an unverifiable one. This
# gate resolves each citation and FATALs when it resolves to zero files or to
# many.
#
# THE CENTRAL RULE, and the reason this gate is not a link checker:
# RESOLVE AT THE ERA THE DOCUMENT DECLARES, NEVER AT HEAD BY DEFAULT.
# A pinned citation is a *records-was* statement -- true at its sha and not
# required to be true now. Resolving those against HEAD fails correctly
# written rows and teaches authors to re-anchor pinned records, which is the
# opposite of what the pin is for. The failure is not hypothetical: C0 renames
# `shekyl_archival_debit_auth_pin` -> `shekyl_archival_cold_authority_pin`, so
# every row citing the old name is correct at its pin and resolves to nothing
# at HEAD. Moving from line numbers to symbols does not escape the pin
# problem; it only makes the failure louder.
#
# ERA SELECTION, most specific wins:
#   1. an inline `at `<sha>`` on the citation's own line (row-level override).
#      ONLY that spelling. The atomicity audit writes one as "against *its own*
#      pin (`<sha>`)", which is NOT parsed and falls back to the section era --
#      stated here rather than quietly widened, because accepting spellings on
#      sight is how a wrong-era resolution gets in. Note the residue: an
#      unparsed row pin inside a TABLE ROW is not caught by the section refusal
#      either, since that refusal ignores table rows by design. Pin a row with
#      `at `<sha>`` or pin its section.
#   2. the pin governing the enclosing section -- `Reviewed at **`<sha>`**` or
#      a table header `(all at `<sha>`)`. A pin's scope ENDS at the next
#      heading of the same or shallower level. Without that bound the §5.4.1
#      slice pin leaks into the decision log, where a dated ledger row cites a
#      file that did not exist yet -- measured, one false FATAL.
#   3. no pin in scope -> HEAD. An unpinned citation is an *asserts-is* claim
#      about current code, so HEAD is its era. This is deliberate rather than
#      a skip: skipping unpinned citations would let a document with no pins
#      at all pass in silence.
#
# AND THE CASE THAT RULE 3 WOULD OTHERWISE SWALLOW: a section that TRIES to
# declare an era in a spelling this parser does not recognise falls through to
# HEAD on every row beneath it -- silently resolving *records-was* citations
# against current code, which is precisely the failure this gate exists to
# prevent, now wearing a green tick.
#
# THE CHECK IS PER SECTION, NOT PER DOCUMENT. A document-level "are there any
# parseable pins?" test is satisfied by the document's OTHER slices and never
# fires, so one unbolded slice heading in an otherwise well-pinned register
# passes in silence. That shipped in the first version of this gate and was
# caught empirically by a lane whose sixteen rows all resolved at HEAD while
# the gate reported them green "at their declared eras". Worse, the unbolded
# pin line itself matches the inline form, so that ONE line resolves correctly
# while every row under it does not.
#
# A section is flagged when BOTH hold:
#   - it contains an era-declaration ATTEMPT: a `<sha>`-shaped token on a prose
#     line (not a table row, and not a line that carries a citation itself);
#   - and citations inside it fell back to HEAD.
# Row-level shas live in table cells and are excluded, so a dated ledger whose
# rows carry their own provenance is not flagged. Measured against the live
# register: zero false positives.
#
# This subsumes the whole-document case. `docs/LMDB_WRITE_ATOMICITY_AUDIT.md`
# pins by ROW-SET in front matter (`` `dev` `<sha>` `` for DRS-W1..W11, another
# for W12..W15, a third for the regrade) and says its line citations are
# records-was; every one of its sections is flagged. Supporting that token form
# without its row-set scoping would be worse than refusing -- it would pin
# every row to whichever sha happened to be declared last.
#
# Deliberately NOT done: accepting the unbolded spelling. Silently accepting
# more spellings is how the row-set token would have got in. Refuse, and name
# the exact form the author should use.
#
# WHAT COUNTS AS A CITATION, deliberately narrow so the gate cannot cry wolf
# and get deleted (this repo has lost gates that way):
#   - a backticked token shaped `[dir/]*name.ext[:range]`, ext in SOURCE_EXTS;
#   - a path matches a tracked file when it equals it or is a PATH SUFFIX of
#     it. The documents cite `cryptonote_core/blockchain.cpp`, not the full
#     `src/cryptonote_core/blockchain.cpp`, and requiring full paths would
#     FATAL most of the corpus to buy nothing.
#   - prose, ranges without a file, and directory-only tokens are out of scope.
#
# WHY A BARE BASENAME IS ALLOWED: it is not ambiguity if it resolves uniquely.
# Demanding directory-qualified paths document-wide would FATAL every
# `blockchain.cpp:NNNN` row -- and `blockchain.cpp` is unique, so the demand
# buys nothing. The defect is a basename matching MANY tracked files, which is
# the "one hit in the wrong file" class: `cryptonote_format_utils.cpp` matches
# both `src/cryptonote_basic/` and `tests/unit_tests/` at the pin and at HEAD.
#
# SYMBOL + RANGE (walk-legend lines only). Where a legend entry names a symbol
# AND a file range, the range must be contained in exactly one BODY-BEARING
# definition of that symbol at the era. Containment IS the resolution:
#   - it disambiguates real overloads -- `check_tx_inputs` has two definitions
#     at the pin, [3310,3328] and [3499,4419], and the cited 3536-3740 sits in
#     exactly one;
#   - a bare declaration carries no body, so the declaration+definition pair
#     that is normal in headers collapses to one definition by construction,
#     with no special case to maintain;
#   - and it accommodates SUB-BLOCK ranges. The walks W-TI, W-EM and W-BP are
#     all sub-blocks inside a ~900-line `check_tx_inputs`, so the tempting
#     rule "the symbol sits at the head of the cited range" would FATAL three
#     correct rows.
#   No range plus more than one definition is a FATAL that says "add a range".
#
# RULE 47 -- the gate asserts its own subject:
#   - a listed document that yields ZERO citations is a FATAL, not a pass.
#     That is the regex-stopped-matching failure, and it is the one that
#     reports "no bad citations" on a reformatted document;
#   - an unreachable pin is a FATAL, not a skip. CI's default checkout is
#     depth 1, where `git show <old-sha>:path` simply fails; a gate that
#     treated that as "nothing to check" would pass vacuously on every PR.
#
# Rule 46: the verdict never travels through a pipe. Every git call is
# subprocess.run(check=False) with its returncode read explicitly, and the
# exit status is set by sys.exit() here.
#
# Run: `python3 scripts/ci/check_doc_code_citations.py [--docs a.md,b.md]`
# Exit 0 = every citation resolved uniquely at its declared era.

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Documents whose code citations are load-bearing evidence. A document listed
# here must produce citations; see the rule-47 note above.
DEFAULT_DOCS = ("docs/design/CONSENSUS_STORE_RECONCILIATION.md",)

# Documents whose citations are load-bearing but which this gate does not check
# yet, each with the blocker that keeps it out. This is NOT an allowlist of
# known failures -- a gate that quietly excludes what it cannot pass cannot
# fail. The deferral is held open by a named cause and CANNOT OUTLIVE IT: the
# gate FATALs if a deferred document would now pass, which forces it back into
# the checked set the moment its blocker is gone.
DEFERRED_DOCS = {
    "docs/LMDB_WRITE_ATOMICITY_AUDIT.md": (
        "declares its eras by ROW-SET in front matter (`dev` `<sha>` for "
        "DRS-W1..W11, another for W12..W15, a third for the 2026-09-09 regrade) "
        "and states its line citations are records-was. Teaching this parser "
        "that token form WITHOUT its row-set scoping would pin every row to "
        "whichever sha was declared last -- a silent wrong-era resolution, "
        "worse than refusing. How the document declares eras is an editorial "
        "decision owned by its authors, not this gate."
    ),
}

SOURCE_EXTS = ("cpp", "h", "hpp", "c", "cc", "rs", "py", "sh")

HEADING_RE = re.compile(r"^(#{1,6}) ")
SECTION_PIN_RE = re.compile(
    r"Reviewed at \*\*`([0-9a-f]{7,40})`\*\*" r"|\(all at `([0-9a-f]{7,40})`\)"
)
INLINE_PIN_RE = re.compile(r"\bat `([0-9a-f]{7,40})`")
# `path/to/file.ext` or `file.ext:123-456`; the range is captured but the
# en-dash, em-dash, `+` and plain `-` forms all appear in the corpus.
CITATION_RE = re.compile(
    r"`([A-Za-z0-9_./-]+\.(?:" + "|".join(SOURCE_EXTS) + r"))"
    r"(?::(\d+)(?:[–—-](\d+))?\+?)?`"
)
# A walk legend entry. The register writes BOTH `**W-TI**` and `**Walk W-BP**`,
# and its legends WRAP across lines -- the marker sits on one line while the
# symbol and range it introduces sit on the next. So containment is checked
# over the legend BLOCK (a blank-line-delimited paragraph), never per line: a
# per-line check silently ran on 3 citations in the whole register and never
# once on W-TI, the overload case the rule exists for.
WALK_MARKER_RE = re.compile(r"\*\*(?:Walk\s+)?(W-[A-Z]{2})\*\*")
SYMBOL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)`")

HEAD = "HEAD"

# Any `<sha>`-shaped token, used only to detect era declarations this parser
# did not understand -- never to resolve with.
ANY_SHA_RE = re.compile(r"`([0-9a-f]{7,40})`")

# Spellings authors actually use to declare an era, which this gate does NOT
# parse. Matching them is how an unparsed declaration is told apart from prose
# that merely mentions a revision -- the register's front matter and its §5
# narrative both cite shas mid-sentence as provenance, and neither is
# declaring an era for the rows beneath it.
#
#   1. the slice convention, anchored at LINE START: a real pin opens its line
#      ("Reviewed at **`<sha>`** (2026-09-02). Walks: ..."). A sha buried
#      mid-paragraph is provenance, not a declaration.
#   2. the branch-and-sha idiom (`` `dev` `<sha>` ``) used by the atomicity
#      audit's row-set pins.
PIN_INTENT_RES = (
    re.compile(r"^\*{0,2}(?:Re-?)?[Rr]eviewed at\b"),
    re.compile(r"`dev`\s*`[0-9a-f]{7,40}`"),
)


class Era:
    """Tracked-file listing for one revision, cached; None when unreachable."""

    _cache: dict = {}

    @classmethod
    def files(cls, rev):
        if rev not in cls._cache:
            proc = subprocess.run(
                ["git", "-C", ROOT, "ls-tree", "-r", "--name-only", rev],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                cls._cache[rev] = None
            else:
                cls._cache[rev] = [p for p in proc.stdout.split("\n") if p]
        return cls._cache[rev]

    @classmethod
    def blob(cls, rev, path):
        proc = subprocess.run(
            ["git", "-C", ROOT, "show", f"{rev}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return None if proc.returncode != 0 else proc.stdout.split("\n")


def resolve_path(token, tracked):
    """Tracked files the citation names: exact match or path suffix."""
    return [p for p in tracked if p == token or p.endswith("/" + token)]


def definition_extents(lines, symbol):
    """[(start, end)] 1-based inclusive spans of BODY-BEARING definitions.

    A definition is a line that mentions the symbol followed by `(`, is not a
    continuation or a call inside a deeper scope (column-0 start), and whose
    brace balance actually opens a body. A bare declaration ends in `;` before
    any `{` and is therefore not returned -- which is how the header
    declaration+definition pair collapses to one without a special case.
    """
    bare = symbol.split("::")[-1]
    # Anchored on a non-identifier character: a plain substring search for
    # `validate_miner_transaction(` also matches inside
    # `prevalidate_miner_transaction(`, which reported two definitions where
    # the file has one of each and turned a correct walk into a FATAL.
    call = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(bare) + r"\s*\(")
    out = []
    for i, line in enumerate(lines):
        if line[:1] in (" ", "\t", "", "#", "/"):
            continue
        if not call.search(line):
            continue
        depth = 0
        opened = False
        # Scan to end of file, never a fixed window. A 400-line cap silently
        # dropped `check_tx_inputs` -- ~920 lines, and the very function this
        # gate exists to disambiguate -- leaving one extent where there are
        # two. The containment check then had nothing to disambiguate and its
        # passing test passed vacuously.
        for j in range(i, len(lines)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        out.append((i + 1, j + 1))
                        break
            if opened and depth == 0:
                break
            if not opened and lines[j].rstrip().endswith(";"):
                break  # declaration, no body
    return out


def eras_for_lines(lines):
    """Era governing each 1-based line: inline override, else the innermost
    enclosing section pin, else HEAD.

    Pins NEST, so they are held on a stack. A single pin plus a level was
    wrong in a way the live register does not currently exercise but which is
    a wrong-era resolution waiting to happen: with a pinned `####` parent, a
    pinned `#####` slice, and a SECOND `#####` slice that pins nothing, the
    single-pin form cleared the child's pin at the sibling heading and left
    nothing behind -- so the sibling fell to HEAD instead of inheriting its
    parent's era. Records-was citations resolved against current code, which
    is the whole defect this gate exists to prevent, sitting in its parser.

    A stack restores the enclosing pin instead of dropping to HEAD. Popping on
    `level >= section_level` is what makes a sibling close its predecessor
    while a deeper heading does not.
    """
    eras = {}
    stack = []  # (section_level, sha), innermost last
    section_level = 99
    for i, line in enumerate(lines, 1):
        heading = HEADING_RE.match(line)
        if heading:
            section_level = len(heading.group(1))
            while stack and stack[-1][0] >= section_level:
                stack.pop()
        found = SECTION_PIN_RE.search(line)
        if found:
            while stack and stack[-1][0] >= section_level:
                stack.pop()
            stack.append((section_level, found.group(1) or found.group(2)))
        inline = INLINE_PIN_RE.search(line)
        eras[i] = inline.group(1) if inline else (stack[-1][1] if stack else HEAD)
    return eras


def section_spans(lines):
    """Every heading's span, properly NESTED: a section runs to the next
    same-or-shallower heading, so a `#####` slice lies INSIDE its `####`
    parent.

    This is the document's one notion of scope. Era selection already nested
    this way while the unparsed-era check treated every heading as a fresh
    section, so a pin declared on a parent never shared a section with the
    citations under its children -- two instruments over one document with
    different grammars and nothing comparing them.
    """
    heads = []
    for lineno, line in enumerate(lines, 1):
        match = HEADING_RE.match(line)
        if match:
            heads.append(
                [len(match.group(1)), line.strip("# ").strip()[:60], lineno, len(lines)]
            )
    for i, head in enumerate(heads):
        for later in heads[i + 1:]:
            if later[0] <= head[0]:
                head[3] = later[2] - 1
                break
    front = [0, "(front matter)", 1, (heads[0][2] - 1 if heads else len(lines))]
    return [tuple(h) for h in ([front] + heads)]


def unparsed_era_sections(lines, eras):
    """Era declarations this parser did not understand, whose citations
    therefore resolve at a revision the document does not claim.

    THE SCOPE QUESTION IS ASKED OF THE PARSER, NOT RE-IMPLEMENTED HERE. For
    each refused declaration the line is rewritten into the form the parser
    accepts, eras are recomputed, and the two maps are diffed: the citations
    that would resolve differently ARE the affected ones, by definition.

    That is not a shortcut, it is the fix for a recurring defect. Three
    findings on this gate came from the refusal keeping its own notion of
    scope beside `eras_for_lines`' notion -- they agreed until they didn't.
    Every rule the parser has comes along for free here and cannot drift:

      - an inline `at `<sha>`` row pin wins in BOTH maps, so no diff, so the
        row is correctly not attributed to the section;
      - a NESTED section with its own parsed pin likewise wins in both, so a
        child slice that pins itself is untouched by an unparsed parent;
      - a nested section WITHOUT a pin does differ, and is correctly affected;
      - scope ends at the next same-or-shallower heading because that is what
        the parser does, not because this function remembers to.

    And where the refused declaration names the sha the section would have
    inherited anyway, the two maps are identical: no diff, no finding, because
    no resolution changes.
    """
    flagged = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if (
            stripped.startswith("|")
            or HEADING_RE.match(line)
            or not ANY_SHA_RE.search(line)
            or not any(intent.search(line) for intent in PIN_INTENT_RES)
            or SECTION_PIN_RE.search(line)
        ):
            continue
        declared = ANY_SHA_RE.search(line).group(1)

        patched = list(lines)
        patched[lineno - 1] = "Reviewed at **`" + declared + "`**"
        would_be = eras_for_lines(patched)

        affected = [
            other
            for other in range(1, len(lines) + 1)
            if would_be.get(other) != eras.get(other)
            and CITATION_RE.search(lines[other - 1])
        ]
        if affected:
            flagged.append(
                {
                    "declaration": "`" + declared + "`",
                    "declared_at": lineno,
                    "head_cites": sum(
                        len(CITATION_RE.findall(lines[a - 1])) for a in affected
                    ),
                    "heading": _enclosing_heading(lines, lineno),
                    "lines": set(affected),
                }
            )
    return flagged


def _enclosing_heading(lines, lineno):
    for back in range(lineno - 1, 0, -1):
        if HEADING_RE.match(lines[back - 1]):
            return lines[back - 1].strip("# ").strip()[:60]
    return "(front matter)"


def legend_blocks(lines):
    """Blank-line-delimited paragraphs carrying a walk marker, as
    (first_lineno, last_lineno, joined_text)."""
    out = []
    start = None
    buf = []
    for lineno, line in enumerate(lines, 1):
        if line.strip():
            if start is None:
                start = lineno
            buf.append(line)
            continue
        if buf and WALK_MARKER_RE.search(" ".join(buf)):
            out.append((start, start + len(buf) - 1, " ".join(buf)))
        start, buf = None, []
    if buf and WALK_MARKER_RE.search(" ".join(buf)):
        out.append((start, start + len(buf) - 1, " ".join(buf)))
    return out


def check_legend_containment(relpath, lines, eras, failures, mis_scoped=frozenset()):
    """A walk's cited range must lie inside exactly one body-bearing definition
    of the symbol that walk names.

    Scoped per WALK, not per block: one paragraph introduces several walks
    (`**W-TI** = ... , **W-RB** = ... , **W-PQ** = ...`), so the text is split
    on the markers and each walk's symbol is paired only with the range in its
    own segment.
    """
    for first_lineno, last_lineno, text in legend_blocks(lines):
        # A legend sitting under a declaration this gate could not parse is
        # read at an era the document does not claim, so any containment
        # finding from it would be built on the same false premise the path
        # limb already declines to report.
        if mis_scoped & set(range(first_lineno, last_lineno + 1)):
            continue
        rev = eras.get(first_lineno, HEAD)
        tracked = Era.files(rev)
        if tracked is None:
            continue  # the unreachable-pin limb already reported this
        parts = WALK_MARKER_RE.split(text)
        for walk_id, segment in zip(parts[1::2], parts[2::2]):
            # Pair POSITIONALLY: a walk entry lists several clauses, each with
            # its own symbols and range ("`a` + `b` (`f.cpp:1-2`), plus ... the
            # operand derivations (`c` `:9`, `hardforks.cpp:35-37`)"). Pairing
            # every symbol with every range made `get_tx_volume_avg` answer for
            # a range belonging to the clause above it. A range's symbols are
            # those between it and the previous range.
            cursor = 0
            for match in [m for m in CITATION_RE.finditer(segment) if m.group(2)]:
                symbols = [
                    sym
                    for sym in SYMBOL_RE.findall(segment[cursor:match.start()])
                    if "." not in sym and "/" not in sym
                ]
                cursor = match.end()
                candidates = resolve_path(match.group(1), tracked)
                if len(candidates) != 1:
                    continue  # the path limb owns that failure
                blob = Era.blob(rev, candidates[0])
                if blob is None:
                    continue
                start = int(match.group(2))
                end = int(match.group(3) or match.group(2))
                for symbol in symbols:
                    extents = definition_extents(blob, symbol)
                    if not extents:
                        continue  # prose, or defined elsewhere -- not a claim
                    # OVERLAP, not strict containment. A walk range may sit
                    # inside one definition (W-TI is a sub-block of a ~900-line
                    # function) or deliberately SPAN several (W-MT covers
                    # `prevalidate_miner_transaction` and
                    # `validate_miner_transaction` together). Both are honest
                    # citations. The defect is a range that touches NO
                    # definition of the symbol it names -- a pointer that has
                    # come loose from its subject.
                    if any(e[0] <= end and start <= e[1] for e in extents):
                        continue
                    failures.append(
                        f"{relpath}:{first_lineno}: walk {walk_id} cites "
                        f"`{symbol}` with range {start}-{end}, which overlaps "
                        f"no definition of it in {candidates[0]} at `{rev}` "
                        + ", ".join(f"[{a},{b}]" for a, b in extents)
                        + " -- the range has come loose from the symbol it "
                        "names."
                    )


def check_document(relpath, failures):
    abspath = os.path.join(ROOT, relpath)
    if not os.path.exists(abspath):
        failures.append(f"{relpath}: listed for citation checking but not present")
        return
    with open(abspath, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    eras = eras_for_lines(lines)
    seen = 0

    unparsed = unparsed_era_sections(lines, eras)
    for section in unparsed:
        failures.append(
            f"{relpath}:{section['declared_at']}: section "
            f"\"{section['heading']}\" declares an era this gate does not "
            f"parse ({section['declaration']}), so its {section['head_cites']} "
            f"citation(s) resolved at a DIFFERENT revision -- an enclosing "
            f"section's pin, or HEAD. They would have been checked against "
            f"code the document does not claim they were read at, and the gate "
            f"would have reported them green. Use the parsed section form, "
            f"`Reviewed at **`<sha>`**` or a table header `(all at `<sha>`)`, "
            f"or pin the rows individually with `at `<sha>`` on each."
        )
    # Only the citations an unparsed declaration actually mis-scopes are
    # skipped below -- resolving THOSE would be checking against an era the
    # document does not claim, and any finding would be noise built on a false
    # premise. The rest of the document is still checked: aborting the whole
    # file on one era finding let a single refusal mask every other defect in
    # it, which is the opposite of what a gate is for.
    mis_scoped = set()
    for section in unparsed:
        mis_scoped |= section["lines"]

    for lineno, line in enumerate(lines, 1):
        if lineno in mis_scoped:
            continue
        rev = eras[lineno]
        matches = list(CITATION_RE.finditer(line))
        if not matches:
            continue
        tracked = Era.files(rev)
        if tracked is None:
            failures.append(
                f"{relpath}:{lineno}: pin `{rev}` is unreachable in this checkout, so "
                f"its citations cannot be resolved. A shallow clone cannot run this "
                f"gate -- fetch full history rather than skipping the era."
            )
            continue
        for match in matches:
            seen += 1
            token = match.group(1)
            candidates = resolve_path(token, tracked)
            if not candidates:
                failures.append(
                    f"{relpath}:{lineno}: `{token}` matches no tracked file at "
                    f"`{rev}` (the era this citation declares)"
                )
                continue
            if len(candidates) > 1:
                failures.append(
                    f"{relpath}:{lineno}: `{token}` matches {len(candidates)} tracked "
                    f"files at `{rev}` -- "
                    + ", ".join(candidates)
                    + ". A citation that resolves to many files resolves to none of "
                    "them; qualify it with enough leading directories to be unique."
                )
                continue

    check_legend_containment(relpath, lines, eras, failures, mis_scoped)

    if seen == 0:
        failures.append(
            f"{relpath}: yielded ZERO code citations. This document is listed "
            f"because its citations are load-bearing, so zero means the citation "
            f"grammar stopped matching it, not that it is clean. Fix the parser or "
            f"drop the document from the list -- a gate that reads nothing reports "
            f"the same green as a gate that read everything."
        )
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--docs",
        help="comma-separated document paths to check instead of the default set",
    )
    args = parser.parse_args()
    docs = args.docs.split(",") if args.docs else list(DEFAULT_DOCS)

    failures = []
    total = 0
    for relpath in docs:
        count = check_document(relpath.strip(), failures)
        total += count or 0

    # A deferral that outlives its cause is just silence. Re-run each deferred
    # document and demand that it still fails; if it passes, the blocker is
    # gone and the document belongs back in DEFAULT_DOCS.
    if not args.docs:
        for relpath, blocker in DEFERRED_DOCS.items():
            probe = []
            check_document(relpath, probe)
            if not probe:
                failures.append(
                    f"{relpath}: is listed as DEFERRED because it {blocker} "
                    f"It now passes, so that blocker is gone. Move it into "
                    f"DEFAULT_DOCS -- a deferral kept past its cause is an "
                    f"exclusion nobody re-examines."
                )

    if failures:
        print(f"Unresolvable code citations ({len(failures)}):\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}\n", file=sys.stderr)
        sys.exit(1)

    print(f"code citations: {total} resolved uniquely at their declared eras")
    sys.exit(0)


if __name__ == "__main__":
    main()
