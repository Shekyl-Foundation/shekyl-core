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
#   1. an inline `at `<sha>`` on the citation's own line (row-level override);
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
# AND THE CASE THAT RULE 3 WOULD OTHERWISE SWALLOW: a document that declares
# its eras in a form this parser does not recognise would fall through to
# HEAD on every row -- silently resolving *records-was* citations against
# current code, which is precisely the failure this gate exists to prevent,
# now wearing a green tick. `docs/LMDB_WRITE_ATOMICITY_AUDIT.md` is the live
# instance: it pins by ROW-SET in front matter (`` `dev` `<sha>` `` for
# DRS-W1..W11, another for W12..W15, a third for the regrade) and states in
# its own prose that its line citations are records-was. So: a document that
# contains sha-shaped tokens but yields NO section pin this parser understood
# is a FATAL. Supporting the token form without its row-set scoping would be
# worse than refusing -- it would silently pin every row to whichever sha
# happened to be declared last.
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
# A walk legend entry: `**W-XX**` followed by prose that may name a symbol.
LEGEND_RE = re.compile(r"\*\*W-[A-Z]{2}\*\*")
SYMBOL_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)`")

HEAD = "HEAD"

# Any `<sha>`-shaped token, used only to detect era declarations this parser
# did not understand -- never to resolve with.
ANY_SHA_RE = re.compile(r"`([0-9a-f]{7,40})`")


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
    out = []
    for i, line in enumerate(lines):
        if line[:1] in (" ", "\t", "", "#", "/"):
            continue
        if f"{bare}(" not in line and f"{symbol}(" not in line:
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
    """Era governing each 1-based line: inline override, else section pin, else HEAD."""
    eras = {}
    pin = None
    pin_level = 99
    section_level = 99
    for i, line in enumerate(lines, 1):
        heading = HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            if pin is not None and level <= pin_level:
                pin = None  # the pin's section closed
            section_level = level
        found = SECTION_PIN_RE.search(line)
        if found:
            pin = found.group(1) or found.group(2)
            pin_level = section_level
        inline = INLINE_PIN_RE.search(line)
        eras[i] = inline.group(1) if inline else (pin or HEAD)
    return eras


def check_document(relpath, failures):
    abspath = os.path.join(ROOT, relpath)
    if not os.path.exists(abspath):
        failures.append(f"{relpath}: listed for citation checking but not present")
        return
    with open(abspath, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    eras = eras_for_lines(lines)
    seen = 0

    # Era declarations this parser could not read (see the header note).
    if not any(SECTION_PIN_RE.search(line) for line in lines):
        shas = sorted({m for line in lines for m in ANY_SHA_RE.findall(line)})
        if shas:
            failures.append(
                f"{relpath}: contains {len(shas)} revision-shaped tokens "
                f"({', '.join(shas[:4])}{', ...' if len(shas) > 4 else ''}) but "
                f"declares no era in a form this gate parses, so every citation "
                f"below would be resolved at HEAD. If those citations are "
                f"records-was -- this document says they are -- resolving them at "
                f"HEAD is the exact defect this gate exists to catch. Give the "
                f"document a parseable pin, or pin its rows individually."
            )
            return 0

    for lineno, line in enumerate(lines, 1):
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
            if not LEGEND_RE.search(line) or match.group(2) is None:
                continue
            # Walk legend with a range: the symbol must own that range.
            start, end = int(match.group(2)), int(match.group(3) or match.group(2))
            blob = Era.blob(rev, candidates[0])
            if blob is None:
                failures.append(
                    f"{relpath}:{lineno}: `{candidates[0]}` is tracked at `{rev}` but "
                    f"its content could not be read"
                )
                continue
            for symbol in SYMBOL_RE.findall(line):
                if "." in symbol or symbol.startswith("W-"):
                    continue
                extents = definition_extents(blob, symbol)
                if not extents:
                    continue  # not a symbol defined in this file; prose, not a citation
                owning = [e for e in extents if e[0] <= start and end <= e[1]]
                if len(owning) == 1:
                    continue
                if len(extents) > 1 and not owning:
                    failures.append(
                        f"{relpath}:{lineno}: `{symbol}` has {len(extents)} "
                        f"definitions in {candidates[0]} at `{rev}` "
                        + ", ".join(f"[{a},{b}]" for a, b in extents)
                        + f" and the cited range {start}-{end} lies inside none of "
                        "them -- the range does not name which definition is meant."
                    )
                elif len(owning) > 1:
                    failures.append(
                        f"{relpath}:{lineno}: `{symbol}` range {start}-{end} lies "
                        f"inside {len(owning)} definitions at `{rev}`; it does not "
                        "pick one."
                    )

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
