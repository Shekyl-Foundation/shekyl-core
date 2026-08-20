# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Empty-identifier-heading gate for docs/.
#
# Every identifier heading in docs/ must be followed by a non-empty body
# before the next heading of equal or higher level. An identifier heading is
# one whose text names a tracked item -- MR-F1, MR-DQ-3, T-A11, DQ-F, SP-T2,
# R1-D9 and the like -- i.e. exactly the headings that other documents, the
# tracking index, and grounding sweeps cite by name.
#
# Why this exists. These files are edited by script as often as by hand, and a
# mis-anchored slice silently relocates a section's body while leaving its
# heading in place. That failure is invisible to every other gate: the file
# parses, the links resolve, the word count barely moves, and the heading
# still answers a search. What a reader gets is an identifier that looks
# answered and is not. The T18 mutation-regime round hit this three times in
# one session -- twice from a reversed Python slice, once from a splice that
# landed inside a macro body -- and caught all three by eye, one edit before
# the corruption would have been committed as the round's own record.
#
# This is an instance of `47-gate-subject-assertion.mdc`: a heading whose body
# has vanished is a subject that no longer exists, presenting as one that
# does.
#
# Deliberately narrow, so the gate cannot cry wolf and get deleted:
#   - only headings whose text STARTS with an identifier-shaped token, so
#     ordinary prose headings ("Why this document exists") are out of scope;
#   - a body is any non-blank line that is not itself a heading;
#   - a heading immediately followed by a DEEPER heading is fine -- that is a
#     section with subsections, not an empty one;
#   - fenced code blocks are skipped, so a `#` inside a shell snippet is never
#     mistaken for a heading.
#
# Exit 0 when every identifier heading has a body; 1 otherwise, listing each
# offender as `path:line: heading` so the failure names its own location.

from __future__ import annotations

import re
import sys
from pathlib import Path

DOCS = Path("docs")

# Leading token of a heading, e.g. `MR-DQ-3`, `T-A11`, `P2B-1`, `G4`, `M3a`.
# A heading may wrap its identifier in bold and/or inline code -- both
# shapes are in use (`### `CR-D1``, `#### **MR-F2'**`). Missing the code
# form silently skipped real tracked headings, which is this gate's own
# failure mode turned on itself.
LEADING_TOKEN = re.compile(r"^[`*\s]*([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)")
# A tracked identifier ENDS in a number (optionally with a single lowercase
# suffix): `…-3`, `A11`, `G4`, `M3a`. This is what separates `G4` from `P2P`,
# which is prose that merely contains a digit -- the gate must not fire on
# ordinary headings or it gets deleted rather than fixed.
IDENTIFIER_TAIL = re.compile(r"\d[a-z]?$")

# Pinned floor for the number of identifier headings the gate must actually
# examine. See the rule-47 note in `main`. Set below the current census with
# headroom, so ordinary doc churn does not trip it but a pattern that stops
# matching does.
MINIMUM_IDENTIFIER_HEADINGS = 200
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")


def offenders(path: Path) -> tuple[list[tuple[int, str]], int]:
    lines = path.read_text(encoding="utf-8").split("\n")
    heads: list[tuple[int, int, str]] = []  # (line_index, level, text)
    # Fence tracking follows Markdown's actual rule: a fence is closed only
    # by the SAME marker character, at least as long as the opener. Toggling
    # on any fence-like line meant a literal `~~~` inside a backtick block
    # flipped the state twice, leaving the parser "inside" a fence past the
    # real close and silently skipping every heading after it.
    fence: str | None = None
    for i, line in enumerate(lines):
        m_fence = FENCE.match(line)
        if m_fence:
            marker = m_fence.group(1)
            if fence is None:
                fence = marker
                continue
            if marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        m = HEADING.match(line)
        if m:
            heads.append((i, len(m.group(1)), m.group(2)))

    found: list[tuple[int, str]] = []
    examined = 0
    for idx, (i, level, text) in enumerate(heads):
        token = LEADING_TOKEN.match(text)
        if not token or not IDENTIFIER_TAIL.search(token.group(1)):
            continue
        examined += 1

        nxt = heads[idx + 1] if idx + 1 < len(heads) else None
        if nxt is not None and nxt[1] > level:
            # The next heading is DEEPER: this section has subsections, which
            # are content. `## P2B-1` followed directly by `### Finding` is a
            # normal shape, not an empty item.
            continue

        end = nxt[0] if nxt is not None else len(lines)
        if not any(ln.strip() for ln in lines[i + 1 : end]):
            found.append((i + 1, text))
    return found, examined


def main() -> int:
    if not DOCS.is_dir():
        print(f"FATAL: {DOCS}/ not found; run from the repo root.", file=sys.stderr)
        return 1

    files = sorted(DOCS.rglob("*.md"))
    if not files:
        # Rule 47: a gate that examines nothing must not report success.
        print("FATAL: no markdown files found under docs/.", file=sys.stderr)
        return 1

    bad: list[str] = []
    checked = 0
    examined = 0
    for path in files:
        found, seen = offenders(path)
        examined += seen
        for line, text in found:
            bad.append(f"{path}:{line}: identifier heading has no body -> {text}")
        checked += 1

    # Rule 47, applied to this gate itself. Counting FILES only proves that
    # markdown exists; it says nothing about whether any identifier heading
    # was actually examined. If the identifier pattern stops matching -- a
    # regex edit, or a house convention that drifts -- every heading is
    # skipped and this gate reports green having checked nothing, which is
    # precisely the vacuous success it was written to prevent.
    #
    # The floor is a pin: it should rise as the docs grow, and a fall means
    # either real deletions (update it deliberately) or a broken pattern.
    if examined < MINIMUM_IDENTIFIER_HEADINGS:
        print(
            f"FATAL: examined only {examined} identifier headings, below the pinned "
            f"floor of {MINIMUM_IDENTIFIER_HEADINGS}.",
            file=sys.stderr,
        )
        print(
            "  The gate's subject has gone missing, not its findings: either the\n"
            "  identifier pattern stopped matching the house convention, or tracked\n"
            "  headings were deleted. A green result here would mean nothing.",
            file=sys.stderr,
        )
        return 1

    if bad:
        print("empty identifier headings:", file=sys.stderr)
        for b in bad:
            print(f"  {b}", file=sys.stderr)
        print(
            "\nAn identifier heading with no body reads as answered and is not.\n"
            "If a scripted edit relocated the body, restore it; if the item was\n"
            "deliberately emptied, delete the heading too.",
            file=sys.stderr,
        )
        return 1

    print(
        f"doc headings: {examined} identifier headings across {checked} files, "
        "every one has a body"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
