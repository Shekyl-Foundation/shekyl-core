# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Landed-row stamp gate for docs/design/*.md and docs/completed/*.md.
#
# A roadmap row that claims a slice **landed** must name the PR that landed
# it. The PR number is knowable when the row is written; the merge sha is not
# (a row for an in-flight branch legitimately reads "sha stamped at merge"),
# so this gate binds the knowable half only and says nothing about shas.
#
# Why a gate rather than the checklist that already asks for it: stamping is a
# step in DAEMON_RPC_KV_CUTOVER.md's own per-slice checklist, and it was
# skipped for six consecutive merged slices (RK-1..RK-4b, corrected in PR
# #576). The doc then read "design open for RK-4a" while RK-4a, RK-4b and
# RK-4c had all been written. A status banner is what rule 95 gives a
# grep-driven reader to classify every claim below it, so a stale one
# misclassifies the whole file -- which is the cost this check exists to stop.
#
# Instance of 47-gate-subject-assertion.mdc: zero landed rows is a missing
# subject, not a pass.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS = os.path.join(ROOT, "docs")

# A table row (leading pipe) asserting a landing.
LANDED_ROW = re.compile(r"^\s*\|.*\*\*landed\*\*", re.IGNORECASE)
# A landed row must CARRY "PR #<digits>". Checking only for the literal
# placeholder "PR #" would let a row with no PR token at all pass -- absence
# reading as presence, the inverse-direction hole a coverage gate has to close
# explicitly (found by review, PR #576).
#
# Scope is per FILE, not repo-wide: requiring a PR number on every row that
# says "landed" fires on ~50 closeout-table rows in 15 documents where a PR
# number was never the convention and "landed" is ordinary prose. A document
# that stamps ANY of its landed rows has adopted the convention, and there the
# unstamped row is the defect. This binds the convention where it is used
# instead of imposing it where it is not.
STAMPED = re.compile(r"PR #[0-9]+")
# A code span quotes a string rather than asserting it. A decision-log row
# that *names* the placeholder (recording that it was once there) is not an
# unstamped row, and a checker that cannot tell naming from using repeats the
# defect it exists to catch -- this gate tripped on its own log entry first.
CODE_SPAN = re.compile(r"`[^`]*`")


def md_files() -> list[str]:
    out: list[str] = []
    for sub in ("design", "completed"):
        d = os.path.join(DOCS, sub)
        if not os.path.isdir(d):
            continue
        out += sorted(
            os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md")
        )
    return out


def main() -> int:
    files = md_files()
    if not files:
        print("check_landed_rows_stamped: no docs/design or docs/completed "
              "markdown found -- missing subject (rule 47)", file=sys.stderr)
        return 2

    landed_seen = 0
    bad: list[str] = []
    for path in files:
        rel = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8", errors="replace") as fh:
            # Strip code spans FIRST, then decide both questions on the
            # stripped text: a row that quotes `**landed**` while describing
            # this gate is naming the marker, not claiming a landing. The
            # stripping has to precede the row test as well as the stamp
            # test -- doing only the latter left this file's own log entry
            # reported as an unstamped row.
            rows = []
            for n, ln in enumerate(fh, 1):
                bare = CODE_SPAN.sub("", ln)
                if LANDED_ROW.match(bare):
                    rows.append((n, bare))
        landed_seen += len(rows)
        # Does this document use the stamp convention at all?
        if not any(STAMPED.search(ln) for _, ln in rows):
            continue
        for n, line in rows:
                if not STAMPED.search(line):
                    bad.append(f"{rel}:{n}: row claims **landed** but carries "
                               f"no 'PR #<number>' stamp")

    if landed_seen == 0:
        print("check_landed_rows_stamped: no row claiming **landed** found "
              "in docs/design or docs/completed -- the gate's subject is "
              "absent (rule 47); it would pass over anything", file=sys.stderr)
        return 2

    if bad:
        print("Unstamped landed rows (name the PR that landed the slice):",
              file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 1

    print(f"check_landed_rows_stamped: {landed_seen} landed rows, all stamped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
