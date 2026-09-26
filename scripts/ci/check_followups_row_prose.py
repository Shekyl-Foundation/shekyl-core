#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# docs/FOLLOWUPS.md: every row's prose must END A SENTENCE.
#
# Why this gate exists. The 2026-08-28 compression of FOLLOWUPS (`7ab156282`,
# rule 95's one-liner discipline applied mechanically) kept each row's FIRST
# PHYSICAL LINE and dropped the rest. Headings that wrapped were cut at the
# wrap: 91 rows lost the end of their own heading sentence ("TJ-8 — do NOT
# credit the" ‖ " witness-binding MAC against the window"), and a dozen more
# lost their body mid-sentence ("PR 6 cites", "(added"). The file's own
# undisposed register recorded one symptom ("FA-10 is" → *undetermined*)
# without the cause. A heading with no end is mechanically detectable — the
# same shape as check_doc_headings.py's empty-identifier-heading gate — so the
# class is closed here rather than found two rows at a time.
#
# THE RULE, over a row's prose (its `- **heading**` line plus any indented
# continuation lines up to the first nested bullet): the prose must not end
# dangling. Dangling is one of:
#   - an open bracket or a dash          `(added` / `— ` / `File —`
#   - a colon with no nested list after   `Target:` / `framing:`
#     (a colon INTRODUCING nested bullets other than Target:/Owner: is a list
#     and is fine)
#   - a bare lowercase word               `the` / `from` / `cites` / `Migrate`
#     is NOT bare-lowercase and would pass — the rule catches function words
#     and clause tails, which is what a wrap-cut leaves behind; a capitalised
#     tail is rare and the history pass caught those by hand.
# Everything else ends a row acceptably: terminal punctuation, a closing
# bracket or backtick, a reference token (`§7`, `PWD-B3`, `Q10`, `#746`), a
# closing `**`.
#
# Instance of 47-gate-subject-assertion.mdc: zero rows parsed is a failure,
# and a pinned floor refuses a parse that silently finds far fewer rows than
# the file holds. `--selftest` pins the rule on the shapes above.

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOLLOWUPS = ROOT / "docs" / "FOLLOWUPS.md"

# The file held 352 rows when this gate landed; a parse that finds fewer than
# this many is a broken extractor, not a shorter file. Lower only with a
# deliberate FOLLOWUPS shrink, never to make a run pass.
MIN_ROWS = 300

ROW_RE = re.compile(r"^- \*\*")
NESTED_RE = re.compile(r"^\s+- ")
META_RE = re.compile(r"^\s+- (Target|Owner):")


def rows(text: str) -> list[dict]:
    """Each top-level row: its prose (heading line + continuation lines, joined),
    the line number, and whether a nested non-meta bullet follows it."""
    lines = text.split("\n")
    out: list[dict] = []
    i = 0
    while i < len(lines):
        if ROW_RE.match(lines[i]):
            start = i
            prose = [lines[i].strip()]
            j = i + 1
            while j < len(lines) and lines[j].startswith("  ") and not NESTED_RE.match(lines[j]):
                prose.append(lines[j].strip())
                j += 1
            # Scan the row's nested bullets for a list that a colon may introduce.
            k = j
            has_list = False
            while k < len(lines) and (lines[k].startswith("  ") or lines[k] == ""):
                if NESTED_RE.match(lines[k]) and not META_RE.match(lines[k]):
                    has_list = True
                    break
                if lines[k] == "" and k + 1 < len(lines) and ROW_RE.match(lines[k + 1]):
                    break
                k += 1
            out.append({"line": start + 1, "prose": " ".join(prose), "has_list": has_list})
            i = j
        else:
            i += 1
    return out


def dangling(prose: str, has_list: bool) -> str | None:
    """Why the prose dangles, or None."""
    t = prose.rstrip()
    if t.endswith("**"):
        t = t[:-2].rstrip()
    if not t:
        return "empty row"
    if re.search(r"[(\[—–-]$", t):
        return "ends on an open bracket or a dash"
    if t.endswith(":"):
        return None if has_list else "ends on a colon that introduces nothing"
    last = t.split()[-1]
    if last[0] in "([" and not any(c in last for c in ")]"):
        return f"ends inside an unclosed bracket {last!r}"
    if re.fullmatch(r"[a-z][a-z']*", last):
        return f"ends on a bare word {last!r}"
    return None


def check(text: str) -> tuple[list[str], int]:
    found = rows(text)
    problems = []
    for r in found:
        why = dangling(r["prose"], r["has_list"])
        if why:
            problems.append(f"FOLLOWUPS.md:{r['line']}: {why} — …{r['prose'][-80:]!r}")
    return problems, len(found)


def selftest() -> int:
    cases = [
        ("- **A heading that ends.**\n  - Target: pre-genesis\n", 0),
        ("- **A heading with a reference** — see §7.3\n  - Target: pre-genesis\n", 0),
        ("- **A row citing a token** PWD-B3\n  - Target: pre-genesis\n", 0),
        ("- **A row citing a PR** (#746)\n  - Target: pre-genesis\n", 0),
        ("- **A heading cut at the wrap — do NOT credit the**\n  - Target: pre-genesis\n", 1),
        ("- **A body cut mid-sentence.** PR 6 cites\n  - Target: pre-genesis\n", 1),
        ("- **A body cut at a paren.** (added\n  - Target: pre-genesis\n", 1),
        ("- **A colon that introduces nothing.** Target:\n  - Target: pre-genesis\n", 1),
        (
            "- **A colon that introduces a list:**\n  - Target: pre-genesis\n  - **Sub-item one.**\n",
            0,
        ),
        (
            "- **A wrapped body that ends.** the first line\n  and the second line ends here.\n  - Target: pre-genesis\n",
            0,
        ),
        (
            "- **A wrapped body cut on line two.** the first line\n  and the second line ends on the\n  - Target: pre-genesis\n",
            1,
        ),
    ]
    failures = []
    for text, want in cases:
        problems, n = check(text)
        if n != 1:
            failures.append(f"parsed {n} rows from {text[:40]!r}")
        if len(problems) != want:
            failures.append(f"expected {want} problem(s), got {problems} for {text[:50]!r}")
    if failures:
        print("followups row-prose selftest FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"followups row-prose selftest: {len(cases)} cases OK")
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    if not FOLLOWUPS.is_file():
        print(f"FATAL: {FOLLOWUPS} missing — the gate's subject does not exist", file=sys.stderr)
        return 2
    problems, n = check(FOLLOWUPS.read_text(encoding="utf-8"))
    if n == 0:
        print("FATAL: parsed zero FOLLOWUPS rows — the extractor is not reading the file", file=sys.stderr)
        return 2
    if n < MIN_ROWS:
        print(
            f"FATAL: parsed {n} rows, below the pinned floor {MIN_ROWS} — a broken extractor, "
            "not a shorter file (lower MIN_ROWS only with a deliberate shrink)",
            file=sys.stderr,
        )
        return 2
    if problems:
        print(f"FAIL: {len(problems)} FOLLOWUPS row(s) end mid-sentence:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            "\nA row's prose must end a sentence (or a reference). If the row was cut by the "
            "2026-08-28 compression, restore its text from `git show 7ab156282^:docs/FOLLOWUPS.md`.",
            file=sys.stderr,
        )
        return 1
    print(f"followups row prose: {n} rows, every one ends a sentence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
