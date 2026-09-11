# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# FOLLOWUPS Target: token gate.
#
# Every top-level work item in docs/FOLLOWUPS.md must carry
# `Target: pre-genesis` or `Target: post-genesis` or `Target: V4`.
# V3.1 / V3.2 / V3.x are not targets.
#
# It also checks that every entry closes the bold it opens. An entry with an
# ODD number of `**` has emphasis it never terminates, which renders as literal
# asterisks. Parity, not "fewer than two": an entry whose first bold closes and
# whose second does not has three, and a `< 2` test passes it. Two such entries
# existed and were missed that way (150e23466).
#
# Instance of 47-gate-subject-assertion.mdc: a missing FOLLOWUPS.md, or a
# file with no Target: lines at all, is a missing subject.
#
# FALSIFICATION STATUS, stated because uniformity is otherwise assumed: only
# the unclosed-bold leg has a harness (`--selftest`, exercising both directions
# plus a legitimate-multiple-bold negative control). The Target-token leg, the
# banned-V3.x sweeps over docs/ and .cursor/rules/, and the subject assertions
# have NO harness. A reader seeing one falsified leg must not conclude the file
# is uniformly falsified — it is not.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FOLLOWUPS = os.path.join(ROOT, "docs", "FOLLOWUPS.md")
ALLOWED = {"pre-genesis", "post-genesis", "V4"}
ITEM_RE = re.compile(r"^- ")
ENTRY_RE = re.compile(r"^- \*\*")
TARGET_RE = re.compile(r"^\s*-\s*Target:\s*(\S+)")
BANNED_TARGET = re.compile(
    r"Target:\s*V3\.(?:1|2|x|1\.x|1\+)", re.I
)
REQUIRED_HEADERS = ("## Pre-genesis", "## Post-genesis", "## V4")
# Historical records may still mention old Target: tokens.
SKIP_V3X_DIRS = ("docs/completed", "docs/CHANGELOG.md", "docs/V3_WALLET_DECISION_LOG.md")


def _opens_unclosed_bold(line: str) -> bool:
    """True iff a FOLLOWUPS entry line has an odd number of `**` markers."""
    return bool(ENTRY_RE.match(line)) and line.count("**") % 2 == 1


def main() -> int:
    if not os.path.isfile(FOLLOWUPS):
        print("followups targets: docs/FOLLOWUPS.md is missing", file=sys.stderr)
        return 2
    with open(FOLLOWUPS, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    text = "".join(lines)
    missing_h = [h for h in REQUIRED_HEADERS if h not in text]
    if missing_h:
        print(f"followups targets: missing section(s) {missing_h}",
              file=sys.stderr)
        return 2
    items = []
    i = 0
    while i < len(lines):
        if ITEM_RE.match(lines[i]) and not TARGET_RE.match(lines[i]):
            items.append(i)
        i += 1
    if not items:
        print("followups targets: no top-level work items found", file=sys.stderr)
        return 2
    bad = []
    for idx in items:
        # Target must appear in the next 3 lines
        window = lines[idx : idx + 4]
        tgt = None
        for w in window[1:]:
            m = TARGET_RE.match(w)
            if m:
                tgt = m.group(1)
                break
        rel_line = idx + 1
        if tgt is None:
            bad.append(f"docs/FOLLOWUPS.md:{rel_line}: item has no Target: line")
        elif tgt not in ALLOWED:
            bad.append(
                f"docs/FOLLOWUPS.md:{rel_line}: Target: {tgt!r} "
                f"not in {sorted(ALLOWED)}"
            )
    for n, line in enumerate(lines, start=1):
        if _opens_unclosed_bold(line):
            bad.append(
                f"docs/FOLLOWUPS.md:{n}: entry opens bold it never closes "
                f"({line.count('**')} '**' markers, odd)"
            )
    text = "".join(lines)
    for m in BANNED_TARGET.finditer(text):
        line = text[: m.start()].count("\n") + 1
        bad.append(f"docs/FOLLOWUPS.md:{line}: banned V3.x work-item target")

    # Living docs / rules: V3.1 / V3.2 / V3.x are not Target: tokens.
    for dirpath, _dirs, files in os.walk(os.path.join(ROOT, "docs")):
        rel_dir = os.path.relpath(dirpath, ROOT)
        if rel_dir.startswith("docs/completed"):
            continue
        for f in files:
            if not f.endswith(".md"):
                continue
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, ROOT)
            if rel in SKIP_V3X_DIRS or rel.startswith("docs/completed"):
                continue
            if rel == "docs/FOLLOWUPS.md":
                continue
            with open(p, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
            for m in BANNED_TARGET.finditer(body):
                line = body[: m.start()].count("\n") + 1
                bad.append(f"{rel}:{line}: banned V3.x work-item target")
    rules = os.path.join(ROOT, ".cursor", "rules")
    if os.path.isdir(rules):
        for f in os.listdir(rules):
            if not f.endswith(".mdc"):
                continue
            p = os.path.join(rules, f)
            with open(p, encoding="utf-8", errors="replace") as fh:
                body = fh.read()
            rel = os.path.relpath(p, ROOT)
            for m in BANNED_TARGET.finditer(body):
                line = body[: m.start()].count("\n") + 1
                bad.append(f"{rel}:{line}: banned V3.x work-item target")
    if bad:
        for b in bad:
            print(b)
        print(f"\n{len(bad)} FOLLOWUPS Target: failure(s).", file=sys.stderr)
        return 1
    print(f"followups targets: {len(items)} items, all pre-genesis|post-genesis|V4")
    return 0


def _selftest() -> int:
    """Falsify the unclosed-bold leg: it must fire, and must stay silent.

    Both directions plus a negative control, because a check that cannot fail
    and a check that fires on valid input are the same defect wearing
    different signs.
    """
    cases = [
        ("unclosed, one marker", "- **opens and never closes\n", True),
        ("unclosed, second bold", "- **closed.** **Closed\n", True),
        ("well formed", "- **title** body\n", False),
        ("legitimate multiple bold", "- **title** and **more** bold\n", False),
        ("not an entry", "- plain bullet with no bold\n", False),
        ("continuation line", "  - Target: pre-genesis\n", False),
    ]
    failures = []
    for name, line, must_fire in cases:
        fired = _opens_unclosed_bold(line)
        if fired != must_fire:
            failures.append(
                f"selftest: {name!r} expected fire={must_fire}, got {fired}"
            )
    if failures:
        for f in failures:
            print(f, file=sys.stderr)
        return 1
    print(f"followups selftest: unclosed-bold leg, {len(cases)} cases, "
          f"both directions exercised")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit(main())
