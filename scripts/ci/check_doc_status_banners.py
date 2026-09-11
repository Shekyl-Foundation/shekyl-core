# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Status-banner gate for docs/design/*.md and docs/completed/*.md.
#
# Rule 95 requires a Status line in the first 40 lines after the H1 so a
# grep-driven reader sees the class (LIVING CONTRACT / OPEN / CLOSED-as-record)
# before the body. Completeness here is "the banner exists", not that the
# wording is the only allowed phrasing — CLOSED, RETIRED, LIVING, OPEN, DRAFT
# (historical, on a completed/ file) all match.
#
# Instance of 47-gate-subject-assertion.mdc: an empty population of matching
# files is a missing subject, not a pass.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS = os.path.join(ROOT, "docs")
STATUS_RE = re.compile(r"(?im)^\s{0,3}(\*\*)?status(\*\*)?\s*[.:]")


def files_in(subdir: str) -> list[str]:
    d = os.path.join(DOCS, subdir)
    if not os.path.isdir(d):
        return []
    return sorted(
        os.path.join(d, f) for f in os.listdir(d) if f.endswith(".md")
    )


def banner_ok(path: str) -> bool:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    lines = text.splitlines()
    h1 = next((i for i, ln in enumerate(lines) if ln.startswith("# ")), None)
    if h1 is None:
        return False
    window = "\n".join(lines[h1 : h1 + 41])
    return STATUS_RE.search(window) is not None


def main() -> int:
    subjects = files_in("design") + files_in("completed")
    if not subjects:
        print("doc banners: no markdown under docs/design/ or docs/completed/",
              file=sys.stderr)
        return 2
    missing = []
    for p in subjects:
        if not banner_ok(p):
            rel = os.path.relpath(p, ROOT)
            missing.append(rel)
    if missing:
        for rel in missing:
            print(f"{rel}: missing Status banner in first 40 lines after H1")
        print(f"\n{len(missing)} file(s) missing a Status banner "
              f"(rule 95).", file=sys.stderr)
        return 1
    print(f"doc banners: {len(subjects)} design/completed files carry Status")
    return 0


if __name__ == "__main__":
    sys.exit(main())
