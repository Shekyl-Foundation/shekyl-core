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
# Instance of 47-gate-subject-assertion.mdc: a missing FOLLOWUPS.md, or a
# file with no Target: lines at all, is a missing subject.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FOLLOWUPS = os.path.join(ROOT, "docs", "FOLLOWUPS.md")
ALLOWED = {"pre-genesis", "post-genesis", "V4"}
ITEM_RE = re.compile(r"^- ")
TARGET_RE = re.compile(r"^\s*-\s*Target:\s*(\S+)")
BANNED_TARGET = re.compile(
    r"Target:\s*V3\.(?:1|2|x|1\.x|1\+)", re.I
)
REQUIRED_HEADERS = ("## Pre-genesis", "## Post-genesis", "## V4")
# Historical records may still mention old Target: tokens.
SKIP_V3X_DIRS = ("docs/completed", "docs/CHANGELOG.md", "docs/V3_WALLET_DECISION_LOG.md")


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


if __name__ == "__main__":
    sys.exit(main())
