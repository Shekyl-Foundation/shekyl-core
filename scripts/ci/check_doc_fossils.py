# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Forbidden-fossil gate for always-applied cursor rules.
#
# Live transaction-type names in rules must be CTType*, not the pre-rename
# RCTTypeFcmpPlusPlusPqc / RCTTypeNull. Historical RCTTypeFull (etc.) in the
# deleted-list is allowed. Bare GENESIS_STRATEGY.md and privacy-security.mdc
# are filenames that do not exist in shekyl-core.
#
# Instance of 47-gate-subject-assertion.mdc: zero alwaysApply rule files is
# a missing subject.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES = os.path.join(ROOT, ".cursor", "rules")

LIVE_RCT = re.compile(r"RCTType(?:FcmpPlusPlusPqc|Null)\b")
GENESIS_STRATEGY = re.compile(r"GENESIS_STRATEGY\.md")
PRIVACY = re.compile(r"privacy-security\.mdc")


def always_apply_rules() -> list[str]:
    if not os.path.isdir(RULES):
        return []
    out = []
    for f in sorted(os.listdir(RULES)):
        if not f.endswith(".mdc"):
            continue
        p = os.path.join(RULES, f)
        with open(p, encoding="utf-8", errors="replace") as fh:
            head = fh.read(800)
        if "alwaysApply: true" in head:
            out.append(p)
    return out


def main() -> int:
    subjects = always_apply_rules()
    if not subjects:
        print("doc fossils: no alwaysApply .mdc files under .cursor/rules/",
              file=sys.stderr)
        return 2
    hits = []
    for p in subjects:
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        rel = os.path.relpath(p, ROOT)
        for i, line in enumerate(lines, 1):
            if LIVE_RCT.search(line):
                hits.append(f"{rel}:{i}: live RCTType* fossil (use CTType*)")
            if GENESIS_STRATEGY.search(line):
                hits.append(f"{rel}:{i}: GENESIS_STRATEGY.md does not exist in core")
            if PRIVACY.search(line):
                hits.append(f"{rel}:{i}: privacy-security.mdc does not exist")
    if hits:
        for h in hits:
            print(h)
        print(f"\n{len(hits)} forbidden fossil(s) in always-applied rules.",
              file=sys.stderr)
        return 1
    print(f"doc fossils: {len(subjects)} alwaysApply rules clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
