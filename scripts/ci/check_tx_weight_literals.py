# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# CEN-H3's per-transaction weight limit is derived
# (`shekyl_wire::transaction::TX_WEIGHT_LIMIT`). The old literal, from the
# 600-byte coinbase reserve, must not be restated in code. Docs may still
# record the number as what a census once pinned.
#
# Instance of 47-gate-subject-assertion.mdc: a scan that opens no source
# file is not a clean tree.

from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# Split so this file does not contain the literal it forbids.
UNDERSCORED = "149" + "_400"
BARE = "149" + "400"
EXTENSIONS = {".rs", ".cpp", ".h", ".hpp", ".inl", ".c"}
SKIP_DIRS = {
    ".git",
    "target",
    "build",
    "docs",
    "node_modules",
}
MIN_FILES = 500


def source_files() -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith("wt-")]
        for name in filenames:
            if os.path.splitext(name)[1] in EXTENSIONS:
                found.append(os.path.join(dirpath, name))
    return found


def hits_in(text: str) -> list[str]:
    bad = []
    if UNDERSCORED in text:
        bad.append(UNDERSCORED)
    if BARE in text:
        bad.append(BARE)
    return bad


def main() -> int:
    if "--selftest" in sys.argv:
        sample = "const LIMIT: usize = " + UNDERSCORED + ";\n"
        if not hits_in(sample):
            print("selftest: the matcher did not see the old limit", file=sys.stderr)
            return 1
        if hits_in("the zone is 300_000 bytes\n"):
            print("selftest: the matcher fired on an unrelated number", file=sys.stderr)
            return 1
        print("selftest: the old weight-limit literal is visible to the matcher")
        return 0

    files = source_files()
    if len(files) < MIN_FILES:
        print(
            f"scanned {len(files)} source files, below {MIN_FILES}: the subject is absent",
            file=sys.stderr,
        )
        return 1
    failures = []
    for path in files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        found = hits_in(text)
        if found:
            rel = os.path.relpath(path, ROOT)
            failures.append(f"{rel}: {', '.join(found)}")
    if failures:
        print("TX_WEIGHT_LIMIT is derived; the old literal is restated:", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"no restated weight-limit literal in {len(files)} source files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
