# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Release-archive docs gate: every gitian descriptor copies the user guide
# into the archive it builds, and none copies the repository README. The
# README is written for someone building from source; the person who opens a
# binary archive needs the guide to running what is in it (alpha.11 bug hunt
# A10: the shipped README named flags that do not exist and said no packages
# exist, beside the packages). Instance of 47-gate-subject-assertion.mdc: it
# fails if a descriptor is missing or copies no docs at all, rather than
# passing over nothing.

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GITIAN = os.path.join(ROOT, "contrib", "gitian")
DESCRIPTORS = ("linux", "freebsd", "osx", "win")
SHIPPED = "../docs/USER_GUIDE.md"
# A `cp` whose last argument is the archive's bin directory: the line that
# chooses what the archive carries beside the binaries.
COPY = re.compile(r"^\s*cp\s+(?P<sources>.+?)\s+bin\s*$")


def check(name: str) -> list[str]:
    path = os.path.join(GITIAN, f"gitian-{name}.yml")
    rel = os.path.relpath(path, ROOT)
    if not os.path.isfile(path):
        return [f"{rel}: missing; the gate has no descriptor to read"]
    with open(path, encoding="utf-8") as fh:
        copies = [m.group("sources").split() for m in map(COPY.match, fh) if m]
    if not copies:
        return [f"{rel}: no `cp ... bin` line; the gate cannot see what the archive ships"]
    sources = [s for line in copies for s in line]
    problems = []
    if SHIPPED not in sources:
        problems.append(f"{rel}: the archive does not ship {SHIPPED}")
    if "../README.md" in sources:
        problems.append(f"{rel}: the archive ships the repository README (../README.md)")
    return problems


def main() -> int:
    problems = [p for name in DESCRIPTORS for p in check(name)]
    if problems:
        for p in problems:
            print(p)
        print(f"\n{len(problems)} release-archive docs problem(s).", file=sys.stderr)
        return 1
    print(f"release-archive docs: {len(DESCRIPTORS)} descriptors ship {SHIPPED}, none the repository README")
    return 0


if __name__ == "__main__":
    sys.exit(main())
