#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""The Windows probe sheet and the probe suite must agree on what exists.

WHY THIS EXISTS
---------------
`WINDOWS_WALLET_PROBE_SHEET.md` is a **pre-registration**: it records, before
any Windows machine ran, which probes exist and — the column that does the work
— which decision a failure revisits. That only means something if the probes it
names are actually implemented.

Nothing else checks that correspondence. A deleted `#[test]` still compiles,
still passes CI, and silently drops coverage; unlike a deleted *function*, it
produces no error anywhere. That is exactly how **P-14** — the bounds check
guarding an out-of-bounds read on an attacker-supplied SACL — was lost in
PR #523: an over-wide deletion took it, the build stayed green, and only a
reviewer noticed.

WHY THIS IS NOT THE GATE THAT WAS JUST DELETED
----------------------------------------------
The same PR removed `check_win_probe_copy.py`, which policed a *duplicate* of a
function. That gate existed to compensate for a duplicate that should not have
existed, and deleting the duplicate removed the need.

This one is different in kind: the sheet and the suite are two legitimate
artifacts — a design record and its implementation — and their correspondence
is a real property with no other way to observe it.

WHAT IT ASSERTS
---------------
  * every §1 (CI-durable) probe has a test function;
  * every test function is registered in §1;
  * §2 (deferred) and §3 (laptop-only) probes have NO test, because claiming
    coverage that does not exist is the failure this file is written against.

Exit 0 = in agreement, 1 = drift.
"""

from __future__ import annotations

import io
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
SHEET = REPO / 'docs/design/WINDOWS_WALLET_PROBE_SHEET.md'
SUITE = REPO / 'rust/shekyl-win-sec/tests/probes.rs'

# A registry row: `| P-7 | …`. Anchored at line start so prose mentions of a
# probe id (§4's results discussion is full of them) cannot be mistaken for
# registrations.
ROW = re.compile(r'^\|\s*P-(\d+)\s*\|')
SECTION = re.compile(r'^##\s*(\d+)\.')
# A probe implementation: `fn p7_unlabelled_pipe_is_read_as_medium(`.
TEST_FN = re.compile(r'^\s*(?:async\s+)?fn\s+p(\d+)_[a-z0-9_]+\s*\(', re.M)


def sheet_sections() -> dict[int, set[int]]:
    """Probe ids per numbered section of the sheet."""
    out: dict[int, set[int]] = {}
    current = None
    for line in io.open(SHEET, encoding='utf-8'):
        m = SECTION.match(line)
        if m:
            current = int(m.group(1))
            out.setdefault(current, set())
            continue
        m = ROW.match(line)
        if m and current is not None:
            out[current].add(int(m.group(1)))
    return out


def implemented() -> set[int]:
    return {int(n) for n in TEST_FN.findall(io.open(SUITE, encoding='utf-8').read())}


def main() -> int:
    for path in (SHEET, SUITE):
        if not path.is_file():
            print(f'FAIL: missing {path.relative_to(REPO)}')
            return 1

    sections = sheet_sections()
    ci_durable = sections.get(1, set())
    deferred = sections.get(2, set()) | sections.get(3, set())
    have = implemented()

    problems = []

    missing = sorted(ci_durable - have)
    if missing:
        problems.append(
            'registered as CI-durable (§1) but NOT implemented: '
            + ', '.join(f'P-{n}' for n in missing)
            + '\n    A probe the sheet claims exists, and does not. This is the '
              'shape that lost P-14.'
        )

    unregistered = sorted(have - ci_durable)
    if unregistered:
        problems.append(
            'implemented but NOT registered in §1: '
            + ', '.join(f'P-{n}' for n in unregistered)
            + '\n    A probe with no pre-registered prediction, and so no '
              'recorded decision it revisits on failure.'
        )

    premature = sorted(deferred & have)
    if premature:
        problems.append(
            'registered as deferred/laptop-only (§2/§3) but implemented: '
            + ', '.join(f'P-{n}' for n in premature)
            + '\n    Either the sheet is stale or the probe is running '
              'somewhere it was declared not to.'
        )

    if problems:
        print('probe registry FAILED — the sheet and the suite disagree:\n')
        for p in problems:
            print(f'  - {p}\n')
        return 1

    print(
        f'probe registry OK: {len(ci_durable)} CI-durable probes registered and '
        f'implemented ({", ".join(f"P-{n}" for n in sorted(ci_durable))}); '
        f'{len(deferred)} deferred/laptop-only, correctly unimplemented.'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
