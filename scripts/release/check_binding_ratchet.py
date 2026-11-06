#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The domain-binding ratchet gate for a release cut (`docs/RELEASE_PROMOTION.md` §4).

`docs/design/DOMAIN_BINDING_RATCHET.tsv` lists the registry rows the binding
gate cannot yet hold to their binding (the signing envelope §2.5;
`NETWORK_IDENTITY.md` §2.4.1): an input site that takes raw bytes, an id or
name row not declared as a domain constant, a row with no ruled binding. The
list only shrinks (its counts are pinned in
`rust/shekyl-crypto-pq/tests/domain_binding.rs`), and it must be empty at the
genesis release, v3.1.0 (Rick, 2026-11-05): a cut at or past it with any row
left is refused. A row leaves when its site is fixed; this gate takes no
exemption on its command line.

It reads the file, not a build, and an unreadable file or an unknown section
is a failure, not a skip (rule 47: the gate asserts its own subject).

Releases compare by SemVer as `docs/VERSIONING.md` defines them, with the
precedence `check_staging_deadlines.py` implements.

Usage:
  check_binding_ratchet.py <candidate-tag> [--root DIR]
  check_binding_ratchet.py --selftest

Exit status: 0 = the cut is before v3.1.0, or the ratchet is empty;
1 = rows remain at or past v3.1.0, or the file could not be read; 2 = usage.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RATCHET = Path("docs/design/DOMAIN_BINDING_RATCHET.tsv")
GENESIS_RELEASE = "v3.1.0"
SECTIONS = ("input-raw", "unframed", "pending")

_SPEC = importlib.util.spec_from_file_location(
    "check_staging_deadlines", Path(__file__).resolve().parent / "check_staging_deadlines.py"
)
_deadlines = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_deadlines)
release_key = _deadlines.release_key


def ratchet_rows(text: str) -> list[tuple[str, str]]:
    """(section, literal) for every row of the ratchet."""
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not fields[1]:
            raise ValueError(f"line {n}: expected section, literal, note")
        if fields[0] not in SECTIONS:
            raise ValueError(f"line {n}: unknown section {fields[0]!r}")
        rows.append((fields[0], fields[1]))
    if "# section\tliteral\tnote" not in text:
        raise ValueError("no column header: this is not the ratchet")
    return rows


def check(candidate: str, text: str) -> list[str]:
    cut = release_key(candidate)
    rows = ratchet_rows(text)
    if cut < release_key(GENESIS_RELEASE):
        return []
    return [
        f"{literal} is still in the binding ratchet ({section}) at {candidate}: "
        f"the ratchet must be empty at {GENESIS_RELEASE}"
        for section, literal in rows
    ]


_HEADER = "# the ratchet\n# section\tliteral\tnote\n"
_SAMPLE = _HEADER + "input-raw\tshekyl/a-v1\tno type yet\npending\tshekyl/b-v1\tno ruling\n"


def selftest() -> int:
    assert check("v3.1.0-rc.1", _SAMPLE) == [], "before genesis, rows may remain"
    refused = check("v3.1.0", _SAMPLE)
    assert len(refused) == 2 and "shekyl/a-v1" in refused[0], refused
    assert len(check("v3.2.0", _SAMPLE)) == 2, "past genesis"
    assert check("v3.1.0", _HEADER) == [], "an empty ratchet passes the cut"
    for broken in (
        _SAMPLE.replace("input-raw", "inputraw"),
        _SAMPLE.replace("\tno ruling", ""),
        _SAMPLE.replace("# section\tliteral\tnote\n", ""),
    ):
        try:
            check("v3.0.0", broken)
        except ValueError:
            continue
        raise AssertionError("a ratchet the gate cannot read must fail, not pass")
    print("binding-ratchet gate selftest: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", nargs="?")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.candidate:
        parser.print_usage(sys.stderr)
        return 2
    try:
        refusals = check(args.candidate, (args.root / RATCHET).read_text())
    except (OSError, ValueError) as e:
        print(f"binding ratchet: {e}", file=sys.stderr)
        return 1
    for r in refusals:
        print(f"refused: {r}", file=sys.stderr)
    if refusals:
        return 1
    print(f"binding ratchet: nothing refuses the cut at {args.candidate}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
