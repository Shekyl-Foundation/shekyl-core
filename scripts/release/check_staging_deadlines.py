#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The staging-deadline gate for a release cut (`docs/RELEASE_PROMOTION.md` §4).

A staging flag stages a candidate behaviour on the test networks
(`docs/design/NETWORK_IDENTITY.md` NI-R9, amended 2026-11-04). Staging may
continue after mainnet genesis, but no flag lives forever: each names a
**deadline release** (`Staging::deadline` in `rust/shekyl-network/src/lib.rs`),
and a cut at or past that release while the flag still exists is refused.
The flag leaves by its exit (promoted or deleted), or its deadline is
re-ruled with the reason recorded beside it; this gate does not take an
exemption on its command line.

It reads the table's source, not a build: every variant of `enum Staging`
must name an option (`/// \\`dev-…\\`.`) and a deadline, and a variant without
one is a failure, not a skip (rule 47: the gate asserts its own subject).

Releases compare by SemVer as `docs/VERSIONING.md` defines them:
`3.1.0-alpha.1 < 3.1.0-beta.1 < 3.1.0-rc.1 < 3.1.0`.

Usage:
  check_staging_deadlines.py <candidate-tag> [--root DIR]
  check_staging_deadlines.py --selftest

Exit status: 0 = no flag is past its deadline; 1 = a flag is past its
deadline, or the table could not be read; 2 = usage.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLE = Path("rust/shekyl-network/src/lib.rs")

_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.]+))?$")


def release_key(tag: str) -> tuple:
    """SemVer precedence: the core, then a release above any pre-release,
    then the pre-release's dot-separated identifiers (numbers numerically,
    below words; words by ASCII)."""
    m = _TAG.match(tag)
    if not m:
        raise ValueError(f"{tag!r} is not a release identifier (vMAJOR.MINOR.PATCH[-pre])")
    core = tuple(int(x) for x in m.group(1, 2, 3))
    pre = m.group(4)
    if pre is None:
        return core + ((1,),)
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return core + ((0,) + ids,)


def staging_flags(source: str) -> list[tuple[str, str, str]]:
    """(variant, option, deadline) for every `Staging` variant."""
    enum = re.search(r"pub enum Staging \{(.*?)\n\}", source, re.S)
    if not enum:
        raise ValueError("no `pub enum Staging` in the table")
    variants = re.findall(r"///\s*`(dev-[a-z-]+)`\.\s*\n\s*(\w+),", enum.group(1))
    if not variants:
        raise ValueError("`enum Staging` has no variant naming its option")
    body = re.search(
        r"pub const fn deadline\(self\) -> &'static str \{\s*match self \{(.*?)\n\s*\}\s*\n\s*\}",
        source,
        re.S,
    )
    if not body:
        raise ValueError("no `Staging::deadline` in the table")
    deadlines = dict(re.findall(r"Self::(\w+)\s*=>\s*\"([^\"]+)\"", body.group(1)))
    out = []
    for option, variant in variants:
        if variant not in deadlines:
            raise ValueError(f"{option} ({variant}) names no deadline release")
        out.append((variant, option, deadlines[variant]))
    return out


def check(candidate: str, source: str) -> list[str]:
    cut = release_key(candidate)
    refusals = []
    for _variant, option, deadline in staging_flags(source):
        if cut >= release_key(deadline):
            refusals.append(
                f"{option} still exists at {candidate}, at or past its deadline {deadline}: "
                f"its owner promotes or deletes it, or the deadline is re-ruled with a "
                f"recorded reason (Staging::deadline)"
            )
    return refusals


_SAMPLE = '''
pub enum Staging {
    /// `dev-clearnet-encrypt`.
    ClearnetEncrypt,
    /// `dev-relay-cover`.
    RelayCover,
}

impl Staging {
    pub const fn deadline(self) -> &'static str {
        match self {
            Self::ClearnetEncrypt => "v3.1.0",
            Self::RelayCover => "v3.2.0-beta.1",
        }
    }
}
'''


def selftest() -> int:
    order = ["v3.1.0-alpha.2", "v3.1.0-alpha.11", "v3.1.0-beta.1", "v3.1.0-rc.1", "v3.1.0", "v3.1.1", "v3.2.0-alpha.1"]
    keys = [release_key(t) for t in order]
    assert keys == sorted(keys) and len(set(keys)) == len(keys), "SemVer precedence"
    assert check("v3.1.0-rc.1", _SAMPLE) == [], "before every deadline"
    refused = check("v3.1.0", _SAMPLE)
    assert len(refused) == 1 and "dev-clearnet-encrypt" in refused[0], refused
    assert len(check("v3.2.0", _SAMPLE)) == 2, "past both"
    for broken in (
        _SAMPLE.replace('            Self::RelayCover => "v3.2.0-beta.1",\n', ""),
        _SAMPLE.replace("pub enum Staging", "pub enum Staged"),
        _SAMPLE.replace("pub const fn deadline", "pub const fn due"),
    ):
        try:
            check("v3.0.0", broken)
        except ValueError:
            continue
        raise AssertionError("a table the gate cannot read must fail, not pass")
    for bad in ("3.1", "v3.1.0-", "next"):
        try:
            release_key(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} parsed as a release")
    print("staging-deadline gate selftest: ok")
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
        refusals = check(args.candidate, (args.root / TABLE).read_text())
    except (OSError, ValueError) as e:
        print(f"staging deadlines: {e}", file=sys.stderr)
        return 1
    for r in refusals:
        print(f"refused: {r}", file=sys.stderr)
    if refusals:
        return 1
    print(f"staging deadlines: no flag is past its deadline at {args.candidate}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
