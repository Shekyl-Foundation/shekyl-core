#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
"""Independent oracle for CONSENSUS_CONSTANTS_DIGEST.

`docs/design/CLIENT_VERSION_CONSTANTS_VALIDATION.md` §3.3/§3.12 pins the
canonical form of the `config/` integer authorities, and
`rust/shekyl-rpc-types/build.rs` computes it and compares against
`PINNED_DIGEST`. Both the build script and the crate's tests `#[path]`-include
one Rust canonicaliser, which is what makes the rules single-defined.

The crate's KAT does catch a Rust-side drift **on its own** -- its expected
form and digest are frozen literals, so a changed canonicaliser disagrees with
them (verified: a reversed key sort fails the KAT). What it cannot catch is a
drift where those literals are moved in the same edit, which is a two-line
change in one file. Those literals were computed in Python at authoring time,
so their independence is historical: it protects the value, not the rules.

This gate makes the independence standing. It re-implements the rules here,
from the design text rather than from the Rust, and recomputes every run, so
there is no expected literal to move alongside the implementation. Moving the
digest silently now requires editing two implementations in two languages.
That is the property the design claims (VC-R18).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD_RS = ROOT / "rust" / "shekyl-rpc-types" / "build.rs"

# §3.3 rule 0: the header line, then each file in this fixed order.
CANONICAL_HEADER = "shekyl-consensus-constants-canonical-v2"
CANONICAL_FILES = [
    "config/consensus_constants.json",
    "config/economics_params.json",
]


def canonical_form(pairs: list[tuple[str, str]]) -> str:
    """§3.3 rules 0-7, implemented from the design text."""
    out = CANONICAL_HEADER + "\n"
    for name, text in pairs:
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise SystemExit(f"FAIL: {name} is not a JSON object")
        out += f"= {name}\n"
        for key in sorted(
            (k for k in doc if not k.startswith("_")), key=lambda k: k.encode()
        ):
            value = doc[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise SystemExit(
                    f"FAIL: {name} key {key!r} is not an integer; the canonical "
                    f"form admits only non-negative integers (§3.3 rule 5)"
                )
            if value < 0:
                raise SystemExit(f"FAIL: {name} key {key!r} is negative")
            out += f"{key} {value}\n"
    return out


def digest_hex(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def pinned_from_build_rs() -> str:
    text = BUILD_RS.read_text(encoding="utf-8")
    m = re.search(r'const PINNED_DIGEST: &str = "([0-9a-f]{64})"', text)
    if not m:
        # Rule 47: the gate asserts its own subject exists. A renamed constant
        # or a moved pin must fail loudly, not pass over an absent subject.
        raise SystemExit(
            f"FAIL: no `const PINNED_DIGEST: &str = \"<64 hex>\"` in {BUILD_RS}. "
            "The pin moved or was renamed; this gate compares against it and "
            "cannot vouch for a subject it did not find."
        )
    return m.group(1)


def selftest() -> None:
    """The gate must be able to fail. Prove both directions on fixtures."""
    a = '{"_c": "prose", "zeta": 7, "alpha": 0, "mid": 18446744073709551615}'
    b = '{"coin": 1000000000, "a": 1}'
    pairs = [(CANONICAL_FILES[0], a), (CANONICAL_FILES[1], b)]
    form = canonical_form(pairs)
    expected = (
        f"{CANONICAL_HEADER}\n"
        f"= {CANONICAL_FILES[0]}\nalpha 0\nmid 18446744073709551615\nzeta 7\n"
        f"= {CANONICAL_FILES[1]}\na 1\ncoin 1000000000\n"
    )
    assert form == expected, f"selftest: canonical form drifted:\n{form!r}"
    base = digest_hex(form)
    # A value edit moves it.
    moved = canonical_form([(CANONICAL_FILES[0], a.replace('"zeta": 7', '"zeta": 8')),
                            (CANONICAL_FILES[1], b)])
    assert digest_hex(moved) != base, "selftest: a value edit did not move the digest"
    # A rename at an unchanged value moves it (VC-D12: the key is part of the
    # binding). This is the case that fired on FL-R15.
    renamed = canonical_form([(CANONICAL_FILES[0], a.replace('"zeta"', '"zeta_renamed"')),
                              (CANONICAL_FILES[1], b)])
    assert digest_hex(renamed) != base, "selftest: a rename did not move the digest"
    # Prose is not digested.
    prose = canonical_form([(CANONICAL_FILES[0], a.replace('"prose"', '"entirely other"')),
                            (CANONICAL_FILES[1], b)])
    assert digest_hex(prose) == base, "selftest: a prose edit moved the digest"
    print(
        "SELFTEST PASS: independent canonicaliser reproduces the pinned form, "
        "moves on a value edit and on a rename, and ignores prose"
    )


def main() -> int:
    selftest()
    pairs = []
    for name in CANONICAL_FILES:
        path = ROOT / name
        if not path.is_file():
            raise SystemExit(f"FAIL: {name} is missing; the digest's subject does not exist")
        pairs.append((name, path.read_text(encoding="utf-8")))
    ours = digest_hex(canonical_form(pairs))
    theirs = pinned_from_build_rs()
    if ours != theirs:
        print(
            "FAIL: the independent Python oracle and the Rust build disagree.\n"
            f"    python computes {ours}\n"
            f"    build.rs pins   {theirs}\n"
            "Either the config authorities changed and the pin was not updated "
            "(re-pin, and answer the membership question the build's panic "
            "states), or the Rust canonicaliser drifted from the rules in "
            "CLIENT_VERSION_CONSTANTS_VALIDATION.md §3.3 -- which is the case "
            "this gate exists to catch, because the build script and the "
            "crate's tests share one Rust implementation, and the KAT literals "
            "that would otherwise catch it can be moved in the same edit.",
            file=sys.stderr,
        )
        return 1
    keys = sum(
        len([k for k in json.loads(t) if not k.startswith("_")]) for _, t in pairs
    )
    print(
        f"consensus digest oracle: {ours[:16]}… agreed independently in Python "
        f"over {keys} constants across {len(CANONICAL_FILES)} authorities"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
