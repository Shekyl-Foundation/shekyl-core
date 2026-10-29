#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The dialer and the peer list hold no per-connector arms.

Each connector declares its dial numbers in one profile,
`shekyl_transport_layer::dial_profile` (the dial profile brief, Rick
2026-10-27). The dialer's mechanisms and the peer list's cooldown ladder
read it; they do not branch on the connector. So `rust/shekyl-dialer/src`
and `rust/shekyl-peerlist/src` contain no match arm on `ConnectorId::Tor`
or `ConnectorId::Clearnet`, including a tuple arm and an arm whose `=>`
is on the next line, no `matches!` of one, and no `==` or `!=` of one
on either side, outside the allowlist below, each entry with its reason.
A new overlay is a new profile row, not a new arm here.

Rule 47: the gate asserts it found its subject. Each source directory must
exist and hold its anchor file, or the gate fails rather than passing on
nothing. `--selftest` plants an arm in a scratch copy and requires the gate
to fail on it, and to pass on the clean copy.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import sys
import tempfile

ROOTS = ("rust/shekyl-dialer/src", "rust/shekyl-peerlist/src")

# The file in each root the gate must find, so a moved or renamed source tree
# fails the gate instead of passing it on nothing (rule 47).
ANCHORS = (
    "rust/shekyl-dialer/src/owner/mod.rs",
    "rust/shekyl-peerlist/src/partition.rs",
)

# A per-connector arm. The `=>` may sit on the same line, including after a
# tuple pattern `(ConnectorId::Clearnet, ListName::Gray) =>`, or on the next
# line. A comparison names the connector on either side. `matches!` is an arm.
CONNECTOR = r"ConnectorId::(?:Tor|Clearnet)"
ARM = re.compile(rf"{CONNECTOR}\b[^;\n]*=>")
ARM_WRAPPED = re.compile(rf"{CONNECTOR}\b[^;\n]*\n[ \t]*=>")
COMPARE = re.compile(rf"(?:==|!=)\s*{CONNECTOR}\b|{CONNECTOR}\b\s*(?:==|!=)")
MATCHES_MACRO = re.compile(rf"matches!\s*\([^;]*?{CONNECTOR}\b")

# The pacing match this profile removed from `attempts_per_test`. The gate
# fails on it, wrapped or not: a connector supplies numbers, not this arm.
REMOVED_ATTEMPTS_ARM = """\
pub const fn attempts_per_test(connector: ConnectorId, list: ListName) -> u8 {
    match (connector, list) {
        (ConnectorId::Clearnet, ListName::Gray) => 1,
        (ConnectorId::Clearnet, ListName::White) => 2,
        (ConnectorId::Tor, _) => 3,
    }
}
"""

REMOVED_ATTEMPTS_ARM_WRAPPED = """\
pub const fn attempts_per_test(connector: ConnectorId, list: ListName) -> u8 {
    match (connector, list) {
        (ConnectorId::Clearnet, ListName::Gray)
            => 1,
        (ConnectorId::Tor, _)
            => 3,
    }
}
"""

CLEAN_ANCHOR = "pub fn mechanism(profile: Profile) -> u8 { profile.n }\n"

# Each allowed file, with why it may name a connector.
ALLOWLIST = {
    "rust/shekyl-dialer/src/link_tally.rs": (
        "the Tor link tally: the managed-Tor supervisor's posture line, "
        "Tor by nature (TOR_SUPERVISOR.md section 4.2)"
    ),
}


def arms_in(text: str) -> list[tuple[int, str]]:
    """Each per-connector arm in `text`, as its line number and that line."""
    lines = text.splitlines()
    found: dict[int, str] = {}
    for pattern in (ARM, ARM_WRAPPED, COMPARE, MATCHES_MACRO):
        for match in pattern.finditer(text):
            number = text.count("\n", 0, match.start()) + 1
            found.setdefault(number, lines[number - 1].strip())
    return [(number, found[number]) for number in sorted(found)]


def scan(repo: pathlib.Path) -> list[str]:
    """Every problem in `repo`: a missing subject, or an arm outside the allowlist."""
    problems: list[str] = []
    for anchor in ANCHORS:
        if not (repo / anchor).is_file():
            problems.append(f"{anchor}: not found; the gate cannot see its subject")
    for root in ROOTS:
        base = repo / root
        if not base.is_dir():
            problems.append(f"{root}: not found; the gate cannot see its subject")
            continue
        files = sorted(base.rglob("*.rs"))
        if not files:
            problems.append(f"{root}: holds no Rust source")
        for path in files:
            relative = path.relative_to(repo).as_posix()
            if relative in ALLOWLIST:
                continue
            for number, line in arms_in(path.read_text(encoding="utf-8")):
                problems.append(
                    f"{relative}:{number}: a per-connector arm; read "
                    f"dial_profile(connector) instead: {line}"
                )
    return problems


def selftest() -> int:
    """The gate fails on a planted arm and passes on a clean tree."""
    with tempfile.TemporaryDirectory() as scratch:
        repo = pathlib.Path(scratch)
        for anchor in ANCHORS:
            target = repo / anchor
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(CLEAN_ANCHOR)
        clean = scan(repo)
        if clean:
            print("selftest: the clean tree failed:", *clean, sep="\n  ")
            return 1
        planted = repo / "rust/shekyl-dialer/src/owner/mod.rs"

        def plant(text: str, label: str) -> int:
            planted.write_text(text)
            problems = scan(repo)
            if not any("per-connector arm" in problem for problem in problems):
                print(f"selftest: {label} passed")
                return 1
            return 0

        if plant(
            "pub fn bound(c: ConnectorId) -> usize {\n"
            "    match c { ConnectorId::Tor => 5, _ => 1 }\n}\n",
            "a planted `ConnectorId::Tor =>` arm",
        ):
            return 1
        if plant(
            "pub fn tor(c: ConnectorId) -> bool { c == ConnectorId::Tor }\n",
            "a planted `== ConnectorId::` comparison",
        ):
            return 1
        if plant(
            "pub fn clear(c: ConnectorId) -> bool { ConnectorId::Clearnet != c }\n",
            "a planted `ConnectorId:: !=` comparison",
        ):
            return 1
        if plant(
            "pub fn tor(c: ConnectorId) -> bool { matches!(c, ConnectorId::Tor) }\n",
            "a planted matches! arm",
        ):
            return 1
        if plant(REMOVED_ATTEMPTS_ARM, "the removed attempts_per_test tuple arm"):
            return 1
        if plant(REMOVED_ATTEMPTS_ARM_WRAPPED, "a line-wrapped tuple arm"):
            return 1
        # The missing-subject check is the only reason the next scan fails.
        # A planted arm left in place would hide a gate that no longer looks
        # for its subject.
        planted.write_text(CLEAN_ANCHOR)
        restored = scan(repo)
        if restored:
            print("selftest: the restored tree failed:", *restored, sep="\n  ")
            return 1
        shutil.rmtree(repo / "rust/shekyl-peerlist")
        missing = scan(repo)
        if (
            not missing
            or any("per-connector arm" in problem for problem in missing)
            or not any("not found" in problem for problem in missing)
        ):
            print(
                "selftest: a missing source tree did not fail on the missing subject:",
                *missing,
                sep="\n  ",
            )
            return 1
    print(
        "selftest: the gate fails on a planted arm, a tuple arm, a comparison "
        "and a missing tree"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    problems = scan(args.repo)
    if problems:
        print("the dialer or the peer list branches on a connector:", *problems, sep="\n  ")
        return 1
    print(
        f"no per-connector arms in {', '.join(ROOTS)} "
        f"(allowlisted: {', '.join(sorted(ALLOWLIST))})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
