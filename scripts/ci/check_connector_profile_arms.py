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
and `rust/shekyl-peerlist/src` contain no `ConnectorId::Tor =>`, no
`ConnectorId::Clearnet =>`, and no `== ConnectorId::` or `!= ConnectorId::`
outside the allowlist below, each entry with its reason. A new overlay is
a new profile row, not a new arm here.

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

PATTERN = re.compile(r"ConnectorId::(?:Tor|Clearnet)\s*=>|[!=]=\s*ConnectorId::")

# Each allowed file, with why it may name a connector.
ALLOWLIST = {
    "rust/shekyl-dialer/src/link_tally.rs": (
        "the Tor link tally: the managed-Tor supervisor's posture line, "
        "Tor by nature (TOR_SUPERVISOR.md section 4.2)"
    ),
}


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
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if PATTERN.search(line):
                    problems.append(
                        f"{relative}:{number}: a per-connector arm; read "
                        f"dial_profile(connector) instead: {line.strip()}"
                    )
    return problems


def selftest() -> int:
    """The gate fails on a planted arm and passes on a clean tree."""
    with tempfile.TemporaryDirectory() as scratch:
        repo = pathlib.Path(scratch)
        for anchor in ANCHORS:
            target = repo / anchor
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("pub fn mechanism(profile: Profile) -> u8 { profile.n }\n")
        clean = scan(repo)
        if clean:
            print("selftest: the clean tree failed:", *clean, sep="\n  ")
            return 1
        planted = repo / "rust/shekyl-dialer/src/owner/mod.rs"
        planted.write_text(
            "pub fn bound(c: ConnectorId) -> usize {\n"
            "    match c { ConnectorId::Tor => 5, _ => 1 }\n}\n"
        )
        if not scan(repo):
            print("selftest: a planted `ConnectorId::Tor =>` arm passed")
            return 1
        planted.write_text("pub fn tor(c: ConnectorId) -> bool { c == ConnectorId::Tor }\n")
        if not scan(repo):
            print("selftest: a planted `== ConnectorId::` comparison passed")
            return 1
        shutil.rmtree(repo / "rust/shekyl-peerlist")
        if not scan(repo):
            print("selftest: a missing source tree passed")
            return 1
    print("selftest: the gate fails on a planted arm, a comparison and a missing tree")
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
