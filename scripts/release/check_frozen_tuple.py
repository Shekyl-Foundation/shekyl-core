#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The frozen-tuple gate for a release cut (`docs/RELEASE_PROMOTION.md` §6).

A testnet's identity on the wire is its genesis block: the network id every
handshake carries is derived from the genesis hash, and the hash covers the
genesis transaction and the header nonce. Two builds with the same genesis
find each other and connect.

That is the hazard this gate is for. When a cut changes what a valid chain
is, and the genesis does not change with it, the old fleet and the new
build share one network id. They connect, each rejects the other's blocks,
and they ban each other, until someone works out that the two "same network"
halves were never one network. The remedy costs one integer: move
`config::testnet::GENESIS_NONCE`, which moves the hash and the id, and the
old and new builds stop seeing each other at the handshake.

So, between the previous release tag and the candidate:

  * if the consensus surface moved, the testnet genesis hash must have moved;
  * the reverse is allowed (rotating a genesis for another reason is a
    decision, not a defect) and is reported.

"The consensus surface moved" is read from two records that the tree already
keeps and already forces to move:

  * `PINNED_DIGEST` in `rust/shekyl-rpc-types/build.rs`, the reviewed digest
    of the integer constant authorities under `config/`. The build fails
    until it is re-pinned when one of them changes.
  * the captured replay chains under
    `rust/shekyl-chain-ingest/tests/vectors/`. A rule change that makes
    earlier blocks invalid forces a re-capture (rule 07), so the directory's
    tree id moves.

Neither record alone is enough. The 2026-10 rule that reserved the header's
minor version re-captured every chain and left the digest untouched, because
no constant under `config/` changed.

This is a release-time check, run against a previous tag, not a per-PR
gate: a PR that changes a rule is not yet a cut, and several may land
before the genesis moves once for all of them.

Usage:
  check_frozen_tuple.py <previous-tag> [<candidate-ref>]   (candidate: HEAD)

Exit status: 0 = consistent; 1 = the consensus surface moved and the testnet
genesis did not (or a record could not be read); 2 = usage.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

DIGEST_FILE = "rust/shekyl-rpc-types/build.rs"
DIGEST_RE = re.compile(r'const PINNED_DIGEST: &str = "([0-9a-f]{64})";')
GENESIS_FILE = "rust/shekyl-rpc-types/src/identity.rs"
GENESIS_RE = re.compile(
    r'const TESTNET_GENESIS: \[u8; 32\] =\s*hex32\(b"([0-9a-f]{64})"\);'
)
CHAINS_DIR = "rust/shekyl-chain-ingest/tests/vectors"


class Unreadable(Exception):
    """A record this gate compares could not be read at a ref."""


def git(root, *args):
    proc = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise Unreadable(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def pinned(root, ref, path, pattern, what):
    text = git(root, "show", f"{ref}:{path}")
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise Unreadable(
            f"{ref}:{path}: expected exactly one {what}, found {len(matches)}"
        )
    return matches[0]


def record(root, ref):
    return {
        "digest": pinned(root, ref, DIGEST_FILE, DIGEST_RE, "PINNED_DIGEST"),
        "chains": git(root, "rev-parse", f"{ref}:{CHAINS_DIR}").strip(),
        "genesis": pinned(root, ref, GENESIS_FILE, GENESIS_RE, "TESTNET_GENESIS"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("previous", help="the previous release tag")
    parser.add_argument("candidate", nargs="?", default="HEAD")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args(argv)

    try:
        before = record(args.root, args.previous)
        after = record(args.root, args.candidate)
    except Unreadable as exc:
        print(f"frozen tuple: {exc}", file=sys.stderr)
        return 1

    moved = []
    if before["digest"] != after["digest"]:
        moved.append("the consensus-constants digest (PINNED_DIGEST)")
    if before["chains"] != after["chains"]:
        moved.append(f"the captured replay chains ({CHAINS_DIR})")
    rotated = before["genesis"] != after["genesis"]

    print(f"frozen tuple: {args.previous} -> {args.candidate}")
    print(f"  testnet genesis: {before['genesis']} -> {after['genesis']}")
    for item in moved:
        print(f"  moved: {item}")

    if moved and not rotated:
        print(
            "frozen tuple: REFUSED. The consensus surface moved and the testnet "
            "genesis did not, so this build and the previous release share a "
            "network id while disagreeing about the chain. Move "
            "config::testnet::GENESIS_NONCE and re-record its pins "
            "(docs/RELEASE_PROMOTION.md §6).",
            file=sys.stderr,
        )
        return 1
    if rotated and not moved:
        print(
            "frozen tuple: the testnet genesis rotated with no recorded consensus "
            "change. Allowed; make sure it was meant."
        )
    elif rotated:
        print("frozen tuple: consensus moved and the testnet genesis rotated with it.")
    else:
        print("frozen tuple: nothing moved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
