# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for scripts/release/check_frozen_tuple.py. Each case builds a
# small git repository holding the three records the gate reads, tags a
# "previous release", makes one edit, and runs the gate across the two. The
# cases that matter are the two refusals: a rule change that moved the
# captured chains with the genesis left alone, and the same for the digest.

import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parents[1] / "release" / "check_frozen_tuple.py"

DIGEST = 'const PINNED_DIGEST: &str = "{}";\n'
GENESIS = 'const TESTNET_GENESIS: [u8; 32] =\n    hex32(b"{}");\n'


def git(root, *args):
    subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        check=True, capture_output=True,
    )


def write(root, digest="a" * 64, genesis="b" * 64, chain=b"chain-one"):
    (root / "rust/shekyl-rpc-types/src").mkdir(parents=True, exist_ok=True)
    (root / "rust/shekyl-chain-ingest/tests/vectors/c").mkdir(parents=True, exist_ok=True)
    (root / "rust/shekyl-rpc-types/build.rs").write_text(DIGEST.format(digest))
    (root / "rust/shekyl-rpc-types/src/identity.rs").write_text(GENESIS.format(genesis))
    (root / "rust/shekyl-chain-ingest/tests/vectors/c/block").write_bytes(chain)


def run(edit):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        git(root, "init", "-q")
        write(root)
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "release")
        git(root, "tag", "prev")
        edit(root)
        git(root, "add", "-A")
        git(root, "commit", "-q", "--allow-empty", "-m", "candidate")
        return subprocess.run(
            [sys.executable, str(GATE), "prev", "HEAD", "--root", str(root)],
            capture_output=True, text=True,
        )


CASES = [
    ("nothing moved passes", lambda r: None, 0, "nothing moved"),
    ("re-captured chains with the genesis left alone is refused",
     lambda r: write(r, chain=b"chain-two"), 1, "REFUSED"),
    ("a moved digest with the genesis left alone is refused",
     lambda r: write(r, digest="c" * 64), 1, "REFUSED"),
    ("re-captured chains with a rotated genesis passes",
     lambda r: write(r, chain=b"chain-two", genesis="d" * 64), 0, "rotated with it"),
    ("a moved digest with a rotated genesis passes",
     lambda r: write(r, digest="c" * 64, genesis="d" * 64), 0, "rotated with it"),
    ("a genesis rotated on its own passes and is reported",
     lambda r: write(r, genesis="d" * 64), 0, "no recorded consensus change"),
    ("a genesis pin the gate cannot find is a failure, not a pass",
     lambda r: (r / "rust/shekyl-rpc-types/src/identity.rs").write_text("// moved\n"),
     1, "expected exactly one TESTNET_GENESIS"),
    ("a missing chains directory is a failure, not a pass",
     lambda r: git(r, "rm", "-rq", "rust/shekyl-chain-ingest/tests/vectors"),
     1, "rev-parse"),
]


def main():
    failures = 0
    for name, edit, want, needle in CASES:
        proc = run(edit)
        out = proc.stdout + proc.stderr
        if proc.returncode != want or needle not in out:
            failures += 1
            print(f"FAIL {name}: exit {proc.returncode}, wanted {want} with {needle!r}\n{out}")
    if failures:
        print(f"frozen-tuple self-test: {failures} of {len(CASES)} cases FAILED")
        return 1
    print(f"frozen-tuple self-test: all {len(CASES)} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
