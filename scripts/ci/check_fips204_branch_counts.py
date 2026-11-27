#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""fips204's coefficient helpers keep the shape recorded for this binary.

Runs the fork's own `shekyl/check_branch_counts.py`, from the revision this
workspace pins, on a shipped-profile build of `ca3_pq_sign_timing` with
line tables. The fork classifies every conditional branch inlined from the
helpers. This script states the pair for that binary. The fork carries no
count: another binary inlines the same helpers in more places.

A compiler change moves the pair. **A toolchain bump re-pins
`TIMING_COUNTS`, on x86_64 and on the floor device,** after reading
the result. The nightly job runs x86_64. Invoking this script with aarch64
checks the recorded floor pair; the nightly job does not invoke it.

  cargo build --release --locked -p shekyl-crypto-pq --example ca3_pq_sign_timing
      (with CARGO_PROFILE_RELEASE_DEBUG=line-tables-only, from rust/)
  check_fips204_branch_counts.py BINARY x86_64|aarch64
  check_fips204_branch_counts.py --subject  (the example this record judges)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SUBJECT = "ca3_pq_sign_timing"
# (loop back-edges, gamma2 tests) in ca3_pq_sign_timing, rustc 1.94.0.
TIMING_COUNTS = {"x86_64": (27, 4), "aarch64": (27, 0)}


def expected_argument(arch: str) -> str:
    """The pair the fork's checker reads for `arch`."""
    backs, gammas = TIMING_COUNTS[arch]
    return f"{arch}={backs},{gammas}"


def fork_script() -> str:
    """Path of `shekyl/check_branch_counts.py` in the pinned fips204 checkout."""
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=os.path.join(ROOT, "rust"),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.stderr.strip() or "fips204 branch counts: cargo metadata failed")
    metadata = json.loads(completed.stdout)
    found = [p for p in metadata["packages"] if p["name"] == "fips204"]
    # Rule 47: the subject exists, and it is the fork.
    if len(found) != 1 or not str(found[0].get("source", "")).startswith("git+"):
        raise SystemExit("fips204 branch counts: the workspace does not resolve one pinned fork of fips204")
    path = os.path.join(os.path.dirname(found[0]["manifest_path"]), "shekyl", "check_branch_counts.py")
    if not os.path.isfile(path):
        raise SystemExit(f"fips204 branch counts: no checker at {path}")
    return path


def self_test() -> int:
    """The recorded pairs format as the fork's `--expected` argument."""
    if expected_argument("x86_64") != "x86_64=27,4" or expected_argument("aarch64") != "aarch64=27,0":
        print("FAIL: self-test: a recorded pair did not format as ARCH=BACK,GAMMA2")
        return 1
    if main(["/no/such-fips204-subject", "x86_64"]) == 0:
        print("FAIL: self-test: a missing binary passed")
        return 1
    if main(["/no/such-fips204-subject", "riscv"]) == 0:
        print("FAIL: self-test: an unknown architecture passed")
        return 1
    print("PASS self-test")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv == ["--subject"]:
        print(SUBJECT)
        return 0
    if len(argv) != 2 or argv[1] not in TIMING_COUNTS:
        print(__doc__)
        return 2
    binary, arch = argv
    # Rule 47: the subject exists before anything is said about it.
    if not os.path.isfile(binary):
        print(f"fips204 branch counts: no binary at {binary}")
        return 2
    completed = subprocess.run(
        [sys.executable, fork_script(), binary, arch, "--expected", expected_argument(arch)],
        check=False,
    )
    if completed.returncode != 0:
        print(
            "fips204 branch counts: read the result before changing anything here. "
            "A toolchain bump re-pins TIMING_COUNTS on x86_64 and on the floor device; "
            "a branch on a coefficient is a finding."
        )
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
