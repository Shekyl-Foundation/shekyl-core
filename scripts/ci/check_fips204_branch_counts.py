#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""fips204's coefficient helpers keep the shape the fork gave them.

Runs the fork's own `shekyl/check_branch_counts.py`, from the revision this
workspace pins, on a shipped-profile build of `fips204_branch_subject` with
line tables. Every conditional branch inlined from the helpers must be a loop
back-edge or, on x86_64, the test of the public `gamma2`, in exactly the number
recorded here for this binary.

A compiler change moves these counts. **A toolchain bump re-pins them, on
x86_64 and on the floor device,** after reading the result: the count is what
tells a person that the code generation changed.

  cargo build --release --locked -p shekyl-crypto-pq --example fips204_branch_subject
      (with CARGO_PROFILE_RELEASE_DEBUG=line-tables-only, from rust/)
  check_fips204_branch_counts.py BINARY x86_64|aarch64
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# (loop back-edges, gamma2 tests) in fips204_branch_subject, rustc 1.94.0.
EXPECTED = {"x86_64": (16, 4), "aarch64": (16, 0)}


def fork_checker():
    """The checker from the fips204 revision this workspace pins."""
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=os.path.join(ROOT, "rust"), check=True, capture_output=True, text=True,
    ).stdout)
    found = [p for p in metadata["packages"] if p["name"] == "fips204"]
    # Rule 47: the subject exists, and it is the fork.
    if len(found) != 1 or not str(found[0].get("source", "")).startswith("git+"):
        raise SystemExit("fips204 branch counts: the workspace does not resolve one pinned fork of fips204")
    path = os.path.join(os.path.dirname(found[0]["manifest_path"]), "shekyl", "check_branch_counts.py")
    if not os.path.exists(path):
        raise SystemExit(f"fips204 branch counts: no checker at {path}")
    spec = importlib.util.spec_from_file_location("fips204_check_branch_counts", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in EXPECTED:
        print(__doc__)
        return 2
    # Rule 47: the subject exists before anything is said about it.
    if not os.path.isfile(argv[0]):
        print(f"fips204 branch counts: no binary at {argv[0]}")
        return 2
    checker = fork_checker()
    checker.EXPECTED = dict(EXPECTED)
    sys.argv = ["check_branch_counts.py", argv[0], argv[1]]
    status = checker.main()
    if status != 0:
        print("fips204 branch counts: read the result before changing anything here. "
              "A toolchain bump re-pins EXPECTED on x86_64 and on the floor device; "
              "a branch on a coefficient is a finding.")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
