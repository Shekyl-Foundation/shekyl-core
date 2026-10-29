# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# ESR-16. Production reads EconomicParams through economic_params() and
# RelayPolicy through relay_policy(). A production site that builds
# EconomicParams::default() itself, or keeps a second OnceLock of the
# set, has a second accessor.
#
# The economics sim is the sweep: it builds parameter sets. Tests are
# not production. Instance of 47-gate-subject-assertion.mdc.

from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST = os.path.join(ROOT, "rust")
ACCESSOR = os.path.join("shekyl-economics", "src", "params.rs")
MIN_FILES = 200


def strip_cfg_test(text: str) -> str:
    """Drop `#[cfg(test)]` items. A scan of test bodies is not a production read."""
    out = []
    depth = 0
    skip_until = None
    arm = False
    for line in text.splitlines(keepends=True):
        opens = line.count("{")
        closes = line.count("}")
        if skip_until is not None:
            depth += opens - closes
            if depth <= skip_until:
                skip_until = None
            continue
        compact = line.replace(" ", "")
        if "#[cfg(test)]" in compact or compact.startswith("#[test]"):
            arm = True
            depth += opens - closes
            continue
        if arm:
            arm = False
            base = depth
            depth += opens - closes
            if depth > base:
                skip_until = base
            continue
        depth += opens - closes
        out.append(line)
    return "".join(out)


def production_files() -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(RUST):
        dirnames[:] = [d for d in dirnames if d != "target" and "test" not in d]
        rel_dir = os.path.relpath(dirpath, RUST)
        if rel_dir.split(os.sep)[0] in {
            "shekyl-economics-sim",
            "shekyl-staking-sim",
            "shekyl-wss-q1b-bench",
        }:
            continue
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            if "test" in name:
                continue
            found.append(os.path.join(dirpath, name))
    return found


def main() -> int:
    files = production_files()
    if len(files) < MIN_FILES:
        print(
            f"economic-accessor gate scanned {len(files)} rust files; "
            f"expected at least {MIN_FILES}. The subject is missing.",
            file=sys.stderr,
        )
        return 1
    saw_accessor = False
    saw_relay = False
    failures = []
    for path in files:
        rel = os.path.relpath(path, RUST)
        text = open(path, encoding="utf-8").read()
        if rel == ACCESSOR and "fn economic_params(" in text:
            saw_accessor = True
        if rel.endswith(os.path.join("src", "relay_policy.rs")) and "fn relay_policy(" in text:
            saw_relay = True
        if rel == ACCESSOR:
            continue
        body = strip_cfg_test(text)
        if "EconomicParams::default()" in body:
            failures.append(f"{rel}: production builds EconomicParams::default()")
        if "OnceLock<EconomicParams>" in body:
            failures.append(f"{rel}: a second EconomicParams OnceLock")
    if not saw_accessor or not saw_relay:
        print(
            "economic-accessor gate did not see economic_params() and relay_policy(). "
            "The subject is missing.",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("production reads EconomicParams through economic_params():", file=sys.stderr)
        for item in failures:
            print(f"  {item}", file=sys.stderr)
        return 1
    print(f"economic accessors: {len(files)} production rust files, one of each")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sample = "fn live() { let _ = EconomicParams::default(); }\n"
        if "EconomicParams::default()" not in strip_cfg_test(sample):
            print("selftest: a live default() was stripped", file=sys.stderr)
            sys.exit(1)
        tested = "#[cfg(test)]\nfn t() { let _ = EconomicParams::default(); }\n"
        if "EconomicParams::default()" in strip_cfg_test(tested):
            print("selftest: a cfg(test) default() survived", file=sys.stderr)
            sys.exit(1)
        print("economic-accessor selftest passed")
        sys.exit(0)
    sys.exit(main())
