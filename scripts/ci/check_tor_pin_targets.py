#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every target the release builds has exactly one Tor disposition, and the
records that restate the pin agree with it (`TOR_BUNDLE_DISTRIBUTION.md` TB-4,
TB-9).

# Why this gate exists

`config/tor_pins.json` is compiled into the binary by
`rust/shekyl-tor-control-client/build.rs`, which refuses to build a target that
has no row. That makes "no disposition" a compile error — but only on a target
somebody compiles. A host added to a gitian descriptor is first compiled by the
release build, days after the pull request that added it merged. This gate
moves that failure to the pull request.

# What it asserts

  1. **The pin file's hosts are the gitian descriptors' hosts**, as sets, both
     directions. A descriptor host with no row would fail the release build; a
     row for a host nothing builds is a pin nobody verifies.
  2. **Every descriptor yields at least one host.** A `HOSTS=` line this script
     cannot find is not "no hosts"; it is this script having gone blind
     (rule 47).
  3. **The pin file is well formed**, every row — the build script checks only
     the row it compiles.
  4. **`tor-pin-verify.yml` restates no bundle version.** It reads the pin
     file. A version written into the workflow is a second record that goes
     stale when the pin moves (it had, by three bundle releases, when this
     gate was written), so the gate refuses one coming back.
  5. **`tor-pin-verify.yml` verifies every pinned host**, so a newly pinned
     target is not left without its launch run.
  6. **`docs/RELEASE_CHECKLIST.md` names every pinned bundle version** in its
     "Bundled Tor pin current" block, which is a pointer to the pin file and
     has to move with it.

Exit status: 0 = all hold; 1 = a difference (each one printed).
"""

import argparse
import importlib.util
import re
import sys
from pathlib import Path

HOSTS_RE = re.compile(r'^\s*HOSTS="([^"]*)"\s*$', re.MULTILINE)


def load_tor_bundle(root):
    path = root / "scripts" / "release" / "tor_bundle.py"
    spec = importlib.util.spec_from_file_location("tor_bundle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gitian_hosts(root, problems):
    hosts = {}
    descriptors = sorted((root / "contrib" / "gitian").glob("gitian-*.yml"))
    if not descriptors:
        problems.append("no gitian descriptors found under contrib/gitian")
    for descriptor in descriptors:
        found = HOSTS_RE.findall(descriptor.read_text(encoding="utf-8"))
        names = [h for line in found for h in line.split()]
        if not names:
            problems.append(f"{descriptor.name}: no HOSTS=\"...\" line found")
        for name in names:
            hosts.setdefault(name, descriptor.name)
    return hosts


def check(root):
    problems = []
    tor_bundle = load_tor_bundle(root)
    try:
        doc = tor_bundle.load_pins(root / "config" / "tor_pins.json")
    except tor_bundle.Refused as exc:
        return [str(exc)]

    built = gitian_hosts(root, problems)
    rows = {row["gitian_host"]: row for row in doc["targets"]}
    for host in sorted(set(built) - set(rows)):
        problems.append(
            f"{built[host]} builds {host}, which has no row in config/tor_pins.json: "
            "add a pinned row or an unavailable row with its reason"
        )
    for host in sorted(set(rows) - set(built)):
        problems.append(
            f"config/tor_pins.json has a row for {host}, which no gitian descriptor builds"
        )

    pinned = [row for row in doc["targets"] if row["disposition"] == "pinned"]

    workflow = root / ".github" / "workflows" / "tor-pin-verify.yml"
    workflow_text = workflow.read_text(encoding="utf-8")
    if "scripts/release/tor_bundle.py" not in workflow_text:
        problems.append(f"{workflow.name}: does not stage through scripts/release/tor_bundle.py")
    for row in pinned:
        if row["bundle_version"] in workflow_text:
            problems.append(
                f"{workflow.name}: restates the bundle version {row['bundle_version']}; "
                "it reads config/tor_pins.json and must not carry a copy"
            )
        if f"host: {row['gitian_host']}" not in workflow_text:
            problems.append(
                f"{workflow.name}: has no job for the pinned host {row['gitian_host']}"
            )

    checklist = (root / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
    for row in pinned:
        label = f"Expert Bundle {row['bundle_version']} (tor {row['tor_version']})"
        if label not in checklist:
            problems.append(
                f"docs/RELEASE_CHECKLIST.md does not name the {row['bundle_target']} pin "
                f"as \"{label}\""
            )
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    problems = check(args.root)
    if problems:
        for problem in problems:
            print(f"tor pin targets: {problem}", file=sys.stderr)
        return 1
    print("tor pin targets: every built host has one disposition; pin records agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
