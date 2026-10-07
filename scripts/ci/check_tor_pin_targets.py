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
     row for a host nothing builds is a pin nobody verifies. A host triple must
     also be the release name of that row's `os` and `arch`: packaging selects
     a row by the triple and `build.rs` selects one by `os`/`arch`, so a swap
     of two triples would ship one bundle and accept another. The pin reader
     refuses that row; this gate runs the reader.
  2. **Every descriptor yields at least one host.** A `HOSTS=` line this script
     cannot find is not "no hosts"; it is this script having gone blind
     (rule 47).
  3. **The pin file is well formed**, every row — the build script checks only
     the row it compiles.
  4. **`tor-pin-verify.yml` restates no bundle version.** It reads the pin
     file. A version written into the workflow is a second record that goes
     stale when the pin moves (it had, by three bundle releases, when this
     gate was written), so the gate refuses one coming back — anywhere in the
     file, a comment included, since a stale comment misleads as well.
  5. **`tor-pin-verify.yml` verifies every pinned host**, so a newly pinned
     target is not left without its launch run. Read from the parsed
     workflow: a job's `strategy.matrix` must carry the host, and that same
     job must have a step whose script runs `tor_bundle.py stage`. The words
     appearing in a comment, or in a job that does not stage, satisfy
     nothing (rule 47).
  6. **`docs/RELEASE_CHECKLIST.md` names every pinned bundle version** in its
     "Bundled Tor pin current" block, which is a pointer to the pin file and
     has to move with it.
  7. **Pending rows are counted, and can be refused.** An `unavailable` row
     with `"pending": "<work item>"` is a target not pinned *yet*, as distinct
     from one ruled out. Both compile the same way, so only this gate can
     tell them apart. It prints each pending row on every run. With
     `--refuse-pending` it fails while any remains: the change that makes a
     missing tor refuse the start (TB-2) turns that flag on in the workflow,
     so the refusal cannot land with a published target still waiting for
     its pin (TB-12).

Exit status: 0 = all hold; 1 = a difference (each one printed).
"""

import argparse
import importlib.util
import re
import sys
from pathlib import Path

HOSTS_RE = re.compile(r'^\s*HOSTS="([^"]*)"\s*$', re.MULTILINE)
STAGE_RE = re.compile(r"scripts/release/tor_bundle\.py\s+stage\b")


def load_yaml(path):
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment, not logic
        raise SystemExit(
            "check_tor_pin_targets: PyYAML is required to read the workflow "
            "structurally. Install python3-yaml (the grep-gates job does)."
        ) from exc
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except OSError as exc:
        raise Unreadable(f"{path.name}: cannot be read: {exc}") from exc
    except yaml.YAMLError as exc:
        raise Unreadable(f"{path.name}: not valid YAML: {exc}") from exc


class Unreadable(Exception):
    """A file this gate must read could not be parsed."""


def script_lines(run):
    """The lines of a step's script that execute: no blank lines, no comments."""
    return [
        line for line in (run or "").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def matrix_hosts(job):
    """Every `host` value a job's matrix assigns, at any nesting."""
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "host" and isinstance(value, str):
                    found.add(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk((job.get("strategy") or {}).get("matrix") or {})
    return found


def staged_hosts(workflow):
    """Hosts with a job that both names them in its matrix and stages."""
    hosts = set()
    for job in (workflow.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        stages = any(
            STAGE_RE.search(line)
            for step in job.get("steps") or []
            if isinstance(step, dict)
            for line in script_lines(step.get("run"))
        )
        if stages:
            hosts |= matrix_hosts(job)
    return hosts


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


def pending_rows(root):
    """(host, work item) for each row that is unavailable only for now.
    Empty when the pin file does not load: `check` reports that."""
    tor_bundle = load_tor_bundle(root)
    try:
        doc = tor_bundle.load_pins(root / "config" / "tor_pins.json")
    except tor_bundle.Refused:
        return []
    return [
        (row["gitian_host"], row["pending"])
        for row in doc["targets"]
        if "pending" in row
    ]


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
    try:
        verified = staged_hosts(load_yaml(workflow) or {})
        workflow_text = workflow.read_text(encoding="utf-8")
    except (Unreadable, OSError) as exc:
        verified = set()
        workflow_text = ""
        problems.append(str(exc))
    for row in pinned:
        if row["bundle_version"] in workflow_text:
            problems.append(
                f"{workflow.name}: restates the bundle version {row['bundle_version']}; "
                "it reads config/tor_pins.json and must not carry a copy"
            )
        if row["gitian_host"] not in verified:
            problems.append(
                f"{workflow.name}: no job both names the pinned host {row['gitian_host']} "
                "in its matrix and stages it through scripts/release/tor_bundle.py"
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
    parser.add_argument(
        "--refuse-pending",
        action="store_true",
        help="fail while any target is unavailable only because its pin is pending",
    )
    args = parser.parse_args()
    problems = check(args.root)
    pending = pending_rows(args.root)
    for host, item in pending:
        print(f"tor pin targets: {host} is unavailable pending {item}")
    if args.refuse_pending:
        for host, item in pending:
            problems.append(
                f"{host} is still pending {item}: pin it, or rule it unavailable, "
                "before the startup refusal lands"
            )
    if problems:
        for problem in problems:
            print(f"tor pin targets: {problem}", file=sys.stderr)
        return 1
    print("tor pin targets: every built host has one disposition; pin records agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
