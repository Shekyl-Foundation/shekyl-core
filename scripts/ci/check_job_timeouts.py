#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every job that runs steps carries its own `timeout-minutes`.

A job without one gets the platform's 360 minutes. A hang there holds a
runner for six hours and reports nothing until then; on a self-hosted
runner it holds the device. On 2026-11-06, 33 of the 63 jobs had no
value, among them every job in `build.yml` and `rust-audit-test.yml`.
Each was sized at about twice its p90 over its recent successful runs,
with a 10-minute floor; the figure used is written beside each value.

What passes: every job without a reusable `uses` has `timeout-minutes` as
a whole number from 1 to 360. An expression is refused, because this gate
cannot read what it evaluates to. A reusable workflow's jobs are graded in
their own file.

Scope: the live workflows (`.yml`, `.yaml`). A `.disabled` file does not
run; renaming it back makes it live, and the PR that does so runs this.

Rule 47, per file rather than by a global count: every live workflow
must parse and contribute at least one job, graded or a reusable call. A
parser that silently saw nothing, or a file whose jobs went missing, fails
by name; deleting a whole workflow needs no edit here. An empty or missing
workflows directory fails too.
"""

from __future__ import annotations

import os
import sys

import yaml

from check_workflows_parse import StrictLoader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
LIVE_SUFFIXES = (".yml", ".yaml")

# The platform's cap; a value above it is not honoured.
MAX_MINUTES = 360


def problems_in(filename: str, doc: object) -> tuple[list[str], int]:
    """The problems in one parsed workflow, and how many step jobs it has."""
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [f"{filename}: no jobs mapping"], 0
    if not doc["jobs"]:
        return [f"{filename}: no jobs, so nothing in it is graded"], 0
    problems: list[str] = []
    graded = 0
    for name, job in doc["jobs"].items():
        if not isinstance(job, dict):
            problems.append(f"{filename}: job {name} is not a mapping")
            continue
        if "uses" in job:
            continue
        graded += 1
        if "timeout-minutes" not in job:
            problems.append(
                f"{filename}: job {name} has no timeout-minutes, so a hang "
                f"holds its runner for the platform's {MAX_MINUTES} min"
            )
            continue
        value = job["timeout-minutes"]
        # `bool` is an `int` in Python; `true` is not a number of minutes.
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(
                f"{filename}: job {name} timeout-minutes is {value!r}, "
                "not a whole number"
            )
        elif not 1 <= value <= MAX_MINUTES:
            problems.append(
                f"{filename}: job {name} timeout-minutes is {value}, "
                f"outside 1..{MAX_MINUTES}"
            )
    return problems, graded


def check_tree() -> int:
    if not os.path.isdir(WORKFLOWS):
        print(f"job timeouts: {WORKFLOWS} is missing", file=sys.stderr)
        return 1
    problems: list[str] = []
    graded = 0
    live = [name for name in sorted(os.listdir(WORKFLOWS)) if name.endswith(LIVE_SUFFIXES)]
    if not live:
        problems.append(f"job timeouts: no live workflow in {WORKFLOWS}")
    for filename in live:
        with open(os.path.join(WORKFLOWS, filename), encoding="utf-8") as handle:
            try:
                doc = yaml.load(handle, Loader=StrictLoader)
            except yaml.YAMLError as error:
                problems.append(f"{filename}: does not parse, so nothing in it is graded: {error}")
                continue
        found, count = problems_in(filename, doc)
        problems.extend(found)
        graded += count
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    print(f"job timeouts: {len(live)} workflows, {graded} step jobs, each with its own timeout")
    return 0


def selftest() -> int:
    cases = [
        ("a job with a timeout", {"jobs": {"a": {"runs-on": "x", "timeout-minutes": 10}}}, 0),
        ("a job without one", {"jobs": {"a": {"runs-on": "x"}}}, 1),
        ("an expression", {"jobs": {"a": {"timeout-minutes": "${{ inputs.t }}"}}}, 1),
        ("a boolean", {"jobs": {"a": {"timeout-minutes": True}}}, 1),
        ("zero", {"jobs": {"a": {"timeout-minutes": 0}}}, 1),
        ("above the cap", {"jobs": {"a": {"timeout-minutes": 361}}}, 1),
        ("a reusable call", {"jobs": {"a": {"uses": "./.github/workflows/b.yml"}}}, 0),
        ("no jobs", {"on": "push"}, 1),
        ("an empty jobs mapping", {"on": "push", "jobs": {}}, 1),
    ]
    failed = 0
    for label, doc, want in cases:
        problems, _ = problems_in("fixture.yml", doc)
        if len(problems) != want:
            print(f"selftest FAIL: {label}: {len(problems)} problem(s), want {want}")
            failed = 1
    if not failed:
        print(f"selftest: {len(cases)} cases")
    return failed


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    return check_tree()


if __name__ == "__main__":
    raise SystemExit(main())
