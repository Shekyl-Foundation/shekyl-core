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
with a 10-minute floor. A workflow states its exceptions beside the value.

What passes: every job without a reusable `uses` has `timeout-minutes` as
a whole number from 1 to 360. An expression is refused, because this gate
cannot read what it evaluates to. A reusable workflow's jobs are graded in
their own file.

Scope: the live workflows (`.yml`, `.yaml`). A `.disabled` file does not
run; renaming it back makes it live, and the PR that does so runs this.

Rule 47: a workflows directory with fewer step jobs than on 2026-11-06 is a
missing subject, not a pass. A deleted workflow lowers the count, and the
PR that deletes it lowers `MIN_STEP_JOBS` with it.
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

# Step jobs in the live workflows on 2026-11-06.
MIN_STEP_JOBS = 62


def problems_in(filename: str, doc: object) -> tuple[list[str], int]:
    """The problems in one parsed workflow, and how many step jobs it has."""
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [f"{filename}: no jobs mapping"], 0
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
    for filename in sorted(os.listdir(WORKFLOWS)):
        if not filename.endswith(LIVE_SUFFIXES):
            continue
        with open(os.path.join(WORKFLOWS, filename), encoding="utf-8") as handle:
            doc = yaml.load(handle, Loader=StrictLoader)
        found, count = problems_in(filename, doc)
        problems.extend(found)
        graded += count
    if graded < MIN_STEP_JOBS:
        problems.append(
            f"job timeouts: {graded} step jobs graded, fewer than the "
            f"{MIN_STEP_JOBS} on 2026-11-06; a workflow went missing, or one "
            "was deleted without lowering MIN_STEP_JOBS"
        )
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    print(f"job timeouts: {graded} step jobs, each with its own timeout")
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
