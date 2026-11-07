#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A red push run on `dev` reaches the dev-red reporter from every job.

`dev` has no merge queue, so the push runs of `build.yml` and
`rust-audit-test.yml` on `dev` are the first to test what the merges made
(06-branching.mdc). Each ends in a job that calls
`report-dev-red.yml`, which opens or threads an issue. That job reads
only the results of the jobs it `needs`: a job added to the workflow and
left out of that list could go red on `dev` with no issue. This holds the
list, and the condition, to the file.

What passes, in each of the two workflows:

* exactly one job calls `./.github/workflows/report-dev-red.yml`;
* its `needs` is every other job in the file, no more and no fewer;
* its `if` is exactly `CONDITION` below: a push run on `dev`, not
  cancelled as a whole, in which a needed job failed or was cancelled. A
  job past its `timeout-minutes` is cancelled, not failed, and
  `failure()` does not see it; a run superseded by a newer merge is
  cancelled as a whole and reports nothing. An exact match, because a
  check for the parts would pass the same parts joined by `||`.

Rule 47: the two workflows are named here, so a renamed or deleted one,
or a reporter removed from either, fails by name rather than leaving
nothing to grade.
"""

from __future__ import annotations

import os
import sys

import yaml

from check_workflows_parse import StrictLoader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
REPORTER = "./.github/workflows/report-dev-red.yml"
SUBJECTS = ("build.yml", "rust-audit-test.yml")
CONDITION = (
    "${{ !cancelled() && github.event_name == 'push' && github.ref == 'refs/heads/dev' && "
    "(contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled')) }}"
)


def problems_in(filename: str, doc: object) -> list[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [f"{filename}: no jobs mapping"]
    jobs = doc["jobs"]
    callers = [n for n, j in jobs.items() if isinstance(j, dict) and j.get("uses") == REPORTER]
    if len(callers) != 1:
        return [f"{filename}: {len(callers)} jobs call {REPORTER}, not exactly one"]
    name = callers[0]
    job = jobs[name]
    problems = []
    needs = job.get("needs", [])
    needs = {needs} if isinstance(needs, str) else set(needs)
    others = set(jobs) - {name}
    if missing := sorted(others - needs):
        problems.append(
            f"{filename}: {name} does not need {', '.join(missing)}; "
            "a red there on dev would open no issue"
        )
    if extra := sorted(needs - others):
        problems.append(f"{filename}: {name} needs {', '.join(extra)}, which is not a job here")
    if job.get("if") != CONDITION:
        problems.append(
            f"{filename}: {name}'s `if` is {job.get('if')!r}, not the "
            f"reporting condition {CONDITION!r}"
        )
    return problems


def selftest() -> int:
    good = {
        "jobs": {
            "a": {"runs-on": "x"},
            "b": {"needs": "a", "runs-on": "x"},
            "r": {
                "needs": ["a", "b"],
                "if": CONDITION,
                "uses": REPORTER,
            },
        }
    }
    cases = [("a reporter needing every job", good, 0)]

    def variant(edit):
        doc = yaml.safe_load(yaml.safe_dump(good))
        edit(doc["jobs"])
        return doc

    cases += [
        ("a job left out of needs", variant(lambda j: j["r"].__setitem__("needs", ["a"])), 1),
        ("a need that is not a job", variant(lambda j: j["r"].__setitem__("needs", ["a", "b", "c"])), 1),
        ("no reporter", variant(lambda j: j.pop("r")), 1),
        ("two reporters", variant(lambda j: j.__setitem__("s", dict(j["r"]))), 1),
        ("a reporter that reports PR runs too", variant(lambda j: j["r"].__setitem__(
            "if", CONDITION.replace("github.event_name == 'push' && ", ""))), 1),
        ("a reporter blind to a timed-out job", variant(lambda j: j["r"].__setitem__(
            "if", "${{ failure() && github.event_name == 'push' && github.ref == 'refs/heads/dev' }}")), 1),
        ("the same parts joined by ||", variant(lambda j: j["r"].__setitem__(
            "if", CONDITION.replace("github.event_name == 'push' &&", "github.event_name == 'push' ||"))), 1),
        ("no condition", variant(lambda j: j["r"].pop("if")), 1),
    ]
    bad = []
    for label, doc, want in cases:
        got = len(problems_in("fixture.yml", doc))
        if got != want:
            bad.append(f"{label}: {got} problem(s), expected {want}")
    if bad:
        for b in bad:
            print(f"SELFTEST FAIL: {b}")
        return 1
    print(
        "SELFTEST PASS: a reporter needing every job passes; a missing or extra "
        "need, no reporter, two reporters, and any condition but the reporting "
        "one (PR runs, blind to a timeout, joined by ||, absent) each fail"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print("usage: check_dev_red_reporter.py [--selftest]", file=sys.stderr)
        return 2
    problems = []
    for filename in SUBJECTS:
        path = os.path.join(WORKFLOWS, filename)
        try:
            with open(path, encoding="utf-8") as f:
                doc = yaml.load(f, Loader=StrictLoader)
        except (OSError, yaml.YAMLError) as e:
            problems.append(f"{filename}: cannot read it: {e}")
            continue
        problems += problems_in(filename, doc)
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(
        f"dev-red reporter: {' and '.join(SUBJECTS)} each end in one reporter "
        "that needs every other job and reports a failed or timed-out job of a "
        "push run on dev"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
