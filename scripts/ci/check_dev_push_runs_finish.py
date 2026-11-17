#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A run on `dev` that has started is not cancelled by the next merge.

Every push to `dev` shares one ref, so a workflow whose concurrency group
is its ref and whose `cancel-in-progress` is `true` cancels the running
`dev` run at each merge. A run that takes longer than the gap between
merges then never finishes, and `dev` has no verdict for hours: from
2026-11-10 to 11-17, 50 of 84 Rust runs on `dev` were cancelled, and
1,595 runner-minutes went to runs that reported nothing.

What passes: each workflow named in `FINISHING` triggers on push to
`dev`, and its top-level concurrency has `cancel-in-progress` equal to
`CANCEL_ONLY_PRS`. A pull request's newer push still cancels its older
run, since that run tests a head nobody will merge. Any other event
queues: the running run finishes, one run waits, and a newer push
replaces the waiting one, so a burst of merges still costs one more run,
not one per merge. A job-level `cancel-in-progress` in those files is
refused too, because it would cancel the job the workflow keeps.

The list holds the workflows whose `dev` runs outlast the gap between
merges. A workflow that grows past that gap joins it in the PR that
lengthens it; the short gates may keep `true`, because the next run
tests every commit the cancelled one held.

Rule 47: a named file that is missing, does not parse, or no longer
pushes on `dev` fails by name, since this gate would otherwise grade
nothing for it.
"""

from __future__ import annotations

import os
import sys

import yaml

from check_workflows_parse import StrictLoader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The one form: a pull request cancels its own superseded run; a push,
# a schedule or a dispatch never cancels a run that has started.
CANCEL_ONLY_PRS = "${{ github.event_name == 'pull_request' }}"

# Each with its median full run on `dev`, 2026-11-10 to 11-17, in
# runner-minutes (wall-minutes in a queue run longer).
FINISHING = (
    "benchmarks.yml",  # publishes the baseline, then raises the drift alarm
    "build.yml",  # 77
    "fuzz-harness.yml",  # 22, but 60 wall-minutes behind the queue
    "rust-audit-test.yml",  # 123
)


def pushes_on_dev(doc: dict) -> bool:
    trigger = doc.get("on")
    if not isinstance(trigger, dict) or "push" not in trigger:
        return False
    push = trigger["push"]
    if push is None:
        return True
    if not isinstance(push, dict):
        return False
    if "branches" in push:
        return "dev" in (push["branches"] or [])
    if "branches-ignore" in push:
        return "dev" not in (push["branches-ignore"] or [])
    # A tags filter alone runs on tag pushes only.
    return "tags" not in push and "tags-ignore" not in push


def problems_in(filename: str, doc: object) -> list[str]:
    if not isinstance(doc, dict):
        return [f"{filename}: not a mapping, so nothing in it is graded"]
    if not pushes_on_dev(doc):
        return [
            f"{filename}: no longer runs on push to dev; take it off "
            "FINISHING in check_dev_push_runs_finish.py"
        ]
    problems: list[str] = []
    concurrency = doc.get("concurrency")
    if not isinstance(concurrency, dict):
        problems.append(
            f"{filename}: no concurrency mapping, so a pull request's "
            "superseded runs stack behind each other"
        )
    else:
        value = concurrency.get("cancel-in-progress")
        if not isinstance(value, str) or value.strip() != CANCEL_ONLY_PRS:
            problems.append(
                f"{filename}: cancel-in-progress is {value!r}; it must be "
                f"{CANCEL_ONLY_PRS!r}, so a merge does not cancel the dev run "
                "before it"
            )
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            job_concurrency = job.get("concurrency")
            if isinstance(job_concurrency, dict) and "cancel-in-progress" in job_concurrency:
                problems.append(
                    f"{filename}: job {name} sets its own cancel-in-progress, "
                    "which would cancel the job the workflow keeps"
                )
    return problems


def check_tree() -> int:
    problems: list[str] = []
    for filename in FINISHING:
        path = os.path.join(WORKFLOWS, filename)
        if not os.path.isfile(path):
            problems.append(
                f"{filename}: missing; take it off FINISHING in "
                "check_dev_push_runs_finish.py if it was retired"
            )
            continue
        with open(path, encoding="utf-8") as handle:
            try:
                doc = yaml.load(handle, Loader=StrictLoader)
            except yaml.YAMLError as error:
                problems.append(f"{filename}: does not parse, so nothing in it is graded: {error}")
                continue
        problems.extend(problems_in(filename, doc))
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    print(f"dev push runs finish: {len(FINISHING)} workflows, each cancels only a pull request's run")
    return 0


def selftest() -> int:
    def doc(cancel: object, push: object = None, jobs: dict | None = None) -> dict:
        return {
            "on": {"push": push if push is not None else {"branches": ["dev"]}, "pull_request": None},
            "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": cancel},
            "jobs": jobs or {"a": {"runs-on": "x"}},
        }

    cases = [
        ("the one form", doc(CANCEL_ONLY_PRS), 0),
        ("the one form, padded", doc(f" {CANCEL_ONLY_PRS} "), 0),
        ("true", doc(True), 1),
        ("the string true", doc("true"), 1),
        ("false", doc(False), 1),
        ("the old dev-only form", doc("${{ github.ref != 'refs/heads/dev' }}"), 1),
        ("absent", {**doc(CANCEL_ONLY_PRS), "concurrency": {"group": "x"}}, 1),
        ("no concurrency", {k: v for k, v in doc(CANCEL_ONLY_PRS).items() if k != "concurrency"}, 1),
        ("pushes on main only", doc(CANCEL_ONLY_PRS, push={"branches": ["main"]}), 1),
        ("no push trigger", {**doc(CANCEL_ONLY_PRS), "on": {"pull_request": None}}, 1),
        ("pushes on tags only", doc(CANCEL_ONLY_PRS, push={"tags": ["v*"]}), 1),
        ("pushes on every branch", {**doc(CANCEL_ONLY_PRS), "on": {"push": None}}, 0),
        ("ignores main only", doc(CANCEL_ONLY_PRS, push={"branches-ignore": ["main"]}), 0),
        (
            "a job cancels itself",
            doc(CANCEL_ONLY_PRS, jobs={"a": {"concurrency": {"group": "g", "cancel-in-progress": True}}}),
            1,
        ),
        ("not a mapping", ["a"], 1),
    ]
    failed = 0
    for label, fixture, want in cases:
        problems = problems_in("fixture.yml", fixture)
        if len(problems) != want:
            print(f"selftest FAIL: {label}: {len(problems)} problem(s), want {want}: {problems}")
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
