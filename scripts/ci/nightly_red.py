#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The red legs of a nightly run, a timeout among them.

The nightly workflows (`nightly.yml`, `nightly-live-daemon-slow.yml`) end in
a `report-red` job that opens a tracking issue for each red leg, or comments
on the open one. It used to run on `failure()` alone, and a job past its
`timeout-minutes` ends `cancelled`, not `failure`: on 2026-11-21 the slow
lane's `dev` leg was cut at 240 minutes and `economics-sim-ignored` at 180 on
both branches, and no issue opened. A timeout is a red. The reporter now runs
on every scheduled run that was not cancelled as a whole, and this names
what it reports:

  - a job that ended `failure` (or `timed_out`) is red;
  - a job that ended `cancelled` is red, and is named a timeout when it ran
    its whole `timeout-minutes` (read from the workflow file the run used,
    the reporter's checkout), and a cancellation short of it otherwise;
  - a run cancelled as a whole (a newer run superseded it, or a person
    stopped it) reports nothing: the reporter's `if` is `!cancelled()`, so
    it does not run. The nightly workflows have no concurrency group, so a
    scheduled run is never superseded; a run cancelled by hand reports
    nothing because the person who cancelled it already knows (ruled
    2026-11-22). A job past its timeout leaves `!cancelled()` true for the
    reporter: a scratch probe on 2026-11-22 ran both this reporter's and
    the dev-red reporter's condition after a 1-minute timeout, each ran,
    and `--run` named the leg "timed out"; runs cancelled while running and
    while waiting each reported nothing. Read afterwards, a run whose job timed out also
    concludes `cancelled` (2026-11-21), so `--run` judges each job by its
    own record, and a cancellation short of the limit is named as one.

  nightly_red.py --run RUN_ID --workflow FILE   the red legs, as JSON
  nightly_red.py --check                        the reporters' `needs` and `if`
  nightly_red.py --selftest

`--run` calls `gh api` with GITHUB_REPOSITORY and GH_TOKEN from the workflow.
Each red leg: name, key (the job's id in FILE), url, conclusion, minutes (as
run), limit (its `timeout-minutes`), and kind: `failed`, `timed out` or
`cancelled`.

`--check` holds each nightly workflow's `report-red` job to the file: it
`needs` every other job, no more and no fewer, and its `if` is exactly
`CONDITION`. A job left out of `needs` could go red with no issue; a
condition on `failure()` misses every timeout; one on `always()` would
report a run a newer run superseded. Rule 47: the workflows are named here,
so a renamed one, or a reporter removed from one, fails by name.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_workflows_parse import StrictLoader  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

REPORTER = "report-red"
CONDITION = "${{ !cancelled() && (github.event_name == 'schedule' || inputs.report) }}"
# The nightly workflows whose reds reach a human through their own
# `report-red` job (the dev-red reporter's subjects are graded by
# check_dev_red_reporter.py).
SUBJECTS = ("nightly.yml", "nightly-live-daemon-slow.yml")

RED = {"failure", "timed_out"}
# Seconds of slack under the limit: GitHub cuts the job at its limit and
# stamps the completion a few seconds later, so a job that ran its limit
# reads a little over it, never far under.
SLACK_SECONDS = 60


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def job_key(name: str) -> str:
    """A matrix leg is named `<key> (<values>)`; a plain job, `<key>`."""
    return name.split(" (", 1)[0]


def limits(workflow: dict) -> dict[str, int]:
    """Each job's `timeout-minutes`, by job id."""
    out = {}
    for key, job in (workflow.get("jobs") or {}).items():
        if isinstance(job, dict) and isinstance(job.get("timeout-minutes"), int):
            out[key] = job["timeout-minutes"]
    return out


def classify(jobs: list[dict], workflow: dict) -> list[dict]:
    """The red legs among `jobs` (the jobs API's records)."""
    limit_of = limits(workflow)
    red = []
    for job in jobs:
        conclusion = job.get("conclusion")
        if conclusion not in RED and conclusion != "cancelled":
            continue
        key = job_key(job["name"])
        seconds = None
        if job.get("started_at") and job.get("completed_at"):
            seconds = (stamp(job["completed_at"]) - stamp(job["started_at"])).total_seconds()
        limit = limit_of.get(key)
        if conclusion == "timed_out":
            kind = "timed out"
        elif conclusion in RED:
            kind = "failed"
        elif limit is not None and seconds is not None and seconds >= limit * 60 - SLACK_SECONDS:
            kind = "timed out"
        else:
            kind = "cancelled"
        red.append({
            "name": job["name"],
            "key": key,
            "url": job.get("html_url", ""),
            "conclusion": conclusion,
            "minutes": None if seconds is None else int(seconds // 60),
            "limit": limit,
            "kind": kind,
        })
    return red


def gh(path: str) -> dict:
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def problems_in(filename: str, doc: object) -> list[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [f"{filename}: no jobs mapping"]
    jobs = doc["jobs"]
    if REPORTER not in jobs:
        return [f"{filename}: no `{REPORTER}` job: its reds reach no one"]
    job = jobs[REPORTER]
    problems = []
    needs = job.get("needs", [])
    needs = {needs} if isinstance(needs, str) else set(needs)
    others = set(jobs) - {REPORTER}
    if missing := sorted(others - needs):
        problems.append(f"{filename}: {REPORTER} does not need {', '.join(missing)}; a red there would open no issue")
    if extra := sorted(needs - others):
        problems.append(f"{filename}: {REPORTER} needs {', '.join(extra)}, which is not a job here")
    if job.get("if") != CONDITION:
        problems.append(f"{filename}: {REPORTER}'s `if` is {job.get('if')!r}, not {CONDITION!r}")
    return problems


# nightly-live-daemon-slow.yml's jobs that run gate lanes: one set of steps,
# written out in each (actionlint cannot check a job behind a YAML alias), so
# a fix to one copy that misses the other is caught here.
LANE_JOBS = ("nightly-live-daemon-slow.yml", ("slow-gates", "body-fill"))


def copies_differ(filename: str, doc: object, names: tuple[str, ...]) -> list[str]:
    jobs = doc.get("jobs", {}) if isinstance(doc, dict) else {}
    missing = [n for n in names if n not in jobs]
    if missing:
        return [f"{filename}: no {', '.join(missing)} job; the lane jobs are named here"]
    first = names[0]
    problems = []
    for other in names[1:]:
        for part in ("container", "steps"):
            if jobs[first].get(part) != jobs[other].get(part):
                problems.append(f"{filename}: {other}'s {part} differ from {first}'s; the lane jobs run one set")
    return problems


def check() -> int:
    problems = []
    for filename in SUBJECTS:
        path = os.path.join(WORKFLOWS, filename)
        if not os.path.isfile(path):
            problems.append(f"{filename}: missing; it is named here as a nightly reporter's subject")
            continue
        with open(path, encoding="utf-8") as f:
            doc = yaml.load(f, Loader=StrictLoader)
        problems += problems_in(filename, doc)
        if filename == LANE_JOBS[0]:
            problems += copies_differ(filename, doc, LANE_JOBS[1])
    for p in problems:
        print(f"FATAL: {p}")
    if not problems:
        print(f"nightly reporters: {', '.join(SUBJECTS)} each need every job and report on {CONDITION}; "
              f"{LANE_JOBS[0]}'s lane jobs run one set of steps")
    return 1 if problems else 0


def job(name: str, conclusion: str | None, minutes: float) -> dict:
    start = "2026-11-21T11:29:25Z"
    end = datetime.fromtimestamp(stamp(start).timestamp() + minutes * 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"name": name, "conclusion": conclusion, "started_at": start, "completed_at": end, "html_url": "u"}


def selftest() -> int:
    workflow = {"jobs": {"slow-gates": {"timeout-minutes": 240}, "economics-sim-ignored": {"timeout-minutes": 180},
                         "store-ignored": {"timeout-minutes": 60}, REPORTER: {}}}
    bad = []

    def expect(label, jobs, want):
        got = [(r["name"], r["kind"]) for r in classify(jobs, workflow)]
        if got != want:
            bad.append(f"{label}: {got} != {want}")

    # 2026-11-21: the slow lane's dev leg ran 240.07 minutes against a limit of 240.
    expect("a planted timeout is a red, named as one",
           [job("slow-gates (dev)", "cancelled", 240.07), job("slow-gates (main)", "success", 188)],
           [("slow-gates (dev)", "timed out")])
    expect("a failed leg is a red", [job("store-ignored (dev)", "failure", 12)], [("store-ignored (dev)", "failed")])
    expect("the API's own timed_out is a timeout", [job("store-ignored (main)", "timed_out", 60)],
           [("store-ignored (main)", "timed out")])
    expect("a leg cancelled short of its limit is red, not called a timeout",
           [job("economics-sim-ignored (dev)", "cancelled", 30)], [("economics-sim-ignored (dev)", "cancelled")])
    expect("green, skipped and unfinished legs are not red",
           [job("store-ignored (dev)", "success", 5), job("store-ignored (main)", "skipped", 0),
            job(REPORTER, None, 0)], [])
    expect("a job the file does not time is red, not called a timeout",
           [job("renamed-job (dev)", "cancelled", 400)], [("renamed-job (dev)", "cancelled")])

    # The reporter's `if`: a superseded run never reaches it.
    good = {"jobs": {"a": {}, "b": {}, REPORTER: {"needs": ["a", "b"], "if": CONDITION}}}

    def variant(edit):
        doc = yaml.safe_load(yaml.safe_dump(good))
        edit(doc["jobs"])
        return doc

    for label, doc, want in (
        ("a reporter needing every job, on the condition", good, 0),
        ("a job left out of needs", variant(lambda j: j[REPORTER].__setitem__("needs", ["a"])), 1),
        ("a need that is not a job", variant(lambda j: j[REPORTER].__setitem__("needs", ["a", "b", "c"])), 1),
        ("a reporter on failure() only, which misses every timeout",
         variant(lambda j: j[REPORTER].__setitem__("if", CONDITION.replace("!cancelled()", "failure()"))), 1),
        ("a reporter on always(), which reports a superseded run",
         variant(lambda j: j[REPORTER].__setitem__("if", CONDITION.replace("!cancelled()", "always()"))), 1),
        ("the parts joined by ||",
         variant(lambda j: j[REPORTER].__setitem__("if", CONDITION.replace("&&", "||"))), 1),
        ("no reporter", variant(lambda j: j.pop(REPORTER)), 1),
    ):
        got = len(problems_in("fixture.yml", doc))
        if got != want:
            bad.append(f"{label}: {got} problem(s), expected {want}")

    lanes = {"jobs": {"x": {"container": {"image": "i"}, "steps": [{"run": "a"}]},
                      "y": {"container": {"image": "i"}, "steps": [{"run": "a"}]}}}
    for label, edit, want in (
        ("two lane jobs with one set of steps", lambda j: None, 0),
        ("a step changed in one copy", lambda j: j["y"]["steps"].append({"run": "b"}), 1),
        ("a lane job gone", lambda j: j.pop("y"), 1),
    ):
        doc = yaml.safe_load(yaml.safe_dump(lanes))
        edit(doc["jobs"])
        got = len(copies_differ("fixture.yml", doc, ("x", "y")))
        if got != want:
            bad.append(f"{label}: {got} problem(s), expected {want}")

    if bad:
        for b in bad:
            print(f"SELFTEST FAIL: {b}")
        return 1
    print("SELFTEST PASS: a leg cut at its limit is a timeout and red; failed and API-timed-out legs are red; "
          "a cancellation short of its limit, or of an untimed job, is red and not called a timeout; green, "
          "skipped and unfinished legs are not; the reporter needs every job and runs on !cancelled(), so a "
          "superseded run reports nothing, and failure(), always(), || and a missing reporter each fail; "
          "lane jobs whose steps differ, or one gone, fail")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return check()
    if len(argv) == 4 and argv[0] == "--run" and argv[2] == "--workflow":
        repo = os.environ["GITHUB_REPOSITORY"]
        jobs = []
        page = 1
        while True:
            got = gh(f"repos/{repo}/actions/runs/{argv[1]}/jobs?per_page=100&page={page}")["jobs"]
            jobs += got
            if len(got) < 100:
                break
            page += 1
        with open(argv[3], encoding="utf-8") as f:
            workflow = yaml.load(f, Loader=StrictLoader)
        print(json.dumps(classify(jobs, workflow)))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
