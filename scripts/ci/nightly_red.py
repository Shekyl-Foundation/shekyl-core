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
  - a job that ended `cancelled` is red, and is named by GitHub's own
    record of why: its check run carries the annotation "The job has
    exceeded the maximum execution time of <limit>" when it timed out, and
    "The run was canceled by @<who>." when a person stopped it (both seen
    on 2026-11-22: the scratch probe's 1-minute sleeper, and the market
    walk's dispatch cancelled by hand). A timeout is named one only on that
    annotation, never from the job's length against its limit;
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
    own record.

  nightly_red.py --run RUN_ID                   the red legs, as JSON
  nightly_red.py --check                        the reporters' `needs` and `if`
  nightly_red.py --selftest

`--run` calls `gh api` with GITHUB_REPOSITORY and GH_TOKEN from the workflow.
Each red leg: name, key (the job's id in its workflow), url, conclusion,
minutes (as run; null when GitHub recorded no start or end), kind (`failed`,
`timed out` or `cancelled`) and why (GitHub's annotation that says why a
cancelled job stopped, verbatim; null when there is none).

`--check` holds each nightly workflow's `report-red` job to the file: it
`needs` every other job, no more and no fewer, its `if` is exactly
`CONDITION`, and its script names each of those jobs (`'<job>'`), routing a
red leg by its `key`. A job left out of `needs` could go red with no issue;
a job the script does not name reaches the script and fails it with no
issue (a planner job has no matrix values to read from its name); a
condition on `failure()` misses every timeout; one on `always()` would
report a run a newer run superseded. Rule 47: the workflows are named here,
so a renamed one, or a reporter removed from one, fails by name.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
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
# GitHub's annotation on a job it stopped at its `timeout-minutes`.
TIMEOUT = re.compile(r"^The job has exceeded the maximum execution time of \S+$")
# GitHub's annotations on any cancelled job: the generic line, not a reason.
GENERIC = "The operation was canceled."


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def job_key(name: str) -> str:
    """A matrix leg is named `<key> (<values>)`; a plain job, `<key>`."""
    return name.split(" (", 1)[0]


def classify(jobs: list[dict], annotations: Callable[[int], list[str]]) -> list[dict]:
    """The red legs among `jobs` (the jobs API's records). `annotations`
    gives a job's check-run annotation messages; it is asked only for a
    cancelled job."""
    red = []
    for job in jobs:
        conclusion = job.get("conclusion")
        if conclusion not in RED and conclusion != "cancelled":
            continue
        seconds = None
        if job.get("started_at") and job.get("completed_at"):
            seconds = (stamp(job["completed_at"]) - stamp(job["started_at"])).total_seconds()
        why = None
        if conclusion == "timed_out":
            kind = "timed out"
        elif conclusion in RED:
            kind = "failed"
        else:
            said = [m for m in annotations(job["id"]) if m != GENERIC]
            timed_out = [m for m in said if TIMEOUT.match(m)]
            kind = "timed out" if timed_out else "cancelled"
            why = (timed_out or said or [None])[0]
        red.append({
            "name": job["name"],
            "key": job_key(job["name"]),
            "url": job.get("html_url", ""),
            "conclusion": conclusion,
            "minutes": None if seconds is None else int(seconds // 60),
            "kind": kind,
            "why": why,
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
    if isinstance(needs, str):
        needs = [needs]
    if not isinstance(needs, list) or not all(isinstance(n, str) for n in needs):
        return [f"{filename}: {REPORTER}'s `needs` is {needs!r}, not a job id or a list of them"]
    needs = set(needs)
    others = set(jobs) - {REPORTER}
    if missing := sorted(others - needs):
        problems.append(f"{filename}: {REPORTER} does not need {', '.join(missing)}; a red there would open no issue")
    if extra := sorted(needs - others):
        problems.append(f"{filename}: {REPORTER} needs {', '.join(extra)}, which is not a job here")
    if job.get("if") != CONDITION:
        problems.append(f"{filename}: {REPORTER}'s `if` is {job.get('if')!r}, not {CONDITION!r}")
    scripts = [str((st.get("with") or {}).get("script", "")) for st in job.get("steps", [])
               if isinstance(st, dict) and str(st.get("uses", "")).startswith("actions/github-script")]
    if len(scripts) != 1:
        problems.append(f"{filename}: {REPORTER} has {len(scripts)} github-script steps, not the one that opens issues")
    elif unrouted := sorted(n for n in needs & others if f"'{n}'" not in scripts[0]):
        problems.append(f"{filename}: {REPORTER}'s script names no route for {', '.join(unrouted)}; "
                        f"a red there would fail the reporter and open no issue")
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
        print(f"nightly reporters: {', '.join(SUBJECTS)} each need every job, name a route for each, "
              f"and report on {CONDITION}; {LANE_JOBS[0]}'s lane jobs run one set of steps")
    return 1 if problems else 0


def job(name: str, conclusion: str | None, minutes: float | None, job_id: int = 0) -> dict:
    start = "2026-11-21T11:29:25Z"
    if minutes is None:
        return {"id": job_id, "name": name, "conclusion": conclusion, "started_at": start,
                "completed_at": None, "html_url": "u"}
    end = datetime.fromtimestamp(stamp(start).timestamp() + minutes * 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"id": job_id, "name": name, "conclusion": conclusion, "started_at": start, "completed_at": end,
            "html_url": "u"}


def selftest() -> int:
    bad = []
    # GitHub's annotations, verbatim from 2026-11-22: the scratch probe's
    # 1-minute sleeper (a timeout), and the market walk's dispatch cancelled
    # by hand.
    said = {
        1: ["The job has exceeded the maximum execution time of 1m0s", GENERIC],
        2: ["The run was canceled by @radawson.", GENERIC],
        3: [GENERIC],
        4: ["The job has exceeded the maximum execution time of 5h30m0s", GENERIC],
    }
    asked = []

    def annotations(job_id):
        asked.append(job_id)
        return said.get(job_id, [])

    def expect(label, jobs, want):
        got = [(r["name"], r["kind"], r["why"]) for r in classify(jobs, annotations)]
        if got != want:
            bad.append(f"{label}: {got} != {want}")

    expect("a timeout is named by GitHub's annotation, and red",
           [job("slow-gates (dev)", "cancelled", 1.2, 1), job("slow-gates (main)", "success", 188)],
           [("slow-gates (dev)", "timed out", said[1][0])])
    # Copilot on #1514: a duration rule called a 1-minute job cancelled
    # after seconds a timeout. The annotation decides, not the length.
    expect("a job cancelled by hand seconds into a 1-minute limit is not a timeout",
           [job("store-ignored (dev)", "cancelled", 0.1, 2)],
           [("store-ignored (dev)", "cancelled", "The run was canceled by @radawson.")])
    expect("a job cancelled at the length of its limit, by hand, is not a timeout",
           [job("slow-gates (dev)", "cancelled", 330.2, 2)],
           [("slow-gates (dev)", "cancelled", "The run was canceled by @radawson.")])
    expect("a timeout with no recorded end still names its reason",
           [job("body-fill (dev, body-fill-market)", "cancelled", None, 4)],
           [("body-fill (dev, body-fill-market)", "timed out", said[4][0])])
    expect("a cancellation with only the generic line has no reason",
           [job("wire-ignored (main)", "cancelled", 3, 3)], [("wire-ignored (main)", "cancelled", None)])
    expect("a cancellation GitHub annotated nothing on is red, with no reason",
           [job("wire-ignored (dev)", "cancelled", 3, 9)], [("wire-ignored (dev)", "cancelled", None)])
    expect("a failed leg is a red", [job("store-ignored (dev)", "failure", 12)],
           [("store-ignored (dev)", "failed", None)])
    expect("the API's own timed_out is a timeout", [job("store-ignored (main)", "timed_out", 60)],
           [("store-ignored (main)", "timed out", None)])
    asked.clear()
    expect("green, skipped and unfinished legs are not red, and cost no annotation read",
           [job("store-ignored (dev)", "success", 5), job("store-ignored (main)", "skipped", 0),
            job(REPORTER, None, 0), job("store-ignored (x)", "failure", 1)],
           [("store-ignored (x)", "failed", None)])
    if asked:
        bad.append(f"annotations were read for jobs that did not end cancelled: {asked}")
    legs = classify([job("body-fill (dev, body-fill-market)", "cancelled", None, 4)], annotations)
    if legs[0]["minutes"] is not None or legs[0]["key"] != "body-fill":
        bad.append(f"a leg with no end: minutes {legs[0]['minutes']!r}, key {legs[0]['key']!r}")

    # The reporter's `if`: a superseded run never reaches it.
    routes = {"uses": "actions/github-script@v8", "with": {"script": "const lanes = {'a': {}, 'b': {}};"}}
    good = {"jobs": {"a": {}, "b": {}, REPORTER: {"needs": ["a", "b"], "if": CONDITION, "steps": [routes]}}}

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
        # A job the reporter's script has no route for (2026-11-22: `plan`,
        # whose leg has no matrix values, failed both scripts' name parse).
        ("a needed job the script names no route for",
         variant(lambda j: j[REPORTER]["steps"][0]["with"].__setitem__("script", "const lanes = {'a': {}};")), 1),
        ("a job named only inside a longer name is not routed",
         variant(lambda j: j[REPORTER]["steps"][0]["with"].__setitem__("script", "{'a': {}, 'bb': {}}")), 1),
        ("no github-script step", variant(lambda j: j[REPORTER].__setitem__("steps", [])), 1),
        ("needs written as a single job id", variant(lambda j: j[REPORTER].__setitem__("needs", "a")), 1),
        ("needs left empty (null)", variant(lambda j: j[REPORTER].__setitem__("needs", None)), 1),
        ("needs as a mapping", variant(lambda j: j[REPORTER].__setitem__("needs", {"a": 1})), 1),
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
    print("SELFTEST PASS: a cancelled leg is a timeout only on GitHub's timeout annotation, and names its "
          "reason; a hand cancel, even at its limit's length or seconds into a 1-minute limit, is not; failed "
          "and API-timed-out legs are red; green, skipped and unfinished legs are not, and read no annotation; "
          "the reporter needs every job and runs on !cancelled(), so a superseded run reports nothing, and "
          "failure(), always(), ||, a missing reporter and a malformed needs each fail without a crash; a "
          "needed job the script names no route for fails; lane jobs whose steps differ, or one gone, fail")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return check()
    if len(argv) == 2 and argv[0] == "--run":
        repo = os.environ["GITHUB_REPOSITORY"]
        jobs = []
        page = 1
        while True:
            got = gh(f"repos/{repo}/actions/runs/{argv[1]}/jobs?per_page=100&page={page}")["jobs"]
            jobs += got
            if len(got) < 100:
                break
            page += 1

        def annotations(job_id: int) -> list[str]:
            got = gh(f"repos/{repo}/check-runs/{job_id}/annotations?per_page=100")
            return [a.get("message", "") for a in got]

        print(json.dumps(classify(jobs, annotations)))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
