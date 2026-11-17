#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A workflow's pass job: the one required check that stands for every job in it.

`build.yml` (`ci/gh-actions/cli`) ends in `cli-pass` and `rust-audit-test.yml`
(`ci/gh-actions/rust`) in `rust-pass` (ruled 2026-11-16). Branch protection
requires those two names and none of the jobs they stand for.

WHY. A job skipped by its `if:` reports as a skip, and protection counts a
skip as a pass. A draft pull request skips the heavy jobs; when it is marked
ready, the jobs that wait on the scope job get no check until that job
finishes (23 min under the queue of 2026-11-16), and until then the draft's
skip is the newest check under the required name. A failed scope job is the
same hole: every job after it is skipped. The pass job closes both:

* it needs every other job and runs with `if: always()`, so it reports only
  once every job it stands for has finished, and a failure anywhere makes it
  red;
* on a draft it reports as `<name> (draft)`. A job that runs reports its
  evaluated name, so a draft never reports the required name, and a PR
  marked ready is blocked until its own pass job finishes. (A job that is
  SKIPPED reports its name expression unevaluated, which is why the name
  trick works only on a job that always runs.)

WHAT PASSES (`--decide`, run by the pass job on `toJSON(needs)`): every
needed job succeeded or was skipped by scope. It fails when the scope job did
not succeed, when any needed job failed or was cancelled, and when a job was
skipped because something it needed failed. A skip is read as scope only in a
run where nothing failed: the pass job needs every job, so whatever a
skipped job waited on is in the same list, and one failed or cancelled job
there marks every skip in the run as not accepted.

WHAT `--check` HOLDS (grep gates): each pass job's name, `if:`, `needs`
(every job but itself and the dev-red reporter), the scope job it names, and
the step that runs `--decide` on its own workflow.

`--selftest` runs each verdict case and plants each structural defect.
"""

from __future__ import annotations

import json
import os
import sys

PASS_JOB = "pass"
REPORTER = "report-dev-red"
IF = "always()"
NEEDS_ENV = "${{ toJSON(needs) }}"
# (workflow, the required context it reports, its scope job).
WORKFLOWS = {
    ".github/workflows/build.yml": ("cli-pass", "changes"),
    ".github/workflows/rust-audit-test.yml": ("rust-pass", "changes"),
}
RESULTS = ("success", "skipped", "failure", "cancelled")


def name_expression(context: str) -> str:
    return (
        "${{ github.event_name == 'pull_request' && github.event.pull_request.draft"
        f" && '{context} (draft)' || '{context}' }}}}"
    )


def decide_command(scope: str) -> str:
    return f"python3 scripts/ci/workflow_pass.py --decide --scope {scope}"


def decide(needs: dict, scope: str) -> list[str]:
    """Why the run does not pass; empty when it does."""
    results = {job: (v or {}).get("result") for job, v in needs.items()}
    why = []
    if scope not in results:
        why.append(f"the scope job `{scope}` is not a job this pass job needs")
    elif results[scope] != "success":
        why.append(f"the scope job `{scope}`: {results[scope]}")
    for job, result in sorted(results.items()):
        if result not in RESULTS:
            why.append(f"`{job}`: unknown result {result!r}")
        elif result in ("failure", "cancelled") and job != scope:
            why.append(f"`{job}`: {result}")
    if why:
        for job, result in sorted(results.items()):
            if result == "skipped":
                # The pass job cannot see why a job was skipped; a skip is
                # read as scope only when nothing in the run failed.
                why.append(f"`{job}`: skipped, not counted as scope because something in this run failed")
    return why


def run_decide(scope: str) -> int:
    raw = os.environ.get("NEEDS")
    if not raw:
        print("FAIL: NEEDS is empty; the pass job must set it to toJSON(needs) (rule 47)")
        return 1
    needs = json.loads(raw)
    if not needs:
        print("FAIL: the pass job needs no job, so it stands for nothing (rule 47)")
        return 1
    for job, v in sorted(needs.items()):
        print(f"  {job}: {(v or {}).get('result')}")
    why = decide(needs, scope)
    if why:
        print(f"FAIL: {len(why)} reason(s):")
        for line in why:
            print("  " + line)
        return 1
    print(f"pass: {len(needs)} job(s), each succeeded or was skipped by scope")
    return 0


def check_doc(doc: dict, workflow: str, context: str, scope: str) -> list[str]:
    jobs = doc.get("jobs") or {}
    out = []
    if scope not in jobs:
        out.append(f"{workflow}: no scope job `{scope}`")
    elif jobs[scope].get("needs"):
        out.append(f"{workflow}: the scope job `{scope}` needs another job; it must run first")
    job = jobs.get(PASS_JOB)
    if not isinstance(job, dict):
        return out + [f"{workflow}: no `{PASS_JOB}` job"]
    if job.get("name") != name_expression(context):
        out.append(f"{workflow}: `{PASS_JOB}` is named {job.get('name')!r}, not {name_expression(context)!r}")
    if str(job.get("if", "")).strip() != IF:
        out.append(f"{workflow}: `{PASS_JOB}` has `if: {job.get('if')}`, not `if: {IF}`")
    needs = job.get("needs") or []
    needs = {needs} if isinstance(needs, str) else set(needs)
    want = set(jobs) - {PASS_JOB, REPORTER}
    if needs != want:
        missing, extra = sorted(want - needs), sorted(needs - want)
        out.append(f"{workflow}: `{PASS_JOB}` needs {sorted(needs)}; missing {missing}, extra {extra}")
    steps = job.get("steps") or []
    runs = [s for s in steps if isinstance(s, dict) and decide_command(scope) in str(s.get("run", ""))]
    if len(runs) != 1:
        out.append(f"{workflow}: `{PASS_JOB}` has {len(runs)} step(s) running `{decide_command(scope)}`, not 1")
    elif (runs[0].get("env") or {}).get("NEEDS") != NEEDS_ENV:
        out.append(f"{workflow}: `{PASS_JOB}`'s decide step does not set NEEDS to {NEEDS_ENV}")
    return out


def run_check(root: str) -> int:
    import yaml

    problems = []
    for workflow, (context, scope) in WORKFLOWS.items():
        path = os.path.join(root, workflow)
        if not os.path.isfile(path):
            problems.append(f"{workflow}: missing (rule 47)")
            continue
        with open(path, encoding="utf-8") as fh:
            problems += check_doc(yaml.safe_load(fh), workflow, context, scope)
    if problems:
        print("FAIL:")
        for p in problems:
            print("  " + p)
        return 1
    print(f"pass jobs: {len(WORKFLOWS)} workflows, each ends in a pass job that needs every job")
    return 0


def fixture(context: str, scope: str, workflow: str) -> dict:
    return {
        "jobs": {
            scope: {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]},
            "build": {"needs": scope, "if": "x", "steps": [{"run": "true"}]},
            PASS_JOB: {
                "name": name_expression(context),
                "needs": [scope, "build"],
                "if": IF,
                "steps": [{"run": decide_command(scope), "env": {"NEEDS": NEEDS_ENV}}],
            },
            REPORTER: {"needs": [scope, "build", PASS_JOB]},
        }
    }


def selftest() -> int:
    bad = []
    s, k, f, c = "success", "skipped", "failure", "cancelled"

    def needs(**results):
        return {job: {"result": r, "outputs": {}} for job, r in results.items()}

    verdicts = [
        ("every job succeeded", needs(changes=s, build=s, lint=s), True),
        ("a job skipped by scope (docs-only, a draft)", needs(changes=s, build=k, lint=s), True),
        ("every job but scope skipped by scope", needs(changes=s, build=k, lint=k), True),
        ("a job failed", needs(changes=s, build=f, lint=s), False),
        ("a job cancelled (past its timeout)", needs(changes=s, build=c, lint=s), False),
        ("the scope job failed, so every job after it skipped", needs(changes=f, build=k, lint=k), False),
        ("the scope job cancelled", needs(changes=c, build=k, lint=k), False),
        ("the scope job skipped", needs(changes=k, build=k), False),
        ("a job skipped because one it needs failed", needs(changes=s, build=f, test=k), False),
        ("a job skipped because one it needs was cancelled", needs(changes=s, build=c, test=k), False),
        ("an unknown result", needs(changes=s, build="neutral"), False),
        ("no scope job among the needs", needs(build=s), False),
    ]
    for why, case, want in verdicts:
        got = not decide(case, "changes")
        if got != want:
            bad.append(f"verdict, {why}: wanted pass={want}, got pass={got} ({decide(case, 'changes')})")
    reasons = decide(needs(changes=s, build=f, test=k), "changes")
    if not any(r.startswith("`test`: skipped") for r in reasons):
        bad.append(f"a skip after a failure is not named: {reasons}")

    wf, ctx, scope = ".github/workflows/x.yml", "x-pass", "changes"
    if check_doc(fixture(ctx, scope, wf), wf, ctx, scope):
        bad.append(f"the good fixture is refused: {check_doc(fixture(ctx, scope, wf), wf, ctx, scope)}")

    def planted(why, change):
        doc = fixture(ctx, scope, wf)
        change(doc["jobs"])
        if not check_doc(doc, wf, ctx, scope):
            bad.append(f"structure, {why}: not refused")

    planted("a job the pass job does not need", lambda j: j.update(extra={"needs": scope}))
    planted("a static name (a draft would report the required name)", lambda j: j[PASS_JOB].update(name=ctx))
    planted("an `if` that can skip it", lambda j: j[PASS_JOB].update({"if": "success()"}))
    planted("no `if` (a failure upstream skips it)", lambda j: j[PASS_JOB].pop("if"))
    planted("needing the reporter", lambda j: j[PASS_JOB]["needs"].append(REPORTER))
    planted("no decide step", lambda j: j[PASS_JOB].update(steps=[{"run": "true"}]))
    planted("NEEDS not set", lambda j: j[PASS_JOB]["steps"][0].pop("env"))
    planted("a scope job that waits on another", lambda j: j[scope].update(needs="build"))
    planted("no pass job", lambda j: j.pop(PASS_JOB))
    if bad:
        print("SELFTEST FAIL:")
        for line in bad:
            print("  " + line)
        return 1
    print(f"workflow pass selftest: {len(verdicts)} verdicts, the good structure accepted, 9 defects refused")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) == 4 and argv[1] == "--decide" and argv[2] == "--scope":
        return run_decide(argv[3])
    if argv[1:] == ["--check"]:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        return run_check(root)
    print("usage: workflow_pass.py --selftest | --check | --decide --scope <job>")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
