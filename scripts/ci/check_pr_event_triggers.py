#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every pull_request workflow runs on any base, and again when retargeted.

A `branches:` filter on `pull_request` means the workflow does not run while
the PR's base is some other branch. Retargeting the PR fires `pull_request`
with `action: edited`, and `edited` is not in the default activity types, so
the workflow does not run then either. Stacked PRs (#1254, #1259) merged
with CodeQL, the doc gates, the FFI signature gate and the rest of that set
never started. The merge queue reruns on `merge_group`; that trigger is
unchanged and is not this gate's subject.

What a passing `pull_request` trigger is:

* a mapping, with no `branches` or `branches-ignore`
* `types` exactly `[opened, synchronize, reopened, edited]`
* every job carries
  `(github.event.action != 'edited' || contains(toJSON(github.event.changes), 'base'))`
  so a title edit runs nothing and a base change runs the job

A job whose name interpolates `matrix.*` cannot carry it on the job `if`:
the `if` is evaluated before the matrix expands, and a skip then emits no
per-leg check name (`check_matrix_job_gating.py`). That job gates its
steps. The jobs it needs keep the ordinary job `if`, so a title-only edit
skips them and the matrix is not reported again as a success for work it
did not do. The three matrix jobs whose per-leg names are not required
checks are the same allowlist as `check_matrix_job_gating.py`; they keep a
job-level `if`.

The eleven workflows that had the branches filter are named below. A tree
with none of them, or with no `pull_request` workflow at all, is a missing
subject (rule 47), not a pass.
"""

from __future__ import annotations

import os
import re
import sys

import yaml

from check_workflows_parse import StrictLoader, is_workflow_file

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The activity types, in the order every workflow writes them. `edited` is
# the one the default set omits; the other three are the default set, and
# naming `types` replaces that default, so dropping one of them is silent.
TYPES = ["opened", "synchronize", "reopened", "edited"]

# `github.event.changes` is absent except on `edited`. Indexing it fails the
# `if` on a push, so every job skips. `toJSON` of an absent value stays
# defined, and that JSON contains `base` only when the base changed.
# Comparing the object with `!= null` also did not come out true.
CLAUSE_RE = re.compile(
    r"\(\s*github\.event\.action\s*!=\s*'edited'\s*\|\|\s*"
    r"contains\(toJSON\(github\.event\.changes\),\s*'base'\)\s*\)"
)

# Kept in step with check_matrix_job_gating.ALLOWED. A row here that is not
# a row there would bless a job-level if the other gate forbids.
MATRIX_IF_ALLOWED = {
    ("randomx-v2-differential.yml", "runtime-modes"),
    ("randomx-v2-differential.yml", "rotating"),
    ("depends.yml", "build-cross"),
}

# The workflows whose pull_request trigger carried `branches:`. They are the
# hole this gate was written for; each one still has to be a pull_request
# workflow, or the hole is back and this file no longer sees it.
NAMED = (
    "benchmarks.yml",
    "cmake-gate-test.yml",
    "codeql.yml",
    "doc-claims.yml",
    "docs-gates.yml",
    "economics-c2a-prime.yml",
    "ffi-signatures.yml",
    "gf7-no-emit-guard.yml",
    "p2p-nnhfs-model.yml",
    "rpc-channel-model.yml",
    "schema-snapshot.yml",
)

# The pull_request workflows on 2026-11-04. A count below this means a
# trigger was deleted rather than fixed; a new workflow is fine, and it is
# graded by the same rules.
MIN_PULL_REQUEST_WORKFLOWS = 22

_BRANCH_KEYS = ("branches", "branches-ignore")


def clause_in(value: object) -> bool:
    return isinstance(value, str) and CLAUSE_RE.search(value) is not None


def needs_list(job: dict) -> list[str] | None:
    needs = job.get("needs")
    if needs is None:
        return []
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list) and all(isinstance(item, str) for item in needs):
        return list(needs)
    return None


def _interpolated(job: dict) -> bool:
    return "${{" in str(job.get("name") or "")


def _steps_lack_clause(filename: str, jid: str, job: dict) -> list[str]:
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        return [f"{filename}: job `{jid}` has no steps to carry the retarget condition"]
    out = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not clause_in(step.get("if")):
            out.append(
                f"{filename}: job `{jid}` step {index} is missing the retarget "
                "condition `(github.event.action != 'edited' || "
                "contains(toJSON(github.event.changes), 'base'))`"
            )
    return out


def problems_in(filename: str, doc: object) -> list[str]:
    if not isinstance(doc, dict):
        return [f"{filename}: not a mapping"]
    trigger = doc.get("on")
    if not isinstance(trigger, dict) or "pull_request" not in trigger:
        return []
    pr = trigger["pull_request"]
    problems: list[str] = []
    if not isinstance(pr, dict):
        return [
            f"{filename}: `pull_request` has no mapping, so it cannot name "
            "`types` or refuse a branches filter"
        ]
    if any(key in pr for key in _BRANCH_KEYS):
        problems.append(
            f"{filename}: `pull_request` carries a branches filter, so a PR "
            "whose base is another branch never runs it"
        )
    if pr.get("types") != TYPES:
        problems.append(
            f"{filename}: `pull_request` types are {pr.get('types')!r}, want {TYPES}"
        )
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return problems + [f"{filename}: no jobs"]
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            problems.append(f"{filename}: job `{jid}` is not a mapping")
            continue
        listed = needs_list(job)
        if listed is None:
            problems.append(f"{filename}: job `{jid}` has a `needs` this gate cannot read")
            listed = []
        for dep in listed:
            if dep not in jobs:
                problems.append(f"{filename}: job `{jid}` needs `{dep}`, which is not a job")
        if _interpolated(job) and (filename, jid) not in MATRIX_IF_ALLOWED:
            if "if" in job:
                problems.append(
                    f"{filename}: job `{jid}` has an interpolated name and a "
                    "job-level `if`; a skip emits no per-leg check name. Gate "
                    "the steps (check_matrix_job_gating.py)."
                )
            problems.extend(_steps_lack_clause(filename, jid, job))
        elif not clause_in(job.get("if")):
            problems.append(
                f"{filename}: job `{jid}` is missing the retarget condition on "
                "its job `if`"
            )
    return problems


def _clause() -> str:
    return (
        "(github.event.action != 'edited' || contains(toJSON(github.event.changes), 'base'))"
    )


def _job(name: str = "literal", if_=None, steps=None, needs=None) -> dict:
    job: dict = {
        "name": name,
        "runs-on": "ubuntu-latest",
        "steps": steps if steps is not None else [{"run": "true", "if": _clause()}],
    }
    if if_ is not None:
        job["if"] = if_
    if needs is not None:
        job["needs"] = needs
    return job


def _doc(jobs: dict, types=None, branches=None, pull_request=True) -> dict:
    if not pull_request:
        return {"on": {"push": {"branches": ["dev"]}}, "jobs": jobs}
    pr: dict = {"types": list(TYPES if types is None else types)}
    if branches is not None:
        pr["branches"] = branches
    return {"on": {"pull_request": pr}, "jobs": jobs}


def selftest() -> int:
    clause = _clause()
    cases = [
        ("branches filter", _doc({"a": _job(if_=clause)}, branches=["dev"]), True),
        ("types omit edited", _doc({"a": _job(if_=clause)}, types=["opened"]), True),
        ("literal job has no if", _doc({"a": _job()}), True),
        ("good literal job", _doc({"a": _job(if_=clause)}), False),
        (
            "interpolated job-level if",
            _doc({"m": _job(name="${{ matrix.name }}", if_=clause)}),
            True,
        ),
        (
            "interpolated steps gated",
            _doc({"m": _job(name="${{ matrix.name }}")}),
            False,
        ),
        (
            "matrix needs-job carries the job if",
            _doc(
                {
                    "scope": _job(if_=clause),
                    "m": _job(name="${{ matrix.name }}", needs="scope"),
                }
            ),
            False,
        ),
        (
            "matrix needs-job has no if",
            _doc(
                {
                    "scope": _job(),
                    "m": _job(name="${{ matrix.name }}", needs="scope"),
                }
            ),
            True,
        ),
        (
            "allowlisted matrix job",
            _doc({"build-cross": _job(name="${{ matrix.toolchain.name }}", if_=clause)}),
            False,
        ),
        ("push only", _doc({"a": _job()}, pull_request=False), False),
        (
            "pull_request is null",
            {"on": {"pull_request": None}, "jobs": {"a": _job(if_=clause)}},
            True,
        ),
    ]
    failed = 0
    for label, doc, want_problem in cases:
        filename = "depends.yml" if label == "allowlisted matrix job" else "fixture.yml"
        got = problems_in(filename, doc)
        if want_problem != bool(got):
            print(f"SELFTEST FAIL: {label}: want problem={want_problem}, got {got}")
            failed += 1
    folded = yaml.load(
        """
on:
  pull_request:
    types: [opened, synchronize, reopened, edited]
jobs:
  archive:
    name: source archive
    if: >-
      (github.event.action != 'edited' || contains(toJSON(github.event.changes), 'base'))
      && (
      (github.event_name == 'push'))
    runs-on: ubuntu-latest
    steps:
      - run: "true"
""",
        Loader=StrictLoader,
    )
    got = problems_in("fixture.yml", folded)
    if got:
        print(f"SELFTEST FAIL: folded job if was not recognised: {got}")
        failed += 1
    if failed:
        return 1
    print(
        "SELFTEST PASS: a branches filter, a missing edited type, and a job "
        "if on a matrix name all fail; a gated literal job, gated steps, and "
        "the allowlisted matrix jobs pass"
    )
    return 0


def main() -> int:
    rc = selftest()
    if "--selftest" in sys.argv or rc:
        return rc
    if not os.path.isdir(WORKFLOWS):
        print(f"pr triggers: {WORKFLOWS} does not exist — the subject is missing")
        return 2
    names = sorted(
        name
        for name in os.listdir(WORKFLOWS)
        if is_workflow_file(name) and os.path.isfile(os.path.join(WORKFLOWS, name))
    )
    if not names:
        print("pr triggers: no workflow files — the subject is missing")
        return 2
    problems: list[str] = []
    pull_request_files: list[str] = []
    allowed_seen: set[tuple[str, str]] = set()
    for name in names:
        path = os.path.join(WORKFLOWS, name)
        try:
            with open(path, "rb") as handle:
                doc = yaml.load(handle, Loader=StrictLoader)
        except yaml.YAMLError as exc:
            problems.append(f"{name}: does not parse: {exc}")
            continue
        trigger = doc.get("on") if isinstance(doc, dict) else None
        if isinstance(trigger, dict) and "pull_request" in trigger:
            pull_request_files.append(name)
            jobs = doc.get("jobs") if isinstance(doc, dict) else None
            if isinstance(jobs, dict):
                for jid, job in jobs.items():
                    if (
                        isinstance(job, dict)
                        and _interpolated(job)
                        and (name, jid) in MATRIX_IF_ALLOWED
                    ):
                        allowed_seen.add((name, jid))
        problems.extend(problems_in(name, doc))
    for name in NAMED:
        if name not in pull_request_files:
            problems.append(
                f"{name}: named as one of the workflows the branches filter "
                "used to silence, and it has no pull_request trigger"
            )
    if len(pull_request_files) < MIN_PULL_REQUEST_WORKFLOWS:
        problems.append(
            f"pull_request workflows: {len(pull_request_files)}, want at least "
            f"{MIN_PULL_REQUEST_WORKFLOWS} — a trigger was deleted rather than fixed"
        )
    for key in sorted(MATRIX_IF_ALLOWED):
        if key not in allowed_seen:
            problems.append(
                "MATRIX_IF_ALLOWED has a row matching no interpolated job: "
                f"{key[0]} / {key[1]}"
            )
    if problems:
        print(f"FAIL: {len(problems)} pull_request trigger problem(s):")
        for problem in problems:
            print("  " + problem)
        return 1
    print(
        f"pr triggers: {len(pull_request_files)} pull_request workflows, no "
        f"branches filter, edited included, retarget condition present "
        f"({len(NAMED)} of them are the ones the branches filter used to silence)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
