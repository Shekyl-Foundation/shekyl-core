#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every pull_request workflow runs on any base, and only on code events.

A `branches:` filter on `pull_request` means the workflow does not run while
the PR's base is some other branch. Stacked PRs (#1254, #1259) merged with
CodeQL, the doc gates, the FFI signature gate and the rest of that set never
started. The merge queue reruns on `merge_group`; that trigger is unchanged
and is not this gate's subject.

The `edited` activity type is refused. #1268 added it so a retarget (the
one `edited` whose payload carries `changes.base`) would re-run every
workflow against the new base, with a job-level condition skipping every
other edit. A skipped job still emits a check run with conclusion
`skipped`, Bugbot and Copilot edit the PR body within a minute of every
push, and the PR's rollup reports the newest check run per name. The
result on #1264 and #1267 was a page of "skipped" over runs that were
queued and running; a skipped check run also satisfies a required status
check, so the newest-wins rollup would have shown a required check green
for work not yet done. No activity-type filter distinguishes a retarget
from a title edit, and GitHub offers no other event for it.

Disposition for the retarget case (rule 21): a retargeted PR keeps the
check runs computed against its previous base until its next push; the
merge queue validates the actual merge result before `dev` moves
(`06-branching.mdc`). Reopen if the repository gains a workflow identity
that is not `GITHUB_TOKEN` (a GitHub App installation token): events that
token raises do trigger workflows, so a one-job `edited` workflow could
then close and reopen a retargeted PR, and `reopened` runs everything
against the new base with no skipped check runs on the other edits.

What a passing `pull_request` trigger is:

* a mapping, with no `branches` or `branches-ignore`
* `types` absent (the default set) or exactly `[opened, synchronize,
  reopened]`; naming `types` replaces the default set, so a list that
  drops one of the three is silent and is refused too, as is a `types`
  key with no list under it
* no expression in the file that reads `github.event.changes`; that
  object exists only on `edited`, so a reader of it is a leftover of the
  condition this gate retired. An expression is an `if` value at any
  depth, `concurrency.group`, or any string carrying `${{`; a `run:`
  script or a `name:` that mentions the words is prose, not a read

The eleven workflows that had the branches filter are named below. A tree
with none of them, or with no `pull_request` workflow at all, is a missing
subject (rule 47), not a pass.
"""

from __future__ import annotations

import os
import sys

import yaml

from check_workflows_parse import StrictLoader, is_workflow_file

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The default activity types, in the order every workflow writes them.
TYPES = ["opened", "synchronize", "reopened"]

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
_EDITED_ONLY = "github.event.changes"


def pull_request_form(trigger: object) -> str | None:
    """How this workflow names `pull_request`, or None when it does not.

    A mapping can carry `types` and refuse a branches filter. A bare name
    (`on: pull_request`, `on: [pull_request]`) is a workflow the structural
    checker accepts and this gate would otherwise not see.
    """
    if trigger == "pull_request" or (
        isinstance(trigger, list) and "pull_request" in trigger
    ):
        return "shorthand"
    if isinstance(trigger, dict) and "pull_request" in trigger:
        return "mapping"
    return None


def _expressions(node: object, under_if: bool = False):
    """The strings GitHub evaluates as expressions, and nothing else.

    An `if` value is an expression whether or not it is wrapped in `${{`;
    `concurrency.group` is the same. Any other string is an expression only
    where it carries `${{`. A `run:` script or a `name:` that mentions
    `github.event.changes` in words is prose, and is not reported.
    """
    if isinstance(node, str):
        if under_if or "${{" in node:
            yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _expressions(value, under_if=(key == "if"))
    elif isinstance(node, list):
        for item in node:
            yield from _expressions(item)


def _concurrency_group(doc: dict) -> object:
    concurrency = doc.get("concurrency")
    return concurrency.get("group") if isinstance(concurrency, dict) else None


def problems_in(filename: str, doc: object) -> list[str]:
    if not isinstance(doc, dict):
        return [f"{filename}: not a mapping"]
    trigger = doc.get("on")
    form = pull_request_form(trigger)
    if form is None:
        return []
    if form == "shorthand":
        return [
            f"{filename}: `pull_request` is a bare event name, so it cannot "
            "refuse a branches filter or name `types`. Write it as a mapping."
        ]
    pr = trigger["pull_request"]
    problems: list[str] = []
    if not isinstance(pr, dict):
        return [
            f"{filename}: `pull_request` has no mapping, so it cannot refuse "
            "a branches filter"
        ]
    if any(key in pr for key in _BRANCH_KEYS):
        problems.append(
            f"{filename}: `pull_request` carries a branches filter, so a PR "
            "whose base is another branch never runs it"
        )
    if "types" in pr and pr["types"] != TYPES:
        problems.append(
            f"{filename}: `pull_request` types are {pr['types']!r}, want {TYPES} "
            "or no `types` key; `edited` runs every job skipped on each body edit"
        )
    group = _concurrency_group(doc)
    expressions = list(_expressions(doc))
    if isinstance(group, str):
        expressions.append(group)
    if any(_EDITED_ONLY in text for text in expressions):
        problems.append(
            f"{filename}: an expression reads `{_EDITED_ONLY}`, which exists "
            "only on the `edited` event this gate refuses"
        )
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append(f"{filename}: no jobs")
    return problems


def _job() -> dict:
    return {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}


def _doc(types=None, branches=None, pull_request=True, job=None) -> dict:
    jobs = {"a": job if job is not None else _job()}
    if not pull_request:
        return {"on": {"push": {"branches": ["dev"]}}, "jobs": jobs}
    pr: dict = {}
    if types is not None:
        pr["types"] = list(types)
    if branches is not None:
        pr["branches"] = branches
    return {"on": {"pull_request": pr}, "jobs": jobs}


def selftest() -> int:
    cases = [
        ("branches filter", _doc(branches=["dev"]), True),
        ("branches-ignore filter", {"on": {"pull_request": {"branches-ignore": ["x"]}}, "jobs": {"a": _job()}}, True),
        ("types with edited", _doc(types=TYPES + ["edited"]), True),
        ("types drop reopened", _doc(types=["opened", "synchronize"]), True),
        ("types are the default set", _doc(types=TYPES), False),
        ("types absent", _doc(), False),
        (
            "types present with nothing under it",
            {"on": {"pull_request": {"types": None}}, "jobs": {"a": _job()}},
            True,
        ),
        ("push only", _doc(pull_request=False), False),
        (
            "job if reads github.event.changes",
            _doc(job={**_job(), "if": "github.event.changes.base != null"}),
            True,
        ),
        (
            "step if reads github.event.changes",
            _doc(
                job={
                    **_job(),
                    "steps": [{"run": "true", "if": "contains(toJSON(github.event.changes), 'x')"}],
                }
            ),
            True,
        ),
        (
            "interpolated string reads github.event.changes",
            _doc(job={**_job(), "name": "${{ toJSON(github.event.changes) }}"}),
            True,
        ),
        (
            "concurrency group reads github.event.changes",
            {**_doc(), "concurrency": {"group": "x-${{ toJSON(github.event.changes) }}"}},
            True,
        ),
        (
            "run script and name mention the words in prose",
            _doc(
                job={
                    **_job(),
                    "name": "no reader of github.event.changes",
                    "steps": [{"run": "echo github.event.changes is absent here"}],
                }
            ),
            False,
        ),
        ("pull_request is null", {"on": {"pull_request": None}, "jobs": {"a": _job()}}, True),
        ("no jobs", {"on": {"pull_request": {}}, "jobs": {}}, True),
        (
            "bare pull_request",
            yaml.load(
                "on: pull_request\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: 'true'\n",
                Loader=StrictLoader,
            ),
            True,
        ),
        (
            "list pull_request",
            yaml.load(
                "on: [push, pull_request]\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - run: 'true'\n",
                Loader=StrictLoader,
            ),
            True,
        ),
    ]
    failed = 0
    for label, doc, want_problem in cases:
        got = problems_in("fixture.yml", doc)
        if want_problem != bool(got):
            print(f"SELFTEST FAIL: {label}: want problem={want_problem}, got {got}")
            failed += 1
    if failed:
        return 1
    print(
        "SELFTEST PASS: a branches filter, an `edited` type, a short or empty "
        "types list, and an expression reading github.event.changes all "
        "fail; the default types, named or absent, and a prose mention pass"
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
    for name in names:
        path = os.path.join(WORKFLOWS, name)
        try:
            with open(path, "rb") as handle:
                doc = yaml.load(handle, Loader=StrictLoader)
        except yaml.YAMLError as exc:
            problems.append(f"{name}: does not parse: {exc}")
            continue
        if isinstance(doc, dict) and pull_request_form(doc.get("on")) is not None:
            pull_request_files.append(name)
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
    if problems:
        print(f"FAIL: {len(problems)} pull_request trigger problem(s):")
        for problem in problems:
            print("  " + problem)
        return 1
    print(
        f"pr triggers: {len(pull_request_files)} pull_request workflows, no "
        f"branches filter, default activity types only, no reader of "
        f"github.event.changes ({len(NAMED)} of them are the ones the "
        "branches filter used to silence)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
