#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every pull_request workflow runs on any base, and only on code events.

A `branches:` filter on `pull_request` means the workflow does not run while
the PR's base is some other branch. Stacked PRs (#1254, #1259) merged with
CodeQL, the doc gates, the FFI signature gate and the rest of that set never
started.

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
check runs computed against its previous base until its next push, so its
checks can be green for a base it no longer has. Nothing tests its merge
into `dev` before it lands; the push runs on `dev` test the result after
(`06-branching.mdc`), so a break shows red on `dev`, not on the PR. A push
to the retargeted PR, such as merging `dev` into it, closes the gap before
the merge. Reopen if the repository gains a workflow identity
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
* or exactly `[opened, synchronize, reopened, ready_for_review]`, in a
  workflow with a job skipped on a draft pull request (ruled 2026-11-16:
  the heavy jobs skip drafts). An expression that reads
  `github.event.pull_request.draft` needs that list, and that list needs
  such an expression. A job skipped on a draft emits a `skipped` check
  run, which satisfies a required status check; `ready_for_review` runs
  it again on the same head when the draft is marked ready, and the
  rollup's newest check run is then the real one, queued or running.
  Without the type, the draft's `skipped` would stand as the PR's pass
  until its next push. With the type and no draft condition, marking a
  PR ready re-runs every job for nothing
* or exactly `[opened, synchronize, reopened, ready_for_review, labeled,
  unlabeled]`, in a workflow whose expressions read the event's labels
  (`github.event.label.name` or `github.event.pull_request.labels`): a
  status kept true to a label (`merge-ready.yml`, ruled 2026-11-19), which
  must see every event that changes the head, the draft state or the
  labels. No condition of it reads the draft flag (a job skipped on a
  draft would leave that head's status unposted), so the draft rule does
  not bind it. A bare `[labeled]` is no form: an action on a label runs
  inside the status kept true to that label, which sees every event
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
# The same, for a workflow whose jobs skip a draft pull request.
READY_TYPES = TYPES + ["ready_for_review"]
# A status kept true to a label: every event that changes the head, the
# draft state or the labels.
LABEL_STATUS_TYPES = READY_TYPES + ["labeled", "unlabeled"]
_LABELS = ("github.event.label.name", "github.event.pull_request.labels")
# What an expression reads to skip a draft.
_DRAFT = "github.event.pull_request.draft"

# The workflows whose pull_request trigger carried `branches:`. They are the
# hole this gate was written for; each one still has to be a pull_request
# workflow, or the hole is back and this file no longer sees it.
# `codeql.yml` was one; it runs on a push to dev and weekly, with no pull
# request trigger at all (ruled 2026-11-16), so it has no filter to carry.
NAMED = (
    "benchmarks.yml",
    "doc-claims.yml",
    "docs-gates.yml",
    "gf7-no-emit-guard.yml",
    "p2p-nnhfs-model.yml",
    "rpc-channel-model.yml",
    "schema-snapshot.yml",
)

# The pull_request workflows on 2026-11-07, after the C++ removal deleted
# the FFI-signature and C2a' C++ workflows with what they built. A count
# below this means a trigger was deleted rather than fixed; a new workflow
# is fine, and it is graded by the same rules.
MIN_PULL_REQUEST_WORKFLOWS = 20

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


def _if_values(node: object):
    """Every `if` value, at any depth: the conditions that skip something."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "if" and isinstance(value, str):
                yield value
            else:
                yield from _if_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _if_values(item)


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
    group = _concurrency_group(doc)
    expressions = list(_expressions(doc))
    if isinstance(group, str):
        expressions.append(group)
    skips_drafts = any(_DRAFT in text for text in expressions)
    # An absent `types` key is the default set, which the message says in
    # words: `None` would read as a key with nothing under it.
    types = pr["types"] if "types" in pr else TYPES
    written = repr(pr["types"]) if "types" in pr else "absent (the default set)"
    if types == LABEL_STATUS_TYPES:
        if not any(any(x in text for x in _LABELS) for text in expressions):
            problems.append(
                f"{filename}: `pull_request` types are {LABEL_STATUS_TYPES} and no expression reads the "
                "event's labels, so the label events run it for nothing"
            )
        # Here the draft flag may be handed to the script as an input; only
        # a condition that reads it skips anything.
        if any(_DRAFT in text for text in _if_values(doc)):
            problems.append(f"{filename}: a status kept to a label skips a draft; it must post on every event")
    elif skips_drafts:
        if types != READY_TYPES:
            problems.append(
                f"{filename}: a job skips a draft pull request, and `pull_request` types are "
                f"{written}, not {READY_TYPES}: marking the draft ready runs nothing, "
                "so the draft's skipped check stands as a pass"
            )
    elif types == READY_TYPES:
        problems.append(
            f"{filename}: `pull_request` types include `ready_for_review` and no job skips a "
            "draft, so marking a pull request ready re-runs every job for nothing"
        )
    elif types != TYPES:
        problems.append(
            f"{filename}: `pull_request` types are {pr['types']!r}, want {TYPES} "
            "or no `types` key; `edited` runs every job skipped on each body edit"
        )
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
        (
            "a job skips drafts, with ready_for_review",
            _doc(types=READY_TYPES, job={**_job(), "if": "!github.event.pull_request.draft"}),
            False,
        ),
        (
            "a job skips drafts, without ready_for_review",
            _doc(types=TYPES, job={**_job(), "if": "!github.event.pull_request.draft"}),
            True,
        ),
        (
            "a job skips drafts, types absent",
            _doc(job={**_job(), "if": "!github.event.pull_request.draft"}),
            True,
        ),
        (
            "a step env skips drafts, without ready_for_review",
            _doc(
                types=TYPES,
                job={**_job(), "env": {"WORK": "${{ !github.event.pull_request.draft }}"}},
            ),
            True,
        ),
        ("ready_for_review with no draft condition", _doc(types=READY_TYPES), True),
        (
            "a bare label action, no longer a form",
            _doc(types=["labeled"], job={**_job(), "if": "github.event.label.name == 'x'"}),
            True,
        ),
        (
            "a label status reading the labels",
            _doc(types=LABEL_STATUS_TYPES, job={**_job(), "env": {
                "HAS": "${{ contains(github.event.pull_request.labels.*.name, 'x') }}"}}),
            False,
        ),
        ("a label status that reads no label", _doc(types=LABEL_STATUS_TYPES), True),
        (
            "a label status that hands the draft flag to its script",
            _doc(types=LABEL_STATUS_TYPES, job={**_job(), "env": {
                "D": "${{ github.event.pull_request.draft }}", "L": "${{ github.event.label.name }}"}}),
            False,
        ),
        (
            "a label status that skips drafts",
            _doc(types=LABEL_STATUS_TYPES, job={**_job(), "if": "!github.event.pull_request.draft",
                                                "env": {"L": "${{ github.event.label.name }}"}}),
            True,
        ),
        (
            "a label status with a branches filter",
            _doc(types=LABEL_STATUS_TYPES, branches=["dev"], job={**_job(), "if": "github.event.label.name == 'x'"}),
            True,
        ),
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
    # The message names an absent `types` key as the default set, not None.
    absent = problems_in("fixture.yml", _doc(job={**_job(), "if": "!github.event.pull_request.draft"}))
    if not absent or "absent (the default set)" not in absent[0] or "None" in absent[0]:
        print(f"SELFTEST FAIL: an absent types key is named as such: got {absent}")
        failed += 1
    if failed:
        return 1
    print(
        "SELFTEST PASS: a branches filter, an `edited` type, a short or empty "
        "types list, and an expression reading github.event.changes all "
        "fail, as do a draft-skipping job without `ready_for_review` and "
        "`ready_for_review` without one; the default types, named or absent, "
        "the draft list with a draft-skipping job, a label status that reads the labels, and a prose mention pass"
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
        f"branches filter, default activity types (plus `ready_for_review` where a job "
        f"skips drafts), no reader of "
        f"github.event.changes ({len(NAMED)} of them are the ones the "
        "branches filter used to silence)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
