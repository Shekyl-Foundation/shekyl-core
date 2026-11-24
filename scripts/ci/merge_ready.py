#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `merge-ready` commit status: the owning lane's "done", as a mark
GitHub enforces (ruled 2026-11-19). It is a signal to the merger, not a
second test run (ruled 2026-11-23): nothing here runs a test.

# Why

Pull requests were merged when the required checks went green while other
workflows and fleet runs on the same head were still going. A draft is the
wrong tool, since rule 06 skips the expensive jobs on a draft. A pull
request is a draft while its lane works on it, comes out of draft for
review, and takes the `merge-ready` label when review and validation are
complete: every check on the current head has concluded, the lane's fleet
and local runs for that head are done, and its review threads are resolved.
`merge-ready` is the required status that holds the pull request to that.

A pull request's CI runs on its head merged onto the `dev` of its last
push, so two pull requests each green alone can still be red together. The
run on `dev` after the merge is what tests that combination, and a red there
opens its own issue (report-dev-red.yml).

# The status

`merge-ready` is a commit status on the pull request's head. Its
description carries its kind first (`describe`):

  kind      state    meaning
  waiting   pending  no label: the owner has not labelled this head, or a
                     push took the label off
  checking  pending  the label went on; every check on the head is read
  refused   pending  a check ran or was red, a review thread was open or the
                     pull request was a draft: the label came off, with a
                     comment naming each
  ready     success  the label stands on this head

Without the label the status is pending, never red: the reason is in the
comment. A status is never skipped: a head with no `merge-ready` status at
all is also blocked by the ruleset ("expected"), and the job that posts it
is not named `merge-ready`, since a ruleset matches a check run and a status
by name alike. A push to `dev` changes nothing here: the label vouches for
the head.

# What each event does

  synchronize        the label comes off, with a comment: a label never
                     vouches for a head its owner did not see, and the new
                     head's checks have only just started
  labeled            `checking`, then every check run and status on the
                     head, this run's own, `EXCLUDED` by name and
                     `EXCLUDED_APPS` by app aside, must have concluded,
                     none red. Of a workflow's `pull_request` runs on the
                     head only the newest is judged (`SUPERSEDING_EVENTS`);
                     a job another run replaced through their concurrency
                     group is not (`replaced_cancels`); a review bot's job
                     is judged by its review instead (`REVIEW_JOBS`). No
                     review thread may be open; the pull request may not be
                     a draft. All of that holds: `ready`. Anything else:
                     `refused`
  unlabeled          waiting
  opened, reopened   waiting, or the label check when it is on
  ready_for_review   the label comes off, as for a push

A label or an unlabel of any other label runs nothing (merge-ready.yml's
condition, `decide`'s "ignore").

A check run created by the labelling itself (another workflow listening for
labels, whose jobs skip at once) is given `SETTLE_SECONDS` to conclude
before it counts as running. One that started before the label went on
(its check suite was created before `LABELLED_AT` less `GRACE_SECONDS`) is
not waited for: the label is refused at once. A check run's own start time
cannot tell: it is when a runner picked the job up.

Removing the label with the workflow's token starts no `unlabeled` run, so
the step that removes it posts the status itself.

  merge_ready.py run        merge-ready.yml's label check; reads EVENT, PR,
                            HEAD, DRAFT, LABEL (the event's label),
                            HAS_LABEL, LABELLED_AT and GITHUB_RUN_ID
  merge_ready.py --selftest

`run` also reads RUN_URL (the run's link), GITHUB_REPOSITORY and GH_TOKEN.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timedelta

LABEL = "merge-ready"
CONTEXT = "merge-ready"
# Names a job of merge-ready.yml, held to the file by the selftest. A run
# knows its own jobs by their check suite (`own_suite`), not by this name,
# which any workflow's job can take.
LABEL_JOB = "merge-ready label check"
# Checks that never conclude on this repository, each with why. A check
# left out of a judgment is named here, never dropped silently.
EXCLUDED: dict[str, str] = {}
# Apps whose check runs are never judged, running or concluded, each with
# why; known by the app's slug, never the check's name, which any
# workflow's job can take. Named in every refusal comment beside EXCLUDED.
EXCLUDED_APPS: dict[str, str] = {
    # Rick, 2026-11-22: Bugbot is informational only, too unreliable to
    # wait on. Its check run on #1489's head sat queued from 10:52Z and
    # refused the label at 12:26Z. A red Bugbot refuses nothing either;
    # what it posts is a review thread, and an open thread is judged.
    "cursor": "Cursor Bugbot, informational only",
}
# Review bots whose job is judged by the review it posts, not by how the job
# ends: the workflow run's path, the reviewer's login, and why. Copilot's
# review job ended red 19 minutes after it had posted its review on the head
# (#1497 at fc1cf82f33, 2026-11-22). With a review from the bot on this head,
# its job is not judged, running or red; without one, it is judged as any
# other check, and a red one says that no review came. Matched by the run's
# path, never the check's name, which any workflow's job can take.
REVIEW_JOBS: dict[str, tuple[str, str]] = {
    "dynamic/agents/copilot-pull-request-reviewer": (
        "copilot-pull-request-reviewer[bot]",
        "Copilot's review job can end red after its review is posted",
    ),
}
# The events whose newer run of a workflow on the head replaces its older
# runs there (`superseded_suites`). A `pull_request` run's scope is the head
# and the pull request's diff, so a newer one covers an older one: a draft's
# run skips the heavy jobs and the run when it is marked ready runs them all
# (#1497). A run of any other event is never replaced and replaces nothing:
# a `workflow_dispatch` on the head is chosen by its inputs, narrower than
# the pull request's run (benchmarks.yml's capture skips its `compare` job,
# nightly.yml's `job` picks one leg), and a `push` run's scope is measured
# from the branch's previous tip, not the head alone. Each such run's reds
# stay judged until a re-run attempt clears them.
SUPERSEDING_EVENTS = frozenset({"pull_request"})
# GitHub's annotation on a job a newer run of the same concurrency group
# replaced, read from the check run. A timeout or a hand cancel carries
# another line, so neither reads as replaced.
GROUP_CANCEL = re.compile(r"^Canceling since a higher priority waiting request for .+ exists$")
# A check run the labelling itself started (a workflow listening for
# labels, its jobs skipped at once) concludes within seconds.
SETTLE_SECONDS = 90
POLL_SECONDS = 10
# How far before the label event a check suite the labelling created may
# read as created: the two timestamps come from different services.
GRACE_SECONDS = 5
GREEN = {"success", "neutral", "skipped"}
WAITING = "the owner's merge-ready label"

# The status kinds and the state each posts.
KINDS = {"waiting": "pending", "checking": "pending", "refused": "pending", "ready": "success"}


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout


def repo() -> str:
    return os.environ["GITHUB_REPOSITORY"]


def describe(kind: str, words: str) -> str:
    """A status description, its kind first, cut to GitHub's 140 characters."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    return f"{kind}: {words}"[:140]


def statuses(sha: str) -> list[dict]:
    """The head's newest status per context, every page of them."""
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/commits/{sha}/status?per_page=100", "--jq", ".statuses[]"],
        check=True, capture_output=True, text=True).stdout
    return [json.loads(x) for x in out.splitlines() if x]


def post(sha: str, state: str, description: str) -> None:
    assert state in ("pending", "success"), state
    gh(f"repos/{repo()}/statuses/{sha}", "--method", "POST", "-f", f"state={state}", "-f", f"context={CONTEXT}",
       "-f", f"description={description[:140]}", "-f", f"target_url={os.environ['RUN_URL']}")
    print(f"{CONTEXT} on {sha[:10]}: {state}: {description[:140]}")


def post_kind(sha: str, kind: str, words: str) -> None:
    post(sha, KINDS[kind], describe(kind, words))


def comment(pr: int, lines: list[str]) -> None:
    gh(f"repos/{repo()}/issues/{pr}/comments", "--method", "POST", "-f", "body=" + "\n".join(lines))


def has_label(pr: int) -> bool:
    return any(lb["name"] == LABEL for lb in json.loads(gh(f"repos/{repo()}/issues/{pr}/labels")))


def remove_label(pr: int) -> None:
    """Take the label off and confirm it is off. A label already gone is
    the same end, so the delete's own answer is not the verdict."""
    subprocess.run(["gh", "api", "--method", "DELETE", f"repos/{repo()}/issues/{pr}/labels/{LABEL}"],
                   capture_output=True, text=True)
    if has_label(pr):
        raise RuntimeError(f"#{pr}: the {LABEL} label is still on after removing it")


def current_head(pr: int) -> str:
    return json.loads(gh(f"repos/{repo()}/pulls/{pr}"))["head"]["sha"]


# The label check.


def when(stamp: str | None) -> datetime | None:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None


def settling(check: dict, labelled_at: str | None) -> bool:
    """Whether a running check may have been started by the labelling: its
    check suite was created no earlier than the label, less GRACE_SECONDS.
    Without either time, every running check may wait."""
    at, created = when(labelled_at), when(check.get("suite_created_at"))
    return at is None or created is None or created >= at - timedelta(seconds=GRACE_SECONDS)


def judge(check_runs: list[dict], sts: list[dict], open_threads: int, draft: bool,
          labelled_at: str | None = None,
          review_suites: tuple[set[int], set[int]] = (set(), set()),
          own: int | None = None) -> list[tuple[str, bool]]:
    """Why the label cannot stand on this head, each with whether it may
    still settle: each check still running (settling when the labelling may
    have started it) or red, by name, an open review thread, a draft. Empty
    means it stands. `review_suites` is `review_job_suites`' pair: the
    review jobs whose review is on the head, not judged, and those whose
    review is not, a red one saying so. `own` is this run's check suite,
    whose jobs are this judgment and what waits on it."""
    reviewed, unreviewed = review_suites
    out = []
    for c in check_runs:
        name = c.get("name", "")
        suite = (c.get("check_suite") or {}).get("id")
        if (own is not None and suite == own) or name in EXCLUDED or suite in reviewed:
            continue
        if (c.get("app") or {}).get("slug") in EXCLUDED_APPS:
            continue
        if c.get("status") != "completed":
            out.append((f"`{name}` is {c.get('status')}", settling(c, labelled_at)))
        elif c.get("conclusion") not in GREEN:
            no_review = ", and its review is not on this head" if suite in unreviewed else ""
            out.append((f"`{name}` concluded {c.get('conclusion')}{no_review}", False))
    for s in sts:
        context = s.get("context", "")
        if context == CONTEXT or context in EXCLUDED:
            continue
        if s.get("state") == "pending":
            out.append((f"`{context}` is pending", False))
        elif s.get("state") != "success":
            out.append((f"`{context}` is {s.get('state')}", False))
    if open_threads:
        out.append((f"{open_threads} review thread(s) open", False))
    if draft:
        out.append(("the pull request is a draft, whose expensive jobs are skipped", False))
    return out


def decide(event: str, label: str, has: bool) -> str:
    """The step an event takes: 'clear' (remove the label with a comment,
    post waiting), 'judge' (check the label), 'wait' (post waiting) or
    'ignore' (another label: nothing changes)."""
    if event in ("labeled", "unlabeled") and label != LABEL:
        return "ignore"
    if event in ("synchronize", "ready_for_review"):
        return "clear" if has else "wait"
    if event == "labeled":
        return "judge"
    if event == "unlabeled":
        return "wait"
    if event in ("opened", "reopened"):
        return "judge" if has else "wait"
    raise ValueError(f"merge-ready.yml does not listen for {event!r}")


def superseded_suites(workflow_runs: list[dict]) -> set[int]:
    """The check suites of workflow runs a newer run of the same workflow
    replaced on this head.

    `filter=latest` keeps the newest check run of each name within a check
    suite, and a re-run attempt stays in its run's suite, so it covers
    re-runs. It does not cover a second run of a workflow on the same head:
    a draft marked ready without a push starts new runs, and the draft's
    cancelled jobs, its `(draft)` pass jobs and a matrix job cancelled
    before its name expanded (`matrix.name`) stay on the head beside the
    newer runs' green ones (#1497 at fc1cf82f33, 2026-11-22: 14 of its 15
    reasons). Of each workflow's runs of a `SUPERSEDING_EVENTS` event, only
    the newest is judged; every run of another event is judged in full. A
    check run from a suite no workflow run names (another app's) is always
    judged.
    """
    replaceable = [run for run in workflow_runs if run.get("event") in SUPERSEDING_EVENTS]
    newest: dict[tuple[object, object], dict] = {}
    for run in replaceable:
        key = (run.get("workflow_id"), run.get("event"))
        if key not in newest or (run.get("created_at") or "", run.get("id", 0)) > (
                newest[key].get("created_at") or "", newest[key].get("id", 0)):
            newest[key] = run
    current = {run.get("check_suite_id") for run in newest.values()}
    return {run.get("check_suite_id") for run in replaceable} - current


def reviewers_on(reviews: list[dict], head: str) -> set[str]:
    """The logins that posted a review on this head."""
    return {(r.get("user") or {}).get("login", "") for r in reviews if r.get("commit_id") == head}


def review_job_suites(workflow_runs: list[dict], reviewers: set[str]) -> tuple[set[int], set[int]]:
    """The check suites of `REVIEW_JOBS` runs on the head: those whose bot
    posted a review on it, and those whose bot did not."""
    reviewed, unreviewed = set(), set()
    for run in workflow_runs:
        bot = REVIEW_JOBS.get(run.get("path", ""))
        if bot is not None:
            (reviewed if bot[0] in reviewers else unreviewed).add(run.get("check_suite_id"))
    return reviewed, unreviewed


def replaced_cancels(workflow_runs: list[dict], check_runs: list[dict],
                     annotations: Callable[[int], list[str]]) -> set[int]:
    """The cancelled check runs a newer run replaced through their
    concurrency group, by id, for a run `superseded_suites` never replaces.

    A dispatch that a newer dispatch of its group cancels stays on the head
    as a red with nothing wrong in it (GUI #93 at 0e9275ef54, 2026-11-24).
    GitHub's line for that (`GROUP_CANCEL`) sits on one job of the run, the
    one running when the cancel came, so the run is known by any of its
    jobs. It counts only with a run of the same workflow and event on the
    head, created between this run's start and that job's end: the run that
    replaced it, which is judged in full. Only the run's cancelled jobs are
    dropped: a job that failed before the cancel stays a red.
    """
    out: set[int] = set()
    for run in workflow_runs:
        if run.get("event") in SUPERSEDING_EVENTS:
            continue
        started = run.get("run_started_at") or run.get("created_at") or ""
        newer = [r.get("created_at") or "" for r in workflow_runs
                 if r.get("id") != run.get("id") and r.get("workflow_id") == run.get("workflow_id")
                 and r.get("event") == run.get("event") and (r.get("created_at") or "") >= started]
        if not newer:
            continue
        cancelled = [c for c in check_runs if (c.get("check_suite") or {}).get("id") == run.get("check_suite_id")
                     and c.get("conclusion") == "cancelled"]
        replaced = any(
            any(GROUP_CANCEL.match(line) for line in annotations(c["id"]))
            and any(at <= (c.get("completed_at") or "") for at in newer)
            for c in cancelled)
        if replaced:
            out |= {c["id"] for c in cancelled}
    return out


def current_runs(check_runs: list[dict], superseded: set[int], replaced: frozenset[int] | set[int] = frozenset()
                 ) -> list[dict]:
    """The check runs not in a superseded suite and not replaced."""
    return [c for c in check_runs
            if (c.get("check_suite") or {}).get("id") not in superseded and c.get("id") not in replaced]


def own_suite(workflow_runs: list[dict], run_id: str) -> int:
    """This run's check suite. A run that cannot find itself would read its
    own running job as a check still going, so it stops."""
    for run in workflow_runs:
        if str(run.get("id")) == run_id:
            return run["check_suite_id"]
    raise RuntimeError(f"run {run_id} is not among the head's workflow runs")


def annotation_lines(check_id: int) -> list[str]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/check-runs/{check_id}/annotations?per_page=100",
         "--jq", ".[].message"], check=True, capture_output=True, text=True).stdout
    return out.splitlines()


def workflow_runs(sha: str) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/actions/runs?head_sha={sha}&per_page=100",
         "--jq", ".workflow_runs[]"], check=True, capture_output=True, text=True).stdout
    return [json.loads(x) for x in out.splitlines() if x]


def reviews(pr: int) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/pulls/{pr}/reviews?per_page=100", "--jq", ".[]"],
        check=True, capture_output=True, text=True).stdout
    return [json.loads(x) for x in out.splitlines() if x]


def check_runs(sha: str) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/commits/{sha}/check-runs?filter=latest&per_page=100",
         "--jq", ".check_runs[]"], check=True, capture_output=True, text=True).stdout
    return [json.loads(x) for x in out.splitlines() if x]


def with_suite_times(runs: list[dict]) -> list[dict]:
    """Each running check run with its check suite's creation time."""
    created: dict[int, str] = {}
    for c in runs:
        suite = (c.get("check_suite") or {}).get("id")
        if c.get("status") != "completed" and suite is not None:
            if suite not in created:
                created[suite] = json.loads(gh(f"repos/{repo()}/check-suites/{suite}"))["created_at"]
            c["suite_created_at"] = created[suite]
    return runs


def open_threads(pr: int) -> int:
    """The review threads still open, over every page of them."""
    owner, name = repo().split("/")
    query = ("query($o:String!,$n:String!,$p:Int!,$endCursor:String){repository(owner:$o,name:$n){"
             "pullRequest(number:$p){reviewThreads(first:100,after:$endCursor){nodes{isResolved}"
             "pageInfo{hasNextPage endCursor}}}}}")
    out = subprocess.run(
        ["gh", "api", "graphql", "--paginate", "-f", f"query={query}", "-f", f"o={owner}", "-f", f"n={name}",
         "-F", f"p={pr}", "--jq", ".data.repository.pullRequest.reviewThreads.nodes[].isResolved"],
        check=True, capture_output=True, text=True).stdout
    return sum(1 for x in out.split() if x == "false")


def run() -> int:
    event, pr, head = os.environ["EVENT"], int(os.environ["PR"]), os.environ["HEAD"]
    draft = os.environ.get("DRAFT") == "true"
    step = decide(event, os.environ.get("LABEL", ""), os.environ.get("HAS_LABEL") == "true")
    if step == "ignore":
        print(f"{event} of another label: {CONTEXT} unchanged")
        return 0
    if step == "wait":
        post_kind(head, "waiting", WAITING)
        return 0
    if step == "clear":
        why = "a push moved the head" if event == "synchronize" else "the draft was marked ready"
        remove_label(pr)
        post_kind(head, "waiting", f"{WAITING}; {why} and took it off")
        comment(pr, [
            f"**`{LABEL}` taken off**: {why}, to {head[:10]}. The label vouches for one head, and this one's "
            "checks have only just started. Label it again when every check on it and your own runs are done.",
        ])
        return 0
    post_kind(head, "checking", "every check on the head")
    deadline = time.monotonic() + SETTLE_SECONDS
    labelled_at = os.environ.get("LABELLED_AT")
    while True:
        wf = workflow_runs(head)
        checks = check_runs(head)
        runs = current_runs(checks, superseded_suites(wf), replaced_cancels(wf, checks, annotation_lines))
        bots = review_job_suites(wf, reviewers_on(reviews(pr), head))
        found = judge(with_suite_times(runs), statuses(head), open_threads(pr), draft, labelled_at, bots,
                      own_suite(wf, os.environ["GITHUB_RUN_ID"]))
        if not found or not all(may_settle for _, may_settle in found) or time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    why = [w for w, _ in found]
    if not why:
        print(f"#{pr} {head[:10]}: every check concluded green, no review thread open")
        if current_head(pr) != head or not has_label(pr):
            print(f"#{pr}: the head moved past {head[:10]} or the label came off; that event's run decides")
            return 0
        post_kind(head, "ready", "the owner's label stands on this head")
        # A label taken off while that posted: its own run may have posted
        # `waiting` first, and this `ready` must not outlive the label.
        if not has_label(pr):
            post_kind(head, "waiting", WAITING)
        return 0
    remove_label(pr)
    post_kind(head, "refused", f"{len(why)} reason(s); see the comment")
    comment(pr, [
        f"**`{LABEL}` refused at {head[:10]}** and taken off. Label it again when each of these is done:",
        "",
        *[f"- {w}" for w in why],
        "",
        *([f"Not judged here, by name: {', '.join(f'`{n}` ({r})' for n, r in EXCLUDED.items())}."] if EXCLUDED else []),
        *([f"Not judged here, by app: {', '.join(f'`{a}` ({r})' for a, r in EXCLUDED_APPS.items())}."]
          if EXCLUDED_APPS else []),
    ])
    return 0


def selftest() -> int:
    problems = []
    done = lambda name, conclusion="success": {"name": name, "status": "completed", "conclusion": conclusion}  # noqa: E731
    going = lambda name, status="in_progress": {"name": name, "status": status, "conclusion": None}  # noqa: E731
    ok = [done("rust-pass"), done("cli-pass"), done("Economics sim", "skipped")]
    for label, runs, sts, threads, draft, want in [
        ("every check concluded green", ok, [{"context": "ci/x", "state": "success"}], 0, False, 0),
        # Negative controls: an early label is refused.
        ("an early label: a check still running", ok + [going("Rust: audit, test, determinism")], [], 0, False, 1),
        ("an early label: a check queued", ok + [going("Win64", "queued")], [], 0, False, 1),
        ("a check that failed", ok + [done("Ubuntu 24.04", "failure")], [], 0, False, 1),
        ("a check that was cancelled", ok + [done("Ubuntu 24.04", "cancelled")], [], 0, False, 1),
        ("a commit status still pending", ok, [{"context": "ci/x", "state": "pending"}], 0, False, 1),
        ("a commit status red", ok, [{"context": "ci/x", "state": "failure"}], 0, False, 1),
        ("an open review thread", ok, [], 2, False, 1),
        ("a draft", ok, [], 0, True, 1),
        ("this check's own status is not judged", ok, [{"context": CONTEXT, "state": "pending"}], 0, False, 0),
    ]:
        got = len(judge(runs, sts, threads, draft))
        if got != want:
            problems.append(f"judge, {label}: {got} reason(s), want {want}")
    # A second run of a workflow on the same head (a draft marked ready
    # without a push, #1497): only each workflow's newest run is judged.
    def suite(c, sid):
        return {**c, "check_suite": {"id": sid}}

    def wf_run(rid, wid, created, sid, event="pull_request"):
        return {"id": rid, "workflow_id": wid, "created_at": f"2026-11-22T{created}:00Z",
                "check_suite_id": sid, "event": event}

    # This run's own jobs are known by its check suite, never by a name.
    mine = [suite(going(LABEL_JOB), 900), suite(going("what waits on the label check", "queued"), 900)]
    for label, runs, want in [
        ("this run's own jobs are not judged", ok + mine, 0),
        # Negative control.
        ("a job of another run taking the label check's name is judged", ok + mine + [suite(going(LABEL_JOB), 901)], 1),
    ]:
        got = len(judge(runs, [], 0, False, own=900))
        if got != want:
            problems.append(f"own suite, {label}: {got} reason(s), want {want}")
    if own_suite([wf_run(77, 1, "01:00", 900)], "77") != 900:
        problems.append("own_suite: a run did not find its own check suite")
    try:
        own_suite([wf_run(77, 1, "01:00", 900)], "78")
        problems.append("own_suite: a run not on the head was given a suite")
    except RuntimeError:
        pass
    wf = [wf_run(1, 10, "01:32", 101), wf_run(2, 10, "05:00", 102), wf_run(3, 20, "01:32", 201)]
    stale = [suite(done("Rust: audit, test, determinism", "cancelled"), 101),
             suite(done("rust-pass (draft)", "failure"), 101), suite(done("matrix.name", "cancelled"), 101)]
    fresh = [suite(done("Rust: audit, test, determinism"), 102), suite(done("rust-pass"), 102),
             suite(done("cli-pass"), 201)]
    other_app = [suite(done("an app's check", "failure"), 999)]
    sup = superseded_suites(wf)
    for label, runs, want in [
        ("an earlier run's cancelled and draft jobs on the same head are not judged", stale + fresh, 0),
        # Negative controls.
        ("the newest run's own red is judged",
         stale + fresh + [suite(done("Windows (MSVC, daemon)", "cancelled"), 102)], 1),
        ("a workflow with a single run is judged",
         stale + fresh + [suite(done("cli-pass (draft)", "failure"), 201)], 1),
        ("a suite no workflow run names (another app's) is judged", stale + fresh + other_app, 1),
    ]:
        got = len(judge(current_runs(runs, sup), [], 0, False))
        if got != want:
            problems.append(f"superseded runs, {label}: {got} reason(s), want {want}")
    if superseded_suites(wf[:1] + wf[2:]):
        problems.append("superseded runs: a workflow's only run was superseded")
    # Only a `pull_request` run replaces, and only another `pull_request`
    # run: a narrower run of another event never hides a red (Copilot on
    # #1521: benchmarks.yml's capture-only dispatch skips `compare`).
    pr_red = [suite(done("compare & post PR comment", "failure"), 501)]
    for label, runs_wf, runs, want in [
        ("a pull_request run's red beside a newer dispatch of its workflow is judged",
         [wf_run(6, 50, "01:00", 501), wf_run(7, 50, "02:00", 502, "workflow_dispatch")],
         pr_red + [suite(done("capture-pr"), 502)], 1),
        ("an older dispatch's red beside a newer dispatch of its workflow is judged",
         [wf_run(6, 50, "01:00", 501, "workflow_dispatch"), wf_run(7, 50, "02:00", 502, "workflow_dispatch")],
         [suite(done("proptest-exhaustive", "failure"), 501), suite(done("store-ignored"), 502)], 1),
        ("a dispatch's red beside a newer pull_request run of its workflow is judged",
         [wf_run(6, 50, "01:00", 501, "workflow_dispatch"), wf_run(7, 50, "02:00", 502)],
         [suite(done("capture-pr", "failure"), 501), suite(done("capture-pr"), 502)], 1),
        ("a push run's red beside a newer pull_request run of its workflow is judged",
         [wf_run(6, 50, "01:00", 501, "push"), wf_run(7, 50, "02:00", 502)],
         [suite(done("rust", "failure"), 501), suite(done("rust"), 502)], 1),
        # Control: a draft's run and the ready run, both pull_request (#1497).
        ("a draft's pull_request red beside the newer ready run is not judged",
         [wf_run(6, 50, "01:00", 501), wf_run(7, 50, "02:00", 502)],
         [suite(done("rust-pass (draft)", "failure"), 501), suite(done("rust-pass"), 502)], 0),
    ]:
        got = len(judge(current_runs(runs, superseded_suites(runs_wf)), [], 0, False))
        if got != want:
            problems.append(f"superseded runs, {label}: {got} reason(s), want {want}")
    # A dispatch a newer one replaced through their concurrency group leaves
    # no red; a timeout, a hand cancel or a real failure does (GUI #93).
    group = "Canceling since a higher priority waiting request for core-drift-abc-a/branch exists"
    timeout = "The job has exceeded the maximum execution time of 1m0s"
    by_hand = "The run was canceled by @someone."

    def job(cid, conclusion, ended, sid=601):
        return {**suite(done(f"job {cid}", conclusion), sid), "id": cid, "completed_at": f"2026-11-24T{ended}:00Z"}

    def dispatch(rid, created, sid, wid=60, event="workflow_dispatch", started=None):
        run_ = wf_run(rid, wid, created, sid, event)
        return {**run_, "run_started_at": f"2026-11-24T{started or created}:00Z",
                "created_at": f"2026-11-24T{created}:00Z"}

    first, second = dispatch(1, "01:00", 601), dispatch(2, "01:30", 602)
    both = [job(11, "cancelled", "01:31"), job(12, "cancelled", "01:31"), job(21, "success", "02:00", 602)]
    for label, runs_wf, checks, said, want in [
        ("the annotated job and the run's other cancelled job", [first, second], both, {11: [group]}, {11, 12}),
        # Negative controls.
        ("a job that failed before the cancel stays", [first, second], both + [job(13, "failure", "01:20")],
         {11: [group], 13: ["exit 1"]}, {11, 12}),
        ("a timeout", [first, second], both, {11: [timeout]}, set()),
        ("a hand cancel", [first, second], both, {11: [by_hand]}, set()),
        ("another line that starts the same way", [first, second], both, {11: ["Canceling the step"]}, set()),
        ("a pull_request run, which `superseded_suites` judges",
         [dispatch(1, "01:00", 601, 60, "pull_request"), dispatch(2, "01:30", 602, 60, "pull_request")], both,
         {11: [group]}, set()),
        ("no annotation", [first, second], both, {}, set()),
        ("no newer run on the head", [first], both[:2], {11: [group]}, set()),
        ("a newer run of another workflow", [first, dispatch(2, "01:30", 602, 61)], both, {11: [group]}, set()),
        ("a newer run of another event", [first, dispatch(2, "01:30", 602, 60, "push")], both, {11: [group]}, set()),
        ("a run created after the job ended", [first, dispatch(2, "01:45", 602)], both, {11: [group]}, set()),
        ("a run created before this attempt started",
         [dispatch(1, "01:00", 601, started="01:40"), second], [job(11, "cancelled", "01:50")], {11: [group]}, set()),
    ]:
        got = replaced_cancels(runs_wf, checks, lambda cid: said.get(cid, []))
        if got != want:
            problems.append(f"replaced cancels, {label}: {sorted(got)}, want {sorted(want)}")
    kept = current_runs(both + [job(13, "failure", "01:20")], set(), {11, 12})
    if len(judge(kept, [], 0, False)) != 1:
        problems.append("replaced cancels: dropping the cancelled jobs did not leave the failed one judged")
    # A review bot's job is judged by its review on the head (#1497).
    bot_path, (bot, _) = next(iter(REVIEW_JOBS.items()))
    head, older_head = "f" * 40, "b" * 40
    bot_wf = wf + [{"id": 4, "workflow_id": 30, "created_at": "2026-11-22T01:40:43Z", "check_suite_id": 301,
                    "path": bot_path},
                   {"id": 5, "workflow_id": 40, "created_at": "2026-11-22T01:40:43Z", "check_suite_id": 401,
                    "path": ".github/workflows/lookalike.yml"}]
    bot_red = [suite(done("copilot-pull-request-reviewer", "failure"), 301)]
    bot_running = [suite(going("copilot-pull-request-reviewer"), 301)]
    lookalike_red = [suite(done("copilot-pull-request-reviewer", "failure"), 401)]
    on_head = [{"user": {"login": bot}, "commit_id": head}]
    on_older = [{"user": {"login": bot}, "commit_id": older_head}]
    by_human = [{"user": {"login": "a-maintainer"}, "commit_id": head}]
    for label, runs, revs, want, says in [
        ("a red review job whose review is on the head is not judged", fresh + bot_red, on_head, 0, None),
        ("a running review job whose review is on the head is not judged", fresh + bot_running, on_head, 0, None),
        # Negative controls.
        ("a red review job with its review on an older head only", fresh + bot_red, on_older, 1,
         "its review is not on this head"),
        ("a red review job with no review", fresh + bot_red, [], 1, "its review is not on this head"),
        ("a red review job when only someone else reviewed the head", fresh + bot_red, by_human, 1,
         "its review is not on this head"),
        ("a running review job with no review waits", fresh + bot_running, [], 1, "is in_progress"),
        ("a job named like the bot in another workflow is judged", fresh + lookalike_red, on_head, 1,
         "concluded failure"),
    ]:
        found = judge(current_runs(runs, superseded_suites(bot_wf)), [], 0, False, None,
                      review_job_suites(bot_wf, reviewers_on(revs, head)))
        if len(found) != want or (says and not all(says in w for w, _ in found)):
            problems.append(f"review jobs, {label}: {[w for w, _ in found]}, want {want}")
    for name in EXCLUDED:
        if judge(ok + [going(name, "queued")], [], 0, False):
            problems.append(f"judge: {name!r} is in EXCLUDED and still refused the label")
    # An excluded app's check runs are never judged, whatever their state
    # (#1489: Bugbot queued); a job of another app taking its name is.
    by_app = lambda c, slug: {**c, "app": {"slug": slug}}  # noqa: E731
    for slug in EXCLUDED_APPS:
        for label, c, want in [
            ("queued", going("Cursor Bugbot", "queued"), 0),
            ("in progress", going("Cursor Bugbot"), 0),
            ("concluded failure", done("Cursor Bugbot", "failure"), 0),
            ("concluded neutral", done("Cursor Bugbot", "neutral"), 0),
            # Negative controls.
            ("taken by a workflow's job, red", by_app(done("Cursor Bugbot", "failure"), "github-actions"), 1),
            ("taken by a workflow's job, queued", by_app(going("Cursor Bugbot", "queued"), "github-actions"), 1),
        ]:
            run_ = c if "app" in c else by_app(c, slug)
            got = len(judge(ok + [run_], [], 0, False))
            if got != want:
                problems.append(f"excluded app {slug!r}, {label}: {got} reason(s), want {want}")
    t = "2026-11-19T22:10:24Z"
    for label, created, want in [
        ("a check whose run began before the label", "2026-11-19T22:10:06Z", False),
        ("a check whose run the labelling began", "2026-11-19T22:10:25Z", True),
        ("a check whose run began just inside the grace", "2026-11-19T22:10:20Z", True),
    ]:
        got = judge([{**going("x"), "suite_created_at": created}], [], 0, False, t)[0][1]
        if got != want:
            problems.append(f"settling, {label}: {got} != {want}")
    for label, event, lab, has, want in [
        # Negative control: a push clears the label.
        ("a push to a labelled head clears the label", "synchronize", "", True, "clear"),
        ("a push to an unlabelled head waits", "synchronize", "", False, "wait"),
        ("the label going on is judged", "labeled", LABEL, True, "judge"),
        ("another label changes nothing", "labeled", "bug", True, "ignore"),
        ("another label coming off changes nothing", "unlabeled", "bug", True, "ignore"),
        ("the label coming off waits", "unlabeled", LABEL, False, "wait"),
        ("a draft marked ready clears the label", "ready_for_review", "", True, "clear"),
        ("opened without the label waits", "opened", "", False, "wait"),
        ("reopened with the label is judged", "reopened", "", True, "judge"),
    ]:
        if decide(event, lab, has) != want:
            problems.append(f"decide, {label}: {decide(event, lab, has)} != {want}")
    try:
        decide("edited", "", False)
        problems.append("decide: an event the workflow does not list was accepted")
    except ValueError:
        pass
    # Every kind names itself first and fits GitHub's limit, and only
    # `ready` posts success.
    for kind, state in KINDS.items():
        d = describe(kind, "x" * 300)
        if len(d) > 140 or not d.startswith(f"{kind}: "):
            problems.append(f"describe, {kind}: {d!r}")
        if (state == "success") != (kind == "ready"):
            problems.append(f"{kind} posts {state}: only `ready` posts success")
    try:
        describe("not-a-kind", "x")
        problems.append("describe: a kind outside KINDS was accepted")
    except ValueError:
        pass
    # The workflows carry the names this reads (rule 47).
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    label_cond = (f"(github.event.action != 'labeled' && github.event.action != 'unlabeled')\n"
                  f"      || github.event.label.name == '{LABEL}'")
    path = ".github/workflows/merge-ready.yml"
    with open(os.path.join(root, path), encoding="utf-8") as f:
        text = f.read()
    for needle, what in [
        ("types: [opened, synchronize, reopened, ready_for_review, labeled, unlabeled]", "the six events"),
        (f"    name: {LABEL_JOB}\n", "the label check's name"),
        ("python3 scripts/ci/merge_ready.py run", "the label check's step"),
        ("LABELLED_AT: ${{ github.event.pull_request.updated_at }}", "the label event's time"),
        (label_cond, "the condition that runs nothing for another label"),
        ("          ref: ${{ github.base_ref }}\n          sparse-checkout: scripts/ci/merge_ready.py\n",
         "the label check's script from the base branch"),
    ]:
        if needle not in text:
            problems.append(f"{path} lacks {what} ({needle.strip()!r})")
    if CONTEXT in re.findall(r"^    name: (.*)$", text, re.M):
        problems.append(f"{path}: a job is named {CONTEXT!r}: its green check run would satisfy the required status")
    jobs = re.findall(r"^  ([A-Za-z0-9_-]+):\n", text[text.index("\njobs:"):], re.M)
    if jobs != ["label-check"]:
        problems.append(f"{path}: its jobs are {jobs}: the label check is the only one, and nothing runs a test")
    for p in problems:
        print(f"selftest FAIL: {p}")
    if not problems:
        print("selftest: an early, red or draft label is refused, a push clears it, a run's own jobs, superseded runs, "
              "a replaced dispatch, review jobs, the status kinds, and the workflow carries these names")
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["run"]:
        return run()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
