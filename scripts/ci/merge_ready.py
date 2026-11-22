#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `merge-ready` commit status: the owning lane's "done", as a mark
GitHub enforces, and a re-test of the head against the newest `dev`
(ruled 2026-11-19).

# Why

Pull requests were merged when the required checks went green while other
workflows and fleet runs on the same head were still going. A draft is the
wrong tool, since rule 06 skips the expensive jobs on a draft. The owning
lane applies the `merge-ready` label when every check on the current head
has concluded, its fleet and local runs for that head are done, and its
review threads are resolved; `merge-ready` is the required status that holds
the pull request to that.

A pull request is also tested on its head merged onto the `dev` of its last
push. When another pull request merges first, the one still open was never
tested against it, and each green alone can be red together (#1404 and
#1409, #1425 and #1426, #1440 and #1447). So the label re-tests the head
merged with the newest `dev`, on the tests both changes reach
(merge_ready_overlap.py), and every later merge that shares a test with a
labelled pull request re-tests it again (merge-ready-dev.yml). Nothing
marks or re-tests a pull request without the label: a mark on every pull
request a merge reaches made each merge a wait for the ones behind it, a
merge queue by another name.

# The status

`merge-ready` is a commit status on the pull request's head. Its
description carries its kind first (`describe`, read back by `parse`):

  kind        state    meaning
  waiting     pending  no label: the owner has not labelled this head, or
                       a push took the label off
  checking    pending  the label went on; every check on the head is read
  refused     pending  a check ran or was red, a review thread was open or
                       the pull request was a draft: the label came off,
                       with a comment naming each
  re-testing  pending  the head merged with `dev` runs the tests both
                       changes reach
  ready       success  the label stands and the re-test passed (or nothing
                       both changes test changed)
  red         pending  the re-test failed: the label came off, with a
                       comment naming the merges and the failing tests

The last three also carry `dev <12 hex> since <12 hex or unknown>`: the
`dev` the status speaks for, and the `dev` the head was last ready against.
A re-test runs the tests the pull request shares with everything merged
since `since`, so a re-test that a newer one cancelled loses nothing: the
newer one covers its merges too.

Without the label the status is pending, never red: the reason is in the
comment. A status is never skipped: a head with no `merge-ready` status at
all is also blocked by the ruleset ("expected"), and the job that posts it
is not named `merge-ready`, since a ruleset matches a check run and a status
by name alike.

# What each event does

  synchronize        the label comes off, with a comment: a label never
                     vouches for a head its owner did not see, and the new
                     head's checks have only just started
  labeled            `checking`, then every check run and status on the
                     head, this flow's own and `EXCLUDED` by name aside,
                     must have concluded, none red (of a workflow run twice
                     on the head, its newest run's only; a review bot's job
                     is judged by its review instead, `REVIEW_JOBS`); no
                     review thread may be open; the pull request may not be a draft. Anything
                     else: `refused`. Then the plan: the tests the head
                     shares with the merges since its merge base, `ready`
                     at once when there are none, else `re-testing` and a
                     re-test (merge-ready-retest.yml)
  unlabeled          waiting
  opened, reopened   waiting, or the label check when it is on
  ready_for_review   the label comes off, as for a push
  a push to `dev`    for each labelled pull request whose tests the push
                     reaches: `re-testing` naming the merge, and a re-test
                     (merge_ready_overlap.py --plan); the rest untouched
  the re-test ends   `ready`; or `red` with the label taken off; or
                     nothing, when a newer re-test cancelled it

A label or an unlabel of any other label runs nothing (merge-ready.yml's
condition, `decide`'s "ignore").

A check run created by the labelling itself (another workflow listening for
labels, whose jobs skip at once) is given `SETTLE_SECONDS` to conclude
before it counts as running. One that started before the label went on
(its check suite was created before `LABELLED_AT` less `GRACE_SECONDS`) is
not waited for: the label is refused at once. A check run's own start time
cannot tell: it is when a runner picked the job up.

# Who may post

A newer `dev`'s status is never overwritten by an older one's, whatever
order the runs finish in (`may_post`). A run posts over its own status; over
a `re-testing`, `ready` or `red` speaking for an older `dev`, or for the
same `dev` from an older run. Over `waiting` or `refused` from another run
it never posts: the label came off after it started. Over another run's
`checking` only a push's plan posts (the label run fetched `dev` before the
push and would miss it). A report also posts `ready` only while the label is
on and the head has not moved.

Removing the label with the workflow's token starts no `unlabeled` run, so
the step that removes it posts the status itself.

  merge_ready.py run        merge-ready.yml's label check; reads EVENT, PR,
                            HEAD, DRAFT, LABEL (the event's label),
                            HAS_LABEL, LABELLED_AT; writes `judged`
  merge_ready.py plan       merge-ready.yml's plan after a label passed;
                            reads PR, HEAD, BASE; writes `leg`
  merge_ready.py report PR HEAD RESULT
                            merge-ready-retest.yml's report; RESULT is the
                            re-test job's result; reads DEV, SINCE, MERGED,
                            CRATES, CONFLICT, TESTS_FAILED, TIMED_OUT
  merge_ready.py --selftest

Each reads RUN_URL (the run's link), GITHUB_REPOSITORY and GH_TOKEN.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LABEL = "merge-ready"
CONTEXT = "merge-ready"
# This flow's own jobs: running while they read the head, or left behind on
# it by an earlier labelling (a re-test a newer one cancelled). Not named
# CONTEXT: a ruleset's required check matches a check run and a commit
# status by name alike, and these jobs end green.
SELF_JOBS = ("merge-ready label check", "merge-ready re-test plan")
# The re-test's jobs as a caller names them: `#<pr> / re-test`, `#<pr> / report`.
RETEST_JOB = "re-test"
REPORT_JOB = "report"
SELF_LEG = re.compile(rf"^#\d+ / ({RETEST_JOB}|{REPORT_JOB})$")
# Checks that never conclude on this repository, each with why. A check
# left out of a judgment is named here, never dropped silently.
EXCLUDED: dict[str, str] = {}
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
# A check run the labelling itself started (a workflow listening for
# labels, its jobs skipped at once) concludes within seconds.
SETTLE_SECONDS = 90
POLL_SECONDS = 10
# How far before the label event a check suite the labelling created may
# read as created: the two timestamps come from different services.
GRACE_SECONDS = 5
GREEN = {"success", "neutral", "skipped"}
WAITING = "the owner's merge-ready label"

# The status grammar. `dev` and `since` are short SHAs; `since` may be
# UNKNOWN, a range the planner could not establish (the re-test then runs
# the pull request's whole scope).
UNKNOWN = "unknown"
SHA_CHARS = 12
DEV_KINDS = {"re-testing": "pending", "ready": "success", "red": "pending"}
LIFE_KINDS = {"waiting": "pending", "checking": "pending", "refused": "pending"}
KINDS = {**LIFE_KINDS, **DEV_KINDS}
GRAMMAR = re.compile(
    rf"^({'|'.join(KINDS)})(?:: dev ([0-9a-f]{{{SHA_CHARS}}}) since ([0-9a-f]{{{SHA_CHARS}}}|{UNKNOWN}))?(?:; |: |$)"
)
# The kinds a push to `dev` re-tests: a head whose label passed its check.
PUSH_ACTS = ("checking", "re-testing", "ready")

# merge-ready-retest.yml's names, held to the file by the selftest: the
# report finds its re-test job by name and reads the verdict from the job's
# outputs. The merge and the tests steps end green whatever they find, so a
# red re-test is the pull request's and never fails a push run on `dev`.
RETEST_WORKFLOW = ".github/workflows/merge-ready-retest.yml"
RETEST_OUTPUTS = ("conflict", "tests_failed", "timed_out")
MERGE_STEP = "merge the newest dev into the head"
TESTS_STEP = "the shared tests against the newest dev"


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout


def repo() -> str:
    return os.environ["GITHUB_REPOSITORY"]


def short(sha: str) -> str:
    return sha if sha == UNKNOWN else sha[:SHA_CHARS]


def describe(kind: str, words: str, dev: str | None = None, since: str | None = None) -> str:
    """A status description in the grammar, cut to GitHub's 140 characters."""
    if kind in DEV_KINDS:
        return f"{kind}: dev {short(dev)} since {short(since)}; {words}"[:140]
    if kind in LIFE_KINDS:
        return f"{kind}: {words}"[:140]
    raise ValueError(f"unknown kind {kind!r}")


def parse(status: dict | None) -> dict | None:
    """A status of this context: its kind, `dev` and `since` (None for the
    kinds without them); None for no status. One outside the grammar is
    kind '?'."""
    if status is None:
        return None
    m = GRAMMAR.match(status.get("description") or "")
    if not m or (m.group(1) in DEV_KINDS) != (m.group(2) is not None):
        return {"kind": "?", "dev": None, "since": UNKNOWN, "url": status.get("target_url") or ""}
    return {"kind": m.group(1), "dev": m.group(2), "since": m.group(3), "url": status.get("target_url") or ""}


def statuses(sha: str) -> list[dict]:
    """The head's newest status per context, every page of them."""
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/commits/{sha}/status?per_page=100", "--jq", ".statuses[]"],
        check=True, capture_output=True, text=True).stdout
    return [json.loads(x) for x in out.splitlines() if x]


def newest(sts: list[dict]) -> dict | None:
    return next((s for s in sts if s.get("context") == CONTEXT), None)


RUN_ID = re.compile(r"/actions/runs/(\d+)")


def may_post(current: dict | None, run_url: str, dev: str, role: str, dev_is_newer) -> bool:
    """Whether this run, speaking for `dev`, may post over the head's newest
    status (`parse`d). `role` is 'plan' (the label's plan), 'mark' (a push's
    plan) or 'report' (a re-test's). `dev_is_newer(theirs)` answers whether
    `dev` descends from, and is not, the commit `theirs` (a short SHA)
    names."""
    if role not in ("plan", "mark", "report"):
        raise ValueError(role)
    if current is None:
        return False
    if current["url"] == run_url:
        return True
    kind = current["kind"]
    if kind in ("waiting", "refused", "?"):
        return False
    if kind == "checking":
        return role == "mark"
    if current["dev"] == short(dev):
        mine, other = RUN_ID.search(run_url), RUN_ID.search(current["url"])
        return bool(mine and other) and int(mine.group(1)) > int(other.group(1))
    return dev_is_newer(current["dev"]) is True


def dev_is_newer_than(theirs: str, dev: str) -> bool:
    """Whether `dev` descends from, and is not, the commit `theirs` names."""
    full = json.loads(gh(f"repos/{repo()}/commits/{theirs}"))["sha"]
    if full == dev:
        return False
    return json.loads(gh(f"repos/{repo()}/compare/{full}...{dev}"))["status"] == "ahead"


def post(sha: str, state: str, description: str) -> None:
    assert state in ("pending", "success"), state
    gh(f"repos/{repo()}/statuses/{sha}", "--method", "POST", "-f", f"state={state}", "-f", f"context={CONTEXT}",
       "-f", f"description={description[:140]}", "-f", f"target_url={os.environ['RUN_URL']}")
    print(f"{CONTEXT} on {sha[:10]}: {state}: {description[:140]}")


def post_kind(sha: str, kind: str, words: str, dev: str | None = None, since: str | None = None) -> None:
    post(sha, KINDS[kind], describe(kind, words, dev, since))


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


def is_self(name: str) -> bool:
    return name in SELF_JOBS or bool(SELF_LEG.match(name))


def judge(check_runs: list[dict], sts: list[dict], open_threads: int, draft: bool,
          labelled_at: str | None = None,
          review_suites: tuple[set[int], set[int]] = (set(), set())) -> list[tuple[str, bool]]:
    """Why the label cannot stand on this head, each with whether it may
    still settle: each check still running (settling when the labelling may
    have started it) or red, by name, an open review thread, a draft. Empty
    means it stands. `review_suites` is `review_job_suites`' pair: the
    review jobs whose review is on the head, not judged, and those whose
    review is not, a red one saying so."""
    reviewed, unreviewed = review_suites
    out = []
    for c in check_runs:
        name = c.get("name", "")
        suite = (c.get("check_suite") or {}).get("id")
        if is_self(name) or name in EXCLUDED or suite in reviewed:
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
    reasons). Only each workflow's newest run on the head is judged. A check
    run from a suite no workflow run names (another app's) is always judged.
    """
    newest: dict[object, dict] = {}
    for run in workflow_runs:
        key = run.get("workflow_id")
        if key not in newest or (run.get("created_at") or "", run.get("id", 0)) > (
                newest[key].get("created_at") or "", newest[key].get("id", 0)):
            newest[key] = run
    current = {run.get("check_suite_id") for run in newest.values()}
    return {run.get("check_suite_id") for run in workflow_runs} - current


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


def current_runs(check_runs: list[dict], superseded: set[int]) -> list[dict]:
    """The check runs not in a superseded suite."""
    return [c for c in check_runs if (c.get("check_suite") or {}).get("id") not in superseded]


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


def output(key: str, value: str) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write(f"{key}={value}\n")


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
    post_kind(head, "checking", "every check on the head, then a re-test against dev")
    deadline = time.monotonic() + SETTLE_SECONDS
    labelled_at = os.environ.get("LABELLED_AT")
    while True:
        wf = workflow_runs(head)
        runs = current_runs(check_runs(head), superseded_suites(wf))
        bots = review_job_suites(wf, reviewers_on(reviews(pr), head))
        found = judge(with_suite_times(runs), statuses(head), open_threads(pr), draft, labelled_at, bots)
        if not found or not all(may_settle for _, may_settle in found) or time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    why = [w for w, _ in found]
    if not why:
        print(f"#{pr} {head[:10]}: every check concluded green, no review thread open")
        output("judged", "ok")
        return 0
    remove_label(pr)
    post_kind(head, "refused", f"{len(why)} reason(s); see the comment")
    comment(pr, [
        f"**`{LABEL}` refused at {head[:10]}** and taken off. Label it again when each of these is done:",
        "",
        *[f"- {w}" for w in why],
        "",
        *([f"Not judged here, by name: {', '.join(f'`{n}` ({r})' for n, r in EXCLUDED.items())}."] if EXCLUDED else []),
    ])
    return 0


# The label's plan.


def plan() -> int:
    """After the label passed: the tests the head shares with the merges
    since it was last ready, against `dev` fetched now (after the label
    check, so a push before this is in it, and one after it sees
    `checking` and re-tests this head itself)."""
    import merge_ready_overlap as mo

    pr, head, base = int(os.environ["PR"]), os.environ["HEAD"], os.environ["BASE"]
    run_url = os.environ["RUN_URL"]
    if current_head(pr) != head or not has_label(pr):
        print(f"#{pr}: the head moved past {head[:10]} or the label came off; that event's run decides")
        return 0
    subprocess.run(["git", "fetch", "--no-tags", "--quiet", "origin", base], check=True)
    dev = subprocess.run(["git", "rev-parse", "FETCH_HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    current = parse(newest(statuses(head)))
    if not may_post(current, run_url, dev, "plan", lambda t: dev_is_newer_than(t, dev)):
        print(f"#{pr}: {CONTEXT} is held by a newer run ({current}); it decides")
        return 0
    try:
        row = mo.label_row(pr, head, dev, mo.Context())
    except Exception as e:  # fail closed: the pull request's whole scope
        row = mo.fail_closed(pr, head, e, UNKNOWN)
        print(f"::warning::#{pr}: {row['why']}; re-testing its whole scope")
    print(f"#{pr} {head[:10]} against dev {dev[:10]}: {row['action']}, {row['why']}")
    if row["action"] == "ready":
        post_kind(head, "ready", f"nothing both changes test changed since {short(row['since'])}", dev, dev)
        return 0
    post_kind(head, "re-testing", f"after {row['merged']}", dev, row["since"])
    output("leg", json.dumps({"dev": dev, **{k: row[k] for k in ("pr", "head", "since", "merged")}}))
    return 0


# The re-test's report.


def verdict_of(result: str, conflict: bool, tests_failed: bool, timed_out: bool) -> str:
    """The re-test's result as the pull request sees it: the job's own
    result, except that a job which ended green with a conflict, failing
    tests or the time budget in its outputs is a failure."""
    if result == "success" and (conflict or tests_failed or timed_out):
        return "failure"
    return result


def red_steps(info: dict, conflict: bool, tests_failed: bool, timed_out: bool) -> dict:
    """The job's failed steps with the step that carried the verdict added:
    that step ended green, so the API does not list it."""
    carried = [MERGE_STEP] if conflict else [TESTS_STEP] if (tests_failed or timed_out) else []
    return {**info, "failed_steps": info["failed_steps"] + [x for x in carried if x not in info["failed_steps"]]}


def red_words(result: str, conflict: bool, timed_out: bool, info: dict | None, merged: str) -> str:
    """Why a re-test that did not pass is red. `result` is not 'success'
    or 'cancelled'."""
    after = f"after {merged}"
    if result != "failure":
        return f"re-test did not run ({result}, {after})"
    if conflict:
        return f"does not merge with dev {after}"
    if timed_out:
        return f"timed out {after}"
    if info is None:
        return f"{after}: see the run"
    if info["builds"]:
        return f"does not build {after}: {', '.join(info['builds'])}"
    if info["tests"]:
        return f"{len(info['tests'])} failing test(s) {after}"
    return f"{after}: {', '.join(info['failed_steps']) or 'see the run'}"


def report_step(result: str, moved: bool, postable: bool, labelled: bool) -> str:
    """What a report does: 'none', 'ready' or 'red'. A cancelled re-test
    was replaced by a newer one, which reports; a moved head is the push's;
    a status held by a newer run or a label taken off is theirs."""
    if result == "cancelled" or moved or not postable or not labelled:
        return "none"
    return "ready" if result == "success" else "red"


def report(pr: int, head: str, result: str) -> int:
    run_url, dev, since = os.environ["RUN_URL"], os.environ["DEV"], os.environ["SINCE"]
    merged, crates = os.environ.get("MERGED", ""), os.environ.get("CRATES", "")
    conflict = os.environ.get("CONFLICT") == "true"
    tests_failed = os.environ.get("TESTS_FAILED") == "true"
    timed_out = os.environ.get("TIMED_OUT") == "true"
    result = verdict_of(result, conflict, tests_failed, timed_out)
    moved = current_head(pr) != head
    current = parse(newest(statuses(head)))
    postable = not moved and may_post(current, run_url, dev, "report", lambda t: dev_is_newer_than(t, dev))
    step = report_step(result, moved, postable, not moved and has_label(pr))
    if step == "none":
        print(f"#{pr} {head[:10]}: {result}; posts nothing (cancelled={result == 'cancelled'}, moved={moved}, "
              f"status={current and current['kind']}, may post={postable})")
        return 0
    if step == "ready":
        post_kind(head, "ready", f"re-tested after {merged}", dev, since)
        return 0
    jobs = json.loads(gh(f"repos/{repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}/jobs?per_page=100")).get("jobs", [])
    job = next((j for j in jobs if j["name"] == f"#{pr} / {RETEST_JOB}"), None)
    import failed_tests

    info = failed_tests.describe(job) if job and result == "failure" else None
    if info is not None:
        info = red_steps(info, conflict, tests_failed, timed_out)
    if result == "failure" and job is None:
        print(f"::warning::no job named '#{pr} / {RETEST_JOB}' in this run; the description cannot name the failure")
    words = red_words(result, conflict, timed_out, info, merged)
    remove_label(pr)
    post_kind(head, "red", words, dev, since)
    lines = [
        f"**`{LABEL}` taken off: red against `dev`.** Head {head[:10]}, merged with `dev` {dev[:10]}, is red "
        f"on the tests it shares with {merged}: {words}.",
        "",
        f"The merges changed crates this pull request's tests reach: {crates or 'see the run'}.",
    ]
    if info and info["builds"]:
        lines += ["", "Did not compile:", *[f"- `{b}`" for b in info["builds"]]]
    if info and info["tests"]:
        lines += ["", "Failing tests:", *[f"- `{t}`" for t in info["tests"]]]
    if info and info["failed_steps"]:
        lines += ["", "Failed steps:", *[f"- {s}" for s in info["failed_steps"]]]
    lines += ["", f"Re-test: {info['url'] if info else run_url}", "",
              f"Merge `dev` into this branch and fix it, then label `{LABEL}` again."]
    comment(pr, lines)
    return 0


def selftest() -> int:
    problems = []
    done = lambda name, conclusion="success": {"name": name, "status": "completed", "conclusion": conclusion}  # noqa: E731
    going = lambda name, status="in_progress": {"name": name, "status": status, "conclusion": None}  # noqa: E731
    ok = [done("rust-pass"), done("cli-pass"), done("Economics sim", "skipped"), going(SELF_JOBS[0])]
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
        # An earlier labelling's re-test, cancelled by a newer one or still
        # running, is this flow's own, not the head's.
        ("an earlier re-test cancelled", ok + [done("#7 / re-test", "cancelled"), done("#7 / report")], [], 0,
         False, 0),
        ("a re-test running", ok + [going("#7 / re-test"), going(SELF_JOBS[1])], [], 0, False, 0),
        ("a job merely named like one", ok + [going("#7 / re-test-other")], [], 0, False, 1),
    ]:
        got = len(judge(runs, sts, threads, draft))
        if got != want:
            problems.append(f"judge, {label}: {got} reason(s), want {want}")
    # A second run of a workflow on the same head (a draft marked ready
    # without a push, #1497): only each workflow's newest run is judged.
    def suite(c, sid):
        return {**c, "check_suite": {"id": sid}}

    wf = [
        {"id": 1, "workflow_id": 10, "created_at": "2026-11-22T01:32:00Z", "check_suite_id": 101},
        {"id": 2, "workflow_id": 10, "created_at": "2026-11-22T05:00:00Z", "check_suite_id": 102},
        {"id": 3, "workflow_id": 20, "created_at": "2026-11-22T01:32:00Z", "check_suite_id": 201},
    ]
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
    # The grammar round-trips every kind, a `since` the planner could not
    # establish, and a long description; one outside it reads '?'.
    dev, older, newer = "d" * 40, "a" * 40, "e" * 40
    for kind in KINDS:
        for since in ("c" * 40, UNKNOWN):
            d = describe(kind, "x" * 300, dev, since)
            p = parse({"description": d})
            want = (kind, short(dev), short(since)) if kind in DEV_KINDS else (kind, None, None)
            if len(d) > 140 or (p["kind"], p["dev"], p["since"]) != want:
                problems.append(f"grammar, {kind} since {since[:4]}: {d!r} -> {p}")
        if KINDS[kind] == "success" and kind != "ready":
            problems.append(f"{kind} posts success: only a passed re-test does")
    for text in ("waiting for the owner's merge-ready label", "ready: no dev here", "waiting: dev " + "d" * 12
                 + " since " + "c" * 12 + "; x"):
        if parse({"description": text})["kind"] != "?":
            problems.append(f"parse: {text!r} outside the grammar was read as a state")
    # Who may post. `dev` descends from `older`; `newer` descends from `dev`.
    run = "https://example/actions/runs/5"
    order = {short(older): True, short(newer): False}

    def S(kind, at=dev, url=run):
        return parse({"description": describe(kind, "w", at, "b" * 40), "target_url": url})

    other_old, other_new = "https://example/actions/runs/4", "https://example/actions/runs/6"
    for label, cur, role, want in [
        ("no status", None, "report", False),
        ("its own status", S("re-testing"), "report", True),
        ("its own checking, the label's plan", S("checking"), "plan", True),
        ("an older dev's re-testing", S("re-testing", older, other_new), "report", True),
        ("a newer dev's re-testing", S("re-testing", newer, other_old), "mark", False),
        ("an older dev's ready, a push's plan", S("ready", older, other_old), "mark", True),
        ("the same dev from an older run", S("re-testing", dev, other_old), "report", True),
        ("the same dev from a newer run", S("re-testing", dev, other_new), "report", False),
        ("another run's checking: a push's plan re-tests it", S("checking", url=other_old), "mark", True),
        ("another run's checking: a relabel the report leaves alone", S("checking", url=other_old), "report",
         False),
        ("another run's checking: a newer label's plan decides", S("checking", url=other_new), "plan", False),
        ("waiting after it: the label came off", S("waiting", url=other_new), "report", False),
        ("refused after it", S("refused", url=other_new), "mark", False),
        ("outside the grammar", {"kind": "?", "dev": None, "since": UNKNOWN, "url": other_old}, "report", False),
    ]:
        if may_post(cur, run, dev, role, order.get) != want:
            problems.append(f"may_post, {label}: {not want}")
    # What a report does.
    for label, args, want in [
        ("green", ("success", False, True, True), "ready"),
        ("red", ("failure", False, True, True), "red"),
        ("never ran", ("skipped", False, True, True), "red"),
        ("cancelled by a newer re-test: nothing, the label stays", ("cancelled", False, True, True), "none"),
        ("the head moved", ("failure", True, True, True), "none"),
        ("a newer run holds the status", ("success", False, False, True), "none"),
        ("the label came off", ("success", False, True, False), "none"),
    ]:
        if report_step(*args) != want:
            problems.append(f"report_step, {label}: {report_step(*args)} != {want}")
    info = {"failed_steps": [], "tests": [], "builds": [], "url": "u"}
    for label, result, conflict, timed_out, inf, want in [
        ("never started", "skipped", False, False, None, "did not run"),
        ("timed out", "failure", False, True, {**info, "failed_steps": ["tests"]}, "timed out"),
        ("a conflict", "failure", True, False, {**info, "failed_steps": ["merge"]}, "does not merge"),
        ("failing tests", "failure", False, False, {**info, "tests": ["a b", "c d"]}, "2 failing test(s)"),
        ("a target that did not compile", "failure", False, False, {**info, "builds": ["x (test \"y\")"]},
         "does not build"),
        ("no test named", "failure", False, False, {**info, "failed_steps": ["install Rust"]}, "install Rust"),
    ]:
        if want not in red_words(result, conflict, timed_out, inf, "#1"):
            problems.append(f"red_words, {label}: lacks {want!r}")
    for label, args, want in [
        ("green, nothing in the outputs", ("success", False, False, False), "success"),
        ("green with failing tests", ("success", False, True, False), "failure"),
        ("green with a conflict", ("success", True, False, False), "failure"),
        ("green past the time budget", ("success", False, False, True), "failure"),
        ("a setup step failed", ("failure", False, False, False), "failure"),
        ("cancelled", ("cancelled", False, False, False), "cancelled"),
    ]:
        if verdict_of(*args) != want:
            problems.append(f"verdict_of, {label}: {verdict_of(*args)} != {want}")
    base = {"failed_steps": [], "tests": ["a b"], "builds": [], "url": "u"}
    if red_steps(base, False, True, False)["failed_steps"] != [TESTS_STEP]:
        problems.append("red_steps: failing tests do not name the tests step")
    if red_steps(base, True, False, False)["failed_steps"] != [MERGE_STEP]:
        problems.append("red_steps: a conflict does not name the merge step")
    # The workflows carry the names this reads (rule 47).
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    label_cond = (f"(github.event.action != 'labeled' && github.event.action != 'unlabeled')\n"
                  f"      || github.event.label.name == '{LABEL}'")
    for path, needles in [
        (".github/workflows/merge-ready.yml", [
            ("types: [opened, synchronize, reopened, ready_for_review, labeled, unlabeled]", "the six events"),
            (f"    name: {SELF_JOBS[0]}\n", "the label check named as SELF_JOBS"),
            (f"    name: {SELF_JOBS[1]}\n", "the plan named as SELF_JOBS"),
            ("python3 scripts/ci/merge_ready.py run", "the label check's step"),
            ("python3 scripts/ci/merge_ready.py plan", "the plan's step"),
            ("LABELLED_AT: ${{ github.event.pull_request.updated_at }}", "the label event's time"),
            (label_cond, "the condition that runs nothing for another label"),
            ("name: '#${{ github.event.pull_request.number }}'", "the re-test caller named by the pull request"),
        ]),
        (".github/workflows/merge-ready-dev.yml", [
            ("name: '#${{ matrix.pr }}'", "the re-test caller named by the pull request"),
            ("python3 scripts/ci/merge_ready_overlap.py --plan", "the push's plan"),
        ]),
        (RETEST_WORKFLOW, [
            (f"    name: {RETEST_JOB}\n", "the re-test job's name"),
            (f"    name: {REPORT_JOB}\n", "the report job's name"),
            (f"- name: {MERGE_STEP}\n", "the merge step's name"),
            (f"- name: {TESTS_STEP}\n", "the tests step's name"),
            ("if: steps.merge.outputs.conflict != 'true'\n", "the steps a conflict skips"),
            ("python3 scripts/ci/merge_ready_overlap.py --scope", "the re-test's own scope"),
            ("group: merge-ready-retest-${{ inputs.pr }}", "one re-test per pull request"),
        ] + [n for out in RETEST_OUTPUTS for n in [
            (f"{out}: ${{{{ steps.", f"the job output {out}"),
            (f'echo "{out}=true" >> "$GITHUB_OUTPUT"', f"a step setting {out}"),
            (f"{out.upper()}: ${{{{ needs.retest.outputs.{out} }}}}", f"the report's {out.upper()}")]]),
    ]:
        with open(os.path.join(root, path), encoding="utf-8") as f:
            text = f.read()
        for needle, what in needles:
            if needle not in text:
                problems.append(f"{path} lacks {what} ({needle.strip()!r})")
        if CONTEXT in re.findall(r"^    name: (.*)$", text, re.M):
            problems.append(f"{path}: a job is named {CONTEXT!r}: its green check run would satisfy the required status")
    for p in problems:
        print(f"selftest FAIL: {p}")
    if not problems:
        print("selftest: an early, red or draft label is refused, a push clears it, the status grammar, the newest "
              "dev's run holds the status, a superseded re-test posts nothing, and the workflows carry these names")
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["run"]:
        return run()
    if argv == ["plan"]:
        return plan()
    if len(argv) == 4 and argv[0] == "report":
        return report(int(argv[1]), argv[2], argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
