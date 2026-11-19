#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `merge-ready` commit status: the owning lane's "done", as a mark
GitHub enforces (ruled 2026-11-19).

# Why

Pull requests were merged when the required checks went green while other
workflows and fleet runs on the same head were still going. A draft is the
wrong tool, since rule 06 skips the expensive jobs on a draft. The owning
lane applies the `merge-ready` label when every check on the current head
has concluded, its fleet and local runs for that head are done, and its
review threads are resolved; `merge-ready` is the required status that holds
the pull request to that.

# The status

`merge-ready` is a commit status on the pull request's head, posted by
merge-ready.yml on every pull request event:

  pending   waiting for the owner's label, or the label was refused
  success   the label is on, and when it went on every check on the head
            had concluded green and no review thread was open

A status is never skipped: a head with no `merge-ready` status at all is
also blocked by the ruleset ("expected"), so no event path turns it into a
pass. Rule 06's trap, a skipped job counting as a pass, does not reach it.

# What each event does (`decide`)

  synchronize        a push: the label comes off and the new head is
                     pending, so a label never vouches for a head it did
                     not see
  labeled            the label going on is checked: every check run and
                     status on the head, this check excluded and `EXCLUDED`
                     by name, must have concluded, none red; no review
                     thread may be open; the pull request may not be a
                     draft. Anything else and the label comes off, with a
                     comment naming each check, and the status stays
                     pending
  unlabeled          pending
  opened, reopened   pending, or the label check when it is on
  ready_for_review   the label comes off (the draft's skipped jobs now run)

A check run created by the labelling itself (another workflow listening for
labels, whose jobs skip at once) is given `SETTLE_SECONDS` to conclude
before it counts as running. One that started before the label went on
(its check suite, the run of its workflow, was created before
`LABELLED_AT` less `GRACE_SECONDS`) is not waited for: the label is
refused at once. A check run's own start time cannot tell: it is when a
runner picked the job up, which a queue puts minutes after the event.

Not seen: a check re-run on the head after the label went on. The events
that report a finished run (`check_suite`, `workflow_run`) take their
workflow from the default branch, which is `main`; the rule is that the
lane labels last and pushes, which clears the label, to change anything.

  merge_ready.py run        merge-ready.yml's step; reads EVENT, PR, HEAD,
                            DRAFT, LABEL (the event's label), HAS_LABEL,
                            LABELLED_AT, RUN_URL, GITHUB_REPOSITORY, GH_TOKEN
  merge_ready.py --selftest
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta

LABEL = "merge-ready"
CONTEXT = "merge-ready"
# This workflow's own job: it is running while it reads the head. Not named
# CONTEXT: a ruleset's required check matches a check run and a commit
# status by name alike, and this job always ends green.
SELF_JOBS = ("merge-ready label check",)
# Checks that never conclude on this repository, each with why. A check
# left out of a judgment is named here, never dropped silently.
EXCLUDED: dict[str, str] = {}
# A check run the labelling itself started (a workflow listening for
# labels, its jobs skipped at once) concludes within seconds.
SETTLE_SECONDS = 90
POLL_SECONDS = 10
# How far before the label event a check suite the labelling created may
# read as created: the two timestamps come from different services.
GRACE_SECONDS = 5
GREEN = {"success", "neutral", "skipped"}
WAITING = "waiting for the owner's merge-ready label"


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout


def repo() -> str:
    return os.environ["GITHUB_REPOSITORY"]


def when(stamp: str | None) -> datetime | None:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None


def settling(check: dict, labelled_at: str | None) -> bool:
    """Whether a running check may have been started by the labelling: its
    check suite was created no earlier than the label, less GRACE_SECONDS.
    Without either time, every running check may wait."""
    at, created = when(labelled_at), when(check.get("suite_created_at"))
    return at is None or created is None or created >= at - timedelta(seconds=GRACE_SECONDS)


def judge(check_runs: list[dict], statuses: list[dict], open_threads: int, draft: bool,
          labelled_at: str | None = None) -> list[tuple[str, bool]]:
    """Why the label cannot stand on this head, each with whether it may
    still settle: each check still running (settling when the labelling may
    have started it) or red, by name, an open review thread, a draft. Empty
    means it stands."""
    out = []
    for c in check_runs:
        name = c.get("name", "")
        if name in SELF_JOBS or name in EXCLUDED:
            continue
        if c.get("status") != "completed":
            out.append((f"`{name}` is {c.get('status')}", settling(c, labelled_at)))
        elif c.get("conclusion") not in GREEN:
            out.append((f"`{name}` concluded {c.get('conclusion')}", False))
    for s in statuses:
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


def decide(event: str, label: str, has_label: bool) -> str:
    """The step an event takes: 'clear' (remove the label, post pending),
    'judge' (check the label), or 'wait' (post pending)."""
    if event in ("synchronize", "ready_for_review"):
        return "clear" if has_label else "wait"
    if event == "labeled" and label == LABEL:
        return "judge"
    if event in ("opened", "reopened", "labeled", "unlabeled"):
        return "judge" if has_label else "wait"
    raise ValueError(f"merge-ready.yml does not listen for {event!r}")


def post(sha: str, state: str, description: str) -> None:
    gh(f"repos/{repo()}/statuses/{sha}", "--method", "POST", "-f", f"state={state}", "-f", f"context={CONTEXT}",
       "-f", f"description={description[:140]}", "-f", f"target_url={os.environ['RUN_URL']}")
    print(f"{CONTEXT} on {sha[:10]}: {state}: {description[:140]}")


def remove_label(pr: int) -> None:
    subprocess.run(["gh", "api", "--method", "DELETE", f"repos/{repo()}/issues/{pr}/labels/{LABEL}"],
                   capture_output=True, text=True)
    still = json.loads(gh(f"repos/{repo()}/issues/{pr}/labels"))
    if any(lb["name"] == LABEL for lb in still):
        raise RuntimeError(f"#{pr}: the {LABEL} label is still on after removing it")


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


def statuses(sha: str) -> list[dict]:
    return json.loads(gh(f"repos/{repo()}/commits/{sha}/status"))["statuses"]


def open_threads(pr: int) -> int:
    owner, name = repo().split("/")
    query = ("query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p){"
             "reviewThreads(first:100){nodes{isResolved}}}}}")
    data = json.loads(gh("graphql", "-f", f"query={query}", "-f", f"o={owner}", "-f", f"n={name}", "-F", f"p={pr}"))
    nodes = data["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
    return sum(1 for n in nodes if not n["isResolved"])


def run() -> int:
    event, pr, head = os.environ["EVENT"], int(os.environ["PR"]), os.environ["HEAD"]
    has_label = os.environ.get("HAS_LABEL") == "true"
    draft = os.environ.get("DRAFT") == "true"
    step = decide(event, os.environ.get("LABEL", ""), has_label)
    if step == "wait":
        post(head, "pending", WAITING)
        return 0
    if step == "clear":
        remove_label(pr)
        post(head, "pending", f"{WAITING}: a push or a draft marked ready took it off")
        return 0
    deadline = time.monotonic() + SETTLE_SECONDS
    labelled_at = os.environ.get("LABELLED_AT")
    while True:
        found = judge(with_suite_times(check_runs(head)), statuses(head), open_threads(pr), draft, labelled_at)
        if not found or not all(may_settle for _, may_settle in found) or time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    why = [w for w, _ in found]
    if not why:
        post(head, "success", f"labelled at {head[:10]}: every check concluded green, no review thread open")
        return 0
    remove_label(pr)
    post(head, "pending", f"{LABEL} refused: {len(why)} reason(s); see the comment")
    gh(f"repos/{repo()}/issues/{pr}/comments", "--method", "POST", "-f", "body=" + "\n".join([
        f"**`{LABEL}` refused at {head[:10]}** and taken off. Label it again when each of these is done:",
        "",
        *[f"- {w}" for w in why],
        "",
        *([f"Not judged here, by name: {', '.join(f'`{n}` ({r})' for n, r in EXCLUDED.items())}."] if EXCLUDED else []),
    ]))
    return 0


def selftest() -> int:
    problems = []
    done = lambda name, conclusion="success": {"name": name, "status": "completed", "conclusion": conclusion}  # noqa: E731
    going = lambda name, status="in_progress": {"name": name, "status": status, "conclusion": None}  # noqa: E731
    ok = [done("rust-pass"), done("cli-pass"), done("Economics sim", "skipped"), going(SELF_JOBS[0])]
    for label, runs, sts, threads, draft, want in [
        ("every check concluded green", ok, [{"context": "fresh-against-dev", "state": "success"}], 0, False, 0),
        # Negative controls: an early label is refused.
        ("an early label: a check still running", ok + [going("Rust: audit, test, determinism")], [], 0, False, 1),
        ("an early label: a check queued", ok + [going("Win64", "queued")], [], 0, False, 1),
        ("a check that failed", ok + [done("Ubuntu 24.04", "failure")], [], 0, False, 1),
        ("a check that was cancelled", ok + [done("Ubuntu 24.04", "cancelled")], [], 0, False, 1),
        ("a commit status still pending", ok, [{"context": "fresh-against-dev", "state": "pending"}], 0, False, 1),
        ("a commit status red", ok, [{"context": "fresh-against-dev", "state": "failure"}], 0, False, 1),
        ("an open review thread", ok, [], 2, False, 1),
        ("a draft", ok, [], 0, True, 1),
        ("this check's own status is not judged", ok, [{"context": CONTEXT, "state": "pending"}], 0, False, 0),
    ]:
        got = len(judge(runs, sts, threads, draft))
        if got != want:
            problems.append(f"judge, {label}: {got} reason(s), want {want}")
    # Waiting: only a check the labelling may have started settles; one
    # running from before the label refuses it at once.
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
        ("another label on a labelled head re-judges", "labeled", "merge-next", True, "judge"),
        ("another label on an unlabelled head waits", "labeled", "merge-next", False, "wait"),
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
    # The workflow listens for exactly the events decide() answers, runs on
    # every one of them, and names its job as SELF_JOBS (rule 47).
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    with open(os.path.join(root, ".github", "workflows", "merge-ready.yml"), encoding="utf-8") as f:
        workflow = f.read()
    for needle, what in [
        ("types: [opened, synchronize, reopened, ready_for_review, labeled, unlabeled]", "the six events"),
        (f"    name: {SELF_JOBS[0]}\n", "the job named as SELF_JOBS"),
        ("python3 scripts/ci/merge_ready.py run", "the step that runs this"),
        ("LABELLED_AT: ${{ github.event.pull_request.updated_at }}", "the label event's time"),
    ]:
        if needle not in workflow:
            problems.append(f"merge-ready.yml lacks {what} ({needle.strip()!r})")
    if CONTEXT in SELF_JOBS:
        problems.append(f"a job is named {CONTEXT!r}: its green check run would satisfy the required status")
    job = workflow.split("\njobs:\n", 1)[-1]
    if "\n    if:" in job:
        problems.append("merge-ready.yml's job has an `if`: a skipped job is a pass to protection")
    for p in problems:
        print(f"selftest FAIL: {p}")
    if not problems:
        print("selftest: an early, red or draft label is refused, a push and a draft marked ready clear the label, "
              "every event posts a state, and the workflow runs on every event it lists")
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
