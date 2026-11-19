#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `fresh-against-dev` commit status (Brief C, option (a)).

After a merge to `dev`, the freshness workflow (freshness.yml) re-tests
every open pull request whose tests reach a crate the merge changed, on
that pull request's head merged with the new `dev`
(freshness-retest.yml). It reports through one commit status on the head,
`fresh-against-dev`:

  pending   a re-test is queued or running; the description names the
            merge and the crates it shares with the pull request
  success   the re-test passed
  failure   it failed, timed out, did not merge, or was cancelled; the
            description says which, and a comment on the pull request
            names the merge, the failing tests and the failed steps
  error     the re-test never started

`rust-pass` (rust-audit-test.yml's `pass` job) reads it on a pull request:
absent or `success` passes, anything else fails, so a pull request that is
being re-tested against the `dev` it would merge into, or failed that, is
not mergeable. The status changes after the pull request's own run
finished, so the freshness workflow re-runs `rust-pass` itself, when it
marks the head pending and again with the result.

A newer merge's re-test of the same pull request supersedes an older one
(freshness-retest.yml's concurrency group). Which result stands is
decided by `dev`, not by the order the posts arrive: a status links the
run that posted it, and a run posts on a head only when the head's newest
status is its own or comes from a run on an older `dev` (an ancestor of
its own). Two pushes seconds apart can enter a pull request's group out of
order, so the older re-test cancels the newer; the newer run then reports
red ("cancelled") and the older posts nothing, so the race costs a push,
never a green that predates a merge.

A pull request that moved to a new head since the merge is not marked,
and its old head's report neither comments nor re-runs `rust-pass`: the
new head's own run tests it against `dev`, and a re-run of the old head's
run would join, and cancel, the new head's run (they share a concurrency
group). GitHub re-runs a workflow run at most 50 times; a head whose Rust
run has no re-run left gets a comment saying `rust-pass` cannot read the
re-test, and a push refreshes it.

  freshness_status.py check SHA       rust-pass's gate
  freshness_status.py mark            freshness.yml: every head in RETESTS
                                      pending, and its rust-pass re-run
  freshness_status.py report PR HEAD RESULT
                                      freshness-retest.yml: RESULT is the
                                      re-test job's result
  freshness_status.py --selftest

`gh`, GITHUB_REPOSITORY, GITHUB_RUN_ID and GH_TOKEN come from the workflow;
FRESHNESS_RUN_URL is the run's link, DEV the `dev` commit it tests, MERGED
the merged pull requests (`#N` each), CRATES / RETESTS what
freshness_overlap.py decided.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

# `report` reads job logs through failed_tests.py, imported
# where used: `rust-pass` runs `check` from a checkout of this file alone.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONTEXT = "fresh-against-dev"
PASS_JOB = "rust-pass"
RUST_WORKFLOW = "rust-audit-test.yml"
# freshness-retest.yml's names, held to the file by the selftest: the
# report finds its re-test job by name, and reads a conflict and the time
# budget from the job's outputs.
RETEST_WORKFLOW = ".github/workflows/freshness-retest.yml"
RETEST_JOB = "re-test"
RETEST_OUTPUTS = ("conflict", "timed_out")
# GitHub re-runs a workflow run at most 50 times (attempt 51 is refused).
MAX_RUN_ATTEMPT = 50
# How long a report waits for a rust-pass re-run already in flight (the
# mark's) before re-running it again; rust-pass takes under a minute.
RERUN_WAIT_SECONDS = 300


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], check=True, capture_output=True, text=True).stdout


def repo() -> str:
    return os.environ["GITHUB_REPOSITORY"]


def statuses(sha: str) -> list[dict]:
    """The head's statuses, newest first, as GitHub lists them."""
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/commits/{sha}/statuses", "--jq", ".[]"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line]


def newest(sts: list[dict]) -> dict | None:
    return next((s for s in sts if s.get("context") == CONTEXT), None)


def verdict(sts: list[dict]) -> tuple[bool, str]:
    """The newest `fresh-against-dev` status decides; none at all passes."""
    s = newest(sts)
    if s is None:
        return True, f"{CONTEXT}: absent (no merge to dev has reached this head's tests since it was pushed)"
    if s.get("state") == "success":
        return True, f"{CONTEXT}: success ({s.get('description', '')})"
    return False, f"{CONTEXT}: {s.get('state')} ({s.get('description', '')}) {s.get('target_url', '')}"


def may_post(sts: list[dict], run_url: str, dev: str, ours_first: bool, newer) -> bool:
    """Whether this run, testing `dev`, may post on the head. Yes when the
    head's newest status is this run's, or comes from a run on an older
    `dev`; no when it comes from a run on the same or a newer `dev`, or
    from anything else. With no status at all, only `mark` may (`ours_first`):
    a report with nothing of its own to resolve posts nothing.
    `newer(url)` answers whether this run's `dev` is newer than that of the
    run at `url`, None when `url` is not a freshness run."""
    s = newest(sts)
    if s is None:
        return ours_first
    url = s.get("target_url") or ""
    if url == run_url:
        return True
    return newer(url) is True


def dev_is_newer_than(url: str, dev: str) -> bool | None:
    """Whether `dev` descends from, and is not, the commit the freshness
    run at `url` tested; None when `url` is not a run of this repository."""
    prefix = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo()}/actions/runs/"
    if not url.startswith(prefix) or not url[len(prefix):].isdigit():
        return None
    other = json.loads(gh(f"repos/{repo()}/actions/runs/{url[len(prefix):]}"))["head_sha"]
    if other == dev:
        return False
    return json.loads(gh(f"repos/{repo()}/compare/{other}...{dev}"))["status"] == "ahead"


def check(sha: str) -> int:
    ok, why = verdict(statuses(sha))
    print(why)
    if not ok:
        print(f"::error::this head is not fresh against dev: {why}")
    return 0 if ok else 1


def post(sha: str, state: str, description: str) -> None:
    assert state in ("pending", "success", "failure", "error"), state
    target = os.environ["FRESHNESS_RUN_URL"]
    gh(f"repos/{repo()}/statuses/{sha}", "--method", "POST", "-f", f"state={state}", "-f", f"context={CONTEXT}",
       "-f", f"description={description[:140]}", "-f", f"target_url={target}")
    print(f"{CONTEXT} on {sha[:10]}: {state}: {description[:140]}")


def current_head(pr: int) -> str:
    return json.loads(gh(f"repos/{repo()}/pulls/{pr}"))["head"]["sha"]


def rerun_pass(pr: int, sha: str, wait: bool) -> None:
    """Re-run `rust-pass` on the pull request's newest Rust run for this
    head, so it reads the status just posted. A run still in progress
    reads it when it gets there; `wait` covers the one case where it read
    an older one already, a re-run started by `mark` minutes before."""
    path = f"repos/{repo()}/actions/workflows/{RUST_WORKFLOW}/runs?head_sha={sha}&event=pull_request&per_page=1"
    deadline = time.monotonic() + (RERUN_WAIT_SECONDS if wait else 0)
    while True:
        runs = json.loads(gh(path)).get("workflow_runs", [])
        if not runs:
            print(f"#{pr} {sha[:10]}: no Rust run yet; its {PASS_JOB} will read the status")
            return
        run = runs[0]
        if run["status"] == "completed":
            break
        if time.monotonic() >= deadline:
            print(f"#{pr}: run {run['id']} still {run['status']}: its {PASS_JOB} reads the status when it runs")
            return
        time.sleep(15)
    if run.get("run_attempt", 1) >= MAX_RUN_ATTEMPT:
        print(f"::warning::#{pr}: run {run['id']} has used its {MAX_RUN_ATTEMPT} attempts; {PASS_JOB} cannot re-read")
        gh(f"repos/{repo()}/issues/{pr}/comments", "--method", "POST", "-f",
           f"body=`{PASS_JOB}` cannot read this pull request's `{CONTEXT}` status: its Rust run "
           f"({run['html_url']}) has used GitHub's {MAX_RUN_ATTEMPT} re-runs. Push (a merge of `dev` "
           "will do) for a run that reads it before this merges.")
        return
    jobs = json.loads(gh(f"repos/{repo()}/actions/runs/{run['id']}/jobs?per_page=100")).get("jobs", [])
    job = next((j for j in jobs if j["name"] == PASS_JOB), None)
    if job is None:
        print(f"#{pr}: run {run['id']} has no {PASS_JOB} job (a draft reports another name)")
        return
    gh(f"repos/{repo()}/actions/jobs/{job['id']}/rerun", "--method", "POST")
    print(f"#{pr}: re-ran {PASS_JOB} (job {job['id']}, run {run['id']})")


def mark() -> int:
    merged = os.environ["MERGED"]
    run_url = os.environ["FRESHNESS_RUN_URL"]
    dev = os.environ["DEV"]
    retests = json.loads(os.environ["RETESTS"])
    for r in retests:
        if current_head(r["pr"]) != r["head"]:
            print(f"#{r['pr']}: moved past {r['head'][:10]}; its new head's own run tests it")
            continue
        if not may_post(statuses(r["head"]), run_url, dev, True, lambda u: dev_is_newer_than(u, dev)):
            print(f"#{r['pr']}: a run on a newer dev already holds {CONTEXT}; it reports")
            continue
        crates = ", ".join(r["crates"])
        post(r["head"], "pending", f"re-testing against dev after {merged} ({crates})")
        rerun_pass(r["pr"], r["head"], wait=False)
    return 0


def describe(result: str, conflict: bool, timed_out: bool, info: dict | None, merged: str) -> tuple[str, str]:
    """The state and description for a re-test's result. `conflict` and
    `timed_out` are the re-test job's outputs."""
    after = f"after {merged}"
    if result == "success":
        return "success", f"green against dev {after}"
    if result == "cancelled":
        return "failure", f"re-test cancelled before it finished ({after}); push to re-test"
    if result != "failure":
        return "error", f"re-test did not run ({result}, {after})"
    if conflict:
        return "failure", f"does not merge with dev {after}"
    if timed_out:
        return "failure", f"timed out against dev {after}"
    if info is None:
        return "failure", f"red against dev {after}: see the run"
    if info["builds"]:
        return "failure", f"does not build against dev {after}: {', '.join(info['builds'])}"
    if info["tests"]:
        return "failure", f"red against dev {after}: {len(info['tests'])} failing test(s)"
    return "failure", f"red against dev {after}: {', '.join(info['failed_steps']) or 'see the run'}"


def comment(pr: int, head: str, merged: str, crates: str, description: str, info: dict | None) -> None:
    lines = [
        f"**Not fresh against `dev`.** After {merged} merged, this pull request's head "
        f"{head[:10]} merged with the new `dev` is red: {description}.",
        "",
        f"The merge changed crates this pull request's tests reach: {crates}.",
    ]
    if info and info["builds"]:
        lines += ["", "Did not compile:", *[f"- `{b}`" for b in info["builds"]]]
    if info and info["tests"]:
        lines += ["", "Failing tests:", *[f"- `{t}`" for t in info["tests"]]]
    if info and info["failed_steps"]:
        lines += ["", "Failed steps:", *[f"- {s}" for s in info["failed_steps"]]]
    lines += [
        "",
        f"Re-test: {info['url'] if info else os.environ['FRESHNESS_RUN_URL']}",
        "",
        f"`{PASS_JOB}` stays red while `{CONTEXT}` is. Merge `dev` into this branch and fix it; "
        "the push's own run tests it against the new `dev`.",
    ]
    gh(f"repos/{repo()}/issues/{pr}/comments", "--method", "POST", "-f", "body=" + "\n".join(lines))


def report(pr: int, head: str, result: str) -> int:
    merged = os.environ["MERGED"]
    run_url = os.environ["FRESHNESS_RUN_URL"]
    dev = os.environ["DEV"]
    if not may_post(statuses(head), run_url, dev, False, lambda u: dev_is_newer_than(u, dev)):
        print(f"#{pr} {head[:10]}: a run on the same or a newer dev holds {CONTEXT}; it reports")
        return 0
    jobs = json.loads(gh(f"repos/{repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}/jobs?per_page=100")).get("jobs", [])
    job = next((j for j in jobs if j["name"] == f"#{pr} / {RETEST_JOB}"), None)
    import failed_tests

    info = failed_tests.describe(job) if job and result == "failure" else None
    if result == "failure" and job is None:
        print(f"::warning::no job named '#{pr} / {RETEST_JOB}' in this run; the description cannot name the failure")
    conflict = os.environ.get("CONFLICT") == "true"
    timed_out = os.environ.get("TIMED_OUT") == "true"
    state, description = describe(result, conflict, timed_out, info, merged)
    post(head, state, description)
    if current_head(pr) != head:
        print(f"#{pr}: moved past {head[:10]}; no comment or re-run (its new head's own run tests it)")
        return 0
    if state != "success":
        comment(pr, head, merged, os.environ.get("CRATES", ""), description, info)
    rerun_pass(pr, head, wait=True)
    return 0


def selftest() -> int:
    run = "https://example/run/1"
    S = lambda state, url=run, **kw: {"context": CONTEXT, "state": state, "target_url": url, **kw}  # noqa: E731
    cases = [
        ("no status at all", [], True),
        ("only other contexts", [{"context": "ci/x", "state": "failure"}], True),
        ("success", [S("success", description="ok")], True),
        ("pending", [S("pending", description="re-testing")], False),
        ("failure", [S("failure", description="red after #1")], False),
        ("error", [S("error")], False),
        ("the newest decides: failure over an older success", [S("failure"), S("success")], False),
        ("the newest decides: success over an older failure", [S("success"), S("failure")], True),
    ]
    problems = []
    for label, sts, want in cases:
        got, _ = verdict(sts)
        if got != want:
            problems.append(f"verdict, {label}: {got} != {want}")
    # Run 2 tested an older dev than this run (1), run 3 a newer one, and
    # anything else is not a freshness run.
    older, newer_run, foreign = "https://example/run/2", "https://example/run/3", "https://example/elsewhere"
    order = {older: True, newer_run: False, foreign: None}
    for label, sts, ours_first, want in [
        ("this run's own status", [S("pending")], False, True),
        ("an older dev's status posted after this run's", [S("pending", older), S("pending")], False, True),
        ("a newer dev's status posted before this run's report", [S("pending", newer_run)], False, False),
        ("a newer dev's status over this run's", [S("pending", newer_run), S("pending")], False, False),
        ("a status from no freshness run", [S("success", foreign)], True, False),
        ("no status: mark posts", [], True, True),
        ("no status: a report has nothing to resolve", [], False, False),
    ]:
        if may_post(sts, run, "dev1", ours_first, order.get) != want:
            problems.append(f"may_post, {label}: {not want}")
    info = {"failed_steps": [], "tests": [], "builds": [], "url": "u"}
    for label, result, conflict, timed_out, inf, want in [
        ("green", "success", False, False, None, "success"),
        ("cancelled is red, never left pending", "cancelled", False, False, None, "failure"),
        ("never started", "skipped", False, False, None, "error"),
        ("timed out", "failure", False, True, {**info, "failed_steps": ["tests"]}, "timed out"),
        ("a conflict", "failure", True, False, {**info, "failed_steps": ["merge"]}, "does not merge"),
        ("failing tests", "failure", False, False, {**info, "failed_steps": ["tests"], "tests": ["a b", "c d"]},
         "2 failing test(s)"),
        ("a target that did not compile", "failure", False, False,
         {**info, "failed_steps": ["tests"], "builds": ['shekyl-daemon (test "owning_connection")']},
         "does not build against dev"),
        ("no test named", "failure", False, False, {**info, "failed_steps": ["install Rust"]}, "install Rust"),
    ]:
        state, description = describe(result, conflict, timed_out, inf, "#1")
        if want not in (state, ) and want not in description:
            problems.append(f"describe, {label}: {state} {description!r} lacks {want!r}")
        if state == "pending":
            problems.append(f"describe, {label}: a result left the head pending")
    # The names the report reads are freshness-retest.yml's (rule 47): the
    # re-test job's name, its outputs, each set by a step, and the report's
    # environment carrying them.
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    with open(os.path.join(root, RETEST_WORKFLOW), encoding="utf-8") as f:
        workflow = f.read()
    needles = [(f"    name: {RETEST_JOB}\n", "the re-test job's name")]
    for out in RETEST_OUTPUTS:
        needles += [
            (f"{out}: ${{{{ steps.", f"the job output {out}"),
            (f'echo "{out}=true" >> "$GITHUB_OUTPUT"', f"a step setting {out}"),
            (f"{out.upper()}: ${{{{ needs.retest.outputs.{out} }}}}", f"the report's {out.upper()}"),
        ]
    for needle, what in needles:
        if needle not in workflow:
            problems.append(f"{RETEST_WORKFLOW} lacks {what} ({needle.strip()!r})")
    if problems:
        for p in problems:
            print(f"selftest FAIL: {p}")
        return 1
    print(f"selftest: {len(cases)} verdict cases, the newest dev's run holds the status, every result "
          f"posts a final state, and {RETEST_WORKFLOW} has the names the report reads")
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] == "--selftest":
        return selftest()
    cmd = argv[0]
    if cmd == "check" and len(argv) == 2:
        return check(argv[1])
    if cmd == "mark" and len(argv) == 1:
        return mark()
    if cmd == "report" and len(argv) == 4:
        return report(int(argv[1]), argv[2], argv[3])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
