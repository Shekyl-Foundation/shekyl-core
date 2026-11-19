#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The `fresh-against-dev` commit status (Brief C, ruled 2026-11-19).

A pull request is tested on its head merged onto the `dev` of its last
push. When another pull request merges first and changes a crate its tests
reach, the head was never tested with that change. The freshness workflow
(freshness.yml) keeps one commit status on the head, `fresh-against-dev`,
and `rust-pass` (rust-audit-test.yml's `pass` job) fails unless it is
absent or green, so a stale head cannot merge.

# States

Each status this script posts carries its state in the description, in one
grammar (`describe_status`, read back by `parse`):

    <kind>: dev <12 hex> since <12 hex or unknown>; <words for people>

  kind        GitHub state  meaning
  stale       pending       a merge since `since` reaches this head's tests;
                            no re-test runs until the `merge-next` label
  re-testing  pending       a re-test of the head merged with `dev` runs
  green       success       the re-test passed (or nothing both changes
                            test: green without a run)
  red         failure/error the re-test failed, timed out, did not merge,
                            was cancelled or never ran

`dev` is the `dev` commit the status speaks for. `since` is the `dev` the
head was last fresh against: a re-test runs the tests both the pull request
and every merge since then reach (freshness_overlap.py), so a head stale
across several merges is re-tested against all of them. It is carried from
status to status until a green resets it.

# Who may post

A newer `dev`'s status is never overwritten by an older one's, whatever
order the runs finish in: a run posts only when the head's newest status is
its own, speaks for an older `dev` (compare API), or speaks for the same
`dev` from an older run. Two runs on one `dev` are a label added twice or a
push and a label racing; the newer run's re-test cancels the older's
(freshness-retest.yml's concurrency group), and the older then posts
nothing.

# rust-pass

`rust-pass` reads the status when it runs, so a status that changes its
verdict (absent or green against anything else) re-runs it. A change that
keeps the verdict (stale to stale, stale to re-testing, re-testing to red)
does not: GitHub allows a workflow run 50 re-runs, and eleven merges a day
would spend them in days. A head whose Rust run has none left gets a
comment asking for a push.

A pull request that moved to a new head is not marked, and its old head's
report neither comments nor re-runs `rust-pass`: the new head's own run
tests it against `dev`, and a re-run of the old head's run would join, and
cancel, the new head's run (they share a concurrency group).

  freshness_status.py check SHA       rust-pass's gate
  freshness_status.py mark            freshness.yml: each row of MARKS
  freshness_status.py report PR HEAD RESULT
                                      freshness-retest.yml: RESULT is the
                                      re-test job's result
  freshness_status.py --selftest

`gh`, GITHUB_REPOSITORY, GITHUB_RUN_ID and GH_TOKEN come from the workflow;
FRESHNESS_RUN_URL is the run's link, DEV the `dev` commit the run speaks
for, MARKS freshness_overlap.py's plan; a report reads MERGED, SINCE,
CRATES, CONFLICT and TIMED_OUT.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

# `report` reads job logs through failed_tests.py, imported
# where used: `rust-pass` runs `check` from a checkout of this file alone.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONTEXT = "fresh-against-dev"
# The label that asks for a re-test (ruled 2026-11-19: on demand, not per
# merge). freshness.yml's label condition names it; the selftest holds the
# two together.
LABEL = "merge-next"
PASS_JOB = "rust-pass"
RUST_WORKFLOW = "rust-audit-test.yml"
FRESHNESS_WORKFLOW = ".github/workflows/freshness.yml"
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
# A `since` the planner could not establish: the re-test then runs the pull
# request's whole scope.
UNKNOWN = "unknown"
SHA_CHARS = 12
KINDS = {"stale": "pending", "re-testing": "pending", "green": "success", "red": ("failure", "error")}
GRAMMAR = re.compile(rf"^(stale|re-testing|green|red): dev ([0-9a-f]{{{SHA_CHARS}}}) since ([0-9a-f]{{{SHA_CHARS}}}|{UNKNOWN})(?:; |$)")
# The one stale comment a pull request carries, found by this marker and
# edited as merges add to it.
STALE_MARKER = "<!-- fresh-against-dev: stale"
STALE_KEY = re.compile(rf"{STALE_MARKER} head=([0-9a-f]{{40}}) since=(\S+) -->")


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


def short(sha: str) -> str:
    return sha if sha == UNKNOWN else sha[:SHA_CHARS]


def describe_status(kind: str, dev: str, since: str, words: str) -> str:
    return f"{kind}: dev {short(dev)} since {short(since)}; {words}"[:140]


def parse(status: dict | None) -> dict | None:
    """A status of this context in the grammar: its kind, `dev` and
    `since`; None for no status. A status of this context outside the
    grammar is `kind` '?' (not fresh, `since` unknown)."""
    if status is None:
        return None
    m = GRAMMAR.match(status.get("description") or "")
    if not m:
        return {"kind": "?", "dev": None, "since": UNKNOWN, "state": status.get("state")}
    return {"kind": m.group(1), "dev": m.group(2), "since": m.group(3), "state": status.get("state")}


def verdict(sts: list[dict]) -> tuple[bool, str]:
    """The newest `fresh-against-dev` status decides; none at all passes."""
    s = newest(sts)
    if s is None:
        return True, f"{CONTEXT}: absent (no merge to dev has reached this head's tests since it was pushed)"
    if s.get("state") == "success":
        return True, f"{CONTEXT}: success ({s.get('description', '')})"
    return False, f"{CONTEXT}: {s.get('state')} ({s.get('description', '')}) {s.get('target_url', '')}"


RUN_ID = re.compile(r"/actions/runs/(\d+)")


def may_post(sts: list[dict], run_url: str, dev: str, ours_first: bool, dev_is_newer) -> bool:
    """Whether this run, speaking for `dev`, may post on the head. Yes when
    the head's newest status is this run's, speaks for an older `dev`, or
    for the same `dev` from an older run; no when it speaks for a newer
    `dev` or comes from a newer run on the same one. With no status at all,
    only `mark` may (`ours_first`): a report with nothing of its own to
    resolve posts nothing. A status of this context outside the grammar
    may be replaced. `dev_is_newer(theirs)` answers whether `dev` descends
    from, and is not, the commit `theirs` (a short SHA) names."""
    s = newest(sts)
    if s is None:
        return ours_first
    url = s.get("target_url") or ""
    if url == run_url:
        return True
    theirs = parse(s)
    if theirs["kind"] == "?":
        return True
    if theirs["dev"] == short(dev):
        mine, other = RUN_ID.search(run_url), RUN_ID.search(url)
        return not (mine and other) or int(mine.group(1)) > int(other.group(1))
    return dev_is_newer(theirs["dev"]) is True


def dev_is_newer_than(theirs: str, dev: str) -> bool:
    """Whether `dev` descends from, and is not, the commit `theirs` names."""
    full = json.loads(gh(f"repos/{repo()}/commits/{theirs}"))["sha"]
    if full == dev:
        return False
    return json.loads(gh(f"repos/{repo()}/compare/{full}...{dev}"))["status"] == "ahead"


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
       "-f", f"description={description}", "-f", f"target_url={target}")
    print(f"{CONTEXT} on {sha[:10]}: {state}: {description}")


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


def stale_comment(existing: str | None, head: str, since: str, line: str) -> str:
    """The pull request's one stale comment: kept and added to while the
    head and `since` hold, rewritten when either moved."""
    key = f"{STALE_MARKER} head={head} since={short(since)} -->"
    lines = []
    if existing and existing.startswith(key):
        lines = [x for x in existing.splitlines() if x.startswith("- ")]
    if line not in lines:
        lines.append(line)
    return "\n".join([
        key,
        f"**Stale against `dev`.** Merges since `dev` {short(since)} change crates this pull request's tests "
        f"reach, and head {head[:10]} was not tested with them:",
        "",
        *lines,
        "",
        f"`{PASS_JOB}` fails while `{CONTEXT}` is stale. Add the `{LABEL}` label to re-test this head against "
        "the new `dev` on the tests both changes reach (no re-test runs without it), or merge `dev` and push.",
    ])


def upsert_stale_comment(pr: int, head: str, since: str, line: str) -> None:
    out = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo()}/issues/{pr}/comments", "--jq", ".[]"],
        check=True, capture_output=True, text=True,
    ).stdout
    mine = [c for c in (json.loads(x) for x in out.splitlines() if x)
            if (c.get("user") or {}).get("login") == "github-actions[bot]" and c.get("body", "").startswith(STALE_MARKER)]
    if mine:
        c = mine[-1]
        gh(f"repos/{repo()}/issues/comments/{c['id']}", "--method", "PATCH",
           "-f", "body=" + stale_comment(c["body"], head, since, line))
    else:
        gh(f"repos/{repo()}/issues/{pr}/comments", "--method", "POST", "-f", "body=" + stale_comment(None, head, since, line))


def mark_words(row: dict) -> tuple[str, str, str]:
    """(state, kind, words) for a row of the plan."""
    crates = ", ".join(row["crates"])
    if row["action"] == "stale":
        return "pending", "stale", f"label {LABEL} to re-test ({row['merged']}: {crates})"
    if row["action"] == "retest":
        return "pending", "re-testing", f"{row['merged']}: {crates}"
    if row["action"] == "fresh":
        return "success", "green", f"nothing both changes test ({row['merged']})"
    raise ValueError(f"unknown action {row['action']!r}")


def mark() -> int:
    run_url = os.environ["FRESHNESS_RUN_URL"]
    dev = os.environ["DEV"]
    for row in json.loads(os.environ["MARKS"]):
        pr, head = row["pr"], row["head"]
        if current_head(pr) != head:
            print(f"#{pr}: moved past {head[:10]}; its new head's own run tests it")
            continue
        sts = statuses(head)
        if not may_post(sts, run_url, dev, True, lambda t: dev_is_newer_than(t, dev)):
            print(f"#{pr}: a run on a newer dev, or a newer run, already holds {CONTEXT}; it reports")
            continue
        was_ok, _ = verdict(sts)
        state, kind, words = mark_words(row)
        post(head, state, describe_status(kind, dev, row["since"], words))
        if row["action"] == "stale":
            upsert_stale_comment(pr, head, row["since"], f"- {row['merged']}: {', '.join(row['crates'])}")
        if was_ok != (state == "success"):
            rerun_pass(pr, head, wait=False)
    return 0


def describe(result: str, conflict: bool, timed_out: bool, info: dict | None, merged: str) -> tuple[str, str, str]:
    """(state, kind, words) for a re-test's result. `conflict` and
    `timed_out` are the re-test job's outputs."""
    after = f"after {merged}"
    if result == "success":
        return "success", "green", f"re-tested {after}"
    if result == "cancelled":
        return "failure", "red", f"re-test cancelled before it finished ({after}); label {LABEL} again or push"
    if result != "failure":
        return "error", "red", f"re-test did not run ({result}, {after})"
    if conflict:
        return "failure", "red", f"does not merge with dev {after}"
    if timed_out:
        return "failure", "red", f"timed out {after}"
    if info is None:
        return "failure", "red", f"{after}: see the run"
    if info["builds"]:
        return "failure", "red", f"does not build {after}: {', '.join(info['builds'])}"
    if info["tests"]:
        return "failure", "red", f"{len(info['tests'])} failing test(s) {after}"
    return "failure", "red", f"{after}: {', '.join(info['failed_steps']) or 'see the run'}"


def comment(pr: int, head: str, merged: str, crates: str, words: str, info: dict | None) -> None:
    lines = [
        f"**Not fresh against `dev`.** This pull request's head {head[:10]}, merged with `dev` after "
        f"{merged}, is red: {words}.",
        "",
        f"The merges changed crates this pull request's tests reach: {crates}.",
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
    since = os.environ["SINCE"]
    run_url = os.environ["FRESHNESS_RUN_URL"]
    dev = os.environ["DEV"]
    sts = statuses(head)
    if not may_post(sts, run_url, dev, False, lambda t: dev_is_newer_than(t, dev)):
        print(f"#{pr} {head[:10]}: a run on a newer dev, or a newer run, holds {CONTEXT}; it reports")
        return 0
    was_ok, _ = verdict(sts)
    jobs = json.loads(gh(f"repos/{repo()}/actions/runs/{os.environ['GITHUB_RUN_ID']}/jobs?per_page=100")).get("jobs", [])
    job = next((j for j in jobs if j["name"] == f"#{pr} / {RETEST_JOB}"), None)
    import failed_tests

    info = failed_tests.describe(job) if job and result == "failure" else None
    if result == "failure" and job is None:
        print(f"::warning::no job named '#{pr} / {RETEST_JOB}' in this run; the description cannot name the failure")
    conflict = os.environ.get("CONFLICT") == "true"
    timed_out = os.environ.get("TIMED_OUT") == "true"
    state, kind, words = describe(result, conflict, timed_out, info, merged)
    post(head, state, describe_status(kind, dev, since, words))
    if current_head(pr) != head:
        print(f"#{pr}: moved past {head[:10]}; no comment or re-run (its new head's own run tests it)")
        return 0
    if state != "success":
        comment(pr, head, merged, os.environ.get("CRATES", ""), words, info)
    if was_ok != (state == "success"):
        rerun_pass(pr, head, wait=True)
    return 0


def selftest() -> int:
    run = "https://example/actions/runs/5"
    dev, older, newer = "d" * 40, "a" * 40, "e" * 40

    def S(kind, at=dev, url=run, since="b" * 40, state=None):
        state = state or (KINDS[kind] if isinstance(KINDS[kind], str) else "failure")
        return {"context": CONTEXT, "state": state, "target_url": url,
                "description": describe_status(kind, at, since, "words")}

    problems = []
    for label, sts, want in [
        ("no status at all", [], True),
        ("only other contexts", [{"context": "ci/x", "state": "failure"}], True),
        ("green", [S("green")], True),
        ("stale", [S("stale")], False),
        ("re-testing", [S("re-testing")], False),
        ("red", [S("red")], False),
        ("the newest decides: red over an older green", [S("red"), S("green")], False),
        ("the newest decides: green over an older stale", [S("green"), S("stale")], True),
    ]:
        if verdict(sts)[0] != want:
            problems.append(f"verdict, {label}: {not want}")
    # The grammar round-trips, including a `since` the planner could not
    # establish, and a description outside it reads as not fresh.
    for kind in KINDS:
        for since in ("c" * 40, UNKNOWN):
            p = parse(S(kind, since=since))
            if (p["kind"], p["dev"], p["since"]) != (kind, short(dev), short(since)):
                problems.append(f"parse, {kind} since {since[:4]}: {p}")
    if parse({"context": CONTEXT, "state": "pending", "description": "re-testing against dev after #1"})["kind"] != "?":
        problems.append("parse: a description outside the grammar was read as a state")
    long = describe_status("stale", dev, "c" * 40, "x" * 300)
    if len(long) != 140 or parse({"description": long})["kind"] != "stale":
        problems.append("describe_status: a long description lost its state or passed GitHub's 140 characters")
    # Ordering: `dev` descends from `older`; `newer` descends from `dev`.
    order = {short(older): True, short(newer): False}
    for label, sts, ours_first, want in [
        ("this run's own status", [S("re-testing")], False, True),
        ("an older dev's status posted after this run's", [S("stale", older, "https://example/actions/runs/9"),
                                                          S("re-testing")], False, True),
        ("a newer dev's status", [S("stale", newer, "https://example/actions/runs/3")], False, False),
        ("the same dev from an older run (a label added twice)",
         [S("re-testing", dev, "https://example/actions/runs/4")], True, True),
        ("the same dev from a newer run", [S("re-testing", dev, "https://example/actions/runs/6")], True, False),
        ("a status outside the grammar", [{"context": CONTEXT, "state": "pending", "description": "old",
                                           "target_url": "https://example/x"}], True, True),
        ("no status: mark posts", [], True, True),
        ("no status: a report has nothing to resolve", [], False, False),
    ]:
        if may_post(sts, run, dev, ours_first, order.get) != want:
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
         "does not build"),
        ("no test named", "failure", False, False, {**info, "failed_steps": ["install Rust"]}, "install Rust"),
    ]:
        state, kind, words = describe(result, conflict, timed_out, inf, "#1")
        if want != state and want not in words:
            problems.append(f"describe, {label}: {state} {words!r} lacks {want!r}")
        if state == "pending" or (state == "success") != (kind == "green"):
            problems.append(f"describe, {label}: {state} with kind {kind}")
    for action, want in [("stale", ("pending", "stale")), ("retest", ("pending", "re-testing")),
                         ("fresh", ("success", "green"))]:
        state, kind, _ = mark_words({"action": action, "crates": ["c"], "merged": "#1"})
        if (state, kind) != want:
            problems.append(f"mark_words, {action}: {state} {kind}")
    # One stale comment: added to while head and `since` hold, rewritten
    # when either moves.
    h1, h2 = "1" * 40, "2" * 40
    c1 = stale_comment(None, h1, "c" * 40, "- #1: a")
    c2 = stale_comment(c1, h1, "c" * 40, "- #2: b")
    c3 = stale_comment(c2, h2, "c" * 40, "- #3: c")
    if not (c2.count("\n- #") == 2 and "- #1: a" in c2 and STALE_KEY.match(c2)):
        problems.append(f"stale_comment did not add a merge: {c2!r}")
    if "- #1: a" in c3 or "- #3: c" not in c3:
        problems.append(f"stale_comment kept an old head's merges: {c3!r}")
    if stale_comment(c2, h1, "c" * 40, "- #2: b") != c2:
        problems.append("stale_comment repeated a merge")
    # The names the report and the label read are the workflows' (rule 47).
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    for path, needles in [
        (RETEST_WORKFLOW, [(f"    name: {RETEST_JOB}\n", "the re-test job's name"),
                           ("SINCE: ${{ inputs.since }}", "the report's SINCE"),
                           ("ref: ${{ inputs.dev }}", "the report's checkout of dev's scripts")]
         + [n for out in RETEST_OUTPUTS for n in [
             (f"{out}: ${{{{ steps.", f"the job output {out}"),
             (f'echo "{out}=true" >> "$GITHUB_OUTPUT"', f"a step setting {out}"),
             (f"{out.upper()}: ${{{{ needs.retest.outputs.{out} }}}}", f"the report's {out.upper()}")]]),
        (FRESHNESS_WORKFLOW, [(f"github.event.label.name == '{LABEL}'", f"the {LABEL} label condition"),
                              ("name: '#${{ matrix.pr }}'", "the caller job named by the pull request"),
                              ("types: [labeled]", "the label trigger")]),
    ]:
        with open(os.path.join(root, path), encoding="utf-8") as f:
            text = f.read()
        for needle, what in needles:
            if needle not in text:
                problems.append(f"{path} lacks {what} ({needle.strip()!r})")
    if problems:
        for p in problems:
            print(f"selftest FAIL: {p}")
        return 1
    print("selftest: verdicts, the status grammar, the newest dev's run holds the status, every result posts "
          "a final state, one stale comment per head, and the workflows carry the names this reads")
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
