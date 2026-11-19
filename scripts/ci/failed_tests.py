#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The tests a CI job failed, read from its log.

Two readers name the failing tests to a human: the dev-red reporter
(`report-dev-red.yml`, one issue per red job on `dev`) and the freshness
re-test's reporter (`freshness-retest.yml`, a comment on the pull request
the re-test failed). Both read the job's log through the API, so one parser
serves every workflow, whatever ran its tests:

  - nextest: the final status lines after its `Summary [` line,
    `[TRY n ]FAIL [time] (k/n) <binary> <test>` (also TIMEOUT, SIG*, ABORT,
    LEAK-FAIL), named `<binary> <test>`. FLAKY, SLOW and PASS lines are not
    failures. A test that failed on every try appears once.
  - `cargo test`, doctests included: `test <name> ... FAILED` at the start
    of a line. nextest's captured output carries the same text indented,
    and is not read twice.

A target that does not compile is named from cargo's own line,
`error: could not compile `<crate>` (<target>)`, as `<crate> (<target>)`:
a merge that breaks another pull request's test code (#1425 and #1426)
fails there, before any test runs. A failed job whose log names neither
(a gate script, a runner fault) reports its failed steps; the steps come
from the jobs API, not from the log.

  failed_tests.py LOGFILE              the failing tests, one per line
  failed_tests.py --job JOB_ID         one job, as JSON
  failed_tests.py --run RUN_ID         every job of the run that did not pass, as JSON
  failed_tests.py --selftest

`--job`/`--run` call `gh api` with GITHUB_REPOSITORY and GH_TOKEN from the
workflow. The JSON per job: id, name, url, conclusion, failed_steps,
tests, builds (the targets that did not compile), aggregate (a workflow's
`*-pass` job, red because another job is; workflow_pass.py).

The log also carries each step's script, echoed before it runs (ANSI
colour, `##[group]Run ...`), so a line the parser reads must be one the
test runner printed: a script's own text names no test.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from workflow_pass import WORKFLOWS as PASS_WORKFLOWS  # noqa: E402

STAMP = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CARGO_FAILED = re.compile(r"^test (\S.*?) \.\.\. FAILED$")
NOT_COMPILED = re.compile(r"^error: could not compile `([^`]+)`(?: \(([^)]*)\))?")
NEXTEST_SUMMARY = re.compile(r"^\s+Summary \[")
NEXTEST_FAILED = re.compile(
    r"^\s+(?:TRY \d+ )?(?:FAIL|TIMEOUT|ABORT|LEAK-FAIL|SIG[A-Z]+)\s*\[[^\]]*\]\s+(?:\([^)]*\)\s+)?(\S+)\s+(\S.*?)\s*$"
)
# A job that did not pass, as the jobs API concludes it.
PASSING = {"success", "skipped", "neutral"}
# A workflow's aggregate job (`cli-pass`, `rust-pass`): red whenever another
# job is, so a report names the jobs it stands for, not it.
AGGREGATES = {context for context, _ in PASS_WORKFLOWS.values()}


def clean(line: str) -> str:
    return ANSI.sub("", STAMP.sub("", line.rstrip("\r\n")))


def failed_tests(log: str) -> list[str]:
    out: list[str] = []
    after_summary = False
    for raw in log.splitlines():
        line = clean(raw)
        if NEXTEST_SUMMARY.match(line):
            after_summary = True
            continue
        m = CARGO_FAILED.match(line)
        if m:
            name = m.group(1)
        elif after_summary and (m := NEXTEST_FAILED.match(line)):
            name = f"{m.group(1)} {m.group(2)}"
        else:
            continue
        if name not in out:
            out.append(name)
    return out


def failed_builds(log: str) -> list[str]:
    out: list[str] = []
    for raw in log.splitlines():
        m = NOT_COMPILED.match(clean(raw))
        if m:
            name = f"{m.group(1)} ({m.group(2)})" if m.group(2) else m.group(1)
            if name not in out:
                out.append(name)
    return out


def gh(path: str) -> str:
    return subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout


def job_log(job_id: int) -> str:
    """The job's log through the REST endpoint, not `gh api`: newer `gh`
    refuses to print a body holding terminal escapes (a test runner's
    colours) without a flag older `gh` does not know. The endpoint
    redirects to a signed URL; the token is an unredirected header, so it
    is not sent there."""
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    req = urllib.request.Request(f"{api}/repos/{os.environ['GITHUB_REPOSITORY']}/actions/jobs/{job_id}/logs")
    req.add_unredirected_header("Authorization", f"Bearer {os.environ['GH_TOKEN']}")
    req.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def describe(job: dict) -> dict:
    try:
        log = job_log(job["id"])
    except OSError as e:
        log = ""
        print(f"::warning::no log for job {job['id']} ({job['name']}): {e}", file=sys.stderr)
    return {
        "id": job["id"],
        "name": job["name"],
        "url": job.get("html_url", ""),
        "conclusion": job.get("conclusion"),
        "failed_steps": [s["name"] for s in job.get("steps", []) if s.get("conclusion") == "failure"],
        "tests": failed_tests(log),
        "builds": failed_builds(log),
        "aggregate": job["name"] in AGGREGATES,
    }


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 2 and argv[0] == "--job":
        repo = os.environ["GITHUB_REPOSITORY"]
        print(json.dumps(describe(json.loads(gh(f"repos/{repo}/actions/jobs/{argv[1]}")))))
        return 0
    if len(argv) == 2 and argv[0] == "--run":
        repo = os.environ["GITHUB_REPOSITORY"]
        jobs = []
        page = 1
        while True:
            got = json.loads(gh(f"repos/{repo}/actions/runs/{argv[1]}/jobs?per_page=100&page={page}"))["jobs"]
            jobs += got
            if len(got) < 100:
                break
            page += 1
        # A job still running (the caller's own) has no conclusion yet.
        red = [j for j in jobs if j.get("conclusion") and j["conclusion"] not in PASSING]
        print(json.dumps([describe(j) for j in red]))
        return 0
    if len(argv) == 1 and not argv[0].startswith("-"):
        with open(argv[0], encoding="utf-8", errors="replace") as f:
            for name in failed_tests(f.read()):
                print(name)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


# Lines as the API serves them: a timestamp on each, CRLF from a Windows
# runner. The cargo case is #1440/#1447's red on `dev` (2026-11-19, the
# Windows job); the nextest case is a run with a flaky test and a failed one
# (2026-11-17), its summary block cut to the lines that matter.
CARGO_LOG = (
    "2026-11-19T02:40:27.1500000Z running 75 tests\r\n"
    "2026-11-19T02:40:27.1588910Z test docs::tests::the_packaged_files_are_the_rendering ... FAILED\r\n"
    "2026-11-19T02:40:27.1590000Z test docs::tests::every_row_renders ... ok\r\n"
    "2026-11-19T02:40:27.1676843Z ---- docs::tests::the_packaged_files_are_the_rendering stdout ----\r\n"
    "2026-11-19T02:40:27.1700000Z test src/lib.rs - render (line 12) ... FAILED\r\n"
    "2026-11-19T02:40:27.1762099Z test result: FAILED. 73 passed; 1 failed; 1 ignored; 0 measured\r\n"
)
NEXTEST_LOG = """\
2026-11-17T10:00:00.0000000Z   TRY 1 FAIL [  11.082s] (─────────) shekyl-multisig::adversaries a_derivation_spends_the_intents_inputs
2026-11-17T10:00:01.0000000Z   TRY 2 FAIL [   7.923s] (6147/9349) shekyl-multisig::adversaries a_derivation_spends_the_intents_inputs
2026-11-17T10:00:02.0000000Z   TRY 1 FAIL [1002.241s] (─────────) shekyl-p2p-harness::chain_sync_opening a_liar_holds_the_opening
2026-11-17T10:00:03.0000000Z   TRY 2 PASS [ 100.951s] (9349/9349) shekyl-p2p-harness::chain_sync_opening a_liar_holds_the_opening
2026-11-17T10:00:04.0000000Z ────────────
2026-11-17T10:00:04.0000000Z      Summary [2784.400s] 9349 tests run: 9348 passed (123 slow, 1 flaky), 1 failed, 180 skipped
2026-11-17T10:00:04.0000000Z         SLOW [  63.507s] ( 699/9349) shekyl-chain-ingest header_path_tests::a_judged_header
2026-11-17T10:00:04.0000000Z    FLAKY 2/2 [ 100.951s] (9349/9349) shekyl-p2p-harness::chain_sync_opening a_liar_holds_the_opening
2026-11-17T10:00:04.0000000Z   TRY 2 FAIL [   7.923s] (6147/9349) shekyl-multisig::adversaries a_derivation_spends_the_intents_inputs
2026-11-17T10:00:04.0000000Z   stdout ───
2026-11-17T10:00:04.0000000Z     test a_derivation_spends_the_intents_inputs ... FAILED
2026-11-17T10:00:04.0000000Z         TIMEOUT [1800.000s] (9000/9349) shekyl-node open::a_stop_closes_the_store
2026-11-17T10:00:04.0000000Z \x1b[31m     SIGSEGV\x1b[0m [   0.100s] (9001/9349) shekyl-store crash::it_segfaults
2026-11-17T10:00:04.0000000Z error: test run failed
"""
# #1425 and #1426's red on `dev` (2026-11-18): a test target that no longer
# compiles, under clippy; and a library, as cargo names one.
BUILD_LOG = (
    "2026-11-18T07:54:17.9689946Z error[E0599]: no method named `exists` found for enum `std::option::Option<T>`\n"
    "2026-11-18T07:54:18.0587864Z error: could not compile `shekyl-daemon` (test \"owning_connection\") due to 2 previous errors\n"
    "2026-11-18T07:54:18.0600000Z error: could not compile `shekyl-store` due to 1 previous error\n"
)
# A step's script as the log echoes it before the step runs.
ECHOED_SCRIPT = (
    "2026-11-19T07:24:44.8986802Z ##[group]Run bash ../scripts/ci/rust_scoped_tests.sh nextest\n"
    "2026-11-19T07:24:44.8987898Z \x1b[36;1m  echo \"test the_split ... FAILED\" >&2\x1b[0m\n"
    "2026-11-19T07:24:44.8987898Z \x1b[36;1m  *) echo \"     Summary [ ok ]\"; echo \"  FAIL [ 1s ] (1/1) a b\" ;;\x1b[0m\n"
    "2026-11-19T07:24:44.8990803Z ##[endgroup]\n"
)


def selftest() -> int:
    problems = []
    got = failed_tests(CARGO_LOG)
    want = ["docs::tests::the_packaged_files_are_the_rendering", "src/lib.rs - render (line 12)"]
    if got != want:
        problems.append(f"cargo test: {got} != {want}")
    got = failed_tests(NEXTEST_LOG)
    want = [
        "shekyl-multisig::adversaries a_derivation_spends_the_intents_inputs",
        "shekyl-node open::a_stop_closes_the_store",
        "shekyl-store crash::it_segfaults",
    ]
    # Before the summary, a TRY 1 FAIL that later passed is not a failure;
    # after it, FLAKY and SLOW are not, and the indented captured output is
    # not a second name.
    if got != want:
        problems.append(f"nextest: {got} != {want}")
    if failed_tests("2026-11-19T00:00:00Z error[E0425]: cannot find value `x`\n"):
        problems.append("a build error was read as a failing test")
    got = failed_builds(BUILD_LOG)
    want = ['shekyl-daemon (test "owning_connection")', "shekyl-store"]
    if got != want:
        problems.append(f"builds: {got} != {want}")
    if failed_tests(BUILD_LOG):
        problems.append("a compile error was read as a failing test")
    if failed_tests(ECHOED_SCRIPT):
        problems.append(f"a step's echoed script was read as a failing test: {failed_tests(ECHOED_SCRIPT)}")
    if problems:
        for p in problems:
            print(f"selftest FAIL: {p}")
        return 1
    print("selftest: cargo test and doctest failures; nextest failures after its summary, "
          "flaky, slow and captured output left out; targets that did not compile; a build error "
          "and a step's echoed script name no test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
