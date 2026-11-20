#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Summarise a nextest JUnit file for the Rust job: flaky tests first, then
where the time went.

The `ci` profile retries a failing test once (`rust/.config/nextest.toml`).
A test that fails and then passes does not fail the job, so this report is
where it shows: each one is listed under "Flaky" in the job summary and
raised as a warning annotation, which GitHub shows on the pull request.
nextest writes such a test as a `<testcase>` with a `<flakyFailure>` and no
`<failure>`; a test that failed on every try has a `<failure>` (and a
`<rerunFailure>` per retry).

The timing half is what the partition of the test run is sized from:

* the twenty slowest tests, with their binary;
* the five binaries with the most test time (the sum of their tests'
  times, which is what a partition moves between runners), with their
  span, first start to last end, which is how long that binary held the
  step;
* the run's wall time and test count.

Usage:
  nextest_report.py <junit.xml> [--scope <rust_tests>]
                                  # markdown to $GITHUB_STEP_SUMMARY, else stdout
  nextest_report.py --selftest

`--scope` is the Rust job's `rust_tests` value (`scripts/ci/change_scope.py`):
`all` for the workspace run, else the changed packages, whose reverse
closure may hold no test at all (a binary with no tests and no dependents).
nextest records that empty selection as `tests="0"` and passes it
(`--no-tests=pass`); the report then says "0 tests" and exits 0.

The warning annotations are printed only under GitHub Actions, where they
are commands; a local run gets the markdown alone, flaky tests included.

Exit 0 when the report was written, flaky tests or not; this report is not
the job's verdict, nextest's exit status is. Exit 2 when the file is
missing, does not parse, or holds no test outside that scoped empty
selection: a report over nothing would read as a clean run (rule 47).
"""

from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta

SLOWEST_TESTS = 20
SLOWEST_BINARIES = 5


@dataclass
class Case:
    binary: str
    name: str
    start: datetime
    seconds: float
    flaky_tries: int
    failed: bool

    @property
    def end(self) -> datetime:
        return self.start + timedelta(seconds=self.seconds)


@dataclass
class Run:
    cases: list[Case]
    wall_seconds: float


class NoSubject(Exception):
    pass


def parse(xml_text: str, scoped: bool = False) -> Run:
    """`scoped` is a run over the changed packages' reverse closure, not the
    workspace. There an empty selection is a decision nextest made and
    recorded (`tests="0"` on the root, under `--no-tests=pass`), and the
    report says so; a workspace run with no test is a broken run, and a
    file without that count is not nextest's, so both are refused."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NoSubject(f"the JUnit file does not parse: {e}") from e
    if root.tag != "testsuites":
        raise NoSubject(f"the root element is <{root.tag}>, not <testsuites>")
    try:
        wall_seconds = float(root.get("time", ""))
    except ValueError as e:
        raise NoSubject(f"the run has no readable time ({e})") from e
    cases = []
    for suite in root.iter("testsuite"):
        binary = suite.get("name", "?")
        for tc in suite.iter("testcase"):
            name = tc.get("name", "?")
            # nextest writes both on every test case; a file without them is
            # not nextest's, and a report that guessed them would misorder
            # the tables it exists to give.
            try:
                start = datetime.fromisoformat(tc.get("timestamp", ""))
                seconds = float(tc.get("time", ""))
            except ValueError as e:
                raise NoSubject(f"{binary} {name}: no readable timestamp and time ({e})") from e
            cases.append(
                Case(
                    binary=binary,
                    name=name,
                    start=start,
                    seconds=seconds,
                    flaky_tries=len(tc.findall("flakyFailure")),
                    failed=tc.find("failure") is not None or tc.find("error") is not None,
                )
            )
    if not cases and not (scoped and root.get("tests") == "0"):
        raise NoSubject("the JUnit file holds no test")
    return Run(cases=cases, wall_seconds=wall_seconds)


def fmt_secs(s: float) -> str:
    if s >= 60:
        return f"{int(s // 60)}m{int(s % 60):02d}s"
    return f"{s:.1f}s"


def report(run: Run) -> tuple[str, list[str]]:
    """The markdown summary, and one annotation line per flaky test."""
    if not run.cases:
        return "## Rust tests (nextest)\n\n0 tests: the scope selected none.\n", []
    flaky = [c for c in run.cases if c.flaky_tries and not c.failed]
    failed = [c for c in run.cases if c.failed]
    lines = ["## Rust tests (nextest)", ""]
    lines.append(
        f"{len(run.cases)} tests, {len(failed)} failed, {len(flaky)} flaky; "
        f"test run wall time {fmt_secs(run.wall_seconds)}."
    )
    lines += ["", "### Flaky (passed on retry)", ""]
    if flaky:
        lines += ["| Test | Binary | Failed tries |", "|---|---|---|"]
        lines += [f"| `{c.name}` | `{c.binary}` | {c.flaky_tries} |" for c in flaky]
    else:
        lines.append("None.")
    if failed:
        lines += ["", "### Failed", ""]
        lines += [f"- `{c.binary}` `{c.name}`" for c in failed]

    lines += ["", f"### Slowest {SLOWEST_TESTS} tests", "", "| Time | Test | Binary |", "|---|---|---|"]
    for c in sorted(run.cases, key=lambda c: c.seconds, reverse=True)[:SLOWEST_TESTS]:
        lines.append(f"| {fmt_secs(c.seconds)} | `{c.name}` | `{c.binary}` |")

    by_binary: dict[str, list[Case]] = {}
    for c in run.cases:
        by_binary.setdefault(c.binary, []).append(c)
    totals = sorted(
        ((sum(c.seconds for c in cs), b, cs) for b, cs in by_binary.items()),
        key=lambda t: t[0],
        reverse=True,
    )
    lines += [
        "",
        f"### The {SLOWEST_BINARIES} binaries with the most test time",
        "",
        "| Test time | Span | Tests | Binary |",
        "|---|---|---|---|",
    ]
    for total, b, cs in totals[:SLOWEST_BINARIES]:
        span = (max(c.end for c in cs) - min(c.start for c in cs)).total_seconds()
        lines.append(f"| {fmt_secs(total)} | {fmt_secs(span)} | {len(cs)} | `{b}` |")

    annotations = [
        f"::warning title=Flaky test::{c.binary} {c.name} failed {c.flaky_tries} "
        f"time(s), then passed on retry"
        for c in flaky
    ]
    return "\n".join(lines) + "\n", annotations


SELFTEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1" errors="0" time="70.5">
  <testsuite name="crate-a" tests="3" disabled="0" errors="0" failures="1">
    <testcase name="t::passes" classname="crate-a" timestamp="2026-11-07T11:55:06.772-05:00" time="0.042"></testcase>
    <testcase name="t::flaky_once" classname="crate-a" timestamp="2026-11-07T11:55:06.802-05:00" time="0.031">
      <flakyFailure timestamp="2026-11-07T11:55:06.772-05:00" time="0.028" message="panicked" type="test failure">x</flakyFailure>
    </testcase>
    <testcase name="t::always_fails" classname="crate-a" timestamp="2026-11-07T11:55:06.772-05:00" time="0.023">
      <failure message="panicked" type="test failure">x</failure>
      <rerunFailure timestamp="2026-11-07T11:55:06.801-05:00" time="0.033" message="panicked" type="test failure">x</rerunFailure>
    </testcase>
  </testsuite>
  <testsuite name="crate-b::slow" tests="1" disabled="0" errors="0" failures="0">
    <testcase name="slow_one" classname="crate-b::slow" timestamp="2026-11-07T11:55:00.000+00:00" time="70.0"></testcase>
  </testsuite>
</testsuites>
"""


# nextest 0.9.138 for a filterset that selects no test, under --no-tests=pass.
EMPTY_SCOPED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="0" failures="0" errors="0" uuid="21e2338b-8546-48f4-81a4-2a792acfc45c" timestamp="2026-11-09T19:12:12.374-05:00" time="0.000">
</testsuites>
"""


def selftest() -> int:
    """The fixture's flaky and failed cases are nextest's own output for a
    test that failed once then passed, and one that failed on both tries
    (0.9.138, `retries = 1`)."""
    problems = []
    run = parse(SELFTEST_XML)
    md, ann = report(run)
    if len(ann) != 1 or "t::flaky_once" not in ann[0]:
        problems.append(f"expected one flaky annotation for t::flaky_once, got {ann}")
    if "t::always_fails" in "".join(ann):
        problems.append("a test that failed on every try was reported as flaky")
    if "4 tests, 1 failed, 1 flaky" not in md:
        problems.append("the count line is wrong")
    def first_row(heading: str) -> str:
        table = md.split(heading, 1)[1].strip().splitlines()
        return table[2] if len(table) > 2 else ""

    if first_row(f"### Slowest {SLOWEST_TESTS} tests") != "| 1m10s | `slow_one` | `crate-b::slow` |":
        problems.append("the slowest test is not first in its table")
    if first_row("binaries with the most test time") != "| 1m10s | 1m10s | 1 | `crate-b::slow` |":
        problems.append("the binary table's first row is not crate-b::slow with its span")
    clean, ann_clean = report(parse(SELFTEST_XML.replace("<flakyFailure", "<x").replace("</flakyFailure>", "</x>")))
    if ann_clean or "None." not in clean:
        problems.append("a run with no flaky test did not say None")
    empty, ann_empty = report(parse(EMPTY_SCOPED_XML, scoped=True))
    if ann_empty or "0 tests: the scope selected none." not in empty:
        problems.append("a scoped run that selected no test was not reported as such")
    for bad, why in [
        (EMPTY_SCOPED_XML, "no test, outside a scoped run"),
        ('<testsuites name="nextest-run" time="0"></testsuites>', "no test"),
        ("<testsuites", "does not parse"),
        ("<testsuite name='x'/>", "not <testsuites>"),
        (SELFTEST_XML.replace(' timestamp="2026-11-07T11:55:00.000+00:00"', ""), "a test with no timestamp"),
        (SELFTEST_XML.replace('time="70.0"', 'time="soon"'), "a test with no readable time"),
        (SELFTEST_XML.replace('time="70.5"', ""), "a run with no time"),
    ]:
        try:
            parse(bad)
            problems.append(f"a file with {why} was accepted")
        except NoSubject:
            pass
    # A scoped run accepts nextest's own empty selection and nothing else
    # that is empty: a count of zero is the subject.
    try:
        parse('<testsuites name="nextest-run" time="0"></testsuites>', scoped=True)
        problems.append("a scoped run accepted an empty file with no test count")
    except NoSubject:
        pass
    if problems:
        for p in problems:
            print(f"SELFTEST FAIL: {p}")
        return 1
    print(
        "SELFTEST PASS: a flaky test is listed and annotated, a test failed on "
        "every try is not flaky, the slow tables lead with the slowest, a scoped "
        "run that selected no test says so, and an empty, unparseable or foreign "
        "file, or one missing a test's timestamp or time, is refused"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 3 and argv[1] == "--scope" and argv[2]:
        path, scoped = argv[0], argv[2] != "all"
    elif len(argv) == 1:
        path, scoped = argv[0], False
    else:
        print("usage: nextest_report.py <junit.xml> [--scope <rust_tests>] | --selftest", file=sys.stderr)
        return 2
    try:
        with open(path, encoding="utf-8") as f:
            run = parse(f.read(), scoped)
    except (OSError, NoSubject) as e:
        print(f"nextest report: {path}: {e}", file=sys.stderr)
        return 2
    md, annotations = report(run)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for a in annotations:
            print(a)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(md)
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
