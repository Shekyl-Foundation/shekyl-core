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
  nextest_report.py <junit.xml>   # markdown to $GITHUB_STEP_SUMMARY, else stdout
  nextest_report.py --selftest

Exit 0 when the report was written, flaky tests or not; this report is not
the job's verdict, nextest's exit status is. Exit 2 when the file is
missing, does not parse, or holds no test: a report over nothing would read
as a clean run (rule 47).
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


def parse(xml_text: str) -> Run:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NoSubject(f"the JUnit file does not parse: {e}") from e
    if root.tag != "testsuites":
        raise NoSubject(f"the root element is <{root.tag}>, not <testsuites>")
    cases = []
    for suite in root.iter("testsuite"):
        for tc in suite.iter("testcase"):
            cases.append(
                Case(
                    binary=suite.get("name", "?"),
                    name=tc.get("name", "?"),
                    start=datetime.fromisoformat(tc.get("timestamp")),
                    seconds=float(tc.get("time", "0")),
                    flaky_tries=len(tc.findall("flakyFailure")),
                    failed=tc.find("failure") is not None or tc.find("error") is not None,
                )
            )
    if not cases:
        raise NoSubject("the JUnit file holds no test")
    return Run(cases=cases, wall_seconds=float(root.get("time", "0")))


def fmt_secs(s: float) -> str:
    if s >= 60:
        return f"{int(s // 60)}m{int(s % 60):02d}s"
    return f"{s:.1f}s"


def report(run: Run) -> tuple[str, list[str]]:
    """The markdown summary, and one annotation line per flaky test."""
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
    for bad, why in [
        ('<testsuites name="nextest-run" time="0"></testsuites>', "no test"),
        ("<testsuites", "does not parse"),
        ("<testsuite name='x'/>", "not <testsuites>"),
    ]:
        try:
            parse(bad)
            problems.append(f"a file with {why} was accepted")
        except NoSubject:
            pass
    if problems:
        for p in problems:
            print(f"SELFTEST FAIL: {p}")
        return 1
    print(
        "SELFTEST PASS: a flaky test is listed and annotated, a test failed on "
        "every try is not flaky, the slow tables lead with the slowest, and an "
        "empty, unparseable or foreign file is refused"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) != 1:
        print(__doc__.split("\n\n")[-2], file=sys.stderr)
        return 2
    path = argv[0]
    try:
        with open(path, encoding="utf-8") as f:
            run = parse(f.read())
    except (OSError, NoSubject) as e:
        print(f"nextest report: {path}: {e}", file=sys.stderr)
        return 2
    md, annotations = report(run)
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
