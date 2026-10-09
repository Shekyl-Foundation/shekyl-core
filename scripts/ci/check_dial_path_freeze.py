#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Freezes the C++ dial path until the P2P-3 slice 3 cutover deletes it.
#
# WHY. Ruling A (2026-10-08): the dial path in src/p2p is being replaced by
# the Rust dialer, and every fix landed on it since 2026-09-20 kept alive a
# path that is being deleted. The list of frozen functions is
# scripts/ci/dial_path_freeze.tsv. For each row this gate compares the
# function at the base revision with the function at the head revision:
#
#   present at both and different   FAIL
#   absent at head                  PASS  (deleted, which is the point)
#   unchanged                       PASS
#
# Rule 47: a row the gate cannot find at the base revision fails. It is not
# skipped, because a gate that finds nothing to compare reports the same
# green as a gate that compared everything.
#
# The list is read at the base revision, so a PR that edits the list is
# still judged against the list it started from. A row removed at head while
# its function is still present is the one exception the ruling allows, and
# it needs a dated ruling by Rick in the dialer brief naming the function.
# The gate looks for that line and reports the exception it accepted.
#
# When the base revision's list is empty, every frozen function is gone and
# the freeze is discharged: the gate says so and passes. That is the state
# the cutover PR leaves behind; the gate and the list are deleted after it.
#
# Rule 46: nothing here reads a verdict through a pipe. git is run directly
# and its exit status is checked.

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LIST = "scripts/ci/dial_path_freeze.tsv"
DEFAULT_BRIEF = "docs/design/P2P_3_SLICE_3_DIALER_BRIEF.md"
RULING_DATE = re.compile(r"\b20\d\d-\d\d-\d\d\b")


class GateError(Exception):
    """A configuration problem. The gate fails rather than guessing."""


@dataclass(frozen=True)
class Row:
    kind: str
    path: str
    anchor: str
    callee: str | None

    @property
    def name(self) -> str:
        """The bare function name: the last `::` segment before the `(`."""
        head = self.anchor.rstrip("(")
        return head.rsplit("::", 1)[-1].split()[-1]

    def describe(self) -> str:
        if self.kind == "calls":
            return f"{self.path}: calls to {self.callee} inside {self.name}"
        return f"{self.path}: {self.name}"


def parse_list(text: str, where: str) -> list[Row]:
    rows: list[Row] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if fields[0] == "body" and len(fields) == 3:
            rows.append(Row("body", fields[1], fields[2], None))
        elif fields[0] == "calls" and len(fields) == 4:
            rows.append(Row("calls", fields[1], fields[2], fields[3]))
        else:
            raise GateError(f"{where}:{number}: malformed row: {line!r}")
    return rows


def git_show(repo: Path, rev: str, path: str) -> str | None:
    """File contents at `rev`, or None when the path is absent there."""
    done = subprocess.run(
        ["git", "-C", str(repo), "show", f"{rev}:{path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode == 0:
        return done.stdout.replace("\r\n", "\n")
    stderr = done.stderr.strip()
    if "does not exist" in stderr or "exists on disk, but not in" in stderr:
        return None
    raise GateError(f"git show {rev}:{path} failed: {stderr}")


def git_rev_parse(repo: Path, rev: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{rev}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise GateError(f"cannot resolve revision {rev!r}: {done.stderr.strip()}")
    return done.stdout.strip()


def skip_literal_or_comment(text: str, i: int) -> int | None:
    """If a comment or literal starts at `i`, return the index after it."""
    two = text[i : i + 2]
    if two == "//":
        end = text.find("\n", i)
        return len(text) if end < 0 else end
    if two == "/*":
        end = text.find("*/", i + 2)
        if end < 0:
            raise GateError("unterminated block comment")
        return end + 2
    if text[i] in "\"'":
        quote = text[i]
        j = i + 1
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == quote:
                return j + 1
            if text[j] == "\n":
                # An unterminated literal on one line: C++ would not compile
                # it, so treat the line end as the literal's end.
                return j
            j += 1
        return j
    return None


def balanced_end(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket closing the one at `start`."""
    assert text[start] == open_ch
    depth = 0
    i = start
    while i < len(text):
        skipped = skip_literal_or_comment(text, i)
        if skipped is not None:
            i = skipped
            continue
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise GateError(f"unbalanced {open_ch}{close_ch}")


def extract_function(text: str, anchor: str) -> str | None:
    """The definition anchored at `anchor`, line start to closing brace.

    None when the anchor is absent. A second occurrence of the anchor is a
    configuration error: the row no longer names one function.
    """
    first = text.find(anchor)
    if first < 0:
        return None
    if text.find(anchor, first + 1) >= 0:
        raise GateError(f"anchor occurs more than once: {anchor!r}")
    paren = first + len(anchor) - 1
    if text[paren] != "(":
        raise GateError(f"anchor must end at its opening parenthesis: {anchor!r}")
    after_params = balanced_end(text, paren, "(", ")")
    i = after_params
    while i < len(text):
        skipped = skip_literal_or_comment(text, i)
        if skipped is not None:
            i = skipped
            continue
        if text[i] == "{":
            break
        if text[i] == ";":
            raise GateError(f"anchor is a declaration, not a definition: {anchor!r}")
        i += 1
    else:
        raise GateError(f"no body after anchor: {anchor!r}")
    end = balanced_end(text, i, "{", "}")
    line_start = text.rfind("\n", 0, first) + 1
    return text[line_start:end]


def call_lines(body: str, callee: str) -> list[str]:
    pattern = re.compile(rf"\b{re.escape(callee)}\b")
    return [line.strip() for line in body.splitlines() if pattern.search(line)]


@dataclass
class Verdict:
    ok: bool
    text: str


def judge_row(row: Row, base_text: str | None, head_text: str | None) -> Verdict:
    if base_text is None:
        return Verdict(False, f"FAIL  {row.describe()}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {row.describe()}: not found at base (rule 47)")
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)

    if row.kind == "body":
        if head_fn is None:
            return Verdict(True, f"PASS  {row.describe()}: deleted")
        if head_fn == base_fn:
            return Verdict(True, f"PASS  {row.describe()}: unchanged")
        diff = "\n".join(
            difflib.unified_diff(
                base_fn.splitlines(),
                head_fn.splitlines(),
                fromfile=f"base:{row.path}:{row.name}",
                tofile=f"head:{row.path}:{row.name}",
                lineterm="",
                n=1,
            )
        )
        return Verdict(
            False,
            f"FAIL  {row.describe()}: body changed; the dial path is frozen "
            f"(Ruling A, 2026-10-08). Delete it with the cutover or leave it.\n{diff}",
        )

    assert row.callee is not None
    base_calls = call_lines(base_fn, row.callee)
    if not base_calls:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: no call to {row.callee} inside {row.name} at base (rule 47)",
        )
    if head_fn is None:
        return Verdict(True, f"PASS  {row.describe()}: {row.name} deleted")
    head_calls = call_lines(head_fn, row.callee)
    if not head_calls:
        return Verdict(True, f"PASS  {row.describe()}: calls deleted")
    if head_calls == base_calls:
        return Verdict(True, f"PASS  {row.describe()}: unchanged")
    return Verdict(
        False,
        f"FAIL  {row.describe()}: the frozen call lines changed\n"
        + "\n".join(f"  base: {line}" for line in base_calls)
        + "\n"
        + "\n".join(f"  head: {line}" for line in head_calls),
    )


def ruling_for(brief: str | None, name: str) -> str | None:
    """A line of the dialer brief that unfreezes `name`: the name, a date, Rick."""
    if brief is None:
        return None
    for line in brief.splitlines():
        if name in line and "Rick" in line and RULING_DATE.search(line):
            return line.strip()
    return None


def judge_removed_row(row: Row, head_text: str | None, brief: str | None) -> Verdict:
    """A row present at base and absent at head."""
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        return Verdict(True, f"PASS  {row.describe()}: row retired, function deleted")
    if row.kind == "calls" and not call_lines(head_fn, row.callee or ""):
        return Verdict(True, f"PASS  {row.describe()}: row retired, calls deleted")
    ruling = ruling_for(brief, row.name)
    if ruling is None:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: row removed while the function is still present. "
            f"Unfreezing needs a dated ruling by Rick in {DEFAULT_BRIEF} naming {row.name}.",
        )
    return Verdict(True, f"PASS  {row.describe()}: unfrozen by ruling: {ruling}")


def run(repo: Path, base: str, head: str, list_path: str, brief_path: str) -> int:
    base_sha = git_rev_parse(repo, base)
    head_sha = git_rev_parse(repo, head)
    print(f"dial-path freeze: base {base_sha[:12]} head {head_sha[:12]} list {list_path}")

    base_list = git_show(repo, base_sha, list_path)
    head_list = git_show(repo, head_sha, list_path)
    if base_list is None and head_list is None:
        raise GateError(f"{list_path} is absent at both revisions; the gate has no subject")
    if base_list is None:
        print(f"the list is introduced by this change; reading it at head")
    base_rows = parse_list(base_list, f"base:{list_path}") if base_list is not None else []
    head_rows = parse_list(head_list, f"head:{list_path}") if head_list is not None else []

    if base_list is not None and not base_rows:
        print("the freeze list is empty at base: every frozen function is gone and the "
              "freeze is discharged. Delete this gate and the list.")
        return 0

    judged = base_rows if base_list is not None else head_rows
    added = [row for row in head_rows if row not in judged]
    removed = [row for row in base_rows if row not in head_rows] if base_list is not None else []

    files = {row.path for row in judged + added + removed}
    base_texts = {path: git_show(repo, base_sha, path) for path in files}
    head_texts = {path: git_show(repo, head_sha, path) for path in files}
    brief = git_show(repo, head_sha, brief_path)

    verdicts: list[Verdict] = []
    for row in judged + added:
        verdicts.append(judge_row(row, base_texts[row.path], head_texts[row.path]))
    for row in removed:
        verdicts.append(judge_removed_row(row, head_texts[row.path], brief))

    for verdict in verdicts:
        print(verdict.text)
    failed = sum(1 for verdict in verdicts if not verdict.ok)
    print(f"dial-path freeze: {len(verdicts)} rows judged, {failed} failed")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="revision the frozen bodies are read from")
    parser.add_argument("--head", default="HEAD", help="revision under judgement")
    parser.add_argument("--repo", default=None, help="repository root (default: this checkout)")
    parser.add_argument("--list", default=DEFAULT_LIST, help="the freeze list, repo-relative")
    parser.add_argument("--brief", default=DEFAULT_BRIEF, help="the dialer brief, repo-relative")
    args = parser.parse_args()

    repo = Path(args.repo) if args.repo else Path(__file__).resolve().parents[2]
    try:
        return run(repo, args.base, args.head, args.list, args.brief)
    except GateError as error:
        print(f"FAIL  dial-path freeze: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
