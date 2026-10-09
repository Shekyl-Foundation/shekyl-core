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
# path that is being deleted. The list is scripts/ci/dial_path_freeze.tsv.
# It has three kinds of row:
#
#   body    a function, compared from its anchor to its closing brace;
#   calls   the lines inside a function that call another;
#   shrink  a file whose count of non-blank, non-comment lines may not go up
#           (net_node.inl and net_node.h are shrink-only, Rick 2026-10-08).
#
# For a body or calls row, the base and head revisions are compared:
#
#   present at both and different   FAIL
#   gone at head                    PASS, and "gone" means gone: the bare
#                                   name matches nothing under src/p2p at
#                                   head outside comments and string
#                                   literals, and the base body does not
#                                   survive under another signature
#   anchor gone, name still present FAIL  (renamed or re-signed, not deleted)
#   unchanged                       PASS
#
# For a shrink row, the file's code-line count at head may not exceed its
# count at base. Comment and blank lines are not code lines; the gate's own
# scanner decides which is which, the same scanner that matches braces.
#
# Rule 47: a row the gate cannot find at the base revision fails. It is not
# skipped, because a gate that finds nothing to compare reports the same
# green as a gate that compared everything.
#
# THE ONE EXCEPTION is a line in the dialer brief of exactly this form:
#
#   **UNFREEZE (Rick, YYYY-MM-DD):** <anchor or file path> — <reason>
#
# It must be new in the PR (absent at the base revision) and name the full
# anchor from the list, or the shrink row's file path. A matching line lets
# that row change, grow, or be removed while its subject is still present.
# Nothing looser is read.
#
# The list is read at the base revision, so a PR that edits the list is
# still judged against the list it started from. When the base revision's
# list is empty, every frozen function is gone and the freeze is discharged:
# the gate says so and passes. That is the state the cutover PR leaves
# behind; the gate and the list are deleted after it.
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
FROZEN_TREE = "src/p2p"
UNFREEZE = re.compile(r"^\*\*UNFREEZE \(Rick, \d{4}-\d{2}-\d{2}\):\*\* (?P<subject>.+?) — (?P<reason>.+)$")


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
        if self.kind == "shrink":
            return f"{self.path}: shrink-only"
        return f"{self.path}: {self.name}"

    @property
    def subject(self) -> str:
        """What an UNFREEZE line must name to lift this row."""
        return self.path if self.kind == "shrink" else self.anchor


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
        elif fields[0] == "shrink" and len(fields) == 2:
            rows.append(Row("shrink", fields[1], "", None))
        else:
            raise GateError(f"{where}:{number}: malformed row: {line!r}")
    return rows


# --- git ---------------------------------------------------------------------


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def git_show(repo: Path, rev: str, path: str) -> str | None:
    """File contents at `rev`, or None when the path is absent there."""
    done = git(repo, "show", f"{rev}:{path}")
    if done.returncode == 0:
        return done.stdout.replace("\r\n", "\n")
    stderr = done.stderr.strip()
    if "does not exist" in stderr or "exists on disk, but not in" in stderr:
        return None
    raise GateError(f"git show {rev}:{path} failed: {stderr}")


def git_rev_parse(repo: Path, rev: str) -> str:
    done = git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}")
    if done.returncode != 0:
        raise GateError(f"cannot resolve revision {rev!r}: {done.stderr.strip()}")
    return done.stdout.strip()


def tree_texts(repo: Path, rev: str, prefix: str) -> dict[str, str]:
    """Every file under `prefix` at `rev`, by path."""
    done = git(repo, "ls-tree", "-r", "--name-only", rev, "--", prefix)
    if done.returncode != 0:
        raise GateError(f"git ls-tree {rev} {prefix} failed: {done.stderr.strip()}")
    texts: dict[str, str] = {}
    for path in done.stdout.split("\n"):
        if path:
            text = git_show(repo, rev, path)
            if text is not None:
                texts[path] = text
    return texts


# --- the C++ scanner ----------------------------------------------------------


def skip_literal_or_comment(text: str, i: int) -> tuple[int, str] | None:
    """If a comment or literal starts at `i`, return (index after it, kind).

    A `'` between two digits is a digit separator (`1'000`), not the start
    of a character literal.
    """
    two = text[i : i + 2]
    if two == "//":
        end = text.find("\n", i)
        return (len(text) if end < 0 else end), "comment"
    if two == "/*":
        end = text.find("*/", i + 2)
        if end < 0:
            raise GateError("unterminated block comment")
        return end + 2, "comment"
    if text[i] in "\"'":
        if (
            text[i] == "'"
            and i > 0
            and text[i - 1].isdigit()
            and i + 1 < len(text)
            and text[i + 1].isdigit()
        ):
            return None
        quote = text[i]
        j = i + 1
        while j < len(text):
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == quote:
                return j + 1, "literal"
            if text[j] == "\n":
                # An unterminated literal on one line: C++ would not compile
                # it, so treat the line end as the literal's end.
                return j, "literal"
            j += 1
        return j, "literal"
    return None


def strip(text: str, kinds: tuple[str, ...]) -> str:
    """`text` with every span of the given kinds replaced by spaces; newlines
    are kept so line counts and line numbers survive."""
    out: list[str] = []
    i = 0
    while i < len(text):
        skipped = skip_literal_or_comment(text, i)
        if skipped is None:
            out.append(text[i])
            i += 1
            continue
        end, kind = skipped
        if kind in kinds:
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:end]))
        else:
            out.append(text[i:end])
        i = end
    return "".join(out)


def strip_comments(text: str) -> str:
    """Comments become spaces. Literals stay: a line holding one is code."""
    return strip(text, ("comment",))


def strip_comments_and_literals(text: str) -> str:
    """Comments and string or character literals become spaces. This is what
    a name search reads: `"open descriptors"` in a log line is not the
    function `open`, and the gate must be able to pass the deletion of a
    function whose bare name is an ordinary word."""
    return strip(text, ("comment", "literal"))


def code_line_count(text: str) -> int:
    """Lines that carry something other than whitespace once comments are gone."""
    return sum(1 for line in strip_comments(text).splitlines() if line.strip())


def word(name: str) -> re.Pattern[str]:
    """`name` as a whole identifier: what `rg -w` matches."""
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])")


def balanced_end(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket closing the one at `start`."""
    assert text[start] == open_ch
    depth = 0
    i = start
    while i < len(text):
        skipped = skip_literal_or_comment(text, i)
        if skipped is not None:
            i = skipped[0]
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


@dataclass(frozen=True)
class Function:
    text: str
    body: str

    @property
    def normalised_body(self) -> str:
        return " ".join(self.body.split())


def extract_function(text: str, anchor: str) -> Function | None:
    """The definition anchored at `anchor`: its text from line start to
    closing brace, and its body from the opening brace.

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
            i = skipped[0]
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
    return Function(text=text[line_start:end], body=text[i:end])


def call_lines(body: str, callee: str) -> list[str]:
    """Lines of `body` that name `callee` outside comments and literals,
    stripped, in order."""
    pattern = word(callee)
    return [
        line.strip()
        for line in strip_comments_and_literals(body).splitlines()
        if pattern.search(line)
    ]


# --- verdicts ----------------------------------------------------------------


@dataclass
class Verdict:
    ok: bool
    text: str


class Head:
    """What the head revision holds under the frozen tree."""

    def __init__(self, texts: dict[str, str]):
        self.texts = texts
        self._stripped = {path: strip_comments_and_literals(text) for path, text in texts.items()}

    def names(self, name: str) -> list[str]:
        """Files where `name` is a whole identifier outside comments and
        literals: `rg -n -w <name> src/p2p`, read by the gate's own scanner."""
        pattern = word(name)
        return sorted(path for path, text in self._stripped.items() if pattern.search(text))

    def body_survives(self, function: Function) -> list[str]:
        """Files where the base body appears, whitespace-normalised. Short
        bodies are skipped: `{ return true; }` proves nothing."""
        if code_line_count(function.body) < 3:
            return []
        needle = function.normalised_body
        return sorted(path for path, text in self.texts.items() if needle in " ".join(text.split()))


def gone(row: Row, base_fn: Function, head: Head, what: str) -> Verdict:
    """The function anchored at `row.anchor` is absent at head. Is it gone?"""
    survivors = head.names(row.name)
    if survivors:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: anchor absent but `{row.name}` is still named at head "
            f"outside comments ({', '.join(survivors)}): renamed or re-signed, not deleted",
        )
    carriers = head.body_survives(base_fn)
    if carriers:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: anchor absent but the body survives under another "
            f"signature ({', '.join(carriers)}): renamed, not deleted",
        )
    return Verdict(True, f"PASS  {row.describe()}: {what}")


def judge_body(row: Row, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    if base_text is None:
        return Verdict(False, f"FAIL  {row.describe()}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {row.describe()}: not found at base (rule 47)")
    head_text = head.texts.get(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        return gone(row, base_fn, head, "deleted")
    if head_fn.text == base_fn.text:
        return Verdict(True, f"PASS  {row.describe()}: unchanged")
    if row.subject in unfrozen:
        return Verdict(True, f"PASS  {row.describe()}: changed under an UNFREEZE line naming it")
    diff = "\n".join(
        difflib.unified_diff(
            base_fn.text.splitlines(),
            head_fn.text.splitlines(),
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


def judge_calls(row: Row, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    assert row.callee is not None
    if base_text is None:
        return Verdict(False, f"FAIL  {row.describe()}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {row.describe()}: {row.name} not found at base (rule 47)")
    base_calls = call_lines(base_fn.body, row.callee)
    if not base_calls:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: no call to {row.callee} inside {row.name} at base (rule 47)",
        )
    head_text = head.texts.get(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        enclosing = gone(row, base_fn, head, f"{row.name} deleted")
        if not enclosing.ok:
            return enclosing
        return callee_gone(row, head, f"{row.name} and its calls deleted")
    head_calls = call_lines(head_fn.body, row.callee)
    if head_calls == base_calls:
        return Verdict(True, f"PASS  {row.describe()}: unchanged")
    if row.subject in unfrozen:
        return Verdict(True, f"PASS  {row.describe()}: changed under an UNFREEZE line naming it")
    if not head_calls:
        return callee_gone(row, head, "calls deleted")
    return Verdict(
        False,
        f"FAIL  {row.describe()}: the frozen call lines changed\n"
        + "\n".join(f"  base: {line}" for line in base_calls)
        + "\n"
        + "\n".join(f"  head: {line}" for line in head_calls),
    )


def callee_gone(row: Row, head: Head, what: str) -> Verdict:
    assert row.callee is not None
    survivors = head.names(row.callee)
    if survivors:
        return Verdict(
            False,
            f"FAIL  {row.describe()}: the calls are gone but `{row.callee}` is still named at "
            f"head outside comments ({', '.join(survivors)}): not deleted",
        )
    return Verdict(True, f"PASS  {row.describe()}: {what}")


def judge_shrink(row: Row, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    if base_text is None:
        return Verdict(False, f"FAIL  {row.describe()}: absent at base (rule 47)")
    head_text = head.texts.get(row.path)
    if head_text is None:
        return Verdict(True, f"PASS  {row.describe()}: file deleted")
    before = code_line_count(base_text)
    after = code_line_count(head_text)
    if after <= before:
        return Verdict(True, f"PASS  {row.describe()}: {before} -> {after} code lines")
    if row.subject in unfrozen:
        return Verdict(
            True,
            f"PASS  {row.describe()}: {before} -> {after} code lines under an UNFREEZE line naming the file",
        )
    return Verdict(
        False,
        f"FAIL  {row.describe()}: {before} -> {after} non-blank, non-comment lines. "
        f"{row.path} is shrink-only (Rick, 2026-10-08); a change may not raise its code-line count",
    )


def judge_removed(row: Row, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    """A row present at base and absent at head."""
    if row.kind == "shrink":
        if row.path not in head.texts:
            return Verdict(True, f"PASS  {row.describe()}: row retired, file deleted")
        if row.subject in unfrozen:
            return Verdict(True, f"PASS  {row.describe()}: row retired under an UNFREEZE line naming the file")
        return Verdict(
            False,
            f"FAIL  {row.describe()}: row removed while the file is still present. "
            f"Lifting it needs a new line in {DEFAULT_BRIEF}: "
            f"**UNFREEZE (Rick, YYYY-MM-DD):** {row.path} — <reason>",
        )
    if base_text is None:
        return Verdict(False, f"FAIL  {row.describe()}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {row.describe()}: not found at base (rule 47)")
    head_text = head.texts.get(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        verdict = gone(row, base_fn, head, "row retired, function deleted")
        if not verdict.ok or row.kind == "body":
            return verdict
        return callee_gone(row, head, "row retired, function and calls deleted")
    if row.kind == "calls" and not call_lines(head_fn.body, row.callee or ""):
        return callee_gone(row, head, "row retired, calls deleted")
    if row.subject in unfrozen:
        return Verdict(True, f"PASS  {row.describe()}: row retired under an UNFREEZE line naming it")
    return Verdict(
        False,
        f"FAIL  {row.describe()}: row removed while the function is still present. "
        f"Lifting it needs a new line in {DEFAULT_BRIEF}: "
        f"**UNFREEZE (Rick, YYYY-MM-DD):** {row.anchor} — <reason>",
    )


# --- the exception -----------------------------------------------------------


def unfreeze_subjects(base_brief: str | None, head_brief: str | None) -> tuple[set[str], list[str]]:
    """Subjects named by UNFREEZE lines that are new at head.

    Returns the subjects and a log of what was read, including lines that
    are not new and therefore do not count.
    """
    base_lines = set(base_brief.splitlines()) if base_brief else set()
    subjects: set[str] = set()
    log: list[str] = []
    if head_brief is None:
        return subjects, log
    for line in head_brief.splitlines():
        match = UNFREEZE.match(line.strip())
        if not match:
            continue
        subject = match.group("subject").strip().strip("`")
        if line in base_lines:
            log.append(f"note  UNFREEZE line already present at base, not counted: {line.strip()}")
            continue
        subjects.add(subject)
        log.append(f"note  UNFREEZE accepted for {subject}: {match.group('reason').strip()}")
    return subjects, log


# --- the run -------------------------------------------------------------------


def run(repo: Path, base: str, head: str, list_path: str, brief_path: str) -> int:
    base_sha = git_rev_parse(repo, base)
    head_sha = git_rev_parse(repo, head)
    print(f"dial-path freeze: base {base_sha[:12]} head {head_sha[:12]} list {list_path}")

    base_list = git_show(repo, base_sha, list_path)
    head_list = git_show(repo, head_sha, list_path)
    if base_list is None and head_list is None:
        raise GateError(f"{list_path} is absent at both revisions; the gate has no subject")
    if base_list is None:
        print("the list is introduced by this change; reading it at head")
    base_rows = parse_list(base_list, f"base:{list_path}") if base_list is not None else []
    head_rows = parse_list(head_list, f"head:{list_path}") if head_list is not None else []

    if base_list is not None and not base_rows:
        print(
            "the freeze list is empty at base: every frozen function is gone and the "
            "freeze is discharged. Delete this gate and the list."
        )
        return 0

    judged = base_rows if base_list is not None else head_rows
    added = [row for row in head_rows if row not in judged]
    removed = [row for row in base_rows if row not in head_rows] if base_list is not None else []

    unfrozen, notes = unfreeze_subjects(
        git_show(repo, base_sha, brief_path), git_show(repo, head_sha, brief_path)
    )
    for note in notes:
        print(note)

    head_tree = Head(tree_texts(repo, head_sha, FROZEN_TREE))
    base_texts = {row.path: git_show(repo, base_sha, row.path) for row in judged + added + removed}

    verdicts: list[Verdict] = []
    for row in judged + added:
        if row.kind == "body":
            verdicts.append(judge_body(row, base_texts[row.path], head_tree, unfrozen))
        elif row.kind == "calls":
            verdicts.append(judge_calls(row, base_texts[row.path], head_tree, unfrozen))
        else:
            verdicts.append(judge_shrink(row, base_texts[row.path], head_tree, unfrozen))
    for row in removed:
        verdicts.append(judge_removed(row, base_texts[row.path], head_tree, unfrozen))

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
