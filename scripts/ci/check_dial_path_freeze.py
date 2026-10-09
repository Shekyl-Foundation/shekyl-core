#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Freezes the C++ dial path until the P2P-3 slice 3 cutover deletes it, and
# holds the C++ files the Rust lanes are replacing to deletions only.
#
# WHY. Ruling A (2026-10-08): the dial path in src/p2p is being replaced by
# the Rust dialer, and every fix landed on it since 2026-09-20 kept alive a
# path that is being deleted. The list is scripts/ci/dial_path_freeze.tsv.
# It has three kinds of row:
#
#   body    a function, compared from its anchor to its closing brace;
#   calls   the lines inside a function that call another;
#   shrink  a file to which a change may add no code lines (Rick,
#           2026-10-09: net_node.inl, net_node.h, levin_notify.cpp).
#
# For a body or calls row, the base and head revisions are compared:
#
#   present at both and different   FAIL
#   gone at head                    PASS, and "gone" means gone: one scan of
#                                   every file under src/, with comments and
#                                   literals stripped, finds neither the
#                                   anchor, nor the witness identifier (the
#                                   bare name unless the row names one), nor
#                                   the base body under another signature
#   anchor gone, name still present FAIL  (renamed or re-signed, not deleted)
#   unchanged                       PASS
#
# Moving a frozen function out of src/p2p and into another directory under
# src/ is still the dial path. The identity scan is that one stripped view;
# it is loaded only when a row is absent, not on an unchanged tree.
#
# For a shrink row, the diff from base to head may add no code lines.
# Deletions are free. A comment-only addition is free. An in-place edit of a
# code line is an added code line, and so is replacing logic with a call
# into Rust: that is visible as one dated UNFREEZE line per PR that moves
# something. That diff strips comments only and keeps literals, so a string
# edit is still an added code line. The identity scan strips literals too:
# a log line that quotes a deleted name is not the function.
#
# Rule 47: a row the gate cannot find at the base revision fails. It is not
# skipped, because a gate that finds nothing to compare reports the same
# green as a gate that compared everything.
#
# A shrink row passes as deleted only when its file is gone, not renamed:
# `git diff --name-status -M base head` over the tree (a pathspec naming the
# old path alone would hide the rename and report a plain D) must show no
# rename or copy from the path, and no file under src/ at head may hold half
# or more of the base file's distinct code lines. A split that leaves one
# half somewhere is a move, not a deletion.
#
# THE ONE EXCEPTION is a line in the dialer brief of exactly this form:
#
#   **UNFREEZE (Rick, YYYY-MM-DD):** <anchor or file path> — <reason>
#
# It must be new in the PR (absent at the base revision) and name the full
# anchor from the list, or the shrink row's file path. A matching line lets
# that row change, add lines, or be removed while its subject is still
# present. Nothing looser is read. Scope (Rick, 2026-10-09): a line naming a
# function covers that function's row and nothing else. Editing a frozen
# function inside a shrink file takes two lines, one naming the anchor and
# one naming the file, because the two rules guard two different things.
#
# The list is read at the base revision, so a PR that edits the list is
# still judged against the list it started from. The cutover removes the
# body and calls rows; when none remain at base the function freeze is
# discharged and the gate says so. A shrink row is retired only when its
# file is deleted: net_node.inl outlives the dial path, and the no-added-
# lines rule is what keeps the next lane from growing it.
#
# Rule 46: nothing here reads a verdict through a pipe. git is run directly
# and its exit status is checked.

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

DEFAULT_LIST = "scripts/ci/dial_path_freeze.tsv"
DEFAULT_BRIEF = "docs/design/P2P_3_SLICE_3_DIALER_BRIEF.md"
# Where a frozen definition, its name, or its body may still be the dial path.
IDENTITY_TREE = "src"
UNFREEZE = re.compile(r"^\*\*UNFREEZE \(Rick, \d{4}-\d{2}-\d{2}\):\*\* (?P<subject>.+?) — (?P<reason>.+)$")


class GateError(Exception):
    """A configuration problem. The gate fails rather than guessing."""


@dataclass(frozen=True)
class Body:
    """A function, compared from its anchor to its closing brace."""

    path: str
    anchor: str
    witness: str | None = None


@dataclass(frozen=True)
class Calls:
    """The lines inside a function that call `callee`."""

    path: str
    anchor: str
    callee: str


@dataclass(frozen=True)
class Shrink:
    """A file to which a change may add no code lines."""

    path: str


Row = Body | Calls | Shrink


def bare_name(anchor: str) -> str:
    """The bare function name: the last `::` segment before the `(`."""
    head = anchor.rstrip("(")
    return head.rsplit("::", 1)[-1].split()[-1]


def gone_marker(row: Body | Calls) -> str:
    """The identifier whose absence from src/ means the function is gone.

    A body row may name a witness: a bare name like `open` is an ordinary
    word, and the witness is what the deletion has to remove.
    """
    if isinstance(row, Body) and row.witness:
        return row.witness
    return bare_name(row.anchor)


def describe(row: Row) -> str:
    if isinstance(row, Calls):
        return f"{row.path}: calls to {row.callee} inside {bare_name(row.anchor)}"
    if isinstance(row, Shrink):
        return f"{row.path}: shrink-only"
    return f"{row.path}: {bare_name(row.anchor)}"


def subject_of(row: Row) -> str:
    """What an UNFREEZE line must name to lift this row."""
    if isinstance(row, Shrink):
        return row.path
    return row.anchor


def parse_list(text: str, where: str) -> list[Row]:
    rows: list[Row] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if fields[0] == "body" and len(fields) == 3:
            rows.append(Body(fields[1], fields[2]))
        elif fields[0] == "body" and len(fields) == 4:
            rows.append(Body(fields[1], fields[2], fields[3]))
        elif fields[0] == "calls" and len(fields) == 4:
            rows.append(Calls(fields[1], fields[2], fields[3]))
        elif fields[0] == "shrink" and len(fields) == 2:
            rows.append(Shrink(fields[1]))
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


def normalised_code(text: str) -> str:
    """`text` with comments gone and each line's whitespace collapsed, so a
    comment edit beside code, or a re-indentation, is not a changed line.
    Blank and comment-only lines become empty lines."""
    return "\n".join(" ".join(line.split()) for line in strip_comments(text).splitlines()) + "\n"


STRUCTURE_ONLY = re.compile(r"^[{}();,]*$")


def content_lines(text: str) -> set[str]:
    """The distinct normalised code lines of `text` that say something: a
    line of braces and punctuation is structure every file shares."""
    return {
        line
        for line in normalised_code(text).splitlines()
        if line and not STRUCTURE_ONLY.match(line)
    }


def added_code_lines(repo: Path, base_text: str, head_text: str) -> list[str]:
    """Code lines present at head and not at base, as git's line diff sees
    them over the normalised texts. A pure deletion adds none; an in-place
    edit adds the edited line."""
    with tempfile.TemporaryDirectory(prefix="freeze-diff-") as scratch:
        before = Path(scratch) / "base"
        after = Path(scratch) / "head"
        before.write_text(normalised_code(base_text))
        after.write_text(normalised_code(head_text))
        done = git(repo, "diff", "--no-index", "--unified=0", "--", str(before), str(after))
    # git diff --no-index: 0 no differences, 1 differences, anything else an error.
    if done.returncode not in (0, 1):
        raise GateError(f"git diff --no-index failed: {done.stderr.strip()}")
    added: list[str] = []
    for line in done.stdout.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            body = line[1:].strip()
            if body:
                added.append(body)
    return added


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
    """The head revision. A row's own file is read on demand. The identity
    scan of src/ is loaded only when a subject is absent."""

    def __init__(self, repo: Path, base_sha: str, sha: str):
        self.repo = repo
        self.base_sha = base_sha
        self.sha = sha
        self._files: dict[str, str | None] = {}
        self._renames: dict[str, list[str]] | None = None
        self._src: dict[str, str] | None = None
        self._stripped: dict[str, str] | None = None

    def text(self, path: str) -> str | None:
        if path not in self._files:
            self._files[path] = git_show(self.repo, self.sha, path)
        return self._files[path]

    def renames_from(self, path: str) -> list[str]:
        """Destinations git reports as a rename or copy of `path`, read from
        `git diff --name-status -M base head` over the whole tree. A pathspec
        naming only `path` would report a plain deletion."""
        if self._renames is None:
            done = git(self.repo, "diff", "--name-status", "-M", "-C", self.base_sha, self.sha)
            if done.returncode != 0:
                raise GateError(f"git diff --name-status failed: {done.stderr.strip()}")
            renames: dict[str, list[str]] = {}
            for line in done.stdout.splitlines():
                fields = line.split("\t")
                if len(fields) == 3 and fields[0][:1] in ("R", "C"):
                    renames.setdefault(fields[1], []).append(f"{fields[0]} {fields[2]}")
            self._renames = renames
        return self._renames.get(path, [])

    def src_texts(self) -> dict[str, str]:
        """Every file under src/ at head."""
        if self._src is None:
            self._src = tree_texts(self.repo, self.sha, IDENTITY_TREE)
        return self._src

    def stripped_src(self) -> dict[str, str]:
        """src/ with comments and literals stripped: the one view the anchor,
        the name, and the body are searched on."""
        if self._stripped is None:
            self._stripped = {
                path: strip_comments_and_literals(text) for path, text in self.src_texts().items()
            }
        return self._stripped

    def names(self, name: str) -> list[str]:
        """Files under src/ where `name` is a whole identifier outside
        comments and literals."""
        pattern = word(name)
        return sorted(path for path, text in self.stripped_src().items() if pattern.search(text))

    def anchored_in(self, anchor: str) -> list[str]:
        """Files under src/ whose code holds the anchor. A comment that
        quotes it does not: the search reads the stripped view. A definition
        moved anywhere under src/ is still the dial path."""
        return sorted(path for path, text in self.stripped_src().items() if anchor in text)

    def body_survives(self, function: Function) -> list[str]:
        """Files under src/ where the base body appears once comments,
        literals, and whitespace are gone. Short bodies are skipped:
        `{ return true; }` proves nothing."""
        if code_line_count(function.body) < 3:
            return []
        needle = " ".join(strip_comments_and_literals(function.body).split())
        return sorted(
            path for path, text in self.stripped_src().items() if needle in " ".join(text.split())
        )


def gone(row: Body | Calls, base_fn: Function, head: Head, what: str) -> Verdict:
    """The function anchored at `row.anchor` is absent from `row.path` at
    head. Is it gone?"""
    moved = head.anchored_in(row.anchor)
    if moved:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: the definition moved to {', '.join(moved)}, not deleted",
        )
    marker = gone_marker(row)
    survivors = head.names(marker)
    if survivors:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: anchor absent but `{marker}` is still named at head "
            f"outside comments and literals ({', '.join(survivors)}): renamed or re-signed, not deleted",
        )
    carriers = head.body_survives(base_fn)
    if carriers:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: anchor absent but the body survives under another "
            f"signature ({', '.join(carriers)}): renamed, not deleted",
        )
    return Verdict(True, f"PASS  {describe(row)}: {what}")


def judge_body(row: Body, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    if base_text is None:
        return Verdict(False, f"FAIL  {describe(row)}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {describe(row)}: not found at base (rule 47)")
    head_text = head.text(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        return gone(row, base_fn, head, "deleted")
    if head_fn.text == base_fn.text:
        return Verdict(True, f"PASS  {describe(row)}: unchanged")
    if subject_of(row) in unfrozen:
        return Verdict(True, f"PASS  {describe(row)}: changed under an UNFREEZE line naming it")
    diff = "\n".join(
        difflib.unified_diff(
            base_fn.text.splitlines(),
            head_fn.text.splitlines(),
            fromfile=f"base:{row.path}:{bare_name(row.anchor)}",
            tofile=f"head:{row.path}:{bare_name(row.anchor)}",
            lineterm="",
            n=1,
        )
    )
    return Verdict(
        False,
        f"FAIL  {describe(row)}: body changed; the dial path is frozen "
        f"(Ruling A, 2026-10-08). Delete it with the cutover or leave it.\n{diff}",
    )


def judge_calls(row: Calls, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    name = bare_name(row.anchor)
    if base_text is None:
        return Verdict(False, f"FAIL  {describe(row)}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {describe(row)}: {name} not found at base (rule 47)")
    base_calls = call_lines(base_fn.body, row.callee)
    if not base_calls:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: no call to {row.callee} inside {name} at base (rule 47)",
        )
    head_text = head.text(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        enclosing = gone(row, base_fn, head, f"{name} deleted")
        if not enclosing.ok:
            return enclosing
        return callee_gone(row, head, f"{name} and its calls deleted")
    head_calls = call_lines(head_fn.body, row.callee)
    if head_calls == base_calls:
        return Verdict(True, f"PASS  {describe(row)}: unchanged")
    if subject_of(row) in unfrozen:
        return Verdict(True, f"PASS  {describe(row)}: changed under an UNFREEZE line naming it")
    if not head_calls:
        return callee_gone(row, head, "calls deleted")
    return Verdict(
        False,
        f"FAIL  {describe(row)}: the frozen call lines changed\n"
        + "\n".join(f"  base: {line}" for line in base_calls)
        + "\n"
        + "\n".join(f"  head: {line}" for line in head_calls),
    )


def callee_gone(row: Calls, head: Head, what: str) -> Verdict:
    survivors = head.names(row.callee)
    if survivors:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: the calls are gone but `{row.callee}` is still named at "
            f"head outside comments and literals ({', '.join(survivors)}): not deleted",
        )
    return Verdict(True, f"PASS  {describe(row)}: {what}")


SURVIVAL_SHARE = 0.5


def file_gone(repo: Path, head: Head, row: Shrink, base_text: str, what: str) -> Verdict:
    """The shrink row's file is absent at head. Was it deleted, or moved?"""
    moved = head.renames_from(row.path)
    if moved:
        return Verdict(
            False,
            f"FAIL  {describe(row)}: renamed, not deleted ({', '.join(moved)}); "
            f"the file is gone only when no path carries it",
        )
    base_lines = content_lines(base_text)
    if base_lines:
        carriers = []
        for path, text in head.src_texts().items():
            shared = len(base_lines & content_lines(text))
            if shared / len(base_lines) >= SURVIVAL_SHARE:
                carriers.append(f"{path} ({shared} of {len(base_lines)} code lines)")
        if carriers:
            return Verdict(
                False,
                f"FAIL  {describe(row)}: the file is gone but its code survives under src/: "
                f"{'; '.join(carriers)}: renamed or split, not deleted",
            )
    return Verdict(True, f"PASS  {describe(row)}: {what}")


def judge_shrink(
    repo: Path, row: Shrink, base_text: str | None, head_text: str | None, head: Head, unfrozen: set[str]
) -> Verdict:
    if base_text is None:
        return Verdict(False, f"FAIL  {describe(row)}: absent at base (rule 47)")
    if head_text is None:
        return file_gone(repo, head, row, base_text, "file deleted")
    before = code_line_count(base_text)
    after = code_line_count(head_text)
    added = added_code_lines(repo, base_text, head_text)
    if not added:
        return Verdict(
            True,
            f"PASS  {describe(row)}: {before} -> {after} code lines, none added",
        )
    if subject_of(row) in unfrozen:
        return Verdict(
            True,
            f"PASS  {describe(row)}: {len(added)} code line(s) added under an UNFREEZE line naming the file",
        )
    shown = "\n".join(f"  + {line}" for line in added[:8])
    more = f"\n  ... and {len(added) - 8} more" if len(added) > 8 else ""
    return Verdict(
        False,
        f"FAIL  {describe(row)}: {len(added)} code line(s) added ({before} -> {after} code lines). "
        f"{row.path} takes deletions only (Rick, 2026-10-09); an added or edited code line needs "
        f"**UNFREEZE (Rick, YYYY-MM-DD):** {row.path} — <reason> in {DEFAULT_BRIEF}\n{shown}{more}",
    )


def judge_removed(row: Row, base_text: str | None, head: Head, unfrozen: set[str]) -> Verdict:
    """A row present at base and absent at head."""
    if isinstance(row, Shrink):
        if head.text(row.path) is None:
            if base_text is None:
                return Verdict(False, f"FAIL  {describe(row)}: absent at base (rule 47)")
            return file_gone(head.repo, head, row, base_text, "row retired, file deleted")
        if subject_of(row) in unfrozen:
            return Verdict(True, f"PASS  {describe(row)}: row retired under an UNFREEZE line naming the file")
        return Verdict(
            False,
            f"FAIL  {describe(row)}: row removed while the file is still present. "
            f"Lifting it needs a new line in {DEFAULT_BRIEF}: "
            f"**UNFREEZE (Rick, YYYY-MM-DD):** {row.path} — <reason>",
        )
    if base_text is None:
        return Verdict(False, f"FAIL  {describe(row)}: {row.path} is absent at base (rule 47)")
    base_fn = extract_function(base_text, row.anchor)
    if base_fn is None:
        return Verdict(False, f"FAIL  {describe(row)}: not found at base (rule 47)")
    head_text = head.text(row.path)
    head_fn = None if head_text is None else extract_function(head_text, row.anchor)
    if head_fn is None:
        verdict = gone(row, base_fn, head, "row retired, function deleted")
        if not verdict.ok or isinstance(row, Body):
            return verdict
        return callee_gone(row, head, "row retired, function and calls deleted")
    if isinstance(row, Calls) and not call_lines(head_fn.body, row.callee):
        return callee_gone(row, head, "row retired, calls deleted")
    if subject_of(row) in unfrozen:
        return Verdict(True, f"PASS  {describe(row)}: row retired under an UNFREEZE line naming it")
    return Verdict(
        False,
        f"FAIL  {describe(row)}: row removed while the function is still present. "
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

    judged = base_rows if base_list is not None else head_rows
    if base_list is not None and not any(isinstance(row, (Body, Calls)) for row in base_rows):
        print(
            "no body or calls rows remain at base: every frozen function is gone and the "
            "function freeze is discharged. The shrink rows stay as long as their files do."
        )
        if not base_rows:
            print("the list is empty; nothing is frozen. Delete this gate and the list.")
            return 0

    added = [row for row in head_rows if row not in judged]
    removed = [row for row in base_rows if row not in head_rows] if base_list is not None else []

    unfrozen, notes = unfreeze_subjects(
        git_show(repo, base_sha, brief_path), git_show(repo, head_sha, brief_path)
    )
    for note in notes:
        print(note)

    head_tree = Head(repo, base_sha, head_sha)
    base_texts = {row.path: git_show(repo, base_sha, row.path) for row in judged + added + removed}

    verdicts: list[Verdict] = []
    for row in judged + added:
        if isinstance(row, Body):
            verdicts.append(judge_body(row, base_texts[row.path], head_tree, unfrozen))
        elif isinstance(row, Calls):
            verdicts.append(judge_calls(row, base_texts[row.path], head_tree, unfrozen))
        else:
            verdicts.append(
                judge_shrink(
                    repo, row, base_texts[row.path], head_tree.text(row.path), head_tree, unfrozen
                )
            )
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
