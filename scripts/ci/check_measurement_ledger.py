#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Measurement-ledger gate: a constant that rests on a measurement must not
# outlive the code that measurement was taken on without somebody saying so.
#
# THE DEFECT THIS EXISTS FOR. A constant is derived from a capture taken at one
# revision. The code path whose cost it budgets changes later. Nothing notices,
# because the link between the constant, the capture and the code path is
# prose in a design document. Two instances, a month apart: the block-weight
# surge factor rests on a floor capture at `8af70a60a`, and the FCMP++ proof
# changed nine days later; the archival shard length and anchor lag rest on
# fetch captures taken before the serve path began reading each shard twice.
# Both were found by a person reading, long after the change merged.
#
# THE RULE. `docs/benchmarks/measurement_ledger.toml` holds one row per
# cost-justified constant: where it is defined, which tracked benchmark
# measures it, the capture and the revision the capture was taken at, and the
# code paths whose cost it budgets. For every measured row this gate asks one
# question of git: is any commit that touches those paths newer than the
# row's review point? It needs no hardware and reads no timing data.
#
# A ROW IS IN ONE OF THREE STATES, and the gate fails when a row's stated
# state disagrees with git IN EITHER DIRECTION:
#
#   current     nothing touching the paths is newer than the review point.
#               A newer commit is a FAIL that names it.
#   stale       something is newer, the row names it (`stale_since`) and
#               names the carrier of the re-measurement. A `stale` row with
#               nothing newer is a FAIL too: a ledger that cries stale about
#               a current capture is as wrong as the reverse, and the next
#               reader stops believing the word. A stale row KEEPS LISTENING:
#               `stale_through` lists the commits to its paths it has heard,
#               each with a note on the cost, and a commit newer than the
#               last of them is a FAIL. Staleness excuses the row from a
#               fresh capture. It does not excuse the next change that
#               doubles the cost from saying so.
#   unmeasured  no capture exists in the tree. The row is there so the
#               ledger's completeness can be read, and it names its carrier.
#
# So green means "the ledger tells the truth", not "every capture is fresh".
# The stale rows are the rulings that are owed, and they are printed on every
# run.
#
# CLEARING A FAIL is an edit to the ledger, reviewed in the diff like any
# other line: land a newer capture; or add a `cleared` note saying every
# commit through a named one is cost-neutral, and why; or mark the row stale
# with its carrier; or, on a row already stale, add a `stale_through` entry
# saying what the change does to the cost. A commit trailer was considered
# and refused: the judgement "this did not move the cost" belongs next to
# the constant it is about, where the next reader of the constant finds it.
#
# ONLY A NEWER CAPTURE RETIRES STALENESS, and two rules hold that. A
# `cleared` note on a stale row may not reach `stale_since`: otherwise a note
# written about today's change would cover the change that made the row
# stale, and the row would read current with that change declared
# cost-neutral by a sentence about something else. And a row that was stale
# at HEAD's first parent and is current now must sit on a capture that
# includes its old `stale_since`. In CI the first parent is the base branch,
# so the comparison covers the whole pull request; on a local branch it
# covers the last commit only.
#
# THE TOOLCHAIN is on no row's paths and moves every wall-clock figure. Each
# change to `toolchain_file` newer than a current row's review point needs
# one `[[toolchain]]` acknowledgment for the whole ledger, saying what it
# does to measured cost.
#
# THIS GATE DEPENDS ON MERGE COMMITS. `cleared.through`, `stale_through`,
# `stale_since` and `[[toolchain]].commit` are commit ids that must stay
# ancestors of the branch they were written on. Squash-merge or
# rebase-and-merge would mint new ids and orphan every one of them; the gate
# fails loudly when that happens (an id that is not an ancestor of HEAD),
# but it cannot repair it. `06-branching.mdc` forbids both strategies; this
# is one more thing that rests on that.
#
# WHAT "NEWER" MEANS. `git log HEAD --not <heard> -- <paths>` with git's
# default history simplification: the commits touching the paths that are in
# HEAD's history and in the history of nothing the row has heard. What a row
# has heard is its capture's revision and every commit a `cleared` or
# `stale_through` entry names. Those are a SET, not a chain: two pull
# requests that each acknowledge their own commit name tips on parallel
# branches, and after both merge the row has heard everything. (Git may still
# ask for the two appended lines to be kept by hand; that conflict is the
# mechanism working.) A capture built from a commit that never merged is
# compared from its merge-base with HEAD, and the run says so.
#
# THE REVISION IS A LEDGER FIELD, NOT PARSED FROM THE CAPTURE. Several
# captures carry no revision (the P2P span files have no header at all), and
# one family's stamp is known to go stale. Where a capture does record a
# revision the gate cross-checks it; where it does not, `rev_source` must say
# where the ledger's value came from.
#
# SUBJECT (47-gate-subject-assertion.mdc). Exit 2 — the question could not be
# asked — when the ledger is missing or empty, when no row has a capture, when
# the tracked-set document it names is missing, or when the checkout is
# shallow AND its history is cut inside a range a row asks about (a cut older
# than every review point hides nothing, and is not refused). A declared path that matches no
# tracked file is a FAIL: a ledger whose paths have rotted would otherwise
# pass in silence, which is the failure it exists to end.
#
# Exit 0 truthful ledger; 1 findings; 2 cannot ask. `--selftest` builds
# throwaway git repositories and bites each failure class red, beside a
# control row that must stay green.
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LEDGER = "docs/benchmarks/measurement_ledger.toml"

STATUSES = ("current", "stale", "unmeasured")
COMMON_KEYS = {"name", "defined_in", "needle", "measured_by", "status", "paths"}
MEASURED_KEYS = {"capture", "capture_rev", "rev_source", "cleared"}
STALE_KEYS = {"stale_since", "carrier", "stale_through"}
UNMEASURED_KEYS = {"carrier"}
HEADER_REV = "capture header"
# A revision a capture file records about itself.
CAPTURE_REV_RE = re.compile(r"git[_ ]rev(?:ision)?[\"'\s:=]+([0-9a-f]{7,40})", re.I)
T_ROW_RE = re.compile(r"^BA-T\d+$")
MIN_REASON = 12


class GateError(Exception):
    """The gate could not ask its question (exit 2)."""


def git(root: str, *args: str) -> tuple[int, str]:
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


COMMIT_ID_RE = re.compile(r"[0-9a-f]{7,40}")


def resolve(root: str, rev: str) -> str | None:
    """A hex commit id, resolved; nothing else.

    An empty string peels to HEAD (`^{commit}` with no name), and a name such
    as `HEAD` or a branch moves with the tree. Either would let an entry
    acknowledge whatever is newest, which is the one thing an entry must not
    be able to do. Only a commit id says which commit was read.
    """
    if not COMMIT_ID_RE.fullmatch(rev):
        return None
    rc, out = git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    return out if rc == 0 and out else None


def shallow_boundary(root: str) -> set[str]:
    """The commits a shallow repository's history is cut at; empty when complete."""
    rc, out = git(root, "rev-parse", "--is-shallow-repository")
    if rc != 0 or out != "true":
        return set()
    _, common = git(root, "rev-parse", "--git-common-dir")
    path = common if os.path.isabs(common) else os.path.join(root, common)
    try:
        with open(os.path.join(path, "shallow"), encoding="ascii") as fh:
            return {ln.strip() for ln in fh if ln.strip()}
    except OSError:
        return set()


SHALLOW_MSG = ("this checkout is shallow and its history is cut inside the range "
               "the ledger asks about; fetch full history (`git fetch --unshallow`)")


def is_ancestor(root: str, a: str, b: str) -> bool:
    rc, _ = git(root, "merge-base", "--is-ancestor", a, b)
    return rc == 0


def is_exclude(spec: str) -> bool:
    return spec.startswith(":!") or spec.startswith(":^") or (
        spec.startswith(":(") and "exclude" in spec.split(")", 1)[0]
    )


def newer_commits(root: str, heard: list[str], paths: list[str]) -> list[str]:
    """Commits touching `paths` that are in HEAD's history and in none of `heard`'s.

    `heard` is a set, not a chain. Two pull requests that each acknowledge
    their own commit name tips on parallel branches; neither is an ancestor
    of the other, and after both merge every commit is reachable from one of
    them. A chain would fail on the merge that makes it true.
    """
    # A shallow repository answers this question honestly only when no cut
    # lies between what was heard and HEAD. A deeper cut hides nothing the
    # row asks about.
    cut = shallow_boundary(root)
    if cut:
        rc, span = git(root, "rev-list", "HEAD", "--not", *heard)
        if rc != 0 or cut & set(span.splitlines()):
            raise GateError(SHALLOW_MSG)
    rc, out = git(root, "log", "--format=%H %P", "HEAD", "--not", *heard, "--", *paths)
    if rc != 0:
        raise GateError("git log HEAD --not <heard> failed")
    newer: list[str] = []
    for ln in out.splitlines():
        sha, *parents = ln.split()
        # A merge that joins two branches touching the paths differs from each
        # parent there, so git lists it, though it changed nothing a person
        # wrote. It counts only when it carries a change of its own: a
        # conflict resolved by hand, or an edit made in the merge. That is
        # exactly what `--remerge-diff` shows, and it is empty for a clean
        # merge. If this git cannot answer, the merge is kept.
        if len(parents) > 1:
            rc, own = git(root, "show", "--remerge-diff", "--format=", sha, "--", *paths)
            if rc == 0 and not own:
                continue
        newer.append(sha)
    return newer


# Where a line comment starts, by file kind. A needle that survives only in a
# comment is a quotation of the old value, not the definition: the commonest
# way a changed constant keeps its old text is "was N" beside the new one.
# Documents and JSON have no comments to strip, and a needle there is prose
# or data by construction.
LINE_COMMENT = {
    ".rs": ("//",), ".h": ("//",), ".hpp": ("//",), ".c": ("//",), ".cpp": ("//",),
    ".cc": ("//",), ".inl": ("//",),
    ".py": ("#",), ".sh": ("#",), ".toml": ("#",), ".yml": ("#",), ".yaml": ("#",),
}
BLOCK_COMMENT_LEADERS = ("/*", "*")


def stated(text: str, needle: str, path: str) -> str:
    """'code' when the needle is on a line outside a comment, else 'comment' or 'absent'."""
    markers = LINE_COMMENT.get(os.path.splitext(path)[1])
    seen = "absent"
    for line in text.splitlines():
        at = line.find(needle)
        if at < 0:
            continue
        if markers is None:
            return "code"
        block = "//" in markers and line.lstrip().startswith(BLOCK_COMMENT_LEADERS)
        # A `#define` is code in C: `#` opens a comment only where it is the
        # marker. A marker inside a string literal ahead of the needle reads
        # as a comment here; that errs toward failing, and the row then needs
        # a needle that starts earlier on the line.
        cut = min((i for i in (line.find(m) for m in markers) if i >= 0), default=-1)
        if block or 0 <= cut < at:
            seen = "comment"
            continue
        return "code"
    return seen


def describe(root: str, sha: str) -> str:
    _, out = git(root, "log", "-1", "--format=%h %ad %s", "--date=short", sha)
    return out


def check_row(root: str, row: dict, t_rows: set[str], notes: list[str],
              bases: dict[str, str]) -> list[str]:
    """Every way one row can be untrue. An empty list means it tells the truth."""
    name = row.get("name", "<unnamed>")
    fails: list[str] = []

    def bad(msg: str) -> None:
        fails.append(f"{name}: {msg}")

    status = row.get("status")
    if status not in STATUSES:
        bad(f"status {status!r} is not one of {', '.join(STATUSES)}")
        return fails
    allowed = set(COMMON_KEYS)
    if status in ("current", "stale"):
        allowed |= MEASURED_KEYS
    if status == "stale":
        allowed |= STALE_KEYS
    if status == "unmeasured":
        allowed |= UNMEASURED_KEYS
    for k in sorted(set(row) - allowed):
        bad(f"key {k!r} is not valid for a {status} row")
    for k in sorted(COMMON_KEYS - set(row)):
        bad(f"missing {k!r}")
    if fails:
        return fails

    # The constant is where the row says it is, with the value the row quotes.
    defined = os.path.join(root, row["defined_in"])
    if not os.path.isfile(defined):
        bad(f"defined_in {row['defined_in']} does not exist")
    else:
        with open(defined, encoding="utf-8", errors="replace") as fh:
            found = stated(fh.read(), str(row["needle"]), row["defined_in"])
        if found == "absent":
            bad(f"needle {row['needle']!r} is not in {row['defined_in']} "
                "(the constant moved, was renamed, or changed value)")
        elif found == "comment":
            bad(f"needle {row['needle']!r} appears in {row['defined_in']} only "
                "inside a comment; the definition itself has changed")

    measured_by = row["measured_by"]
    if not isinstance(measured_by, list) or not measured_by:
        bad("measured_by must be a non-empty list of BA-T rows")
    else:
        for t in measured_by:
            if not T_ROW_RE.match(str(t)):
                bad(f"measured_by {t!r} is not a BA-T row id")
            elif t not in t_rows:
                bad(f"measured_by {t} is not defined in the tracked-set document")

    paths = row["paths"]
    if not isinstance(paths, list) or not any(not is_exclude(p) for p in paths):
        bad("paths must list at least one included pathspec")
        return fails
    for spec in paths:
        if is_exclude(spec):
            continue
        rc, out = git(root, "ls-files", "--", spec)
        if rc != 0 or not out:
            bad(f"path {spec!r} matches no tracked file")

    if status == "unmeasured":
        if len(str(row.get("carrier", "")).strip()) < MIN_REASON:
            bad("an unmeasured row names its carrier (what will measure it, "
                "or the ruling that it needs no measurement)")
        return fails

    for k in ("capture", "capture_rev", "rev_source"):
        if not str(row.get(k, "")).strip():
            bad(f"a {status} row needs {k!r}")
    if fails:
        return fails

    capture = os.path.join(root, row["capture"])
    header_revs: list[str] = []
    if not os.path.isfile(capture):
        bad(f"capture {row['capture']} does not exist")
    else:
        with open(capture, encoding="utf-8", errors="replace") as fh:
            header_revs = CAPTURE_REV_RE.findall(fh.read())
    rev = resolve(root, row["capture_rev"])
    if rev is None:
        if shallow_boundary(root):
            raise GateError(SHALLOW_MSG)
        bad(f"capture_rev {row['capture_rev']} is not a commit in this repository")
        return fails
    if header_revs:
        if not any(rev.startswith(h) or h.startswith(rev) for h in header_revs):
            bad(f"capture_rev {row['capture_rev']} disagrees with the revision the "
                f"capture records ({', '.join(sorted(set(header_revs)))})")
    elif row["rev_source"].strip() == HEADER_REV:
        bad(f"rev_source says {HEADER_REV!r} but {row['capture']} records no revision")
    if fails:
        return fails

    since = resolve(root, str(row.get("stale_since", ""))) if status == "stale" else None

    # What the row has reviewed: the capture's history, plus the history of
    # each commit a `cleared` note names.
    base = rev
    if not is_ancestor(root, rev, "HEAD"):
        rc, mb = git(root, "merge-base", rev, "HEAD")
        if rc != 0 or not mb:
            bad(f"capture_rev {rev[:10]} shares no history with HEAD")
            return fails
        base = mb
        notes.append(f"{name}: capture_rev {rev[:10]} is not an ancestor of "
                     f"HEAD; compared from their merge-base {mb[:10]}")
    heard = [base]
    for i, note in enumerate(row.get("cleared", [])):
        through = resolve(root, str(note.get("through", "")))
        if through is None:
            bad(f"cleared[{i}].through is not a commit in this repository")
            return fails
        if since is not None and is_ancestor(root, since, through):
            bad(f"cleared[{i}] reaches stale_since {since[:10]}: a note written about "
                "one change cannot declare the cause of staleness cost-neutral. "
                "Only a newer capture retires a stale row")
            return fails
        if len(str(note.get("reason", "")).strip()) < MIN_REASON:
            bad(f"cleared[{i}] gives no reason")
        if not is_ancestor(root, through, "HEAD"):
            bad(f"cleared[{i}].through {through[:10]} is not an ancestor of HEAD")
            return fails
        heard.append(through)
    if fails:
        return fails

    newer = newer_commits(root, heard, paths)
    if status == "current":
        bases[name] = base
        if newer:
            shown = "; ".join(describe(root, c) for c in newer[-3:][::-1])
            more = f" (and {len(newer) - 3} more)" if len(newer) > 3 else ""
            bad(f"says current, but {len(newer)} commit(s) touching its paths are "
                f"newer than its capture and notes: {shown}{more}. Land a newer capture, "
                "add a `cleared` note with the reason they are cost-neutral, or "
                "mark the row stale with its carrier")
        return fails

    # stale
    if len(str(row.get("carrier", "")).strip()) < MIN_REASON:
        bad("a stale row names the carrier of its re-measurement")
    if since is None:
        bad("stale_since is not a commit in this repository")
        return fails
    if not newer:
        bad("says stale, but nothing touching its paths is newer than its "
            "capture; mark it current")
        return fails
    if since not in newer:
        bad(f"stale_since {since[:10]} is not among the {len(newer)} commit(s) "
            "touching its paths after its capture")
        return fails

    # A stale row keeps listening. Being stale excuses the row from a fresh
    # capture; it does not excuse the next change to its paths from a word
    # about what that change does to the cost.
    acks = row.get("stale_through", [])
    if not isinstance(acks, list) or not acks:
        bad("a stale row carries `stale_through`: the commits touching its paths "
            "that it has acknowledged, each with a note on the cost")
        return fails
    for i, ack in enumerate(acks):
        through = resolve(root, str(ack.get("through", "")))
        if through is None:
            bad(f"stale_through[{i}].through is not a commit in this repository")
            return fails
        if len(str(ack.get("note", "")).strip()) < MIN_REASON:
            bad(f"stale_through[{i}] says nothing about the cost")
        if not is_ancestor(root, through, "HEAD"):
            bad(f"stale_through[{i}].through {through[:10]} is not an ancestor of HEAD")
            return fails
        heard.append(through)
    if fails:
        return fails
    unheard = newer_commits(root, heard, paths)
    if unheard:
        shown = "; ".join(describe(root, c) for c in unheard[-3:][::-1])
        more = f" (and {len(unheard) - 3} more)" if len(unheard) > 3 else ""
        bad(f"is stale, and {len(unheard)} commit(s) touching its paths have not "
            f"been heard: {shown}{more}. Add a `stale_through` entry saying what "
            "the change does to the cost")
    return fails


def check_toolchain(root: str, data: dict, bases: dict[str, str]) -> list[str]:
    """A toolchain change moves every wall-clock figure and is on no row's paths.

    One acknowledgment per change to the pinned toolchain, at the ledger's
    level, owed for as long as any row is current across it.
    """
    fails: list[str] = []
    tc = str(data.get("toolchain_file", ""))
    rc, tracked = git(root, "ls-files", "--", tc) if tc else (1, "")
    if rc != 0 or not tracked:
        return [f"toolchain_file {tc!r} matches no tracked file"]
    acked: set[str] = set()
    for i, ack in enumerate(data.get("toolchain", [])):
        sha = resolve(root, str(ack.get("commit", "")))
        if sha is None:
            fails.append(f"toolchain[{i}].commit is not a commit in this repository")
            continue
        if len(str(ack.get("note", "")).strip()) < MIN_REASON:
            fails.append(f"toolchain[{i}] says nothing about the cost")
        rc, touched = git(root, "log", "-1", "--format=%H", sha, "--", tc)
        if rc != 0 or touched != sha:
            fails.append(f"toolchain[{i}].commit {sha[:10]} does not change {tc}")
            continue
        acked.add(sha)
    owed: dict[str, list[str]] = {}
    for name, base in sorted(bases.items()):
        for c in newer_commits(root, [base], [tc]):
            owed.setdefault(c, []).append(name)
    for c, names in owed.items():
        if c not in acked:
            fails.append(f"toolchain: {describe(root, c)} changed {tc} after the "
                         f"review point of current row(s) {', '.join(names)}. Add a "
                         "`[[toolchain]]` entry saying what it does to measured cost")
    return fails


def check_transitions(root: str, rows: list[dict]) -> list[str]:
    """Only a capture that includes the cause retires a stale row.

    Compared against the ledger at HEAD's first parent, which in CI is the
    base branch a pull request merges into, so the comparison covers the
    whole pull request. A row that was stale there and is current here must
    have a capture taken at or after its `stale_since`.
    """
    rc, text = git(root, "show", f"HEAD^1:{LEDGER}")
    if rc != 0 or not text:
        return []
    try:
        before = {r.get("name"): r for r in tomllib.loads(text).get("constant", [])}
    except tomllib.TOMLDecodeError:
        return []
    fails: list[str] = []
    for row in rows:
        was = before.get(row.get("name"))
        if not was or was.get("status") != "stale" or row.get("status") != "current":
            continue
        since = resolve(root, str(was.get("stale_since", "")))
        now = resolve(root, str(row.get("capture_rev", "")))
        if since is None or now is None:
            continue
        if not is_ancestor(root, since, now):
            fails.append(f"{row['name']}: was stale since {since[:10]} and is now "
                         f"current on a capture at {now[:10]}, which does not include "
                         "that commit. Only a newer capture retires a stale row")
    return fails



def load(root: str) -> tuple[dict, list[dict], set[str]]:
    rc, _ = git(root, "rev-parse", "--git-dir")
    if rc != 0:
        raise GateError("not a git repository")
    path = os.path.join(root, LEDGER)
    if not os.path.isfile(path):
        raise GateError(f"{LEDGER} is missing — missing subject (rule 47)")
    with open(path, "rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            raise GateError(f"{LEDGER} does not parse: {e}") from e
    rows = data.get("constant", [])
    if not rows:
        raise GateError(f"{LEDGER} has no rows — missing subject (rule 47)")
    if not any(r.get("status") in ("current", "stale") for r in rows):
        raise GateError("no row has a capture, so the staleness question was "
                        "never asked — missing subject (rule 47)")
    tracked = data.get("tracked_set", "")
    tpath = os.path.join(root, tracked)
    if not tracked or not os.path.isfile(tpath):
        raise GateError(f"tracked_set {tracked!r} does not exist; the ledger's "
                        "measured_by ids cannot be resolved")
    with open(tpath, encoding="utf-8", errors="replace") as fh:
        t_rows = set(re.findall(r"^\| \*\*(BA-T\d+)\*\* \|", fh.read(), re.M))
    if not t_rows:
        raise GateError(f"{tracked} defines no BA-T rows")
    return data, rows, t_rows


def run(root: str) -> int:
    try:
        data, rows, t_rows = load(root)
        notes: list[str] = []
        fails: list[str] = []
        seen: set[str] = set()
        bases: dict[str, str] = {}
        for row in rows:
            name = row.get("name", "")
            if name in seen:
                fails.append(f"{name}: duplicate row name")
            seen.add(name)
            fails += check_row(root, row, t_rows, notes, bases)
        fails += check_toolchain(root, data, bases)
        fails += check_transitions(root, rows)
    except GateError as e:
        print(f"FAIL: {e}")
        return 2
    for n in notes:
        print(f"note: {n}")
    stale = [r for r in rows if r.get("status") == "stale"]
    for r in stale:
        print(f"stale: {r['name']} — since {str(r.get('stale_since'))[:10]}; "
              f"carrier: {r.get('carrier')}")
    if fails:
        print("FAIL: the measurement ledger disagrees with the tree:")
        for f in fails:
            print("  " + f)
        return 1
    count = {s: sum(1 for r in rows if r.get("status") == s) for s in STATUSES}
    print(f"measurement ledger: {len(rows)} rows tell the truth — "
          f"{count['current']} current, {count['stale']} stale, "
          f"{count['unmeasured']} unmeasured")
    return 0


# --- selftest ---------------------------------------------------------------

def _sh(root: str, *args: str, check: bool = True) -> str:
    # Every fixture command carries its own identity and no caller config. A
    # fixture that borrows the developer's git identity passes on their
    # machine and fails on a runner that has none.
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr}")
    return r.stdout.strip()


def _write(root: str, rel: str, text: str) -> None:
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def _commit(root: str, msg: str, ledger: bool = False) -> str:
    # The ledger a case writes is working-tree state. It is committed only
    # when a case asks, so that HEAD's first parent holds a ledger exactly
    # where a case put one (the stale-to-current comparison reads it).
    if ledger:
        _sh(root, "add", "-A")
    else:
        _sh(root, "add", "-A", "--", ".", f":(exclude){LEDGER}")
    _sh(root, "commit", "-q", "-m", msg, "--allow-empty")
    return _sh(root, "rev-parse", "HEAD")


TRACKED = "| Id | Benchmark |\n| --- | --- |\n| **BA-T1** | a |\n| **BA-T2** | b |\n"


def _ledger(rows: str, toolchain: str = "", tc_file: str = "toolchain.toml") -> str:
    return (f'tracked_set = "docs/design/TRACKED.md"\ntoolchain_file = "{tc_file}"\n\n'
            + toolchain + rows)


def _heard(*shas: str) -> str:
    entries = ", ".join(f'{{ through = "{s}", note = "selftest: cost effect noted" }}' for s in shas)
    return f"stale_through = [{entries}]\n"


def _row(name: str, status: str, rev: str = "", extra: str = "",
         paths: str = '["src/hot"]', needle: str = "LIMIT = 4",
         defined: str = "src/consts.txt") -> str:
    out = (f'[[constant]]\nname = "{name}"\ndefined_in = "{defined}"\n'
           f'needle = "{needle}"\nmeasured_by = ["BA-T1"]\nstatus = "{status}"\n'
           f"paths = {paths}\n")
    if status != "unmeasured":
        out += (f'capture = "docs/benchmarks/cap.txt"\ncapture_rev = "{rev}"\n'
                f'rev_source = "{HEADER_REV}"\n')
    return out + extra + "\n"


def _fixture(tmp: str) -> dict[str, str]:
    """A repository with a capture at c1 and one later change to the hot path."""
    _sh(tmp, "init", "-q", "-b", "main")
    _write(tmp, "src/consts.txt", "LIMIT = 4\n")
    _write(tmp, "src/hot/a.rs", "fn a() {}\n")
    _write(tmp, "src/cold/b.rs", "fn b() {}\n")
    _write(tmp, "toolchain.toml", 'channel = "1.0"\n')
    _write(tmp, "docs/design/TRACKED.md", TRACKED)
    c1 = _commit(tmp, "c1: the measured tree")
    _write(tmp, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
    c1b = _commit(tmp, "capture lands")
    _write(tmp, "src/cold/b.rs", "fn b() { /* cold */ }\n")
    c2 = _commit(tmp, "c2: touches a path nobody budgets")
    return {"c1": c1, "c1b": c1b, "c2": c2}


def _verdict(tmp: str, rows: str, toolchain: str = "",
             tc_file: str = "toolchain.toml") -> tuple[int, str]:
    _write(tmp, LEDGER, _ledger(rows, toolchain, tc_file))
    old = sys.stdout
    sys.stdout = buf = __import__("io").StringIO()
    try:
        rc = run(tmp)
    finally:
        sys.stdout = old
    return rc, buf.getvalue()


def selftest() -> int:
    failures: list[str] = []
    passed = 0

    def expect(tmp: str, rows: str, want: int, why: str, says: str = "",
               toolchain: str = "", tc_file: str = "toolchain.toml") -> None:
        nonlocal passed
        rc, out = _verdict(tmp, rows, toolchain, tc_file)
        if rc != want or (says and says not in out):
            failures.append(f"{why}: wanted exit {want}"
                            + (f" naming {says!r}" if says else "")
                            + f", got {rc}\n{out}")
        else:
            passed += 1

    with tempfile.TemporaryDirectory() as tmp:
        c = _fixture(tmp)
        control = _row("control", "current", c["c1"])

        # CONTROL: a change to an unbudgeted path leaves the row current. Every
        # red below sits beside this row, so a red cannot be the fixture's own.
        expect(tmp, control, 0, "control: an untouched hot path is current")

        _write(tmp, "src/hot/a.rs", "fn a() { /* slower */ }\n")
        c3 = _commit(tmp, "c3: changes the hot path")
        expect(tmp, control, 1, "a newer commit on a budgeted path fails a current row",
               "c3: changes the hot path")

        cold = _row("cold", "current", c["c1"], paths='["src/cold"]')
        expect(tmp, cold, 1, "the same question is asked per row, of that row's paths",
               "c2: touches a path")
        scoped = _row("scoped", "current", c["c1"], paths='["docs/design"]')
        expect(tmp, scoped, 0, "a row whose paths did not move after its capture is current")

        cleared = _row("control", "current", c["c1"],
                       f'cleared = [{{ through = "{c3}", reason = "comment only; no code path changed" }}]\n')
        expect(tmp, cleared, 0, "a cleared note through the newer commit clears it")
        no_reason = _row("control", "current", c["c1"],
                         f'cleared = [{{ through = "{c3}", reason = "ok" }}]\n')
        expect(tmp, no_reason, 1, "a cleared note without a reason is refused", "no reason")
        backwards = _row("control", "current", c["c1"],
                         f'cleared = [{{ through = "{c3}", reason = "comment only; no code path changed" }}, '
                         f'{{ through = "{c["c2"]}", reason = "moves the review point backwards" }}]\n')
        expect(tmp, backwards, 0, "cleared notes are a set: an older one after a newer one is harmless")

        stale = _row("control", "stale", c["c1"],
                     f'stale_since = "{c3}"\ncarrier = "BA-T1 floor re-run, owed"\n' + _heard(c3))
        expect(tmp, stale, 0, "a stale row naming the commit and a carrier passes", "stale: control")
        stale_wrong = _row("control", "stale", c["c1"],
                           f'stale_since = "{c["c2"]}"\ncarrier = "BA-T1 floor re-run, owed"\n')
        expect(tmp, stale_wrong, 1, "stale_since must be a commit that touched the paths",
               "is not among")
        stale_no_carrier = _row("control", "stale", c["c1"], f'stale_since = "{c3}"\ncarrier = ""\n')
        expect(tmp, stale_no_carrier, 1, "a stale row without a carrier is refused", "carrier")
        cries_wolf = _row("control", "stale", c3,
                          f'stale_since = "{c3}"\ncarrier = "BA-T1 floor re-run, owed"\n')
        _write(tmp, "docs/benchmarks/cap.txt", f"# git_rev={c3}\nvalue=2\n")
        _commit(tmp, "a newer capture lands")
        expect(tmp, cries_wolf, 1, "INVERSE: stale with nothing newer is refused",
               "mark it current")
        fresh = _row("control", "current", c3)
        expect(tmp, fresh, 0, "a newer capture makes the row current again")

        expect(tmp, _row("control", "current", c["c1"]), 1,
               "a ledger revision that disagrees with the capture's own is refused",
               "disagrees with the revision")
        expect(tmp, _row("control", "current", c3, paths='["src/gone"]'), 1,
               "a declared path that matches no tracked file is refused",
               "matches no tracked file")
        expect(tmp, _row("control", "current", c3, needle="LIMIT = 5"), 1,
               "a constant whose value changed under the ledger is refused", "needle")
        expect(tmp, _row("control", "current", "0" * 40), 1,
               "an unknown revision is refused", "not a commit")
        expect(tmp, fresh.replace('["BA-T1"]', '["BA-T9"]'), 1,
               "a measured_by id the tracked set does not define is refused", "BA-T9")
        expect(tmp, fresh + 'typo_key = "x"\n', 1, "an unknown key is refused", "typo_key")
        expect(tmp, fresh + fresh, 1, "a duplicate row name is refused", "duplicate")

        unmeasured = _row("placeholder", "unmeasured",
                          extra='carrier = "BA-T2 derives it on the floor"\n')
        expect(tmp, fresh + unmeasured, 0, "an unmeasured row with a carrier passes")
        expect(tmp, fresh + _row("placeholder", "unmeasured", extra='carrier = ""\n'), 1,
               "an unmeasured row without a carrier is refused", "carrier")
        expect(tmp, fresh + _row("placeholder", "unmeasured",
                                 extra='carrier = "BA-T2 derives it"\ncapture = "x"\n'), 1,
               "an unmeasured row may not claim a capture", "capture")

        # Subject assertions: each must be "cannot ask", never a pass.
        expect(tmp, "", 2, "an empty ledger is a missing subject")
        expect(tmp, unmeasured, 2, "a ledger with no measured row never asks the question")
        _write(tmp, LEDGER, 'tracked_set = "docs/design/NOPE.md"\n\n' + fresh)
        if run_quiet(tmp) != 2:
            failures.append("a missing tracked-set document did not refuse")
        else:
            passed += 1
        os.remove(os.path.join(tmp, LEDGER))
        if run_quiet(tmp) != 2:
            failures.append("a missing ledger did not refuse")
        else:
            passed += 1

        # A capture built from a commit that never merged: compared from the
        # merge-base, and said so.
        _sh(tmp, "checkout", "-q", "-b", "side", c["c1"])
        _write(tmp, "src/side.txt", "x\n")
        side = _commit(tmp, "a side branch that never merges")
        _sh(tmp, "checkout", "-q", "main")
        _write(tmp, "docs/benchmarks/cap.txt", "value=3\n")
        _commit(tmp, "a capture with no header revision")
        off = _row("control", "stale", side,
                   f'stale_since = "{c3}"\ncarrier = "BA-T1 floor re-run, owed"\n'
                   + _heard(c3)).replace(
                       f'rev_source = "{HEADER_REV}"', 'rev_source = "the run record names it"')
        expect(tmp, off, 0, "a non-ancestor revision is compared from the merge-base",
               "not an ancestor of HEAD")
        expect(tmp, _row("control", "stale", side,
                         f'stale_since = "{c3}"\ncarrier = "BA-T1 floor re-run, owed"\n'), 1,
               "rev_source 'capture header' with no header revision is refused",
               "records no revision")

        # A shallow clone whose cut lies inside a row's range cannot answer
        # and must say so; one whose cut is older than the review point can.
        _write(tmp, LEDGER, _ledger(off))
        _commit(tmp, "ledger", ledger=True)
        recent = _sh(tmp, "rev-parse", "HEAD~1")
        inside = _row("control", "current", recent).replace(
            f'rev_source = "{HEADER_REV}"', 'rev_source = "the run record names it"')
        with tempfile.TemporaryDirectory() as shallow:
            subprocess.run(["git", "clone", "-q", "--depth", "1", "file://" + tmp, shallow],
                           check=True, capture_output=True)
            if run_quiet(shallow) != 2:
                failures.append("a shallow clone cut inside the range did not refuse")
            else:
                passed += 1
        with tempfile.TemporaryDirectory() as shallow:
            subprocess.run(["git", "clone", "-q", "--depth", "3", "file://" + tmp, shallow],
                           check=True, capture_output=True)
            _write(shallow, LEDGER, _ledger(inside))
            if run_quiet(shallow) != 0:
                failures.append("a shallow clone cut OLDER than the review point was refused")
            else:
                passed += 1

    # --- a stale row keeps listening; only a capture retires it; toolchain ---
    with tempfile.TemporaryDirectory() as tmp:
        _sh(tmp, "init", "-q", "-b", "main")
        _write(tmp, "src/consts.txt", "LIMIT = 4\n")
        _write(tmp, "src/hot/a.rs", "fn a() {}\n")
        _write(tmp, "toolchain.toml", 'channel = "1.0"\n')
        _write(tmp, "docs/design/TRACKED.md", TRACKED)
        c1 = _commit(tmp, "c1: the measured tree")
        _write(tmp, "docs/benchmarks/cap.txt", f"# git_rev={c1}\nvalue=1\n")
        _commit(tmp, "capture lands")
        _write(tmp, "src/hot/a.rs", "fn a() { /* twice the work */ }\n")
        cause = _commit(tmp, "cause: doubles the cost")
        owed = f'stale_since = "{cause}"\ncarrier = "BA-T1 floor re-run, owed"\n'

        expect(tmp, _row("control", "stale", c1, owed + _heard(cause)), 0,
               "control: a stale row that has heard every commit to its paths passes")
        expect(tmp, _row("control", "stale", c1, owed), 1,
               "a stale row with no stale_through is refused", "stale_through")

        # An entry names a commit by id. A name that moves with the tree, or
        # no name at all, would acknowledge whatever is newest.
        expect(tmp, _row("control", "stale", c1, owed + _heard("HEAD")), 1,
               "an entry naming HEAD is not a commit id", "not a commit")
        expect(tmp, _row("control", "stale", c1, owed + _heard("main")), 1,
               "an entry naming a branch is not a commit id", "not a commit")
        expect(tmp, _row("control", "stale", c1,
                         owed + 'stale_through = [{ note = "no commit named at all" }]\n'), 1,
               "an entry with no commit is not a commit id", "not a commit")
        expect(tmp, _row("control", "current", c1,
                         'cleared = [{ through = "HEAD", reason = "names the tip" }]\n'), 1,
               "a cleared note naming HEAD cannot clear a current row", "not a commit")
        expect(tmp, _row("control", "stale", c1,
                         'stale_since = "HEAD"\ncarrier = "BA-T1 floor re-run, owed"\n'
                         + _heard(cause)), 1,
               "stale_since naming HEAD is refused", "stale_since is not a commit")

        # The needle must be the definition, not a quotation of the old one.
        _write(tmp, "src/k.rs", "// pub const K: u8 = 4;\npub const K: u8 = 5; // was: pub const K: u8 = 4;\n")
        _write(tmp, "src/k.h", "#define K_MAX  8   // bounds the thing\n")
        _commit(tmp, "constants in source files")
        held = owed + _heard(cause)
        expect(tmp, _row("control", "stale", c1, held, needle="pub const K: u8 = 4;", defined="src/k.rs"), 1,
               "A CHANGED CONSTANT whose old text survives in comments is refused",
               "only inside a comment")
        expect(tmp, _row("control", "stale", c1, held, needle="pub const K: u8 = 5;", defined="src/k.rs"), 0,
               "the live definition is found beside its own trailing comment")
        expect(tmp, _row("control", "stale", c1, held, needle="#define K_MAX  8", defined="src/k.h"), 0,
               "a C `#define` is code, not a comment")
        expect(tmp, _row("control", "stale", c1, owed + _heard(c1)), 1,
               "a stale_through entry that does not cover stale_since leaves it unheard",
               "cause: doubles the cost")

        _write(tmp, "src/hot/a.rs", "fn a() { /* four times the work */ }\n")
        again = _commit(tmp, "again: doubles it once more")
        expect(tmp, _row("control", "stale", c1, owed + _heard(cause)), 1,
               "A STALE ROW KEEPS LISTENING: a later commit to its paths fails it",
               "again: doubles it once more")
        expect(tmp, _row("control", "stale", c1, owed + _heard(cause, again)), 0,
               "advancing stale_through with a note clears it")
        expect(tmp, _row("control", "stale", c1, owed + _heard(again, cause)), 0,
               "stale_through entries are a set: their order does not matter")

        # Two pull requests touch the path on parallel branches and each
        # acknowledges its own commit. Neither tip is an ancestor of the other.
        _sh(tmp, "checkout", "-q", "-b", "left")
        _write(tmp, "src/hot/left.rs", "fn left() {}\n")
        left = _commit(tmp, "left: one pull request")
        _sh(tmp, "checkout", "-q", "-b", "right", again)
        _write(tmp, "src/hot/right.rs", "fn right() {}\n")
        right = _commit(tmp, "right: another pull request")
        _sh(tmp, "checkout", "-q", "main")
        _sh(tmp, "merge", "-q", "--no-ff", "-m", "Merge pull request #1", "left")
        _sh(tmp, "merge", "-q", "--no-ff", "-m", "Merge pull request #2", "right")
        expect(tmp, _row("control", "stale", c1, owed + _heard(cause, again, left)), 1,
               "PARALLEL BRANCHES: acknowledging one tip leaves the other unheard",
               "right: another pull request")
        expect(tmp, _row("control", "stale", c1, owed + _heard(cause, again, left, right)), 0,
               "PARALLEL BRANCHES: both tips acknowledged, in either order, passes")
        expect(tmp, _row("control", "stale", c1, owed + _heard(right, left)), 0,
               "the two tips alone cover everything behind them")

        tip = _sh(tmp, "rev-parse", "HEAD")
        absorb = (f'cleared = [{{ through = "{tip}", reason = "my change is a comment only" }}]\n')
        expect(tmp, _row("control", "stale", c1, owed + _heard(left, right) + absorb), 1,
               "A CLEARED NOTE MAY NOT REACH stale_since", "Only a newer capture")

        # The same absorption attempted the long way: drop the stale fields and
        # call the row current. The base branch remembers.
        _write(tmp, LEDGER, _ledger(_row("control", "stale", c1, owed + _heard(left, right))))
        _commit(tmp, "the ledger as the base branch holds it", ledger=True)
        _commit(tmp, "the pull request's commit")
        expect(tmp, _row("control", "current", c1, absorb), 1,
               "STALE TO CURRENT WITHOUT A CAPTURE is refused against the first parent",
               "does not include")
        _write(tmp, "docs/benchmarks/cap.txt", f"# git_rev={tip}\nvalue=4\n")
        _commit(tmp, "a capture taken after the cause")
        fresh = _row("control", "current", tip)
        expect(tmp, fresh, 0, "a capture that includes the cause retires the stale row")

        # Toolchain: on no row's paths, acknowledged once for the ledger.
        _write(tmp, "toolchain.toml", 'channel = "2.0"\n')
        bump = _commit(tmp, "bump: the pinned toolchain moves")
        expect(tmp, fresh, 1, "a toolchain change after a current row's review point fails",
               "bump: the pinned toolchain moves")
        ack = f'[[toolchain]]\ncommit = "{bump}"\nnote = "codegen may differ; allocation path re-read"\n\n'
        expect(tmp, fresh, 0, "one ledger-level acknowledgment clears it", toolchain=ack)
        wrong = f'[[toolchain]]\ncommit = "{again}"\nnote = "acknowledges the wrong commit"\n\n'
        expect(tmp, fresh, 1, "an acknowledgment naming a commit that did not change it is refused",
               "does not change", toolchain=wrong)
        expect(tmp, fresh, 1, "a toolchain_file that matches no tracked file is refused",
               "matches no tracked file", toolchain=ack, tc_file="nope.toml")
        _write(tmp, "src/hot/a.rs", "fn a() { /* and again */ }\n")
        third = _commit(tmp, "third: the hot path moves under the new capture")
        expect(tmp, _row("control", "stale", tip,
                         f'stale_since = "{third}"\ncarrier = "BA-T1 floor re-run, owed"\n'
                         + _heard(third)), 0,
               "a ledger with no current row owes no toolchain acknowledgment")

        # A merge is heard for free only when it is clean. One that resolves
        # a conflict on the path carries a change nobody acknowledged.
        owed3 = f'stale_since = "{third}"\ncarrier = "BA-T1 floor re-run, owed"\n'
        _sh(tmp, "checkout", "-q", "-b", "x")
        _write(tmp, "src/hot/a.rs", "fn a() { /* x */ }\n")
        x = _commit(tmp, "x: one side")
        _sh(tmp, "checkout", "-q", "-b", "y", third)
        _write(tmp, "src/hot/a.rs", "fn a() { /* y */ }\n")
        y = _commit(tmp, "y: the other side")
        _sh(tmp, "checkout", "-q", "main")
        _sh(tmp, "merge", "-q", "--no-ff", "-m", "Merge pull request #3", "x")
        # Expected to stop on the conflict, so its exit status is not checked;
        # the identity must still be the fixture's own, never the caller's.
        _sh(tmp, "merge", "-q", "--no-ff", "--no-commit", "y", check=False)
        _write(tmp, "src/hot/a.rs", "fn a() { /* neither: written in the merge */ }\n")
        resolved = _commit(tmp, "Merge pull request #4, resolved by hand")
        expect(tmp, _row("control", "stale", tip, owed3 + _heard(third, x, y)), 1,
               "a merge that resolves a conflict on the path is a change of its own",
               "resolved by hand")
        expect(tmp, _row("control", "stale", tip, owed3 + _heard(resolved)), 0,
               "acknowledging the hand-resolved merge clears it")

    if failures:
        print("SELFTEST FAIL:")
        for f in failures:
            print("  " + f)
        return 1
    print(f"selftest: {passed} cases pass")
    return 0


def run_quiet(root: str) -> int:
    old = sys.stdout
    sys.stdout = __import__("io").StringIO()
    try:
        return run(root)
    finally:
        sys.stdout = old


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
