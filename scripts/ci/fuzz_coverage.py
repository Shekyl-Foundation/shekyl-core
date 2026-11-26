#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Did this fuzz binary stop reaching its own code?
#
# The floor in `scripts/ci/fuzz_coverage_floors.tsv` records one fact: the
# final `cov:` of the binary a named run measured. `fuzz_run.py` used that
# number for a second job as well, "has the harness stopped reaching code
# it reached", and the two jobs cannot share one comparison
# (05-system-thinking). A dependency generation moves edges while the
# crate's own sources are unchanged. Lowering the floor each time that
# happens records the new plateau, and it also trains the ledger to follow
# the red tests down one row at a time.
#
# `decide` is the second job. A run inside the row's spread tolerance is
# held. A run under it is codegen drift, and still green, only when the
# crate's own sources are unchanged since the floor's commit and coverage
# still meets `CODEGEN_TOLERANCE` (the default margin minus one
# spread-limit). The verdict names the fuzz-lock packages whose versions
# moved. Anything past that allowance, any shortfall after the sources
# changed, or a subject that cannot be shown unchanged, is a shortfall.
# The floor itself still moves only with the run that measured it
# (`check_fuzz_inventory.py --floors`).

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import check_fuzz_inventory
from check_fuzz_inventory import DEFAULT_TOLERANCE, FULL_COMMIT_RE, SPREAD_LIMIT

# Comparisons stay integer, the same shape as the historical red line
# (`reached * PERCENT_BASE < plateau * percent`).
PERCENT_BASE = 100

# Points of plateau a later binary may lose, beyond the default margin,
# while the crate's own sources are unchanged. One spread-limit: the same
# step the default margin is built from
# (`PERCENT_BASE - DEFAULT_TOLERANCE == 2 * SPREAD_LIMIT`).
CODEGEN_EXTRA = SPREAD_LIMIT
CODEGEN_TOLERANCE = DEFAULT_TOLERANCE - CODEGEN_EXTRA

# How many lock-package moves a verdict names before it counts the rest.
# The nightly summary cell stays readable; the full list is what the
# selftest holds.
LOCK_CHANGE_SHOWN = 8

# A shallow nightly checkout has the tip and not the floor commit. The
# diff needs that commit's tree, not its parents. One commit is fetched
# when the object is absent. A fetch that fails is "not shown unchanged":
# no codegen allowance.
FETCH_SECONDS = 60

# Paths under `rust/<crate>/` that are the binary the fuzzer runs. The
# fuzz lock is not one of them: its version moves are named beside the
# verdict. `build.rs` is code the binary is built from. `fuzz/seeds` is
# what the run reaches; a seed change is the measurement's subject, not
# a dependency generation. `tests/` is not in the fuzz binary.
SOURCE_RELS = (
    "src",
    "Cargo.toml",
    "build.rs",
    "fuzz/Cargo.toml",
    "fuzz/fuzz_targets",
    "fuzz/seeds",
)
# At least one of these must be in the floor commit. A quiet diff over
# paths the commit does not contain is an absent subject (rule 47), not
# an unchanged one.
SUBJECT_RELS = ("src", "fuzz/fuzz_targets")

_CRATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")


class ShortfallCause(Enum):
    """Why a run under its spread line gets no codegen allowance."""

    # The crate's sources differ from the floor commit. The floor describes
    # the previous binary.
    SOURCES_CHANGED = "sources_changed"
    # Sources are unchanged, and coverage is past the codegen allowance.
    PAST_CODEGEN = "past_codegen"
    # The sources could not be shown unchanged. Absence is not a proof.
    SUBJECT_UNKNOWN = "subject_unknown"


@dataclass(frozen=True)
class SubjectDelta:
    """What changed in the crate since the commit that measured the floor.

    `sources_changed` is None when that commit's tree cannot be read, or
    does not contain the crate: no codegen allowance. `lock_changes` is
    None when the fuzz lock cannot be read on both sides, and an empty
    tuple when it was read and no registry or git package version moved.
    Each entry is `name old -> new`.
    """

    sources_changed: bool | None
    lock_changes: tuple[str, ...] | None


UNKNOWN_SUBJECT = SubjectDelta(None, None)


@dataclass(frozen=True)
class Held:
    """Inside the spread tolerance. The binary reached what it reached."""

    reached: int
    plateau: int
    tolerance: int


@dataclass(frozen=True)
class CodegenDrift:
    """Under the spread line, inside the codegen allowance, sources unchanged."""

    reached: int
    plateau: int
    tolerance: int
    held_percent: int
    short_of_spread: int
    lock_changes: tuple[str, ...] | None


@dataclass(frozen=True)
class Shortfall:
    """The run does not reach the recorded plateau, and nothing excuses it."""

    reached: int
    plateau: int
    tolerance: int
    held_percent: int
    short_of_spread: int
    cause: ShortfallCause
    lock_changes: tuple[str, ...] | None


Decision = Held | CodegenDrift | Shortfall


def meets(reached: int, plateau: int, percent: int) -> bool:
    """True when `reached` is at least `percent` percent of `plateau`."""
    return reached * PERCENT_BASE >= plateau * percent


def minimum_edges(plateau: int, percent: int) -> int:
    """The smallest `cov:` that meets `percent` of `plateau`, rounded up."""
    return -(-plateau * percent // PERCENT_BASE)


def held_percent(reached: int, plateau: int) -> int:
    """The whole percent of `plateau` that `reached` is."""
    if plateau <= 0:
        return 0
    return reached * PERCENT_BASE // plateau


def lock_version_changes(before: dict[str, set[str]], after: dict[str, set[str]]) -> tuple[str, ...]:
    """Registry and git packages whose versions differ, sorted by name.

    One version on each side is `name old -> new`. A version present on
    one side only is `name version -> (absent)` or `name (absent) -> version`.
    """
    changes = []
    for name in sorted(set(before) | set(after)):
        old, new = before.get(name, set()), after.get(name, set())
        if old == new:
            continue
        if len(old) == 1 and len(new) == 1:
            changes.append(f"{name} {min(old)} -> {min(new)}")
            continue
        changes.extend(f"{name} {version} -> (absent)" for version in sorted(old - new))
        changes.extend(f"{name} (absent) -> {version}" for version in sorted(new - old))
    return tuple(changes)


def lock_phrase(changes: tuple[str, ...] | None) -> str:
    """The lock half of a verdict. The full list is capped for the summary."""
    if changes is None:
        return "the fuzz lock could not be read"
    if not changes:
        return "no fuzz-lock package version changed"
    shown = changes[:LOCK_CHANGE_SHOWN]
    text = "fuzz lock moved " + ", ".join(shown)
    rest = len(changes) - len(shown)
    if rest:
        text += f", and {rest} more"
    return text


# What a verdict shows of a 40-character commit. The floor file keeps the
# full id; the log keeps this prefix, which `git rev-parse` still resolves.
COMMIT_SHOWN = 12


def commit_phrase(commit: str | None) -> str:
    """A short commit id, or a name when the id is not a full one."""
    if commit and FULL_COMMIT_RE.fullmatch(commit):
        return commit[:COMMIT_SHOWN]
    return "the floor commit"


def decide(reached: int, plateau: int, tolerance: int, subject: SubjectDelta | None) -> Decision:
    """How `reached` sits against `plateau` at `tolerance` percent.

    The spread line is first. Codegen grace is only the next step, and
    only when `subject.sources_changed` is False. None, an unknown
    subject, and a changed subject get no grace. A tolerance already at
    or under `CODEGEN_TOLERANCE` cannot be widened further: failing that
    line also fails the allowance.
    """
    if plateau > 0 and meets(reached, plateau, tolerance):
        return Held(reached, plateau, tolerance)
    percent_held = held_percent(reached, plateau)
    short = max(0, minimum_edges(plateau, tolerance) - reached) if plateau > 0 else 0
    locks = None if subject is None else subject.lock_changes
    sources_unchanged = subject is not None and subject.sources_changed is False
    if sources_unchanged and plateau > 0 and meets(reached, plateau, CODEGEN_TOLERANCE):
        return CodegenDrift(reached, plateau, tolerance, percent_held, short, locks)
    if subject is None or subject.sources_changed is None:
        cause = ShortfallCause.SUBJECT_UNKNOWN
    elif subject.sources_changed:
        cause = ShortfallCause.SOURCES_CHANGED
    else:
        cause = ShortfallCause.PAST_CODEGEN
    return Shortfall(reached, plateau, tolerance, percent_held, short, cause, locks)


def drift_says(decision: CodegenDrift, commit: str | None) -> str:
    """The clause a green codegen drift adds to the ordinary coverage line."""
    return (
        f"codegen drift, {decision.held_percent}% of the floor "
        f"({decision.short_of_spread} edges under the {decision.tolerance}% line), "
        f"within {CODEGEN_TOLERANCE}% while the crate's sources are unchanged since "
        f"{commit_phrase(commit)}; {lock_phrase(decision.lock_changes)}"
    )


def shortfall_says(decision: Shortfall, commit: str | None) -> str:
    """The red coverage line, including why the allowance did not apply."""
    where = commit_phrase(commit)
    prefix = (
        f"cov {decision.reached}, under {decision.tolerance}% of its floor of {decision.plateau}: "
        f"the harness no longer reaches code it reached "
        f"({decision.held_percent}% of the floor, {decision.short_of_spread} edges under "
        f"the {decision.tolerance}% line)"
    )
    if decision.cause is ShortfallCause.SUBJECT_UNKNOWN:
        return (
            prefix + f"; the crate's sources since {where} were not shown unchanged, "
            "so the codegen allowance does not apply"
        )
    if decision.cause is ShortfallCause.SOURCES_CHANGED:
        return (
            prefix + f"; the crate's sources changed since {where}, so the floor describes "
            f"the previous binary. Remeasure it. {lock_phrase(decision.lock_changes)}"
        )
    return (
        prefix + f"; the crate's sources are unchanged since {where} and coverage is past "
        f"the codegen allowance of {CODEGEN_TOLERANCE}%. {lock_phrase(decision.lock_changes)}"
    )


def _git(root: Path, *args: str, timeout: int | None = None) -> subprocess.CompletedProcess[str] | None:
    """One git command. None when it cannot be run. The exit is the caller's."""
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=_GIT_ENV,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _commit_present(root: Path, commit: str) -> bool:
    done = _git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    return done is not None and done.returncode == 0


def _ensure_commit(root: Path, commit: str) -> bool:
    """The floor commit's object is in this clone. Fetch one commit if not.

    A nightly checkout is the tip alone (`actions/checkout` depth 1). The
    floor commit is an ancestor that depth does not carry. Fetching it
    reads that tree; it does not move HEAD. No remote, a refused fetch,
    or a timeout leaves the object absent, which is fail-closed.
    """
    if _commit_present(root, commit):
        return True
    _git(root, "fetch", "--depth=1", "origin", commit, timeout=FETCH_SECONDS)
    return _commit_present(root, commit)


def _tree_has(root: Path, commit: str, rel: str) -> bool | None:
    """True when `rel` is in `commit`. None when git cannot answer."""
    done = _git(root, "ls-tree", "--name-only", commit, rel)
    if done is None or done.returncode != 0:
        return None
    return bool(done.stdout.strip())


def _show(root: Path, spec: str) -> str | None:
    done = _git(root, "show", spec)
    if done is None or done.returncode != 0:
        return None
    return done.stdout


def _versions(text: str) -> dict[str, set[str]] | None:
    """`locked`'s name-to-versions map, or None when the lock does not parse."""
    try:
        return check_fuzz_inventory.locked(text)
    except tomllib.TOMLDecodeError:
        return None


def _lock_text(root: Path, rel: str, commit: str | None) -> str | None:
    """The fuzz lock at `commit`, or the working tree when `commit` is None."""
    if commit is None:
        path = root / rel
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return _show(root, f"HEAD:{rel}")
    return _show(root, f"{commit}:{rel}")


def subject_delta(root: Path, commit: str, crate: str) -> SubjectDelta:
    """The crate's sources and fuzz-lock versions since `commit`.

    Unknown when `commit` is not a full id, `crate` is not one path
    segment, the object cannot be read, git's diff is neither clean nor
    different, or the commit does not contain the crate. A lock that
    cannot be read leaves `sources_changed` as the diff found it and
    `lock_changes` None.
    """
    if not FULL_COMMIT_RE.fullmatch(commit) or not _CRATE_RE.fullmatch(crate):
        return UNKNOWN_SUBJECT
    try:
        return _subject_delta(root, commit, crate)
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN_SUBJECT


def _subject_delta(root: Path, commit: str, crate: str) -> SubjectDelta:
    if not _ensure_commit(root, commit):
        return UNKNOWN_SUBJECT
    present = [_tree_has(root, commit, f"rust/{crate}/{rel}") for rel in SUBJECT_RELS]
    if any(found is None for found in present) or not any(present):
        return UNKNOWN_SUBJECT
    paths = [f"rust/{crate}/{rel}" for rel in SOURCE_RELS]
    diff = _git(root, "diff", "--quiet", commit, "--", *paths)
    if diff is None or diff.returncode not in (0, 1):
        return UNKNOWN_SUBJECT
    lock_rel = f"rust/{crate}/fuzz/Cargo.lock"
    before = _lock_text(root, lock_rel, commit)
    after = _lock_text(root, lock_rel, None)
    old = _versions(before) if before is not None else None
    new = _versions(after) if after is not None else None
    changes = None if old is None or new is None else lock_version_changes(old, new)
    return SubjectDelta(diff.returncode == 1, changes)


def selftest() -> int:
    """The decision and the subject diff. Each case names the edit that fails it."""
    failures: list[str] = []
    n_checks = 0

    def check(why: str, ok: bool, detail: str) -> None:
        nonlocal n_checks
        n_checks += 1
        if not ok:
            failures.append(f"{why}: {detail}")

    # The allowance is one spread-limit under the default margin, and the
    # default margin is two. Hardcoding 85, or retuning one constant,
    # fails this.
    check(
        "the default margin is two spread-limits",
        PERCENT_BASE - DEFAULT_TOLERANCE == 2 * SPREAD_LIMIT,
        f"{PERCENT_BASE - DEFAULT_TOLERANCE} != {2 * SPREAD_LIMIT}",
    )
    check(
        "the codegen allowance is one spread-limit under the default",
        CODEGEN_TOLERANCE == DEFAULT_TOLERANCE - SPREAD_LIMIT == PERCENT_BASE - 3 * SPREAD_LIMIT,
        f"CODEGEN_TOLERANCE={CODEGEN_TOLERANCE}",
    )

    unchanged = SubjectDelta(False, ("zeroize 1.8.2 -> 1.9.2",))
    changed = SubjectDelta(True, ())
    unreadable_lock = SubjectDelta(False, None)
    commit = "298205388b5baf413b15e5cc056f67ef5de48ce4"
    # (why, reached, plateau, tolerance, subject, kind, cause or None, needles)
    rows: list[tuple] = [
        ("inside the spread line, whatever the subject", 1000, 1000, 90, changed, Held, None, ()),
        ("exactly the spread line", 900, 1000, 90, unchanged, Held, None, ()),
        ("one edge under, sources unchanged", 880, 1000, 90, unchanged, CodegenDrift, None, ("codegen drift", "88% of the floor", "20 edges under", "zeroize 1.8.2 -> 1.9.2", f"within {CODEGEN_TOLERANCE}%")),
        ("exactly the codegen line", 850, 1000, 90, unchanged, CodegenDrift, None, ("codegen drift",)),
        ("one edge under the codegen line", 849, 1000, 90, unchanged, Shortfall, ShortfallCause.PAST_CODEGEN, ("past the codegen allowance", "84% of the floor")),
        ("a real loss, sources unchanged", 700, 1000, 90, unchanged, Shortfall, ShortfallCause.PAST_CODEGEN, ("past the codegen allowance", "70% of the floor", "200 edges under")),
        ("sources changed, inside the codegen band", 880, 1000, 90, changed, Shortfall, ShortfallCause.SOURCES_CHANGED, ("sources changed", "Remeasure it")),
        ("no subject at all", 880, 1000, 90, None, Shortfall, ShortfallCause.SUBJECT_UNKNOWN, ("not shown unchanged",)),
        ("a subject that could not be read", 880, 1000, 90, UNKNOWN_SUBJECT, Shortfall, ShortfallCause.SUBJECT_UNKNOWN, ("not shown unchanged",)),
        # The planted length-check: 137 of 182 is 75%, under 85. An edit
        # that grants the allowance to any unchanged subject greens this.
        ("the length-check harness, sources unchanged", 137, 182, 90, unchanged, Shortfall, ShortfallCause.PAST_CODEGEN, ("cov 137, under 90% of its floor of 182", "past the codegen allowance")),
        # A row whose own tolerance is already the codegen line. Subtracting
        # another spread-limit would green 849.
        ("a tolerance already at the codegen line", 849, 1000, CODEGEN_TOLERANCE, unchanged, Shortfall, ShortfallCause.PAST_CODEGEN, ("past the codegen allowance",)),
        # A wider measured spread (80) that the run misses. The allowance
        # is not stacked under that line: 1199 of 1500 is under 85 too.
        ("a wider tolerance is not widened again", 1199, 1500, 80, unchanged, Shortfall, ShortfallCause.PAST_CODEGEN, ("cov 1199, under 80%", "past the codegen allowance")),
        ("exactly a wider tolerance is held", 1200, 1500, 80, changed, Held, None, ()),
        ("an unreadable lock still names the drift", 880, 1000, 90, unreadable_lock, CodegenDrift, None, ("the fuzz lock could not be read",)),
        ("sources unchanged and the lock did not move", 880, 1000, 90, SubjectDelta(False, ()), CodegenDrift, None, ("no fuzz-lock package version changed",)),
    ]
    for why, reached, plateau, tolerance, subject, kind, cause, needles in rows:
        decision = decide(reached, plateau, tolerance, subject)
        if not isinstance(decision, kind):
            failures.append(f"{why}: wanted {kind.__name__}, got {type(decision).__name__}")
            continue
        if isinstance(decision, Shortfall) and decision.cause is not cause:
            failures.append(f"{why}: wanted {cause}, got {decision.cause}")
        says = ""
        if isinstance(decision, CodegenDrift):
            says = drift_says(decision, commit)
        elif isinstance(decision, Shortfall):
            says = shortfall_says(decision, commit)
        missing = [needle for needle in needles if needle not in says]
        if missing:
            failures.append(f"{why}: missing {missing} in {says!r}")
        if isinstance(decision, (CodegenDrift, Shortfall)) and decision.short_of_spread != max(0, minimum_edges(plateau, tolerance) - reached):
            failures.append(f"{why}: short_of_spread {decision.short_of_spread}")

    # The length-check minimum is the historical red line, not the allowance.
    check("137 of 182 meets neither line", not meets(137, 182, 90) and not meets(137, 182, CODEGEN_TOLERANCE), "137 was treated as reaching 182")
    check("the spread minimum rounds up", minimum_edges(182, 90) == 164 and meets(164, 182, 90) and not meets(163, 182, 90), f"minimum {minimum_edges(182, 90)}")

    many = tuple(f"pkg{i} 1.0.0 -> 1.0.{i}" for i in range(LOCK_CHANGE_SHOWN + 1))
    phrase = lock_phrase(many)
    # The count of arrows in the shown clause is the cap, and the suffix
    # names the rest. Showing every move, or dropping the rest, fails.
    shown, _, rest = phrase.partition(", and ")
    check(
        "the shown lock moves are the cap",
        shown.count("->") == LOCK_CHANGE_SHOWN and rest == "1 more",
        phrase,
    )
    check("eight moves are shown in full", lock_phrase(many[:LOCK_CHANGE_SHOWN]).count("->") == LOCK_CHANGE_SHOWN and "more" not in lock_phrase(many[:LOCK_CHANGE_SHOWN]), lock_phrase(many[:LOCK_CHANGE_SHOWN]))

    before = {
        "zeroize": {"1.8.2"},
        "heapless": {"0.8.0"},
        "bitvec": {"1.0.1", "2.0.0"},
        "same": {"1.0.0"},
    }
    after = {
        "zeroize": {"1.9.2"},
        "added": {"1.0.0"},
        "bitvec": {"1.0.1"},
        "same": {"1.0.0"},
    }
    want_changes = (
        "added (absent) -> 1.0.0",
        "bitvec 2.0.0 -> (absent)",
        "heapless 0.8.0 -> (absent)",
        "zeroize 1.8.2 -> 1.9.2",
    )
    check("version moves pair by name", lock_version_changes(before, after) == want_changes, str(lock_version_changes(before, after)))

    # Path packages have no `source` and are the tree's own. `locked` omits
    # them; a second parser that reported them would name a crate version
    # as if it were codegen.
    path_before = 'version = 4\n\n[[package]]\nname = "shekyl-noise"\nversion = "0.1.0"\n\n[[package]]\nname = "zeroize"\nversion = "1.8.2"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
    path_after = path_before.replace('name = "shekyl-noise"\nversion = "0.1.0"', 'name = "shekyl-noise"\nversion = "0.2.0"').replace('version = "1.8.2"', 'version = "1.9.2"')
    old_v, new_v = _versions(path_before), _versions(path_after)
    got_changes = None if old_v is None or new_v is None else lock_version_changes(old_v, new_v)
    check("a path package is not a lock move", got_changes == ("zeroize 1.8.2 -> 1.9.2",), str(got_changes))
    check("a lock that does not parse is unreadable", _versions("[[package]\n") is None, "bad toml parsed")
    header = Path(__file__).resolve().parent.joinpath("fuzz_coverage_floors.tsv").read_text(encoding="utf-8")
    check(
        "the floor header states this allowance",
        f"{CODEGEN_TOLERANCE} while the default is {DEFAULT_TOLERANCE}" in header,
        "the header drifted from CODEGEN_TOLERANCE",
    )

    subject_failures, n_subject = _subject_cases()
    failures.extend(subject_failures)
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"fuzz coverage selftest: {len(rows) + n_checks + n_subject} cases pass")
    return 0


def _subject_cases() -> tuple[list[str], int]:
    """A planted crate. Each edit is the one that makes that case lie."""
    failures: list[str] = []
    checked = 0
    lock_v1 = (
        "version = 4\n\n[[package]]\nname = \"zeroize\"\nversion = \"1.8.2\"\n"
        "source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
    )
    lock_v2 = lock_v1.replace("1.8.2", "1.9.2")
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        crate = root / "rust" / "demo"
        files = {
            crate / "src" / "lib.rs": "fn floor() {}\n",
            crate / "Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.0.0\"\n",
            crate / "build.rs": "fn main() {}\n",
            crate / "fuzz" / "Cargo.toml": "[package]\nname = \"demo-fuzz\"\nversion = \"0.0.0\"\n",
            crate / "fuzz" / "fuzz_targets" / "t.rs": "fn main() {}\n",
            crate / "fuzz" / "seeds" / "t" / "seed": "a",
            crate / "fuzz" / "Cargo.lock": lock_v1,
            crate / "tests" / "t.rs": "fn tests_are_not_the_binary() {}\n",
        }
        for path, text in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        init = _git(root, "init", "-b", "main")
        if init is None or init.returncode != 0:
            return [f"the planted repo did not init: {None if init is None else init.stderr}"], 0
        (root / "hooks").mkdir()
        for key, value in (
            ("user.email", "coverage-floor@example.com"),
            ("user.name", "coverage-floor"),
            ("commit.gpgsign", "false"),
            ("core.hooksPath", str(root / "hooks")),
        ):
            cfg = _git(root, "config", key, value)
            if cfg is None or cfg.returncode != 0:
                return [f"the planted repo has no {key}"], 0
        added = _git(root, "add", "--", "rust/demo")
        committed = _git(root, "commit", "-m", "floor")
        if added is None or committed is None or added.returncode != 0 or committed.returncode != 0:
            return ["the planted floor commit failed"], 0
        rev = _git(root, "rev-parse", "HEAD")
        if rev is None or rev.returncode != 0:
            return ["the planted commit has no id"], 0
        sha = rev.stdout.strip()

        def expect(why: str, delta: SubjectDelta, sources: bool | None, lock: tuple[str, ...] | None) -> None:
            nonlocal checked
            checked += 1
            if delta.sources_changed is not sources or delta.lock_changes != lock:
                failures.append(f"{why}: wanted sources={sources} lock={lock}, got {delta}")

        # Lock only. Adding `fuzz/Cargo.lock` to SOURCE_RELS fails this,
        # because the diff would then call the sources changed.
        (crate / "fuzz" / "Cargo.lock").write_text(lock_v2)
        expect("a lock-only move is codegen's subject", subject_delta(root, sha, "demo"), False, ("zeroize 1.8.2 -> 1.9.2",))
        (crate / "fuzz" / "Cargo.lock").write_text(lock_v1)

        # Tests are not the fuzz binary. Listing `tests` as a source fails this.
        (crate / "tests" / "t.rs").write_text("fn tests_moved() {}\n")
        expect("a test edit is not the fuzz binary", subject_delta(root, sha, "demo"), False, ())
        (crate / "tests" / "t.rs").write_text("fn tests_are_not_the_binary() {}\n")

        for rel, why in (
            ("src/lib.rs", "a library edit"),
            ("Cargo.toml", "a manifest edit"),
            ("build.rs", "a build-script edit"),
            ("fuzz/Cargo.toml", "a fuzz-manifest edit"),
            ("fuzz/fuzz_targets/t.rs", "a harness edit"),
            ("fuzz/seeds/t/seed", "a seed edit"),
        ):
            path = crate / rel
            original = path.read_text()
            path.write_text(original + "\n")
            expect(why, subject_delta(root, sha, "demo"), True, ())
            path.write_text(original)

        # A quiet diff over a crate the commit does not contain is an absent
        # subject. Treating exit 0 as unchanged would green it.
        expect("a crate the commit does not contain", subject_delta(root, sha, "shekyl-missing"), None, None)
        expect("a commit id that is not 40 hex characters", subject_delta(root, sha[:12], "demo"), None, None)
        expect("a commit the repo does not have", subject_delta(root, "0" * 40, "demo"), None, None)
        expect("a crate segment that escapes the tree", subject_delta(root, sha, "../demo"), None, None)

        # A second commit changes only the lock. A depth-1 clone of it does
        # not contain the floor commit; the nightly checkout is that shape.
        # Treating the missing object as unchanged would green the case
        # without reading the tree. Fetching it must report the lock move.
        (crate / "fuzz" / "Cargo.lock").write_text(lock_v2)
        relocked = _git(root, "add", "--", "rust/demo/fuzz/Cargo.lock")
        second = _git(root, "commit", "-m", "lock")
        if relocked is None or second is None or relocked.returncode != 0 or second.returncode != 0:
            failures.append("the shallow-clone fixture's second commit failed")
        else:
            with tempfile.TemporaryDirectory() as shallow_raw:
                dest = Path(shallow_raw) / "repo"
                # A path clone hardlinks the whole object store, so the floor
                # commit would already be present and the fetch would not run.
                # file:// forces the transport a remote uses.
                cloned = subprocess.run(
                    ["git", "clone", "--depth", "1", f"file://{root}", str(dest)],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=_GIT_ENV,
                )
                if cloned.returncode != 0:
                    failures.append(f"the depth-1 clone failed: {cloned.stderr}")
                elif _commit_present(dest, sha):
                    failures.append("the depth-1 clone already had the floor commit, so the fetch was not tested")
                else:
                    expect(
                        "a depth-1 clone fetches the floor commit and reads the lock",
                        subject_delta(dest, sha, "demo"),
                        False,
                        ("zeroize 1.8.2 -> 1.9.2",),
                    )
    return failures, checked


def main() -> int:
    import sys

    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    print(f"usage: {sys.argv[0]} --selftest", file=sys.stderr)
    return 2


if __name__ == "__main__":
    import sys

    sys.exit(main())
