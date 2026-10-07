#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Measurement-ledger gate (BA-Q23). A constant that rests on a measurement
# must not outlive the code that measurement was taken on without the ledger
# saying so.
#
# The ledger splits that fact in two. A `[[path_set]]` names the pathspecs
# whose cost is shared, and the commits those pathspecs have heard
# (`cleared` for a cost-neutral review point, `stale_through` for a stale
# constant that is still listening). A `[[constant]]` points at one path set
# and carries what is true of that constant alone: where the value is
# written, which benchmark measures it, the capture, and whether it is
# current, stale, or unmeasured. One commit to a shared path is acknowledged
# once.
#
# `cleared` is read only by current constants. A stale constant does not
# consult it. The only edit that retires staleness is a capture whose
# revision contains the constant's `stale_since`, under the same name. The
# check walks the stale constants at HEAD's first parent, which in CI is the
# base branch. On a local branch that parent is the last commit only.
#
# An `estimated` constant is a prediction with its arithmetic: a band with
# a unit, the basis, and the captures the basis is computed from, which
# must exist. It is the shape a design takes before its path is built. The
# only edit that makes an estimate current or stale is a capture file that
# was not in the parent tree: a measurement that landed, not an estimate
# that hardened. An estimate may be withdrawn to unmeasured; it may not
# vanish.
#
# Exit 0: the ledger tells the truth. Exit 1: it disagrees with the tree.
# Exit 2: the question could not be asked (rule 47). `--selftest` builds
# throwaway repositories and bites each failure class.

from __future__ import annotations

import enum
import io
import math
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strip_c_comments import self_test as strip_self_test  # noqa: E402
from strip_c_comments import strip as strip_comments  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
# Repo-relative. `git show HEAD^1:<this>` reads the parent ledger.
LEDGER = "docs/benchmarks/measurement_ledger.toml"

# A sentence a reviewer can judge. "ok" is under it; a clause that names
# the cost is over it. One floor for every acknowledgment and every carrier.
MIN_SENTENCE_CHARS = 12
# Git's default abbreviation floor, and the full object id.
MIN_COMMIT_ID_HEX = 7
MAX_COMMIT_ID_HEX = 40
# How many commits a finding quotes before saying "and N more".
COMMITS_NAMED = 3
# How much of an object id a finding shows.
OID_SHOWN = 10

COMMIT_ID_RE = re.compile(rf"[0-9a-f]{{{MIN_COMMIT_ID_HEX},{MAX_COMMIT_ID_HEX}}}")
PATH_SET_ID_RE = re.compile(r"[a-z][a-z0-9]*(-[a-z0-9]+)*")
T_ROW_RE = re.compile(r"^BA-T\d+$")
CAPTURE_REV_RE = re.compile(r"git[_ ]rev(?:ision)?[\"'\s:=]+([0-9a-f]{7,40})", re.I)

# `rev_source` must equal this when the capture file records its own revision.
REV_SOURCE_HEADER = "capture header"

# Suffixes whose comments `strip_c_comments` removes. Anything else is either
# a hash-comment language or prose (JSON, Markdown), where the needle is the
# statement.
C_FAMILY_SUFFIXES = {".rs", ".h", ".hpp", ".c", ".cpp", ".cc", ".inl"}
HASH_COMMENT_SUFFIXES = {".py", ".sh", ".toml", ".yml", ".yaml"}

HEADER_KEYS = {
    "tracked_set", "toolchain_file", "path_set", "constant", "toolchain",
    "retired_estimate",
}
PATH_SET_KEYS = {"id", "spec", "cleared", "stale_through"}
CONSTANT_KEYS = {"name", "defined_in", "needle", "measured_by", "status", "path_set"}
MEASURED_KEYS = {"capture", "capture_rev", "rev_source"}
STALE_KEYS = {"stale_since", "carrier"}
UNMEASURED_KEYS = {"carrier"}
ESTIMATED_KEYS = {"estimate", "basis", "basis_captures", "carrier"}
TOOLCHAIN_ACK_KEYS = {"commit", "note"}
BAND_KEYS = {"low", "high", "unit"}
RETIRED_KEYS = {"name", "estimate", "measured", "capture", "capture_rev", "verdict", "note"}
VERDICT_HELD = "held"
VERDICT_FALSIFIED = "falsified"

SHALLOW_MSG = (
    "this checkout is shallow and its history is cut inside the range "
    "the ledger asks about; fetch full history (`git fetch --unshallow`)"
)


class GateError(Exception):
    """The gate could not ask its question (exit 2)."""


class Status(enum.Enum):
    CURRENT = "current"
    STALE = "stale"
    UNMEASURED = "unmeasured"
    ESTIMATED = "estimated"

    @classmethod
    def parse(cls, raw: object) -> Status | None:
        if not isinstance(raw, str):
            return None
        try:
            return cls(raw)
        except ValueError:
            return None


class NeedleSite(enum.Enum):
    """Where a constant's quoted text was found."""

    DEFINITION = "definition"
    COMMENT = "comment"
    ABSENT = "absent"


@dataclass(frozen=True)
class Ack:
    """One commit a path set or the toolchain has heard, plus the sentence."""

    through: str
    text: str


@dataclass(frozen=True)
class PathSet:
    """Pathspecs that share one cost, and the commits they have heard.

    `cleared` and `stale_through` are `None` when the key is absent, and an
    empty tuple when the key is present and empty. Callers use that to tell
    "nobody wrote the list" from "the list names nothing".
    """

    id: str
    spec: tuple[str, ...]
    cleared: tuple[Ack, ...] | None
    stale_through: tuple[Ack, ...] | None


@dataclass(frozen=True)
class Band:
    """A predicted range in one unit. A point prediction is `low == high`."""

    low: float
    high: float
    unit: str

    def holds(self, measured: float) -> bool:
        return self.low <= measured <= self.high

    def shown(self) -> str:
        return f"{self.low:g} to {self.high:g} {self.unit}"


@dataclass(frozen=True)
class RetiredEstimate:
    """A prediction kept beside the measurement that settled it."""

    name: str
    estimate: Band
    measured: float
    capture: str
    capture_rev: str
    verdict: str


@dataclass(frozen=True)
class Constant:
    """One cost-justified value. History lives on its path set, not here."""

    name: str
    defined_in: str
    needle: str
    measured_by: tuple[str, ...]
    status: Status
    path_set: str
    capture: str | None = None
    capture_rev: str | None = None
    rev_source: str | None = None
    stale_since: str | None = None
    carrier: str | None = None
    estimate: Band | None = None
    basis: str | None = None
    basis_captures: tuple[str, ...] = ()


@dataclass(frozen=True)
class GitResult:
    code: int
    out: str
    err: str


def git(root: Path, *args: str) -> GitResult:
    completed = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    return GitResult(completed.returncode, completed.stdout.strip(), completed.stderr.strip())


def resolve(root: Path, rev: str) -> str | None:
    """A hex commit id, resolved. Anything else is refused.

    An empty string peels to HEAD, and a branch name moves with the tree.
    Either would acknowledge whatever is newest.
    """
    if not COMMIT_ID_RE.fullmatch(rev):
        return None
    result = git(root, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    if result.code != 0 or not result.out:
        return None
    return result.out


def shallow_boundary(root: Path) -> set[str]:
    """Commits at which a shallow history is cut. Empty when the history is complete."""
    result = git(root, "rev-parse", "--is-shallow-repository")
    if result.code != 0 or result.out != "true":
        return set()
    common = git(root, "rev-parse", "--git-common-dir")
    if common.code != 0 or not common.out:
        return set()
    path = Path(common.out)
    if not path.is_absolute():
        path = root / path
    try:
        text = (path / "shallow").read_text(encoding="ascii")
    except OSError:
        return set()
    return {line.strip() for line in text.splitlines() if line.strip()}


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return git(root, "merge-base", "--is-ancestor", ancestor, descendant).code == 0


def is_exclude(spec: str) -> bool:
    """True for a pathspec that removes paths rather than adding them."""
    if spec.startswith(":!") or spec.startswith(":^"):
        return True
    if not spec.startswith(":("):
        return False
    magic, _, _ = spec.partition(")")
    return "exclude" in magic


def require_stripper() -> None:
    """A stripper that fails its own cases must not decide this gate."""
    held = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = strip_self_test()
    finally:
        sys.stdout = held
    if code != 0:
        raise GateError("strip_c_comments failed its self-test")


def strip_hash_comments(text: str) -> str:
    """Drop `#` through end of line.

    A `#` inside a string is treated as a comment. That fails the constant
    closed, and the needle then has to start before the mark.
    """
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        at = line.find("#")
        if at < 0:
            kept.append(line)
            continue
        newline = "\n" if line.endswith("\n") else ""
        kept.append(line[:at] + newline)
    return "".join(kept)


def definition_site(text: str, needle: str, path: str) -> NeedleSite:
    """Where `needle` sits in `path`'s text: the definition, a comment, or nowhere.

    C and Rust go through `strip_c_comments`, which drops block comments that
    do not start the line. A line-prefix scan of `//` leaves
    `int x; /* old value */` looking like code.
    """
    suffix = Path(path).suffix
    if suffix in C_FAMILY_SUFFIXES:
        visible = strip_comments(text, rust=suffix == ".rs")
    elif suffix in HASH_COMMENT_SUFFIXES:
        visible = strip_hash_comments(text)
    else:
        visible = text
    if needle in visible:
        return NeedleSite.DEFINITION
    if needle in text:
        return NeedleSite.COMMENT
    return NeedleSite.ABSENT


def describe(root: Path, oid: str) -> str:
    result = git(root, "log", "-1", "--format=%h %ad %s", "--date=short", oid)
    return result.out


def name_commits(root: Path, oids: list[str]) -> str:
    shown = oids[-COMMITS_NAMED:][::-1]
    text = "; ".join(describe(root, oid) for oid in shown)
    extra = len(oids) - len(shown)
    if extra:
        text += f" (and {extra} more)"
    return text


def newer_commits(root: Path, heard: list[str], spec: tuple[str, ...]) -> list[str]:
    """Commits in HEAD that touch `spec` and are in none of `heard`'s histories.

    `heard` is a set. Two pull requests that each name their own tip cover
    the merge of both, because each commit is reachable from one of them.
    A clean merge is not itself a change: `--remerge-diff` is empty. A
    merge that resolves a conflict on the path is kept. If this git cannot
    answer, the merge is kept.
    """
    cut = shallow_boundary(root)
    if cut:
        span = git(root, "rev-list", "HEAD", "--not", *heard)
        if span.code != 0 or cut & set(span.out.splitlines()):
            raise GateError(SHALLOW_MSG)
    log = git(root, "log", "--format=%H %P", "HEAD", "--not", *heard, "--", *spec)
    if log.code != 0:
        raise GateError(f"git log HEAD --not <heard> failed: {log.err}")
    newer: list[str] = []
    for line in log.out.splitlines():
        oid, *parents = line.split()
        if len(parents) > 1:
            own = git(root, "show", "--remerge-diff", "--format=", oid, "--", *spec)
            if own.code == 0 and not own.out:
                continue
        newer.append(oid)
    return newer


def _sentence(raw: object) -> str | None:
    if not isinstance(raw, str) or len(raw.strip()) < MIN_SENTENCE_CHARS:
        return None
    return raw.strip()


def _number(raw: object) -> float | None:
    """A finite TOML number. `true` is not a number, and neither is a string."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    value = float(raw)
    return value if math.isfinite(value) else None


def parse_band(raw: object, label: str) -> tuple[Band | None, list[str]]:
    """`{ low, high, unit }`: two numbers in order, and what they count."""
    if not isinstance(raw, dict):
        return None, [f"{label}: estimate is a table of low, high and unit"]
    fails = [
        f"{label}: estimate key {key!r} is not one of low, high, unit"
        for key in sorted(set(raw) - BAND_KEYS)
    ]
    low, high = _number(raw.get("low")), _number(raw.get("high"))
    unit = raw.get("unit")
    if low is None or high is None:
        fails.append(f"{label}: estimate low and high are numbers")
    elif low > high:
        fails.append(f"{label}: estimate low {low:g} is above high {high:g}")
    if not isinstance(unit, str) or not unit.strip():
        fails.append(f"{label}: estimate names its unit")
    if fails or low is None or high is None or not isinstance(unit, str):
        return None, fails
    return Band(low, high, unit.strip()), []


def _article(word: str) -> str:
    return "an" if word[:1] in "aeiou" else "a"


def parse_acks(
    items: object, *, id_key: str, text_key: str, label: str
) -> tuple[tuple[Ack, ...], list[str]]:
    """Parse a list of acknowledgment tables. A bad shape is a finding, not a crash."""
    if not isinstance(items, list):
        return (), [f"{label} must be a list of tables"]
    acks: list[Ack] = []
    fails: list[str] = []
    allowed = {id_key, text_key}
    for index, item in enumerate(items):
        where = f"{label}[{index}]"
        if not isinstance(item, dict):
            fails.append(f"{where} must be a table")
            continue
        unknown = sorted(set(item) - allowed)
        if unknown:
            fails.append(f"{where} has unknown key {unknown[0]!r}")
        raw_id = item.get(id_key, "")
        if not isinstance(raw_id, str) or not COMMIT_ID_RE.fullmatch(raw_id):
            fails.append(f"{where}.{id_key} is not a commit id")
            continue
        text = _sentence(item.get(text_key, ""))
        if text is None:
            fails.append(f"{where} says nothing about the cost")
            text = ""
        acks.append(Ack(raw_id, text))
    return tuple(acks), fails


def bind_ack(root: Path, ack: Ack, label: str) -> tuple[str | None, str | None]:
    """The resolved oid, or a finding. A shallow miss is exit 2, not a lie."""
    oid = resolve(root, ack.through)
    if oid is None:
        if COMMIT_ID_RE.fullmatch(ack.through) and shallow_boundary(root):
            raise GateError(SHALLOW_MSG)
        return None, f"{label} is not a commit in this repository"
    if not is_ancestor(root, oid, "HEAD"):
        return None, f"{label} {oid[:OID_SHOWN]} is not an ancestor of HEAD"
    return oid, None


def _require_str(table: dict, key: str, fails: list[str], label: str) -> str:
    raw = table.get(key, "")
    if not isinstance(raw, str) or not raw.strip():
        fails.append(f"{label} needs {key!r}")
        return ""
    return raw.strip()


def parse_path_set(table: object, index: int) -> tuple[PathSet | None, list[str]]:
    label = f"path_set[{index}]"
    if not isinstance(table, dict):
        return None, [f"{label} must be a table"]
    fails: list[str] = []
    unknown = sorted(set(table) - PATH_SET_KEYS)
    for key in unknown:
        fails.append(f"{label} has unknown key {key!r}")
    raw_id = table.get("id", "")
    if not isinstance(raw_id, str) or not PATH_SET_ID_RE.fullmatch(raw_id):
        fails.append(f"{label} id {raw_id!r} is not a kebab-case name")
        return None, fails
    spec = table.get("spec")
    if (
        not isinstance(spec, list)
        or not spec
        or not all(isinstance(item, str) and item for item in spec)
    ):
        fails.append(f"path set {raw_id}: spec must be a non-empty list of pathspecs")
        spec_t: tuple[str, ...] = ()
    else:
        spec_t = tuple(spec)
    cleared: tuple[Ack, ...] | None = None
    stale_through: tuple[Ack, ...] | None = None
    if "cleared" in table:
        cleared, cleared_fails = parse_acks(
            table["cleared"], id_key="through", text_key="reason",
            label=f"path set {raw_id} cleared",
        )
        fails.extend(cleared_fails)
    if "stale_through" in table:
        stale_through, stale_fails = parse_acks(
            table["stale_through"], id_key="through", text_key="note",
            label=f"path set {raw_id} stale_through",
        )
        fails.extend(stale_fails)
    if not spec_t:
        return None, fails
    return PathSet(raw_id, spec_t, cleared, stale_through), fails


def parse_constant(table: object, index: int) -> tuple[Constant | None, list[str]]:
    label = f"constant[{index}]"
    if not isinstance(table, dict):
        return None, [f"{label} must be a table"]
    status = Status.parse(table.get("status"))
    name = table.get("name", "")
    if not isinstance(name, str) or not name.strip():
        name = f"<unnamed {index}>"
    else:
        name = name.strip()
    fails: list[str] = []
    if status is None:
        fails.append(
            f"{name}: status {table.get('status')!r} is not one of "
            + ", ".join(item.value for item in Status)
        )
        return None, fails
    allowed = set(CONSTANT_KEYS)
    if status is Status.UNMEASURED:
        allowed |= UNMEASURED_KEYS
    elif status is Status.ESTIMATED:
        allowed |= ESTIMATED_KEYS
    else:
        allowed |= MEASURED_KEYS
        if status is Status.STALE:
            allowed |= STALE_KEYS
    for key in sorted(set(table) - allowed):
        fails.append(
            f"{name}: key {key!r} is not valid for "
            f"{_article(status.value)} {status.value} constant"
        )
    for key in sorted(CONSTANT_KEYS - set(table)):
        fails.append(f"{name}: missing {key!r}")
    defined_in = _require_str(table, "defined_in", fails, name)
    needle = table.get("needle", "")
    if not isinstance(needle, str) or not needle:
        fails.append(f"{name}: missing 'needle'")
        needle = ""
    path_set = table.get("path_set", "")
    if not isinstance(path_set, str) or not PATH_SET_ID_RE.fullmatch(path_set):
        fails.append(f"{name}: path_set {path_set!r} is not a path set id")
        path_set = ""
    measured = table.get("measured_by")
    measured_t: tuple[str, ...] = ()
    if not isinstance(measured, list) or not measured:
        fails.append(f"{name}: measured_by must name at least one BA-T row")
    else:
        ids: list[str] = []
        for item in measured:
            if not isinstance(item, str) or not T_ROW_RE.fullmatch(item):
                fails.append(f"{name}: measured_by {item!r} is not a BA-T row id")
            else:
                ids.append(item)
        measured_t = tuple(ids)
    capture = capture_rev = rev_source = stale_since = carrier = None
    estimate = basis = None
    basis_captures: tuple[str, ...] = ()
    if status in (Status.CURRENT, Status.STALE):
        capture = _require_str(table, "capture", fails, name) or None
        capture_rev = _require_str(table, "capture_rev", fails, name) or None
        rev_source = _require_str(table, "rev_source", fails, name) or None
    if status is not Status.CURRENT:
        carrier = _sentence(table.get("carrier", ""))
        if carrier is None:
            fails.append(
                f"{name}: {_article(status.value)} {status.value} constant names its carrier"
            )
            carrier = None
    if status is Status.ESTIMATED:
        estimate, band_fails = parse_band(table.get("estimate"), name)
        fails.extend(band_fails)
        basis = _sentence(table.get("basis", ""))
        if basis is None:
            fails.append(f"{name}: an estimated constant states the arithmetic of its basis")
        raw_captures = table.get("basis_captures")
        if (
            not isinstance(raw_captures, list)
            or not raw_captures
            or not all(isinstance(item, str) and item.strip() for item in raw_captures)
        ):
            fails.append(
                f"{name}: an estimated constant lists the captures its basis is computed from"
            )
        else:
            basis_captures = tuple(item.strip() for item in raw_captures)
    if status is Status.STALE:
        raw_since = table.get("stale_since", "")
        if not isinstance(raw_since, str) or not COMMIT_ID_RE.fullmatch(raw_since):
            fails.append(f"{name}: stale_since is not a commit id")
        else:
            stale_since = raw_since
    if fails and (not path_set or not needle or not defined_in):
        return None, fails
    return Constant(
        name, defined_in, needle, measured_t, status, path_set,
        capture, capture_rev, rev_source, stale_since, carrier,
        estimate, basis, basis_captures,
    ), fails


def link(path_sets: dict[str, PathSet], constants: list[Constant]) -> list[str]:
    """Referential integrity. Acknowledgments are properties of the path set."""
    consumers: dict[str, list[Constant]] = {}
    for constant in constants:
        consumers.setdefault(constant.path_set, []).append(constant)
    fails: list[str] = []
    for path_set in path_sets.values():
        group = consumers.get(path_set.id, [])
        if not group:
            fails.append(f"path set {path_set.id}: no constant references it")
            continue
        current = any(item.status is Status.CURRENT for item in group)
        stale = any(item.status is Status.STALE for item in group)
        if path_set.cleared is not None and not current:
            fails.append(
                f"path set {path_set.id}: cleared is read only by a current constant"
            )
        if stale and not path_set.stale_through:
            fails.append(
                f"path set {path_set.id}: a stale constant needs stale_through"
            )
    for constant in constants:
        if constant.path_set and constant.path_set not in path_sets:
            fails.append(
                f"{constant.name}: path_set {constant.path_set!r} is not defined"
            )
    return fails


def interpret(
    data: dict, t_rows: set[str]
) -> tuple[dict[str, PathSet], list[Constant], list[str]]:
    """TOML tables to a typed ledger. Findings here are shape, not history."""
    fails: list[str] = []
    for key in sorted(set(data) - HEADER_KEYS):
        fails.append(f"unknown ledger key {key!r}")
    path_sets: dict[str, PathSet] = {}
    raw_sets = data.get("path_set", [])
    if not isinstance(raw_sets, list):
        fails.append("path_set must be a list of tables")
        raw_sets = []
    for index, table in enumerate(raw_sets):
        parsed, parsed_fails = parse_path_set(table, index)
        fails.extend(parsed_fails)
        if parsed is None:
            continue
        if parsed.id in path_sets:
            fails.append(f"path set {parsed.id}: duplicate id")
            continue
        path_sets[parsed.id] = parsed
    constants: list[Constant] = []
    seen: set[str] = set()
    raw_constants = data.get("constant", [])
    if not isinstance(raw_constants, list):
        fails.append("constant must be a list of tables")
        raw_constants = []
    for index, table in enumerate(raw_constants):
        parsed, parsed_fails = parse_constant(table, index)
        fails.extend(parsed_fails)
        if parsed is None:
            continue
        if parsed.name in seen:
            fails.append(f"{parsed.name}: duplicate constant name")
            continue
        seen.add(parsed.name)
        for row_id in parsed.measured_by:
            if row_id not in t_rows:
                fails.append(
                    f"{parsed.name}: measured_by {row_id} is not defined "
                    "in the tracked-set document"
                )
        constants.append(parsed)
    fails.extend(link(path_sets, constants))
    return path_sets, constants, fails


def load(root: Path) -> tuple[dict, set[str]]:
    """The ledger and the BA-T ids it may name. GateError when the subject is absent."""
    if git(root, "rev-parse", "--git-dir").code != 0:
        raise GateError("not a git repository")
    path = root / LEDGER
    if not path.is_file():
        raise GateError(f"{LEDGER} is missing — missing subject (rule 47)")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"{LEDGER} does not parse: {exc}") from exc
    constants = data.get("constant", [])
    if not isinstance(constants, list) or not constants:
        raise GateError(f"{LEDGER} has no constants — missing subject (rule 47)")
    if not any(
        isinstance(row, dict) and row.get("status") in (Status.CURRENT.value, Status.STALE.value)
        for row in constants
    ):
        raise GateError(
            "no constant is current or stale, so the staleness question was "
            "never asked — missing subject (rule 47)"
        )
    tracked = data.get("tracked_set", "")
    tracked_path = root / tracked if isinstance(tracked, str) else None
    if not tracked_path or not tracked_path.is_file():
        raise GateError(
            f"tracked_set {tracked!r} does not exist; measured_by ids cannot be resolved"
        )
    t_rows = set(re.findall(r"^\| \*\*(BA-T\d+)\*\* \|", tracked_path.read_text(
        encoding="utf-8", errors="replace"
    ), re.M))
    if not t_rows:
        raise GateError(f"{tracked} defines no BA-T rows")
    return data, t_rows


def _matches_tracked(root: Path, spec: str) -> bool:
    result = git(root, "ls-files", "--", spec)
    return result.code == 0 and bool(result.out)


def _is_tracked_file(root: Path, path: str) -> bool:
    """`path` is one tracked file, spelled exactly.

    A pathspec is not enough for a capture: a directory or a glob matches
    files without naming the one the arithmetic read.
    """
    result = git(root, "ls-files", "--", f":(literal){path}")
    return result.code == 0 and result.out == path


def audit_spec(root: Path, path_set: PathSet) -> list[str]:
    if not any(not is_exclude(item) for item in path_set.spec):
        return [f"path set {path_set.id}: spec needs at least one included pathspec"]
    fails: list[str] = []
    for spec in path_set.spec:
        if is_exclude(spec):
            continue
        if not _matches_tracked(root, spec):
            fails.append(
                f"path set {path_set.id}: path {spec!r} matches no tracked file"
            )
    return fails


def review_base(root: Path, constant: Constant, notes: list[str]) -> tuple[str | None, str | None]:
    """`(base, finding)`. A capture from outside HEAD is compared at the merge-base."""
    assert constant.capture_rev is not None
    oid = resolve(root, constant.capture_rev)
    if oid is None:
        if COMMIT_ID_RE.fullmatch(constant.capture_rev) and shallow_boundary(root):
            raise GateError(SHALLOW_MSG)
        return None, (
            f"{constant.name}: capture_rev {constant.capture_rev} is not a commit "
            "in this repository"
        )
    if is_ancestor(root, oid, "HEAD"):
        return oid, None
    base = git(root, "merge-base", oid, "HEAD")
    if base.code != 0 or not base.out:
        return None, (
            f"{constant.name}: capture_rev {oid[:OID_SHOWN]} shares no history with HEAD"
        )
    notes.append(
        f"{constant.name}: capture_rev {oid[:OID_SHOWN]} is not an ancestor of "
        f"HEAD; compared from their merge-base {base.out[:OID_SHOWN]}"
    )
    return base.out, None


def bound_acks(root: Path, acks: tuple[Ack, ...], label: str) -> tuple[tuple[str, ...], list[str]]:
    """Resolved oids for one path set. Bound once, then shared by every constant on it."""
    oids: list[str] = []
    fails: list[str] = []
    for index, ack in enumerate(acks):
        if not ack.text:
            continue
        oid, problem = bind_ack(root, ack, f"{label}[{index}].through")
        if problem:
            fails.append(problem)
            continue
        assert oid is not None
        oids.append(oid)
    return tuple(oids), fails


def _needle(root: Path, constant: Constant) -> list[str]:
    defined = root / constant.defined_in
    if not defined.is_file():
        return [f"{constant.name}: defined_in {constant.defined_in} does not exist"]
    if not constant.needle:
        return []
    text = defined.read_text(encoding="utf-8", errors="replace")
    site = definition_site(text, constant.needle, constant.defined_in)
    if site is NeedleSite.ABSENT:
        return [
            f"{constant.name}: needle {constant.needle!r} is not in "
            f"{constant.defined_in} (the constant moved, was renamed, or changed value)"
        ]
    if site is NeedleSite.COMMENT:
        return [
            f"{constant.name}: needle {constant.needle!r} appears in "
            f"{constant.defined_in} only inside a comment; the definition itself has changed"
        ]
    return []


def _capture_header(root: Path, constant: Constant) -> tuple[str | None, list[str]]:
    """The resolved capture oid, and any finding about the capture file or its header."""
    assert constant.capture and constant.capture_rev
    capture = root / constant.capture
    if not capture.is_file():
        return None, [f"{constant.name}: capture {constant.capture} does not exist"]
    header_revs = CAPTURE_REV_RE.findall(
        capture.read_text(encoding="utf-8", errors="replace")
    )
    resolved = resolve(root, constant.capture_rev)
    fails: list[str] = []
    if resolved is not None and header_revs:
        agrees = any(
            resolved.startswith(header) or header.startswith(resolved) for header in header_revs
        )
        if not agrees:
            fails.append(
                f"{constant.name}: capture_rev {constant.capture_rev} disagrees with "
                f"the revision the capture records "
                f"({', '.join(sorted(set(header_revs)))})"
            )
    elif resolved is not None and constant.rev_source == REV_SOURCE_HEADER:
        fails.append(
            f"{constant.name}: rev_source says {REV_SOURCE_HEADER!r} but "
            f"{constant.capture} records no revision"
        )
    return resolved, fails


def audit_constant(
    root: Path,
    constant: Constant,
    path_set: PathSet | None,
    spec_ok: bool,
    cleared: tuple[str, ...],
    stale_through: tuple[str, ...],
    notes: list[str],
) -> tuple[list[str], str | None]:
    """Findings for one constant, and its capture base when the constant is current.

    The base is the toolchain question's input. `cleared` and `stale_through`
    are already resolved on the path set; a stale constant does not read `cleared`.
    """
    fails = _needle(root, constant)
    if constant.status is Status.ESTIMATED:
        for capture in constant.basis_captures:
            if not _is_tracked_file(root, capture):
                fails.append(
                    f"{constant.name}: basis capture {capture} is not a tracked file"
                )
        return fails, None
    if constant.status is Status.UNMEASURED or path_set is None or not spec_ok:
        return fails, None
    if not constant.capture or not constant.capture_rev or not constant.rev_source:
        return fails, None
    _resolved, header_fails = _capture_header(root, constant)
    fails.extend(header_fails)
    base, base_fail = review_base(root, constant, notes)
    if base_fail:
        fails.append(base_fail)
        return fails, None
    assert base is not None
    if fails:
        return fails, None
    if constant.status is Status.CURRENT:
        newer = newer_commits(root, [base, *cleared], path_set.spec)
        if newer:
            fails.append(
                f"{constant.name}: says current, but {len(newer)} commit(s) touching "
                f"its paths are newer than its review point: {name_commits(root, newer)}. "
                "Land a newer capture, add a cleared note on its path set, or mark it stale"
            )
        return fails, base
    if not constant.stale_since:
        return fails, None
    since = resolve(root, constant.stale_since)
    if since is None:
        if shallow_boundary(root):
            raise GateError(SHALLOW_MSG)
        fails.append(f"{constant.name}: stale_since is not a commit in this repository")
        return fails, None
    newer = newer_commits(root, [base], path_set.spec)
    if not newer:
        fails.append(
            f"{constant.name}: says stale, but nothing touching its paths is newer "
            "than its capture; mark it current"
        )
        return fails, None
    if since not in newer:
        fails.append(
            f"{constant.name}: stale_since {since[:OID_SHOWN]} is not among the "
            f"{len(newer)} commit(s) touching its paths after its capture"
        )
        return fails, None
    if not path_set.stale_through:
        return fails, None
    unheard = newer_commits(root, [base, *stale_through], path_set.spec)
    if unheard:
        fails.append(
            f"{constant.name}: is stale, and {len(unheard)} commit(s) touching its "
            f"paths have not been heard: {name_commits(root, unheard)}. Add a "
            "stale_through entry on its path set saying what the change does to the cost"
        )
    return fails, None


def check_toolchain(
    root: Path, data: dict, bases: dict[str, str]
) -> list[str]:
    """One acknowledgment per change to the pinned toolchain, for the whole ledger.

    Owed while any constant is current across the change. A compiler bump is
    on no path set's spec and moves every wall-clock figure.
    """
    toolchain_file = data.get("toolchain_file", "")
    if not isinstance(toolchain_file, str) or not toolchain_file:
        return ["toolchain_file is missing"]
    if not _matches_tracked(root, toolchain_file):
        return [f"toolchain_file {toolchain_file!r} matches no tracked file"]
    raw = data.get("toolchain", [])
    fails: list[str] = []
    if not isinstance(raw, list):
        return ["toolchain must be a list of tables"]
    acked: set[str] = set()
    for index, table in enumerate(raw):
        label = f"toolchain[{index}]"
        if not isinstance(table, dict):
            fails.append(f"{label} must be a table")
            continue
        unknown = sorted(set(table) - TOOLCHAIN_ACK_KEYS)
        if unknown:
            fails.append(f"{label} has unknown key {unknown[0]!r}")
        parsed, parsed_fails = parse_acks(
            [table], id_key="commit", text_key="note", label="toolchain"
        )
        fails.extend(item.replace("toolchain[0]", label) for item in parsed_fails)
        if not parsed or not parsed[0].text:
            continue
        oid, problem = bind_ack(root, parsed[0], f"{label}.commit")
        if problem:
            fails.append(problem)
            continue
        touched = git(root, "log", "-1", "--format=%H", oid, "--", toolchain_file)
        if touched.code != 0 or touched.out != oid:
            fails.append(
                f"{label}.commit {oid[:OID_SHOWN]} does not change {toolchain_file}"
            )
            continue
        acked.add(oid)
    owed: dict[str, list[str]] = {}
    for name, base in sorted(bases.items()):
        for oid in newer_commits(root, [base], (toolchain_file,)):
            owed.setdefault(oid, []).append(name)
    for oid, names in owed.items():
        if oid not in acked:
            fails.append(
                f"toolchain: {describe(root, oid)} changed {toolchain_file} after the "
                f"review point of current constant(s) {', '.join(names)}. Add a "
                "[[toolchain]] entry saying what it does to measured cost"
            )
    return fails


def parse_retired(
    root: Path, data: dict
) -> tuple[list[RetiredEstimate], list[str]]:
    """Predictions that were measured, each beside its number.

    The verdict is not taken on trust: it is the band applied to the
    measured value, and a row that says otherwise is refused. That is the
    point of keeping the row. A wrong estimate recorded next to what was
    measured is how the next estimate gets calibrated.
    """
    raw_rows = data.get("retired_estimate", [])
    if not isinstance(raw_rows, list):
        return [], ["retired_estimate must be a list of tables"]
    retired: list[RetiredEstimate] = []
    fails: list[str] = []
    seen: set[str] = set()
    for index, table in enumerate(raw_rows):
        if not isinstance(table, dict):
            fails.append(f"retired_estimate[{index}] must be a table")
            continue
        raw_name = table.get("name")
        name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else ""
        label = f"retired estimate {name or f'[{index}]'}"
        found = [
            f"{label}: key {key!r} is not valid" for key in sorted(set(table) - RETIRED_KEYS)
        ]
        found += [f"{label}: missing {key!r}" for key in sorted(RETIRED_KEYS - set(table))]
        if "name" in table and not name:
            found.append(f"{label}: name is a non-empty string")
        if name in seen:
            found.append(f"{label}: duplicate name")
        band, band_fails = parse_band(table.get("estimate"), label)
        found.extend(band_fails)
        measured = _number(table.get("measured"))
        if measured is None:
            found.append(f"{label}: measured is a number, in the estimate's unit")
        capture = table.get("capture")
        if not isinstance(capture, str) or not _is_tracked_file(root, capture):
            found.append(f"{label}: capture {capture!r} is not a tracked file")
        raw_rev = table.get("capture_rev")
        if not isinstance(raw_rev, str) or resolve(root, raw_rev) is None:
            if isinstance(raw_rev, str) and COMMIT_ID_RE.fullmatch(raw_rev) and shallow_boundary(root):
                raise GateError(SHALLOW_MSG)
            found.append(f"{label}: capture_rev {raw_rev!r} is not a commit in this repository")
        if _sentence(table.get("note", "")) is None:
            found.append(f"{label}: note says what the difference is put down to")
        verdict = table.get("verdict")
        if band is not None and measured is not None:
            expected = VERDICT_HELD if band.holds(measured) else VERDICT_FALSIFIED
            if verdict != expected:
                found.append(
                    f"{label}: verdict {verdict!r}, but {measured:g} {band.unit} against "
                    f"{band.shown()} is {expected}"
                )
        fails.extend(found)
        if found or band is None or measured is None:
            continue
        seen.add(name)
        retired.append(RetiredEstimate(name, band, measured, capture, raw_rev, verdict))
    return retired, fails


def _parent_ledger(root: Path) -> str | None:
    """The ledger at HEAD's first parent, or None when that parent has none.

    A git failure that is not "the file is not in that tree" is exit 2.
    Silence there would let a stale constant disappear without a capture.
    """
    result = git(root, "show", f"HEAD^1:{LEDGER}")
    if result.code == 0:
        return result.out
    # No parent commit, or a parent that does not yet carry the ledger.
    # Both are the quiet case: this history has no stale constant to retire.
    # Any other failure is exit 2. Silence there drops a stale constant.
    missing = (
        "exists on disk, but not in" in result.err
        or "does not exist in" in result.err
        or "invalid object name" in result.err
        or "bad revision" in result.err
        or "unknown revision" in result.err
    )
    if missing:
        return None
    raise GateError(f"cannot read the ledger at HEAD^1: {result.err}")


def check_transitions(
    root: Path, data: dict, constants: list[Constant], retired: list[RetiredEstimate]
) -> list[str]:
    """A parent stale constant stays stale, or a capture under the same name contains its cause.

    Walking the new ledger misses the constant that was deleted or renamed:
    the parent row is gone, so no new row looks back at it. The capture check
    is the only retirement. An unresolvable `stale_since` is a finding. A
    parent ledger that does not parse means the question could not be asked.
    """
    text = _parent_ledger(root)
    if text is None or not text.strip():
        return []
    try:
        parent = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise GateError(
            f"the ledger at HEAD^1 does not parse, so a stale constant's "
            f"retirement cannot be checked: {exc}"
        ) from exc
    rows = parent.get("constant", [])
    if not isinstance(rows, list):
        raise GateError(
            "the ledger at HEAD^1 has no constant list, so a stale constant's "
            "retirement cannot be checked"
        )
    by_name = {constant.name: constant for constant in constants}
    raw_rows = data.get("constant", [])
    raw_names = {
        row.get("name")
        for row in raw_rows
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    fails: list[str] = []
    fails.extend(_estimate_transitions(root, rows, raw_names, by_name, retired))
    for old in rows:
        if not isinstance(old, dict) or old.get("status") != Status.STALE.value:
            continue
        name = old.get("name")
        if not isinstance(name, str) or not name:
            name = "<unnamed>"
        raw_since = old.get("stale_since", "")
        if not isinstance(raw_since, str):
            raw_since = ""
        since = resolve(root, raw_since)
        if since is None:
            if COMMIT_ID_RE.fullmatch(raw_since) and shallow_boundary(root):
                raise GateError(SHALLOW_MSG)
            fails.append(
                f"{name}: was stale, and stale_since {raw_since!r} is not a commit "
                "in this repository, so nothing can show a capture retired it"
            )
            continue
        if name not in raw_names:
            fails.append(
                f"{name}: was stale since {since[:OID_SHOWN]} and is gone. "
                "A stale constant keeps its name until a capture retires it"
            )
            continue
        now = by_name.get(name)
        if now is None or now.status is Status.STALE:
            continue
        if now.status is not Status.CURRENT:
            fails.append(
                f"{name}: was stale since {since[:OID_SHOWN]} and is now "
                f"{now.status.value}. Only a newer capture retires a stale constant"
            )
            continue
        cap = resolve(root, now.capture_rev or "")
        if cap is None or not is_ancestor(root, since, cap):
            shown = cap[:OID_SHOWN] if cap else (now.capture_rev or "nothing")
            fails.append(
                f"{name}: was stale since {since[:OID_SHOWN]} and is now current "
                f"on a capture at {shown}, which does not include that commit. "
                "Only a newer capture retires a stale constant"
            )
    return fails


def _estimate_transitions(
    root: Path, rows: list, raw_names: set, by_name: dict[str, Constant],
    retired: list[RetiredEstimate],
) -> list[str]:
    """An estimate becomes measured only by a capture file new to this history.

    `git cat-file -e HEAD^1:<capture>` says whether the parent tree already
    held the file. If it did, the "capture" predates the estimate's path and
    the row has hardened a prediction into a number. The same test applies
    to an estimate that leaves the constants for `retired_estimate`: it is
    retired by a measurement that landed, with its verdict, or not at all.
    A retired estimate also keeps the band the parent stated, to the unit:
    otherwise 40 to 60 becomes 40 to 70 on the day 67.2 arrives and the
    row reads "held".
    """
    fails: list[str] = []
    retired_by_name = {item.name: item for item in retired}
    for old in rows:
        if not isinstance(old, dict) or old.get("status") != Status.ESTIMATED.value:
            continue
        name = old.get("name")
        if not isinstance(name, str) or not name:
            name = "<unnamed>"
        if name not in raw_names:
            settled = retired_by_name.get(name)
            if settled is None:
                fails.append(
                    f"{name}: was estimated and is gone. An estimate is withdrawn to "
                    "unmeasured with its reason, measured by a capture, or retired "
                    "beside its measurement; it does not vanish"
                )
            else:
                if git(root, "cat-file", "-e", f"HEAD^1:{settled.capture}").code == 0:
                    fails.append(
                        f"{name}: was estimated and is now retired on {settled.capture}, "
                        "which the parent tree already held. Only a capture that lands "
                        "settles an estimate"
                    )
                # The band that is judged is the band that was predicted. A
                # retirement that redraws it has changed the question after
                # seeing the answer.
                predicted, _ = parse_band(old.get("estimate"), name)
                if predicted is None:
                    fails.append(
                        f"{name}: was estimated with a band the parent ledger does not "
                        "state as low, high and unit, so its retirement cannot be "
                        "checked against what was predicted"
                    )
                elif predicted != settled.estimate:
                    fails.append(
                        f"{name}: was estimated at {predicted.shown()} and is retired "
                        f"at {settled.estimate.shown()}. A retired estimate keeps the "
                        "band it was given; the verdict is against the prediction"
                    )
            continue
        now = by_name.get(name)
        if now is None or now.status in (Status.ESTIMATED, Status.UNMEASURED):
            continue
        held = git(root, "cat-file", "-e", f"HEAD^1:{now.capture}")
        if held.code == 0:
            fails.append(
                f"{name}: was estimated and is now {now.status.value} on "
                f"{now.capture}, which the parent tree already held. Only a capture "
                "that lands makes an estimate measured"
            )
    return fails


def run(root: Path) -> int:
    try:
        require_stripper()
        data, t_rows = load(root)
        path_sets, constants, fails = interpret(data, t_rows)
        notes: list[str] = []
        bases: dict[str, str] = {}
        spec_ok: dict[str, bool] = {}
        cleared_of: dict[str, tuple[str, ...]] = {}
        stale_of: dict[str, tuple[str, ...]] = {}
        for path_set in path_sets.values():
            spec_fails = audit_spec(root, path_set)
            fails.extend(spec_fails)
            spec_ok[path_set.id] = not spec_fails
            if path_set.cleared:
                oids, problems = bound_acks(
                    root, path_set.cleared, f"path set {path_set.id} cleared"
                )
                fails.extend(problems)
                cleared_of[path_set.id] = oids
            if path_set.stale_through:
                oids, problems = bound_acks(
                    root, path_set.stale_through, f"path set {path_set.id} stale_through"
                )
                fails.extend(problems)
                stale_of[path_set.id] = oids
        for constant in constants:
            path_set = path_sets.get(constant.path_set)
            found, base = audit_constant(
                root, constant, path_set, spec_ok.get(constant.path_set, False),
                cleared_of.get(constant.path_set, ()),
                stale_of.get(constant.path_set, ()),
                notes,
            )
            fails.extend(found)
            if base is not None:
                bases[constant.name] = base
        fails.extend(check_toolchain(root, data, bases))
        retired, retired_fails = parse_retired(root, data)
        fails.extend(retired_fails)
        # One name, one state. A prediction is open as a constant or
        # settled as a retired estimate, never both.
        constant_names = {constant.name for constant in constants}
        fails.extend(
            f"retired estimate {item.name}: a constant has this name too. A "
            "prediction is open or settled, not both"
            for item in retired
            if item.name in constant_names
        )
        fails.extend(check_transitions(root, data, constants, retired))
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2
    for note in notes:
        print(f"note: {note}")
    for constant in constants:
        if constant.status is Status.STALE:
            since = (constant.stale_since or "")[:OID_SHOWN]
            print(f"stale: {constant.name} — since {since}; carrier: {constant.carrier}")
        elif constant.status is Status.ESTIMATED:
            band = constant.estimate.shown() if constant.estimate else "no band"
            print(f"estimate: {constant.name} — {band}; carrier: {constant.carrier}")
    for item in retired:
        print(
            f"retired estimate: {item.name} — predicted {item.estimate.shown()}, "
            f"measured {item.measured:g} {item.estimate.unit}: {item.verdict}"
        )
    if fails:
        print("FAIL: the measurement ledger disagrees with the tree:")
        for finding in fails:
            print("  " + finding)
        return 1
    counts = {status: 0 for status in Status}
    for constant in constants:
        counts[constant.status] += 1
    print(
        f"measurement ledger: {len(constants)} constants tell the truth — "
        f"{counts[Status.CURRENT]} current, {counts[Status.STALE]} stale, "
        f"{counts[Status.UNMEASURED]} unmeasured, {counts[Status.ESTIMATED]} estimated"
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        from test_check_measurement_ledger import selftest

        return selftest()
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
