#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Hold the `shekyl-chain-rules` census registry to the consensus rule census,
# and print the crate's coverage as two figures over two denominators.
#
# `rust/shekyl-chain-rules/src/census.rs` declares two `census_rows!`
# registries — `CenRow` for the consensus flag, `PolicyRow` for the policy
# flag — one variant per ENFORCED row (bucket ≠ 3) of CONSENSUS_RULE_CENSUS.md
# §4, in census order, each marked `pending`, `implemented(path)`,
# `enforced_at(path, "test")`, `by_construction(path, "falsifier")` or
# `held_by_store("crate", "test")`. The registry is the crate's claim about
# which rules exist, which rows this crate enforces at a site other than the
# per-block stages, which rows hold by construction, and which rows a Rust
# crate below the validator holds; the census is the denominator that claim
# is measured against. Nothing else compares them, so this gate does, and it
# is the ONLY place the crate's "N of M" figure is computed
# (CHAIN_RULES_CRATE.md §6; CONSENSUS_C2_R8_STORE_PLACEMENT.md §9.4).
#
# What is checked (registry against census; manifest against G1):
#
#   bijection — every enforced census row of a flag has exactly one entry in
#               that flag's registry; every entry names an enforced row OF ITS
#               REGISTRY'S FLAG (a bucket-3 row, a typo, or a policy row filed
#               under the consensus enum are all "no such enforced row");
#   order     — entries appear in census §4 order, so `Row::index()` is
#               census-derived rather than editorial;
#   grammar   — one `census_rows!` per flag, a parseable header, every entry
#               `Var pending,`, `Var implemented(rust::path),`,
#               `Var enforced_at(rust::path, "test_fn"),`,
#               `Var by_construction(rust::path, "falsifier"),` or
#               `Var held_by_store("crate", "test_fn"),`, no attribute on an
#               entry (a `#[cfg]` the gate cannot evaluate would let the
#               compiled enum and the counted enum differ);
#   at-open   — an `enforced_at` row (CHAIN_RULES_SLICE_3.md Q4) is enforced by
#               THIS crate but not per block (CEN-E5 runs once, by the writer,
#               at open), so no per-block coverage can contain it. The entry
#               names the Rust `#[test]` in the crate that proves the site
#               refuses; the gate asserts a `#[test] fn <name>(` exists in the
#               crate's sources (rule 47 — a name in a comment is not a test).
#               Counted as implemented (the enforcement is Rust's), printed
#               separately, and excluded by `RuleSet::enforced`
#               from per-block completeness (the compiler's side of the same
#               fact);
#   held-by-store — a `held_by_store` row (DRS_E5_POOL_ALT_PRUNE.md E5-18) is
#               enforced by a Rust crate BELOW the validator — the store, whose
#               alt-chain construction and write path are where the row's
#               operand lives, and which this crate cannot import (DRS-D12 (i):
#               the dependency runs store → rules). The entry names the crate
#               and the `#[test]` in it that proves the holder refuses; the
#               gate asserts the crate is a workspace crate other than this
#               one and that a `#[test] fn <name>(` is DEFINED in its `src/`
#               or `tests/` (rule 47). Counted as implemented (the enforcement
#               is Rust's), printed separately, excluded from per-block
#               completeness by `RuleSet::enforced`;
#   G1 direct — the crate's Cargo.toml names neither `redb` nor
#               `shekyl-chain-store` in any dependency table (the transitive
#               half is `check_chain_rules_no_store.sh`, which needs cargo).
#
# The two flags are reported on two lines and never summed: a policy row
# counted toward consensus coverage is the proximity promotion the sibling
# enums exist to make unrepresentable. `implemented` is the registry's word;
# the compiler pins it (the macro emits `use path as _;` and the SCW-18 ROW
# assertion), so this gate does not run cargo and does not need to.
#
# Each line prints
# `implemented I / enforced E   at-open O   by-construction B   held-by-store S   ratified R / enforced E`
# with E fixed, so coverage cannot improve by moving rows out of scope. `I`
# includes the at-open, by-construction and held-by-store rows (Rust
# enforces them); `O`, `B` and `S` are SUBTRACTIONS, not further
# denominators, printed so the per-block completeness denominator,
# `E − O − B − S`, can be read off the line.
#
# Rule 47: the gate asserts its own subject. A missing registry file, a
# registry `lib.rs` does not compile (`mod census;` absent), a flag with no
# registry, an empty registry, an unparseable census — each is a missing
# subject and exit 2, never a vacuous pass. `--selftest` proves each refusal
# fires on the input built to trip it.
#
# Rule 46: the verdict is the process exit code; nothing here pipes it.
#
# Exit codes: 0 registry and census agree; 1 they differ (or G1 direct is
# violated), derivation printed; 2 subject missing or unparseable.

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# The census parser is `_census.py`, shared with `check_drs_e6_partition.py`:
# one denominator, one reading of what a §4 row is.
from _census import Refused, Row, parse_census  # noqa: E402
from strip_c_comments import strip as strip_comments  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CRATE = REPO / "rust" / "shekyl-chain-rules"
DEFAULT_CENSUS = REPO / "docs" / "design" / "CONSENSUS_RULE_CENSUS.md"
DEFAULT_REGISTRY = CRATE / "src" / "census.rs"
DEFAULT_LIB = CRATE / "src" / "lib.rs"
DEFAULT_MANIFEST = CRATE / "Cargo.toml"

# Registry flag identifier (the macro header's `: Flag`) → census `C/P` cell.
FLAG_OF = {"Consensus": "C", "Policy": "P"}
LABEL = {"C": "consensus", "P": "policy"}
# "Ratified" is the conformance register's denominator, printed beside the
# crate's own so a slice PR can see both; it is never what `implemented` is
# divided by.
RATIFIED_BUCKETS = (1, 2)
# G1: the two packages the crate must not name. The same two names are the
# belt's `BANNED` list; keep them together.
BANNED_PACKAGES = ("redb", "shekyl-chain-store")

INVOCATION_RE = re.compile(r"\bcensus_rows!\s*\{")
HEADER_RE = re.compile(r"^pub\s+enum\s+([A-Z][A-Za-z0-9]*)\s*:\s*([A-Z][A-Za-z]*)\s*\{$")
# One entry: `Var pending,`, `Var implemented(a::b::c),`,
# `Var enforced_at(a::b::c, "test_fn"),`,
# `Var by_construction(a::b::c, "falsifier"),` or
# `Var held_by_store("crate-name", "test_fn"),`. The variant is the census id
# without `CEN-` (`D1b`, `K1a`); a path is a plain Rust path; a test is an
# identifier; a store holder is a workspace crate name (`rust/<name>/`). Any
# other status form is an unparseable entry.
_RUST_PATH = r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*"
_CRATE_NAME = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
ENTRY_RE = re.compile(
    r"^(?P<var>[A-Z]+\d+[a-z]?)\s+"
    r"(?:(?P<pending>pending)"
    rf"|(?P<implemented>implemented)\(\s*(?P<impl_path>{_RUST_PATH})\s*\)"
    rf'|(?P<enforced_at>enforced_at)\(\s*(?P<site>{_RUST_PATH})\s*,\s*"(?P<proof>[A-Za-z_]\w*)"\s*\)'
    rf'|(?P<by_construction>by_construction)\(\s*(?P<property>{_RUST_PATH})\s*,\s*"(?P<falsifier>(?:doctest:|trybuild:)?[A-Za-z_]\w*)"\s*\)'
    rf'|(?P<held_store>held_by_store)\(\s*"(?P<krate>{_CRATE_NAME})"\s*,\s*"(?P<store_test>[A-Za-z_]\w*)"\s*\))'
    r"\s*,$"
)
# The crate whose registry this is. A `held_by_store` entry naming it is a
# row this crate holds, and that is `enforced_at` or `by_construction`.
THIS_CRATE = "shekyl-chain-rules"


# A `#[test]` function definition in the crate's sources, by name. Attributes
# between `#[test]` and `fn` (`#[should_panic]`, `#[ignore]`) are allowed;
# the name inside a comment, a string, or a call is not a definition.
def _test_def_re(name: str) -> re.Pattern[str]:
    # `#[test] fn` or, in an async crate (the ingest's switch tests, CEN-K5–K7),
    # `#[tokio::test] async fn`; other attributes may sit between.
    return re.compile(
        rf"#\[(?:tokio::)?test\]\s*(?:#\[[^\]]*\]\s*)*(?:async\s+)?fn\s+{re.escape(name)}\s*\("
    )
MOD_DECL_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+census\s*;\s*$", re.M)
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


@dataclass(frozen=True)
class Entry:
    variant: str  # "A1"
    status: str  # "pending" | "implemented" | "enforced_at" | "by_construction" | "held_by_store"
    path: str | None  # implemented / enforced_at: the rule type's Rust path; by_construction: the property's
    proof: str | None  # enforced_at: the `#[test]` that proves the site refuses; by_construction: the falsifier
    holder: tuple[str, str] | None  # held_by_store: (crate, test)
    line: int  # 1-based, in the registry file

    @property
    def id(self) -> str:
        return f"CEN-{self.variant}"

    @property
    def implemented(self) -> bool:
        """Rust enforces the row — per block, at another site, by construction,
        or in a Rust crate below the validator."""
        return self.status in ("implemented", "enforced_at", "by_construction", "held_by_store")

    @property
    def at_open(self) -> bool:
        return self.status == "enforced_at"

    @property
    def by_construction(self) -> bool:
        return self.status == "by_construction"

    @property
    def held_by_store(self) -> bool:
        return self.status == "held_by_store"


@dataclass(frozen=True)
class Registry:
    name: str  # "CenRow"
    flag: str  # "C" | "P"
    line: int
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class Inputs:
    census: str
    registry: str | None  # None: file missing
    lib: str | None
    manifest: str | None
    # The crate's Rust sources, concatenated, in which an `enforced_at` proof
    # test must be defined. `None` when the crate has no sources to read.
    crate_src: str | None = None
    # The sources of another workspace crate, by crate name — where a
    # `held_by_store` holder test must be defined. `None` when no such
    # crate exists. The repo reader in production; a dict in the self-test.
    crate_sources: Callable[[str], str | None] = lambda _name: None


@dataclass(frozen=True)
class Figures:
    flag: str
    registry: str
    implemented: int  # rows Rust enforces: per block, plus the at-open, by-construction and held-by-store rows
    at_open: int  # rows this crate enforces outside the per-block stages
    by_construction: int  # rows that hold by construction (type system / parser), with a falsifier
    held_by_store: int  # rows a Rust crate below the validator holds, with the test that proves it
    enforced: int  # the census denominator; never moves for an at-open, a by-construction or a store-held row
    ratified: int
    by_subsystem: dict[str, tuple[int, int]]  # subsystem -> (implemented, enforced)
    implemented_ids: tuple[str, ...]
    at_open_rows: tuple[tuple[str, str, str], ...]  # (id, site, proof test)
    by_construction_rows: tuple[tuple[str, str, str], ...]  # (id, property, falsifier)
    held_by_store_rows: tuple[tuple[str, str, str], ...]  # (id, crate, test)

    @property
    def per_block(self) -> int:
        """What `Coverage::is_complete_for` measures against: `E − O − B − S`."""
        return self.enforced - self.at_open - self.by_construction - self.held_by_store


# --------------------------------------------------------------------------
# registry side
# --------------------------------------------------------------------------


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _invocation_bodies(stripped: str) -> list[tuple[int, str]]:
    """(1-based start line, body text) of every `census_rows! { … }`.

    The body is what sits between the invocation's outer braces, found by
    brace depth so an entry list of any length is one invocation. Comments
    are already gone, so a `census_rows!` in a doc comment is not counted.
    """
    out: list[tuple[int, str]] = []
    for m in INVOCATION_RE.finditer(stripped):
        depth = 1
        i = m.end()
        while i < len(stripped) and depth:
            c = stripped[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        if depth:
            raise Refused(
                f"registry: `census_rows!` at line {_line_of(stripped, m.start())} "
                "has no closing brace"
            )
        body_start = m.end()
        out.append((_line_of(stripped, body_start), stripped[body_start : i - 1]))
    return out


def _parse_one(start_line: int, body: str) -> Registry:
    lines = body.split("\n")
    header: tuple[str, str, int] | None = None
    entries: list[Entry] = []
    closed = False
    for k, raw in enumerate(lines):
        line = raw.strip()
        n = start_line + k
        if not line:
            continue
        if header is None:
            if line.startswith("#["):
                continue  # the enum's own attributes / `#[doc = …]`
            hm = HEADER_RE.match(line)
            if not hm:
                raise Refused(f"registry: unparseable header at line {n}: {line!r}")
            name, flag_ident = hm.group(1), hm.group(2)
            if flag_ident not in FLAG_OF:
                raise Refused(
                    f"registry: unknown flag `{flag_ident}` at line {n}; "
                    f"expected one of {sorted(FLAG_OF)}"
                )
            header = (name, FLAG_OF[flag_ident], n)
            continue
        if closed:
            raise Refused(
                f"registry: text after the enum body at line {n} in {header[0]}: {line!r}"
            )
        if line == "}":
            closed = True
            continue
        if line.startswith("#["):
            raise Refused(
                f"registry: attribute on entry at line {n} in {header[0]} — entries "
                "carry no attributes (a `#[cfg]` would let the compiled enum and the "
                "counted enum differ)"
            )
        em = ENTRY_RE.match(line)
        if not em:
            raise Refused(f"registry: unparseable entry at line {n} in {header[0]}: {line!r}")
        if em.group("pending"):
            status, path, proof, holder = "pending", None, None, None
        elif em.group("implemented"):
            status, path, proof, holder = "implemented", em.group("impl_path"), None, None
        elif em.group("enforced_at"):
            status, path, proof, holder = "enforced_at", em.group("site"), em.group("proof"), None
        elif em.group("by_construction"):
            status, path, proof, holder = "by_construction", em.group("property"), em.group("falsifier"), None
        else:
            status, path, proof, holder = "held_by_store", None, None, (em.group("krate"), em.group("store_test"))
        entries.append(Entry(variant=em.group("var"), status=status, path=path, proof=proof, holder=holder, line=n))
    if header is None:
        raise Refused(f"registry: `census_rows!` at line {start_line} has no header")
    if not closed:
        raise Refused(f"registry: enum body of {header[0]} (line {header[2]}) is not closed")
    if not entries:
        raise Refused(f"registry {header[0]} empty (line {header[2]}) — subject missing")
    return Registry(name=header[0], flag=header[1], line=header[2], entries=tuple(entries))


def parse_registry(text: str) -> dict[str, Registry]:
    """The registry per census flag, exactly one each."""
    stripped = strip_comments(text, rust=True)
    found = [_parse_one(start, body) for start, body in _invocation_bodies(stripped)]
    if not found:
        raise Refused("registry: no `census_rows!` invocation — subject missing")
    by_flag: dict[str, list[Registry]] = {}
    for reg in found:
        by_flag.setdefault(reg.flag, []).append(reg)
    for flag in FLAG_OF.values():
        regs = by_flag.get(flag, [])
        if not regs:
            raise Refused(f"registry: no registry for flag {flag} — subject missing")
        if len(regs) > 1:
            raise Refused(
                f"registry: {len(regs)} registries for flag {flag} "
                f"({', '.join(r.name for r in regs)}); exactly one is allowed"
            )
    return {flag: regs[0] for flag, regs in by_flag.items()}


# --------------------------------------------------------------------------
# manifest side (G1, direct)
# --------------------------------------------------------------------------


def _dependency_names(table: dict, path: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    """(dependency package name, `[table.path]`) for every dependency table,
    at any depth (`[target.'cfg(unix)'.dependencies]` included). A renamed
    dependency (`x = { package = "redb" }`) reports the package, not the key.
    """
    out: list[tuple[str, str]] = []
    for key, value in table.items():
        here = path + (key,)
        if key in DEP_TABLES and isinstance(value, dict):
            for dep, spec in value.items():
                pkg = spec.get("package", dep) if isinstance(spec, dict) else dep
                out.append((str(pkg), ".".join(here)))
        elif isinstance(value, dict):
            out.extend(_dependency_names(value, here))
    return out


def check_manifest(text: str, errors: list[str]) -> None:
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise Refused(f"Cargo.toml unparseable: {e}") from e
    for pkg, table in _dependency_names(manifest):
        if pkg in BANNED_PACKAGES:
            errors.append(f"store handle in Cargo.toml: `{pkg}` under [{table}] (G1)")


# --------------------------------------------------------------------------
# the check
# --------------------------------------------------------------------------


def _enforced(rows: list[Row], flag: str) -> list[Row]:
    return [r for r in rows if r.flag == flag and r.bucket != 3]


def figures(rows: list[Row], reg: Registry) -> Figures:
    enforced = _enforced(rows, reg.flag)
    subsystem_of = {r.id: r.subsystem for r in enforced}
    implemented = [e for e in reg.entries if e.implemented and e.id in subsystem_of]
    at_open = [e for e in implemented if e.at_open]
    by_construction = [e for e in implemented if e.by_construction]
    held_by_store = [e for e in implemented if e.held_by_store]
    by_sub: dict[str, list[int]] = {}
    for r in enforced:
        by_sub.setdefault(r.subsystem, [0, 0])[1] += 1
    for e in implemented:
        by_sub[subsystem_of[e.id]][0] += 1
    return Figures(
        flag=reg.flag,
        registry=reg.name,
        implemented=len(implemented),
        at_open=len(at_open),
        by_construction=len(by_construction),
        held_by_store=len(held_by_store),
        enforced=len(enforced),
        ratified=sum(1 for r in enforced if r.bucket in RATIFIED_BUCKETS),
        by_subsystem={k: (v[0], v[1]) for k, v in by_sub.items()},
        implemented_ids=tuple(e.id for e in implemented),
        at_open_rows=tuple((e.id, e.path or "", e.proof or "") for e in at_open),
        by_construction_rows=tuple((e.id, e.path or "", e.proof or "") for e in by_construction),
        held_by_store_rows=tuple((e.id, e.holder[0], e.holder[1]) for e in held_by_store if e.holder),
    )


def check_at_open(entries: list[Entry], crate_src: str | None, errors: list[str]) -> None:
    """Every `enforced_at` entry names a `#[test]` defined in this crate.

    The compiler pins the site (the macro emits the same `use path as _` and
    ROW assertion `implemented` gets); the test is the gate's to assert, as a
    `held_by_store` holder's is — a definition, not a mention (rule 47).
    """
    at_open = [e for e in entries if e.at_open and e.proof]
    if not at_open:
        return
    if crate_src is None:
        errors.append(
            "enforced_at entries present but the crate's sources could not be read — "
            "cannot show any proof test exists"
        )
        return
    src = strip_comments(crate_src, rust=True)
    for e in at_open:
        if not _test_def_re(e.proof or "").search(src):
            errors.append(
                f"enforced_at entry {e.id} (line {e.line}): proof test {e.proof!r} is not a "
                "`#[test] fn` defined in the crate — an at-open row names the test that proves "
                "its site refuses"
            )


# A `compile_fail` doctest attached to `fn <item>`: the contiguous `///` block
# immediately above the definition contains a ```` ```compile_fail ```` fence.
# Doc comments are NOT stripped for this check — the doctest *is* the comment.
def _compile_fail_doctest_on(src: str, item: str) -> bool:
    for m in re.finditer(rf"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?fn\s+{re.escape(item)}\b", src, re.M):
        # Walk back over the doc block above the definition.
        lines = src[: m.start()].splitlines()
        block: list[str] = []
        for line in reversed(lines):
            stripped = line.strip()
            if stripped.startswith("///") or stripped.startswith("#["):
                block.append(stripped)
            elif stripped == "":
                break
            else:
                break
        if any("```compile_fail" in line for line in block):
            return True
    return False


def check_by_construction(entries: list[Entry], crate_src: str | None, errors: list[str]) -> None:
    """Every `by_construction` entry names a falsifier defined in this crate.

    The compiler pins the property's home (`use path as _`); the falsifier is
    the gate's to assert (rule 47): a `#[test] fn <name>` that would fail if
    the property lapsed; or `doctest:<item>` — a `compile_fail` doctest on
    `fn <item>`; or `trybuild:<test>` — a `#[test] fn <test>` (under the
    crate's `tests/`, read with `src/`) whose body runs `compile_fail`
    programs against stderr snapshots. The last is the shape a type-system
    property is falsified by when its program carries a stub that can drift
    (CEN-F19: a verdict judged against one view cannot connect under
    another; its doctests were found green on E0046 from 2026-09-29 to
    2026-10-10, the stub view having fallen behind `ChainView` —
    CHAIN_RULES_CRATE.md §8.3). A row true by construction with no way to
    fail is a claim, not a row (CHAIN_RULES_SLICE_4.md Q4).
    """
    rows = [e for e in entries if e.by_construction and e.proof]
    if not rows:
        return
    if crate_src is None:
        errors.append(
            "by_construction entries present but the crate's sources could not be read — "
            "cannot show any falsifier exists"
        )
        return
    stripped_src = strip_comments(crate_src, rust=True)
    for e in rows:
        falsifier = e.proof or ""
        if falsifier.startswith("doctest:"):
            item = falsifier[len("doctest:"):]
            if not _compile_fail_doctest_on(crate_src, item):
                errors.append(
                    f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} names no "
                    f"`fn {item}` in the crate carrying a ```compile_fail doctest — a type-system "
                    "property is falsified by the program that must not compile"
                )
        elif falsifier.startswith("trybuild:"):
            test = falsifier[len("trybuild:"):]
            body = _test_body(stripped_src, test)
            if body is None:
                errors.append(
                    f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} is not a "
                    f"`#[test] fn {test}` defined in the crate (`src/` or `tests/`) — a trybuild "
                    "falsifier is the test that compares the program's stderr to its snapshot"
                )
            elif not re.search(r"\.compile_fail\s*\(", body):
                errors.append(
                    f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} is a "
                    f"`#[test] fn {test}` that runs no `compile_fail(…)` program — the property is "
                    "falsified by the program that must not compile, snapshot and all"
                )
        elif not _test_def_re(falsifier).search(stripped_src):
            errors.append(
                f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} is not a "
                "`#[test] fn` defined in the crate — a by-construction row names the test that "
                "would fail if the property lapsed"
            )
    # One falsifier credited to several rows counts once per row in the
    # figures, which is honest only if the test walks every row it serves
    # (slice 5 Q6). The shape that forces it: the test's body names each
    # served row as `CenRow::<id>` (the harness's `credited_to_this_falsifier`
    # takes the list). A shared falsifier that names only the first row
    # reads as compliant and is not; this refuses it.
    shared: dict[str, list[Entry]] = {}
    for e in rows:
        if not (e.proof or "").startswith(("doctest:", "trybuild:")):
            shared.setdefault(e.proof or "", []).append(e)
    for falsifier, served in shared.items():
        if len(served) < 2:
            continue
        body = _test_body(stripped_src, falsifier)
        if body is None:
            continue  # reported above
        for e in served:
            short = e.id.removeprefix("CEN-")
            if not re.search(rf"\bCenRow::{re.escape(short)}\b", body):
                errors.append(
                    f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} serves "
                    f"{len(served)} rows but its body does not name `CenRow::{short}` — a shared "
                    "falsifier walks every row it is credited to (slice 5 Q6), or it is one test "
                    f"counted {len(served)} times"
                )


def _test_body(stripped_src: str, name: str) -> str | None:
    """The brace-balanced body of `#[test] fn <name>`, or `None` if absent."""
    m = _test_def_re(name).search(stripped_src)
    if m is None:
        return None
    start = stripped_src.find("{", m.end())
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(stripped_src)):
        c = stripped_src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return stripped_src[start : i + 1]
    return None


def check_held_by_store(
    entries: list[Entry], crate_sources: Callable[[str], str | None], errors: list[str]
) -> None:
    """Every `held_by_store` entry names a holder crate and the `#[test]` in it.

    The holder is a Rust crate below the validator (DRS-D12 (i): the rules
    crate imports no store, so the dependency runs store → rules and the
    refusal is minted on the store's side). Nothing the compiler can pin
    from this crate, so the gate holds two things: the holder exists — a
    workspace crate other than this one — and the named test is DEFINED in it (`#[test] fn <name>(` in its `src/`
    or `tests/`), never merely mentioned (rule 47). A row this crate itself
    holds is not `held_by_store`: that is `enforced_at` or `by_construction`,
    and naming this crate here is refused.
    """
    for e in entries:
        if not e.held_by_store or e.holder is None:
            continue
        krate, test = e.holder
        if krate == THIS_CRATE:
            errors.append(
                f"held_by_store entry {e.id} (line {e.line}): holder crate {krate!r} is this "
                "crate — a row this crate holds is enforced_at or by_construction, not held_by_store"
            )
            continue
        src = crate_sources(krate)
        if src is None:
            errors.append(
                f"held_by_store entry {e.id} (line {e.line}): holder crate {krate!r} is not a "
                "workspace crate (`rust/<name>/src/`) — a store hold names the crate that refuses"
            )
            continue
        if not _test_def_re(test).search(strip_comments(src, rust=True)):
            errors.append(
                f"held_by_store entry {e.id} (line {e.line}): holder test {test!r} is not a "
                f"`#[test] fn` defined in {krate!r} — a store hold names the test that proves "
                "the holder refuses"
            )


def check(inputs: Inputs) -> tuple[list[str], dict[str, Figures]]:
    """Mismatches between registry and census (empty when they agree), and
    the per-flag figures. Raises `Refused` when a subject is missing."""
    rows = parse_census(inputs.census)
    if inputs.registry is None:
        raise Refused("registry file missing")
    if inputs.lib is None:
        raise Refused("crate root missing")
    if inputs.manifest is None:
        raise Refused("Cargo.toml missing")
    if not MOD_DECL_RE.search(strip_comments(inputs.lib, rust=True)):
        raise Refused(
            "registry not compiled by the crate: lib.rs has no `mod census;` — the "
            "file this gate reads would be one the compiler never sees"
        )
    registries = parse_registry(inputs.registry)
    errors: list[str] = []

    # No variant twice, across both registries: the two enums partition one
    # id space.
    all_entries = [e for reg in registries.values() for e in reg.entries]
    for rid, k in sorted(Counter(e.id for e in all_entries).items()):
        if k > 1:
            errors.append(f"duplicate entry {rid} ({k} occurrences across the registries)")

    for flag in sorted(registries):
        reg = registries[flag]
        enforced_ids = [r.id for r in _enforced(rows, flag)]
        enforced_set = set(enforced_ids)
        entry_ids = [e.id for e in reg.entries]
        entry_set = set(entry_ids)
        for e in reg.entries:
            if e.id not in enforced_set:
                errors.append(
                    f"entry {e.id} (line {e.line}) has no enforced census row with "
                    f"flag {flag} — bucket-3, mistyped, or filed under the wrong enum"
                )
        for rid in enforced_ids:
            if rid not in entry_set:
                errors.append(f"census row {rid} (flag {flag}) missing from registry {reg.name}")
        # Order, judged on the ids both sides have, so a missing row reports
        # once above rather than as a cascade of order faults.
        shared = enforced_set & entry_set
        census_order = [rid for rid in enforced_ids if rid in shared]
        registry_order = [rid for rid in entry_ids if rid in shared]
        for want, got in zip(census_order, registry_order):
            if want != got:
                errors.append(
                    f"registry {reg.name} order differs from census at {got}: "
                    f"census has {want} there"
                )
                break

    check_manifest(inputs.manifest, errors)
    check_at_open(all_entries, inputs.crate_src, errors)
    check_by_construction(all_entries, inputs.crate_src, errors)
    check_held_by_store(all_entries, inputs.crate_sources, errors)
    return errors, {flag: figures(rows, reg) for flag, reg in registries.items()}


def summary(figs: dict[str, Figures]) -> str:
    """The two-line figure (CHAIN_RULES_CRATE.md §6.3), consensus first.

    `at-open`, `by-construction` and `held-by-store` are printed beside a
    fixed `E` so each is visibly a subtraction from the per-block
    denominator, never a smaller `E`.
    """
    w = max(
        len(str(n))
        for f in figs.values()
        for n in (f.implemented, f.enforced, f.ratified, f.at_open, f.by_construction, f.held_by_store)
    )
    out = []
    for flag in sorted(figs, key=lambda f: list(FLAG_OF.values()).index(f)):
        f = figs[flag]
        out.append(
            f"{LABEL[flag] + ':':<11}"
            f"implemented {f.implemented:>{w}} / enforced {f.enforced:<{w}}   "
            f"at-open {f.at_open:>{w}}   by-construction {f.by_construction:>{w}}   "
            f"held-by-store {f.held_by_store:>{w}}   "
            f"ratified {f.ratified:>{w}} / enforced {f.enforced:<{w}}   "
            f"(E = {flag}-rows − bucket 3; "
            "per-block completeness over E − at-open − by-construction − held-by-store)"
        )
    return "\n".join(out)


def describe(figs: dict[str, Figures]) -> str:
    out = [summary(figs)]
    for flag in sorted(figs, key=lambda f: list(FLAG_OF.values()).index(f)):
        f = figs[flag]
        out.append(f"{LABEL[flag]} ({f.registry}), per census subsystem:")
        for sub, (impl, enf) in sorted(f.by_subsystem.items()):
            out.append(f"  {sub}: implemented {impl} / enforced {enf}")
        ids = ", ".join(f.implemented_ids) if f.implemented_ids else "(none)"
        out.append(f"  implemented: {ids}")
        if f.at_open_rows:
            out.append("  enforced at open (Rust-enforced, outside per-block coverage):")
            for rid, site, proof in f.at_open_rows:
                out.append(f"    {rid}: {site} :: {proof}")
        if f.by_construction_rows:
            out.append("  by construction (Rust-enforced by the type system / parser; falsifier named):")
            for rid, prop, falsifier in f.by_construction_rows:
                out.append(f"    {rid}: {prop} :: {falsifier}")
        if f.held_by_store_rows:
            out.append("  held by store (Rust-enforced below the validator; holder crate and test named):")
            for rid, krate, test in f.held_by_store_rows:
                out.append(f"    {rid}: {krate} :: {test}")
    return "\n".join(out)


# --------------------------------------------------------------------------
# self-test: every refusal must fire on the input built to trip it
# --------------------------------------------------------------------------

_CENSUS_OK = """\
# census

## 4. Rows

### 4.A Acceptance topology

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | parent exists | `blockchain.cpp:10` | C | 1 | x | y | z |
| CEN-A2 | height | `blockchain.cpp:20` | C | 4 | x | y | z |
| CEN-A3 | retired | `blockchain.cpp:30` | C | 3 | x | y | z |
| CEN-A4 | already known | `blockchain.cpp:6626` | C | 2 | x | y | z |

### 4.L Storage layer

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-L1 | key image unique | `src/blockchain_db/lmdb/db_lmdb.cpp:1432` | C | 2 | x | y | z |

### 4.M Mempool admission

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-M1 | fee floor | `tx_pool.cpp:5` | P | 1 | x | y | z |
| CEN-M2 | kept_by_block | `tx_pool.cpp:9` | C | 2 | x | y | z |
| CEN-M3 | relay policy | `tx_pool.cpp:12` | P | 3 | x | y | z |
"""
# enforced C: A1(b1) A2(b4) A4(b2) L1(b2) M2(b2) → 5, ratified 4; enforced P: M1 → 1, ratified 1.

_REGISTRY_OK = """\
//! The registry. `check_chain_rules_coverage.py` reads the two `census_rows!`
//! invocations below — this mention is a doc comment and must not count.

census_rows! {
    /// The consensus rows.
    pub enum CenRow: Consensus {
        // 4.A Acceptance topology
        A1 pending,
        A2 implemented(crate::topology::height),
        A4 pending,
        // 4.L Storage layer
        L1 pending,
        // 4.M — `// A9 pending,` in a comment is not an entry either
        M2 pending,
    }
}

census_rows! {
    /* block comment before the header */
    pub enum PolicyRow: Policy {
        M1 pending,
    }
}
"""

_LIB_OK = """\
//! crate root
#![deny(unsafe_code)]

mod census;

pub use census::{CenRow, PolicyRow};
"""

_MANIFEST_OK = """\
[package]
name = "shekyl-chain-rules"
# no `redb`, no `shekyl-chain-store` — this comment mentions both and must not trip G1

[dependencies]
shekyl-types = { path = "../shekyl-types" }

[lints]
workspace = true
"""


# The fake workspace a `held_by_store` entry is checked against: one crate
# below the validator, its sources concatenated as `load` concatenates them.
_STORE_OK = {
    "shekyl-chain-store": (
        "#[test]\nfn l1_held() {}\n"
        "// l1_held_not_this in a comment\n"
        "fn l1_mentioned_only() {}\n"
    ),
}


def _inputs(
    crates: dict[str, str] | None = None,
    **over: str | None,
) -> Inputs:
    base = dict(census=_CENSUS_OK, registry=_REGISTRY_OK, lib=_LIB_OK, manifest=_MANIFEST_OK)
    base.update(over)
    workspace = _STORE_OK if crates is None else crates
    return Inputs(crate_sources=workspace.get, **base)  # type: ignore[arg-type]


def _expect_ok(inputs: Inputs, name: str) -> dict[str, Figures]:
    errs, figs = check(inputs)
    if errs:
        raise SystemExit(f"selftest {name}: expected clean, got:\n  " + "\n  ".join(errs))
    return figs


_FIRED: list[str] = []


def _expect_refusal(inputs: Inputs, needle: str, name: str) -> None:
    try:
        errs, _figs = check(inputs)
    except Refused as e:
        errs = [str(e)]
    if not any(needle in e for e in errs):
        raise SystemExit(
            f"selftest {name}: expected a refusal mentioning {needle!r}, got:\n  "
            + ("\n  ".join(errs) if errs else "(clean)")
        )
    _FIRED.append(name)


def _reg(old: str, new: str) -> Inputs:
    assert old in _REGISTRY_OK, old
    return _inputs(registry=_REGISTRY_OK.replace(old, new))


def selftest() -> None:
    figs = _expect_ok(_inputs(), "consistent set")
    got = {f: (v.implemented, v.enforced, v.ratified) for f, v in figs.items()}
    want = {"C": (1, 5, 4), "P": (0, 1, 1)}
    if got != want:
        raise SystemExit(f"selftest figures: got {got}, want {want}")
    if figs["C"].per_block != 5:
        raise SystemExit(f"selftest per-block: got {figs['C'].per_block}, want 5")
    if figs["C"].by_subsystem != {"4.A": (1, 3), "4.L": (0, 1), "4.M": (0, 1)}:
        raise SystemExit(f"selftest per-subsystem: got {figs['C'].by_subsystem}")
    if figs["C"].implemented_ids != ("CEN-A2",):
        raise SystemExit(f"selftest implemented ids: got {figs['C'].implemented_ids}")
    text = summary(figs)
    if "consensus: implemented 1 / enforced 5   at-open 0   by-construction 0   held-by-store 0   ratified 4 / enforced 5" not in text:
        raise SystemExit(f"selftest summary shape:\n{text}")
    if "policy:    implemented 0 / enforced 1   at-open 0   by-construction 0   held-by-store 0   ratified 1 / enforced 1" not in text:
        raise SystemExit(f"selftest summary shape (policy):\n{text}")
    desc = describe(figs)
    if "4.A: implemented 1 / enforced 3" not in desc:
        raise SystemExit("selftest describe lacks the per-subsystem line")

    # a status the grammar does not name is an unparseable entry, not a
    # status the figures could miscount
    _expect_refusal(_reg("        A4 pending,\n", '        A4 held_by_cxx("tests/x.cpp", "t"),\n'), "unparseable entry at line 10", "held_by_cxx is not a status form")
    # enforced_at — the proof test is a definition in the crate, not a mention
    _SRC_OK = "#[test]\nfn e5_refuses() {}\n// e5_refuses_not_this in a comment\n"
    at_open_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 enforced_at(crate::anchors::E5, "e5_refuses"),\n')
    figs2 = _expect_ok(_inputs(registry=at_open_reg, crate_src=_SRC_OK), "an at-open row with its proof test")
    if (figs2["C"].implemented, figs2["C"].at_open, figs2["C"].enforced, figs2["C"].per_block) != (2, 1, 5, 4):
        raise SystemExit(f"selftest at-open figures: {figs2['C']}")
    if figs2["C"].at_open_rows != (("CEN-L1", "crate::anchors::E5", "e5_refuses"),):
        raise SystemExit(f"selftest at-open rows: {figs2['C'].at_open_rows}")
    if "CEN-L1: crate::anchors::E5 :: e5_refuses" not in describe(figs2):
        raise SystemExit("selftest describe lacks the at-open citation")
    if "implemented 2 / enforced 5   at-open 1   by-construction 0   held-by-store 0   ratified 4" not in summary(figs2):
        raise SystemExit(f"selftest at-open summary:\n{summary(figs2)}")
    _expect_refusal(_inputs(registry=at_open_reg, crate_src="fn e5_refuses() {}\n"), "proof test 'e5_refuses' is not a `#[test] fn` defined in the crate", "at-open proof fn without #[test]")
    _expect_refusal(_inputs(registry=at_open_reg, crate_src="#[test]\nfn other() { e5_refuses(); }\n"), "proof test 'e5_refuses' is not a `#[test] fn`", "at-open proof only called, not defined")
    _expect_refusal(_inputs(registry=at_open_reg, crate_src="// #[test] fn e5_refuses() {}\n"), "proof test 'e5_refuses' is not a `#[test] fn`", "at-open proof only in a comment")
    _expect_refusal(_inputs(registry=at_open_reg, crate_src="#[test]\nfn e5_refuses_more() {}\n"), "proof test 'e5_refuses' is not a `#[test] fn`", "at-open proof only as a prefix of a longer name")
    _expect_refusal(_inputs(registry=at_open_reg, crate_src=None), "crate's sources could not be read", "at-open row but no crate sources")
    _expect_ok(_inputs(registry=at_open_reg, crate_src="#[test]\n#[should_panic(expected = \"x\")]\nfn e5_refuses() {}\n"), "an attribute between #[test] and fn is allowed")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 enforced_at(crate::anchors::E5),\n"), "unparseable entry at line 12", "enforced_at without a proof test")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 enforced_at(crate::anchors::E5, e5_refuses),\n"), "unparseable entry at line 12", "enforced_at proof unquoted")

    # by_construction — a falsifier is a `#[test] fn` or a compile_fail doctest on a named item
    bc_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 by_construction(crate::view::ChainView, "l1_falsifier"),\n')
    figs3 = _expect_ok(_inputs(registry=bc_reg, crate_src="#[test]\nfn l1_falsifier() {}\n"), "a by-construction row with a #[test] falsifier")
    if (figs3["C"].implemented, figs3["C"].by_construction, figs3["C"].at_open, figs3["C"].enforced, figs3["C"].per_block) != (2, 1, 0, 5, 4):
        raise SystemExit(f"selftest by-construction figures: {figs3['C']}")
    if figs3["C"].by_construction_rows != (("CEN-L1", "crate::view::ChainView", "l1_falsifier"),):
        raise SystemExit(f"selftest by-construction rows: {figs3['C'].by_construction_rows}")
    if "CEN-L1: crate::view::ChainView :: l1_falsifier" not in describe(figs3):
        raise SystemExit("selftest describe lacks the by-construction citation")
    if "implemented 2 / enforced 5   at-open 0   by-construction 1   held-by-store 0   ratified 4" not in summary(figs3):
        raise SystemExit(f"selftest by-construction summary:\n{summary(figs3)}")
    _expect_refusal(_inputs(registry=bc_reg, crate_src="fn l1_falsifier() {}\n"), "falsifier 'l1_falsifier' is not a `#[test] fn`", "by-construction falsifier without #[test]")
    # a falsifier shared by two rows names both in its body (slice 5 Q6), or it is one test counted twice
    bc_shared_reg = bc_reg.replace("        M2 pending,\n", '        M2 by_construction(crate::view::ChainView, "l1_falsifier"),\n')
    _expect_ok(
        _inputs(registry=bc_shared_reg, crate_src="#[test]\nfn l1_falsifier() {\n    credited(&[CenRow::L1, CenRow::M2]);\n}\n"),
        "a shared falsifier naming both rows",
    )
    _expect_refusal(
        _inputs(registry=bc_shared_reg, crate_src="#[test]\nfn l1_falsifier() {\n    credited(&[CenRow::L1]);\n}\n"),
        "serves 2 rows but its body does not name `CenRow::M2`",
        "shared falsifier naming only the first row",
    )
    _expect_refusal(_inputs(registry=bc_reg, crate_src=None), "crate's sources could not be read", "by-construction row but no crate sources")
    bc_doc_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 by_construction(crate::view::ChainView, "doctest:validate"),\n')
    doc_src = "/// Judged against one view, cannot connect under another:\n///\n/// ```compile_fail\n/// let x: () = 1u8;\n/// ```\npub fn validate() {}\n"
    _expect_ok(_inputs(registry=bc_doc_reg, crate_src=doc_src), "a by-construction row with a compile_fail doctest falsifier")
    _expect_refusal(_inputs(registry=bc_doc_reg, crate_src="/// ```\n/// let x = 1;\n/// ```\npub fn validate() {}\n"), "names no `fn validate` in the crate carrying a ```compile_fail doctest", "doctest falsifier whose doctest is not compile_fail")
    _expect_refusal(_inputs(registry=bc_doc_reg, crate_src="/// ```compile_fail\n/// x\n/// ```\npub fn other() {}\n\npub fn validate() {}\n"), "names no `fn validate` in the crate carrying a ```compile_fail doctest", "doctest falsifier on a different item")
    # trybuild: — the `#[test]` that runs the compile_fail programs (CEN-F19 since 2026-10-10)
    bc_try_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 by_construction(crate::view::ChainView, "trybuild:brand_holds"),\n')
    try_src = "#[test]\nfn brand_holds() {\n    let t = trybuild::TestCases::new();\n    t.pass(\"tests/trybuild/ok.rs\");\n    t.compile_fail(\"tests/trybuild/escape.rs\");\n}\n"
    _expect_ok(_inputs(registry=bc_try_reg, crate_src=try_src), "a by-construction row with a trybuild falsifier")
    _expect_refusal(_inputs(registry=bc_try_reg, crate_src="fn brand_holds() {\n    t.compile_fail(\"x.rs\");\n}\n"), "is not a `#[test] fn brand_holds` defined in the crate", "trybuild falsifier without #[test]")
    _expect_refusal(_inputs(registry=bc_try_reg, crate_src="#[test]\nfn brand_holds() {\n    let t = trybuild::TestCases::new();\n    t.pass(\"tests/trybuild/ok.rs\");\n}\n"), "runs no `compile_fail(…)` program", "trybuild falsifier that only passes")
    _expect_refusal(_inputs(registry=bc_try_reg, crate_src="#[test]\nfn brand_holds() {\n    // t.compile_fail(\"x.rs\");\n}\n"), "runs no `compile_fail(…)` program", "trybuild compile_fail only in a comment")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 by_construction(crate::view::ChainView),\n"), "unparseable entry at line 12", "by_construction without a falsifier")
    _expect_refusal(_reg("        L1 pending,\n", '        L1 enforced_at("crate::anchors::E5", "e5_refuses"),\n'), "unparseable entry at line 12", "enforced_at site quoted")

    # held_by_store — the holder is a workspace crate below the validator, and
    # the test is a definition in it (DRS_E5_POOL_ALT_PRUNE.md E5-18)
    hs_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 held_by_store("shekyl-chain-store", "l1_held"),\n')
    figs4 = _expect_ok(_inputs(registry=hs_reg), "a store-held row with its holder test")
    if (figs4["C"].implemented, figs4["C"].held_by_store, figs4["C"].at_open, figs4["C"].by_construction, figs4["C"].enforced, figs4["C"].per_block) != (2, 1, 0, 0, 5, 4):
        raise SystemExit(f"selftest held-by-store figures: {figs4['C']}")
    if figs4["C"].held_by_store_rows != (("CEN-L1", "shekyl-chain-store", "l1_held"),):
        raise SystemExit(f"selftest held-by-store rows: {figs4['C'].held_by_store_rows}")
    if "CEN-L1: shekyl-chain-store :: l1_held" not in describe(figs4):
        raise SystemExit("selftest describe lacks the held-by-store citation")
    if "implemented 2 / enforced 5   at-open 0   by-construction 0   held-by-store 1   ratified 4" not in summary(figs4):
        raise SystemExit(f"selftest held-by-store summary:\n{summary(figs4)}")
    _expect_refusal(_inputs(registry=hs_reg, crates={}), "holder crate 'shekyl-chain-store' is not a workspace crate", "store holder crate missing")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "fn l1_held() {}\n"}), "holder test 'l1_held' is not a `#[test] fn` defined in 'shekyl-chain-store'", "store holder fn without #[test]")
    _expect_ok(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "#[tokio::test]\nasync fn l1_held() {}\n"}), "a holder test that is an async tokio test")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "async fn l1_held() {}\n"}), "holder test 'l1_held' is not a `#[test] fn`", "store holder async fn without a test attribute")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "#[tokio::main]\nasync fn l1_held() {}\n"}), "holder test 'l1_held' is not a `#[test] fn`", "store holder under another tokio attribute")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "// #[test] fn l1_held() {}\n"}), "holder test 'l1_held' is not a `#[test] fn`", "store holder test only in a comment")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "#[test]\nfn other() { l1_held(); }\n"}), "holder test 'l1_held' is not a `#[test] fn`", "store holder test only called, not defined")
    _expect_refusal(_inputs(registry=hs_reg, crates={"shekyl-chain-store": "#[test]\nfn l1_held_more() {}\n"}), "holder test 'l1_held' is not a `#[test] fn`", "store holder test only as a prefix of a longer name")
    _expect_refusal(_inputs(registry=hs_reg.replace('"shekyl-chain-store"', '"shekyl-chain-rules"'), crates={"shekyl-chain-rules": "#[test]\nfn l1_held() {}\n"}), "holder crate 'shekyl-chain-rules' is this crate", "store holder is the rules crate itself")
    _expect_refusal(_reg("        L1 pending,\n", '        L1 held_by_store("shekyl-chain-store"),\n'), "unparseable entry at line 12", "held_by_store without a test")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 held_by_store(shekyl-chain-store, l1_held),\n"), "unparseable entry at line 12", "held_by_store without quotes")
    _expect_refusal(_reg("        L1 pending,\n", '        L1 held_by_store("rust/shekyl-chain-store", "l1_held"),\n'), "unparseable entry at line 12", "held_by_store holder is a path, not a crate name")
    _expect_refusal(_reg("        L1 pending,\n", '        L1 held_by_store("../shekyl-chain-store", "l1_held"),\n'), "unparseable entry at line 12", "held_by_store holder escapes the workspace")
    # a store-held row is still a registered row: the bijection sees it
    _expect_refusal(_inputs(registry=hs_reg.replace('        L1 held_by_store("shekyl-chain-store", "l1_held"),\n', "")), "census row CEN-L1 (flag C) missing from registry CenRow", "store-held row removed from the registry")
    # the production reader: a crate name is a directory under `rust/` with
    # a `src/`; what it reads is `src/` and `tests/`, as `load` reads this crate
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "rust" / "a-crate" / "src").mkdir(parents=True)
        (repo / "rust" / "a-crate" / "tests").mkdir()
        (repo / "rust" / "a-crate" / "src" / "lib.rs").write_text("#[test]\nfn in_src() {}\n", encoding="utf-8")
        (repo / "rust" / "a-crate" / "tests" / "it.rs").write_text("#[test]\nfn in_tests() {}\n", encoding="utf-8")
        (repo / "rust" / "no-src").mkdir()
        reader = crate_reader(repo)
        text = reader("a-crate")
        if text is None or "fn in_src" not in text or "fn in_tests" not in text:
            raise SystemExit("selftest crate_reader: a crate's src/ and tests/ must both read")
        if reader("no-src") is not None:
            raise SystemExit("selftest crate_reader: a directory without src/ is not a crate")
        if reader("absent") is not None:
            raise SystemExit("selftest crate_reader: a missing crate is None")
        _FIRED.append("crate_reader refusals (no src/, missing)")

    # bijection
    _expect_refusal(_reg("        L1 pending,\n", ""), "census row CEN-L1 (flag C) missing from registry CenRow", "row missing")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        A3 pending,\n"), "entry CEN-A3 (line 15) has no enforced census row with flag C", "bucket-3 row registered")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        A9 pending,\n"), "entry CEN-A9", "mistyped entry")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        M1 pending,\n"), "entry CEN-M1 (line 15) has no enforced census row with flag C", "policy row under the consensus enum")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        M1 pending,\n"), "duplicate entry CEN-M1", "same id in both registries")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 pending,\n        L1 pending,\n"), "duplicate entry CEN-L1", "same id twice in one registry")
    _expect_refusal(_reg("        A1 pending,\n        A2 implemented(crate::topology::height),\n", "        A2 implemented(crate::topology::height),\n        A1 pending,\n"), "registry CenRow order differs from census at CEN-A2: census has CEN-A1 there", "order")
    # a missing row does not also cascade into an order fault
    errs, _ = check(_reg("        A1 pending,\n", ""))
    if len(errs) != 1:
        raise SystemExit(f"selftest missing-row cascade: expected 1 error, got {errs}")

    # census moves under a fixed registry
    _expect_refusal(_inputs(census=_CENSUS_OK.replace("| CEN-M2 | kept_by_block | `tx_pool.cpp:9` | C | 2 |", "| CEN-M2 | kept_by_block | `tx_pool.cpp:9` | C | 3 |")), "entry CEN-M2", "row retires to bucket 3")
    _expect_refusal(_inputs(census=_CENSUS_OK.replace("| CEN-M2 | kept_by_block | `tx_pool.cpp:9` | C | 2 |", "| CEN-M2 | kept_by_block | `tx_pool.cpp:9` | P | 2 |")), "census row CEN-M2 (flag P) missing from registry PolicyRow", "row re-flagged")
    # Appended inside the 4.A table: a blank line ends a GFM table, so a row
    # placed after one would be read as a headerless new table, not a new row.
    _expect_refusal(_inputs(census=_CENSUS_OK.replace("| CEN-A3 | retired | `blockchain.cpp:30` | C | 3 | x | y | z |\n", "| CEN-A3 | retired | `blockchain.cpp:30` | C | 3 | x | y | z |\n| CEN-A5 | new | `blockchain.cpp:40` | C | 1 | x | y | z |\n")), "census row CEN-A5 (flag C) missing", "new row minted")

    # grammar
    _expect_refusal(_reg("pub enum CenRow: Consensus {", "pub enum CenRow Consensus {"), "unparseable header at line 6", "header")
    _expect_refusal(_reg("pub enum CenRow: Consensus {", "pub enum CenRow: Relay {"), "unknown flag `Relay`", "flag vocabulary")
    _expect_refusal(_reg("        A1 pending,\n", "        A1 pendng,\n"), "unparseable entry at line 8", "entry grammar")
    _expect_refusal(_reg("A2 implemented(crate::topology::height),", "A2 implemented,"), "unparseable entry at line 9", "implemented without a path")
    _expect_refusal(_reg("A2 implemented(crate::topology::height),", "A2 implemented(),"), "unparseable entry at line 9", "implemented with an empty path")
    _expect_refusal(_reg("        A1 pending,\n", "        #[cfg(test)]\n        A1 pending,\n"), "attribute on entry at line 8", "cfg on an entry")
    _expect_refusal(_reg("        M1 pending,\n", ""), "registry PolicyRow empty", "empty registry")
    _expect_refusal(_reg("        M1 pending,\n    }\n", "        M1 pending,\n    }\n    stray\n"), "text after the enum body", "trailing text")
    _expect_refusal(_reg("        M1 pending,\n    }\n", "        M1 pending,\n"), "has no closing brace", "unclosed invocation")

    # subjects missing
    _expect_refusal(_inputs(registry=None), "registry file missing", "no registry file")
    _expect_refusal(_inputs(lib=None), "crate root missing", "no lib.rs")
    _expect_refusal(_inputs(manifest=None), "Cargo.toml missing", "no manifest")
    _expect_refusal(_inputs(lib=_LIB_OK.replace("mod census;", "mod registry;")), "registry not compiled by the crate", "mod decl absent")
    _expect_refusal(_inputs(lib=_LIB_OK.replace("mod census;", "// mod census;")), "registry not compiled by the crate", "mod decl commented out")
    _expect_refusal(_inputs(registry="//! nothing here\n"), "no `census_rows!` invocation", "no invocation")
    _expect_ok(_reg("    /* block comment before the header */\n", "    /* block comment before the header */\n    #[allow(dead_code)]\n"), "an attribute on the enum itself is allowed")
    _expect_refusal(_reg("pub enum PolicyRow: Policy {", "pub enum PolicyRow: Consensus {"), "2 registries for flag C", "two registries one flag")
    _expect_refusal(_inputs(registry=_REGISTRY_OK[: _REGISTRY_OK.index("census_rows! {\n    /* block")]), "no registry for flag P", "flag without a registry")
    _expect_refusal(_inputs(census="# census\n\n## 4. Rows\n\n### 4.A x\n\ntext\n\n## 5. y\n"), "no §4 rows tables", "empty census (inherited refusal)")

    # G1, direct
    _expect_refusal(_inputs(manifest=_MANIFEST_OK + '\n[dev-dependencies]\nredb = "4"\n'), "store handle in Cargo.toml: `redb` under [dev-dependencies]", "redb as a dev-dependency")
    _expect_refusal(_inputs(manifest=_MANIFEST_OK.replace('shekyl-types = { path = "../shekyl-types" }', 'shekyl-types = { path = "../shekyl-types" }\nshekyl-chain-store = { path = "../shekyl-chain-store" }')), "`shekyl-chain-store` under [dependencies]", "store crate as a dependency")
    _expect_refusal(_inputs(manifest=_MANIFEST_OK + "\n[target.'cfg(unix)'.dependencies]\nstore = { package = \"redb\", version = \"4\" }\n"), "`redb` under [target.cfg(unix).dependencies]", "renamed redb under a target table")
    _expect_refusal(_inputs(manifest=_MANIFEST_OK + '\n[build-dependencies]\nredb = "4"\n'), "`redb` under [build-dependencies]", "redb as a build-dependency")
    _expect_refusal(_inputs(manifest="[package\nname = x"), "Cargo.toml unparseable", "manifest not TOML")
    _expect_ok(_inputs(manifest=_MANIFEST_OK + '\n[dev-dependencies]\npostcard = "1"\n'), "an unbanned dev-dependency is fine")

    print(f"check_chain_rules_coverage selftest: {len(_FIRED)} refusals fire, consistent sets pass")


def load(census: Path, registry: Path, lib: Path, manifest: Path) -> Inputs:
    """Read the four inputs; a missing file is a missing subject, named."""
    for label, p in (
        ("census missing", census),
        ("registry file missing", registry),
        ("crate root missing", lib),
        ("Cargo.toml missing", manifest),
    ):
        if not p.is_file():
            raise Refused(f"{label}: {p}")
    read = lambda p: p.read_text(encoding="utf-8")  # noqa: E731
    return Inputs(
        census=read(census),
        registry=read(registry),
        lib=read(lib),
        manifest=read(manifest),
        crate_src=_crate_sources(lib.parent.parent),
        crate_sources=crate_reader(REPO),
    )


def _crate_sources(crate_dir: Path) -> str | None:
    """A crate's Rust sources concatenated — `src/` and its integration
    tests under `tests/` (a `trybuild:` falsifier lives there, where cargo
    compiles it as its own target). `None` when there is no `src/`."""
    src_dir = crate_dir / "src"
    if not src_dir.is_dir():
        return None
    tests_dir = crate_dir / "tests"
    return "\n".join(
        f.read_text(encoding="utf-8")
        for d in (src_dir, tests_dir)
        if d.is_dir()
        for f in sorted(d.rglob("*.rs"))
    )


def crate_reader(repo: Path) -> Callable[[str], str | None]:
    """The production `crate_sources` reader: a workspace crate name → its
    sources (`rust/<name>/src/` and `tests/`), or `None` when `rust/<name>/`
    is not a crate. The name's grammar is the registry's (`_CRATE_NAME`:
    no separator, no `..`), so the lookup cannot leave `rust/`.
    """

    def sources(name: str) -> str | None:
        if not re.fullmatch(_CRATE_NAME, name):
            return None
        return _crate_sources(repo / "rust" / name)

    return sources


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--census", type=Path, default=DEFAULT_CENSUS)
    ap.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    ap.add_argument("--lib", type=Path, default=DEFAULT_LIB)
    ap.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    ap.add_argument(
        "--describe",
        action="store_true",
        help="print the figures and the per-subsystem derivation (still exits 1 on a mismatch)",
    )
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    try:
        errors, figs = check(load(args.census, args.registry, args.lib, args.manifest))
    except Refused as e:
        print(f"check_chain_rules_coverage: {e}", file=sys.stderr)
        return 2
    if args.describe:
        print(describe(figs))
        if errors:
            print(
                f"\ncheck_chain_rules_coverage: {len(errors)} refusal(s) "
                "(--describe does not green a mismatch):",
                file=sys.stderr,
            )
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        return 0
    if errors:
        print(
            f"check_chain_rules_coverage: {len(errors)} refusal(s) — registry against "
            f"{args.census.name}, manifest against G1:",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print("\nfigures as derived:\n" + summary(figs), file=sys.stderr)
        return 1
    print(summary(figs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
