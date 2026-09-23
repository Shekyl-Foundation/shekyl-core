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
# `enforced_at(path, "test")` or `held_by_cxx("file", "test")`. The registry is
# the crate's claim about which rules exist, which rows this crate enforces at
# a site other than the per-block stages, and which rows the C++ ingest driver
# still holds; the census is
# the denominator that claim is measured against. Nothing else compares them, so
# this gate does, and it is the ONLY place the crate's "N of M" figure is
# computed (CHAIN_RULES_CRATE.md §6; CONSENSUS_C2_R8_STORE_PLACEMENT.md §9.4).
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
#               `Var held_by_cxx("tests/….cpp", "gen_test"),`, no attribute
#               on an entry (a `#[cfg]` the gate cannot evaluate would let the
#               compiled enum and the counted enum differ);
#   held      — a `held_by_cxx` row (CHAIN_RULES_SLICE_1.md §4.1, Q2) cites
#               the C++ TEST that proves the holder refuses, not a token: the
#               cited file must exist and contain the test name, and the
#               census row's own `site(s)` cell must cite a C++ file. The file
#               leaving the tree at cutover turns this red — a hold expires
#               with its holder, never silently (PWD-B10: holder-exists is
#               not holder-enforces);
#   at-open   — an `enforced_at` row (CHAIN_RULES_SLICE_3.md Q4) is enforced by
#               THIS crate but not per block (CEN-E5 runs once, by the writer,
#               at open), so no per-block coverage can contain it. The entry
#               names the Rust `#[test]` in the crate that proves the site
#               refuses; the gate asserts a `#[test] fn <name>(` exists in the
#               crate's sources (rule 47 — a name in a comment is not a test).
#               Counted as implemented (the enforcement is Rust's, unlike a
#               hold), printed separately, and excluded by `RuleSet::enforced`
#               from per-block completeness (the compiler's side of the same
#               fact);
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
# The held figure is a SUBTRACTION, not a third denominator: the line prints
# `implemented I / validator-enforced (E − H)   held-by-cxx H   at-open O   by-construction B   enforced E`
# with E fixed, so coverage cannot improve by moving rows out of scope. `I`
# includes the at-open and by-construction rows (Rust enforces them); `O`
# and `B` are printed so the per-block completeness denominator,
# `E − H − O − B`, can be read off the line.
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
# `Var enforced_at(a::b::c, "test_fn"),` or
# `Var held_by_cxx("path/in/repo.cpp", "test_name"),`. The variant is the
# census id without `CEN-` (`D1b`, `K1a`); a path is a plain Rust path; a test
# is an identifier; the holder is a repo-relative file.
_RUST_PATH = r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*"
ENTRY_RE = re.compile(
    r"^(?P<var>[A-Z]+\d+[a-z]?)\s+"
    r"(?:(?P<pending>pending)"
    rf"|(?P<implemented>implemented)\(\s*(?P<impl_path>{_RUST_PATH})\s*\)"
    rf'|(?P<enforced_at>enforced_at)\(\s*(?P<site>{_RUST_PATH})\s*,\s*"(?P<proof>[A-Za-z_]\w*)"\s*\)'
    rf'|(?P<by_construction>by_construction)\(\s*(?P<property>{_RUST_PATH})\s*,\s*"(?P<falsifier>(?:doctest:)?[A-Za-z_]\w*)"\s*\)'
    r'|(?P<held>held_by_cxx)\(\s*"(?P<file>[^"\s]+)"\s*,\s*"(?P<test>[A-Za-z_]\w*)"\s*\))'
    r"\s*,$"
)


# A `#[test]` function definition in the crate's sources, by name. Attributes
# between `#[test]` and `fn` (`#[should_panic]`, `#[ignore]`) are allowed;
# the name inside a comment, a string, or a call is not a definition.
def _test_def_re(name: str) -> re.Pattern[str]:
    return re.compile(rf"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+{re.escape(name)}\s*\(")
# The C++ source suffixes this tree uses (`.cc` — `src/fcmp/bulletproofs_plus.cc`
# is a census site; `.inl` — the protocol handler). One list, two consumers:
# the census `site(s)` check and the holder-path check below.
CXX_SUFFIXES = ("cc", "cpp", "cxx", "h", "hpp", "inl")
_CXX_SUFFIX = "|".join(CXX_SUFFIXES)
# A census `site(s)` cell that places the rule in C++: the only rows
# `held_by_cxx` may claim (the holder is the C++ ingest driver). Either the
# cell names a C++ source, or it is a bare line citation — the census's
# stated default (§4 preamble: "`blockchain.cpp` under `src/cryptonote_core/`
# unless another file is named"). A Rust site (`rust/….rs:N`) matches neither.
CXX_SITE_RE = re.compile(rf"\.(?:{_CXX_SUFFIX})\b|^\s*\d+")
# The holder a `held_by_cxx` entry cites: a repo-relative C++ file. A Rust or
# Markdown file that happens to contain the identifier is not a C++ holder,
# and an absolute path is not repo-relative — both are refused before the
# file is read, so the registry cannot become environment-specific.
CXX_HOLDER_RE = re.compile(rf"^(?!/)(?!\w:)(?!\.\.)[^\s]+\.(?:{_CXX_SUFFIX})$")
# `core_tests` generators run only if registered with `GENERATE_AND_PLAY(name)`
# in this one file; a generator that is defined but unregistered compiles,
# is never played, and would leave a hold green while CTest ran without it
# (PR #767 review). gtest cases (`tests/unit_tests/`) self-register through
# their `TEST(...)` macro, so the definition is the registration there.
CORE_TESTS_DIR = "tests/core_tests/"
CORE_TESTS_REGISTRY = "tests/core_tests/chaingen_main.cpp"

MOD_DECL_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+census\s*;\s*$", re.M)
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


@dataclass(frozen=True)
class Entry:
    variant: str  # "A1"
    status: str  # "pending" | "implemented" | "enforced_at" | "by_construction" | "held_by_cxx"
    path: str | None  # implemented / enforced_at: the rule type's Rust path; by_construction: the property's
    proof: str | None  # enforced_at: the `#[test]` that proves the site refuses; by_construction: the falsifier
    holder: tuple[str, str] | None  # held_by_cxx: (repo-relative file, test name)
    line: int  # 1-based, in the registry file

    @property
    def id(self) -> str:
        return f"CEN-{self.variant}"

    @property
    def implemented(self) -> bool:
        """Rust enforces the row — per block, at another site, or by construction."""
        return self.status in ("implemented", "enforced_at", "by_construction")

    @property
    def at_open(self) -> bool:
        return self.status == "enforced_at"

    @property
    def by_construction(self) -> bool:
        return self.status == "by_construction"

    @property
    def held(self) -> bool:
        return self.status == "held_by_cxx"


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
    # Text of a repo-relative C++ file a `held_by_cxx` entry cites, or None
    # when it does not exist. The repo reader in production; a dict in the
    # self-test, so a holder's disappearance is a case the test can build.
    cxx: Callable[[str], str | None] = lambda _path: None
    # The crate's Rust sources, concatenated, in which an `enforced_at` proof
    # test must be defined. `None` when the crate has no sources to read.
    crate_src: str | None = None


@dataclass(frozen=True)
class Figures:
    flag: str
    registry: str
    implemented: int  # rows Rust enforces: per block, plus the at-open rows
    held: int  # rows the C++ ingest driver holds until cutover
    at_open: int  # rows this crate enforces outside the per-block stages
    by_construction: int  # rows that hold by construction (type system / parser), with a falsifier
    enforced: int  # the census denominator; never moves for a hold, an at-open or a by-construction row
    ratified: int
    by_subsystem: dict[str, tuple[int, int, int]]  # subsystem -> (implemented, held, enforced)
    implemented_ids: tuple[str, ...]
    held_rows: tuple[tuple[str, str, str], ...]  # (id, file, test)
    at_open_rows: tuple[tuple[str, str, str], ...]  # (id, site, proof test)
    by_construction_rows: tuple[tuple[str, str, str], ...]  # (id, property, falsifier)

    @property
    def validator_enforced(self) -> int:
        return self.enforced - self.held

    @property
    def per_block(self) -> int:
        """What `Coverage::is_complete_for` measures against: `E − H − O − B`."""
        return self.validator_enforced - self.at_open - self.by_construction


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
            status, path, proof, holder = "held_by_cxx", None, None, (em.group("file"), em.group("test"))
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
    held = [e for e in reg.entries if e.held and e.id in subsystem_of]
    at_open = [e for e in implemented if e.at_open]
    by_construction = [e for e in implemented if e.by_construction]
    by_sub: dict[str, list[int]] = {}
    for r in enforced:
        by_sub.setdefault(r.subsystem, [0, 0, 0])[2] += 1
    for e in implemented:
        by_sub[subsystem_of[e.id]][0] += 1
    for e in held:
        by_sub[subsystem_of[e.id]][1] += 1
    return Figures(
        flag=reg.flag,
        registry=reg.name,
        implemented=len(implemented),
        held=len(held),
        at_open=len(at_open),
        by_construction=len(by_construction),
        enforced=len(enforced),
        ratified=sum(1 for r in enforced if r.bucket in RATIFIED_BUCKETS),
        by_subsystem={k: (v[0], v[1], v[2]) for k, v in by_sub.items()},
        implemented_ids=tuple(e.id for e in implemented),
        held_rows=tuple((e.id, e.holder[0], e.holder[1]) for e in held if e.holder),
        at_open_rows=tuple((e.id, e.path or "", e.proof or "") for e in at_open),
        by_construction_rows=tuple((e.id, e.path or "", e.proof or "") for e in by_construction),
    )


def check_at_open(entries: list[Entry], crate_src: str | None, errors: list[str]) -> None:
    """Every `enforced_at` entry names a `#[test]` defined in this crate.

    The compiler pins the site (the macro emits the same `use path as _` and
    ROW assertion `implemented` gets); the test is the gate's to assert, as a
    `held_by_cxx` holder's is — a definition, not a mention (rule 47).
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
    the gate's to assert (rule 47): either a `#[test] fn <name>` that would
    fail if the property lapsed, or `doctest:<item>` — a `compile_fail`
    doctest on `fn <item>`, the shape a type-system property is falsified
    by (CEN-F19: a verdict judged against one view cannot connect under
    another). A row true by construction with no way to fail is a claim,
    not a row (CHAIN_RULES_SLICE_4.md Q4).
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
        elif not _test_def_re(falsifier).search(stripped_src):
            errors.append(
                f"by_construction entry {e.id} (line {e.line}): falsifier {falsifier!r} is not a "
                "`#[test] fn` defined in the crate — a by-construction row names the test that "
                "would fail if the property lapsed"
            )


def check_held(entries: list[Entry], rows: list[Row], cxx: Callable[[str], str | None], errors: list[str]) -> None:
    """Every `held_by_cxx` entry names a holder that exists and refuses.

    Three refusals, each its own subject: the census places the row in C++
    (its `site(s)` cell cites a C++ file — a row the census puts elsewhere
    is not the ingest driver's to hold); the cited file exists (its absence
    is cutover, and the hold expires with it); the cited test is in it (a
    token that exists is not a test that refuses — PWD-B10 — so the entry
    names the test and the gate checks for that identifier, not the file).
    """
    sites = {r.id: r.sites for r in rows}
    for e in entries:
        if not e.held or e.holder is None:
            continue
        file, test = e.holder
        site = sites.get(e.id, "")
        if not CXX_SITE_RE.search(site):
            errors.append(
                f"held_by_cxx entry {e.id} (line {e.line}): the census places this row at "
                f"{site!r}, which cites no C++ source — only a C++-held row may be held_by_cxx"
            )
        if not CXX_HOLDER_RE.match(file):
            errors.append(
                f"held_by_cxx entry {e.id} (line {e.line}): holder {file!r} is not a "
                f"repo-relative C++ file (.{', .'.join(CXX_SUFFIXES)}; no absolute path, no `..`)"
            )
            continue
        text = cxx(file)
        if text is None:
            errors.append(
                f"held_by_cxx entry {e.id} (line {e.line}): holder file {file!r} is not in the "
                "tree — the hold has expired with its holder (cutover); re-classify the row"
            )
            continue
        if not re.search(rf"\b{re.escape(test)}\b", strip_comments(text)):
            errors.append(
                f"held_by_cxx entry {e.id} (line {e.line}): holder test {test!r} is not in "
                f"{file!r} — a hold names a test that proves the holder refuses"
            )
            continue
        if file.startswith(CORE_TESTS_DIR):
            registry = cxx(CORE_TESTS_REGISTRY)
            if registry is None:
                errors.append(
                    f"held_by_cxx entry {e.id} (line {e.line}): core_tests registry "
                    f"{CORE_TESTS_REGISTRY!r} is not in the tree — cannot show {test!r} is played"
                )
            elif not re.search(
                rf"GENERATE_AND_PLAY\(\s*{re.escape(test)}\s*\)", strip_comments(registry)
            ):
                errors.append(
                    f"held_by_cxx entry {e.id} (line {e.line}): holder test {test!r} is defined "
                    f"but not registered with GENERATE_AND_PLAY in {CORE_TESTS_REGISTRY!r} — "
                    "an unregistered generator is never played, and the hold would be vacuous"
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
    check_held(all_entries, rows, inputs.cxx, errors)
    check_at_open(all_entries, inputs.crate_src, errors)
    check_by_construction(all_entries, inputs.crate_src, errors)
    return errors, {flag: figures(rows, reg) for flag, reg in registries.items()}


def summary(figs: dict[str, Figures]) -> str:
    """The two-line figure (CHAIN_RULES_CRATE.md §6.3), consensus first.

    `validator-enforced` is `E − H`, printed beside a fixed `E` so a hold is
    visibly a subtraction, never a smaller denominator.
    """
    w = max(
        len(str(n))
        for f in figs.values()
        for n in (f.implemented, f.enforced, f.ratified, f.held, f.at_open, f.by_construction)
    )
    out = []
    for flag in sorted(figs, key=lambda f: list(FLAG_OF.values()).index(f)):
        f = figs[flag]
        out.append(
            f"{LABEL[flag] + ':':<11}"
            f"implemented {f.implemented:>{w}} / validator-enforced {f.validator_enforced:<{w}}   "
            f"held-by-cxx {f.held:>{w}}   at-open {f.at_open:>{w}}   by-construction {f.by_construction:>{w}}   "
            f"enforced {f.enforced:<{w}}   "
            f"ratified {f.ratified:>{w}} / enforced {f.enforced:<{w}}   "
            f"(E = {flag}-rows − bucket 3; validator-enforced = E − held; "
            "per-block completeness over E − held − at-open − by-construction)"
        )
    return "\n".join(out)


def describe(figs: dict[str, Figures]) -> str:
    out = [summary(figs)]
    for flag in sorted(figs, key=lambda f: list(FLAG_OF.values()).index(f)):
        f = figs[flag]
        out.append(f"{LABEL[flag]} ({f.registry}), per census subsystem:")
        for sub, (impl, held, enf) in sorted(f.by_subsystem.items()):
            held_note = f" (held-by-cxx {held})" if held else ""
            out.append(f"  {sub}: implemented {impl} / enforced {enf}{held_note}")
        ids = ", ".join(f.implemented_ids) if f.implemented_ids else "(none)"
        out.append(f"  implemented: {ids}")
        if f.held_rows:
            out.append("  held-by-cxx (expires with the holder at cutover):")
            for rid, file, test in f.held_rows:
                out.append(f"    {rid}: {file} :: {test}")
        if f.at_open_rows:
            out.append("  enforced at open (Rust-enforced, outside per-block coverage):")
            for rid, site, proof in f.at_open_rows:
                out.append(f"    {rid}: {site} :: {proof}")
        if f.by_construction_rows:
            out.append("  by construction (Rust-enforced by the type system / parser; falsifier named):")
            for rid, prop, falsifier in f.by_construction_rows:
                out.append(f"    {rid}: {prop} :: {falsifier}")
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
| CEN-A4 | already known | 6626 (bare line: the census default `blockchain.cpp`) | C | 2 | x | y | z |

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
# A4 is held_by_cxx in the OK registry → validator-enforced 4, held 1.

_REGISTRY_OK = """\
//! The registry. `check_chain_rules_coverage.py` reads the two `census_rows!`
//! invocations below — this mention is a doc comment and must not count.

census_rows! {
    /// The consensus rows.
    pub enum CenRow: Consensus {
        // 4.A Acceptance topology
        A1 pending,
        A2 implemented(crate::topology::height),
        A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),
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


# The fake C++ tree a `held_by_cxx` entry is checked against: one file, one
# test. `_cxx_missing_test` has the file without the test; the empty tree is
# cutover.
_CXX_REGISTRY_OK = "int main() {\n    GENERATE_AND_PLAY(gen_block_already_known);\n}\n"
_CXX_OK = {
    "tests/core_tests/block_validation.cpp": (
        "struct gen_block_already_known : public gen_block_accepted_base<2> {};\n"
        "// gen_block_already_known_is_not_this — a longer identifier must not match\n"
    ),
    CORE_TESTS_REGISTRY: _CXX_REGISTRY_OK,
}
_CXX_MISSING_TEST = {
    "tests/core_tests/block_validation.cpp": "struct gen_block_other {};\n",
    CORE_TESTS_REGISTRY: _CXX_REGISTRY_OK,
}
# Defined but never registered: the generator compiles and is never played.
_CXX_UNREGISTERED = {
    "tests/core_tests/block_validation.cpp": _CXX_OK["tests/core_tests/block_validation.cpp"],
    CORE_TESTS_REGISTRY: "int main() {\n    GENERATE_AND_PLAY(gen_block_other);\n    // GENERATE_AND_PLAY(gen_block_already_known); — commented out is not registered\n}\n",
}


def _inputs(cxx: dict[str, str] | None = None, **over: str | None) -> Inputs:
    base = dict(census=_CENSUS_OK, registry=_REGISTRY_OK, lib=_LIB_OK, manifest=_MANIFEST_OK)
    base.update(over)
    tree = _CXX_OK if cxx is None else cxx
    return Inputs(cxx=tree.get, **base)  # type: ignore[arg-type]


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


def _reg(old: str, new: str, cxx: dict[str, str] | None = None) -> Inputs:
    assert old in _REGISTRY_OK, old
    return _inputs(cxx=cxx, registry=_REGISTRY_OK.replace(old, new))


def selftest() -> None:
    figs = _expect_ok(_inputs(), "consistent set")
    got = {f: (v.implemented, v.held, v.enforced, v.ratified) for f, v in figs.items()}
    want = {"C": (1, 1, 5, 4), "P": (0, 0, 1, 1)}
    if got != want:
        raise SystemExit(f"selftest figures: got {got}, want {want}")
    if figs["C"].validator_enforced != 4:
        raise SystemExit(f"selftest validator-enforced: got {figs['C'].validator_enforced}, want 4")
    if figs["C"].by_subsystem != {"4.A": (1, 1, 3), "4.L": (0, 0, 1), "4.M": (0, 0, 1)}:
        raise SystemExit(f"selftest per-subsystem: got {figs['C'].by_subsystem}")
    if figs["C"].implemented_ids != ("CEN-A2",):
        raise SystemExit(f"selftest implemented ids: got {figs['C'].implemented_ids}")
    if figs["C"].held_rows != (("CEN-A4", "tests/core_tests/block_validation.cpp", "gen_block_already_known"),):
        raise SystemExit(f"selftest held rows: got {figs['C'].held_rows}")
    text = summary(figs)
    # E stays 5 on the line while validator-enforced reads 4: a subtraction, not a smaller denominator.
    if "consensus: implemented 1 / validator-enforced 4   held-by-cxx 1   at-open 0   by-construction 0   enforced 5   ratified 4 / enforced 5" not in text:
        raise SystemExit(f"selftest summary shape:\n{text}")
    if "policy:    implemented 0 / validator-enforced 1   held-by-cxx 0   at-open 0   by-construction 0   enforced 1   ratified 1 / enforced 1" not in text:
        raise SystemExit(f"selftest summary shape (policy):\n{text}")
    desc = describe(figs)
    if "4.A: implemented 1 / enforced 3 (held-by-cxx 1)" not in desc:
        raise SystemExit("selftest describe lacks the per-subsystem line with the held note")
    if "CEN-A4: tests/core_tests/block_validation.cpp :: gen_block_already_known" not in desc:
        raise SystemExit("selftest describe lacks the held-row citation")

    # held_by_cxx — the three refusals (CHAIN_RULES_SLICE_1.md §4.1) and the grammar
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', cxx={}), "holder file 'tests/core_tests/block_validation.cpp' is not in the tree — the hold has expired", "holder file gone (cutover)")
    _expect_refusal(_inputs(cxx=_CXX_MISSING_TEST), "holder test 'gen_block_already_known' is not in 'tests/core_tests/block_validation.cpp'", "holder test missing")
    _expect_refusal(_inputs(cxx={"tests/core_tests/block_validation.cpp": "gen_block_already_known_is_not_this\n", CORE_TESTS_REGISTRY: _CXX_REGISTRY_OK}), "holder test 'gen_block_already_known' is not in", "holder test only as a prefix of a longer identifier")
    _expect_refusal(_inputs(cxx=_CXX_UNREGISTERED), "is defined but not registered with GENERATE_AND_PLAY", "core_tests generator defined but unregistered (a commented-out registration is not one)")
    _expect_refusal(_inputs(cxx={"tests/core_tests/block_validation.cpp": "// TODO: gen_block_already_known\n", CORE_TESTS_REGISTRY: _CXX_REGISTRY_OK}), "holder test 'gen_block_already_known' is not in", "holder test named only in a comment")
    _expect_refusal(_inputs(cxx={"tests/core_tests/block_validation.cpp": _CXX_OK["tests/core_tests/block_validation.cpp"]}), "core_tests registry 'tests/core_tests/chaingen_main.cpp' is not in the tree", "core_tests registry file missing")
    _expect_ok(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("tests/unit_tests/ingest.cpp", "gen_block_already_known"),', cxx={"tests/unit_tests/ingest.cpp": "TEST(ingest, gen_block_already_known) {}\n"}), "a gtest case self-registers: the definition is the registration")
    _expect_refusal(_inputs(census=_CENSUS_OK.replace("| CEN-A4 | already known | 6626 (bare line: the census default `blockchain.cpp`) |", "| CEN-A4 | already known | `rust/shekyl-daemon/src/ingest.rs:40` |")), "cites no C++ source — only a C++-held row may be held_by_cxx", "held row whose census site is Rust")
    _expect_ok(_inputs(census=_CENSUS_OK.replace("| CEN-A4 | already known | 6626 (bare line: the census default `blockchain.cpp`) |", "| CEN-A4 | already known | `src/cryptonote_core/cryptonote_core.cpp:1450` |")), "an explicit C++ site is a C++ site")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("tests/core_tests/block_validation.cpp"),'), "unparseable entry at line 10", "held_by_cxx with a bare path and no test")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx(tests/core_tests/block_validation.cpp, gen_block_already_known),'), "unparseable entry at line 10", "held_by_cxx without quotes")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen-block"),'), "unparseable entry at line 10", "held_by_cxx test name is not an identifier")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("/abs/tests/core_tests/block_validation.cpp", "gen_block_already_known"),', cxx={"/abs/tests/core_tests/block_validation.cpp": "gen_block_already_known"}), "is not a repo-relative C++ file", "absolute holder path")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("../elsewhere/x.cpp", "gen_block_already_known"),', cxx={"../elsewhere/x.cpp": "gen_block_already_known"}), "is not a repo-relative C++ file", "holder path escapes the repo")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("rust/shekyl-chain-rules/src/lib.rs", "gen_block_already_known"),', cxx={"rust/shekyl-chain-rules/src/lib.rs": "gen_block_already_known"}), "is not a repo-relative C++ file", "holder is a Rust file that contains the identifier")
    _expect_refusal(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("docs/design/X.md", "gen_block_already_known"),', cxx={"docs/design/X.md": "gen_block_already_known"}), "is not a repo-relative C++ file", "holder is a Markdown file")
    _expect_ok(_reg('A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),', 'A4 held_by_cxx("tests/unit_tests/ingest.cc", "gen_block_already_known"),', cxx={"tests/unit_tests/ingest.cc": "TEST(ingest, gen_block_already_known) {}\n"}), "a .cc holder is a C++ holder")
    _expect_ok(_inputs(census=_CENSUS_OK.replace("| CEN-A4 | already known | 6626 (bare line: the census default `blockchain.cpp`) |", "| CEN-A4 | already known | `src/fcmp/bulletproofs_plus.cc:40` |")), "a .cc census site is a C++ site")
    # the production reader refuses what the grammar cannot see: an absolute
    # path pointing INSIDE the checkout, and a `..` that resolves inside it
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "tests").mkdir()
        (repo / "tests" / "a.cpp").write_text("struct gen_x {};\n", encoding="utf-8")
        reader = repo_reader(repo)
        if reader("tests/a.cpp") != "struct gen_x {};\n":
            raise SystemExit("selftest repo_reader: relative path inside the repo must read")
        if reader(str(repo / "tests" / "a.cpp")) is not None:
            raise SystemExit("selftest repo_reader: an absolute path must be refused even inside the checkout")
        if reader("tests/../tests/a.cpp") is not None:
            raise SystemExit("selftest repo_reader: a `..` component must be refused even when it resolves inside")
        if reader("tests/missing.cpp") is not None:
            raise SystemExit("selftest repo_reader: a missing file is None")
        if reader("tests") is not None:
            raise SystemExit("selftest repo_reader: a directory is None")
        _FIRED.append("repo_reader refusals (absolute, .., missing, directory)")
    # enforced_at — the proof test is a definition in the crate, not a mention
    _SRC_OK = "#[test]\nfn e5_refuses() {}\n// e5_refuses_not_this in a comment\n"
    at_open_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 enforced_at(crate::anchors::E5, "e5_refuses"),\n')
    figs2 = _expect_ok(_inputs(registry=at_open_reg, crate_src=_SRC_OK), "an at-open row with its proof test")
    if (figs2["C"].implemented, figs2["C"].at_open, figs2["C"].validator_enforced, figs2["C"].per_block) != (2, 1, 4, 3):
        raise SystemExit(f"selftest at-open figures: {figs2['C']}")
    if figs2["C"].at_open_rows != (("CEN-L1", "crate::anchors::E5", "e5_refuses"),):
        raise SystemExit(f"selftest at-open rows: {figs2['C'].at_open_rows}")
    if "CEN-L1: crate::anchors::E5 :: e5_refuses" not in describe(figs2):
        raise SystemExit("selftest describe lacks the at-open citation")
    if "held-by-cxx 1   at-open 1   by-construction 0   enforced 5" not in summary(figs2):
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
    if (figs3["C"].implemented, figs3["C"].by_construction, figs3["C"].at_open, figs3["C"].validator_enforced, figs3["C"].per_block) != (2, 1, 0, 4, 3):
        raise SystemExit(f"selftest by-construction figures: {figs3['C']}")
    if figs3["C"].by_construction_rows != (("CEN-L1", "crate::view::ChainView", "l1_falsifier"),):
        raise SystemExit(f"selftest by-construction rows: {figs3['C'].by_construction_rows}")
    if "CEN-L1: crate::view::ChainView :: l1_falsifier" not in describe(figs3):
        raise SystemExit("selftest describe lacks the by-construction citation")
    if "at-open 0   by-construction 1   enforced 5" not in summary(figs3):
        raise SystemExit(f"selftest by-construction summary:\n{summary(figs3)}")
    _expect_refusal(_inputs(registry=bc_reg, crate_src="fn l1_falsifier() {}\n"), "falsifier 'l1_falsifier' is not a `#[test] fn`", "by-construction falsifier without #[test]")
    _expect_refusal(_inputs(registry=bc_reg, crate_src=None), "crate's sources could not be read", "by-construction row but no crate sources")
    bc_doc_reg = _REGISTRY_OK.replace("        L1 pending,\n", '        L1 by_construction(crate::view::ChainView, "doctest:validate"),\n')
    doc_src = "/// Judged against one view, cannot connect under another:\n///\n/// ```compile_fail\n/// let x: () = 1u8;\n/// ```\npub fn validate() {}\n"
    _expect_ok(_inputs(registry=bc_doc_reg, crate_src=doc_src), "a by-construction row with a compile_fail doctest falsifier")
    _expect_refusal(_inputs(registry=bc_doc_reg, crate_src="/// ```\n/// let x = 1;\n/// ```\npub fn validate() {}\n"), "names no `fn validate` in the crate carrying a ```compile_fail doctest", "doctest falsifier whose doctest is not compile_fail")
    _expect_refusal(_inputs(registry=bc_doc_reg, crate_src="/// ```compile_fail\n/// x\n/// ```\npub fn other() {}\n\npub fn validate() {}\n"), "names no `fn validate` in the crate carrying a ```compile_fail doctest", "doctest falsifier on a different item")
    _expect_refusal(_reg("        L1 pending,\n", "        L1 by_construction(crate::view::ChainView),\n"), "unparseable entry at line 12", "by_construction without a falsifier")
    _expect_refusal(_reg("        L1 pending,\n", '        L1 enforced_at("crate::anchors::E5", "e5_refuses"),\n'), "unparseable entry at line 12", "enforced_at site quoted")

    # a held row is still a registered row: the bijection sees it
    _expect_refusal(_reg('        A4 held_by_cxx("tests/core_tests/block_validation.cpp", "gen_block_already_known"),\n', ""), "census row CEN-A4 (flag C) missing from registry CenRow", "held row removed from the registry")

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
    src_dir = lib.parent
    crate_src = "\n".join(read(f) for f in sorted(src_dir.rglob("*.rs"))) if src_dir.is_dir() else None
    return Inputs(
        census=read(census),
        registry=read(registry),
        lib=read(lib),
        manifest=read(manifest),
        cxx=repo_reader(REPO),
        crate_src=crate_src,
    )


def repo_reader(repo: Path) -> Callable[[str], str | None]:
    """The production `cxx` reader: a repo-relative path → the file's text,
    or `None` when it is absolute, escapes `repo`, or is not a regular file.
    A hold cites a file in this tree or it cites nothing — an absolute path
    that happens to point inside the checkout would make the registry
    environment-specific, so it is refused before resolution (PR #767 review).
    """

    def cxx(rel: str) -> str | None:
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            return None
        target = (repo / candidate).resolve()
        if repo.resolve() not in target.parents or not target.is_file():
            return None
        return target.read_text(encoding="utf-8")

    return cxx


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
