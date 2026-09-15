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
# §4, in census order, each marked `pending` or `implemented(path)`. The
# registry is the crate's claim about which rules exist; the census is the
# denominator that claim is measured against. Nothing else compares them, so
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
#               `Var pending,` or `Var implemented(rust::path),`, no attribute
#               on an entry (a `#[cfg]` the gate cannot evaluate would let the
#               compiled enum and the counted enum differ);
#   G1 direct — the crate's Cargo.toml names neither `redb` nor
#               `shekyl-chain-store` in any dependency table (the transitive
#               half is `check_chain_rules_no_store.sh`, which needs cargo).
#
# The two flags are reported on two lines and never summed: a policy row
# counted toward consensus coverage is the proximity promotion the sibling
# enums exist to make unrepresentable. `implemented` is the registry's word;
# the compiler pins it (the macro emits `use path as _;`), so this gate does
# not run cargo and does not need to.
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
# One entry: `Var pending,` or `Var implemented(a::b::c),`. The variant is
# the census id without `CEN-` (`D1b`, `K1a`); the path is a plain Rust path.
ENTRY_RE = re.compile(
    r"^([A-Z]+\d+[a-z]?)\s+"
    r"(?:(pending)|(implemented)\(\s*([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*\))"
    r"\s*,$"
)
MOD_DECL_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+census\s*;\s*$", re.M)
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


@dataclass(frozen=True)
class Entry:
    variant: str  # "A1"
    implemented: bool
    path: str | None
    line: int  # 1-based, in the registry file

    @property
    def id(self) -> str:
        return f"CEN-{self.variant}"


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


@dataclass(frozen=True)
class Figures:
    flag: str
    registry: str
    implemented: int
    enforced: int
    ratified: int
    by_subsystem: dict[str, tuple[int, int]]  # subsystem -> (implemented, enforced)
    implemented_ids: tuple[str, ...]


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
        entries.append(
            Entry(
                variant=em.group(1),
                implemented=em.group(3) is not None,
                path=em.group(4),
                line=n,
            )
        )
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
    by_sub: dict[str, list[int]] = {}
    for r in enforced:
        by_sub.setdefault(r.subsystem, [0, 0])[1] += 1
    for e in implemented:
        by_sub[subsystem_of[e.id]][0] += 1
    return Figures(
        flag=reg.flag,
        registry=reg.name,
        implemented=len(implemented),
        enforced=len(enforced),
        ratified=sum(1 for r in enforced if r.bucket in RATIFIED_BUCKETS),
        by_subsystem={k: (v[0], v[1]) for k, v in by_sub.items()},
        implemented_ids=tuple(e.id for e in implemented),
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
    return errors, {flag: figures(rows, reg) for flag, reg in registries.items()}


def summary(figs: dict[str, Figures]) -> str:
    """The two-line figure (CHAIN_RULES_CRATE.md §6.3), consensus first."""
    w = max(len(str(n)) for f in figs.values() for n in (f.implemented, f.enforced, f.ratified))
    out = []
    for flag in sorted(figs, key=lambda f: list(FLAG_OF.values()).index(f)):
        f = figs[flag]
        out.append(
            f"{LABEL[flag] + ':':<11}"
            f"implemented {f.implemented:>{w}} / enforced {f.enforced:<{w}}   "
            f"ratified {f.ratified:>{w}} / enforced {f.enforced:<{w}}   "
            f"(E = {flag}-rows − bucket 3)"
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
# enforced C: A1(b1) A2(b4) L1(b2) M2(b2) → 4, ratified 3; enforced P: M1 → 1, ratified 1.

_REGISTRY_OK = """\
//! The registry. `check_chain_rules_coverage.py` reads the two `census_rows!`
//! invocations below — this mention is a doc comment and must not count.

census_rows! {
    /// The consensus rows.
    pub enum CenRow: Consensus {
        // 4.A Acceptance topology
        A1 pending,
        A2 implemented(crate::topology::height),
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


def _inputs(**over: str | None) -> Inputs:
    base = dict(census=_CENSUS_OK, registry=_REGISTRY_OK, lib=_LIB_OK, manifest=_MANIFEST_OK)
    base.update(over)
    return Inputs(**base)  # type: ignore[arg-type]


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
    want = {"C": (1, 4, 3), "P": (0, 1, 1)}
    if got != want:
        raise SystemExit(f"selftest figures: got {got}, want {want}")
    if figs["C"].by_subsystem != {"4.A": (1, 2), "4.L": (0, 1), "4.M": (0, 1)}:
        raise SystemExit(f"selftest per-subsystem: got {figs['C'].by_subsystem}")
    if figs["C"].implemented_ids != ("CEN-A2",):
        raise SystemExit(f"selftest implemented ids: got {figs['C'].implemented_ids}")
    text = summary(figs)
    if "consensus: implemented 1 / enforced 4   ratified 3 / enforced 4" not in text:
        raise SystemExit(f"selftest summary shape:\n{text}")
    if "policy:    implemented 0 / enforced 1   ratified 1 / enforced 1" not in text:
        raise SystemExit(f"selftest summary shape (policy):\n{text}")
    if "4.A: implemented 1 / enforced 2" not in describe(figs):
        raise SystemExit("selftest describe lacks the per-subsystem line")

    # bijection
    _expect_refusal(_reg("        L1 pending,\n", ""), "census row CEN-L1 (flag C) missing from registry CenRow", "row missing")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        A3 pending,\n"), "entry CEN-A3 (line 14) has no enforced census row with flag C", "bucket-3 row registered")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        A9 pending,\n"), "entry CEN-A9", "mistyped entry")
    _expect_refusal(_reg("        M2 pending,\n", "        M2 pending,\n        M1 pending,\n"), "entry CEN-M1 (line 14) has no enforced census row with flag C", "policy row under the consensus enum")
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
    _expect_refusal(_inputs(census=_CENSUS_OK.replace("| CEN-A3 | retired | `blockchain.cpp:30` | C | 3 | x | y | z |\n", "| CEN-A3 | retired | `blockchain.cpp:30` | C | 3 | x | y | z |\n| CEN-A4 | new | `blockchain.cpp:40` | C | 1 | x | y | z |\n")), "census row CEN-A4 (flag C) missing", "new row minted")

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
    return Inputs(census=read(census), registry=read(registry), lib=read(lib), manifest=read(manifest))


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
