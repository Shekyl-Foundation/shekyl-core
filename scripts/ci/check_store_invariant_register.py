# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# C2-R8 Q6 / §11: the store-invariant register (STORE_INVARIANT_REGISTER.md
# §2) is a BIJECTION with the `StoreInvariant` enum in shekyl-chain-store,
# over the rows that claim to be built.
#
#   register `built` rows  \  enum variants  -> a row says "built" and nothing
#                                                in the crate carries it
#   enum variants  \  register `built` rows  -> an invariant exists in code
#                                                that no design ever named
#
# WHY A GATE AT BIRTH. C2-R8 moves CEN-L13/L14's guards out of the consensus
# census into this register. Left ungated, the register is the census-outside-
# DEFAULT_DOCS shape exactly: a table nothing reads, whose rows drift from the
# `insert`/`upsert` sites they claim to describe with no signal. The gate
# reads the same pair `check_redb_schema_bijection.py` reads for tables —
# a doc register and a Rust definition — and holds them to each other.
#
# WHY `built` AND NOT EVERY ROW. At birth every row is `ruled` and the enum
# does not exist (rule 23: no variant before its producer). Demanding a
# variant per `ruled` row would force staged symbols; demanding nothing would
# make the gate vacuous. The `Status` column is the arming switch: the PR that
# flips a row to `built` must add the variant in the same change, or this is
# red.
#
# Instance of 47-gate-subject-assertion.mdc: an empty register and a missing
# enum have an empty difference. Every parse asserts its own subject — the
# table has rows, the ids are dense, the vocabulary is closed, and if any row
# is `built` the enum MUST be found — before any set arithmetic runs.
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _gfm_table import fenced_lines, has_pipe, split_cells  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "docs/design/STORE_INVARIANT_REGISTER.md"
CRATE_SRC = ROOT / "rust/shekyl-chain-store/src"

ID_RE = re.compile(r"^SI-(\d+)$")
ANCHOR_RE = re.compile(r"^`?StoreInvariant::([A-Z][A-Za-z0-9]*)`?$")
ENUM_RE = re.compile(r"pub\s+enum\s+StoreInvariant\s*\{(.*?)\n\}", re.S)
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9]*)\s*(?:[,({]|$)", re.M)
STATUSES = ("ruled", "built", "retired")
COLUMNS = ("Id", "Invariant", "Table / surface", "Consensus twin", "Origin", "Status", "Anchor")


class GateError(Exception):
    pass


def strip_comments(src: str) -> str:
    """Drop `//` line comments so a variant named in a doc comment does not
    read as a definition. Block comments are not used in this crate; a `/*`
    is treated as text, which errs toward a false red, never a false green."""
    return "\n".join(line.split("//", 1)[0] for line in src.splitlines())


def parse_register(text: str) -> list[dict[str, str]]:
    lines = text.splitlines()
    fenced, open_fence = fenced_lines(lines)
    if open_fence:
        raise GateError("register: unterminated code fence")
    rows: list[dict[str, str]] = []
    header: list[str] | None = None
    for n, line in enumerate(lines):
        if n in fenced or not has_pipe(line):
            header = None if header is not None and not line.strip() else header
            continue
        cells = [c.strip() for c in split_cells(line)]
        if header is None:
            if cells[: len(COLUMNS)] == list(COLUMNS):
                header = cells
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue  # the delimiter row
        if len(cells) != len(COLUMNS):
            raise GateError(
                f"register line {n + 1}: {len(cells)} cells, header has {len(COLUMNS)}"
            )
        rows.append(dict(zip(COLUMNS, cells)))
    if not rows:
        raise GateError("register: no SI rows parsed (subject absent)")
    seen: set[int] = set()
    for row in rows:
        m = ID_RE.match(row["Id"])
        if not m:
            raise GateError(f"register: id {row['Id']!r} is not SI-<n>")
        k = int(m.group(1))
        if k in seen:
            raise GateError(f"register: duplicate id SI-{k}")
        seen.add(k)
        if row["Status"] not in STATUSES:
            raise GateError(f"register SI-{k}: status {row['Status']!r} not in {STATUSES}")
        anchor = row["Anchor"]
        if row["Status"] == "built":
            if not ANCHOR_RE.match(anchor):
                raise GateError(
                    f"register SI-{k}: built row needs an anchor `StoreInvariant::Name`, got {anchor!r}"
                )
        elif anchor:
            raise GateError(f"register SI-{k}: {row['Status']} row must not carry an anchor")
    expected = set(range(1, max(seen) + 1))
    if seen != expected:
        raise GateError(f"register: ids not dense, missing SI-{sorted(expected - seen)}")
    return rows


def parse_enum(src_dir: Path) -> list[str] | None:
    """Variants of `pub enum StoreInvariant`, or None when no definition exists.
    Two definitions are a red, not a merge."""
    found: list[list[str]] = []
    for path in sorted(src_dir.rglob("*.rs")):
        text = strip_comments(path.read_text(encoding="utf-8"))
        for m in ENUM_RE.finditer(text):
            found.append(VARIANT_RE.findall(m.group(1)))
    if not found:
        return None
    if len(found) > 1:
        raise GateError("crate: more than one `pub enum StoreInvariant` definition")
    variants = found[0]
    if not variants:
        raise GateError("crate: `pub enum StoreInvariant` parsed with zero variants")
    if len(set(variants)) != len(variants):
        raise GateError("crate: duplicate StoreInvariant variant names")
    return variants


def check(register_text: str, src_dir: Path) -> str:
    rows = parse_register(register_text)
    built = {
        ANCHOR_RE.match(r["Anchor"]).group(1): r["Id"] for r in rows if r["Status"] == "built"
    }
    if len(built) != sum(1 for r in rows if r["Status"] == "built"):
        raise GateError("register: two built rows share one anchor")
    variants = parse_enum(src_dir)
    if variants is None:
        if built:
            raise GateError(
                f"{len(built)} built row(s) but no `pub enum StoreInvariant` in the crate: "
                f"{sorted(built.values())}"
            )
        return (
            f"store-invariant register: {len(rows)} rows, all ruled/retired; "
            "no StoreInvariant enum yet (subject asserted on the register alone)"
        )
    missing_code = sorted(set(built) - set(variants))
    missing_row = sorted(set(variants) - set(built))
    if missing_code or missing_row:
        raise GateError(
            "register/enum bijection broken:\n"
            + "".join(f"  built row {built[v]} has no variant StoreInvariant::{v}\n" for v in missing_code)
            + "".join(f"  variant StoreInvariant::{v} has no built row\n" for v in missing_row)
        )
    return f"store-invariant register: {len(rows)} rows, {len(built)} built <-> {len(variants)} variants"


# --- selftest ----------------------------------------------------------------

HEADER = (
    "| Id | Invariant | Table / surface | Consensus twin | Origin | Status | Anchor |\n"
    "| --- | --- | --- | --- | --- | --- | --- |\n"
)


def _row(i: int, status: str, anchor: str = "") -> str:
    return f"| SI-{i} | inv {i} | t | — | o | {status} | {anchor} |\n"


def _crate(tmp: Path, body: str | None) -> Path:
    src = tmp / "src"
    src.mkdir(exist_ok=True)
    if body is not None:
        (src / "invariant.rs").write_text(body, encoding="utf-8")
    return src


def selftest() -> None:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        enum_ab = "/// doc mentions StoreInvariant::Ghost, not a def\npub enum StoreInvariant {\n    A,\n    B(u8),\n}\n"

        def expect_ok(name: str, reg: str, body: str | None) -> None:
            try:
                check(reg, _crate(tmp, body))
            except GateError as e:
                fails.append(f"{name}: expected pass, got {e}")
            finally:
                for p in (tmp / "src").glob("*.rs"):
                    p.unlink()

        def expect_red(name: str, reg: str, body: str | None, needle: str) -> None:
            try:
                check(reg, _crate(tmp, body))
                fails.append(f"{name}: expected red, passed")
            except GateError as e:
                if needle not in str(e):
                    fails.append(f"{name}: red for the wrong reason: {e}")
            finally:
                for p in (tmp / "src").glob("*.rs"):
                    p.unlink()

        expect_ok("birth: all ruled, no enum", HEADER + _row(1, "ruled") + _row(2, "ruled"), None)
        expect_ok(
            "bijection holds",
            HEADER + _row(1, "built", "`StoreInvariant::A`") + _row(2, "built", "StoreInvariant::B") + _row(3, "ruled"),
            enum_ab,
        )
        expect_red("empty register", HEADER, None, "no SI rows")
        expect_red("sparse ids", HEADER + _row(1, "ruled") + _row(3, "ruled"), None, "not dense")
        expect_red("duplicate id", HEADER + _row(1, "ruled") + _row(1, "ruled"), None, "duplicate id")
        expect_red("bad status", HEADER + _row(1, "landed"), None, "not in")
        expect_red("ruled with anchor", HEADER + _row(1, "ruled", "StoreInvariant::A"), None, "must not carry")
        expect_red("built without anchor", HEADER + _row(1, "built"), None, "needs an anchor")
        expect_red("built but no enum", HEADER + _row(1, "built", "StoreInvariant::A"), None, "no `pub enum StoreInvariant`")
        expect_red(
            "built row, variant missing",
            HEADER + _row(1, "built", "StoreInvariant::A") + _row(2, "built", "StoreInvariant::Zed"),
            enum_ab,
            "has no variant StoreInvariant::Zed",
        )
        expect_red(
            "variant, row missing",
            HEADER + _row(1, "built", "StoreInvariant::A"),
            enum_ab,
            "StoreInvariant::B has no built row",
        )
        expect_red("enum with zero variants", HEADER + _row(1, "ruled"), "pub enum StoreInvariant {\n}\n", "zero variants")
        expect_red(
            "two enums in one file",
            HEADER + _row(1, "ruled"),
            "pub enum StoreInvariant {\n    A,\n}\npub enum StoreInvariant {\n    B,\n}\n",
            "more than one",
        )
        expect_red("wrong column count", HEADER + "| SI-1 | inv | t | — | o | ruled |\n", None, "cells, header has")
    if fails:
        print("store-invariant register selftest FAILED:", file=sys.stderr)
        for f in fails:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print("store-invariant register selftest: 14 cases held")


def main() -> None:
    if "--selftest" in sys.argv:
        selftest()
        return
    if not REGISTER.is_file():
        print(f"FAIL: {REGISTER.relative_to(ROOT)} missing (subject absent)", file=sys.stderr)
        sys.exit(1)
    if not CRATE_SRC.is_dir():
        print(f"FAIL: {CRATE_SRC.relative_to(ROOT)} missing (subject absent)", file=sys.stderr)
        sys.exit(1)
    try:
        print(check(REGISTER.read_text(encoding="utf-8"), CRATE_SRC))
    except GateError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
