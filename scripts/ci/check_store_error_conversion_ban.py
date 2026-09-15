# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# C2-R8 Q2 §3.3: the CONVERSION BAN between the store's error classes and the
# consensus verdict. `StoreInvariantViolated` / `StoreCannot` (store crate)
# are never converted into `InvalidBlock` (validation crate), by `From`, by
# `Into`, by `TryFrom`, or by a hand-written `match` arm.
#
# WHY. A store-side constraint that produces a user-visible "invalid block"
# is a HIDDEN RULE — `db_lmdb.cpp:1438`'s `MDB_NODUPDATA` put is the instance
# R8 was convened over. The same constraint producing a fatal is a belt. The
# taxonomy holds only while nothing maps the second class onto the first,
# and the first two clauses of the ban are compile-time and free; this gate
# is the third clause, the one that catches a `match` someone writes by hand.
#
# THREE CLAUSES.
#   1. no `impl From/Into/TryFrom` between a store error type and a verdict
#      type, anywhere under rust/;
#   2. `shekyl-chain-store` never NAMES a verdict type — the store does not
#      know `InvalidBlock` exists;
#   3. no match arm: a verdict token within three lines of a store-error token
#      in any .rs file under rust/ (comments stripped).
# Clauses 1 and 2 are live at birth. Clause 3 is armed and has no verdict
# type to match until the validation crate lands; the gate REPORTS how many
# verdict-type definitions it found so "clean" cannot be mistaken for
# "checked".
#
# Instance of 47-gate-subject-assertion.mdc: the gate first parses
# `pub enum StoreError` with >= 1 variant and counts the .rs files it walked;
# zero of either is a failure, because a ban over an empty tree passes.
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
STORE_CRATE = RUST / "shekyl-chain-store"
STORE_ERROR_FILE = STORE_CRATE / "src/store/error.rs"
SELF = Path(__file__).resolve()

STORE_TOKEN = r"(?:StoreError|StoreInvariant|InvariantViolated|StoreCannot)"
VERDICT_TOKEN = r"Invalid(?:Block|Tx|Transaction)"
STORE_RE = re.compile(rf"\b{STORE_TOKEN}\b")
VERDICT_RE = re.compile(rf"\b{VERDICT_TOKEN}\b")
VERDICT_DEF_RE = re.compile(rf"\b(?:enum|struct)\s+{VERDICT_TOKEN}\b")
STORE_ENUM_RE = re.compile(r"pub\s+enum\s+StoreError\s*\{(.*?)\n\}", re.S)
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9]*)\s*(?:[,({]|$)", re.M)
# `impl From<A> for B`, `impl Into<B> for A`, `impl TryFrom<A> for B`, with
# optional generics/paths on either side. Matched on a single joined line.
CONV_RE = re.compile(
    r"impl(?:<[^>]*>)?\s+(?:From|Into|TryFrom)\s*<\s*([^>]+?)\s*>\s+for\s+([\w:<>' ,]+)"
)
SKIP_DIRS = {"target", ".git"}
WINDOW = 3


class GateError(Exception):
    pass


def strip_comments(src: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in src.splitlines())


def rust_files(root: Path):
    for p in sorted(root.rglob("*.rs")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        yield p


def assert_subject(rust_root: Path, error_file: Path) -> int:
    if not error_file.is_file():
        raise GateError(f"subject absent: {error_file} not found")
    m = STORE_ENUM_RE.search(strip_comments(error_file.read_text(encoding="utf-8")))
    if not m:
        raise GateError(f"subject absent: `pub enum StoreError` not parsed in {error_file.name}")
    n = len(VARIANT_RE.findall(m.group(1)))
    if n == 0:
        raise GateError("subject absent: StoreError parsed with zero variants")
    return n


def check(rust_root: Path, store_crate: Path, error_file: Path, exclude: set[Path] = frozenset()) -> str:
    n_variants = assert_subject(rust_root, error_file)
    files = [p for p in rust_files(rust_root) if p not in exclude]
    if not files:
        raise GateError("subject absent: no .rs files walked")
    findings: list[str] = []
    verdict_defs = 0
    for path in files:
        text = strip_comments(path.read_text(encoding="utf-8"))
        rel = path.relative_to(rust_root)
        verdict_defs += len(VERDICT_DEF_RE.findall(text))
        in_store = store_crate in path.parents
        # clause 2
        if in_store:
            for i, line in enumerate(text.splitlines(), 1):
                if VERDICT_RE.search(line):
                    findings.append(f"clause 2: {rel}:{i} store crate names a verdict type: {line.strip()}")
        # clause 1 — join lines so a multi-line impl header still matches
        for m in CONV_RE.finditer(" ".join(text.split())):
            src_t, dst_t = m.group(1), m.group(2)
            sides = (STORE_RE.search(src_t) is not None, VERDICT_RE.search(src_t) is not None,
                     STORE_RE.search(dst_t) is not None, VERDICT_RE.search(dst_t) is not None)
            store_side = sides[0] or sides[2]
            verdict_side = sides[1] or sides[3]
            if store_side and verdict_side:
                findings.append(f"clause 1: {rel} converts between store error and verdict: `{m.group(0).strip()}`")
        # clause 3 — a verdict token within WINDOW lines of a store token
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not STORE_RE.search(line):
                continue
            for j in range(i, min(i + WINDOW, len(lines))):
                if VERDICT_RE.search(lines[j]):
                    findings.append(
                        f"clause 3: {rel}:{i + 1}-{j + 1} verdict token within {WINDOW} lines of a store-error token: "
                        f"{lines[j].strip()}"
                    )
                    break
    if findings:
        raise GateError("conversion ban violated:\n" + "".join(f"  {f}\n" for f in findings))
    return (
        f"store-error conversion ban: StoreError {n_variants} variants, {len(files)} files walked, "
        f"clauses 1-2 clean; clause 3 armed against {verdict_defs} verdict-type definition(s)"
    )


# --- selftest ----------------------------------------------------------------

STORE_ERR = "pub enum StoreError {\n    Open,\n    CellCorrupt { key: u8 },\n}\n"


def selftest() -> None:
    fails: list[str] = []

    def run(name: str, files: dict[str, str], needle: str | None) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "rust"
            crate = root / "shekyl-chain-store"
            err = crate / "src/store/error.rs"
            for rel, body in files.items():
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body, encoding="utf-8")
            try:
                check(root, crate, err)
                if needle is not None:
                    fails.append(f"{name}: expected red, passed")
            except GateError as e:
                if needle is None:
                    fails.append(f"{name}: expected pass, got {e}")
                elif needle not in str(e):
                    fails.append(f"{name}: red for the wrong reason: {e}")

    E = "shekyl-chain-store/src/store/error.rs"
    V = "shekyl-validator/src/verdict.rs"
    run("clean tree", {E: STORE_ERR, V: "pub struct InvalidBlock;\nfn f() {}\n"}, None)
    run("subject: no error.rs", {V: "fn f() {}\n"}, "not found")
    run("subject: enum absent", {E: "pub struct Other;\n"}, "not parsed")
    run("subject: zero variants", {E: "pub enum StoreError {\n}\n"}, "zero variants")
    run("clause 1: From store->verdict", {E: STORE_ERR, V: "impl From<StoreError> for InvalidBlock {\n    fn from(_: StoreError) -> Self { Self }\n}\n"}, "clause 1")
    run("clause 1: multi-line header", {E: STORE_ERR, V: "impl From<\n    shekyl_chain_store::StoreInvariant,\n> for InvalidBlock {}\n"}, "clause 1")
    run("clause 1: Into verdict", {E: STORE_ERR, V: "impl Into<InvalidBlock> for StoreCannot {}\n"}, "clause 1")
    run("clause 1: TryFrom", {E: STORE_ERR, V: "impl TryFrom<StoreError> for InvalidTx {}\n"}, "clause 1")
    run("clause 1 not tripped by daemon error", {E: STORE_ERR, V: "impl From<StoreError> for DaemonError {}\n"}, None)
    run("clause 2: store names verdict", {E: STORE_ERR, "shekyl-chain-store/src/lib.rs": "pub use x::InvalidBlock;\n"}, "clause 2")
    run("clause 2: comment does not count", {E: STORE_ERR, "shekyl-chain-store/src/lib.rs": "// never InvalidBlock here\n"}, None)
    run("clause 3: match arm", {E: STORE_ERR, V: "fn f(e: StoreError) -> InvalidBlock {\n    match e {\n        StoreError::CellCorrupt { .. } => InvalidBlock::Corrupt,\n    }\n}\n"}, "clause 3")
    run("clause 3: arm split over lines", {E: STORE_ERR, V: "match e {\n    StoreError::Open =>\n        {\n            InvalidBlock::X\n        }\n}\n"}, "clause 3")
    run("clause 3: far apart is not an arm", {E: STORE_ERR, V: "fn a(e: StoreError) {}\n\n\n\nfn b() -> InvalidBlock { InvalidBlock }\n"}, None)
    if fails:
        print("store-error conversion-ban selftest FAILED:", file=sys.stderr)
        for f in fails:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print("store-error conversion-ban selftest: 14 cases held")


def main() -> None:
    if "--selftest" in sys.argv:
        selftest()
        return
    try:
        print(check(RUST, STORE_CRATE, STORE_ERROR_FILE))
    except GateError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
