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
#   1. no `impl From/Into/TryFrom/TryInto` between a store error type and
#      `InvalidBlock`, anywhere under rust/. The trait name may be bare
#      (`From`) or a path (`core::convert::From`, `::std::convert::TryInto`);
#      a regex that only accepted the bare ident would let a legal impl
#      bypass the ban. `TryInto` is the dual of `TryFrom` and a direct impl
#      is legal; omitting it is a clause-1 hole.
#   2. `shekyl-chain-store` never NAMES `InvalidBlock` — the store does not
#      know the consensus verdict type exists;
#   3. no match arm maps a store-error token (pattern side of `=>`) onto
#      `InvalidBlock` (body side). Arms are scanned by brace depth, not by
#      a line window: a three-line heuristic misses a body that logs then
#      constructs, and flags adjacent functions that are not a conversion.
#
# VERDICT TOKEN. The ruling names `InvalidBlock`. Aliases (`InvalidTx`,
# `InvalidTransaction`) are intentionally absent: the latter is already an
# RPC-client error, and a guessed alias both false-positives on that path
# and false-negatives on a differently-named verdict (`BlockVerdict`). A
# PR that mints a second validation-crate verdict type adds it here.
#
# SUBJECT. All three clauses are live. The gate asserts the *canonical*
# definition: `pub struct InvalidBlock` in
# `rust/shekyl-chain-rules/src/verdict.rs`. Counting any `struct|enum
# InvalidBlock` anywhere under rust/ is vacuous — a private test fixture
# would keep clause 3 green after the real type disappeared (rule 47).
# If the file moves or the type is renamed, the refusal names VERDICT_FILE
# and VERDICT_TOKEN.
#
# Records-was (2026-09-14 → 2026-09-15). At birth clauses 1–2 were live and
# clause 3 was ARMED: `verdict_defs == 0` was the birth state, printed and
# not refused, because requiring >= 1 would have redded a gate whose subject
# had not been minted. The carrier was "the PR that mints `InvalidBlock`
# turns zero into a failure"; DRS-E6 increment 1 minted it and raised the
# gate in the same PR (CHAIN_RULES_CRATE.md §7).
#
# Instance of 47-gate-subject-assertion.mdc: the gate first parses
# `pub enum StoreError` with >= 1 variant, counts the .rs files it walked,
# and counts verdict-type definitions; zero of any is a failure, because a
# ban over an empty tree — or over a tree with nothing to convert *to* —
# passes.
from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"
STORE_CRATE = RUST / "shekyl-chain-store"
STORE_ERROR_FILE = STORE_CRATE / "src/store/error.rs"
VERDICT_FILE = RUST / "shekyl-chain-rules" / "src" / "verdict.rs"
VERDICT_REL = VERDICT_FILE.relative_to(RUST)
SELF = Path(__file__).resolve()
STRIPPER = ROOT / "scripts" / "ci" / "strip_c_comments.py"

STORE_TOKEN = r"(?:StoreError|StoreInvariant|InvariantViolated|StoreCannot)"
# The validation crate's OWN non-verdict outcomes (`shekyl-chain-rules/src/
# fault.rs`, E6 slice 2 Q8): a stale stateless-stage claim, a corrupt view,
# and the enum that carries them beside the view's fault. The ban extends to
# them for the same reason it exists for store errors — "couldn't prove it"
# reads like "rejected it" at a glance, and a retry arm is MORE tempting to
# collapse onto `InvalidBlock` than a store error, not less. Clause 1 sees
# the bare names in a conversion header; clause 3 sees the qualified arms
# (`Fault::View(_) => InvalidBlock…` would launder the store's fault through
# the wrapper the bare STORE_TOKEN cannot see).
FAULT_TOKEN = r"(?:Stale|Corrupt|Fault)"
FAULT_ARM_TOKEN = r"(?:Stale|Corrupt|Fault::(?:View|Stale|Corrupt))"
VERDICT_TOKEN = r"InvalidBlock"
STORE_RE = re.compile(rf"\b(?:{STORE_TOKEN}|{FAULT_TOKEN})\b")
STORE_ARM_RE = re.compile(rf"\b(?:{STORE_TOKEN}|{FAULT_ARM_TOKEN})\b")
VERDICT_RE = re.compile(rf"\b{VERDICT_TOKEN}\b")
VERDICT_DEF_RE = re.compile(rf"\bpub\s+struct\s+{VERDICT_TOKEN}\b")
STORE_ENUM_RE = re.compile(r"pub\s+enum\s+StoreError\s*\{(.*?)\n\}", re.S)
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9]*)\s*(?:[,({]|$)", re.M)
# `impl From<A> for B`, `impl Into<B> for A`, `impl TryFrom<A> for B`,
# `impl TryInto<B> for A`, with optional generics on `impl` and a bare or
# path-qualified trait name. Longer names first so `TryFrom` is not eaten
# as `From`. Matched on a single joined line.
TRAIT = r"(?:(?:::)?(?:[A-Za-z_][\w]*::)*(?:TryFrom|TryInto|From|Into))"
# The converted type may itself be generic one level deep (`From<Fault<V>>`),
# so the inner group admits one nested `<…>`; a deeper nesting is not a shape
# the ban's subjects take.
CONV_RE = re.compile(
    rf"impl(?:<[^>]*>)?\s+{TRAIT}\s*<\s*((?:[^<>]|<[^<>]*>)+?)\s*>\s+for\s+([\w:<>' ,]+)"
)
SKIP_DIRS = {"target", ".git"}

_STRIP_MOD = None


def _strip_mod():
    global _STRIP_MOD
    if _STRIP_MOD is None:
        spec = importlib.util.spec_from_file_location("strip_c_comments", STRIPPER)
        if spec is None or spec.loader is None:
            raise GateError(f"subject absent: cannot load {STRIPPER}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _STRIP_MOD = mod
    return _STRIP_MOD


class GateError(Exception):
    pass


def strip_comments(src: str) -> str:
    """Delegate to strip_c_comments.py (nested block comments, lifetimes).

    A `//`-only stripper is a clause-2/3 false red on `/* InvalidBlock */`
    and is not what this gate's header claims.
    """
    return _strip_mod().strip(src, rust=True)


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


def assert_verdict_subject(rust_root: Path) -> None:
    """The canonical `pub struct InvalidBlock` must exist where it was minted.

    A same-named type anywhere else — a test fixture, a private alias, an
    enum — is not the API this gate protects.
    """
    verdict = rust_root / VERDICT_REL
    if not verdict.is_file():
        raise GateError(
            f"subject absent: no public struct {VERDICT_TOKEN} in {VERDICT_REL} "
            "(file not found) — if it moved, update VERDICT_FILE"
        )
    text = strip_comments(verdict.read_text(encoding="utf-8"))
    if VERDICT_DEF_RE.search(text) is None:
        raise GateError(
            f"subject absent: no public struct {VERDICT_TOKEN} in {VERDICT_REL} — "
            "InvalidBlock was minted as `pub struct` there; if it moved or was "
            "renamed, update VERDICT_FILE / VERDICT_TOKEN"
        )


def blank_strings(src: str) -> str:
    """Replace interiors of `"..."` and `'X'` with spaces of the same width.

    Brace-depth then cannot be ended by a `}` that lives in a log string.
    Line numbers are preserved. Lifetimes (`'a`) are not char literals.
    Raw strings (`r#"..."#`) are unmodelled, same limit as strip_c_comments.py;
    a misclassification that lands is the reopening criterion.
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            out.append('"')
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                if src[i] == '"':
                    out.append('"')
                    i += 1
                    break
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            continue
        if c == "'" and i + 1 < n:
            # Char literal `'X'` / `'\n'` / `'{'`; a lifetime has no closer.
            nxt = src[i + 1]
            if nxt == "\\" and i + 3 < n and src[i + 3] == "'":
                out.append("'" + " " * 2 + "'")
                i += 4
                continue
            if i + 2 < n and src[i + 2] == "'":
                out.append("' '")
                i += 3
                continue
        out.append(c)
        i += 1
    return "".join(out)


def match_arms(src: str) -> list[tuple[str, str, int]]:
    """(pattern, body, 1-based line of `=>`) for each fat-arrow arm.

    Pattern is the text after the previous `{` or `,` at this brace depth,
    so sibling arms and adjacent functions are not one span. Body runs from
    `=>` until depth returns to the arrow's depth on a `,` or `}`. Nested
    `=>` are found by scanning each body; jumping to the arm's end would
    skip them. Callers blank strings first so a `}` inside a literal cannot
    close the arm.
    """
    return _match_arms(src, 0)


def _match_arms(src: str, line_offset: int) -> list[tuple[str, str, int]]:
    arms: list[tuple[str, str, int]] = []
    n = len(src)
    depth = 0
    paren = 0
    last_sep: dict[int, int] = {0: -1}
    i = 0
    while i < n - 1:
        c = src[i]
        if c == "{":
            depth += 1
            last_sep[depth] = i
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        if c == "(":
            paren += 1
            i += 1
            continue
        if c == ")":
            paren = max(0, paren - 1)
            i += 1
            continue
        if c == "," and paren == 0:
            last_sep[depth] = i
            i += 1
            continue
        if c == "=" and src[i + 1] == ">":
            sep = last_sep.get(depth, -1)
            pattern = src[sep + 1 : i]
            arrow_depth = depth
            line = line_offset + src[:i].count("\n") + 1
            j = i + 2
            body_paren = paren
            while j < n:
                ch = src[j]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    if depth == arrow_depth:
                        break
                    depth -= 1
                elif ch == "(":
                    body_paren += 1
                elif ch == ")":
                    body_paren = max(0, body_paren - 1)
                elif ch == "," and depth == arrow_depth and body_paren == 0:
                    break
                j += 1
            body = src[i + 2 : j]
            arms.append((pattern, body, line))
            arms.extend(_match_arms(body, line_offset + src[: i + 2].count("\n")))
            last_sep[arrow_depth] = j
            i = j
            continue
        i += 1
    return arms


def check(rust_root: Path, store_crate: Path, error_file: Path, exclude: set[Path] = frozenset()) -> str:
    n_variants = assert_subject(rust_root, error_file)
    assert_verdict_subject(rust_root)
    files = [p for p in rust_files(rust_root) if p not in exclude]
    if not files:
        raise GateError("subject absent: no .rs files walked")
    findings: list[str] = []
    for path in files:
        text = blank_strings(strip_comments(path.read_text(encoding="utf-8")))
        rel = path.relative_to(rust_root)
        in_store = store_crate in path.parents
        # clause 2
        if in_store:
            for i, line in enumerate(text.splitlines(), 1):
                if VERDICT_RE.search(line):
                    findings.append(f"clause 2: {rel}:{i} store crate names a verdict type: {line.strip()}")
        # clause 1 — join lines so a multi-line impl header still matches
        for m in CONV_RE.finditer(" ".join(text.split())):
            src_t, dst_t = m.group(1), m.group(2)
            sides = (
                STORE_RE.search(src_t) is not None,
                VERDICT_RE.search(src_t) is not None,
                STORE_RE.search(dst_t) is not None,
                VERDICT_RE.search(dst_t) is not None,
            )
            store_side = sides[0] or sides[2]
            verdict_side = sides[1] or sides[3]
            if store_side and verdict_side:
                findings.append(
                    f"clause 1: {rel} converts between store error and verdict: `{m.group(0).strip()}`"
                )
        # clause 3 — store or fault token on the pattern side of `=>`, verdict
        # on the body
        for pattern, body, line in match_arms(text):
            if STORE_ARM_RE.search(pattern) and VERDICT_RE.search(body):
                findings.append(
                    f"clause 3: {rel}:{line} match arm maps a store-error or fault token onto {VERDICT_TOKEN}"
                )
    if findings:
        raise GateError("conversion ban violated:\n" + "".join(f"  {f}\n" for f in findings))
    return (
        f"store-error conversion ban: StoreError {n_variants} variants, {len(files)} files walked, "
        f"canonical pub struct {VERDICT_TOKEN} in {VERDICT_REL}; clauses 1-3 clean "
        f"(store tokens and the validation crate's own fault tokens)"
    )


# --- selftest ----------------------------------------------------------------

STORE_ERR = "pub enum StoreError {\n    Open,\n    CellCorrupt { key: u8 },\n}\n"
# The verdict type, where the real one lives. Every fixture carries it unless
# the case is about its absence: without it the gate refuses on subject before
# any clause is reached, so a clause case could not be red for its own reason.
VERDICT_DEF = "pub struct InvalidBlock {\n    pub rule: u8,\n}\n"


def selftest() -> None:
    # A stripper regression would silently widen every clause. Fail here, not
    # in a comment, so this gate's --selftest is a subject assertion on its
    # own comment scanner (rule 47).
    if _strip_mod().self_test() != 0:
        sys.exit(1)

    fails: list[str] = []
    cases = 0

    def run(name: str, files: dict[str, str], needle: str | None, *, verdict: bool = True) -> None:
        nonlocal cases
        cases += 1
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "rust"
            crate = root / "shekyl-chain-store"
            err = crate / "src/store/error.rs"
            if verdict:
                files = {D: VERDICT_DEF, **files}
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
    D = "shekyl-chain-rules/src/verdict.rs"
    V = "shekyl-chain-rules/src/validate.rs"
    run("clean tree", {E: STORE_ERR, V: "fn f() {}\n"}, None)
    run("subject: no error.rs", {V: "fn f() {}\n"}, "not found")
    run("subject: enum absent", {E: "pub struct Other;\n"}, "not parsed")
    run("subject: zero variants", {E: "pub enum StoreError {\n}\n"}, "zero variants")
    run(
        "subject: no verdict definition",
        {E: STORE_ERR, V: "fn f() {}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "subject: commented-out verdict definition does not count",
        {E: STORE_ERR, V: "/* pub struct InvalidBlock; */\nfn f() {}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "subject: enum-shaped definition in another file does not substitute",
        {E: STORE_ERR, V: "pub enum InvalidBlock {\n    A,\n}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "subject: enum-shaped definition in the canonical file is not the struct",
        {E: STORE_ERR, D: "pub enum InvalidBlock {\n    A,\n}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "subject: private struct in the canonical file does not count",
        {E: STORE_ERR, D: "struct InvalidBlock {\n    pub rule: u8,\n}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "subject: a pub struct elsewhere does not substitute for the canonical file",
        {E: STORE_ERR, V: "pub struct InvalidBlock {\n    pub rule: u8,\n}\n"},
        "no public struct InvalidBlock",
        verdict=False,
    )
    run(
        "clause 1: From store->verdict",
        {
            E: STORE_ERR,
            V: "impl From<StoreError> for InvalidBlock {\n    fn from(_: StoreError) -> Self { Self }\n}\n",
        },
        "clause 1",
    )
    run(
        "clause 1: multi-line header",
        {E: STORE_ERR, V: "impl From<\n    shekyl_chain_store::StoreInvariant,\n> for InvalidBlock {}\n"},
        "clause 1",
    )
    run("clause 1: Into verdict", {E: STORE_ERR, V: "impl Into<InvalidBlock> for StoreCannot {}\n"}, "clause 1")
    run(
        "clause 1: TryFrom",
        {E: STORE_ERR, V: "impl TryFrom<StoreError> for InvalidBlock {}\n"},
        "clause 1",
    )
    run(
        "clause 1: TryInto",
        {E: STORE_ERR, V: "impl TryInto<InvalidBlock> for StoreError {}\n"},
        "clause 1",
    )
    run(
        "clause 1: qualified path",
        {E: STORE_ERR, V: "impl core::convert::From<StoreError> for InvalidBlock {}\n"},
        "clause 1",
    )
    run(
        "clause 1: leading-colon path",
        {E: STORE_ERR, V: "impl ::std::convert::TryFrom<StoreError> for InvalidBlock {}\n"},
        "clause 1",
    )
    run("clause 1 not tripped by daemon error", {E: STORE_ERR, V: "impl From<StoreError> for DaemonError {}\n"}, None)
    run("clause 1: From stale->verdict", {E: STORE_ERR, V: "impl From<Stale> for InvalidBlock {}\n"}, "clause 1")
    run(
        "clause 1: From the fault enum->verdict",
        {E: STORE_ERR, V: "impl<V> From<Fault<V>> for InvalidBlock {}\n"},
        "clause 1",
    )
    run(
        "clause 3: stale arm onto verdict",
        {E: STORE_ERR, V: "match f {\n    Fault::Stale(_) => InvalidBlock::new(row, locus),\n    other => other,\n}\n"},
        "clause 3",
    )
    run(
        "clause 3: view fault laundered through the wrapper",
        {E: STORE_ERR, V: "match f {\n    Fault::View(_) => InvalidBlock::new(row, locus),\n}\n"},
        "clause 3",
    )
    run(
        "clause 3: unqualified Corrupt arm onto verdict",
        {E: STORE_ERR, V: "match f {\n    Corrupt(_) => InvalidBlock::new(row, locus),\n}\n"},
        "clause 3",
    )
    run(
        "clause 3: a fault arm that stays a fault is fine",
        {E: STORE_ERR, V: "match f {\n    Fault::View(e) => e,\n    Fault::Stale(s) => panic!(\"{s}\"),\n}\n"},
        None,
    )
    run("clause 2: store names verdict", {E: STORE_ERR, "shekyl-chain-store/src/lib.rs": "pub use x::InvalidBlock;\n"}, "clause 2")
    run("clause 2: comment does not count", {E: STORE_ERR, "shekyl-chain-store/src/lib.rs": "// never InvalidBlock here\n"}, None)
    run(
        "clause 2: block comment does not count",
        {E: STORE_ERR, "shekyl-chain-store/src/lib.rs": "/* never InvalidBlock here */\n"},
        None,
    )
    run(
        "clause 1: block-commented impl does not count",
        {E: STORE_ERR, V: "/* impl From<StoreError> for InvalidBlock {} */\n"},
        None,
    )
    run(
        "clause 3: match arm",
        {
            E: STORE_ERR,
            V: "fn f(e: StoreError) -> InvalidBlock {\n    match e {\n        StoreError::CellCorrupt { .. } => InvalidBlock::Corrupt,\n    }\n}\n",
        },
        "clause 3",
    )
    run(
        "clause 3: arm split over lines",
        {E: STORE_ERR, V: "match e {\n    StoreError::Open =>\n        {\n            InvalidBlock::X\n        }\n}\n"},
        "clause 3",
    )
    run(
        "clause 3: long arm",
        {
            E: STORE_ERR,
            V: (
                "match e {\n"
                "    StoreError::Open => {\n"
                "        let _a = 1;\n"
                "        let _b = 2;\n"
                "        let _c = 3;\n"
                "        InvalidBlock::X\n"
                "    }\n"
                "}\n"
            ),
        },
        "clause 3",
    )
    run(
        "clause 3: far apart is not an arm",
        {E: STORE_ERR, V: "fn a(e: StoreError) {}\n\n\n\nfn b() -> InvalidBlock { InvalidBlock }\n"},
        None,
    )
    run(
        "clause 3: nearby fns are not an arm",
        {E: STORE_ERR, V: "fn a(e: StoreError) {}\nfn b() -> InvalidBlock { InvalidBlock }\n"},
        None,
    )
    run(
        "clause 3: sibling arms are not a conversion",
        {
            E: STORE_ERR,
            V: "match x {\n    Foo => StoreError::Open,\n    Bar => InvalidBlock,\n}\n",
        },
        None,
    )
    run(
        "clause 3: nested arm",
        {
            E: STORE_ERR,
            V: "match x {\n    Foo => match e {\n        StoreError::Open => InvalidBlock::X,\n    },\n}\n",
        },
        "clause 3",
    )
    run(
        "clause 3: brace inside string does not hide the arm",
        {
            E: STORE_ERR,
            V: 'match e {\n    StoreError::Open => (log("}"), InvalidBlock::X).1,\n}\n',
        },
        "clause 3",
    )
    if fails:
        print("store-error conversion-ban selftest FAILED:", file=sys.stderr)
        for f in fails:
            print(f"  {f}", file=sys.stderr)
        sys.exit(1)
    print(f"store-error conversion-ban selftest: {cases} cases held")


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
