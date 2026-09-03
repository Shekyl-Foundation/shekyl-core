#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Count `pub` (not pub(crate)) inherent methods on Engine. Used by
# check_engine_decomposition.sh METHODS_CEILING. Prints one integer.
# Optional CRATE_SRC as argv[1] (shekyl-engine-core/src, not src/engine);
# --list prints path:line name; --self-test runs the where-clause / façade /
# cfg(test)-mod / noise / path-to-Engine / test-filename / raw-ident /
# impl-item-macro / crate-root-impl negative controls.

from __future__ import annotations

import os
import re
import sys
import tempfile

# Applied to *masked* source (strings/comments stripped to spaces), so
# `extern "C"` is `extern` plus spaces, not a quoted ABI token.
# `pub(crate)` / `pub(super)` do not match: they have `(` immediately after `pub`.
FN_PUB = re.compile(
    r"^(\s+)pub\s+(?:(?:const|async|unsafe|extern)\s+)*"
    r"fn\s+(?:r#)?(\w+)\s*[\(<]"
)
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")
# `mod foo`, `pub mod foo`, `pub(crate) mod foo`, `pub(in crate::engine) mod foo`.
# Optional `r#` so `mod r#type;` is still a module decl, not production code.
MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?:r#)?\w+")
# Raw strings: r"…" / r#"…"# / br#"…"# / cr#"…"#. Must run before ordinary strings.
_RAW_STR = re.compile(r"(?:[bc])?r(#*)\"")
# Inherent Self is a path ending in `Engine` (`Engine`, `super::Engine`,
# `crate::Engine`, `crate::engine::Engine`). `Wrapper<Engine<S>>` does not
# match: match is anchored at the Self type, not a substring search.
_ENGINE_SELF = re.compile(
    r"(?:(?:r#)?[A-Za-z_][\w]*::)*Engine(?:\s*<|\s*\{|\s*$)"
)
# Impl-item macros (`foo!();` / `foo! { }` / `foo!(...)`). Not `pub fn`
# bodies that contain `vec![]` — those match FN_PUB on the same line, or
# sit at brace depth > 1. Expanding macros is out of scope for this
# lexer (syn/rustc would be a heavier freeze subject than the count).
_IMPL_ITEM_MACRO = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:r#)?[A-Za-z_]\w*!\s*(?:[;(\[{]|$)"
)


class FreezeHole(Exception):
    """Lexer cannot see expanded macros; fail closed rather than under-count."""

    def __init__(self, rel: str, line_no: int, text: str) -> None:
        super().__init__(
            f"{rel}:{line_no}: impl-item macro {text!r} — METHODS_CEILING "
            "cannot see expanded items; expand the invocation or do not "
            "generate Engine methods from a macro"
        )


def mask_rust_noise(src: str) -> str:
    """Replace comments, strings, and char literals with spaces (keep newlines).

    Brace depth for `#[cfg(test)] mod` skip and inherent-impl scan must not
    see `{` / `}` inside `//`, `/* */`, `"…"`, raw strings, or `'{'`. A lexer
    here is the freeze's subject: syn/rustc would be a new CI dependency for
    a counter that has to run in grep-gates. Length is preserved so `--list`
    line numbers still match the file.
    """
    n = len(src)
    out = [" "] * n
    i = 0
    while i < n:
        if src[i] == "\n":
            out[i] = "\n"
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            if j < 0:
                break
            out[j] = "\n"
            i = j + 1
            continue
        if src.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if src[i] == "\n":
                    out[i] = "\n"
                    i += 1
                elif src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        raw = _RAW_STR.match(src, i)
        if raw:
            hashes = raw.group(1)
            i = raw.end()
            closer = '"' + hashes
            j = src.find(closer, i)
            if j < 0:
                while i < n:
                    if src[i] == "\n":
                        out[i] = "\n"
                    i += 1
                break
            while i < j:
                if src[i] == "\n":
                    out[i] = "\n"
                i += 1
            i = j + len(closer)
            continue
        if src.startswith(('b"', 'c"', '"'), i):
            if src[i] in "bc":
                i += 1
            i += 1  # opening quote
            while i < n:
                if src[i] == "\n":
                    out[i] = "\n"
                    i += 1
                elif src[i] == "\\":
                    i += 2
                    if i > n:
                        i = n
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            continue
        if src.startswith("b'", i) or src[i] == "'":
            if src.startswith("b'", i):
                i += 2
            else:
                i += 1
            if i < n and src[i] == "\\":
                i += 2
                if i < n and src[i] == "'":
                    i += 1
                continue
            if i + 1 < n and src[i + 1] == "'":
                i += 2
                continue
            # Lifetime `'a` / `'static` — no braces; skip the ident.
            while i < n and (src[i].isalnum() or src[i] == "_"):
                i += 1
            continue
        out[i] = src[i]
        i += 1
    return "".join(out)


def brace_delta(s: str) -> int:
    return s.count("{") - s.count("}")


def skip_balanced(s: str, start: int, open_ch: str, close_ch: str) -> int | None:
    """Index just after the matching closer, or None if unbalanced."""
    if start >= len(s) or s[start] != open_ch:
        return start
    depth = 0
    i = start
    while i < len(s):
        c = s[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def is_test_source(fname: str) -> bool:
    """Skip dedicated test modules, not any file whose name contains `test`.

    `attestation.rs` / `contest.rs` are production. Live engine test files
    are `*_tests.rs`, `test_*.rs` (`test_support.rs`, `test_fixtures.rs`),
    `*_fixtures.rs`, and the explicit `regtest_e2e.rs` (the name is the
    harness, not a substring accident).
    """
    base = os.path.basename(fname)
    if base == "regtest_e2e.rs":
        return True
    if base.startswith("test_"):
        return True
    if base.endswith("_tests.rs") or base.endswith("_test.rs"):
        return True
    if base.endswith("_fixtures.rs"):
        return True
    return False


def strip_cfg_test_modules(lines: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        if CFG_TEST.match(lines[i]):
            j = i + 1
            while j < n and (lines[j].strip() == "" or lines[j].lstrip().startswith("#[")):
                j += 1
            if j < n and MOD.match(lines[j]):
                if "{" not in lines[j]:
                    # Out-of-line: `mod foo;` — skip the decl, not the next
                    # production `pub use { ... }` (or anything else with braces).
                    i = j + 1
                    continue
                depth = 0
                started = False
                k = j
                while k < n:
                    depth += brace_delta(lines[k])
                    if "{" in lines[k]:
                        started = True
                    k += 1
                    if started and depth <= 0:
                        break
                i = k
                continue
        out.append(lines[i])
        i += 1
    return out


def impl_self_is_engine(header: str) -> bool:
    compact = re.sub(r"\s+", " ", header)
    # Bounds in a `where` clause can mention `Engine<...>` (e.g. StakeFacade)
    # without this being an inherent Engine impl. Strip them first.
    compact = re.split(r"\bwhere\b", compact, maxsplit=1)[0]
    if re.search(r"\bfor\s+Engine\b", compact):
        return False
    m = re.search(r"\bimpl\b", compact)
    if not m:
        return False
    i = m.end()
    while i < len(compact) and compact[i].isspace():
        i += 1
    if i < len(compact) and compact[i] == "<":
        nxt = skip_balanced(compact, i, "<", ">")
        if nxt is None:
            return False
        i = nxt
        while i < len(compact) and compact[i].isspace():
            i += 1
    rest = compact[i:]
    return bool(_ENGINE_SELF.match(rest))


def count_in_file(path: str, rel: str, listing: bool) -> list[str]:
    raw = open(path, encoding="utf-8").read()
    lines = strip_cfg_test_modules(mask_rust_noise(raw).splitlines(True))
    found: list[str] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].lstrip()
        if stripped.startswith("impl") and (
            stripped.startswith("impl<") or stripped.startswith("impl ")
        ):
            header_parts = [lines[i]]
            started = "{" in lines[i]
            k = i + 1
            while k < len(lines) and not started:
                header_parts.append(lines[k])
                if "{" in lines[k]:
                    started = True
                    break
                k += 1
            header = "".join(header_parts)
            body_start = i if "{" in lines[i] else k
            if started and impl_self_is_engine(header):
                depth = 0
                j = body_start
                while j < len(lines):
                    m = FN_PUB.match(lines[j])
                    if m:
                        found.append(f"{rel}:{j + 1} {m.group(2)}")
                    elif depth == 1 and _IMPL_ITEM_MACRO.match(lines[j]):
                        raise FreezeHole(rel, j + 1, lines[j].strip())
                    depth += brace_delta(lines[j])
                    j += 1
                    if depth <= 0:
                        break
                i = j
                continue
        i += 1
    return found


def method_names_in_source(source: str, rel: str = "x.rs") -> list[str]:
    """Count helper for --self-test. Writes `source` to a temp file named `rel`."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, rel)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        return [entry.split()[-1] for entry in count_in_file(path, rel, True)]


def count_in_dir(root: str, listing: bool = False) -> list[str]:
    """Walk `root` for `.rs` files that are not dedicated test modules."""
    names: list[str] = []
    for dirpath, _, files in os.walk(root):
        for fname in sorted(files):
            if not fname.endswith(".rs"):
                continue
            if is_test_source(fname):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, root)
            names.extend(count_in_file(path, rel, listing))
    return names


def is_engine_only_scan(root: str) -> bool:
    """True when `root` is `src/engine` next to the crate's `lib.rs`."""
    parent = os.path.dirname(os.path.abspath(root))
    return os.path.basename(os.path.abspath(root)) == "engine" and os.path.isfile(
        os.path.join(parent, "lib.rs")
    )


def refuse_engine_subdir(root: str) -> None:
    """Rule 47: scanning only `src/engine` is first evidence the subject is incomplete.

    Inherent `impl Engine` can live anywhere in the defining crate (`lib.rs`,
    `scan.rs`, …). A caller that still passes `src/engine` must fail loud.
    """
    if is_engine_only_scan(root):
        print(
            "FATAL: scan root is src/engine; inherent Engine impls can live "
            "anywhere in the defining crate. Pass rust/shekyl-engine-core/src.",
            file=sys.stderr,
        )
        sys.exit(2)


def crate_src_default() -> str:
    return os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "rust",
            "shekyl-engine-core",
            "src",
        )
    )


def self_test() -> None:
    """Negative controls for the METHODS_CEILING subject.

    Named edits that make this red: drop the `where`-strip (StakeFacade
    methods count as Engine); treat `Engine<` as a substring match
    (`Wrapper<Engine<S>>` counts); count `pub(crate)` or `impl Trait for
    Engine`; stop stripping `#[cfg(test)] mod`; brace-scan past
    `mod foo;` into production `pub use { ... }`; ignore `pub const fn`;
    count `{`/`}` in comments or `'{'` (impl body ends early / test-mod
    skip eats production); refuse `crate::Engine`; skip any filename
    containing the substring `test` (`attestation.rs`); miss `r#type`;
    ignore impl-item macros (`add_method!()`); walk only `src/engine`
    (`lib.rs` inherent impls vanish).
    """
    assert impl_self_is_engine("impl Engine<S, D> {")
    assert impl_self_is_engine("impl<S, D> Engine<S, D> {")
    assert impl_self_is_engine("impl Engine {")
    assert impl_self_is_engine("impl<S: Into<Option<u8>>> Engine<S> {")
    assert impl_self_is_engine("impl crate::Engine {")
    assert impl_self_is_engine("impl crate::Engine<S> {")
    assert impl_self_is_engine("impl crate::engine::Engine {")
    assert impl_self_is_engine("impl super::Engine {")
    assert not impl_self_is_engine("impl Foo for Engine<S> {")
    assert not impl_self_is_engine(
        "impl StakeFacade<'_, S>\nwhere Engine<S, D>: Send\n{"
    )
    assert not impl_self_is_engine("impl Wrapper<Engine<S>> {")

    names = method_names_in_source(
        """
impl<S, D> Engine<S, D> {
    pub fn stake(&self) {}
    pub async fn stake_in(&self) {}
    pub const fn capacity(&self) {}
    pub unsafe fn poke(&self) {}
    pub extern "C" fn abi(&self) {}
    pub fn r#type(&self) {}
    pub(crate) fn hidden(&self) {}
}

impl<S: Into<Option<u8>>> Engine<S> {
    pub fn nested_generics(&self) {}
}

impl<'a, S> StakeFacade<'a, S>
where
    Engine<S>: Send,
{
    pub fn staking_read_view(&self) {}
    pub async fn drain_to_principal() {}
}

impl Foo for Engine<S> {
    pub fn trait_method(&self) {}
}

impl Engine {
    pub fn keep(&self) {}
}

#[cfg(test)]
mod tests {
    impl Engine {
        pub fn only_in_tests(&self) {}
    }
}

#[cfg(test)]
pub(crate) mod synthetic_tree;

pub use leftover::{
    ProductionItem,
};

impl Engine {
    pub fn after_out_of_line_mod(&self) {}
}

#[cfg(test)]
mod inline_crate {
    impl Engine {
        pub fn also_only_in_tests(&self) {}
    }
}

impl crate::Engine {
    pub fn via_crate_reexport(&self) {}
}
"""
    )
    assert set(names) == {
        "stake",
        "stake_in",
        "capacity",
        "poke",
        "abi",
        "type",
        "nested_generics",
        "keep",
        "after_out_of_line_mod",
        "via_crate_reexport",
    }, names
    assert "only_in_tests" not in names
    assert "also_only_in_tests" not in names
    assert "staking_read_view" not in names
    assert "hidden" not in names

    # rustdoc `}` must not close the inherent impl (later pub fn would bypass).
    names = method_names_in_source(
        """
impl Engine {
    /// }
    pub fn still_counted(&self) {}
}
"""
    )
    assert names == ["still_counted"], names

    # Unmatched `{` in a cfg(test) comment must not swallow the next production impl.
    names = method_names_in_source(
        """
#[cfg(test)]
mod tests {
    // {
    impl Engine {
        pub fn test_only(&self) {}
    }
}
impl Engine {
    pub fn production(&self) {}
}
"""
    )
    assert "test_only" not in names
    assert "production" in names

    # Char-literal `{` must not keep the impl scan running into the next type.
    names = method_names_in_source(
        """
impl Engine {
    pub fn before(&self) {}
    const BRACE: char = '{';
    pub fn after(&self) {}
}
impl StakeFacade {
    pub fn not_engine(&self) {}
}
"""
    )
    assert names == ["before", "after"], names

    assert is_test_source("merge_tests.rs")
    assert is_test_source("test_support.rs")
    assert is_test_source("test_fixtures.rs")
    assert is_test_source("stake_engine/test_fixtures.rs")
    assert is_test_source("regtest_e2e.rs")
    assert not is_test_source("attestation.rs")
    assert not is_test_source("contest.rs")
    assert not is_test_source("stake_facade.rs")
    assert not is_test_source("tx_weight_kat.rs")

    # Impl-item macros can emit pub methods the lexer never sees.
    try:
        method_names_in_source(
            """
impl Engine {
    add_method!();
    pub fn keep(&self) {}
}
"""
        )
        raise AssertionError("expected FreezeHole on impl-item macro")
    except FreezeHole:
        pass
    names = method_names_in_source(
        """
impl Engine {
    pub fn keep(&self) {
        let _ = vec![1];
    }
}
"""
    )
    assert names == ["keep"], names

    # Inherent impls outside engine/ (lib.rs, scan.rs, …) still count.
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "engine"))
        with open(os.path.join(td, "lib.rs"), "w", encoding="utf-8") as fh:
            fh.write("impl Engine {\n    pub fn sneaky(&self) {}\n}\n")
        with open(os.path.join(td, "engine", "mod.rs"), "w", encoding="utf-8") as fh:
            fh.write("impl Engine {\n    pub fn keep(&self) {}\n}\n")
        names = {entry.split()[-1] for entry in count_in_dir(td, True)}
        assert names == {"sneaky", "keep"}, names
        assert is_engine_only_scan(os.path.join(td, "engine"))
        assert not is_engine_only_scan(td)


def main() -> None:
    listing = "--list" in sys.argv
    args = [a for a in sys.argv[1:] if a not in ("--list", "--self-test")]
    if "--self-test" in sys.argv:
        self_test()
        print("ok")
        return
    root = args[0] if args else crate_src_default()
    root = os.path.abspath(root)
    refuse_engine_subdir(root)
    try:
        names = count_in_dir(root, listing)
    except FreezeHole as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(1)
    if listing:
        for n in names:
            print(n)
        print(f"count={len(names)}", file=sys.stderr)
    else:
        print(len(names))


if __name__ == "__main__":
    main()
