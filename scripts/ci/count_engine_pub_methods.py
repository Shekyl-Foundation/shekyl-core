#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Count `pub` (not pub(crate)) inherent methods on Engine. Used by
# check_engine_decomposition.sh METHODS_CEILING. Prints one integer.
# Optional ENGINE_DIR as argv[1]; --list prints path:line name;
# --self-test runs the where-clause / façade / cfg(test)-mod negative
# controls.

from __future__ import annotations

import os
import re
import sys
import tempfile

# `pub` + any sequence of fn qualifiers, then `fn`. `pub(crate)` /
# `pub(super)` do not match: they have `(` immediately after `pub`.
FN_PUB = re.compile(
    r"^(\s+)pub\s+(?:(?:const|async|unsafe|extern\s+\"[^\"]+\")\s+)*"
    r"fn\s+(\w+)\s*[\(<]"
)
CFG_TEST = re.compile(r"^\s*#\[cfg\(test\)\]")
# `mod foo`, `pub mod foo`, `pub(crate) mod foo`, `pub(in crate::engine) mod foo`.
MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+")


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
                code = lines[j].split("//", 1)[0]
                if "{" not in code:
                    # Out-of-line: `mod foo;` — skip the decl, not the next
                    # production `pub use { ... }` (or anything else with braces).
                    i = j + 1
                    continue
                depth = 0
                started = False
                k = j
                while k < n:
                    depth += lines[k].count("{") - lines[k].count("}")
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
    return bool(
        re.match(r"(?:super::|crate::engine::)?Engine(?:\s*<|\s*\{|\s*$)", rest)
    )


def count_in_file(path: str, rel: str, listing: bool) -> list[str]:
    raw = open(path, encoding="utf-8").read().splitlines(True)
    lines = strip_cfg_test_modules(raw)
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
                    depth += lines[j].count("{") - lines[j].count("}")
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


def self_test() -> None:
    """Negative controls for the METHODS_CEILING subject.

    Named edits that make this red: drop the `where`-strip (StakeFacade
    methods count as Engine); treat `Engine<` as a substring match
    (`Wrapper<Engine<S>>` counts); count `pub(crate)` or `impl Trait for
    Engine`; stop stripping `#[cfg(test)] mod`; brace-scan past
    `mod foo;` into production `pub use { ... }`; ignore `pub const fn`.
    """
    assert impl_self_is_engine("impl Engine<S, D> {")
    assert impl_self_is_engine("impl<S, D> Engine<S, D> {")
    assert impl_self_is_engine("impl Engine {")
    assert impl_self_is_engine("impl<S: Into<Option<u8>>> Engine<S> {")
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
"""
    )
    assert set(names) == {
        "stake",
        "stake_in",
        "capacity",
        "poke",
        "abi",
        "nested_generics",
        "keep",
        "after_out_of_line_mod",
    }, names
    assert "only_in_tests" not in names
    assert "also_only_in_tests" not in names
    assert "staking_read_view" not in names
    assert "hidden" not in names


def main() -> None:
    listing = "--list" in sys.argv
    args = [a for a in sys.argv[1:] if a not in ("--list", "--self-test")]
    if "--self-test" in sys.argv:
        self_test()
        print("ok")
        return
    engine_dir = args[0] if args else os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "rust",
        "shekyl-engine-core",
        "src",
        "engine",
    )
    engine_dir = os.path.abspath(engine_dir)
    names: list[str] = []
    for dirpath, _, files in os.walk(engine_dir):
        for fname in sorted(files):
            if not fname.endswith(".rs"):
                continue
            if "test" in fname:
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, engine_dir)
            names.extend(count_in_file(path, rel, listing))
    if listing:
        for n in names:
            print(n)
        print(f"count={len(names)}", file=sys.stderr)
    else:
        print(len(names))


if __name__ == "__main__":
    main()
