#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A feature never changes a public type's shape.

# The rule

Rule 125 (Rick, 2026-11-18): a variant of a `pub` enum, and a `pub` field
of a `pub` struct, in a workspace crate carries no `#[cfg(...)]` that
names a feature. The member exists in every build; the feature gates the
code that constructs or fills it. Cargo unifies features across a build,
so a variant one crate's feature adds lands in every dependent's
exhaustive match: on 2026-11-17 `cargo check --workspace --all-features`
stopped compiling `shekyl-wallet-contract`, whose `From<OpenError>` names
every arm, on engine-core's `conformance`-only
`OpenError::StakeRngSelfCertFailed`. Nothing shipped that combination,
so no other check saw it.

Out of scope, because no other crate can name them: a private field, a
member of a `pub(crate)` (or narrower) type, and a member gated on
`cfg(test)` or a platform alone.

# What is held

  1. **No new case.** Every feature-gated member the scan finds is in
     `ALLOWED`.
  2. **The list only shrinks.** Every `ALLOWED` row still names a case
     the scan finds. The change that makes a member unconditional takes
     its row off, so a fixed case cannot come back unseen.

# The scan

The workspace members are read from `rust/Cargo.toml` (no cargo needed);
each member's `.rs` files are scanned. Comments and string literals are
blanked first, offsets kept, so prose and strings never match.

A `{` or `(` opens a type body only at item depth, when the header before
it names an `enum`, `struct` or `union`. A header ends at a depth-zero
`;`, `{` or `}`. An `=` does not end it: a default (`T = u8`,
`const N: usize = 4`, including `= { ... }`) and an associated type
(`Item = u8`) are part of the header. Delimiter depth is one cursor, shared
by that decision, by tuple-field numbers and by which `;` ends an item.

An outer `#[cfg]` directly inside a `pub enum` or a `pub struct` is read
blanked, so a comment cannot supply `feature`. It applies to the member
that follows: a variant name, a `pub` field name, or, for a tuple field,
that field's position (`"0"`, `"1"`, …).

# Rule 47

The gate asserts its subject: it read Rust files from every member and
found `pub enum`s and `pub struct`s to judge. `--selftest` plants each
case in a scratch tree, proves each limb reports it, and proves the
out-of-scope cases and a clean tree pass.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

REPO = Path(__file__).resolve().parents[2]

# (path from the repo root, type, member) -> who removes the row, and how.
# Rows come off; none are added. A new case makes the member unconditional.
ALLOWED: dict[tuple[str, str, str], str] = {}

HEADER = re.compile(r"(?:^|[\s;}{\]])((?:pub(?:\s*\([^)]*\))?\s+)?)(enum|struct|union)\s+(\w+)")
PUB_TYPE = re.compile(r"(?m)^\s*pub\s+(?:enum|struct|union)\s+\w+")
# A depth-zero member of this set ends an item. `=` is not in it.
ITEM_ENDS = frozenset(";{}")
_VIS = re.compile(r"pub(?:\s*\([^)]*\))?")
_IDENT = re.compile(r"[A-Za-z_]\w*")
# A tuple field whose type does not start with a name: `[u8; 8]`, `&'a [u8]`,
# `(u8, u8)`, `*const u8`, `<T as Trait>::Item`.
_TYPE_PUNCT = frozenset("[(&*<")


class Open(NamedTuple):
    """A `{` or `(` the walk has not closed.

    `kind` is `enum`, `struct`, `union` or `other`. A union is tracked so a
    cfg inside it is not read as a field of the enclosing struct; the rule
    does not flag union fields. `positional` is a tuple struct, and `opener`
    is the index its field numbers are counted from. `bounds` is true when
    this `{` is an item boundary: the cursor moves on it and on its match.
    A `{` inside a header (`const N: usize = { 4 }`) does not bound.
    """

    kind: str
    name: str | None
    public: bool
    positional: bool
    opener: int
    bounds: bool


@dataclass
class Depth:
    """Delimiter depth of one walk.

    `<>` counts only while `()`, `[]` and `{}` are closed, and the `>` of
    `->` does not close it. `;` never occurs inside `<...>`, so a `;` clears
    an angle that a comparison (`a < b`) opened. The walk, the header
    measure and the tuple-field count all step through `see`.
    """

    paren: int = 0
    bracket: int = 0
    brace: int = 0
    angle: int = 0

    def others_closed(self) -> bool:
        return self.paren == self.bracket == self.brace == 0

    def at_zero(self) -> bool:
        return self.others_closed() and self.angle == 0

    def see(self, text: str, i: int) -> None:
        c = text[i]
        if c == "(":
            self.paren += 1
        elif c == ")" and self.paren:
            self.paren -= 1
        elif c == "[":
            self.bracket += 1
        elif c == "]" and self.bracket:
            self.bracket -= 1
        elif c == "{":
            self.brace += 1
        elif c == "}" and self.brace:
            self.brace -= 1
        elif c == "<" and self.others_closed() and _opens_generic(text, i):
            self.angle += 1
        elif c == ">" and self.angle and self.others_closed() and not _arrow_tail(text, i):
            self.angle -= 1
        elif c == ";" and self.others_closed():
            self.angle = 0


def _opens_generic(text: str, i: int) -> bool:
    """`<` after a path (`Vec<`, `Foo::<`, `<T as Trait>`) rather than a shift.

    A digit (`1 << 3`, `1 < 2`) is not a path. Inside `[]` or `()` the
    caller does not ask: a const expr there is not a generic.
    """
    j = i - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j < 0:
        return True
    prev = text[j]
    if prev.isdigit() or prev == "<":
        return False
    return prev.isalnum() or prev in "_:(,="


def _arrow_tail(text: str, i: int) -> bool:
    """The `>` of `->`. A function type's arrow is not the end of `<...>`."""
    return i > 0 and text[i - 1] == "-"


def _measure(text: str) -> tuple[Depth, bool, int]:
    """Depth at the end, whether a depth-zero item end occurred, and how
    many depth-zero commas the span holds."""
    depth = Depth()
    ended = False
    commas = 0
    for i, c in enumerate(text):
        if c in ITEM_ENDS and depth.others_closed() and (c == ";" or depth.angle == 0):
            ended = True
        elif c == "," and depth.at_zero():
            commas += 1
        depth.see(text, i)
    return depth, ended, commas


def blank(src: str) -> str:
    """Comments, string, byte-string, raw-string and char literals replaced
    by spaces; newlines and every offset kept."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif src.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif (m := re.match(r'b?r(#*)"', src[i : i + 260])) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            end = '"' + m.group(1)
            j = src.find(end, i + len(m.group(0)))
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == '"' or (src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "'" and (m := re.match(r"'(\\.[^']{0,8}|[^\\'])'", src[i : i + 12])):
            out.append(" " * len(m.group(0)))
            i += len(m.group(0))
        else:
            out.append(c)
            i += 1
    return "".join(out)


def attr_end(text: str, i: int) -> int:
    """Offset just past the attribute that starts at `text[i] == '#'`."""
    j = text.index("[", i)
    depth = 0
    while j < len(text):
        if text[j] == "[":
            depth += 1
        elif text[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(text)


def _body_of(head: str) -> tuple[str, str, bool] | None:
    """The type whose body the opener after `head` starts, if it is one.

    The last `enum` / `struct` / `union` in `head` wins. Its tail is still
    the header when nothing in `ITEM_ENDS` has occurred at item depth and
    the tail's delimiters are closed: `T = u8`, `Item = u8` and
    `const N: usize = { 4 }` are tail, not a body.
    """
    found = None
    for found in HEADER.finditer(head):
        pass
    if found is None:
        return None
    depth, ended, _commas = _measure(head[found.end() :])
    if ended or not depth.at_zero():
        return None
    return found.group(2), found.group(3), found.group(1).strip() == "pub"


def _names_feature(attr: str) -> bool:
    """True when this blanked attribute is a `#[cfg(...)]` that names a feature.

    Comments are already spaces, so a comment cannot supply the word, and a
    comment between `feature` and `=` cannot hide the predicate.
    """
    flat = re.sub(r"\s+", " ", attr)
    return re.match(r"#\[\s*cfg\s*\(", flat) is not None and re.search(r"\bfeature\s*=", flat) is not None


def _skip_space_and_attrs(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text.startswith("#[", i):
            i = attr_end(text, i)
        else:
            break
    return i


def _vis_is_name(text: str, vis: re.Match[str]) -> bool:
    """`pub` at the start of `publisher` is the field's name, not its visibility."""
    if vis.group(0) != "pub":
        return False
    end = vis.end()
    return end < len(text) and (text[end].isalnum() or text[end] == "_")


def _member_at(text: str, i: int) -> tuple[str, str | None] | None:
    """Visibility and name of the member whose attributes end at `i`.

    The name is the identifier. A `pub` tuple field whose type does not
    start with a name (`pub [u8; 8]`, `pub &'a [u8]`) has no name; the
    caller names it by position.
    """
    i = _skip_space_and_attrs(text, i)
    if i >= len(text):
        return None
    vis = ""
    found = _VIS.match(text, i)
    if found and not _vis_is_name(text, found):
        vis = re.sub(r"\s+", "", found.group(0))
        i = _skip_space_and_attrs(text, found.end())
        if i >= len(text):
            return None
    ident = _IDENT.match(text, i)
    if ident:
        return vis, ident.group(0)
    if vis == "pub" and text[i] in _TYPE_PUNCT:
        return vis, None
    return None


def _gated_member(top: Open, text: str, attr_at: int, member_from: int) -> str | None:
    """The member a feature cfg gates, or None when the cfg is out of scope.

    Enum: the variant. Braced struct: the field name, and only when the
    field is `pub`. Tuple struct: the field's position, and only when the
    field is `pub`. Position is the member's identity; tuple fields have
    no names, and two fields can share a type.
    """
    if not top.public or top.kind not in ("enum", "struct"):
        return None
    found = _member_at(text, member_from)
    if found is None:
        return None
    vis, name = found
    if top.kind == "enum":
        return name
    if vis != "pub":
        return None
    if top.positional:
        _depth, _ended, commas = _measure(text[top.opener + 1 : attr_at])
        return str(commas)
    return name


def scan(src: str) -> tuple[list[tuple[int, str, str, str]], int]:
    """(line, type, member, attribute) for each feature-gated member of a
    `pub` enum or a `pub` field of a `pub` struct, and how many braced
    `pub` enums and structs were judged.

    A tuple or unit struct is not counted: a `(` inside `Fn(u8)` is the
    same character as a tuple-struct opener, and the count is rule 47's
    proof that a body was judged, not a census of every type form.
    """
    text = blank(src)
    stack: list[Open] = []
    depth = Depth()
    cursor = 0
    hits: list[tuple[int, str, str, str]] = []
    judged = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        outer = i + 1 < n and text[i + 1] == "["
        if c == "#" and (outer or text.startswith("![", i + 1)):
            end = attr_end(text, i)
            # An inner `#![...]` applies to the enclosing item, not the
            # next member. Only an outer `#[cfg]` can gate a member.
            if outer and stack and _names_feature(text[i:end]):
                member = _gated_member(stack[-1], text, i, end)
                if member is not None:
                    attr = re.sub(r"\s+", " ", src[i:end]).strip()
                    name = stack[-1].name or "?"
                    hits.append((text.count("\n", 0, i) + 1, name, member, attr))
            i = end
            continue
        if c in "{(":
            opened = _body_of(text[cursor:i]) if depth.at_zero() else None
            if opened is None:
                stack.append(Open("other", None, False, False, i, c == "{" and depth.at_zero()))
            else:
                kind, name, public = opened
                positional = kind == "struct" and c == "("
                if public and c == "{":
                    judged += 1
                stack.append(Open(kind, name, public, positional, i, c == "{"))
            # `(` does not move the cursor. A where-clause `Fn(u8)` is at
            # item depth and looks like a tuple body; its `)` pops that
            # frame, and the real `{` is still in the header.
            if c == "{" and stack[-1].bounds:
                cursor = i + 1
        elif c == "}":
            frame = stack.pop() if stack else None
            if frame is not None and frame.bounds:
                cursor = i + 1
        elif c == ")":
            if stack:
                stack.pop()
        elif c == ";" and depth.others_closed():
            cursor = i + 1
        depth.see(text, i)
        i += 1
    return hits, judged


def may_gate_a_member(src: str) -> bool:
    """Superset of what `scan` can hit.

    The precise test is `_names_feature` on the blanked attribute. Both
    words survive a comment between them (`feature /* */ =`). Blanking
    cannot assemble a word a comment split (`feat/* */ure`).
    """
    return "cfg" in src and "feature" in src


def members(root: Path) -> list[str]:
    with open(root / "rust" / "Cargo.toml", "rb") as handle:
        return list(tomllib.load(handle)["workspace"]["members"])


def check(root: Path, allowed: dict[tuple[str, str, str], str]) -> int:
    crates = members(root)
    found: dict[tuple[str, str, str], tuple[int, str]] = {}
    files = judged = 0
    empty = []
    for crate in crates:
        base = root / "rust" / crate
        seen = 0
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in ("target", "fuzz"))
            for name in sorted(filenames):
                if not name.endswith(".rs"):
                    continue
                path = Path(dirpath) / name
                rel = path.relative_to(root).as_posix()
                src = path.read_text(encoding="utf-8", errors="replace")
                seen += 1
                # The full scan only where both words occur. Elsewhere it has
                # nothing to find, and the pub types are counted for rule 47.
                if may_gate_a_member(src):
                    hits, count = scan(src)
                else:
                    hits, count = [], len(PUB_TYPE.findall(src))
                judged += count
                for line, kind, member, attr in hits:
                    found[(rel, kind, member)] = (line, attr)
        files += seen
        if seen == 0:
            empty.append(crate)
    # Rule 47: the subject exists.
    if empty:
        print(f"::error::feature-gated members: no Rust file read from {', '.join(empty)}")
        return 1
    if judged == 0:
        print("::error::feature-gated members: no pub enum or pub struct was judged; the scan saw nothing")
        return 1
    failed = 0
    for key, (line, attr) in sorted(found.items()):
        if key not in allowed:
            path, kind, member = key
            print(
                f"::error file={path},line={line}::{kind}::{member} is gated by `{attr}`: "
                "a variant of a pub enum or a pub field of a pub struct exists in every build; "
                "gate the code that constructs it instead (rule 125)"
            )
            failed = 1
    for key, owner in sorted(allowed.items()):
        if key not in found:
            path, kind, member = key
            print(
                f"::error file={path}::{kind}::{member} is allowed but no longer feature-gated; "
                f"take its row off ALLOWED ({owner})"
            )
            failed = 1
    if not failed:
        print(
            f"feature-gated members: {len(crates)} crates, {files} files, {judged} pub enums and structs; "
            f"{len(found)} allowed case(s), none new"
        )
    return failed


SELFTEST = {
    # name: (source, the (type, member) cases the scan must report)
    "a gated variant of a pub enum": (
        'pub enum E {\n    A,\n    #[cfg(feature = "x")]\n    B(u8),\n}\n',
        [("E", "B")],
    ),
    "a gated pub field of a pub struct": (
        'pub struct S {\n    pub a: u8,\n    #[cfg(all(test, feature = "x"))]\n    pub b: u8,\n}\n',
        [("S", "b")],
    ),
    "a gated variant under a doc comment and a second attribute": (
        'pub enum E {\n    /// Text with a "string" and #[cfg(feature = "y")] in prose.\n'
        '    #[cfg(feature = "x")]\n    #[error("{0}")]\n    B(String),\n}\n',
        [("E", "B")],
    ),
    "a gated variant whose enum has a generic and a where clause": (
        'pub enum E<T>\nwhere\n    T: Clone,\n{\n    #[cfg(any(feature = "x", test))]\n    B { t: T },\n}\n',
        [("E", "B")],
    ),
    "a private field of a pub struct": (
        'pub struct S {\n    #[cfg(feature = "x")]\n    b: u8,\n}\n',
        [],
    ),
    "a pub(crate) field of a pub struct": (
        'pub struct S {\n    #[cfg(feature = "x")]\n    pub(crate) b: u8,\n}\n',
        [],
    ),
    "a gated variant of a pub(crate) enum": (
        'pub(crate) enum E {\n    #[cfg(feature = "x")]\n    B,\n}\n',
        [],
    ),
    "a variant gated on cfg(test) alone": (
        "pub enum E {\n    A,\n    #[cfg(test)]\n    B,\n}\n",
        [],
    ),
    "a gated item, not a member": (
        '#[cfg(feature = "x")]\npub enum E {\n    A,\n}\n#[cfg(feature = "x")]\npub fn f() {}\n',
        [],
    ),
    "a gated statement inside a pub enum's impl": (
        'pub enum E { A }\nimpl E {\n    pub fn f(&self) {\n        #[cfg(feature = "x")]\n        let _a = 1;\n    }\n}\n',
        [],
    ),
    "a defaulted struct": (
        'pub struct Engine<D = u8> {\n    #[cfg(feature = "x")]\n    pub field: D,\n}\n',
        [("Engine", "field")],
    ),
    "a defaulted enum, and an assignment is not a member": (
        'pub enum E<T = u8> {\n    #[cfg(feature = "x")]\n    A,\n}\n'
        'fn f() {\n    let _ = {\n        #[cfg(feature = "y")]\n        let y = 1;\n    };\n}\n',
        [("E", "A")],
    ),
    "an associated type in a where bound": (
        'pub struct Foo<T>\nwhere\n    T: Iterator<Item = u8>,\n{\n    #[cfg(feature = "x")]\n    pub field: T,\n}\n',
        [("Foo", "field")],
    ),
    "a const default in the header": (
        'pub struct S<const N: usize = 4> {\n    #[cfg(feature = "x")]\n    pub field: [u8; N],\n}\n',
        [("S", "field")],
    ),
    "a const block is the header, not the body": (
        'pub struct S<const N: usize = {\n    #[cfg(feature = "y")]\n    1\n}> {\n'
        '    #[cfg(feature = "x")]\n    pub field: u8,\n}\n',
        [("S", "field")],
    ),
    "a function type in the header": (
        'pub struct W<F: Fn(u8)> {\n    #[cfg(feature = "x")]\n    pub field: F,\n}\n',
        [("W", "field")],
    ),
    "a function type in a where clause": (
        'pub struct W<F>\nwhere\n    F: Fn(u8),\n{\n    #[cfg(feature = "x")]\n    pub field: F,\n}\n',
        [("W", "field")],
    ),
    "a comparison does not swallow the next type": (
        "const OK: bool = a < b;\npub struct S {\n    #[cfg(feature = \"x\")]\n    pub field: u8,\n}\n",
        [("S", "field")],
    ),
    "a public tuple field whose type is an array": (
        'pub struct S(#[cfg(feature = "x")] pub [u8; 8]);\n',
        [("S", "0")],
    ),
    "a public tuple field whose type is a reference": (
        "pub struct S(#[cfg(feature = \"x\")] pub &'a [u8]);\n",
        [("S", "0")],
    ),
    "a public tuple field whose type is a raw pointer": (
        'pub struct S(#[cfg(feature = "x")] pub *const u8);\n',
        [("S", "0")],
    ),
    "a comma inside generics is not a tuple field": (
        'pub struct S(Foo<Bar<u8, u8>, u8>, #[cfg(feature = "x")] pub [u8; 8]);\n',
        [("S", "1")],
    ),
    "a comma inside a function type is not a tuple field": (
        'pub struct S(fn(u8, u8) -> u8, #[cfg(feature = "x")] pub [u8; 8]);\n',
        [("S", "1")],
    ),
    "a shift inside an array length is not a generic": (
        'pub struct S(pub [u8; 1 << 3], #[cfg(feature = "x")] pub [u8; 8]);\n',
        [("S", "1")],
    ),
    "a qualified path's comma is not a tuple field": (
        'pub struct S(<u8 as Trait>::Item, #[cfg(feature = "x")] pub [u8; 8]);\n',
        [("S", "1")],
    ),
    "a pub(crate) tuple field whose type starts with punctuation": (
        'pub struct S(#[cfg(feature = "x")] pub(crate) [u8; 8]);\n',
        [],
    ),
    "a feature named around a comment": (
        'pub enum E {\n    #[cfg(feature /* note */ = "x")]\n    B,\n}\n',
        [("E", "B")],
    ),
    "a comment that names a feature": (
        'pub enum E {\n    #[cfg(test /* feature = "x" */)]\n    B,\n}\n',
        [],
    ),
    "a private field named publisher": (
        'pub struct S {\n    #[cfg(feature = "x")]\n    publisher: u8,\n}\n',
        [],
    ),
}


def selftest() -> int:
    failed = 0
    # Every scan case also holds one plain pub struct, so a scan that
    # judged nothing fails the case rather than passing it empty. A gate
    # case that plants a hit on a shape the scan might miss carries the
    # same anchor: `check` returns 1 when nothing was judged, and that
    # limb must not pass for a hit the scan never saw.
    anchor = "pub struct Anchor {\n    pub a: u8,\n}\n"
    for label, (source, expected) in SELFTEST.items():
        hits, judged = scan(anchor + source)
        got = [(kind, member) for _, kind, member, _ in hits]
        if got != expected or judged == 0:
            print(f"selftest FAIL: {label}: found {got}, want {expected} (judged {judged})")
            failed = 1
    # The whole gate on a scratch tree: a clean tree passes, a planted case
    # fails, an allowed case passes, and an allowed row with no case fails.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "rust" / "a" / "src").mkdir(parents=True)
        (root / "rust" / "Cargo.toml").write_text('[workspace]\nmembers = ["a"]\n', encoding="utf-8")
        lib = root / "rust" / "a" / "src" / "lib.rs"
        key = ("rust/a/src/lib.rs", "E", "B")
        cases = [
            ("a clean tree", "pub enum E {\n    A,\n    B,\n}\n", {}, 0),
            ("a planted gated variant", 'pub enum E {\n    A,\n    #[cfg(feature = "x")]\n    B,\n}\n', {}, 1),
            ("an allowed gated variant", 'pub enum E {\n    A,\n    #[cfg(feature = "x")]\n    B,\n}\n', {key: "t"}, 0),
            ("an allowed row whose case was fixed", "pub enum E {\n    A,\n    B,\n}\n", {key: "t"}, 1),
            ("a tree with nothing to judge", "fn f() {}\n", {}, 1),
            (
                "a planted variant on a defaulted enum",
                anchor + 'pub enum E<T = u8> {\n    #[cfg(feature = "x")]\n    A,\n}\n',
                {},
                1,
            ),
            (
                "a planted public tuple field beside a plain struct",
                anchor + 'pub struct S(#[cfg(feature = "x")] pub [u8; 8]);\n',
                {},
                1,
            ),
            (
                "a feature split from its equals by a comment",
                'pub enum E {\n    #[cfg(feature /* note */ = "x")]\n    B,\n}\n',
                {},
                1,
            ),
            (
                "a comment that only looks like a feature cfg",
                'pub enum E {\n    #[cfg(test /* feature = "x" */)]\n    B,\n}\n',
                {},
                0,
            ),
        ]
        for label, source, allowed, want in cases:
            lib.write_text(source, encoding="utf-8")
            # The planted failures' `::error` lines are captured: printed,
            # they would annotate a green job as red.
            said = io.StringIO()
            with contextlib.redirect_stdout(said):
                got = check(root, allowed)
            if got != want:
                print(f"selftest FAIL: {label}: gate exited {got}, want {want}\n{said.getvalue()}")
                failed = 1
    if not failed:
        print(f"selftest: {len(SELFTEST)} scan cases, {len(cases)} gate cases")
    return failed


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return check(REPO, ALLOWED)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
