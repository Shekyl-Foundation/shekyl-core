#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A feature never changes a public type's shape.

# The rule

Rule 25 (Rick, 2026-11-18): a variant of a `pub` enum, and a `pub` field
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
blanked first, offsets kept, so prose and strings never match. Each `{`
or `(` is attributed to the item header before it, and an attribute
directly inside a `pub enum`'s or `pub struct`'s body applies to the
member that follows it.

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
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# (path from the repo root, type, member) -> who removes the row, and how.
# Rows come off; none are added. A new case makes the member unconditional.
ALLOWED: dict[tuple[str, str, str], str] = {
    (
        "rust/shekyl-chain-ingest/src/service.rs",
        "Follow",
        "producer",
    ): "SO-D12 lane (increment 4c, 39805a1787): the field becomes unconditional",
}

HEADER = re.compile(r"(?:^|[\s;}{\]])((?:pub(?:\s*\([^)]*\))?\s+)?)(enum|struct|union)\s+(\w+)")
CANDIDATE = re.compile(r"#\[\s*cfg\s*\([^\]]*\bfeature\s*=")
PUB_TYPE = re.compile(r"(?m)^\s*pub\s+(?:enum|struct|union)\s+\w+")
MEMBER = re.compile(r"(?:\s*#\[[^\]]*\])*\s*((?:pub(?:\s*\([^)]*\))?\s+)?)(\w+)")


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


def scan(src: str) -> tuple[list[tuple[int, str, str, str]], int]:
    """(line, type, member, attribute) for each feature-gated member of a
    `pub` enum or a `pub` field of a `pub` struct; and how many `pub`
    enums and structs were judged."""
    text = blank(src)
    stack: list[tuple[str, str | None, bool]] = []
    last = 0
    hits = []
    judged = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#" and (text.startswith("[", i + 1) or text.startswith("![", i + 1)):
            end = attr_end(text, i)
            attr = re.sub(r"\s+", " ", src[i:end])
            top = stack[-1] if stack else None
            if top and top[2] and top[0] in ("enum", "struct") and re.match(r"#\[\s*cfg\s*\(", attr) and re.search(r"\bfeature\s*=", attr):
                m = MEMBER.match(text, end)
                vis = m.group(1).strip() if m else ""
                if m and (top[0] == "enum" or vis == "pub"):
                    hits.append((text.count("\n", 0, i) + 1, top[1] or "?", m.group(2), attr))
            i = end
            continue
        # Only `;`, `{` and `}` end an item header: a `(` or a `,` can sit
        # inside one (`pub struct W<F: Fn(u8)>`, a `where` clause), and
        # the header keyword is what makes a body a type's.
        if c in "{(":
            head = text[last:i]
            found = None
            for found in HEADER.finditer(head):
                pass
            if found and not re.search(r"[;={}]", head[found.end() :]):
                public = found.group(1).strip() == "pub"
                if public and c == "{":
                    judged += 1
                stack.append((found.group(2), found.group(3), public))
            else:
                stack.append(("other", None, False))
            if c == "{":
                last = i + 1
        elif c in "})":
            if stack:
                stack.pop()
            if c == "}":
                last = i + 1
        elif c == ";":
            last = i + 1
        i += 1
    return hits, judged


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
                # The full scan only where a feature cfg can be: elsewhere
                # it has nothing to find, and the pub types are counted for
                # rule 47 alone.
                if CANDIDATE.search(src):
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
                "gate the code that constructs it instead (rule 25)"
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
}


def selftest() -> int:
    failed = 0
    # Every scan case also holds one plain pub struct, so a scan that
    # judged nothing fails the case rather than passing it empty.
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
        print(f"selftest: {len(SELFTEST)} scan cases, 5 gate cases")
    return failed


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    return check(REPO, ALLOWED)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
