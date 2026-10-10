#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""Production shekyl-relay and shekyl-relay-privacy name no connector.

Tor is a connector, not a Dandelion++ variant (DAEMON_RELAY_PRIVACY.md
§98.4, structure ruling 2026-10-09). The relay keys on declaration
cells (`address_hidden_from_peer`, `cover_class`), never on which
connector produced them.

This catches direct naming: any `ConnectorId::<Variant>` or
`NetworkColumn::<Variant>` — a variant is an upper-case path segment
whose second character is not upper-case, so `ConnectorId::ALL` and
`ConnectorId::COUNT` (the whole-list constants a connector-agnostic
walk uses) pass and `ConnectorId::Tor`, `::Clearnet`, or a connector
added later fail — plus a position comparison `.index() ==` and
`ALL[<literal>]`. It does not cover a renamed import
(`use ConnectorId::Tor as Hidden`).

Those spellings under `rust/shekyl-relay/src` and
`rust/shekyl-relay-privacy/src` may appear only in `#[cfg(test)]`
code: a file declared by `#[cfg(test)] mod name;` or lines inside an
inline `#[cfg(test)] mod name { ... }`. A hit anywhere else is a branch
on connector identity. Zero hits in test code across both roots means
this gate's subject is gone.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRCS = (
    ("rust/shekyl-relay/src", ROOT / "rust" / "shekyl-relay" / "src"),
    ("rust/shekyl-relay-privacy/src", ROOT / "rust" / "shekyl-relay-privacy" / "src"),
)
# A variant: `::` then an upper-case letter not followed by another
# upper-case letter. `ALL` and `COUNT` are not variants.
PAT = re.compile(
    r"ConnectorId::[A-Z](?:[a-z0-9]\w*)?\b"
    r"|NetworkColumn::[A-Z](?:[a-z0-9]\w*)?\b"
    r"|\.index\(\)\s*=="
    r"|ALL\[\d+\]"
)
DECL = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[.*\]\s*)*mod\s+([A-Za-z0-9_]+)\s*;", re.M)


def rust_code(text: str) -> str:
    """Code with comments and literals blanked, newlines kept.

    Brace depth and the connector pattern then see Rust syntax. A
    `{` inside a string, a `// #[cfg(test)]` comment, and a connector
    name in a comment or a literal do not.
    """
    out: list[str] = []
    i = 0
    n = len(text)

    def ident(ch: str) -> bool:
        return ch.isalnum() or ch == "_"

    def blank_until(end: int) -> None:
        nonlocal i
        while i < end and i < n:
            out.append("\n" if text[i] == "\n" else " ")
            i += 1

    def blank_cooked(quote_at: int) -> None:
        nonlocal i
        i = quote_at
        out.append(" ")
        i += 1
        while i < n:
            if text[i] == "\n":
                out.append("\n")
                i += 1
                continue
            if text[i] == "\\":
                out.append(" ")
                i += 1
                if i < n:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
                continue
            if text[i] == '"':
                out.append(" ")
                i += 1
                return
            out.append(" ")
            i += 1

    def blank_raw(quote_at: int, hashes: int) -> None:
        nonlocal i
        i = quote_at
        out.append(" ")
        i += 1
        terminator = '"' + ("#" * hashes)
        while i < n:
            if text.startswith(terminator, i):
                blank_until(i + len(terminator))
                return
            out.append("\n" if text[i] == "\n" else " ")
            i += 1

    def blank_char(quote_at: int) -> None:
        nonlocal i
        i = quote_at
        out.append(" ")
        i += 1
        if i < n and text[i] == "\\":
            out.append(" ")
            i += 1
            if i < n and text[i] == "u" and i + 1 < n and text[i + 1] == "{":
                while i < n and text[i] != "}":
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            if i < n:
                out.append(" ")
                i += 1
        elif i < n:
            out.append(" ")
            i += 1
        if i < n and text[i] == "'":
            out.append(" ")
            i += 1

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and nxt == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        at_token = i == 0 or not ident(text[i - 1])
        if at_token and c in "bcr":
            j = i
            if text[j] in "bc":
                j += 1
            raw = j < n and text[j] == "r"
            if raw:
                j += 1
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and text[j] == '"':
                    blank_until(j)
                    blank_raw(j, hashes)
                    continue
            elif j < n and text[j] in "'\"":
                if text[j] == "'":
                    blank_until(j)
                    blank_char(j)
                else:
                    blank_until(j)
                    blank_cooked(j)
                continue
        if c == '"':
            blank_cooked(i)
            continue
        if c == "'":
            if nxt == "\\" or (nxt != "" and not ident(nxt) and nxt != "'"):
                blank_char(i)
                continue
            if ident(nxt) and i + 2 < n and text[i + 2] == "'" and not ident(text[i + 1]):
                blank_char(i)
                continue
        out.append(c)
        i += 1
    return "".join(out)


def test_files(root: Path) -> set[str]:
    """Files whose whole body is a `#[cfg(test)] mod name;`."""
    found: set[str] = set()
    if not root.is_dir():
        return found
    for path in root.rglob("*.rs"):
        text = rust_code(path.read_text(encoding="utf-8"))
        for name in DECL.findall(text):
            parent = path.parent
            for candidate in (parent / f"{name}.rs", parent / name / "mod.rs"):
                if candidate.is_file():
                    found.add(candidate.relative_to(root).as_posix())
    return found


def test_line_spans(lines: list[str]) -> set[int]:
    """Lines inside an inline `#[cfg(test)] mod name { ... }`."""
    spans: set[int] = set()
    pending = False
    depth = 0
    active = False
    start_depth = 0
    for number, line in enumerate(lines, 1):
        if "#[cfg(test)]" in line:
            pending = True
        opens = line.count("{")
        closes = line.count("}")
        if pending and re.search(r"\bmod\b", line) and "{" in line:
            active = True
            start_depth = depth
            pending = False
        depth += opens - closes
        if active:
            spans.add(number)
            if depth <= start_depth:
                active = False
        elif not line.strip().startswith("#["):
            pending = False
    return spans


def scan(root: Path, label: str = "") -> tuple[list[str], list[str]]:
    """Hits under `root`, reported as `label/path:line` (`path:line` unlabelled)."""
    production: list[str] = []
    tests: list[str] = []
    if not root.is_dir():
        return production, tests
    whole = test_files(root)
    for path in sorted(root.rglob("*.rs")):
        rel_in_root = path.relative_to(root).as_posix()
        rel = f"{label}/{rel_in_root}" if label else rel_in_root
        lines = rust_code(path.read_text(encoding="utf-8")).splitlines()
        inline = test_line_spans(lines)
        for number, line in enumerate(lines, 1):
            if not PAT.search(line):
                continue
            hit = f"{rel}:{number}"
            if rel_in_root in whole or number in inline:
                tests.append(hit)
            else:
                production.append(hit)
    return production, tests


def scan_all(
    roots: tuple[tuple[str, Path], ...],
) -> tuple[list[str], list[str], list[str]]:
    """Hits across `roots`, and the labels of roots that are not directories.

    A missing root is reported, not skipped: `scan` returns nothing for a
    path that is not there, so without this a renamed or mistyped crate
    path would leave the gate green on the other root's hits alone
    (rule 47).
    """
    production: list[str] = []
    tests: list[str] = []
    missing: list[str] = []
    for label, root in roots:
        if not root.is_dir():
            missing.append(label)
            continue
        found_production, found_tests = scan(root, label)
        production.extend(found_production)
        tests.extend(found_tests)
    return production, tests, missing


def judge(production: list[str], tests: list[str], missing: list[str] = ()) -> int:
    failed = False
    if missing:
        print(
            "relay connector gate: a configured source root is not a directory; "
            "the subject moved or the path is wrong",
            file=sys.stderr,
        )
        for label in missing:
            print(label, file=sys.stderr)
        failed = True
    if production:
        print("relay connector gate: a production file names a connector", file=sys.stderr)
        for hit in production:
            print(hit, file=sys.stderr)
        failed = True
    if not tests:
        print(
            "relay connector gate: no test-module matches; the subject is absent",
            file=sys.stderr,
        )
        failed = True
    if failed:
        return 1
    print(f"relay connector gate: {len(tests)} test-module matches, 0 production")
    return 0


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        graph = root / "graph"
        graph.mkdir()
        (graph / "tests.rs").write_text(
            "fn t() { let _ = ConnectorId::Clearnet; }\n",
            encoding="utf-8",
        )
        samples = (
            "let _ = ConnectorId::Tor;\n",
            "let _ = ConnectorId::I2p;\n",
            "let _ = NetworkColumn::Clearnet;\n",
            "let _ = id.index() == 0;\n",
            "let _ = ALL[1];\n",
        )
        for sample in samples:
            (graph / "mod.rs").write_text(
                sample + "#[cfg(test)]\nmod tests;\n",
                encoding="utf-8",
            )
            production, tests = scan(root)
            if judge(production, tests) == 0:
                print(f"selftest: a production hit was accepted: {sample!r}", file=sys.stderr)
                return 1
        (graph / "mod.rs").write_text("fn prod() {}\n#[cfg(test)]\nmod tests;\n", encoding="utf-8")
        production, tests = scan(root)
        if judge(production, tests) != 0:
            print("selftest: a test-only tree was refused", file=sys.stderr)
            return 1
        (graph / "mod.rs").write_text(
            "fn prod() { let _ = ConnectorId::ALL.len() + ConnectorId::COUNT; }\n"
            "#[cfg(test)]\nmod tests;\n",
            encoding="utf-8",
        )
        production, tests = scan(root)
        if judge(production, tests) != 0:
            print("selftest: the whole-list constants were judged a variant", file=sys.stderr)
            return 1
        (graph / "mod.rs").write_text("fn prod() {}\n#[cfg(test)]\nmod tests;\n", encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp2:
            second = Path(tmp2)
            (second / "stem_map").mkdir()
            (second / "stem_map" / "mod.rs").write_text(
                "fn prod() { let _ = ConnectorId::Tor; }\n",
                encoding="utf-8",
            )
            production, tests, missing = scan_all((("first", root), ("second", second)))
            if (
                missing
                or judge(production, tests, missing) == 0
                or production != ["second/stem_map/mod.rs:1"]
            ):
                print(f"selftest: a hit in the second root was not reported: {production}", file=sys.stderr)
                return 1
        # A root that is not there is refused, however green the other is.
        production, tests, missing = scan_all((("first", root), ("gone", root / "no-such-crate")))
        if missing != ["gone"] or judge(production, tests, missing) == 0:
            print(f"selftest: a missing root was accepted: {missing}", file=sys.stderr)
            return 1
        (graph / "tests.rs").write_text("fn t() {}\n", encoding="utf-8")
        production, tests = scan(root)
        if judge(production, tests) == 0:
            print("selftest: an empty subject was accepted", file=sys.stderr)
            return 1
        (graph / "tests.rs").write_text("fn t() {}\n", encoding="utf-8")
        (graph / "mod.rs").write_text(
            "#[cfg(test)]\n"
            "mod tests {\n"
            '    let _ = "{";\n'
            "    let _ = ConnectorId::Clearnet;\n"
            "}\n"
            "fn prod() { let _ = ConnectorId::Tor; }\n",
            encoding="utf-8",
        )
        production, tests = scan(root)
        if not any(hit.startswith("graph/mod.rs:") for hit in production) or not tests:
            print(
                f"selftest: a string brace hid a production hit: {production} {tests}",
                file=sys.stderr,
            )
            return 1
        (graph / "tests.rs").write_text(
            "fn t() { let _ = ConnectorId::Clearnet; }\n",
            encoding="utf-8",
        )
        (graph / "production.rs").write_text(
            "fn prod() { let _ = ConnectorId::Tor; }\n",
            encoding="utf-8",
        )
        (graph / "mod.rs").write_text(
            "// #[cfg(test)]\nmod production;\n#[cfg(test)]\nmod tests;\n",
            encoding="utf-8",
        )
        production, tests = scan(root)
        if judge(production, tests) == 0:
            print("selftest: a comment exempted a production file", file=sys.stderr)
            return 1
        (graph / "production.rs").write_text("fn prod() {}\n", encoding="utf-8")
        (graph / "mod.rs").write_text(
            "// ConnectorId::Tor\n"
            'const NOTE: &str = "ConnectorId::Clearnet";\n'
            "fn prod() {}\n"
            "#[cfg(test)]\n"
            "mod tests;\n",
            encoding="utf-8",
        )
        production, tests = scan(root)
        if judge(production, tests) != 0:
            print("selftest: a comment or a literal was judged production", file=sys.stderr)
            return 1
    print(
        "relay connector gate selftest: production hit (named and unnamed variant), "
        "test-only, whole-list constants, second root, missing root, empty subject, "
        "string brace, comment exemption, and literal"
    )
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) != 1:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        return 2
    return judge(*scan_all(SRCS))


if __name__ == "__main__":
    sys.exit(main())
