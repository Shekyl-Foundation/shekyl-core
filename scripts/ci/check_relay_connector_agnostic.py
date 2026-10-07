#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""Production shekyl-relay does not name Clearnet or Tor.

`ConnectorId::Clearnet` and `ConnectorId::Tor` under
`rust/shekyl-relay/src` may appear only in the test modules. A hit
anywhere else is a branch on connector identity. Zero hits in the
test modules means this gate's subject is gone.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "rust" / "shekyl-relay" / "src"
PAT = re.compile(r"ConnectorId::(Clearnet|Tor)")
DECL = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[.*\]\s*)*mod\s+([A-Za-z0-9_]+)\s*;", re.M)


def test_files(root: Path) -> set[str]:
    """Files whose whole body is a `#[cfg(test)] mod name;`."""
    found: set[str] = set()
    if not root.is_dir():
        return found
    for path in root.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
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


def scan(root: Path) -> tuple[list[str], list[str]]:
    production: list[str] = []
    tests: list[str] = []
    if not root.is_dir():
        return production, tests
    whole = test_files(root)
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        inline = test_line_spans(lines)
        for number, line in enumerate(lines, 1):
            if not PAT.search(line):
                continue
            hit = f"{rel}:{number}"
            if rel in whole or number in inline:
                tests.append(hit)
            else:
                production.append(hit)
    return production, tests


def judge(production: list[str], tests: list[str]) -> int:
    if not tests:
        print(
            "relay connector gate: no test-module matches; the subject is absent",
            file=sys.stderr,
        )
        return 1
    if production:
        print("relay connector gate: a production file names a connector", file=sys.stderr)
        for hit in production:
            print(hit, file=sys.stderr)
        return 1
    print(f"relay connector gate: {len(tests)} test-module matches, 0 production")
    return 0


def selftest() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        graph = root / "graph"
        graph.mkdir()
        (graph / "mod.rs").write_text(
            "fn prod() { let _ = ConnectorId::Tor; }\n#[cfg(test)]\nmod tests;\n",
            encoding="utf-8",
        )
        (graph / "tests.rs").write_text("fn t() { let _ = ConnectorId::Clearnet; }\n", encoding="utf-8")
        production, tests = scan(root)
        if judge(production, tests) == 0:
            print("selftest: a production hit was accepted", file=sys.stderr)
            return 1
        (graph / "mod.rs").write_text("fn prod() {}\n#[cfg(test)]\nmod tests;\n", encoding="utf-8")
        production, tests = scan(root)
        if judge(production, tests) != 0:
            print("selftest: a test-only tree was refused", file=sys.stderr)
            return 1
        (graph / "tests.rs").write_text("fn t() {}\n", encoding="utf-8")
        production, tests = scan(root)
        if judge(production, tests) == 0:
            print("selftest: an empty subject was accepted", file=sys.stderr)
            return 1
    print("relay connector gate selftest: production hit, test-only, and empty subject")
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) != 1:
        print(f"usage: {sys.argv[0]} [--selftest]", file=sys.stderr)
        return 2
    return judge(*scan(SRC))


if __name__ == "__main__":
    sys.exit(main())
