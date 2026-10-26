#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The bundle producer's secrets never reach a log or a `Debug` output.

# What is held

`SO-D12` increment 4c (`ARCHIVAL_SETTLEMENT_WRITER.md` §16): the witness
ring holds every witness secret key and seed in memory only (ruling Q10),
and the challenge reads present nonces from which their SOCKS credentials
derive, which nothing of ours logs (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.3,
`SF-D3`). So in the production sources of the producer:

  1. no format-taking macro (`format!`, `write!`, `println!`, the
     `tracing` macros, `panic!`, `assert!`, ...) or `#[error(...)]`
     message names a seed, a nonce, a secret, or a type that holds one,
     among its arguments;
  2. no type that holds one derives `Debug`: a derived `Debug` prints every
     field, and a struct is printed by `{:?}` wherever it travels.

A doc comment may say "seed"; a format string may not print one.

# What is scanned

The production sources of `rust/shekyl-bundle-producer/src` (test files,
`*_tests.rs`, are out), the ingest crate's driver of it,
`rust/shekyl-chain-ingest/src/bundle_producer.rs`, and the connector's
messages that carry a block's seed, `connector_bundles.rs`.

# Rule 47

The gate asserts its subject before it judges: every scanned file exists,
the ring still holds `struct WitnessSecrets`, and the scan finds format
macros to read (a gate over zero invocations is not a gate). `--selftest`
proves each limb reports its planted case and passes a clean file.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CRATE = REPO / "rust" / "shekyl-bundle-producer" / "src"
INGEST = REPO / "rust" / "shekyl-chain-ingest" / "src"
# The driver, and the connector's messages that carry a block's seed.
DRIVERS = (INGEST / "bundle_producer.rs", INGEST / "connector_bundles.rs")

# Whole-word names that are, or carry, a secret here.
FORBIDDEN = (
    "seed",
    "seeds",
    "nonce",
    "nonces",
    "secret",
    "secrets",
    "FnDsaHybridSecretKey",
    "WitnessSecrets",
    "Zeroizing",
)
FORBIDDEN_RE = re.compile(r"\b(" + "|".join(FORBIDDEN) + r")\b")

MACROS = (
    "format",
    "format_args",
    "write",
    "writeln",
    "print",
    "println",
    "eprint",
    "eprintln",
    "panic",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "unreachable",
    "todo",
    "info",
    "warn",
    "error",
    "debug",
    "trace",
    "event",
)
MACRO_RE = re.compile(
    r"(?:\b(?:tracing::)?(" + "|".join(MACROS) + r")!|#\[(error))\s*[\(\[\{]"
)

# A field whose type or name is a secret.
SECRET_FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*([^,]+),?\s*$"
)


def strip_comments(text: str) -> str:
    """Drop `//` comments (doc comments included) and block comments, so
    prose about seeds does not trip the scan. String literals are kept:
    a format string is the subject."""
    out = []
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def macro_args(text: str, start: int) -> str:
    """The balanced argument span opened at `start` (the bracket)."""
    opener = text[start]
    closer = {"(": ")", "[": "]", "{": "}"}[opener]
    depth = 0
    i = start
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
        i += 1
    return text[start + 1 :]


def format_findings(path: Path, text: str) -> tuple[list[str], int]:
    """Format macros whose arguments name a secret; and how many macros
    were read."""
    code = strip_comments(text)
    findings = []
    count = 0
    for m in MACRO_RE.finditer(code):
        count += 1
        bracket = m.end() - 1
        args = macro_args(code, bracket)
        hit = FORBIDDEN_RE.search(args)
        if hit:
            line = code.count("\n", 0, m.start()) + 1
            site = f"{m.group(1)}!" if m.group(1) else "#[error]"
            findings.append(
                f"{path}:{line}: `{site}` names `{hit.group(1)}` in its arguments"
            )
    return findings, count


def derive_findings(path: Path, text: str) -> list[str]:
    """Types that derive `Debug` and hold a secret field."""
    code = strip_comments(text)
    findings = []
    lines = code.split("\n")
    for idx, line in enumerate(lines):
        if not re.match(r"^\s*#\[derive\(", line) or "Debug" not in line:
            continue
        # The item the attributes sit on: skip further attributes.
        j = idx + 1
        while j < len(lines) and re.match(r"^\s*#\[", lines[j]):
            j += 1
        if j >= len(lines):
            continue
        item = lines[j]
        m = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)", item)
        if not m:
            continue
        name = m.group(2)
        depth = item.count("{") - item.count("}")
        k = j + 1
        body = []
        if "(" in item and "{" not in item:
            body.append(item)
        while depth > 0 and k < len(lines):
            body.append(lines[k])
            depth += lines[k].count("{") - lines[k].count("}")
            k += 1
        for field in body:
            hit = FORBIDDEN_RE.search(field)
            if hit:
                findings.append(
                    f"{path}:{idx + 1}: `{name}` derives Debug and holds `{hit.group(1)}`"
                )
                break
    return findings


def production_files() -> list[Path]:
    files = sorted(
        p for p in CRATE.glob("*.rs") if not p.name.endswith("_tests.rs")
    )
    files.extend(DRIVERS)
    return files


def judge(files: list[Path]) -> tuple[list[str], int]:
    findings = []
    total = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        found, count = format_findings(path, text)
        findings += found
        findings += derive_findings(path, text)
        total += count
    return findings, total


def selftest() -> int:
    cases = {
        "format": ('fn f(seed: u8) { tracing::info!("seed {}", seed); }\n', 1),
        "write": ('fn f(x: &X) { let _ = write!(out, "{:?}", x.nonce); }\n', 1),
        "derive": (
            "#[derive(Clone, Debug)]\nstruct Leaky {\n    seed: Zeroizing<[u8; 32]>,\n}\n",
            1,
        ),
        "error_attribute": (
            '#[derive(thiserror::Error)]\nenum E {\n    #[error("bad seed {0}")]\n    A(u8),\n}\n',
            1,
        ),
        "doc_only": (
            "/// The seed is wiped.\nfn f() { tracing::info!(\"filed {}\", 3); }\n",
            0,
        ),
        "manual_debug": (
            "#[derive(Clone)]\nstruct Quiet {\n    seed: Zeroizing<[u8; 32]>,\n}\n"
            'fn g() { let _ = format!("{}", 1); }\n',
            0,
        ),
    }
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, (body, expected) in cases.items():
            path = Path(tmp) / f"{name}.rs"
            path.write_text(body, encoding="utf-8")
            findings, _ = judge([path])
            if len(findings) != expected:
                print(
                    f"FAIL: selftest `{name}` expected {expected} finding(s), got "
                    f"{len(findings)}: {findings}",
                    file=sys.stderr,
                )
                failed = 1
    if not failed:
        print("OK: selftest: each planted secret is reported and clean files pass")
    return failed


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    files = production_files()
    for path in files:
        if not path.is_file():
            print(f"FAIL: {path} not found; the producer moved, update this gate", file=sys.stderr)
            return 1
    ring = (CRATE / "ring.rs").read_text(encoding="utf-8")
    if "struct WitnessSecrets" not in ring:
        print("FAIL: ring.rs no longer holds `struct WitnessSecrets`; update this gate", file=sys.stderr)
        return 1
    findings, total = judge(files)
    if total == 0:
        print("FAIL: no format macro was read; the scan has no subject", file=sys.stderr)
        return 1
    if findings:
        print("FAIL: a producer secret can reach a log or a Debug output:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(files)} producer source(s), {total} format macro(s): no seed, nonce or "
        "secret key in a format argument or a derived Debug"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
