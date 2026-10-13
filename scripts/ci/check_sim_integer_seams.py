#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The economics sim's fold files carry no float into an integer.

DQ-2G (`ARCHIVAL_WORK_PRECISION_AND_ESCALATION.md`): floats live in the
scenario and report layers; anything that mirrors a chain computation runs
in production's integer arithmetic; a float crosses into integers once, at
a named input boundary. The fold files are where chain quantities are
formed, so a float-to-integer cast in one of them, outside its test
module, is a float that reached a chain quantity. ESR-14
(`ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.20) removed the last of them;
this gate keeps them out.

What is read: each file in `FOLD_FILES`, as one text, up to its test
module (a `#[cfg(test)]` followed by `mod <name> {`; a `#[cfg(test)]` on
an item is not the boundary). String literals and comments are blanked
first, so a `//` or a `0.75` inside a report string is not read. The text
is then split at each `fn` into functions, and each function is read whole:
a cast whose operand began on an earlier line, or a function whose body is
on its own line, is read like any other. A cast is `as <integer type>`.
Its operand is the expression the cast applies to: a parenthesised group,
a method chain, or a name. The cast is a violation when the operand is
float-marked:

* it contains `as f64`, `as f32`, `f64::`, `f32::`, a float literal, or a
  float method (`floor`, `ceil`, `round`, `trunc`, `sqrt`, `powf`, `powi`,
  `exp`, `ln`, `log10`, `log2`);
* or it is, or ends in, a name the function bound to a float before the
  cast: a parameter typed `f64`/`f32`, or a `let` whose type is
  `f64`/`f32` or whose initialiser is float-marked.

A function named in `ALLOWED` with a reason is reported and not failed:
that is the list of exceptions the gate carries, and it is empty. An
`ALLOWED` entry that matches no cast fails the gate: an exclusion must
exclude a live subject, or it is a door left open (rule 47). A listed
file that is missing, or one in which no function was found before its
test module, fails the gate: absence of a subject is not a pass.

`--selftest` runs the reader on fixtures that hold each pattern class the
gate must catch, including the two line-crossing forms, and the forms it
must not, and fails if any is misread. The bundle runs it first.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIM = ROOT / "rust" / "shekyl-economics-sim" / "src"

# The fold files: where chain quantities are formed. `burden.rs` holds the
# honest chain's output count and the shard partition, which set the tree
# depth and the burden operand.
FOLD_FILES = [
    "chain_cursor.rs",
    "engine.rs",
    "budget.rs",
    "stage2.rs",
    "record.rs",
    "burden.rs",
]

# (file, function) -> reason. Empty: ESR-14 left no float-to-integer cast in
# a fold function. An entry here is a declared divergence and needs its §4
# row; an entry that matches nothing fails the gate.
ALLOWED: dict[tuple[str, str], str] = {}

INT_TYPES = r"(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize)"
CAST = re.compile(r"\bas\s+" + INT_TYPES + r"\b")
FN = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+(\w+)", re.M)
TEST_MODULE = re.compile(r"^[ \t]*#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", re.M)
FLOAT_TYPE_BINDING = re.compile(r"\b(\w+)\s*:\s*&?(?:mut\s+)?f(?:64|32)\b")
LET = re.compile(r"\blet\s+(?:mut\s+)?(\w+)\s*(?::\s*([^=;]+?))?\s*=\s*(.*?);", re.S)
FLOAT_MARKERS = re.compile(
    r"\bas\s+f(?:64|32)\b|\bf(?:64|32)::|\b\d+\.\d+(?:e-?\d+)?\b|\b\d+e-?\d+\b|"
    r"\.(?:floor|ceil|round|trunc|sqrt|powf|powi|exp|ln|log10|log2|to_degrees|to_radians)\s*\("
)
WORD = re.compile(r"[A-Za-z_]\w*")


def blanked(source: str) -> str:
    """The source with string literals, char literals and comments replaced
    by spaces, newlines kept, so positions and line numbers do not move.

    One pass, left to right, because each of these can contain the
    delimiters of the others: a `"` in a comment, a `//` in a string, a
    `'"'`. Rust's forms: `"..."` with backslash escapes, `r"..."` and
    `r#"..."#`, `b` prefixes, `'c'` and `'\\n'` (a lifetime `'a` has no
    closing quote and is left alone), `//` to the line's end, `/* */`
    nested."""
    out: list[str] = []
    i = 0
    n = len(source)

    def push_blank(start: int, stop: int) -> None:
        out.append("".join("\n" if c == "\n" else " " for c in source[start:stop]))

    while i < n:
        c = source[i]
        if source.startswith("//", i):
            j = source.find("\n", i)
            j = n if j < 0 else j
            push_blank(i, j)
            i = j
        elif source.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if source.startswith("/*", j):
                    depth += 1
                    j += 2
                elif source.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            push_blank(i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', source[i:]):
            hashes = re.match(r"r(#*)", source[i:]).group(1)
            close = '"' + hashes
            j = source.find(close, i + len(hashes) + 2)
            j = n if j < 0 else j + len(close)
            out.append(c)
            push_blank(i + 1, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            j = min(j + 1, n)
            push_blank(i, j)
            i = j
        elif c == "'":
            m = re.match(r"'(?:\\.[^']*|[^'\\])'", source[i:])
            if m:
                push_blank(i, i + m.end())
                i += m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def readable(source: str) -> str:
    """The source blanked, cut at the test module."""
    text = blanked(source)
    boundary = TEST_MODULE.search(text)
    return text[: boundary.start()] if boundary else text


def operand_before(text: str, at: int) -> str:
    """The expression the cast at `text[at:]` applies to: walking back from
    `at`, across lines, over one parenthesised group, a method chain and a
    name."""
    i = at
    while i > 0 and text[i - 1].isspace():
        i -= 1
    end = i
    while i > 0:
        c = text[i - 1]
        if c in ")]":
            depth = 0
            while i > 0:
                i -= 1
                if text[i] in ")]":
                    depth += 1
                elif text[i] in "([":
                    depth -= 1
                    if depth == 0:
                        break
            continue
        if c.isalnum() or c in "_.:":
            i -= 1
            continue
        if c.isspace():
            # A method chain broken across lines: `.method()` on the next
            # line is still the operand.
            j = i
            while j > 0 and text[j - 1].isspace():
                j -= 1
            if j > 0 and text[j - 1] == "." or (i < end and text[i] == "."):
                i = j
                continue
        break
    return text[i:end]


def is_float_marked(expr: str, floats: set[str]) -> bool:
    if FLOAT_MARKERS.search(expr):
        return True
    return any(w in floats for w in WORD.findall(expr))


def line_of(text: str, at: int) -> int:
    return text.count("\n", 0, at) + 1


def scan(source: str) -> tuple[list[tuple[int, str, str]], int]:
    """Violations as `(line, function, text)` and the number of functions
    read before the test module."""
    text = readable(source)
    lines = source.splitlines()
    starts = [(m.start(), m.group(1)) for m in FN.finditer(text)]
    # The blanking must not swallow code. Every `fn` the raw source has
    # before the cut must still be there; a lost one is a reader that
    # paired a quote wrongly and hid a span.
    raw = [m.group(1) for m in FN.finditer(source[: len(text)])]
    if raw != [name for _, name in starts]:
        lost = sorted(set(raw) - {name for _, name in starts})
        raise RuntimeError(f"the reader lost function(s) to blanking: {lost}")
    violations: list[tuple[int, str, str]] = []
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else len(text)
        body = text[start:end]
        floats: set[str] = set()
        brace = body.find("{")
        signature = body[:brace] if brace >= 0 else body
        floats |= set(FLOAT_TYPE_BINDING.findall(signature))
        # Bindings and casts in source order: a name is a float from the
        # point it is bound.
        events: list[tuple[int, str, re.Match[str]]] = [
            (m.start(), "let", m) for m in LET.finditer(body)
        ] + [(m.start(), "cast", m) for m in CAST.finditer(body)]
        for at, kind, m in sorted(events, key=lambda e: e[0]):
            if kind == "let":
                bound, typ, init = m.group(1), m.group(2), m.group(3)
                if (typ and re.search(r"\bf(?:64|32)\b", typ)) or is_float_marked(init, floats):
                    floats.add(bound)
                continue
            operand = operand_before(body, at)
            if is_float_marked(operand, floats):
                line = line_of(text, start + at)
                violations.append((line, name, lines[line - 1].strip()))
    return violations, len(starts)


def check(files: dict[str, str], allowed: dict[tuple[str, str], str]) -> int:
    failed = False
    used: set[tuple[str, str]] = set()
    for name, source in files.items():
        violations, functions = scan(source)
        if functions == 0:
            print(f"FAIL: {name}: no function found before its test module; nothing was graded")
            failed = True
            continue
        for number, function, text in violations:
            reason = allowed.get((name, function))
            if reason is None:
                print(f"FAIL: {name}:{number}: in `{function}`: a float reaches an integer: {text}")
                failed = True
            else:
                used.add((name, function))
                print(f"allowed: {name}:{number}: in `{function}`: {reason}")
        print(f"{name}: {functions} functions before the test module, {len(violations)} cast(s) from a float")
    for key in sorted(set(allowed) - used):
        print(f"FAIL: ALLOWED names {key[0]}::{key[1]}, which has no cast from a float: a stale exemption")
        failed = True
    return 1 if failed else 0


SELFTEST = {
    "cast of a float quotient": ("let budget_per_epoch = (budget_atomic as f64 / epy) as u64;", True),
    "cast of a float product": ("(params.asymptote as f64 * config.fraction) as u128;", True),
    "cast after a float method": ("let middle = ((low as f64) * (high as f64)).sqrt() as u64;", True),
    "cast of a name bound to a float": ("let demand = scale as f64 * k;\nlet n = demand as u64;", True),
    "cast of a float parameter": ("fn f(x: f64) -> u64 {\n    x as u64\n}", True),
    "cast of a float parameter, body on the fn line": ("fn f(x: f64) -> u64 { x as u64 }", True),
    "cast of a name typed f64": ("let d: f64 = read();\nlet n = d as u64;", True),
    "operand on earlier lines than the cast": (
        "let n = (\n    budget_atomic as f64\n        / epy\n) as u64;",
        True,
    ),
    "let initialiser across lines, then cast": (
        "let d = scale as f64\n    * k;\nlet n = d as u64;",
        True,
    ),
    "method chain across lines": ("let n = (a as f64 / b)\n    .floor()\n    as u64;", True),
    "integer casts beside a float": (
        "let skl = (circulating as u128 * ratio as u128 / SCALE as u128) as f64 / COIN;",
        False,
    ),
    "a float literal in a comment": ("let n = (a / b) as u64; // about 26.28 epochs", False),
    "a float literal in a string": ('let n = (a / b) as u64;\nwriteln!(out, "bond {} x 0.75", n)?;', False),
    "a quote in a comment before the cast": (
        'let s = "x"; // the "flat arm\nlet n = (a as f64 / b) as u64;\nlet t = "y";',
        True,
    ),
    "a comment marker inside a string before the cast": (
        'let u = "https://x"; let n = (a as f64 / b) as u64;',
        True,
    ),
    "a quote char literal before the cast": ("let q = '\"';\nlet n = (a as f64 / b) as u64;", True),
    "a lifetime is not a char literal": ("fn g<'a>(x: &'a str) -> u64 { (y as f64) as u64 }", True),
    "after the test module": ("#[cfg(test)]\nmod tests {\n    let n = (a as f64 / b) as u64;\n}", False),
    "cfg(test) on an item is not the boundary": (
        "#[cfg(test)]\npub fn probe() {}\nlet n = (a as f64 / b) as u64;",
        True,
    ),
}


def selftest() -> int:
    failed = False
    for label, (snippet, expect_violation) in SELFTEST.items():
        source = "fn fixture() {\n" + snippet + "\n}\n"
        violations, _ = scan(source)
        got = bool(violations)
        verdict = "ok" if got == expect_violation else "MISREAD"
        if got != expect_violation:
            failed = True
        print(f"selftest {verdict}: {label}")
    # A stale exemption fails: ALLOWED names a function with no cast from
    # a float.
    clean = "fn clean() -> u64 {\n    (a * b) as u64\n}\n"
    stale = check({"fixture.rs": clean}, {("fixture.rs", "clean"): "no reason"})
    verdict = "ok" if stale == 1 else "MISREAD"
    if stale != 1:
        failed = True
    print(f"selftest {verdict}: a stale ALLOWED entry fails")
    # A live exemption passes, and is reported.
    dirty = "fn dirty(x: f64) -> u64 {\n    x as u64\n}\n"
    live = check({"fixture.rs": dirty}, {("fixture.rs", "dirty"): "fixture"})
    verdict = "ok" if live == 0 else "MISREAD"
    if live != 0:
        failed = True
    print(f"selftest {verdict}: a live ALLOWED entry passes")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    missing = [name for name in FOLD_FILES if not (SIM / name).is_file()]
    if missing:
        print(f"FAIL: fold file(s) missing: {', '.join(missing)}; the gate has no subject")
        return 1
    files = {name: (SIM / name).read_text(encoding="utf-8") for name in FOLD_FILES}
    return check(files, ALLOWED)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
