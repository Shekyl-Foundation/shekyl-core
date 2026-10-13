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

What is read: each file in `FOLD_FILES`, up to its test module (a
`#[cfg(test)]` line followed by `mod <name> {`; a `#[cfg(test)]` on an
item is not the boundary). Comments are dropped. A cast is `as <integer
type>`. Its operand is the expression the cast applies to: a parenthesised
group, a method chain, or a name. The cast is a violation when the operand
is float-marked:

* it contains `as f64`, `as f32`, `f64::`, `f32::`, a float literal, or a
  float method (`floor`, `ceil`, `round`, `trunc`, `sqrt`, `powf`, `powi`,
  `exp`, `ln`, `log10`, `log2`, `abs` on a float, `max`/`min` with a float
  literal);
* or it is, or ends in, a name the function bound to a float: a parameter
  typed `f64`/`f32`, or a `let` whose type is `f64`/`f32` or whose
  initialiser is float-marked.

A function named in `ALLOWED` with a reason is reported and not failed:
that is the list of exceptions the gate carries, and it is empty. A listed
file that is missing, or one in which no function was found before its
test module, fails the gate: absence of a subject is not a pass (rule 47).

`--selftest` runs the reader on fixtures that hold each pattern class the
gate must catch, and one it must not, and fails if any is misread. The
bundle runs it first.
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
# row.
ALLOWED: dict[tuple[str, str], str] = {}

INT_TYPES = r"(?:u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize)"
CAST = re.compile(r"\bas\s+" + INT_TYPES + r"\b")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?fn\s+(\w+)")
TEST_MODULE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")
FLOAT_TYPE_BINDING = re.compile(r"\b(\w+)\s*:\s*&?(?:mut\s+)?f(?:64|32)\b")
LET = re.compile(r"^\s*let\s+(?:mut\s+)?(\w+)\s*(?::\s*([^=]+?))?\s*=\s*(.+?);?\s*$")
FLOAT_MARKERS = re.compile(
    r"\bas\s+f(?:64|32)\b|\bf(?:64|32)::|\b\d+\.\d+(?:e-?\d+)?\b|\b\d+e-?\d+\b|"
    r"\.(?:floor|ceil|round|trunc|sqrt|powf|powi|exp|ln|log10|log2|to_degrees|to_radians)\s*\("
)
WORD = re.compile(r"[A-Za-z_]\w*")


def strip_comment(line: str) -> str:
    """The line without a trailing `//` comment. String literals holding
    `//` are not a shape the fold files have."""
    at = line.find("//")
    return line if at < 0 else line[:at]


def operand_before(text: str, at: int) -> str:
    """The expression the cast at `text[at:]` applies to: walking back from
    `at` over one parenthesised group, a method chain, and a name."""
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
        break
    return text[i:end]


def is_float_marked(expr: str, floats: set[str]) -> bool:
    if FLOAT_MARKERS.search(expr):
        return True
    return any(w in floats for w in WORD.findall(expr))


def scan(name: str, lines: list[str]) -> tuple[list[tuple[int, str, str]], int]:
    """Violations as `(line, function, text)` and the number of functions
    seen before the test module."""
    violations: list[tuple[int, str, str]] = []
    functions = 0
    current = "<module>"
    floats: set[str] = set()
    pending_cfg_test = False
    signature: list[str] = []
    in_signature = False
    for number, raw in enumerate(lines, start=1):
        line = strip_comment(raw)
        stripped = line.strip()
        if stripped == "#[cfg(test)]":
            pending_cfg_test = True
            continue
        if pending_cfg_test and stripped:
            if TEST_MODULE.match(line):
                break
            pending_cfg_test = False
        m = FN.match(line)
        if m:
            current = m.group(1)
            functions += 1
            floats = set()
            signature = [line]
            in_signature = "{" not in line
            if not in_signature:
                floats |= set(FLOAT_TYPE_BINDING.findall(line))
            continue
        if in_signature:
            signature.append(line)
            if "{" in line:
                in_signature = False
                floats |= set(FLOAT_TYPE_BINDING.findall(" ".join(signature)))
            continue
        let = LET.match(line)
        if let:
            bound, typ, init = let.group(1), let.group(2), let.group(3)
            if (typ and re.search(r"\bf(?:64|32)\b", typ)) or is_float_marked(init, floats):
                floats.add(bound)
        for cast in CAST.finditer(line):
            operand = operand_before(line, cast.start())
            if is_float_marked(operand, floats):
                violations.append((number, current, raw.strip()))
    return violations, functions


def check(files: dict[str, list[str]]) -> int:
    failed = False
    for name, lines in files.items():
        violations, functions = scan(name, lines)
        if functions == 0:
            print(f"FAIL: {name}: no function found before its test module; nothing was graded")
            failed = True
            continue
        for number, function, text in violations:
            reason = ALLOWED.get((name, function))
            if reason is None:
                print(f"FAIL: {name}:{number}: in `{function}`: a float reaches an integer: {text}")
                failed = True
            else:
                print(f"allowed: {name}:{number}: in `{function}`: {reason}")
        print(f"{name}: {functions} functions before the test module, {len(violations)} cast(s) from a float")
    return 1 if failed else 0


SELFTEST = {
    "cast of a float quotient": ("let budget_per_epoch = (budget_atomic as f64 / epy) as u64;", True),
    "cast of a float product": ("(params.asymptote as f64 * config.fraction) as u128;", True),
    "cast after a float method": ("let middle = ((low as f64) * (high as f64)).sqrt() as u64;", True),
    "cast of a name bound to a float": ("let demand = scale as f64 * k;\nlet n = demand as u64;", True),
    "cast of a float parameter": ("fn f(x: f64) -> u64 {\nx as u64\n}", True),
    "cast of a name typed f64": ("let d: f64 = read();\nlet n = d as u64;", True),
    "integer casts beside a float": (
        "let skl = (circulating as u128 * ratio as u128 / SCALE as u128) as f64 / COIN;",
        False,
    ),
    "a float literal in a comment": ("let n = (a / b) as u64; // about 26.28 epochs", False),
    "after the test module": ("#[cfg(test)]\nmod tests {\nlet n = (a as f64 / b) as u64;\n}", False),
    "cfg(test) on an item is not the boundary": (
        "#[cfg(test)]\npub fn probe() {}\nlet n = (a as f64 / b) as u64;",
        True,
    ),
}


def selftest() -> int:
    failed = False
    for label, (snippet, expect_violation) in SELFTEST.items():
        lines = ["fn fixture() {"] + snippet.splitlines() + ["}"]
        violations, _ = scan("fixture.rs", lines)
        got = bool(violations)
        verdict = "ok" if got == expect_violation else "MISREAD"
        if got != expect_violation:
            failed = True
        print(f"selftest {verdict}: {label}")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    files: dict[str, list[str]] = {}
    missing = [name for name in FOLD_FILES if not (SIM / name).is_file()]
    if missing:
        print(f"FAIL: fold file(s) missing: {', '.join(missing)}; the gate has no subject")
        return 1
    for name in FOLD_FILES:
        files[name] = (SIM / name).read_text(encoding="utf-8").splitlines()
    return check(files)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
