#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every field of the daemon's C++ snapshot has a C++ reader.

`ShekylDaemonSnapshot` (`DAEMON_CONFIG_CUTOVER.md` §2.9) holds exactly the
configuration values whose reader is still C++. The pinned count
(`SNAPSHOT_FIELDS` in `rust/shekyl-ffi/src/daemon_snapshot_ffi.rs`,
`SHEKYL_DAEMON_SNAPSHOT_FIELDS` in `src/shekyl/shekyl_ffi.h`) stopped a
field from being added without a decision. It did not notice a field whose
reader had moved into Rust: four fields sat in the snapshot with no C++
reader at all (DC-F25, §3.7). This gate compares the structure against the
readers, not against a number.

For every member of the structure it finds a read under `src/` through a
variable of the snapshot's type (`snapshot.network`, `snapshot->network`,
whatever the variable is called), excluding the header that declares the
structure. A member with no read fails, unless `EXEMPT` names it with the
reason; an exemption naming a member the structure no longer has fails as
stale. The two pinned counts and the two member lists (Rust and C++, in
order) must agree with the structure and with each other.

Exit 0 when every field has a reader; 1 naming each field without one;
2 when the structure, the counts or the snapshot-typed variables cannot be
found (rule 47: a gate asserts its own subject).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

RUST_SOURCE = "rust/shekyl-ffi/src/daemon_snapshot_ffi.rs"
C_HEADER = "src/shekyl/shekyl_ffi.h"
C_ROOT = "src"
C_SUFFIXES = {".cpp", ".h", ".hpp", ".inl", ".cc"}

# A member with no C++ reader that stays by decision, and why. Keep this
# empty when it can be.
EXEMPT: dict[str, str] = {
    # The chain is the Rust store: core no longer opens LMDB at this path
    # (DC-F25). Rick decides whether the field is deleted or kept.
    "data_dir": "no C++ reader since the chain moved to the Rust store (DC-F25)",
}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def rust_fields(source: str) -> list[str]:
    m = re.search(r"pub struct ShekylDaemonSnapshot \{(.*?)\n\}", source, flags=re.S)
    if not m:
        return []
    return re.findall(r"^\s*pub (\w+):", m.group(1), flags=re.M)


def rust_count(source: str) -> int | None:
    m = re.search(r"pub const SNAPSHOT_FIELDS: u32 = (\d+);", source)
    return int(m.group(1)) if m else None


def c_fields(header: str) -> list[str]:
    m = re.search(r"struct ShekylDaemonSnapshot \{(.*?)\n\};", header, flags=re.S)
    if not m:
        return []
    return re.findall(r"^\s*[\w:\s\*]+?\b(\w+);", strip_comments(m.group(1)), flags=re.M)


def c_count(header: str) -> int | None:
    m = re.search(r"#define SHEKYL_DAEMON_SNAPSHOT_FIELDS (\d+)u", header)
    return int(m.group(1)) if m else None


def snapshot_names(text: str) -> set[str]:
    """Variables declared with the snapshot's type: `const ShekylDaemonSnapshot&
    snapshot`, `ShekylDaemonSnapshot* snapshot`, `ShekylDaemonSnapshot snapshot`."""
    return set(re.findall(r"\bShekylDaemonSnapshot\b\s*(?:const\s*)?[&*]*\s*(\w+)\b", text))


def readers(repo: Path, fields: list[str]) -> tuple[dict[str, list[str]], set[str]]:
    found: dict[str, list[str]] = {f: [] for f in fields}
    names: set[str] = set()
    for path in sorted((repo / C_ROOT).rglob("*")):
        if path.suffix not in C_SUFFIXES or not path.is_file():
            continue
        rel = path.relative_to(repo).as_posix()
        if rel == C_HEADER:
            continue
        text = strip_comments(path.read_text(errors="replace"))
        local = snapshot_names(text)
        if not local:
            continue
        names |= local
        alt = "|".join(re.escape(n) for n in sorted(local))
        for f in fields:
            for m in re.finditer(rf"\b(?:{alt})(?:\.|->){re.escape(f)}\b", text):
                line = text.count("\n", 0, m.start()) + 1
                found[f].append(f"{rel}:{line}")
    return found, names


def check(repo: Path, exempt: dict[str, str]) -> tuple[list[str], list[str], int]:
    """(subject errors, findings, readers counted). Subject errors are the
    gate's own failures (exit 2); findings are fields without a reader (exit 1)."""
    subject: list[str] = []
    rust_path = repo / RUST_SOURCE
    c_path = repo / C_HEADER
    if not rust_path.is_file() or not c_path.is_file():
        return [f"{RUST_SOURCE} or {C_HEADER} is missing"], [], 0
    rust = rust_path.read_text()
    header = c_path.read_text()
    fields = rust_fields(rust)
    cfields = c_fields(header)
    rc, cc = rust_count(rust), c_count(header)
    if not fields:
        subject.append(f"no `pub struct ShekylDaemonSnapshot` fields found in {RUST_SOURCE}")
    if not cfields:
        subject.append(f"no `struct ShekylDaemonSnapshot` members found in {C_HEADER}")
    if rc is None:
        subject.append(f"SNAPSHOT_FIELDS not found in {RUST_SOURCE}")
    if cc is None:
        subject.append(f"SHEKYL_DAEMON_SNAPSHOT_FIELDS not found in {C_HEADER}")
    if subject:
        return subject, [], 0
    if fields != cfields:
        subject.append(f"the Rust fields {fields} and the C++ members {cfields} differ")
    if rc != len(fields):
        subject.append(f"SNAPSHOT_FIELDS is {rc} and the Rust structure has {len(fields)} fields")
    if cc != len(cfields):
        subject.append(f"SHEKYL_DAEMON_SNAPSHOT_FIELDS is {cc} and the C++ structure has {len(cfields)} members")
    found, names = readers(repo, fields)
    if not names:
        subject.append(f"no variable of type ShekylDaemonSnapshot found under {C_ROOT}/")
    total = sum(len(v) for v in found.values())
    if names and total == 0:
        subject.append("no read of any snapshot field found; the reader pattern is wrong")
    if subject:
        return subject, [], total
    findings: list[str] = []
    for f in fields:
        if found[f]:
            continue
        if f in exempt:
            continue
        findings.append(f"snapshot field `{f}` has no C++ reader under {C_ROOT}/; delete it or name it in EXEMPT with the reason")
    for f in exempt:
        if f not in fields:
            findings.append(f"EXEMPT names `{f}`, which is not a snapshot field; the exemption is stale")
        elif found[f]:
            findings.append(f"EXEMPT names `{f}`, which has a C++ reader ({found[f][0]}); the exemption is stale")
    return [], findings, total


RUST_FIXTURE = """
pub struct ShekylDaemonSnapshot {
    /// a
    pub alpha: u8,
    pub beta: bool,
    pub gamma: *const c_char,
}

pub const SNAPSHOT_FIELDS: u32 = 3;
"""

C_FIXTURE = """
#define SHEKYL_DAEMON_SNAPSHOT_FIELDS 3u
struct ShekylDaemonSnapshot {
  uint8_t alpha;
  bool beta; // a comment
  const char* gamma;
};
"""

READER_FIXTURE = """
#include "shekyl/shekyl_ffi.h"
bool core::init(const ShekylDaemonSnapshot& snapshot)
{
  m_a = snapshot.alpha;
  return true;
}
extern "C" int run(const ShekylDaemonSnapshot* s) noexcept
{
  // s->gamma is only mentioned here, in a comment
  return s->beta ? 0 : 1;
}
"""


def selftest() -> int:
    failures = 0

    def case(title: str, rust: str, header: str, reader: str, exempt: dict[str, str], expect_subject: bool, expect: list[str]) -> None:
        nonlocal failures
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / RUST_SOURCE).parent.mkdir(parents=True)
            (repo / RUST_SOURCE).write_text(rust)
            (repo / C_HEADER).parent.mkdir(parents=True)
            (repo / C_HEADER).write_text(header)
            (repo / C_ROOT / "d").mkdir(parents=True)
            (repo / C_ROOT / "d" / "daemon.cpp").write_text(reader)
            subject, findings, _ = check(repo, exempt)
        if expect_subject:
            ok = bool(subject) and not findings
        else:
            ok = not subject and len(findings) == len(expect) and all(any(e in f for f in findings) for e in expect)
        print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got subject={subject} findings={findings}"))
        failures += 0 if ok else 1

    case("every field read passes", RUST_FIXTURE, C_FIXTURE, READER_FIXTURE.replace("// s->gamma is only", "x = s->gamma; //"), {}, False, [])
    case("a field read only in a comment is named", RUST_FIXTURE, C_FIXTURE, READER_FIXTURE, {}, False, ["`gamma` has no C++ reader"])
    case("an exempt field passes with its reason", RUST_FIXTURE, C_FIXTURE, READER_FIXTURE, {"gamma": "why"}, False, [])
    case("a stale exemption is named", RUST_FIXTURE, C_FIXTURE, READER_FIXTURE, {"gamma": "why", "delta": "gone"}, False, ["`delta`, which is not a snapshot field"])
    case("an exemption with a reader is named", RUST_FIXTURE, C_FIXTURE, READER_FIXTURE, {"gamma": "why", "alpha": "has one"}, False, ["`alpha`, which has a C++ reader"])
    case("a Rust count off by one is refused", RUST_FIXTURE.replace("= 3;", "= 4;"), C_FIXTURE, READER_FIXTURE, {"gamma": "why"}, True, [])
    case("a C++ count off by one is refused", RUST_FIXTURE, C_FIXTURE.replace("3u", "2u"), READER_FIXTURE, {"gamma": "why"}, True, [])
    case("a member missing on one side is refused", RUST_FIXTURE, C_FIXTURE.replace("  bool beta; // a comment\n", ""), READER_FIXTURE, {"gamma": "why"}, True, [])
    case("no snapshot-typed variable is refused", RUST_FIXTURE, C_FIXTURE, "int main() { return 0; }\n", {"gamma": "why"}, True, [])
    case("a missing structure is refused", "nothing here\n", C_FIXTURE, READER_FIXTURE, {}, True, [])
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    repo = Path(__file__).resolve().parents[2]
    os.chdir(repo)
    subject, findings, total = check(repo, EXEMPT)
    if subject:
        for e in subject:
            print(f"error: {e}", file=sys.stderr)
        return 2
    if findings:
        for f in findings:
            print(f"error: {f}", file=sys.stderr)
        return 1
    fields = rust_fields((repo / RUST_SOURCE).read_text())
    print(
        f"snapshot readers: every field of ShekylDaemonSnapshot has a C++ reader "
        f"({len(fields)} fields, {total} reads, {len(EXEMPT)} exempt: {', '.join(EXEMPT) or 'none'})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
