# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Holds the C++ tree's version comparisons to an inventory, in both
# directions, so a gate cannot appear, change or vanish without its row.
#
# WHY. Monero gates behaviour on its hard-fork numbers. Shekyl's block version
# is 1 on every network, so a branch behind `version >= N`, N >= 2, never runs
# and its `else` arm is what ships. The reward-aware template fill sat dead
# behind `version >= 5` from the chain's reboot until 2026-10-04, when the
# economics sim had already modelled it as production
# (docs/design/ECONOMY_UMBRELLA_PLAN.md §3.1). The sweep that followed
# classified every comparison (docs/design/CXX_VERSION_GATES.md); this is
# what keeps the classification true.
#
# WHAT IT COMPARES. Two extractors run over every C++ source under `src/`:
#
#   1. a comparison between a version-named operand and an integer literal or
#      a `*VERSION*` constant, in either order;
#   2. a call into the hard-fork table (`get_ideal_hard_fork_version(` and its
#      siblings), which is how a height becomes a version.
#
# Each hit is keyed on (path, the code text of its line), with a count, and
# the multiset must equal the inventory's. Line numbers are not part of the
# key: they drift. A count is not the test: one gate added and another
# removed leaves a count unchanged and a set different.
#
# The extractors are deliberately wider than "fork gates". A comparison on a
# database schema version or a SOCKS version is extracted too and carries a
# row saying which operand it reads, because the defect this gate exists for
# was a gate nobody had classified. Excluding by name here would be this
# script deciding a row's class without the row.
#
# Instance of 47-gate-subject-assertion.mdc: an empty source list and an empty
# inventory both read as "nothing differs", so both are refused. When the C++
# is gone, this script and its inventory are deleted with it; they do not go
# green on an empty tree.

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = "src"
SOURCE_SUFFIXES = (".cpp", ".h", ".hpp", ".inl", ".c")
INVENTORY = "docs/ci/cxx-version-gates.tsv"
INVENTORY_COLUMNS = (
    "path",
    "count",
    "operand",
    "evaluates",
    "disposition",
    "landing",
    "text",
)

# The operand is a name ending in lowercase `version` (`version`, `tx.version`,
# `hf_version`, `m_hardfork->get_ideal_version()`), so a Windows `dwMajorVersion`
# or a `BOOST_VERSION` preprocessor test is not one. The value is an integer or
# an upper-case `*VERSION*` constant, so one variable compared with another is
# not extracted: that is a rule with computed bounds, not a gate on a number.
_OPERAND = r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_.>\-]*)?version[a-z0-9_]*(?:\(\s*[^()]*\))?"
_VALUE = r"(?<![A-Za-z0-9_])(?:[0-9]+|(?:[A-Z][A-Z0-9_]*)?VERSION[A-Z0-9_]*)(?![A-Za-z0-9_])"
_CMP = r"(?:>=|<=|==|!=|>|<)"
COMPARISON_RE = re.compile(
    rf"(?:{_OPERAND}\s*\)*\s*{_CMP}\s*\(*\s*{_VALUE})"
    rf"|(?:{_VALUE}\s*{_CMP}\s*\(*\s*{_OPERAND})"
)
# A call, not a definition: `Blockchain::get_ideal_hard_fork_version(` and a
# declaration in a class body name the function without consulting the table.
LOOKUP_RE = re.compile(
    r"(?<!::)(?<![A-Za-z0-9_])"
    r"(?:get_earliest_ideal_height_for_version|get_ideal_hard_fork_version"
    r"|get_hard_fork_version|get_next_hard_fork_version|get_current_version"
    r"|get_ideal_version)\s*\("
)
_DECLARATION_RE = re.compile(r"\)\s*(?:const\s*)?(?:override\s*)?(?:=\s*0\s*)?;\s*$")
_TYPE_LED_RE = re.compile(r"^(?:virtual\s+)?(?:[A-Za-z_:<>0-9]+\s+)+[A-Za-z_]+\s*\(")


def strip_comments(text):
    """`text` with `//` and `/* */` comments blanked, line structure kept.

    String literals are respected so a `//` inside one is not a comment. A
    version comparison quoted inside a log string is still extracted: the
    string is code text, and the sweep classifies it with its line.
    """
    out = []
    i = 0
    n = len(text)
    in_block = False
    in_string = None
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == in_string or ch == "\n":
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            i += 2
            continue
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch in "\"'":
            in_string = ch
        out.append(ch)
        i += 1
    return "".join(out)


def is_lookup_call(line):
    """A hard-fork table call on `line`, not a declaration of one."""
    if not LOOKUP_RE.search(line):
        return False
    stripped = line.strip()
    return not (_DECLARATION_RE.search(stripped) and _TYPE_LED_RE.match(stripped))


def extract(root):
    """Counter of (path, code text) over every extractor hit, and the files read."""
    sources = sorted(
        p
        for p in (root / SOURCE_DIR).rglob("*")
        if p.is_file() and p.suffix in SOURCE_SUFFIXES
    )
    hits = Counter()
    for path in sources:
        rel = path.relative_to(root).as_posix()
        code = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for line in code.split("\n"):
            if COMPARISON_RE.search(line) or is_lookup_call(line):
                hits[(rel, " ".join(line.split()))] += 1
    return hits, len(sources)


def read_inventory(path):
    """Counter of (path, code text) from the inventory, and its row problems."""
    rows = Counter()
    problems = []
    lines = path.read_text(encoding="utf-8").split("\n")
    header = lines[0].split("\t") if lines else []
    if tuple(header) != INVENTORY_COLUMNS:
        problems.append(f"header is {header}, expected {list(INVENTORY_COLUMNS)}")
        return rows, problems
    for number, line in enumerate(lines[1:], start=2):
        if not line:
            continue
        cells = line.split("\t")
        if len(cells) != len(INVENTORY_COLUMNS):
            problems.append(f"line {number}: {len(cells)} cells, expected {len(INVENTORY_COLUMNS)}")
            continue
        row = dict(zip(INVENTORY_COLUMNS, cells))
        for column in ("operand", "evaluates", "disposition", "landing"):
            if not row[column].strip():
                problems.append(f"line {number}: `{column}` is empty; every row is classified")
        try:
            count = int(row["count"])
        except ValueError:
            problems.append(f"line {number}: count `{row['count']}` is not an integer")
            continue
        if count < 1:
            problems.append(f"line {number}: count {count} is not positive")
            continue
        key = (row["path"], row["text"])
        if key in rows:
            problems.append(f"line {number}: duplicate row for {key}; raise its count instead")
        rows[key] += count
    return rows, problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--dump",
        action="store_true",
        help="print the tree's hits as path/count/text rows, for building the inventory",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    hits, source_count = extract(root)
    if args.dump:
        for (path, text), count in sorted(hits.items()):
            print(f"{path}\t{count}\t{text}")
        return 0

    if source_count == 0:
        print(
            f"no C++ sources under {SOURCE_DIR}/: this gate has no subject. If the C++ is "
            f"gone, delete this script and {INVENTORY} with it.",
            file=sys.stderr,
        )
        return 2
    inventory_path = root / INVENTORY
    if not inventory_path.is_file():
        print(f"{INVENTORY} is missing", file=sys.stderr)
        return 2
    rows, problems = read_inventory(inventory_path)
    if not rows and not problems:
        problems.append(
            "the inventory has no rows; if the tree has no version comparisons left, "
            "delete this gate and its inventory rather than keeping an empty one"
        )

    unlisted = hits - rows
    stale = rows - hits
    if not (problems or unlisted or stale):
        print(
            f"C++ version gates: {sum(hits.values())} sites in {len(hits)} rows over "
            f"{source_count} files, all in {INVENTORY}"
        )
        return 0

    for problem in problems:
        print(f"{INVENTORY}: {problem}", file=sys.stderr)
    for (path, text), count in sorted(unlisted.items()):
        print(f"NOT IN THE INVENTORY ({count}x): {path}: {text}", file=sys.stderr)
    for (path, text), count in sorted(stale.items()):
        print(f"IN THE INVENTORY, NOT IN THE TREE ({count}x): {path}: {text}", file=sys.stderr)
    if unlisted:
        print(
            "\nA version comparison or hard-fork table call has no row. Shekyl's block "
            "version is 1 and its transaction version is 3, so a comparison against "
            "another number selects one arm forever. Classify it in "
            f"{INVENTORY} (docs/design/CXX_VERSION_GATES.md says how), or do not add it.",
            file=sys.stderr,
        )
    if stale:
        print(
            f"\nA row's site is gone or its text changed. Remove or update the row in {INVENTORY}.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
