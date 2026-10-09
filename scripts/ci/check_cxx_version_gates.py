#!/usr/bin/env python3
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
#   1. a comparison, in either order, one of whose sides is a version operand;
#   2. a call into the hard-fork table (`get_ideal_hard_fork_version(` and its
#      siblings), which is how a height becomes a version.
#
# A version operand is an identifier that ends in lowercase `version`
# (`version`, `tx.version`, `hf_version`, `socks_version()`), or the
# persisted-row spelling `kVersion`. The lowercase ending is what leaves
# `BOOST_VERSION`, `dwMajorVersion` and `original_version_till_height` alone,
# and `last_versions` is not an operand either: the name has to end in
# `version`. `<<`, `>>` and `->` are not comparisons. A lone `<` or `>` is a
# comparison in two shapes: a version on its left and a value on its right
# (`tx.version < min_tx_version`), or a constant on its left and a version on
# its right (`5 < version`), and never a `>` that closes a bracket the line
# opened. That is what separates them from a template (`arg_descriptor<bool>`,
# `std::array<char, 32> version`) and from a placeholder (`<version>`). `<=`,
# `>=`, `==` and `!=` read both sides, and the other side may be a literal, a
# macro, a local or another version: the row says which. Parentheses around
# an operand (`(version) >= 5`) and a grouping parenthesis that closes after
# the operator (`if (version >= 5)`) are not calls, so the name inside still
# counts. The contents of string and character literals are blanked first:
# `"tx version < 3"` in an error message is prose about a comparison. The
# extractor does not decide any of that.
#
# Each hit is keyed on (path, the code text of its line), with a count, and
# the multiset must equal the inventory's. Line numbers are not part of the
# key: they drift. A count is not the test: one gate added and another
# removed leaves a count unchanged and a set different.
#
# `disposition` and `landing` are tokens. The sentences live in
# CXX_VERSION_GATES.md, once. A free-text cell would read as checked.
#
# Instance of 47-gate-subject-assertion.mdc: an empty source list and an empty
# inventory both read as "nothing differs", so both are refused. When the C++
# is gone, this script and its inventory are deleted with it; they do not go
# green on an empty tree. Comments are removed by scripts/ci/strip_c_comments.py,
# and that stripper's own self-test runs first: a stripper that fails its cases
# must not decide which lines are code.

import argparse
import io
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strip_c_comments import self_test as strip_self_test  # noqa: E402
from strip_c_comments import strip as strip_comments  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = "src"
# `.cc` is a translation unit in this tree (fcmp, timings). Omitting it lets a
# gate land there while `source_count` stays nonzero.
SOURCE_SUFFIXES = (".cpp", ".cc", ".h", ".hpp", ".inl", ".c")
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
# Closed vocabulary. The prose for each token is CXX_VERSION_GATES.md §3 and §4.
DISPOSITIONS = (
    "collapse",
    "delete",
    "none",
)
LANDINGS = (
    "tx-version",
    "none",
)

# Persisted rows in shekyl_types.h spell the version byte `kVersion`. Every
# other version operand in this tree ends in lowercase `version`.
PERSISTED_ROW_VERSION = "kVersion"

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A postfix expression up to a space. `<` and `>` are not part of it: they are
# either the comparison or a template bracket, and folding them in glues
# `MDB_val_copy<uint8_t> val_value(version)` into one false comparison.
# `i->version` still denotes `version`, because the `>` splits the token and
# the identifier that ends the side is the one kept.
_EXPR_RE = re.compile(r"[A-Za-z0-9_:.+\-\[\]()*&~]+")
_INT_LITERAL_RE = re.compile(r"\d[0-9']*(?:[uUlL]+)?\Z")
_TWO_CHAR_SKIP = ("<<", ">>", "->")
_TWO_CHAR_CMP = (">=", "<=", "==", "!=")

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


def is_version_operand(identifier):
    """True when `identifier` is a version this gate classifies.

    Lowercase ending, so `BOOST_VERSION` and `dwMajorVersion` are not
    operands. `kVersion` is the persisted-row spelling of the same fact.
    """
    return identifier == PERSISTED_ROW_VERSION or identifier.endswith("version")


def _strip_nested(expr):
    """`expr` with the insides of complete `()` and `[]` groups blanked.

    `last_versions[old_version]` denotes the array, not the index.
    `socks_version()` denotes the function, not its arguments. An unclosed
    `(` is the grouping parenthesis of `if (version >= 5)`, whose close sits
    past the operator, so the name after it is the expression and is kept.
    """
    remove = [False] * len(expr)
    stack = []
    for index, ch in enumerate(expr):
        if ch in "([":
            stack.append((ch, index))
        elif ch == ")" and stack and stack[-1][0] == "(":
            _, start = stack.pop()
            for inner in range(start + 1, index):
                remove[inner] = True
        elif ch == "]" and stack and stack[-1][0] == "[":
            _, start = stack.pop()
            for inner in range(start + 1, index):
                remove[inner] = True
    return "".join(ch for index, ch in enumerate(expr) if not remove[index])


def _unwrap_grouping(expr):
    """`expr` without parentheses that enclose the whole of it.

    `(version)` and `((tx.version))` denote what is inside them. A call's
    parentheses do not enclose the whole expression, so `f(version)` is left
    alone and still denotes `f`.
    """
    while len(expr) >= 2 and expr[0] == "(":
        depth = 0
        for index, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
        if depth != 0 or index != len(expr) - 1:
            break
        expr = expr[1:-1]
    return expr


def denoted_identifier(expr):
    """The identifier `expr` denotes: its last name, indexes and arguments aside."""
    found = _IDENT_RE.findall(_strip_nested(_unwrap_grouping(expr)))
    return found[-1] if found else None


def _side_is_version(expr):
    ident = denoted_identifier(expr)
    return ident is not None and is_version_operand(ident)


def _side_is_value(expr):
    """True when `expr` is something a comparison can test.

    An identifier, a call or an integer literal. The `-` after `<version>`
    and the quote that closes a `"<version>"` placeholder are how that
    placeholder continues, and neither is a value.
    """
    if expr is None:
        return False
    if denoted_identifier(expr) is not None:
        return True
    body = _strip_nested(expr).replace("(", "").replace(")", "").strip()
    # `:` is in the expression charset so `version::v5` stays one token. A
    # lone trailing colon is the punctuation of `"version < 6: ..."`, not
    # part of the literal. `::` is a scope operator and is left in place.
    if body.endswith(":") and not body.endswith("::"):
        body = body[:-1]
    return _INT_LITERAL_RE.fullmatch(body) is not None


def _side_is_constant(expr):
    """True when `expr` is an integer literal or an upper-case constant.

    The left side of a reversed comparison, `5 < version` or
    `CURRENT_TRANSACTION_VERSION < version`. A lower-case name there is as
    likely to be a type in front of a template bracket, so it does not count.
    """
    if expr is None:
        return False
    # `if (5 < version)` and `f(5 < version)` hand over `(5` and `f(5`: the
    # side is what follows the last parenthesis still open.
    open_at = []
    for index, ch in enumerate(expr):
        if ch == "(":
            open_at.append(index)
        elif ch == ")" and open_at:
            open_at.pop()
    body = _unwrap_grouping(expr[open_at[-1] + 1 :] if open_at else expr)
    if _INT_LITERAL_RE.fullmatch(body) is not None:
        return True
    return re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Z0-9_]*", body) is not None


def _closes_a_template(line, index):
    """True when the lone `>` at `index` has an unclosed lone `<` before it.

    `std::array<char, 32> version` closes the bracket the type opened. In
    `if (3 > version)` nothing was opened, so the `>` compares.
    """
    depth = 0
    for at, length in comparison_at(line[:index]):
        if length != 1:
            continue
        depth += 1 if line[at] == "<" else -1
    return depth > 0


def comparison_at(line):
    """Yield (index, length) of each real comparison operator in `line`."""
    i = 0
    n = len(line)
    while i < n:
        pair = line[i : i + 2]
        if pair in _TWO_CHAR_SKIP:
            i += 2
            continue
        if pair in _TWO_CHAR_CMP:
            yield i, 2
            i += 2
            continue
        if line[i] in "<>":
            yield i, 1
        i += 1


def _trailing_expr(text):
    """The expression glued to the end of `text`, if one is."""
    found = None
    for found in _EXPR_RE.finditer(text):
        pass
    if found is not None and found.end() == len(text):
        return found.group()
    return None


def line_compares_version(line):
    """A comparison on `line` that denotes a version on one of its sides.

    `<=`, `>=`, `==` and `!=` are not template brackets, so a version on
    either side counts. A lone `<` or `>` is one as often as it is a
    comparison, so it counts in two shapes only: a version on its left and a
    value on its right, or a constant on its left and a version on its right
    (`5 < version`). The second shape is refused for a `>` that closes a
    template (`std::array<char, 32> version`). What neither shape admits is
    where a closer meets the next name (`arg_descriptor<bool> arg_version`)
    and where a `<version>` placeholder is closed by a quote or a `-`.
    """
    for index, length in comparison_at(line):
        left = _trailing_expr(line[:index].rstrip())
        op = line[index : index + length]
        right_match = _EXPR_RE.match(line[index + length :].lstrip())
        right = right_match.group() if right_match is not None else None
        if op in "<>":
            if left is not None and _side_is_version(left) and _side_is_value(right):
                return True
            if (
                _side_is_constant(left)
                and right is not None
                and _side_is_version(right)
                and not (op == ">" and _closes_a_template(line, index))
            ):
                return True
            continue
        if (left is not None and _side_is_version(left)) or (
            right is not None and _side_is_version(right)
        ):
            return True
    return False


def is_lookup_call(line):
    """A hard-fork table call on `line`, not a declaration of one."""
    if not LOOKUP_RE.search(line):
        return False
    stripped = line.strip()
    return not (_DECLARATION_RE.search(stripped) and _TYPE_LED_RE.match(stripped))


def mask_literals(line):
    """`line` with the contents of its string and character literals blanked.

    An error message that says "tx version < 3" is prose about a comparison.
    The quotes stay, so the code around a literal reads as it did. An
    apostrophe between two alphanumerics is a digit separator (`1'000`), not
    a character literal. A raw string that spans lines is not modelled; a
    line inside one is judged as code, which errs toward a row.
    """
    out = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        is_separator = (
            ch == "'" and 0 < i < n - 1 and line[i - 1].isalnum() and line[i + 1].isalnum()
        )
        if ch not in "\"'" or is_separator:
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
        while i < n and line[i] != ch:
            if line[i] == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            out.append(" ")
            i += 1
        if i < n:
            out.append(ch)
            i += 1
    return "".join(out)


def line_is_site(line):
    code = mask_literals(line)
    return line_compares_version(code) or is_lookup_call(code)


def require_stripper():
    """A stripper that fails its own cases must not decide which lines are code."""
    held = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = strip_self_test()
    finally:
        sys.stdout = held
    return code == 0


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
            if line_is_site(line):
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
        for column in ("operand", "evaluates"):
            if not row[column].strip():
                problems.append(f"line {number}: `{column}` is empty; every row is classified")
        if row["disposition"] not in DISPOSITIONS:
            problems.append(
                f"line {number}: disposition `{row['disposition']}` is not one of "
                f"{', '.join(DISPOSITIONS)}"
            )
        if row["landing"] not in LANDINGS:
            problems.append(
                f"line {number}: landing `{row['landing']}` is not one of "
                f"{', '.join(LANDINGS)}"
            )
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

    if not require_stripper():
        print(
            "strip_c_comments.py failed its self-test; this gate will not read source "
            "through a stripper that cannot tell a comment from code.",
            file=sys.stderr,
        )
        return 2

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
