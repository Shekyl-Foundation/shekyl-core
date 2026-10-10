# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_cxx_version_gates.py. The gate compares two sets, so it
# is bitten in both directions and on the case a count would miss: one gate
# added and another removed. The extractor is pinned on the shapes that have
# already slipped it once: a bare `version >= 5`, a named bound
# (`version < min_tx_version`), a hard-fork table comparison, a persisted-row
# `kVersion`, and a `.cc` translation unit. It is also pinned on what it must
# leave alone, including a comment the line-splice and digit-separator cases
# used to keep as code.

import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_cxx_version_gates.py"
HEADER = "path\tcount\toperand\tevaluates\tdisposition\tlanding\ttext\n"

FILL = """bool fill(uint8_t version)
{
  // a comment saying version >= 9 is not code
  size_t bound = version >= 5 ? wide : narrow;
  if (version >= 5)
  {
    return true;
  }
  /* nor is version >= 8
     in a block comment */
  return false;
}
"""

FILL_ROWS = (
    "src/pool.cpp\t1\tblock major version\talways false\tcollapse\ttx-version\t"
    "size_t bound = version >= 5 ? wide : narrow;\n"
    "src/pool.cpp\t1\tblock major version\talways false\tcollapse\ttx-version\t"
    "if (version >= 5)\n"
)

# Not comparisons: another spelling of the word, a shift, a template, a
# placeholder, an index, a height, and two comments the stripper must drop
# (a backslash-newline splice, and a digit separator the old lexer mis-paired).
QUIET = (
    "#if BOOST_VERSION >= 107400\n"
    "if (osvi.dwMajorVersion == 10) { }\n"
    'MDEBUG("v" << version << db_version);\n'
    'const arg_descriptor<bool> arg_version = {"version", "help"};\n'
    "MDB_val_copy<uint8_t> val_value(version);\n"
    ', "hard_fork_info <version>"\n'
    '"stage it under /opt/shekyl/<version>-<target>/, or set "\n'
    "assert(last_versions[old_version] >= 1);\n"
    "if (height <= original_version_till_height) { }\n"
    "// disabled \\\n"
    "if (version >= 5)\n"
    "int x = 1'000; // version >= 5\n"
)

NAMED = "bool admit(uint8_t version, uint8_t min_tx_version)\n{\n  return version < min_tx_version;\n}\n"
NAMED_ROW = (
    "src/admit.cpp\t1\ttransaction version\tlive admission bound\tcollapse\ttx-version\t"
    "return version < min_tx_version;\n"
)
FORK = "return block_version == heights[i].version;\n"
FORK_ROW = (
    "src/fork.cpp\t1\thard-fork table\tthe mechanism's own bookkeeping\t"
    "delete\ttx-version\treturn block_version == heights[i].version;\n"
)
ROWVER = "if (p[0] != kVersion)\n  return false;\n"
ROWVER_ROW = (
    "src/row.h\t1\tpersisted row version\tlive decode\tnone\tnone\tif (p[0] != kVersion)\n"
)
CC = "bool note(uint8_t version) { if (version >= 5) return true; return false; }\n"
CC_ROW = (
    "src/note.cc\t1\tblock major version\talways false\tcollapse\ttx-version\t"
    "bool note(uint8_t version) { if (version >= 5) return true; return false; }\n"
)

failures = []


def run(sources, inventory):
    """Exit code and stderr of the gate over a temporary tree."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, text in sources.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        if inventory is not None:
            inv = root / "docs/ci/cxx-version-gates.tsv"
            inv.parent.mkdir(parents=True, exist_ok=True)
            inv.write_text(inventory)
        done = subprocess.run(
            [sys.executable, str(GATE), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, done.stdout + done.stderr


def expect(name, sources, inventory, code, needle=None):
    rc, output = run(sources, inventory)
    if rc != code or (needle is not None and needle not in output):
        failures.append(f"{name}: rc={rc} (want {code}), needle={needle!r}\n{output}")


# The control: the tree and its inventory agree, comments are not extracted,
# and the shapes that are not comparisons stay out.
expect(
    "clean tree passes",
    {"src/pool.cpp": FILL, "src/quiet.cpp": QUIET},
    HEADER + FILL_ROWS,
    0,
)

# A gate with no row.
expect(
    "an unlisted gate fails",
    {"src/pool.cpp": FILL + "bool late(uint8_t hf_version) { return hf_version >= 6; }\n"},
    HEADER + FILL_ROWS,
    1,
    "NOT IN THE INVENTORY",
)

# A row with no gate.
expect(
    "a stale row fails",
    {"src/pool.cpp": FILL.replace("  if (version >= 5)\n", "  if (ready)\n")},
    HEADER + FILL_ROWS,
    1,
    "IN THE INVENTORY, NOT IN THE TREE",
)

# One added, one removed: the count is unchanged and the set is not.
expect(
    "a swap at an unchanged count fails",
    {"src/pool.cpp": FILL.replace("if (version >= 5)", "if (version >= 7)")},
    HEADER + FILL_ROWS,
    1,
    "version >= 7",
)

# The same line twice needs a count of two, not a second row.
TWICE = "void a() { }\nif (tx.version > 1)\nint x;\nif (tx.version > 1)\n"
TWICE_ROW = (
    "src/db.cpp\t{n}\ttransaction version\talways true\tcollapse\ttx-version\tif (tx.version > 1)\n"
)
expect("a repeated line at its count passes", {"src/db.cpp": TWICE}, HEADER + TWICE_ROW.format(n=2), 0)
expect(
    "a repeated line under-counted fails",
    {"src/db.cpp": TWICE},
    HEADER + TWICE_ROW.format(n=1),
    1,
    "NOT IN THE INVENTORY (1x)",
)

# A definition or a declaration of a hard-fork table function is not a call.
# A call is refused under every landing, including a row that names it
# `tx-version`: the vocabulary check alone would accept that row.
DEFINITIONS = (
    "uint8_t Chain::get_ideal_hard_fork_version(uint64_t height) const\n"
    "{\n"
    "  return 1;\n"
    "}\n"
    "struct S\n"
    "{\n"
    "  virtual uint8_t get_hard_fork_version(uint64_t height) const = 0;\n"
    "  uint8_t get_ideal_hard_fork_version(uint64_t height) const;\n"
    "};\n"
)
CALL = "  return m_hardfork->get_ideal_version(height);\n"
CALL_ROW = (
    "src/chain.cpp\t1\thard-fork table\talways 1\tdelete\ttx-version\t"
    "return m_hardfork->get_ideal_version(height);\n"
)
expect(
    "a table definition is not a site",
    {"src/pool.cpp": FILL, "src/chain.cpp": DEFINITIONS},
    HEADER + FILL_ROWS,
    0,
)
expect(
    "a table call inventoried under tx-version is refused",
    {"src/pool.cpp": FILL, "src/chain.cpp": CALL},
    HEADER + FILL_ROWS + CALL_ROW,
    1,
    "not a classifiable site",
)
expect(
    "a table call with no row is refused",
    {"src/pool.cpp": FILL, "src/chain.cpp": CALL},
    HEADER + FILL_ROWS,
    1,
    "not a classifiable site",
)

# A named bound, a table comparison, a persisted-row byte and a `.cc` file are
# sites. Each fails until it has a row. The fill rows keep the inventory
# non-empty, so the failure is the unlisted line.
expect(
    "a named bound with no row fails",
    {"src/pool.cpp": FILL, "src/admit.cpp": NAMED},
    HEADER + FILL_ROWS,
    1,
    "return version < min_tx_version;",
)
expect(
    "a hard-fork comparison with no row fails",
    {"src/pool.cpp": FILL, "src/fork.cpp": FORK},
    HEADER + FILL_ROWS,
    1,
    "return block_version == heights[i].version;",
)
expect(
    "a persisted-row version with no row fails",
    {"src/pool.cpp": FILL, "src/row.h": ROWVER},
    HEADER + FILL_ROWS,
    1,
    "if (p[0] != kVersion)",
)
expect(
    "a .cc comparison with no row fails",
    {"src/pool.cpp": FILL, "src/note.cc": CC},
    HEADER + FILL_ROWS,
    1,
    "src/note.cc",
)

# The same shapes, classified, agree. `.cc` is a translation unit, not a skip.
expect(
    "named bounds, the table, kVersion and .cc pass when rowed",
    {
        "src/admit.cpp": NAMED,
        "src/fork.cpp": FORK,
        "src/row.h": ROWVER,
        "src/note.cc": CC,
        "src/quiet.cpp": QUIET,
    },
    HEADER + NAMED_ROW + FORK_ROW + ROWVER_ROW + CC_ROW,
    0,
)

# Disposition and landing are tokens. Empty and prose both fail.
expect(
    "an empty disposition fails",
    {"src/pool.cpp": FILL},
    HEADER + FILL_ROWS.replace("\tcollapse\t", "\t\t", 1),
    1,
    "is not one of",
)
expect(
    "an unknown disposition fails",
    {"src/pool.cpp": FILL},
    HEADER + FILL_ROWS.replace("\tcollapse\t", "\tlater\t", 1),
    1,
    "later",
)
expect(
    "an unknown landing fails",
    {"src/pool.cpp": FILL},
    HEADER + FILL_ROWS.replace("\ttx-version\t", "\tsoon\t", 1),
    1,
    "soon",
)

# Comparisons the extractor read past: a value on the left of a lone angle
# bracket, and an operand inside its own parentheses. Each is one line of
# code with no row, so each fails until the extractor sees it.
MISSED = {
    "a literal on the left of <": "return 5 < version;",
    "a constant on the left of <": "if (CURRENT_TRANSACTION_VERSION < version) return false;",
    "a literal on the left of >": "if (3 > tx.version) return false;",
    "a parenthesised operand": "return (version) >= 5;",
    "a cast operand": "return static_cast<int>(version) == 5;",
}
for shape, line in MISSED.items():
    expect(
        f"{shape} with no row fails",
        {"src/pool.cpp": FILL, "src/shape.cpp": line + "\n"},
        HEADER + FILL_ROWS,
        1,
        f"src/shape.cpp: {line}",
    )

# What must stay quiet beside them. A string or character literal is prose
# about a comparison, not one, and a template closer followed by a variable
# named `version` is a declaration.
PROSE = (
    'LOG_ERROR("tx version < 3 is not supported");\n'
    'throw std::runtime_error("entry version < 6: dropped by load_peers");\n'
    "const char angle = '<'; uint8_t version = read();\n"
    "std::array<char, 32> version;\n"
    "std::map<uint8_t, Row> by_version;\n"
)
expect(
    "literal contents and template closers are not rows",
    {"src/pool.cpp": FILL, "src/prose.cpp": PROSE},
    HEADER + FILL_ROWS,
    0,
)

# A literal beside real code does not hide the code, and the row keeps the
# line as written.
MIXED = 'CHECK(tx.version >= 3, "requires tx version >= 3");\n'
expect(
    "code beside a literal is still a row",
    {"src/pool.cpp": FILL, "src/mixed.cpp": MIXED},
    HEADER + FILL_ROWS,
    1,
    'src/mixed.cpp: CHECK(tx.version >= 3, "requires tx version >= 3");',
)

# The subject must exist (47-gate-subject-assertion).
expect("no C++ sources is refused", {"README.md": "x\n"}, HEADER + FILL_ROWS, 2, "no subject")
expect("a missing inventory is refused", {"src/pool.cpp": FILL}, None, 2, "is missing")
expect(
    "an empty inventory over a clean tree is refused",
    {"src/empty.cpp": "int main() { return 0; }\n"},
    HEADER,
    1,
    "delete this gate",
)

if failures:
    print("\n\n".join(failures), file=sys.stderr)
    print(f"\n{len(failures)} self-test case(s) failed", file=sys.stderr)
    sys.exit(1)
print("check_cxx_version_gates.py self-test: all cases pass")
