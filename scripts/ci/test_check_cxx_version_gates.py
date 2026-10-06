# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_cxx_version_gates.py. The gate compares two sets, so it
# is bitten in both directions and on the case a count would miss: one gate
# added and another removed. The extractor is pinned on the shape that
# motivated it (a bare `version >= 5`, which the first draft of the regex did
# not match) and on what it must leave alone.

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
    "src/pool.cpp\t1\tblock major version\talways false\tmove to Rust\tthe fill PR\t"
    "size_t bound = version >= 5 ? wide : narrow;\n"
    "src/pool.cpp\t1\tblock major version\talways false\tmove to Rust\tthe fill PR\t"
    "if (version >= 5)\n"
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


# The control: the tree and its inventory agree, comments are not extracted.
expect("clean tree passes", {"src/pool.cpp": FILL}, HEADER + FILL_ROWS, 0)

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
TWICE_ROW = "src/db.cpp\t{n}\ttransaction version\talways true\tcollapse\ttx PR\tif (tx.version > 1)\n"
expect("a repeated line at its count passes", {"src/db.cpp": TWICE}, HEADER + TWICE_ROW.format(n=2), 0)
expect(
    "a repeated line under-counted fails",
    {"src/db.cpp": TWICE},
    HEADER + TWICE_ROW.format(n=1),
    1,
    "NOT IN THE INVENTORY (1x)",
)

# A hard-fork table call is extracted; its definition and declaration are not.
LOOKUP = (
    "uint8_t Chain::get_ideal_hard_fork_version(uint64_t height) const\n"
    "{\n"
    "  return m_hardfork->get_ideal_version(height);\n"
    "}\n"
    "struct S\n"
    "{\n"
    "  virtual uint8_t get_hard_fork_version(uint64_t height) const = 0;\n"
    "  uint8_t get_ideal_hard_fork_version(uint64_t height) const;\n"
    "};\n"
)
expect(
    "a table call is a row, a definition is not",
    {"src/chain.cpp": LOOKUP},
    HEADER
    + "src/chain.cpp\t1\thard-fork table\talways 1\twith the mechanism\tits decision\t"
    "return m_hardfork->get_ideal_version(height);\n",
    0,
)

# What the extractor leaves alone: other spellings of "version", and one
# variable compared with another.
QUIET = (
    "#if BOOST_VERSION >= 107400\n"
    "if (osvi.dwMajorVersion == 10) { }\n"
    "if (tx.version < min_tx_version || new_hf_version != hf_version) { }\n"
)
expect(
    "non-operands are not extracted",
    {"src/pool.cpp": FILL, "src/quiet.cpp": QUIET},
    HEADER + FILL_ROWS,
    0,
)

# A row every classification column of which is filled, or it is not a row.
expect(
    "an unclassified row fails",
    {"src/pool.cpp": FILL},
    HEADER + FILL_ROWS.replace("\tmove to Rust\t", "\t\t", 1),
    1,
    "`disposition` is empty",
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
