#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_archival_forcing_cells.py (AFC-1).
#
# The gate's four legs were each bitten by hand when it was written. Hand
# bites are not a pin: a later edit can weaken a leg and nothing notices,
# which is the failure mode the gate itself exists to prevent one level up.
# These fixtures pin all four, in the direction that matters -- a weakened
# leg must make some case here go GREEN that should be RED.
#
# One case is the gate's own history. The anchor leg first matched any 8+
# character lowercase word from the free-text `note`, so a row could resolve
# to a comment containing a generic word rather than to code. `passes_on_a_
# generic_word_in_a_comment` holds that door shut: the symbol column is
# matched exactly, so prose in the note cannot satisfy an anchor.
#
# Run: `python3 scripts/ci/test_check_archival_forcing_cells.py`

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_archival_forcing_cells as GATE  # noqa: E402

HEADER = "table\thalf\tdisposition\tsite\tsymbol\tnote\n"

# Two tables is enough to exercise every leg; the real register's size is
# not what any leg is about.
MACRO = (
    "#define SHEKYL_LMDB_TABLES(X) \\\n"
    '  X(LMDB_ARCHIVAL_BOND, "archival_bond") \\\n'
    '  X(LMDB_ARCHIVAL_BUDGET, "archival_budget") \\\n'
    "\n"
)

SRC = "void put_archival_bond_record() {}\nvoid remove_archival_bond_record() {}\n"


def rows(*overrides: str) -> str:
    """The minimal GREEN register, with literal row overrides appended."""
    base = [
        "archival_bond\tapply\tFORCED-BY:bond-post\tsrc.cpp:1\tput_archival_bond_record\tnote",
        "archival_bond\trevert\tFORCED-BY:pop\tsrc.cpp:2\tremove_archival_bond_record\tnote",
        "archival_budget\tapply\tFORCED-BY:epoch-close\tsrc.cpp:1\tput_archival_bond_record\tnote",
        "archival_budget\trevert\tEXCLUDED:vacuous\tsrc.cpp:2\tremove_archival_bond_record\tnote",
    ]
    return HEADER + "\n".join(list(overrides) or base) + "\n"


class AfcGateLegs(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        self.tsv = d / "cells.tsv"
        self.macro = d / "db_lmdb.cpp"
        self.src = d / "src.cpp"
        self.macro.write_text(MACRO)
        self.src.write_text(SRC)
        self._saved = (GATE.TSV, GATE.XMACRO_SRC, GATE.SOURCES)
        GATE.TSV = self.tsv
        GATE.XMACRO_SRC = self.macro
        GATE.SOURCES = {"src.cpp": self.src}
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        GATE.TSV, GATE.XMACRO_SRC, GATE.SOURCES = self._saved

    def run_gate(self, text: str) -> int:
        self.tsv.write_text(text)
        return GATE.main()

    # Control. Without this, every RED below could be red for the wrong reason.
    def test_the_minimal_register_is_green(self) -> None:
        self.assertEqual(self.run_gate(rows()), 0)

    # Leg 1 — shape.
    def test_wrong_field_count_is_red(self) -> None:
        self.assertEqual(
            self.run_gate(rows("archival_bond\tapply\tFORCED-BY:x\tsrc.cpp:1\tput_archival_bond_record")), 1
        )

    def test_unknown_half_is_red(self) -> None:
        bad = rows().replace("archival_bond\tapply", "archival_bond\tmaybe", 1)
        self.assertEqual(self.run_gate(bad), 1)

    # Leg 2 — denominator, both directions, duplicates, and the subject.
    def test_table_missing_from_the_register_is_red(self) -> None:
        keep = [r for r in rows().splitlines()[1:] if not r.startswith("archival_budget")]
        self.assertEqual(self.run_gate(HEADER + "\n".join(keep) + "\n"), 1)

    def test_table_absent_from_the_macro_is_red(self) -> None:
        extra = rows() + "archival_ghost\tapply\tFORCED-BY:x\tsrc.cpp:1\tput_archival_bond_record\tn\n"
        extra += "archival_ghost\trevert\tFORCED-BY:x\tsrc.cpp:2\tremove_archival_bond_record\tn\n"
        self.assertEqual(self.run_gate(extra), 1)

    def test_duplicate_macro_entry_is_red(self) -> None:
        # Collapsing straight to a set would hide this: the difference and the
        # half counts both stay green over a macro that names a table twice.
        self.macro.write_text(MACRO.replace("\n\n", '  X(LMDB_ARCHIVAL_BOND, "archival_bond") \\\n\n'))
        self.assertEqual(self.run_gate(rows()), 1)

    def test_both_halves_the_same_is_red(self) -> None:
        bad = rows().replace("archival_bond\trevert", "archival_bond\tapply", 1)
        self.assertEqual(self.run_gate(bad), 1)

    def test_macro_renamed_is_red_not_empty_agreement(self) -> None:
        # Rule 47: a gate must assert its own subject exists.
        self.macro.write_text(MACRO.replace("SHEKYL_LMDB_TABLES", "SHEKYL_LMDB_TABLES_RENAMED"))
        self.assertEqual(self.run_gate(rows()), 1)

    # Leg 3 — disposition.
    def test_unknown_disposition_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("FORCED-BY:bond-post", "MAYBE:bond-post", 1)), 1)

    def test_disposition_with_no_payload_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("FORCED-BY:bond-post", "FORCED-BY:", 1)), 1)

    def test_exclusion_with_no_reason_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("EXCLUDED:vacuous", "EXCLUDED:   ", 1)), 1)

    # Leg 4 — anchors.
    def test_drifted_anchor_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("src.cpp:1", "src.cpp:2", 1)), 1)

    def test_anchor_past_end_of_file_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("src.cpp:1", "src.cpp:999", 1)), 1)

    def test_empty_symbol_is_red(self) -> None:
        self.assertEqual(self.run_gate(rows().replace("\tput_archival_bond_record\t", "\t\t", 1)), 1)

    def test_passes_on_a_generic_word_in_a_comment(self) -> None:
        # The gate's own regression. `note` says "template writer"; the site
        # line is a comment containing "template" and no symbol. Under the
        # original note-word matcher this was GREEN.
        self.src.write_text("// until the Phase 2/3 template writer populates it\nvoid x() {}\n")
        bad = rows(
            "archival_bond\tapply\tEXCLUDED:no-producer\tsrc.cpp:1\tstore_archival_attestation_witness\ttemplate writer populates it",
            "archival_bond\trevert\tFORCED-BY:pop\tsrc.cpp:2\tvoid x\tnote",
            "archival_budget\tapply\tFORCED-BY:x\tsrc.cpp:2\tvoid x\tnote",
            "archival_budget\trevert\tFORCED-BY:x\tsrc.cpp:2\tvoid x\tnote",
        )
        self.assertEqual(self.run_gate(bad), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
