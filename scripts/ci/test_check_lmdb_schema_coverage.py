#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for the slice-A write-pattern leg of
# check_lmdb_schema_coverage.py.
#
# That leg exists because the enumeration was written by hand twice and
# was wrong both times, in both directions. A check that only pins the
# *count* of blind-upsert tables stays green under a rotation that keeps
# the count and changes the members — which is the defect that produced
# the leg. These fixtures bite that rotation, plus the subject-missing
# and named-count-mismatch cases.
#
# Run: `python3 scripts/ci/test_check_lmdb_schema_coverage.py`

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_lmdb_schema_coverage as GATE  # noqa: E402

# The four-row table as the freeze states it. Counts in the row labels
# are part of the parse (a label that says (5) but names 4 is red).
FALSIFIER = """\
### The per-table falsifier for `set-shaped`

| | Delete has the element | Blind upsert |
| --- | --- | --- |
| **DUPSORT/cursor-managed (5)** — `spent_keys`, `block_heights`, `tx_indices`, `output_txs`, `output_amounts` | **yes**, all five | **none** |
| **Range-cursor walks (3)** — `block_pending_additions`, `pending_tree_drain`, `archival_shard_segment` | **yes** | **yes**, all three |
| **`output_to_leaf`** | **yes** | **yes** |
| **Delete by key ALONE (6)** — `leaf_to_output`, `archival_bond`, `archival_slash_applied`, `block_burn`, `curve_tree_roots`, `pending_tree_leaves` | **NO** | **yes**, all six |
"""

SET_SHAPED = {
    "spent_keys", "block_heights", "tx_indices", "output_txs", "output_amounts",
    "block_pending_additions", "pending_tree_drain", "archival_shard_segment",
    "output_to_leaf",
    "leaf_to_output", "archival_bond", "archival_slash_applied", "block_burn",
    "curve_tree_roots", "pending_tree_leaves",
}

BLIND = {
    "block_pending_additions", "pending_tree_drain", "archival_shard_segment",
    "output_to_leaf",
    "leaf_to_output", "archival_bond", "archival_slash_applied", "block_burn",
    "curve_tree_roots", "pending_tree_leaves",
}

DELETE_ALONE = {
    "leaf_to_output", "archival_bond", "archival_slash_applied", "block_burn",
    "curve_tree_roots", "pending_tree_leaves",
}


def lmdb_src_for(blind: set[str], keyed_del: set[str]) -> str:
    """Minimal db_lmdb.cpp fragment the derive regex accepts."""
    parts = []
    for t in sorted(blind):
        parts.append(f"  int result = mdb_put(*m_write_txn, m_{t}, &k, &v, 0);")
    for t in sorted(keyed_del):
        parts.append(f"  int result = mdb_del(*m_write_txn, m_{t}, &k, nullptr);")
    return "\n".join(parts) + "\n"


class FalsifierParse(unittest.TestCase):
    def test_the_canonical_table_parses_to_the_named_sets(self):
        parsed, errors = GATE.parse_set_shaped_falsifier(FALSIFIER)
        self.assertEqual(errors, [], errors)
        self.assertIsNotNone(parsed)
        self.assertEqual(set(parsed.listed), SET_SHAPED)
        self.assertEqual(set(parsed.blind_upsert), BLIND)
        self.assertEqual(set(parsed.delete_alone), DELETE_ALONE)

    def test_stated_row_count_mismatch_is_red(self):
        # Label says (5) but one name is dropped. Cardinality of the
        # *other* rows still adds up; the named-count check must fire.
        broken = FALSIFIER.replace("`spent_keys`, ", "")
        parsed, errors = GATE.parse_set_shaped_falsifier(broken)
        self.assertTrue(
            any("says 5 tables but names 4" in e for e in errors),
            errors)
        self.assertIsNotNone(parsed)
        self.assertNotIn("spent_keys", parsed.listed)

    def test_missing_table_is_a_missing_subject(self):
        parsed, errors = GATE.parse_set_shaped_falsifier(
            "### The per-table falsifier\n\nNo table here.\n")
        self.assertIsNone(parsed)
        self.assertTrue(any("four-row table" in e for e in errors), errors)


class WritePatternSetEquality(unittest.TestCase):
    def test_matching_sets_are_green(self):
        src = lmdb_src_for(BLIND, DELETE_ALONE | {"output_to_leaf"})
        _blind, _dels, errors = GATE.check_write_patterns(
            lmdb_src=src,
            set_shaped=SET_SHAPED,
            falsifier_section=FALSIFIER,
        )
        self.assertEqual(errors, [], errors)

    def test_rotation_that_keeps_the_count_is_red(self):
        # spent_keys is cursor-managed (not blind). pending_tree_leaves is
        # blind. Swap them in the C++ fragment: ten tables still match
        # mdb_put(..., 0), but the members moved. A count pin stays green;
        # set equality must not.
        rotated_blind = (BLIND - {"pending_tree_leaves"}) | {"spent_keys"}
        self.assertEqual(len(rotated_blind), len(BLIND))
        src = lmdb_src_for(rotated_blind, DELETE_ALONE)
        _blind, _dels, errors = GATE.check_write_patterns(
            lmdb_src=src,
            set_shaped=SET_SHAPED,
            falsifier_section=FALSIFIER,
        )
        self.assertTrue(errors, "rotation with equal cardinality was green")
        blob = "\n".join(errors)
        self.assertIn("set equality, not cardinality", blob)
        self.assertIn("pending_tree_leaves", blob)
        self.assertIn("spent_keys", blob)

    def test_missing_falsifier_subsection_is_red(self):
        src = lmdb_src_for(BLIND, DELETE_ALONE)
        _blind, _dels, errors = GATE.check_write_patterns(
            lmdb_src=src,
            set_shaped=SET_SHAPED,
            falsifier_section=None,
        )
        self.assertTrue(any("falsifier subsection is gone" in e for e in errors),
                        errors)

    def test_delete_alone_without_keyed_mdb_del_is_red(self):
        src = lmdb_src_for(BLIND, DELETE_ALONE - {"block_burn"})
        _blind, _dels, errors = GATE.check_write_patterns(
            lmdb_src=src,
            set_shaped=SET_SHAPED,
            falsifier_section=FALSIFIER,
        )
        self.assertTrue(any("block_burn" in e and "no keyed mdb_del" in e
                            for e in errors), errors)


class CellFlag(unittest.TestCase):
    def test_none_is_not_no(self):
        self.assertFalse(GATE._cell_is_yes("**none**"))
        self.assertFalse(GATE._cell_is_yes("**NO** — value never read"))
        self.assertTrue(GATE._cell_is_yes("**yes**, all five"))


if __name__ == "__main__":
    unittest.main()
