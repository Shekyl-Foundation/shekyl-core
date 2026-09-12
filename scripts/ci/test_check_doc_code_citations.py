#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Regression tests for `scripts/ci/check_doc_code_citations.py`.
#
# Every limb of that gate gets a fixture that makes it FAIL, because a gate
# whose only proof of life is a defect sitting in the tree loses its proof the
# moment someone fixes the defect. These fixtures keep biting afterwards.
#
# The fixtures are markdown written to a temp dir, but they resolve against
# THIS repository's real history -- that is the subject under test, and a
# resolver proved only against a synthetic git tree would not be proved at all.
#
# A GREEN ASSERTION IS THE WEAK ONE, and this suite has paid for that four
# times. `assertEqual(rc, 0)` says the gate accepted the input; it does NOT
# say the gate accepted it for the right reason, because the defect the
# fixture names may produce a green too. Every such case here has had its
# input chosen so the defect produces the OPPOSITE verdict -- a file deleted
# since the pin, an era where the cited file does not exist, a basename that
# is ambiguous only at one revision. Before adding another, name the defect
# and say which way it would go; if it also goes green, the fixture proves
# nothing and belongs in the FATAL form instead.
#
# Run: `python3 scripts/ci/test_check_doc_code_citations.py` (stdlib unittest,
# no runner needed -- matches scripts/bench/test_compare.py).

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_doc_code_citations.py"

# Real revisions in this repository. The gate's whole job is resolving against
# declared history, so these are deliberately concrete.
PIN = "4b9807c5e"  # the §5.4.1 review pin
ROW_PIN_PRESENT = "e54e5b983"  # curve_tree_header_root_check.cpp EXISTS here
UNBORN = "2dba46537"  # predates tests/unit_tests/curve_tree_header_root_check.cpp


def run_gate(*docs):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--docs", ",".join(str(d) for d in docs)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


class Fixture:
    def __init__(self, body):
        self.dir = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.dir.name) / "fixture.md"
        self.path.write_text(body, encoding="utf-8")

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self.dir.cleanup()


class AmbiguousPath(unittest.TestCase):
    def test_basename_matching_two_files_is_fatal(self):
        """The W-FU class: one hit in the WRONG file. Resolving uniquely is
        not resolving correctly, and this is the shape that proves it."""
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\n"
            "Evidence: `cryptonote_format_utils.cpp:800`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("matches 2 tracked files", out)
        self.assertIn("src/cryptonote_basic/cryptonote_format_utils.cpp", out)
        self.assertIn("tests/unit_tests/cryptonote_format_utils.cpp", out)

    def test_unique_basename_passes(self):
        """A bare basename is NOT a defect when it resolves uniquely.
        Demanding directory-qualified paths doc-wide would FATAL every
        `blockchain.cpp:NNNN` row to buy nothing."""
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\nEvidence: `ct_semantics.cpp:206`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_path_suffix_resolves(self):
        """Docs cite `cryptonote_core/blockchain.cpp`, not the full
        `src/cryptonote_core/...`. Requiring full paths would FATAL the corpus."""
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\n"
            "Evidence: `cryptonote_core/blockchain.cpp:3403`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)


class EraSelection(unittest.TestCase):
    def test_citation_valid_at_its_pin_but_absent_at_head_passes(self):
        """The reason this gate is not a link checker: a records-was citation
        is true at its sha and is NOT required to be true now.

        The cited file was DELETED between the pin and HEAD, which is what
        makes the assertion discriminating. An earlier version cited a file
        that still exists at HEAD, so resolving at the wrong era passed too
        and the test could not tell the two apart.
        """
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\n"
            "Evidence: `shekyl-tor/src/binary.rs:1`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, "a file deleted since the pin must still resolve AT the pin")

    def test_file_not_yet_born_at_the_declared_pin_is_fatal(self):
        """Resolution really happens at the pin: a file that exists at HEAD but
        not at the pin must FAIL, or the pin is decorative."""
        with Fixture(
            f"## S\n\nReviewed at **`{UNBORN}`**.\n\n"
            "Evidence: `tests/unit_tests/curve_tree_header_root_check.cpp:1`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("matches no tracked file", out)
        self.assertIn(UNBORN, out)

    def test_row_level_pin_overrides_the_section_pin(self):
        """A row citing against its own pin inside a section pinned elsewhere.

        The two eras are chosen to DISAGREE: the cited file is absent at the
        section pin and present at the row pin, so the test fails if the
        override is not applied. The earlier version of this fixture used a
        spelling the parser does not treat as a pin AND a file that exists at
        both eras, so it passed without the override ever applying -- vacuous
        in exactly the way this gate exists to catch.
        """
        with Fixture(
            f"## S\n\nReviewed at **`{UNBORN}`**.\n\n"
            f"| CEN-X1 | re-reviewed at `{ROW_PIN_PRESENT}` | "
            "`tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_without_the_row_override_the_same_row_fails(self):
        """The other half: drop the override and the section pin governs, where
        the file does not exist. This is what makes the test above non-vacuous."""
        with Fixture(
            f"## S\n\nReviewed at **`{UNBORN}`**.\n\n"
            "| CEN-X1 | no override | "
            "`tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("matches no tracked file", out)

    def test_section_pin_does_not_leak_past_its_heading(self):
        """Measured false FATAL: the §5.4.1 slice pin leaking into the decision
        log made a dated ledger row cite a file that did not exist yet. A pin's
        scope ends at the next same-or-shallower heading."""
        with Fixture(
            f"### Slice\n\nReviewed at **`{UNBORN}`**.\n\n"
            "Evidence: `cryptonote_core/blockchain.cpp:1`.\n\n"
            "## Decision log\n\n"
            "| 2026-09-05 | landed `tests/unit_tests/curve_tree_header_root_check.cpp` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_unreachable_pin_is_fatal_not_skipped(self):
        """CI's default checkout is depth 1, where `git show <old-sha>:path`
        simply fails. Treating that as 'nothing to check' would pass vacuously
        on every PR -- the gate must refuse to run rather than run empty."""
        with Fixture(
            "## S\n\nReviewed at **`deadbee1234`**.\n\n"
            "Evidence: `cryptonote_core/blockchain.cpp:1`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("unreachable", out)

    def test_unparseable_era_declaration_is_fatal(self):
        """A document pinning in a form the parser cannot read would fall
        through to HEAD on every row -- silently resolving records-was
        citations against current code, the exact defect this gate exists to
        catch, wearing a green tick."""
        with Fixture(
            "## S\n\nP0b rows: `dev` `2dba46537`. Line citations are records-was.\n\n"
            "Evidence: `cryptonote_core/blockchain.cpp:1`.\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("declares an era this gate does not parse", out)


class SectionScopedEra(unittest.TestCase):
    def test_unparsed_pin_in_ONE_section_of_a_pinned_document_is_fatal(self):
        """The limb that shipped without coverage, found empirically by a lane
        whose sixteen rows all resolved at HEAD while the gate called them
        green 'at their declared eras'.

        A document-level 'are there any parseable pins?' test is satisfied by
        the document's OTHER slices and never fires. The two eras here
        disagree on purpose: the cited file exists at HEAD and NOT at the sha
        slice B declares, so resolving at the wrong era is the difference
        between pass and fail rather than a cosmetic one."""
        with Fixture(
            f"### Slice A\n\nReviewed at **`{PIN}`**.\n\n"
            "Evidence: `cryptonote_core/blockchain.cpp:3403`.\n\n"
            f"### Slice B\n\nReviewed at `{UNBORN}`.\n\n"
            "| CEN-X1 | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1, "an unbolded slice pin must not pass on the "
                                "strength of its neighbours' pins")
        self.assertIn("Slice B", out)
        self.assertIn("declares an era this gate does not parse", out)
        self.assertNotIn("Slice A", out)

    def test_row_level_shas_in_a_ledger_do_not_trip_the_section_check(self):
        """The false positive the rule must avoid: a dated ledger whose rows
        carry their own provenance shas in table cells is not a section
        declaring an era, and its unpinned citations are asserts-is."""
        with Fixture(
            "## Decision log\n\n"
            "| 2026-09-05 | fixed at `4b9807c5e` | `cryptonote_core/blockchain.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)


    def test_unparsed_child_pin_under_a_PARSED_parent_is_fatal(self):
        """The register's real heading shape, and the hole the sibling-only
        test missed.

        An unbolded `#####` slice pin under a `####` parent that IS parsed:
        the slice's rows inherit the PARENT's sha, so nothing falls back to
        HEAD and a 'did anything reach HEAD' test never fires. The eras are
        chosen so the inherited one RESOLVES -- the file exists at the parent
        era and not at the era the slice declares -- which is what makes the
        failure silent rather than loud."""
        with Fixture(
            f"#### Register\n\nReviewed at **`{ROW_PIN_PRESENT}`**.\n\n"
            "| CEN-A | ok | `cryptonote_core/blockchain.cpp:1` |\n\n"
            f"##### P0f slice 9\n\nReviewed at `{PIN}`.\n\n"
            "| CEN-X1 | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1, "an unparsed child pin must not hide behind its "
                                "parent's parsed one")
        self.assertIn("P0f slice 9", out)
        self.assertIn("resolved at a DIFFERENT revision", out)

    def test_unparsed_pin_agreeing_with_the_inherited_era_is_not_flagged(self):
        """No defect, so no finding. If the unparsed declaration names the same
        sha the section would have inherited anyway, nothing resolves at the
        wrong revision -- reporting it would be noise, and a gate that cries
        wolf gets deleted."""
        with Fixture(
            f"#### Register\n\nReviewed at **`{PIN}`**.\n\n"
            f"##### Slice\n\nReviewed at `{PIN}`.\n\n"
            "| CEN-A | ok | `cryptonote_core/blockchain.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)


    def test_child_section_with_its_OWN_parsed_pin_is_not_attributed_to_the_parent(self):
        """A nested slice that pins itself is untouched by an unparsed parent.

        The child's parsed pin is more specific and would govern these rows
        whether or not the parent's declaration parsed, so nothing about them
        is mis-resolved. An earlier version re-implemented scope and skipped
        only inline row pins, so it counted these as misresolved and FATALed a
        correct document."""
        with Fixture(
            f"#### Register\n\nReviewed at `{UNBORN}`.\n\n"
            f"##### Slice\n\nReviewed at **`{ROW_PIN_PRESENT}`**.\n\n"
            "| CEN-X1 | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_an_era_finding_does_not_mask_the_rest_of_the_document(self):
        """Only the citations an unparsed declaration actually mis-scopes are
        skipped. Aborting the whole file on one era finding let a single
        refusal hide every other defect in it."""
        with Fixture(
            f"#### R\n\nReviewed at `{UNBORN}`.\n\n"
            "| a | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n\n"
            "## Other\n\n| b | ok | `blockchain_db.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("declares an era this gate does not parse", out)
        self.assertIn("matches 2 tracked files", out)


    def test_a_sibling_slice_inherits_the_PARENT_pin_not_HEAD(self):
        """Pins nest, so they are held on a stack.

        With a pinned `####` parent, a pinned `#####` slice, and a SECOND
        `#####` slice pinning nothing, a single-pin parser cleared the child's
        pin at the sibling heading and left nothing behind — the sibling fell
        to HEAD and its records-was citations resolved against current code.

        Stated as a FATAL on purpose. The first version of this fixture
        asserted a GREEN, and a green cannot tell "inherited the parent"
        from "fell through to HEAD" whenever the cited file resolves at both
        — which it did, so the test passed under the very parser it named.
        Here the parent era is one where the file does NOT exist, so:
            stack parser  -> Slice B inherits the parent -> absent -> FATAL
            single pin    -> Slice B falls to HEAD       -> present -> green
        The defect now produces the opposite verdict, which is the only thing
        that makes the assertion worth anything.
        """
        with Fixture(
            f"#### Parent\n\nReviewed at **`{UNBORN}`**.\n\n"
            f"##### Slice A\n\nReviewed at **`{ROW_PIN_PRESENT}`**.\n\n"
            "| CEN-X | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n\n"
            "##### Slice B\n\n"
            "| CEN-Y | ok | `tests/unit_tests/curve_tree_header_root_check.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1, "Slice B must inherit the parent era, not fall to HEAD")
        self.assertIn("matches no tracked file", out)
        self.assertIn(UNBORN, out)

    def test_an_era_finding_in_one_slice_does_not_hide_a_defect_in_its_SIBLING(self):
        """The counterfactual diff must not attribute a sibling's rows to the
        slice above it. When it did, the sibling was marked mis-scoped and
        skipped, so a real ambiguous-basename defect in it went unreported
        behind the neighbour's era finding."""
        with Fixture(
            f"#### Parent\n\nReviewed at **`{ROW_PIN_PRESENT}`**.\n\n"
            f"##### Slice A\n\nReviewed at `{PIN}`.\n\n"
            "| CEN-X | ok | `cryptonote_core/blockchain.cpp:1` |\n\n"
            "##### Slice B\n\n| CEN-Y | ok | `blockchain_db.cpp:1` |\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("declares an era this gate does not parse", out)
        self.assertIn("matches 2 tracked files", out)

    def test_a_legend_under_an_unparsed_declaration_yields_no_containment_finding(self):
        """Containment must honour the same mis-scoped filter the path limb
        does. A legend read at an era the document does not claim would
        produce findings built on the very premise the gate refused."""
        with Fixture(
            f"### S\n\nReviewed at `{PIN}`.\n\n"
            "Walks: **W-TI** = the spend-path\n"
            "gates in `check_tx_inputs` (`cryptonote_core/blockchain.cpp:100\u2013120`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("declares an era this gate does not parse", out)
        self.assertNotIn("come loose from the symbol", out)


class SymbolAndRange(unittest.TestCase):
    def test_range_inside_exactly_one_overload_passes(self):
        """W-TI: `check_tx_inputs` has two definitions at the pin, [3310,3328]
        and [3499,4419]. The cited 3536-3740 sits in exactly one, so the doc
        already disambiguated and the gate must not cry wolf."""
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\n"
            "Walks: **W-TI** = the spend-path gates in `check_tx_inputs` "
            "(`cryptonote_core/blockchain.cpp:3536–3740`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_range_touching_no_definition_is_fatal(self):
        """The defect the rule is for: a range that overlaps NO definition of
        the symbol it names -- a pointer that has come loose from its
        subject."""
        with Fixture(
            f"## S\n\nReviewed at **`{PIN}`**.\n\n"
            "Walks: **W-TI** = `check_tx_inputs` "
            "(`cryptonote_core/blockchain.cpp:100–120`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("overlaps no definition", out)
        self.assertIn("come loose from the symbol", out)



    def test_containment_runs_across_a_WRAPPED_legend(self):
        """The register's legends wrap: the `**W-TI**` marker sits on one line
        while the symbol and range sit on the next. A per-line check ran on 3
        citations in the whole register and never once on W-TI -- the overload
        case the rule was written for. Checked over the legend BLOCK now."""
        with Fixture(
            f"### S\n\nReviewed at **`{PIN}`**.\n\n"
            "Walks: **W-TI** = the spend-path\n"
            "gates in `check_tx_inputs` (`cryptonote_core/blockchain.cpp:100\u2013120`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1, "a wrapped legend must still be checked")
        self.assertIn("W-TI", out)

    def test_the_Walk_spelling_is_recognised(self):
        """The register writes both `**W-TI**` and `**Walk W-BP**`. A marker
        regex matching only the first silently skipped every walk using the
        second."""
        with Fixture(
            f"### S\n\nReviewed at **`{PIN}`**.\n\n"
            "- **Walk W-BP** — bond-post: `check_tx_inputs`\n"
            "  (`cryptonote_core/blockchain.cpp:100\u2013120`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1, "the `**Walk W-XX**` spelling must be checked too")
        self.assertIn("W-BP", out)

    def test_region_walk_spanning_two_functions_passes(self):
        """A walk range may deliberately SPAN several functions — W-MT covers
        `prevalidate_miner_transaction` and `validate_miner_transaction`
        together. Strict containment-in-one would FATAL that correct row, which
        is why the rule is overlap."""
        with Fixture(
            f"### S\n\nReviewed at **`{PIN}`**.\n\n"
            "One walk, **W-MT**:\n"
            "`prevalidate_miner_transaction` + `validate_miner_transaction`\n"
            "(`cryptonote_core/blockchain.cpp:1653\u20131822`).\n"
        ) as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 0, out)

    def test_a_symbol_is_not_matched_as_a_substring(self):
        """`validate_miner_transaction` must not match inside
        `prevalidate_miner_transaction`. The substring form reported two
        definitions where the file has one of each, turning a correct walk into
        a FATAL."""
        blob = ["bool Blockchain::prevalidate_miner_transaction(const block& b)",
                "{", "  return true;", "}"]
        import importlib.util
        spec = importlib.util.spec_from_file_location("g", str(SCRIPT))
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        self.assertEqual(gate.definition_extents(blob, "validate_miner_transaction"), [])
        self.assertEqual(len(gate.definition_extents(blob, "prevalidate_miner_transaction")), 1)


class CorpusCrossCheck(unittest.TestCase):
    def test_document_yielding_zero_citations_is_fatal(self):
        """The regex-stopped-matching failure. A listed document with no
        citations reports the same green as one that was fully read -- so it
        must not be green. This is the ffi_boundary_ratchet cross-check shape."""
        with Fixture("## S\n\nProse with no code citations at all.\n") as doc:
            rc, out = run_gate(doc)
        self.assertEqual(rc, 1)
        self.assertIn("ZERO code citations", out)

    def test_missing_listed_document_is_fatal(self):
        """A renamed or moved document must not silently drop out of the
        corpus."""
        rc, out = run_gate("docs/design/NO_SUCH_DOCUMENT.md")
        self.assertEqual(rc, 1)
        self.assertIn("not present", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
