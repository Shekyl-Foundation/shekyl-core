// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.I, the view-bound rows — what a transaction's inputs claim
//! against what the chain has recorded (`CHAIN_RULES_SLICE_6.md` commit 4
//! onward). These are [`TxAgainstRule`]s and run in `tx_against`, after
//! `tx_form` has admitted the bytes: the C++'s `check_tx_inputs` order, the
//! stateless arms first and the DB lookups after.
//!
//! The pool (DRS-E5) calls `tx_against` with its view decorator — the chain
//! plus the pool's own spent set — so one rule serves both admission sites,
//! and a key image spent by a pooled transaction is refused by the same row
//! that refuses one spent on-chain.
//!
//! **Key-image uniqueness has two halves and this module holds both.** I7
//! is the chain-wide half, per transaction against the view. CEN-L1 is the
//! intra-block half — no key image twice among one block's inputs — and is
//! a [`BlockRule`] over the candidate, run after every slot has been judged,
//! because a per-slot view sees the chain as it was before the block and
//! not the block's own earlier slots. Landing I7 without L1 would have left
//! a block with two spends of one image passing `validate` and meeting the
//! store's SI-1 belt at connect — a *fatal* invariant, which halts the
//! writer; that is a halt a peer could trigger with two valid spends of an
//! output it owns. The belt exists to catch a validator with a hole, not to
//! be the rule (`STORE_INVARIANT_REGISTER.md` SI-1; the census minted L1 as
//! the validator's, C2-R8 Q6).

use std::collections::BTreeSet;

use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, PerHeightRecord, ViewRead};
use crate::rules::tx::TxClass;
use crate::rules::{BlockContext, BlockRule, Rule, TxAgainstRule, TxContext, TxScope};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::{AtHeight, ChainView, Tip};
use shekyl_types::{BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Ct, Input};

// CEN-I11's window, from `config/consensus_constants.json` at build time
// (`build.rs`). The same file drives the C++ header and
// `shekyl-curve-tree`. The consts stay beside the rule (slice 6 Q5): no
// schedule step varies them, so they are not `RuleSet` fields. The
// sentinels below are the review gate a JSON edit must touch on purpose;
// `reference_window_is_the_json_authoritys` is the falsifier that these
// consts are still that file.
include!(concat!(env!("OUT_DIR"), "/reference_window_generated.rs"));

/// CEN-I11's window, lower edge: a spend's `referenceBlock` is at least
/// this many blocks below the connecting height (`ref_height ≤
/// chain_height − MIN_AGE`; `blockchain.cpp:4121`).
pub const REFERENCE_BLOCK_MIN_AGE: BlockCount = BlockCount::from_raw(FCMP_REFERENCE_BLOCK_MIN_AGE);

/// CEN-I11's window, upper edge: a spend's `referenceBlock` is at most
/// this many blocks below the connecting height (`ref_height ≥
/// chain_height − MAX_AGE`; `blockchain.cpp:4133`).
pub const REFERENCE_BLOCK_MAX_AGE: BlockCount = BlockCount::from_raw(FCMP_REFERENCE_BLOCK_MAX_AGE);

const _: () = assert!(
    REFERENCE_BLOCK_MIN_AGE.to_raw() == 5,
    "fcmp_reference_block_min_age left the baseline 5; review CEN-I11 before updating this sentinel"
);
const _: () = assert!(
    REFERENCE_BLOCK_MAX_AGE.to_raw() == 100,
    "fcmp_reference_block_max_age left the baseline 100; review CEN-I11 before updating this sentinel"
);
const _: () = assert!(
    REFERENCE_BLOCK_MAX_AGE.to_raw() > REFERENCE_BLOCK_MIN_AGE.to_raw(),
    "the reference window is empty"
);

/// CEN-I7: no input's key image is already spent on the recorded chain
/// (`blockchain.cpp` `have_tx_keyimg_as_spent`, per `ToKey` input — the
/// regular spend's arm and the bond-post funding and emission fee-input
/// arms alike; one lookup per key image, whichever class carries it).
/// The chain-wide half of key-image uniqueness; SI-1 is the store's belt
/// beneath it at connect: this rule refuses the block, the store refuses to
/// record what a refused block would have written, and neither relies on
/// the other.
///
/// Non-coinbase: the coinbase has no key image to look up. In-transaction
/// repeats are CEN-H10's (`tx_form`); repeats across a block's listed
/// transactions are CEN-L1's ([`L1`], below), because this rule's view is
/// the chain before the block.
///
/// The refusal names the **input** (`Locus::Input`), as the E2 replay
/// spec's mutation table states for this row (`DRS_E2_REPLAY_DRIVER.md`
/// §3.10, `DoubleSpend → I7 at an input`): the lookup is per input, and
/// the operator sees which spend was already made, not merely that one
/// was.
pub(crate) struct I7;

impl Rule for I7 {
    const ROW: CenRow = CenRow::I7;
}

impl TxAgainstRule for I7 {
    const SCOPE: TxScope = TxScope::NonCoinbase;

    fn check<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        for (input, item) in cx.tx.prefix.inputs.iter().enumerate() {
            let Input::ToKey { key_image, .. } = item else {
                continue;
            };
            if view.has_key_image(&KeyImage::from_bytes(*key_image))? {
                return Ok(Err(InvalidBlock::new(
                    Self::ROW,
                    Locus::Input {
                        slot: cx.slot,
                        input,
                    },
                )));
            }
        }
        Ok(Ok(()))
    }
}

/// CEN-L1: no key image appears twice among one block's inputs — the
/// intra-block half of key-image uniqueness (C2-R8 Q6, minted as the
/// validator's rule; the C++ enforces it only at `add_spent_key`'s
/// `MDB_NODUPDATA` put, caught as a block rejection). Runs after every
/// slot has passed `tx_form` and `tx_against`, over the listed transactions
/// only: the coinbase has no key image, and a repeat *within* one
/// transaction is H10's and has already refused. The refusal names the
/// second occurrence — the slot and the input — so the operator sees which
/// spend collided, not merely that one did.
///
/// Reads no view: the block's own inputs are the whole subject. It is a
/// [`BlockRule`] rather than a `tx_form` rule because it spans slots.
pub(crate) struct L1;

impl Rule for L1 {
    const ROW: CenRow = CenRow::L1;
}

impl BlockRule for L1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        for (n, tx) in cx.candidate().transactions.iter().enumerate() {
            for (input, item) in tx.prefix.inputs.iter().enumerate() {
                let Input::ToKey { key_image, .. } = item else {
                    continue;
                };
                if !seen.insert(*key_image) {
                    return Ok(Err(InvalidBlock::new(
                        Self::ROW,
                        Locus::Input {
                            slot: TxSlot::Listed(n),
                            input,
                        },
                    )));
                }
            }
        }
        Ok(Ok(()))
    }
}

/// The reference a regular spend carries, if this transaction is one: the
/// `Ct::Fcmp` `reference_block` of a [`TxClass::Spend`]. The archival
/// classes take the C++'s other arms (`blockchain.cpp:3460–3486`) and are
/// not this row family's subject; a `Null` CT on a spend is CEN-H15's
/// refusal in `tx_form`, and here it is nothing to look up.
fn spend_reference(cx: &TxContext<'_>) -> Option<BlockHash> {
    if !matches!(cx.class, TxClass::Spend { .. }) {
        return None;
    }
    match &cx.tx.ct {
        Ct::Fcmp {
            reference_block, ..
        } => Some(*reference_block),
        Ct::Null(_) => None,
    }
}

/// CEN-I10: a regular spend's `referenceBlock` is a block on this chain
/// (`blockchain.cpp:4113` `m_db->block_exists(rv.referenceBlock, &ref_height)`
/// — a lookup by hash, so the read is [`ChainView::height_of`] and absence
/// is one thing: not on this chain). The height it answers is the operand
/// I11 measures and I12 reads the root at, so this row is written the way
/// D4 is — a rule that **yields** its operand, run once by `tx_against`,
/// rather than a [`TxAgainstRule`] whose two successors would each repeat
/// the lookup.
///
/// A spend with no reference to look up — `Null` CT — is refused here too:
/// "is a main-chain block" is false of no block. `tx_form` names it H15
/// first, so this arm is reachable only through `tx_against` alone.
pub(crate) struct I10;

impl Rule for I10 {
    const ROW: CenRow = CenRow::I10;
}

impl I10 {
    /// The reference's height for `cx`'s spend, recorded as this row on a
    /// pass; `Ok(Ok(None))` for a transaction that is not a regular spend
    /// (nothing to look up — the row is vacuous there and recorded, as
    /// [`run_tx_against`](crate::rules::run_tx_against) records an
    /// out-of-scope kind).
    pub(crate) fn reference_height<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        coverage: &mut RuleCoverage,
    ) -> Result<Verdict<Option<BlockHeight>>, V::Fault> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            coverage.insert(Self::ROW);
            return Ok(Ok(None));
        }
        let Some(reference) = spend_reference(cx) else {
            return Ok(Err(InvalidBlock::new(Self::ROW, cx.locus())));
        };
        match view.height_of(&reference)? {
            Some(ref_height) => {
                coverage.insert(Self::ROW);
                Ok(Ok(Some(ref_height)))
            }
            None => Ok(Err(InvalidBlock::new(Self::ROW, cx.locus()))),
        }
    }
}

/// CEN-I11: the reference's height is within the window below the
/// connecting height — at least [`REFERENCE_BLOCK_MIN_AGE`] blocks old and
/// at most [`REFERENCE_BLOCK_MAX_AGE`] (`blockchain.cpp:4121–4141`). The
/// C++'s `chain_height` is `m_db->height()`, the block count, which is the
/// connecting height ([`Tip::connecting_height`]); its two guards are
/// written here as the two `checked_sub`s they are:
///
/// - too recent: `chain_height < MIN_AGE || ref_height > chain_height −
///   MIN_AGE` — no admissible reference exists at all, or this one is
///   younger than the newest admissible;
/// - too old: `chain_height > MAX_AGE && ref_height < chain_height −
///   MAX_AGE` — the oldest admissible exists (the chain is past the
///   window's width; at equality the bound is `0` and nothing is below it,
///   which is the `>` guard's exact meaning) and this one is below it.
///
/// The operand is the height I10 yielded, so a reference not on the chain
/// never reaches this row: I10 refused it. Non-spends are recorded
/// vacuous by `tx_against` alongside I12.
pub(crate) struct I11;

impl Rule for I11 {
    const ROW: CenRow = CenRow::I11;
}

impl I11 {
    /// The window as a pure predicate over the two heights — the boundary
    /// arithmetic, with nothing read: `Ok(())` when `ref_height` is
    /// admissible for a block connecting at `connecting`, `Err(())` when it
    /// is too recent or too old. The mock earns its keep on exactly this
    /// function (rule 50's first job); the rows operating are witnessed by
    /// the driver.
    pub(crate) fn window(connecting: BlockHeight, ref_height: BlockHeight) -> Result<(), ()> {
        let Some(newest) = connecting.checked_sub_count(REFERENCE_BLOCK_MIN_AGE) else {
            return Err(());
        };
        if ref_height > newest {
            return Err(());
        }
        if let Some(oldest) = connecting.checked_sub_count(REFERENCE_BLOCK_MAX_AGE) {
            if ref_height < oldest {
                return Err(());
            }
        }
        Ok(())
    }

    /// Judge `ref_height` (I10's operand) against the view's connecting
    /// height, recording this row on a pass.
    pub(crate) fn check<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        ref_height: BlockHeight,
        view: &V,
        coverage: &mut RuleCoverage,
    ) -> Result<Verdict<()>, V::Fault> {
        let connecting = Tip::connecting_height(view.tip()?.as_ref());
        match Self::window(connecting, ref_height) {
            Ok(()) => {
                coverage.insert(Self::ROW);
                Ok(Ok(()))
            }
            Err(()) => Ok(Err(InvalidBlock::new(Self::ROW, cx.locus()))),
        }
    }
}

/// CEN-I12, a **definition**: the membership anchor a regular spend's
/// proof is verified against is the curve-tree state **at** `ref_height`
/// — the root after the reference block's parent connected and before the
/// reference block drained its own leaves — read from the chain's own
/// per-height record ([`ChainView::root_at`]), never from a header
/// (`blockchain.cpp:4152` `get_curve_tree_root_at_height(ref_height)`; the
/// comment above it is the census's wording). Recorded as coverage where
/// it is derived, the D4 arrangement: nothing about a candidate can fail
/// a definition, and `implemented(rules::tx_against::I12)` names this
/// derivation.
///
/// Derived after I10 and I11 have passed, so `ref_height` is recorded and
/// at least `MIN_AGE` below the connecting height. A view that then
/// answers `AboveTip` for it has a hole below its tip — a store invariant
/// observed broken from the validator's side, [`Corrupt::HoleBelowTip`],
/// never a verdict. This is the read that widens `tx_against`'s fault to
/// [`ViewRead`]: the first view-bound row to read a per-height record.
///
/// The anchor's consumer is CEN-I15's proof verification (slice 6 commit
/// 8, this PR); until it lands the value is derived, recorded and dropped —
/// staged with its consumer named, so the derivation and its fault
/// classification are reviewed here, where the operand is defined, and not
/// inside the verification commit.
pub(crate) struct I12;

impl Rule for I12 {
    const ROW: CenRow = CenRow::I12;
}

impl I12 {
    /// The anchor for a spend whose reference I10 placed at `ref_height`,
    /// recorded as this row.
    pub(crate) fn anchor<'id, V: ChainView<'id>>(
        ref_height: BlockHeight,
        view: &V,
        coverage: &mut RuleCoverage,
    ) -> Result<CurveTreeRoot, ViewRead<V::Fault>> {
        coverage.insert(Self::ROW);
        match view.root_at(ref_height).map_err(ViewRead::View)? {
            AtHeight::Recorded(root) => Ok(root),
            AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: ref_height,
                record: PerHeightRecord::CurveTreeRoot,
            })),
        }
    }
}

/// The rows that consume the height [`I10`] yields. Recorded vacuous when
/// that height does not exist — a non-spend, where I10 itself recorded
/// vacuous. CEN-I13 joins this list when `depth_at` exists; the list is
/// the whole of what a later commit has to remember.
const REFERENCE_SUCCESSORS: &[CenRow] = &[I11::ROW, I12::ROW];

/// CEN-I10, CEN-I11 and CEN-I12 as one sequence.
///
/// I10 yields the reference height. On a pass, I11 measures it and I12
/// reads the anchor at it. The anchor is in flight for CEN-I15: derived
/// here so a missing root is classified with the operand, and dropped
/// beside that derivation until the proof is verified against it. A
/// transaction that is not a regular spend records the successors vacuous.
pub(crate) fn judge_reference<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, ViewRead<V::Fault>> {
    let ref_height = match I10::reference_height(cx, view, coverage).map_err(ViewRead::View)? {
        Ok(height) => height,
        Err(refused) => return Ok(Err(refused)),
    };
    let Some(ref_height) = ref_height else {
        for row in REFERENCE_SUCCESSORS {
            coverage.insert(*row);
        }
        return Ok(Ok(()));
    };
    match I11::check(cx, ref_height, view, coverage).map_err(ViewRead::View)? {
        Ok(()) => {}
        Err(refused) => return Ok(Err(refused)),
    }
    // In flight for CEN-I15 (slice 6 commit 8). Dropping it here, beside
    // the derivation, is the staging; `validate` does not name the value.
    let _anchor = I12::anchor(ref_height, view, coverage)?;
    Ok(Ok(()))
}

#[cfg(test)]
#[path = "tx_against_tests.rs"]
mod tx_against_tests;
