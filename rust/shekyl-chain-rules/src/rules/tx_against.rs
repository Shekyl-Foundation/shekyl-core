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
use shekyl_crypto_pq::signature::verify_pqc_auth;
use shekyl_fcmp::leaf::PqcKeyScalar;
use shekyl_fcmp::proof::{self, ShekylFcmpProof};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, SigningPayloadHash,
};
use shekyl_wire::{Ct, Input, Transaction};

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

/// The `Ct::Fcmp` `reference_block` this transaction carries, if its class
/// has one to look up: a [`TxClass::Spend`] (CEN-I10's subject) or a
/// [`TxClass::Emission`] (CEN-J21's: the same context, *required even with
/// zero fee inputs*, because the vin's backing proof verifies against that
/// root — `blockchain.cpp:3868–3870`). The serve credit has no CT to carry
/// one, and the bond post is CEN-H21's funding clause's — not run here
/// (slice 8 §5 row 11 records it). A `Null` CT on a spend is CEN-H15's
/// refusal in `tx_form`, and here it is nothing to look up.
fn proof_reference(cx: &TxContext<'_>) -> Option<BlockHash> {
    if !matches!(cx.class, TxClass::Spend { .. } | TxClass::Emission { .. }) {
        return None;
    }
    match &cx.tx.ct {
        Ct::Fcmp {
            reference_block, ..
        } => Some(*reference_block),
        Ct::Null(_) => None,
    }
}

/// The curve-tree context a proof-bearing transaction's reference names,
/// yielded by [`judge_reference`] for the rows that verify against it:
/// CEN-I15 on a spend (not in this crate yet — see [`I12`]), CEN-J25's
/// backing proof and CEN-J26's fee-input proof on an emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReferenceContext {
    /// I10's operand: the reference's recorded height.
    pub(crate) ref_height: BlockHeight,
    /// I12's anchor: the tree's root **at** `ref_height`.
    pub(crate) anchor: CurveTreeRoot,
    /// The transaction's declared `curve_trees_tree_depth`, admitted by
    /// [`I13::admits`] against the tree's depth at `ref_height`. The
    /// verifier's `layers` is this plus one.
    pub(crate) tree_depth: u8,
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
    /// The lookup alone: the recorded height of the reference `cx` carries,
    /// `None` when there is none to look up or it is on no block of this
    /// chain. The row's body, shared with CEN-J21, which applies it to the
    /// emission and names its own row on the refusal.
    fn lookup<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
    ) -> Result<Option<BlockHeight>, V::Fault> {
        let Some(reference) = proof_reference(cx) else {
            return Ok(None);
        };
        view.height_of(&reference)
    }

    /// The reference's height for `cx`'s spend, recorded as this row on a
    /// pass; `Ok(Ok(None))` for a transaction that is not a regular spend
    /// (nothing to look up — the row is vacuous there and recorded, as
    /// [`run_tx_against`](crate::rules::run_tx_against) records an
    /// out-of-scope kind). The emission's reference is CEN-J21's, judged
    /// by [`J21::check`] over the same lookup.
    pub(crate) fn reference_height<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        coverage: &mut RuleCoverage,
    ) -> Result<Verdict<Option<BlockHeight>>, V::Fault> {
        if !matches!(cx.class, TxClass::Spend { .. }) {
            coverage.insert(Self::ROW);
            return Ok(Ok(None));
        }
        match Self::lookup(cx, view)? {
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
/// The anchor's consumer on a **spend** is CEN-I15's proof verification,
/// which does not run on the spend class yet: turning it on refuses every
/// filler-proof spend fixture the store's and ingest's tests still run
/// `validate` over — the migration the FOLLOWUPS row *The view-bound rows
/// of slices 2–4 are fixtured against `MockChain` …* owns, not yet
/// landed. Until it lands the spend's anchor is derived, recorded and
/// dropped — staged with its consumer named, so the derivation and its
/// fault classification are reviewed here, where the operand is defined.
/// On an **emission** the same read is CEN-J21's, and its anchor is
/// consumed: [`judge_reference`] yields it in the [`ReferenceContext`]
/// the emission's proof rows (CEN-J25, CEN-J26) verify against.
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

/// CEN-I13: the transaction's declared `curve_trees_tree_depth` is in
/// `[1, depth]`, where `depth` is the tree's depth **at `ref_height`** —
/// the tree the proof was built over, read as [`ChainView::depth_at`]
/// (slice 6 Q8, RULED 2026-09-24). The C++ range-checks against the
/// *current* depth (`m_db->get_curve_tree_depth()`, `blockchain.cpp:4165`),
/// which is correct only under three dependencies one of which is an
/// ordering argument (slice 6 §3.3); the height-keyed read removes the
/// dependence. The verifier's `layers` is the declared depth plus one.
///
/// The predicate is the C++'s range, over the ruled operand. The census
/// records the spec's pseudocode as *equality* with the depth at the
/// reference and marks the reconciliation **Found, not ruled** (§7 #16);
/// this row implements the code's predicate until that ruling, as every
/// row does.
///
/// Not yet run on the spend class (the same fixture migration that holds
/// CEN-I15 — see [`I12`]); run on the emission as part of CEN-J21, which
/// is the row that refuses there.
pub(crate) struct I13;

impl Rule for I13 {
    const ROW: CenRow = CenRow::I13;
}

impl I13 {
    /// The range as a pure predicate: `declared ∈ [1, depth_at_reference]`.
    /// The mock earns its keep on this function (rule 50's first job).
    pub(crate) fn admits(declared: u64, depth_at_reference: u8) -> bool {
        declared >= 1 && declared <= u64::from(depth_at_reference)
    }

    /// The tree's depth at `ref_height`, I13's operand. Derived after I10
    /// placed the height on the chain, so a view that answers `AboveTip`
    /// there has a hole below its tip — [`Corrupt::HoleBelowTip`] over the
    /// leaf count the depth is a function of, never a verdict (the I12
    /// classification, on the other per-height record).
    pub(crate) fn depth_at_reference<'id, V: ChainView<'id>>(
        ref_height: BlockHeight,
        view: &V,
    ) -> Result<u8, ViewRead<V::Fault>> {
        match view.depth_at(ref_height).map_err(ViewRead::View)? {
            AtHeight::Recorded(depth) => Ok(depth),
            AtHeight::AboveTip => Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: ref_height,
                record: PerHeightRecord::LeafCount,
            })),
        }
    }
}

/// CEN-I15: the FCMP++ membership-and-spend-authorisation proof verifies
/// over the transaction's spends — the proof bytes, every spend's key
/// image, every pseudo-out, each spend's PQC key scalar
/// `k = H_ℓ(hybrid_public_key)` (`shekyl_fcmp_pqc_key_scalar`), the root
/// at the reference, `layers = depth + 1`, and the prefix hash
/// (`shekyl_fcmp_verify`, `blockchain.cpp:4224`; `FCMP_PLUS_PLUS.md` §7
/// step 4). The body is [`shekyl_fcmp::proof::verify`], **the function the
/// daemon's FFI and daemon-rpc's K12 call** — one verifier, reached from
/// three sites. The operands are assembled here, beside I12's anchor and
/// I13's depth, where they are defined.
///
/// The row is a function over a **spend subset**, because its two callers
/// name different subsets of the same vector: every input on a spend;
/// the `ToKey` fee inputs on an emission (CEN-J26, *"exactly as
/// CEN-I15"*), where the pseudo-outs are indexed by spend ordinal and the
/// auths by input slot (`blockchain.cpp:4071–4078`, `spend_indices`). A
/// subset of zero spends has nothing to prove and the proof must be
/// absent — the C++ `num_spend == 0` arm; on both classes the shape row
/// (H21, H22) has already required that, and this row refuses it again
/// rather than verify an empty subset against a proof.
///
/// Not yet run on the spend class (the fixture migration that holds I13
/// — see [`I12`]); run on the emission's fee inputs as CEN-J26.
pub(crate) struct I15;

impl Rule for I15 {
    const ROW: CenRow = CenRow::I15;
}

impl I15 {
    /// The verify over `tx`'s inputs at `spend_slots` (in input order),
    /// against `reference`. `Err` is the row's refusal, whichever leg: a
    /// body with no prunable region, a proof present over no spends or
    /// absent over some, an input at a named slot that is not a `ToKey`
    /// or has no auth, a count the verifier cannot size, or the proof
    /// failing. The verifier's own refusals (`VerifyError`) are not
    /// distinguished: an `InvalidBlock` carries the row.
    pub(crate) fn verify(
        tx: &Transaction,
        spend_slots: &[usize],
        reference: &ReferenceContext,
    ) -> Result<(), ()> {
        let Ct::Fcmp {
            pqc_auths,
            prunable: Some(prunable),
            ..
        } = &tx.ct
        else {
            return Err(());
        };
        if spend_slots.is_empty() {
            return if prunable.fcmp_proof.is_empty() {
                Ok(())
            } else {
                Err(())
            };
        }
        if prunable.fcmp_proof.is_empty() {
            return Err(());
        }
        let mut key_images = Vec::with_capacity(spend_slots.len());
        let mut pqc_keys = Vec::with_capacity(spend_slots.len());
        for &slot in spend_slots {
            let (Some(Input::ToKey { key_image, .. }), Some(auth)) =
                (tx.prefix.inputs.get(slot), pqc_auths.get(slot))
            else {
                return Err(());
            };
            key_images.push(KeyImage::from_canonical_bytes(*key_image));
            pqc_keys.push(PqcKeyScalar::from_pqc_public_key(&auth.hybrid_public_key));
        }
        let num_inputs = u32::try_from(spend_slots.len()).map_err(|_| ())?;
        let layers = reference.tree_depth.checked_add(1).ok_or(())?;
        let fcmp_proof = ShekylFcmpProof {
            data: prunable.fcmp_proof.clone(),
            num_inputs,
            tree_depth: layers,
        };
        match proof::verify(
            &fcmp_proof,
            &key_images,
            &prunable.pseudo_outs,
            &pqc_keys,
            reference.anchor.as_bytes(),
            layers,
            tx.prefix_hash().to_bytes(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(()),
        }
    }
}

/// CEN-J21: the emission's `referenceBlock` / curve-tree context, as
/// CEN-I10–I13 — the reference is a block of this chain, within I11's
/// window below the connecting height; the anchor is the root **at** it;
/// the declared depth is admitted by I13 against the depth at it —
/// **required even with zero fee inputs**, because the vin's
/// membership-only backing proof verifies against that root
/// (`blockchain.cpp:3868–3905`, the bond-post idiom). One row for the
/// context: the C++ refuses each failure under the emission arm's own
/// messages, and the census keys them all to this row. Refuses at the
/// transaction.
///
/// A storage-pruned body (`prunable: None`) has no declared depth and no
/// proof to verify against the context; `tx_form` refuses it before this
/// stage, and here it is refused rather than judged over a missing field.
pub(crate) struct J21;

impl Rule for J21 {
    const ROW: CenRow = CenRow::J21;
}

impl J21 {
    /// The context for `cx`'s emission, recorded as this row on a pass.
    fn check<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        coverage: &mut RuleCoverage,
    ) -> Result<Verdict<ReferenceContext>, ViewRead<V::Fault>> {
        let refuse = || InvalidBlock::new(Self::ROW, cx.locus());
        let Some(ref_height) = I10::lookup(cx, view).map_err(ViewRead::View)? else {
            return Ok(Err(refuse()));
        };
        let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
        if I11::window(connecting, ref_height).is_err() {
            return Ok(Err(refuse()));
        }
        let Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } = &cx.tx.ct
        else {
            return Ok(Err(refuse()));
        };
        // The per-height reads, after the height is known recorded: the
        // anchor (I12's read, under this row) and the depth (I13's).
        let anchor = match view.root_at(ref_height).map_err(ViewRead::View)? {
            AtHeight::Recorded(root) => root,
            AtHeight::AboveTip => {
                return Err(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                    at: ref_height,
                    record: PerHeightRecord::CurveTreeRoot,
                }))
            }
        };
        let depth = I13::depth_at_reference(ref_height, view)?;
        // Admitted into `[1, depth]`, so it fits the verifier's `u8`; a
        // declared depth the `u8` does not hold is outside the range.
        let tree_depth = match u8::try_from(prunable.tree_depth) {
            Ok(declared) if I13::admits(prunable.tree_depth, depth) => declared,
            _ => return Ok(Err(refuse())),
        };
        coverage.insert(Self::ROW);
        Ok(Ok(ReferenceContext {
            ref_height,
            anchor,
            tree_depth,
        }))
    }
}

/// The rows that consume the height [`I10`] yields. Recorded vacuous when
/// that height does not exist — a non-spend, where I10 itself recorded
/// vacuous. CEN-I13 joins this list when it runs on the spend class; the
/// list is the whole of what that commit has to remember.
const REFERENCE_SUCCESSORS: &[CenRow] = &[I11::ROW, I12::ROW];

/// The reference sequence: CEN-I10, CEN-I11 and CEN-I12 on a spend;
/// CEN-J21 on an emission.
///
/// On a spend, I10 yields the reference height; on a pass, I11 measures it
/// and I12 reads the anchor at it. The anchor is in flight for CEN-I15 on
/// this class (see [`I12`]): derived here so a missing root is classified
/// with the operand, and dropped beside that derivation until the proof is
/// verified against it — the arm yields `None`. On an emission, J21 judges
/// the whole context and yields it, for CEN-J25's backing proof and
/// CEN-J26's fee-input proof; I10–I12 are recorded vacuous there, as on
/// every class that is not a spend. A transaction with no reference to
/// look up records everything vacuous and yields `None`.
pub(crate) fn judge_reference<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<Option<ReferenceContext>>, ViewRead<V::Fault>> {
    let ref_height = match I10::reference_height(cx, view, coverage).map_err(ViewRead::View)? {
        Ok(height) => height,
        Err(refused) => return Ok(Err(refused)),
    };
    let Some(ref_height) = ref_height else {
        for row in REFERENCE_SUCCESSORS {
            coverage.insert(*row);
        }
        if matches!(cx.class, TxClass::Emission { .. }) {
            return J21::check(cx, view, coverage).map(|verdict| verdict.map(Some));
        }
        coverage.insert(J21::ROW);
        return Ok(Ok(None));
    };
    coverage.insert(J21::ROW);
    match I11::check(cx, ref_height, view, coverage).map_err(ViewRead::View)? {
        Ok(()) => {}
        Err(refused) => return Ok(Err(refused)),
    }
    // In flight for CEN-I15 on the spend class. Dropping it here, beside
    // the derivation, is the staging; `validate` does not name the value.
    let _anchor = I12::anchor(ref_height, view, coverage)?;
    Ok(Ok(None))
}

/// CEN-I17, a **definition**: what each input's hybrid signature is over —
/// the PQC signing preimage, `FCMP_SPEND_SIGNING_PREIMAGE.md` §1.1: the
/// pruned segment ‖ keccak256(prunable) ‖ that input's PQC header ‖
/// keccak256 of every input's hybrid public key, so neither the proof nor
/// any input's key can be swapped under a standing signature. **Adopted**
/// from the wire, not re-derived: [`shekyl_wire::PqcSigningPreimage`] is the
/// one derivation the wallet signs over and the daemon verifies against
/// (through `shekyl_tx_pqc_signing_payload_hashes`; slice 6 Q7 (c)), and it
/// is held to the specification's output over eight daemon-accepted shapes
/// by `shekyl-wire/tests/pqc_signing_preimage_kat.rs`. A second body here
/// would be the two-sources class the cutover closed.
///
/// Recorded as coverage where the hashes are derived, the D4 arrangement:
/// nothing about a candidate fails a definition, and
/// `implemented(rules::tx_against::I17)` names this derivation. Stateless —
/// it reads the transaction alone — but derived here beside I12's anchor
/// because the two are CEN-I18's and CEN-I15's operands, assembled where
/// those verification rows run.
///
/// The consumer is CEN-I18's signature verification: [`judge_signatures`]
/// runs the two as one sequence, this row yielding and I18 verifying.
pub(crate) struct I17;

impl Rule for I17 {
    const ROW: CenRow = CenRow::I17;
}

impl I17 {
    /// Every input's `signed_hash(i)`, in input order, recorded as this row.
    /// Empty for a body with no `pqc_auths` — the coinbase, and the
    /// serve-credit form, which CEN-H20 forbids to carry any: that form is
    /// signed over the pass record instead (CEN-J10), so this row and I18
    /// are vacuous on it by construction, not by exemption.
    pub(crate) fn signed_hashes(
        cx: &TxContext<'_>,
        coverage: &mut RuleCoverage,
    ) -> Vec<SigningPayloadHash> {
        coverage.insert(Self::ROW);
        cx.tx.pqc_signing_payload_hashes()
    }
}

/// CEN-I18: every input's hybrid PQC signature — Ed25519 **and** ML-DSA-65,
/// or the M-of-N multisig container — verifies over that input's
/// `signed_hash(i)` (`verify_transaction_pqc_auth`, `tx_pqc_verify.cpp`;
/// gated at `blockchain.cpp:4277–4285` on every non-coinbase transaction
/// but the serve credit). The verification body is
/// [`shekyl_crypto_pq::signature::verify_pqc_auth`], **the same function
/// the daemon's `shekyl_pqc_verify` and daemon-rpc's K13 call** — scheme
/// dispatch, the tx-auth domains and the container parse live there once,
/// so the validator, the daemon and the pool cannot disagree on what a
/// valid slot is. The slot's structural pins (`auth_version`, `flags`,
/// scheme id, key-blob length) are CEN-I16's, in `tx_form`.
///
/// Refuses at the input whose signature does not verify. Vacuous on the
/// two classes with no `pqc_auths` by construction — the coinbase, and the
/// serve-credit form, which CEN-H20 forbids them because its
/// countersignature is CEN-J10's, over the pass record: I17 yields nothing
/// there and this row verifies nothing, and neither reaches for J10's
/// object (`i17_reads_none_of_a_serve_credits_pass_record_…`).
pub(crate) struct I18;

impl Rule for I18 {
    const ROW: CenRow = CenRow::I18;
}

impl I18 {
    /// Verify `pqc_auths[i]` over `hashes[i]` for every input.
    ///
    /// The hashes are I17's, one per auth by construction
    /// ([`shekyl_wire::Transaction::pqc_signing_payload_hashes`]); a body
    /// for which I17 yielded none while `pqc_auths` is populated — the
    /// storage-pruned form, which `tx_form` refuses before this stage and
    /// the wire never carries — has no message for its signatures to be
    /// over, and is refused at the transaction rather than silently
    /// verified over nothing.
    ///
    /// The row is recorded only when the check passes, including the
    /// vacuous non-`Fcmp` arm. A refusal leaves it unrecorded, as
    /// [`crate::rules::run_tx`] does for a stateless rule.
    pub(crate) fn check(
        cx: &TxContext<'_>,
        hashes: &[SigningPayloadHash],
        coverage: &mut RuleCoverage,
    ) -> Verdict<()> {
        let Ct::Fcmp { pqc_auths, .. } = &cx.tx.ct else {
            coverage.insert(Self::ROW);
            return Ok(());
        };
        if pqc_auths.len() != hashes.len() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Tx { slot: cx.slot }));
        }
        for (input, (auth, hash)) in pqc_auths.iter().zip(hashes).enumerate() {
            if verify_pqc_auth(
                auth.scheme_id,
                &auth.hybrid_public_key,
                &auth.hybrid_signature,
                hash.as_bytes(),
            )
            .is_err()
            {
                return Err(InvalidBlock::new(
                    Self::ROW,
                    Locus::Input {
                        slot: cx.slot,
                        input,
                    },
                ));
            }
        }
        coverage.insert(Self::ROW);
        Ok(())
    }
}

/// CEN-I17 and CEN-I18 as one sequence: I17 yields every input's signing
/// hash, I18 verifies each input's signature over it. The D4 arrangement
/// [`judge_reference`] uses for I10–I12 — the definition row records at
/// the derivation, the verification row consumes the operand it yielded.
pub(crate) fn judge_signatures(cx: &TxContext<'_>, coverage: &mut RuleCoverage) -> Verdict<()> {
    let signed_hashes = I17::signed_hashes(cx, coverage);
    I18::check(cx, &signed_hashes, coverage)
}

#[cfg(test)]
#[path = "tx_against_tests.rs"]
mod tx_against_tests;
