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
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
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

/// The `Ct::Fcmp` `reference_block` this transaction carries; `None` for a
/// `Null` CT, which has none (on a spend that is CEN-H15's refusal in
/// `tx_form`, and here it is nothing to look up). Which classes have a
/// reference to judge is [`judge_reference`]'s dispatch, not this read's.
fn proof_reference(tx: &Transaction) -> Option<BlockHash> {
    match &tx.ct {
        Ct::Fcmp {
            reference_block, ..
        } => Some(*reference_block),
        Ct::Null(_) => None,
    }
}

/// Which inputs are `ToKey` — the spend subset a proof is verified over,
/// as input slots in input order: every input on a regular spend, the fee
/// inputs on an emission (CEN-J26), the funding inputs on a bond post.
/// One derivation for the three, in I7's shape (the input's kind, never
/// the transaction's class, decides membership), so the subset
/// [`I15::verify`] takes is the same thing under every attribution and a
/// class arm cannot hand it a different one. The class dispatch in
/// [`judge_reference`] decides *whether* the sequence runs; this decides
/// *over what* (`05-system-thinking`: two decisions, two places).
pub(crate) fn to_key_slots(tx: &Transaction) -> Vec<usize> {
    let mut slots = Vec::new();
    for (slot, input) in tx.prefix.inputs.iter().enumerate() {
        let Input::ToKey { .. } = input else {
            continue;
        };
        slots.push(slot);
    }
    slots
}

/// The curve-tree context a proof-bearing transaction's reference names,
/// yielded by [`judge_reference`] for the rows that verify against it:
/// CEN-I15 on a spend and CEN-J27 on a bond post (both [`I15::verify`]
/// over [`to_key_slots`], run inside the arm that derived the context),
/// CEN-J25's backing proof and CEN-J26's fee-input proof on an emission.
/// *Records-was:* the spend's verify was staged off until 2026-10-08
/// (see [`I12`]).
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
/// D4 is — a step that **yields** its operand, the first of the one
/// sequence [`reference_context`] runs, rather than a [`TxAgainstRule`]
/// whose two successors would each repeat the lookup.
///
/// A spend with no reference to look up — `Null` CT — is refused here too:
/// "is a main-chain block" is false of no block. `tx_form` names it H15
/// first, so this arm is reachable only through `tx_against` alone.
///
/// On a non-spend the row is vacuous and recorded by [`judge_reference`]'s
/// class arm, as [`run_tx_against`](crate::rules::run_tx_against) records
/// an out-of-scope kind. On an emission the same lookup is CEN-J21's step.
pub(crate) struct I10;

impl Rule for I10 {
    const ROW: CenRow = CenRow::I10;
}

impl I10 {
    /// The lookup alone: the recorded height of the reference `cx` carries,
    /// `None` when there is none to look up or it is on no block of this
    /// chain. The row it refuses under is the class arm's
    /// ([`ReferenceRows::lookup`]).
    fn lookup<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
    ) -> Result<Option<BlockHeight>, V::Fault> {
        let Some(reference) = proof_reference(cx.tx) else {
            return Ok(None);
        };
        view.height_of(&reference)
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
/// never reaches this row: I10 refused it. The step is [`I11::window`] in
/// [`reference_context`], refusing under the class arm's row
/// ([`ReferenceRows::window`]); non-spends are recorded vacuous by
/// [`judge_reference`] alongside I12.
pub(crate) struct I11;

impl Rule for I11 {
    const ROW: CenRow = CenRow::I11;
}

/// The newest reference CEN-I11 admits for a spend listed in the block
/// that connects at `connecting`: the block [`REFERENCE_BLOCK_MIN_AGE`]
/// below it (`ref_height ≤ chain_height − MIN_AGE`, `blockchain.cpp:4121`,
/// with `chain_height` the connecting height). `None` when the chain is
/// too young to carry a spend at all — the first block that can list one
/// is height `MIN_AGE`, referencing genesis.
///
/// The one home of this subtraction (rule 05): [`I11::window`] refuses by
/// it, and every producer that anchors a spend — the rules harness's
/// fixtures, the store's, the harness spender — asks it rather than
/// re-deriving `connecting − MIN_AGE`, so no producer can anchor a spend
/// differently from the rule that judges it.
#[must_use]
pub fn newest_admissible_reference(connecting: BlockHeight) -> Option<BlockHeight> {
    connecting.checked_sub_count(REFERENCE_BLOCK_MIN_AGE)
}

impl I11 {
    /// The window as a pure predicate over the two heights — the boundary
    /// arithmetic, with nothing read: `Ok(())` when `ref_height` is
    /// admissible for a block connecting at `connecting`, `Err(())` when it
    /// is too recent or too old. The mock earns its keep on exactly this
    /// function (rule 50's first job); the rows operating are witnessed by
    /// the driver.
    pub(crate) fn window(connecting: BlockHeight, ref_height: BlockHeight) -> Result<(), ()> {
        let Some(newest) = newest_admissible_reference(connecting) else {
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
/// run by [`judge_reference`]'s spend arm over the [`ReferenceContext`]
/// this step and I13's yield. *Records-was:* until 2026-10-08 that
/// consumer was staged off — turning it on refused every filler-proof
/// spend fixture the store's and ingest's tests ran `validate` over — and
/// [`SPEND_REFERENCE`] staged the depth step off with it, the anchor
/// derived, recorded and dropped beside this definition (RULED
/// 2026-10-07: the fixtures became scenarios, the flip landed with the
/// last conversion; `CHAIN_RULES_SLICE_6.md` §5 row 6). On an **emission**
/// the same read is CEN-J21's step, and its anchor is consumed the same
/// way: the emission's proof rows (CEN-J25, CEN-J26) verify against the
/// yielded context.
pub(crate) struct I12;

impl Rule for I12 {
    const ROW: CenRow = CenRow::I12;
}

impl I12 {
    /// The anchor at `ref_height`, a height I10 just placed on the chain.
    /// Recorded by [`reference_context`] under the class arm's row
    /// ([`ReferenceRows::anchor`]), where it is derived.
    pub(crate) fn anchor<'id, V: ChainView<'id>>(
        ref_height: BlockHeight,
        view: &V,
    ) -> Result<CurveTreeRoot, ViewRead<V::Fault>> {
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
/// The depth step of [`reference_context`], refusing under the class
/// arm's row ([`ReferenceRows::depth`]): this row on a spend
/// ([`SPEND_REFERENCE`]; on the spend class since 2026-10-08, see
/// [`I12`]), CEN-J21 on an emission, which is the row that refuses there.
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
/// Run on the spend class by [`judge_reference`]'s spend arm over
/// [`to_key_slots`], once the reference sequence has yielded its context
/// (on the spend class since 2026-10-08, see [`I12`]); run on the
/// emission's fee inputs as CEN-J26.
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
/// The row has no body of its own: it is [`reference_context`] with every
/// step attributed to this row ([`EMISSION_REFERENCE`]) — the same
/// sequence the spend runs under I10–I13, chosen by [`judge_reference`]'s
/// class arm. A storage-pruned body (`prunable: None`) has no declared
/// depth and no proof to verify against the context; `tx_form` refuses it
/// before this stage, and here it is refused rather than judged over a
/// missing field.
pub(crate) struct J21;

impl Rule for J21 {
    const ROW: CenRow = CenRow::J21;
}

/// CEN-J27: the bond post's **funding half** — its `referenceBlock` /
/// curve-tree context as CEN-I10–I13 and the FCMP++ proof over its
/// funding spends as CEN-I15, one row. The reference is a block of this
/// chain inside I11's window below the connecting height, the anchor is
/// the root **at** it, the declared depth is admitted by I13 against the
/// depth at it, and the proof verifies over every `ToKey` input
/// ([`to_key_slots`]: the funding spends, the post's own vin excluded by
/// kind) against that anchor at `tree_depth + 1` layers and the prefix
/// hash (`blockchain.cpp:3654–3733`, the bond arm: the lookup `:3654`, the
/// window `:3661–3673`, the root at the reference `:3677`, the depth
/// `:3678–3684`, the scalars `:3700`, `shekyl_fcmp_verify` `:3713`). The
/// C++ refuses each failure under the bond arm's own messages; the census
/// keys them all to this row. Refuses at the transaction.
///
/// What this row is **not**: CEN-H21 keeps the post's shape and balance
/// (`pqc_auths` against the vin count, at least one funding input, the
/// pseudo-outs count, a non-empty proof, the CT balance against the
/// post's credit and debit — `tx_form`'s, before this stage), and the
/// post's semantics against its record are J13–J18's (`judge_bond_post`).
/// Minted 2026-10-08 (`CHAIN_RULES_SLICE_6.md` §5 row 6, the ruling on
/// the census H21 cell): not folded into I10–I15, whose rows are the
/// regular spend's, and not an H21 split. Until then the Rust validator
/// judged none of this on the `BondPost` class — the funding spends
/// reached it with their reference and proof unjudged (found 2026-10-06,
/// slice 8 row 9).
///
/// The row has no body of its own: it is [`reference_context`] with every
/// step attributed to this row ([`BOND_POST_REFERENCE`]) and
/// [`I15::verify`] over the context it yields — the sequence the spend
/// runs under I10–I13 and I15 and the emission under J21 and J26, chosen
/// by [`judge_reference`]'s class arm. Runs **after** `judge_bond_post`,
/// the C++'s order (`check_archival_bond_post_input` at `:3616`, the
/// funding half after it): a post refused against its record is J13–J18's
/// whatever its proof says. A storage-pruned body has no declared depth
/// and no proof; `tx_form` refuses it before this stage, and here it is
/// refused rather than judged over a missing field.
pub(crate) struct J27;

impl Rule for J27 {
    const ROW: CenRow = CenRow::J27;
}

/// The row each step of [`reference_context`] is recorded under and
/// refuses under — the attribution a class arm of [`judge_reference`]
/// chooses. The sequence is one body; the rows are the class's: on a
/// spend the steps are four rows (CEN-I10, I11, I12, I13), on an emission
/// they are one (CEN-J21, *"as CEN-I10–I13"*), on a bond post one
/// (CEN-J27, the funding half). Widening which classes run the sequence
/// is a new constant and a new arm, never a change to the body — the
/// shape that keeps the emission on J21 whatever the spend's gate
/// becomes, and the shape the bond post took on 2026-10-08.
#[derive(Clone, Copy)]
struct ReferenceRows {
    /// The reference is a block of this chain ([`I10::lookup`]).
    lookup: CenRow,
    /// Its height is inside the window below the connecting height
    /// ([`I11::window`]).
    window: CenRow,
    /// The root at it is the anchor ([`I12::anchor`]) — a definition,
    /// recorded where derived; its missing record is `Corrupt`.
    anchor: CenRow,
    /// The declared depth is admitted against the depth at it
    /// ([`I13::admits`] over [`I13::depth_at_reference`]). `None` is the
    /// step staged off for the class: the sequence stops after the anchor
    /// and yields no context. Every class that runs the sequence names a
    /// row here since 2026-10-08 (the spend's was `None` until CEN-I13
    /// landed on it, see [`I12`]), so no live constant stages the step
    /// off; the flip changed verdicts and nothing else, and collapsing
    /// the `Option` is the shape change it did not make.
    depth: Option<CenRow>,
}

impl ReferenceRows {
    /// The rows of the three steps that can leave an earlier step passed
    /// behind them, in sequence order; the depth step is last and only
    /// ever refuses after all three.
    const fn steps(self) -> [CenRow; 3] {
        [self.lookup, self.window, self.anchor]
    }
}

/// The regular spend's attribution: I10, I11, I12 and I13, each step its
/// own row. *Records-was:* `depth: None` until 2026-10-08 — I13 staged
/// off the spend class through the filler-fixture era (see [`I12`]); the
/// flip was this one cell and the I15 verify in [`judge_reference`]'s
/// spend arm, and nothing else.
const SPEND_REFERENCE: ReferenceRows = ReferenceRows {
    lookup: I10::ROW,
    window: I11::ROW,
    anchor: I12::ROW,
    depth: Some(I13::ROW),
};

/// Every row [`judge_reference`]'s spend arm can record — the four steps
/// of [`SPEND_REFERENCE`] and I15 over the context they yield — which the
/// other arms record **vacuous**, as [`run_tx_against`](crate::rules::run_tx_against)
/// records an out-of-scope kind, so G9's mint sees each evaluated at every
/// slot. Before the flip this was `SPEND_REFERENCE.steps()`: the depth
/// step and I15 were pending and the mint did not ask for them.
const SPEND_ARM_ROWS: [CenRow; 5] = [I10::ROW, I11::ROW, I12::ROW, I13::ROW, I15::ROW];

/// The emission's attribution: every step is CEN-J21's.
const EMISSION_REFERENCE: ReferenceRows = ReferenceRows {
    lookup: J21::ROW,
    window: J21::ROW,
    anchor: J21::ROW,
    depth: Some(J21::ROW),
};

/// The bond post's attribution: every step is CEN-J27's, and so is the
/// verify over the context — the row [`judge_reference`]'s bond-post arm
/// records once the proof has passed, never before (the steps alone are
/// not the row).
const BOND_POST_REFERENCE: ReferenceRows = ReferenceRows {
    lookup: J27::ROW,
    window: J27::ROW,
    anchor: J27::ROW,
    depth: Some(J27::ROW),
};

/// A refusal at the step under `row`, after `passed` steps of `rows` have
/// passed: those steps' rows are recorded, except where the row is the
/// refusing one — a refused row is not recorded, whichever of its steps
/// refused it (on an emission, every step is J21).
fn refuse_step(
    cx: &TxContext<'_>,
    rows: ReferenceRows,
    passed: usize,
    row: CenRow,
    coverage: &mut RuleCoverage,
) -> InvalidBlock {
    for step in rows.steps().into_iter().take(passed) {
        if step != row {
            coverage.insert(step);
        }
    }
    InvalidBlock::new(row, cx.locus())
}

/// The one reference sequence, in the C++'s order (`blockchain.cpp:4113`
/// for the spend, `:3868` for the emission — the same reads): the
/// reference is looked up (I10's step), its height measured against the
/// connecting height (I11's), the declared depth read off the body where
/// the class judges it, the anchor read at the height (I12's), the tree's
/// depth at the height read and the declared one admitted against it
/// (I13's). Each step is recorded under and refuses under `rows`' row for
/// it; the per-height reads classify a missing record as
/// [`Corrupt::HoleBelowTip`], never a verdict.
///
/// Yields the [`ReferenceContext`] when the depth step ran, `None` when
/// `rows` stages it off — the anchor then derived, recorded and dropped.
fn reference_context<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    rows: ReferenceRows,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<Option<ReferenceContext>>, ViewRead<V::Fault>> {
    let Some(ref_height) = I10::lookup(cx, view).map_err(ViewRead::View)? else {
        return Ok(Err(refuse_step(cx, rows, 0, rows.lookup, coverage)));
    };
    let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
    if I11::window(connecting, ref_height).is_err() {
        return Ok(Err(refuse_step(cx, rows, 1, rows.window, coverage)));
    }
    // The declared depth, before the per-height reads: a storage-pruned
    // body is refused under the depth row rather than judged over a
    // missing field. Not read where the step is staged off.
    let declared = match rows.depth {
        None => None,
        Some(row) => match &cx.tx.ct {
            Ct::Fcmp {
                prunable: Some(prunable),
                ..
            } => Some((row, prunable.tree_depth)),
            _ => return Ok(Err(refuse_step(cx, rows, 2, row, coverage))),
        },
    };
    let anchor = I12::anchor(ref_height, view)?;
    let Some((row, declared)) = declared else {
        // Staged off: the anchor is derived, recorded and dropped here,
        // beside the derivation. No class arm names this since the spend's
        // CEN-I13 landed (2026-10-08); the arm is the staging's shape.
        for step in rows.steps() {
            coverage.insert(step);
        }
        return Ok(Ok(None));
    };
    let depth = I13::depth_at_reference(ref_height, view)?;
    // Admitted into `[1, depth]`, so it fits the verifier's `u8`; a
    // declared depth the `u8` does not hold is outside the range.
    let tree_depth = match u8::try_from(declared) {
        Ok(fits) if I13::admits(declared, depth) => fits,
        _ => return Ok(Err(refuse_step(cx, rows, 3, row, coverage))),
    };
    for step in rows.steps() {
        coverage.insert(step);
    }
    coverage.insert(row);
    Ok(Ok(Some(ReferenceContext {
        ref_height,
        anchor,
        tree_depth,
    })))
}

/// The reference rows, dispatched on the transaction's class: CEN-I10,
/// CEN-I11, CEN-I12 and CEN-I13 on a spend, then CEN-I15's verify over
/// the context they yield; CEN-J21 on an emission; CEN-J27 — the same
/// sequence and the same verify, one row — on a bond post; vacuous on
/// every other class.
///
/// The dispatch is explicit so that no gate decides which arm a class
/// reaches: the emission reaches J21 because it is an emission, the bond
/// post reaches J27 because it is a bond post, and neither arm's widening
/// touches the other's. Each arm records the other arms' rows vacuous
/// first, as [`run_tx_against`](crate::rules::run_tx_against) records an
/// out-of-scope kind, then runs [`reference_context`] under its own
/// attribution. On a spend the yielded context is I15's operand — the
/// proof verified over every `ToKey` input ([`to_key_slots`]), the row
/// recorded on success and refusing at the transaction — and the arm
/// yields it on; on an emission the whole context is J21's and is
/// yielded, for CEN-J25's backing proof and CEN-J26's fee-input proof; on
/// a bond post the context and the verify over it are J27's, and the
/// context is yielded on with nothing left to read it. A class with no
/// reference to look up records everything vacuous and yields `None`.
/// *Records-was:* until 2026-10-08 the spend arm ran I10–I12 alone and
/// yielded `None` (see [`I12`]), and the bond post was a vacuous class.
pub(crate) fn judge_reference<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<Option<ReferenceContext>>, ViewRead<V::Fault>> {
    match cx.class {
        TxClass::Spend { .. } => {
            coverage.insert(J21::ROW);
            coverage.insert(J27::ROW);
            match reference_context(cx, view, SPEND_REFERENCE, coverage)? {
                // The C++'s order: the root at the reference and the depth
                // against it (`blockchain.cpp:4088`, `:4098`), then
                // `shekyl_fcmp_verify` over them (`:4157`).
                Ok(Some(reference)) => {
                    if I15::verify(cx.tx, &to_key_slots(cx.tx), &reference).is_err() {
                        return Ok(Err(InvalidBlock::new(I15::ROW, cx.locus())));
                    }
                    coverage.insert(I15::ROW);
                    Ok(Ok(Some(reference)))
                }
                other => Ok(other),
            }
        }
        TxClass::Emission { .. } => {
            for row in SPEND_ARM_ROWS {
                coverage.insert(row);
            }
            coverage.insert(J27::ROW);
            reference_context(cx, view, EMISSION_REFERENCE, coverage)
        }
        TxClass::BondPost { .. } => {
            for row in SPEND_ARM_ROWS {
                coverage.insert(row);
            }
            coverage.insert(J21::ROW);
            // Every step and the verify are one row, so the steps are run
            // into a scratch and folded in only once the proof has passed:
            // a refused row is not recorded, whichever of its steps or its
            // verify refused it. The C++'s order within the arm: the root
            // at the reference and the depth against it (`:3677`, `:3678`),
            // then `shekyl_fcmp_verify` over them (`:3713`).
            let mut steps = *coverage;
            match reference_context(cx, view, BOND_POST_REFERENCE, &mut steps)? {
                Ok(Some(reference)) => {
                    if I15::verify(cx.tx, &to_key_slots(cx.tx), &reference).is_err() {
                        return Ok(Err(InvalidBlock::new(J27::ROW, cx.locus())));
                    }
                    coverage.union(&steps);
                    Ok(Ok(Some(reference)))
                }
                other => Ok(other),
            }
        }
        TxClass::Coinbase | TxClass::ServeCreditOnly { .. } => {
            for row in SPEND_ARM_ROWS {
                coverage.insert(row);
            }
            coverage.insert(J21::ROW);
            coverage.insert(J27::ROW);
            Ok(Ok(None))
        }
    }
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
