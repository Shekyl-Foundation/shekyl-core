// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-H19's **verification half**: every listed transaction's
//! Bulletproof+ verified in **one** batch over the block (slice 6 Q9; the
//! weights derived from the batch, ruling R3, 2026-10-15). The layout half
//! is [`H19`]'s `TxRule` and runs in `tx_form`, unrecorded; this fold is
//! what records the row.
//!
//! # Why a fold, and why `form`
//!
//! A batch verify is inherently multi-transaction and `tx_form` is
//! per-transaction, so the batch cannot live in `tx_form` without
//! abandoning the batch or smuggling block scope into a per-transaction
//! rule (Q9's structural argument): it is a block-level fold. It reads no
//! chain state, so it runs in `form` — on the pipeline's parallel workers,
//! outside the write transaction and off the single connect actor — as a
//! `FormRule`, which records the row once the batch has decided. Inside
//! `form` it runs last: after CEN-D1 has refused a block short of its
//! proof-of-work (so such a block costs RandomX and no proof work), and
//! after every slot's `tx_form` (so H19's layout half and CEN-I4's input
//! cap have bounded the work). Every view-bound row, L1 included, runs
//! later, in `validate`.
//!
//! F14 — the block's weight at most twice the effective median — is one of
//! those rows. The median is a chain fact and grows with the chain, so
//! there is no stateless proof-count ceiling to apply before the batch: an
//! overweight block that met its claimed target still pays for it.
//!
//! # The batch, and the locus
//!
//! The batch is every listed transaction's proof, in block order —
//! transaction order, then proof order (one proof per transaction: the
//! layout half admits no other count) — with the transaction's output
//! commitments as carried. The coinbase carries none, and neither does a
//! serve credit. [`shekyl_bulletproofs::verify_batch`] derives the weights
//! from exactly that batch and verifies it with one multiscalar
//! multiplication: one call for a valid block, which is every block an
//! honest producer makes.
//!
//! A failed batch says some proof is bad, not which. The locus walk
//! re-verifies each proof as a **batch of one under the same derivation** —
//! its own seed, over itself — and refuses at the first transaction whose
//! proof fails alone. The walk is paid only by a block that is already
//! invalid. A proof that does not reassemble from the wire (an unreduced
//! scalar, `BpPlus::to_bulletproof`) cannot be batched; the block skips the
//! batch and goes straight to the walk, where that proof fails alone, so
//! the refusal is always the first bad transaction in block order whichever
//! way its proof is bad.
//!
//! [`ListedProofs`] is that assembly. The fold and any measurement of the
//! fold call it; a second walk over `bulletproofs` would disagree with the
//! fold the moment a transaction carried more than one proof.
//!
//! # A lone transaction is a batch of one
//!
//! The pool judges one transaction at `TxSlot::Lone` with no block around
//! it, through the same per-slot function `form` runs
//! (`judge_slot_stateless`, DRS-E5 PR-b). There the batch *is* that
//! transaction's proof: [`H19::verify_lone`] assembles it the way the fold
//! assembles each listed one ([`ListedProof::of`]) and verifies it alone —
//! the walk's own step, so a proof the block fold would refuse at its slot
//! is refused at `Lone`, and one it would pass passes. `form` never passes
//! `Lone`, so a block's proofs are still verified once, in its batch.

use shekyl_bulletproofs::{verify_batch, BatchEntry, Bulletproof};
use shekyl_curve_io::CompressedPoint;
use shekyl_wire::{Ct, Transaction};

use crate::block::Candidate;
use crate::rules::tx::H19;
use crate::rules::{FormContext, FormRule, Rule};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};

/// Whether [`ListedProofs::batch_outcome`] ran the block's batch.
///
/// Three answers, because "did it verify" is not a boolean: a proof that
/// does not reassemble never enters the batch, and an empty list verifies
/// vacuously.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchOutcome {
    /// Every reassembled proof verified under the batch's derived weights.
    /// An empty list is this: there was nothing to refuse.
    Verified,
    /// The batch ran, and the weighted sum was not the identity.
    Failed,
    /// A proof did not reassemble from the wire, so the batch was not run.
    Unassembled,
}

/// The proofs CEN-H19 batches, in block order.
///
/// A transaction with no proof is absent. More than one proof on a
/// transaction is the layout refusal ([`ListedProofs::assemble`] returns
/// it). A proof that does not reassemble stays in the list: the batch is
/// not run, and the locus walk names that transaction.
pub struct ListedProofs {
    proofs: Vec<ListedProof>,
}

/// One listed transaction's proof as the verifier reads it, or `None` when
/// the wire bytes do not reassemble.
struct ListedProof {
    slot: TxSlot,
    proof: Option<Bulletproof>,
    commitments: Vec<CompressedPoint>,
}

impl ListedProof {
    /// One transaction's proof at `slot`, with its output commitments as
    /// carried: `None` when it carries none (a coinbase, a serve credit, a
    /// storage-pruned body).
    ///
    /// # Errors
    ///
    /// More than one proof — the layout refusal, at `slot`.
    fn of(slot: TxSlot, tx: &Transaction) -> Verdict<Option<Self>> {
        let Ct::Fcmp {
            base,
            prunable: Some(prunable),
            ..
        } = &tx.ct
        else {
            return Ok(None);
        };
        let bp = match prunable.bulletproofs.as_slice() {
            [] => return Ok(None),
            [bp] => bp,
            _ => return Err(InvalidBlock::new(H19::ROW, Locus::Tx { slot })),
        };
        Ok(Some(Self {
            slot,
            proof: bp.to_bulletproof(),
            commitments: base
                .commitments
                .iter()
                .map(|c| CompressedPoint::from(*c))
                .collect(),
        }))
    }

    fn entry(&self) -> Option<BatchEntry<'_>> {
        self.proof.as_ref().map(|proof| BatchEntry {
            proof,
            commitments: &self.commitments,
        })
    }

    /// The proof verified as a batch of one, under its own derived seed.
    fn verifies_alone(&self) -> bool {
        #[cfg(any(test, feature = "harness"))]
        crate::rules::proofs::probes::count_range_proof();
        self.entry()
            .is_some_and(|entry| verify_batch(core::slice::from_ref(&entry)))
    }
}

impl ListedProofs {
    /// The block's proofs in block order — transaction order, then proof
    /// order — each with its transaction's output commitments as carried.
    ///
    /// # Errors
    ///
    /// More than one proof on a listed transaction. The layout half refused
    /// that in `tx_form`; the refusal is total here because a caller can
    /// assemble a candidate the layout half has not seen.
    pub fn assemble(candidate: &Candidate) -> Verdict<Self> {
        let mut proofs = Vec::new();
        for (n, tx) in candidate.transactions.iter().enumerate() {
            if let Some(proof) = ListedProof::of(TxSlot::Listed(n), tx)? {
                proofs.push(proof);
            }
        }
        Ok(Self { proofs })
    }

    /// How many proofs the block lists.
    #[must_use]
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// No listed transaction carried a proof.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// How many commitments each proof carries, in block order.
    pub fn commitment_counts(&self) -> impl Iterator<Item = usize> + '_ {
        self.proofs.iter().map(|proof| proof.commitments.len())
    }

    /// The batch, when every proof reassembled. The seed is derived over
    /// the whole slice inside `verify_batch`.
    pub(crate) fn entries(&self) -> Option<Vec<BatchEntry<'_>>> {
        self.proofs.iter().map(ListedProof::entry).collect()
    }

    /// Whether these proofs verify as one derived-weight batch.
    #[must_use]
    pub fn batch_outcome(&self) -> BatchOutcome {
        match self.entries() {
            Some(batch) if verify_batch(&batch) => BatchOutcome::Verified,
            Some(_) => BatchOutcome::Failed,
            None => BatchOutcome::Unassembled,
        }
    }

    /// The first transaction whose proof fails as a batch of one.
    ///
    /// `None` when every proof verifies alone — the weight-zero case the
    /// fold refuses at the block.
    pub(crate) fn first_failing_alone(&self) -> Option<TxSlot> {
        self.proofs
            .iter()
            .find(|proof| !proof.verifies_alone())
            .map(|proof| proof.slot)
    }
}

impl H19 {
    /// The fold's verdict over a candidate's listed transactions (module
    /// docs). Pure in the candidate: no view, no entropy.
    pub(crate) fn verify_block(candidate: &Candidate) -> Verdict<()> {
        let listed = ListedProofs::assemble(candidate)?;

        if listed.batch_outcome() == BatchOutcome::Verified {
            return Ok(());
        }

        // The locus walk: the first transaction whose proof fails alone.
        if let Some(slot) = listed.first_failing_alone() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Tx { slot }));
        }
        // Unreachable but for a weight of zero. A failed batch has a proof
        // whose verification term is not the identity — a valid proof's term
        // is the identity under every weight — and that proof's own batch of
        // one fails unless its derived weight is zero, probability `1/ℓ`.
        // Refused at the block, never admitted and never a panic.
        Err(InvalidBlock::new(Self::ROW, Locus::Block))
    }
}

impl H19 {
    /// The verification half for one transaction at [`TxSlot::Lone`]: its
    /// proof verified as a batch of one (module docs, *A lone transaction
    /// is a batch of one*). A transaction with no proof passes vacuously,
    /// as an empty block batch does. Pure in the transaction.
    pub(crate) fn verify_lone(tx: &Transaction) -> Verdict<()> {
        match ListedProof::of(TxSlot::Lone, tx)? {
            Some(proof) if !proof.verifies_alone() => Err(InvalidBlock::new(
                Self::ROW,
                Locus::Tx { slot: TxSlot::Lone },
            )),
            _ => Ok(()),
        }
    }
}

impl FormRule for H19 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        #[cfg(test)]
        range_proof_tests::BATCHES.with(|n| n.set(n.get() + 1));
        Self::verify_block(cx.candidate)
    }
}

#[cfg(test)]
#[path = "range_proof_tests.rs"]
mod range_proof_tests;
