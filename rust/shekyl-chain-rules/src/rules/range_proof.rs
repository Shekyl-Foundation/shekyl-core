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
//! # Why a fold, and why here
//!
//! A batch verify is inherently multi-transaction and `tx_form` is
//! per-transaction, so the batch cannot live in `tx_form` without
//! abandoning the batch or smuggling block scope into a per-transaction
//! rule (Q9's structural argument). It runs in `validate`, after the slot
//! loop — so H19's layout half and CEN-I4's input cap have refused before
//! any proof work is spent — and before L1 and the archival uniqueness
//! passes, which is the C++'s order: the CT semantics (`verCtSemanticsSimple`
//! over the block's transactions, `ct_semantics.cpp`) run before the
//! spent-key insertion that refuses a repeat. The fold reads no view; by
//! slice 2's partition it could sit in `form`, and it sits here because the
//! rows that bound its cost run in `validate`'s slot loop.
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

use shekyl_bulletproofs::{verify_batch, BatchEntry, Bulletproof};
use shekyl_curve_io::CompressedPoint;
use shekyl_wire::Ct;

use crate::block::Candidate;
use crate::fault::ViewRead;
use crate::rules::tx::H19;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::ChainView;

/// One listed transaction's proof as the verifier reads it, or `None` if it
/// does not reassemble.
struct Listed {
    slot: TxSlot,
    proof: Option<Bulletproof>,
    commitments: Vec<CompressedPoint>,
}

impl Listed {
    fn entry(&self) -> Option<BatchEntry<'_>> {
        self.proof.as_ref().map(|proof| BatchEntry {
            proof,
            commitments: &self.commitments,
        })
    }

    /// The proof verified as a batch of one, under its own derived seed.
    fn verifies_alone(&self) -> bool {
        self.entry()
            .is_some_and(|entry| verify_batch(core::slice::from_ref(&entry)))
    }
}

impl H19 {
    /// The fold's verdict over a candidate's listed transactions (module
    /// docs). Pure in the candidate: no view, no entropy.
    pub(crate) fn verify_block(candidate: &Candidate) -> Verdict<()> {
        let listed = gather(candidate)?;

        // The batch, when every proof reassembled. The seed is derived over
        // the whole slice inside `verify_batch`, before any proof is
        // accumulated.
        let batch: Option<Vec<BatchEntry<'_>>> = listed.iter().map(Listed::entry).collect();
        if batch.is_some_and(|batch| verify_batch(&batch)) {
            return Ok(());
        }

        // The locus walk: the first transaction whose proof fails alone.
        if let Some(bad) = listed.iter().find(|tx| !tx.verifies_alone()) {
            return Err(InvalidBlock::new(Self::ROW, Locus::Tx { slot: bad.slot }));
        }
        // Unreachable but for a weight of zero. A failed batch has a proof
        // whose verification term is not the identity — a valid proof's term
        // is the identity under every weight — and that proof's own batch of
        // one fails unless its derived weight is zero, probability `1/ℓ`.
        // Refused at the block, never admitted and never a panic.
        Err(InvalidBlock::new(Self::ROW, Locus::Block))
    }
}

/// The block's proofs in block order — transaction order, then proof order —
/// each with its transaction's output commitments as carried.
fn gather(candidate: &Candidate) -> Verdict<Vec<Listed>> {
    let mut listed = Vec::new();
    for (n, tx) in candidate.transactions.iter().enumerate() {
        let slot = TxSlot::Listed(n);
        let Ct::Fcmp {
            base,
            prunable: Some(prunable),
            ..
        } = &tx.ct
        else {
            continue;
        };
        let bp = match prunable.bulletproofs.as_slice() {
            [] => continue,
            [bp] => bp,
            // The layout half refused this in `tx_form`; total here.
            _ => return Err(InvalidBlock::new(H19::ROW, Locus::Tx { slot })),
        };
        listed.push(Listed {
            slot,
            proof: bp.to_bulletproof(),
            commitments: base
                .commitments
                .iter()
                .map(|c| CompressedPoint::from(*c))
                .collect(),
        });
    }
    Ok(listed)
}

impl BlockRule for H19 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        Ok(Self::verify_block(cx.candidate()))
    }
}

#[cfg(test)]
#[path = "range_proof_tests.rs"]
mod range_proof_tests;
