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
use crate::rules::{BlockContext, BlockRule, Rule, TxAgainstRule, TxContext, TxScope};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};
use crate::view::ChainView;
use shekyl_types::{BlockCount, KeyImage};
use shekyl_wire::Input;

/// CEN-I11's window, lower edge: a spend's `referenceBlock` is at least
/// this many blocks below the connecting height (`ref_height ≤
/// chain_height − MIN_AGE`; `blockchain.cpp:4121`). A `const` beside its
/// rule, not a `RuleSet` field: no schedule step varies it (slice 6 Q5,
/// the F21 test). The authority is `config/consensus_constants.json`
/// (`fcmp_reference_block_min_age`), which also drives the C++ header;
/// `reference_window_is_the_json_authoritys` holds this equal to it, so
/// the two cannot drift apart silently.
pub const REFERENCE_BLOCK_MIN_AGE: BlockCount = BlockCount::from_raw(5);

/// CEN-I11's window, upper edge: a spend's `referenceBlock` is at most
/// this many blocks below the connecting height (`ref_height ≥
/// chain_height − MAX_AGE`; `blockchain.cpp:4133`). Same authority and
/// pin as [`REFERENCE_BLOCK_MIN_AGE`] (`fcmp_reference_block_max_age`).
pub const REFERENCE_BLOCK_MAX_AGE: BlockCount = BlockCount::from_raw(100);

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

#[cfg(test)]
#[path = "tx_against_tests.rs"]
mod tx_against_tests;
