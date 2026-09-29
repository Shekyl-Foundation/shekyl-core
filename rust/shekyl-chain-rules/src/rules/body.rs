// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.G — the block body as a whole (E6 slice 7,
//! `CHAIN_RULES_SLICE_7.md` §4): the rows that hold *across* a block's listed
//! transactions after each has passed `tx_form` and `tx_against` on its
//! own. This file carries the stateless one; the view-bound body rows (G1,
//! G7, G9, G10) land beside it in slice 7 commit 7.
//!
//! # CEN-G2 — the declared list and the carried bodies agree
//!
//! A block declares its listed transactions by hash (`transaction_hashes`)
//! and travels with their bodies positionally. **What the C++ does, read at
//! `blockchain.cpp:5505–5590`:** `handle_block_to_main_chain` iterates the
//! header's hashes and resolves each from the pool or the block's own
//! supplement; a hash that resolves to nothing is `MISSING_TXS` — not a
//! refusal but a "do not connect, ask for the bodies" — and a body is never
//! *checked* against the hash it came in under, because in the C++ the hash
//! is the lookup key and the body is what the key returned. The Rust
//! pipeline receives bodies positionally (`Candidate::transactions`, in the
//! header's order), so the agreement the C++ gets by construction is a
//! **rule** here: one the census names and slice 7 Q7 classed as a
//! [`FormRule`] — L1's *class* (a property of the candidate's bytes alone,
//! no view), not L1's *severity*. Until it landed, a reordered or
//! substituted body connected and the store assigned its outputs in body
//! order (§3.1; measured by `body_pairing_tests`, slice 7 commit 2) — the
//! curve tree's drain order, which is why G2 is a precondition for E3's
//! correctness and not a tidiness rule.
//!
//! **The loci, from slice 7 Q8's first test** (a locus is derivable from the
//! refusal's own evidence): a **length** mismatch is refused at
//! [`Locus::Block`] — the rule's evidence is two lengths and names no slot;
//! the **first index** whose body hashes to something other than the
//! declared hash is refused at `Locus::Tx { slot: Listed(i) }` — the rule
//! computed exactly *i*. Length first, so an index arm never reads past the
//! shorter list; first mismatch only, so the locus is the one the rule
//! established rather than "every slot that disagrees".
//!
//! **What G2 is not.** No rule compares a merkle root to anything: the tree
//! hash over the declared list is an input to the block's identity
//! (`Block::pow_blob`; B6 records it, D2 judges the PoW over it), so a
//! different list is a different block, not a mismatch. G2 is the one
//! hash-against-hash comparison in 4.G, per index by construction.
//! `MISSING_TXS` — the pool's "I do not hold this body yet" — is the
//! ingest's affair before a `Candidate` exists; a candidate that reaches
//! `form` has as many bodies as it has, and G2 judges what it has.

use shekyl_wire::Transaction;

use crate::census::CenRow;
use crate::rules::{FormContext, FormRule, Rule};
use crate::verdict::{InvalidBlock, Locus, TxSlot, Verdict};

/// CEN-G2: every declared hash is the hash of the body carried at its
/// index, and there are exactly as many bodies as hashes.
pub(crate) struct G2;

impl Rule for G2 {
    const ROW: CenRow = CenRow::G2;
}

impl FormRule for G2 {
    fn check(cx: &FormContext<'_>) -> Verdict<()> {
        let declared = &cx.candidate.block.transaction_hashes;
        let carried = &cx.candidate.transactions;
        if declared.len() != carried.len() {
            return Err(InvalidBlock::new(Self::ROW, Locus::Block));
        }
        match declared
            .iter()
            .zip(carried)
            .position(|(hash, body)| Transaction::hash(body) != *hash)
        {
            None => Ok(()),
            Some(first) => Err(InvalidBlock::new(
                Self::ROW,
                Locus::Tx {
                    slot: TxSlot::Listed(first),
                },
            )),
        }
    }
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod body_tests;
