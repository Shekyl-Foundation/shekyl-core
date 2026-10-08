// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's spending side: a wallet-side curve tree over a chain of
//! mined blocks, and a real spend of any coinbase (or watched output) in
//! it — the object CEN-I15 judges (DRS-E3 commit 7,
//! `DRS_E3_CURVE_WRITER.md` §2.3; CHAIN_RULES_SLICE_6.md §5 row 6).
//!
//! # Why a crate
//!
//! This was the ingest's `scenario_spend.rs`. The store's tests need the
//! same object — a spend of a fixture block's coinbase that a real prover
//! made, so the rules crate's CEN-I13/I15 Spend-class rows can be flipped
//! to `implemented` over transactions that verify rather than fillers that
//! are skipped — and the store cannot dev-depend on the ingest, which
//! depends on the store. The producer lives in its own crate that both
//! dev-depend on. It is wallet-side only: it depends on
//! [`shekyl_harness_wallet`] (the identities and the coinbase composition
//! the rules harness also reaches) and on the production wallet stack, and
//! never on the ingest, the store, or the block template.
//!
//! # The second-oracle property
//!
//! A membership proof is valid only against the tree it was made in, so a
//! spend needs a path through the tree the **store** grew. This crate
//! takes it from the **wallet-side** tree instead — [`shekyl_curve_tree`]'s
//! `CurveTreeClient`, the proving store DRS-D3c owns — fed the same blocks
//! the chain connected, in order ([`Spender::push`]). The daemon-side
//! writer and the wallet-side client are two Rust producers of one tree
//! over one sequence of blocks, and [`Spender::root_at`] against the
//! store's `root_at` holds them equal at every height a test asks. If the
//! path were assembled from the store's own rows the spend would prove
//! nothing about the wallet side; if the client's tree diverged from the
//! store's, the spend would not verify against the header's root — CEN-I15
//! is exactly the rule that would refuse it, which is the point of
//! building the object here rather than planting a root a fixture read
//! back (slice 6 §5.3).
//!
//! What is real: the miner's keys and the coinbase that paid them (`0x06`
//! KEM ciphertext, `0x07` leaf entry), recovered by the production scanner
//! (`recover_combined_ss`, `scan_output`, `compute_output_key_image`); the
//! path (`assemble_path`); the signature (`sign_transaction_with_terms`,
//! `sign_pqc_auths`); the wire bytes (`encode_final_tx`). Nothing is a
//! filler point or a conforming blob.
//!
//! A spend can pay a [`Recipient`] other than the miner — a persona's base
//! address — and the tree can be told to watch ([`Spender::own`]) for
//! listed outputs so that, once a block carrying them is pushed,
//! [`Spender::owned_input`] sources them for any [`Owner`] holding the
//! matching secrets. That is what an emission claim spends: a backing
//! output and a fee output paid to the persona by an earlier spend of the
//! miner's coinbase.
//!
//! # What a mined block is
//!
//! [`MinedBlock`] names what the tree reads off a connected block: its
//! height, its hash, its miner transaction and its listed bodies. The
//! ingest's `Mined` implements it; a store test implements it over the
//! candidate it connected. The spender is not told what produced the
//! block.

#![forbid(unsafe_code)]

pub mod bond;
mod spender;

use shekyl_chain_rules::{RuleSet, REFERENCE_BLOCK_MIN_AGE};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::Transaction;

pub use bond::PostedBond;
pub use shekyl_chain_rules::newest_admissible_reference;
pub use shekyl_harness_wallet::{MinerWallet, Owner, Recipient};
pub use spender::{Sourced, Spender};

/// A connected block as the wallet-side tree reads it.
pub trait MinedBlock {
    /// The height the block connected at.
    fn height(&self) -> BlockHeight;
    /// The block's identity — the reference block's hash when a spend
    /// anchors at this height.
    fn hash(&self) -> BlockHash;
    /// The miner transaction, the block's first.
    fn miner_transaction(&self) -> &Transaction;
    /// The listed bodies, in the order the block names them.
    fn listed(&self) -> &[Transaction];
}

/// Blocks after a coinbase's height before a spend of it can connect —
/// the unlock window, one, and [`REFERENCE_BLOCK_MIN_AGE`].
///
/// A coinbase mined at `h` is locked to `h + W` (`W` the rule set's
/// `mined_money_unlock_window`; the fixture and the template both set
/// `unlock_time` so). It unlocks when the block at `h + W` connects and
/// enters the tree with that block's drain, so the first root that holds
/// it is the state going into `h + W + 1`. A spend connecting at `c`
/// anchors at the newest reference CEN-I11 admits,
/// [`newest_admissible_reference`]`(c) = c − MIN_AGE`, whose root must
/// hold the leaf: `c − MIN_AGE ≥ h + W + 1`, so `c ≥ h + W + 1 + MIN_AGE`.
///
/// Not the rule set's `tx_spendable_age`: that is the age a **listed**
/// transaction's outputs wait, and a coinbase's wait is its unlock
/// window. The earlier driver added the two and connected at 71, five
/// blocks later than the first admissible height; the margin had no
/// reason written, which is how a number gets copied.
#[must_use]
pub fn coinbase_maturity(rules: &RuleSet) -> BlockCount {
    rules.mined_money_unlock_window() + BlockCount::ONE + REFERENCE_BLOCK_MIN_AGE
}

/// The first height that can spend block 0's coinbase against a root that
/// holds it: [`coinbase_maturity`] measured from genesis.
#[must_use]
pub fn first_spending_height(rules: &RuleSet) -> BlockHeight {
    BlockHeight::ZERO
        .checked_add(coinbase_maturity(rules))
        .expect("an unlock window is a small span")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_spending_height_is_the_window_one_and_the_reference_age() {
        let rules = &RuleSet::GENESIS;
        let first = first_spending_height(rules);
        // The newest reference the first spending height admits is the
        // first root that holds block 0's coinbase: the state going into
        // the block after the one that unlocked it.
        let reference = newest_admissible_reference(first).expect("admits a reference");
        assert_eq!(
            reference.to_raw(),
            rules.mined_money_unlock_window().to_raw() + 1
        );
        // One block earlier, the reference is the unlocking block itself,
        // whose root predates the leaf.
        let earlier = first
            .checked_sub_count(BlockCount::ONE)
            .expect("above genesis");
        assert_eq!(
            newest_admissible_reference(earlier)
                .expect("admits a reference")
                .to_raw(),
            rules.mined_money_unlock_window().to_raw()
        );
    }
}
