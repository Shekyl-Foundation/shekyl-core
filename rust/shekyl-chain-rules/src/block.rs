// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block on either side of `validate`: the untrusted [`Candidate`] going
//! in, the typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use shekyl_types::{BlockHash, TxHash};
use shekyl_wire::{Block, BlockHeader, Transaction};

/// The untrusted input to `validate`: the block as received, plus the bodies
/// of the transactions its header lists, in listed order.
///
/// Public fields — this is the outside. Nothing about it has been checked,
/// including whether `transactions` are the bodies `block.transaction_hashes`
/// names; that is a 4.G rule and lands with its slice. One value rather than
/// two arguments (round-1 ruling Q9): it is what a verdict is *about*, and a
/// third component later is non-breaking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The block: header, miner transaction, listed transaction hashes.
    pub block: Block,
    /// The listed transactions' bodies, in the header's order.
    pub transactions: Vec<Transaction>,
}

/// The typed payload a `ChainValid` wraps.
///
/// The candidate with every identity derived once — `Block::hash`,
/// `Transaction::hash`, CEN-B6's definition applied — and paired with its
/// body, so no consumer re-hashes and no two values can disagree about which
/// block or transaction they describe (ruling Q4/L4: one value per identity).
///
/// Constructed only by `validate`. The fields are private and there is no
/// public constructor: a `ValidatedBlock` in hand was judged.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    hash: BlockHash,
    header: BlockHeader,
    miner_tx: (TxHash, Transaction),
    transactions: Vec<(TxHash, Transaction)>,
}

impl ValidatedBlock {
    /// The block's identity.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The header as judged.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The miner transaction with its identity.
    #[must_use]
    pub const fn miner_tx(&self) -> &(TxHash, Transaction) {
        &self.miner_tx
    }

    /// The listed transactions with their identities, in the header's order.
    #[must_use]
    pub fn transactions(&self) -> &[(TxHash, Transaction)] {
        &self.transactions
    }
}
