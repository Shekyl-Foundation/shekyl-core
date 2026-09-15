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
/// two arguments (round-1 ruling Q9). `#[non_exhaustive]` so a third
/// component later is a constructor-site addition, not a breaking struct
/// literal (the Q9 "non-breaking" claim; Copilot #753).
///
/// ```compile_fail
/// use shekyl_chain_rules::Candidate;
/// let _ = Candidate { block: todo!(), transactions: todo!() };
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The block: header, miner transaction, listed transaction hashes.
    pub block: Block,
    /// The listed transactions' bodies, in the header's order.
    pub transactions: Vec<Transaction>,
}

impl Candidate {
    /// Assemble a candidate from the block as received and the listed
    /// bodies, in listed order.
    #[must_use]
    pub fn new(block: Block, transactions: Vec<Transaction>) -> Self {
        Self {
            block,
            transactions,
        }
    }
}

/// The typed payload a `ChainValid` wraps.
///
/// The candidate exactly as judged — the block is kept whole, so what the
/// store persists is what the rules saw — with every identity derived once:
/// `Block::hash` and `Transaction::hash`, CEN-B6's definition applied, each
/// paired with its body. No consumer re-hashes and no two values can disagree
/// about which block or transaction they describe (ruling Q4/L4: one value
/// per identity).
///
/// Constructed only by `validate`. The fields are private and there is no
/// public constructor: a `ValidatedBlock` in hand was judged (G5).
///
/// ```compile_fail
/// use shekyl_chain_rules::ValidatedBlock;
/// let forged = ValidatedBlock {
///     hash: todo!(),
///     block: todo!(),
///     miner_tx_hash: todo!(),
///     transactions: todo!(),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    hash: BlockHash,
    block: Block,
    miner_tx_hash: TxHash,
    transactions: Vec<(TxHash, Transaction)>,
}

impl ValidatedBlock {
    /// Derive every identity once. Called by `validate` after the last rule
    /// has passed and nowhere else.
    pub(crate) fn derive(candidate: Candidate) -> Self {
        let Candidate {
            block,
            transactions,
        } = candidate;
        Self {
            hash: BlockHash::from_bytes(block.hash()),
            miner_tx_hash: TxHash::from_bytes(block.miner_transaction.hash()),
            block,
            transactions: transactions
                .into_iter()
                .map(|tx| (TxHash::from_bytes(tx.hash()), tx))
                .collect(),
        }
    }

    /// The block's identity.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.hash
    }

    /// The block as judged: header, miner transaction, listed hashes.
    #[must_use]
    pub const fn block(&self) -> &Block {
        &self.block
    }

    /// The header as judged.
    #[must_use]
    pub const fn header(&self) -> &BlockHeader {
        &self.block.header
    }

    /// The miner transaction with its identity.
    #[must_use]
    pub const fn miner_tx(&self) -> (TxHash, &Transaction) {
        (self.miner_tx_hash, &self.block.miner_transaction)
    }

    /// The listed transactions' bodies with their identities, in the
    /// header's order.
    #[must_use]
    pub fn transactions(&self) -> &[(TxHash, Transaction)] {
        &self.transactions
    }
}
