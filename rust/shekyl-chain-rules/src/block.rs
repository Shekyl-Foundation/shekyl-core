// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block on either side of `validate`: the untrusted [`Candidate`] going
//! in, the typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use shekyl_types::{BlockHash, PqcAuthHash, PrunableHash, TxHash};
use shekyl_wire::{Block, BlockHeader, Transaction};

use crate::coverage::RuleCoverage;
use crate::rules::header::B6;

/// A transaction's identities, derived once (CEN-B6) beside its body.
///
/// The txid and the two **discardable components** it was built over: the
/// digest of the per-input `pqc_auths` (the txid's third component,
/// `PDM-Q-F26`) and the digest of the prunable region (its fourth, S-CHAIN-W
/// SCW-10) — the values the chain store records as `txs_pqc_auth_hash` and
/// `txs_prunable_hash` so a node that keeps only the skeleton can still
/// reconstruct the txid it accepted (`Transaction::hash_with_supplied_components`).
/// All three come from the same `validate`, so no consumer re-hashes a body
/// and the store never derives a consensus-visible value (C2-R8 Q4).
///
/// `pqc_auth_hash` is `None` exactly when the txid is **3-part** — a
/// coinbase, a serve-credit, the malformed gen-first and no-input shapes — a fact about
/// the identity, not about what was kept; see [`PqcAuthHash`]. For a
/// coinbase `prunable_hash` is `keccak256("")` — what the C++ store writes —
/// not the txid's null-hash substitute; see [`PrunableHash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxIdentity {
    /// The transaction hash (txid).
    pub hash: TxHash,
    /// The txid's third component, or `None` for a 3-part txid.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// `keccak256` of the prunable byte region.
    pub prunable_hash: PrunableHash,
}

impl TxIdentity {
    fn of(tx: &Transaction) -> Self {
        Self {
            hash: TxHash::from_bytes(tx.hash()),
            pqc_auth_hash: tx.pqc_auth_hash(),
            prunable_hash: tx.prunable_hash(),
        }
    }
}

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
/// `Block::hash`, and per transaction a [`TxIdentity`] (`Transaction::hash`
/// and `Transaction::prunable_hash`), CEN-B6's definition applied, each
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
///     miner_tx: todo!(),
///     transactions: todo!(),
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedBlock {
    hash: BlockHash,
    block: Block,
    miner_tx: TxIdentity,
    transactions: Vec<(TxIdentity, Transaction)>,
}

impl ValidatedBlock {
    /// Derive every identity once. Called by `validate` after the last rule
    /// has passed and nowhere else. The block's identity comes from CEN-B6's
    /// function, which records the row in `coverage` (slice 1, Q5).
    pub(crate) fn derive(candidate: Candidate, coverage: &mut RuleCoverage) -> Self {
        let Candidate {
            block,
            transactions,
        } = candidate;
        Self {
            hash: B6::identity(&block, coverage),
            miner_tx: TxIdentity::of(&block.miner_transaction),
            block,
            transactions: transactions
                .into_iter()
                .map(|tx| (TxIdentity::of(&tx), tx))
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

    /// The miner transaction with its identities.
    #[must_use]
    pub const fn miner_tx(&self) -> (TxIdentity, &Transaction) {
        (self.miner_tx, &self.block.miner_transaction)
    }

    /// The listed transactions' bodies with their identities, in the
    /// header's order.
    #[must_use]
    pub fn transactions(&self) -> &[(TxIdentity, Transaction)] {
        &self.transactions
    }
}
