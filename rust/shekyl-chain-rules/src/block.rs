// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block on either side of `validate`: the untrusted [`Candidate`] going
//! in, the typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use shekyl_types::{BlockHash, PrunableHash, TxHash};
use shekyl_wire::{Block, BlockHeader, Transaction};

/// A transaction's identities, derived once (CEN-B6) beside its body.
///
/// The txid, and the digest of its prunable region — the fourth component
/// of a spend's txid and the value the chain store records as
/// `txs_prunable_hash` (S-CHAIN-W SCW-10). Both come from the same
/// `validate`, so no consumer re-hashes a body and the store never derives
/// a consensus-visible value (C2-R8 Q4). For a coinbase `prunable_hash` is
/// `keccak256("")` — what the C++ store writes — not the txid's null-hash
/// substitute; see [`PrunableHash`].
///
/// **Incomplete by one component — owed, not optional (`PDM-Q-F26`,
/// `ARCHIVAL_PRUNED_DAEMON_MODE.md`).** A spend's txid is 4-part:
/// `H(prefix) · H(base) · H(pqc_auths) · H(prunable)`. This identity carries
/// the fourth component and omits the third. Under `PDM-Q6` the `pqc_auths`
/// slice (~60 % of spend bytes) is the archival good's second occupant and
/// is discardable only against a persisted per-tx hash of it; the txid
/// already commits that hash, and `Transaction::hash()` computes it on the
/// way. The next increment that touches this type adds
/// `pqc_auth_hash: Option<PqcAuthHash>` — the txid's third component, over
/// `varint(count) ‖ auths` exactly as the txid hashes it, **not**
/// `keccak256` of the raw `txs_pqc_auths` segment (which has no count
/// prefix and so verifies nothing the chain signed) — with a KAT against
/// `Transaction::hash()`, and the store records it beside
/// `txs_prunable_hash`.
///
/// `Option`, because the component is absent from the txid itself, not
/// merely from the store: the coinbase (`Ct::Null`) and any spend whose
/// `pqc_auths` is empty (the serve-credit form) hash **3-part**, so `None`
/// is "the txid has no such component" and a sentinel — the null hash, or
/// `keccak256(varint(0))` — would label the miner tx with a value the chain
/// never committed. (`prunable_hash`'s coinbase value is a sentinel only
/// because C++-store parity forced one; no C++ row exists here to force
/// anything.) The store row is sparse on the same predicate as
/// `txs_pqc_auths` itself, which writes no row for an empty segment:
/// segment present ⇔ hash row present ⇔ txid 4-part — `validate` rejects
/// the one shape (gen-first with auths) that could split them — so a row
/// without a segment, or a segment without a row, is a store invariant,
/// never a `None`. Contract on the row before the implementation that
/// would omit it (SCW-7's standard). A `PDM-Q6` ruling that keeps
/// `pqc_auths` universal retires the *row*, not the component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxIdentity {
    /// The transaction hash (txid).
    pub hash: TxHash,
    /// `keccak256` of the prunable byte region.
    pub prunable_hash: PrunableHash,
}

impl TxIdentity {
    fn of(tx: &Transaction) -> Self {
        Self {
            hash: TxHash::from_bytes(tx.hash()),
            prunable_hash: PrunableHash::from_bytes(tx.prunable_hash()),
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
    /// has passed and nowhere else.
    pub(crate) fn derive(candidate: Candidate) -> Self {
        let Candidate {
            block,
            transactions,
        } = candidate;
        Self {
            hash: BlockHash::from_bytes(block.hash()),
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
