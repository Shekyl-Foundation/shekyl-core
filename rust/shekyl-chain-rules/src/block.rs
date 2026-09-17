// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block on either side of `validate`: the untrusted [`Candidate`] going
//! in, the typed [`ValidatedBlock`] coming out inside a `ChainValid`.

use shekyl_types::{BlockHash, PqcAuthHash, PrunableHash, TxHash};
use shekyl_wire::{Block, BlockHeader, Transaction};

/// A transaction's identities, derived once (CEN-B6) beside its body.
///
/// The txid, the digest of its prunable region (`txs_prunable_hash`,
/// SCW-10), and — when the txid is 4-part — the third component
/// `H(varint(count) ‖ auths)` as [`Transaction::hash`] / [`Transaction::pqc_auth_hash`]
/// compute it (`PDM-Q-F26` / RTN-3). All three come from the same
/// `validate`, so no consumer re-hashes a body and the store never derives
/// a consensus-visible value (C2-R8 Q4). This is **not** a second identity:
/// `pqc_auth_hash` is the txid's own third component, typed.
///
/// For a coinbase `prunable_hash` is `keccak256("")` — what the C++ store
/// writes — not the txid's null-hash substitute; see [`PrunableHash`].
///
/// `pqc_auth_hash` is `Option` because the component is absent from the
/// txid itself, not merely from the store: the coinbase (`Ct::Null`) and
/// any spend whose `pqc_auths` is empty (the serve-credit form) hash
/// **3-part**, so `None` is "the txid has no such component" and a sentinel
/// — the null hash, or `keccak256(varint(0))` — would label the miner tx
/// with a value the chain never committed. (`prunable_hash`'s coinbase
/// value is a sentinel only because C++-store parity forced one; no C++
/// row exists here to force anything.)
///
/// The store row beside `txs_prunable_hash` (present ⇔ 4-part, never
/// deleted; hash without segment is *discarded* below `W`) is S-CHAIN-R /
/// `PDM-Q6` item 2: a new table, not a type-only codec change, and
/// therefore a `SCHEMA_VERSION` bump outside this slice. The type carries
/// the value so that increment does not fork a second identity. The store
/// invariant has three legs, because under `PDM-Q6` a hash row **without**
/// its segment is the steady state of every 4-part tx below the universal
/// window `W`, not a fault:
///
/// 1. hash row present ⇔ txid 4-part — permanent, written at connect,
///    never deleted (`validate` rejects the one shape, gen-first with
///    auths, that could split "4-part" from "segment non-empty");
/// 2. segment present ⇒ hash row present — a body the store cannot verify
///    is the invariant violation;
/// 3. hash row present ∧ segment absent ⇔ *discarded* — below `W` and not
///    a retention exception, or never held (a band-1 skeleton). One store
///    state with one meaning, however the node arrived at it.
///
/// So `None` here is *the txid has no third component*; leg 3 is *the
/// component exists and the bytes do not*. They are different facts and
/// must not share a representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TxIdentity {
    /// The transaction hash (txid).
    pub hash: TxHash,
    /// `keccak256` of the prunable byte region.
    pub prunable_hash: PrunableHash,
    /// The txid's third component, or `None` when the txid is 3-part.
    pub pqc_auth_hash: Option<PqcAuthHash>,
}

impl TxIdentity {
    fn of(tx: &Transaction) -> Self {
        Self {
            hash: TxHash::from_bytes(tx.hash()),
            prunable_hash: PrunableHash::from_bytes(tx.prunable_hash()),
            pqc_auth_hash: tx.pqc_auth_hash().map(PqcAuthHash::from_bytes),
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
/// `Block::hash`, and per transaction a [`TxIdentity`] (`Transaction::hash`,
/// `Transaction::prunable_hash`, and `Transaction::pqc_auth_hash`), CEN-B6's
/// definition applied, each
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
