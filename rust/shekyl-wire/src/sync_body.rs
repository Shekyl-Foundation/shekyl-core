// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A block body as chain sync carries it (CS-Q3.3, `PDM-Q-F28`).
//!
//! The commands that move this value live in `shekyl-levin`. The value
//! itself lives here so the validator can bind a body to its header
//! (`shekyl-chain-rules::bind_body`) without taking a framing dependency:
//! the consensus crate does not parse Levin, and the framing crate does
//! not judge a block.
//!
//! Each transaction is full or a skeleton, and the choice is the
//! supplier's. A boundary block is mixed. The form is not a fault; the
//! receiver binds either form to the declared txid.

use std::fmt;
use std::io;

use shekyl_crypto_hash::keccak256;
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash, TxHash};

use crate::transaction::Transaction;

/// A transaction in a synced block body.
#[derive(Clone, PartialEq, Eq)]
pub enum TxBody {
    /// The transaction's whole encoding ([`Transaction::write`]).
    Full(Vec<u8>),
    /// Prefix and base, plus the three operands a pruned receiver cannot
    /// recompute (`PDM-Q-F28`).
    Skeleton(SkeletonTx),
}

/// The unprunable bytes of a transaction and the txid operands that were
/// discarded with the rest (`Transaction::hash_with_supplied_components`).
#[derive(Clone, PartialEq, Eq)]
pub struct SkeletonTx {
    /// [`crate::transaction::TxSegments::pruned`]: version, prefix and the
    /// committed base, exactly. [`Transaction::from_pruned_bytes`] is the
    /// parser; bytes after the base are not this segment.
    pub unprunable: Vec<u8>,
    /// The store's prunable digest, supplied rather than recomputed.
    pub prunable_hash: PrunableHash,
    /// The txid's third component when the prefix can carry one. `None`
    /// is the identity's predicate, the same `Option` [`crate::transaction::TxidParts`]
    /// carries.
    pub pqc_auth_hash: Option<PqcAuthHash>,
    /// The archival length the txid mixes. A skeleton's own measurement
    /// is zero; this is the accepted transaction's.
    pub archival_len: ArchivalLength,
}

impl SkeletonTx {
    /// The txid of the transaction these components belong to.
    ///
    /// # Errors
    ///
    /// The unprunable bytes are not exactly the pruned segment
    /// ([`Transaction::from_pruned_bytes`]). Bytes after the base are
    /// refused: [`Transaction::read`] would take them as authentications
    /// and proof data, and the txid below ignores both.
    pub fn txid(&self) -> io::Result<TxHash> {
        let tx = Transaction::from_pruned_bytes(&self.unprunable)?;
        Ok(tx.hash_with_supplied_components(
            self.pqc_auth_hash,
            self.prunable_hash,
            self.archival_len,
        ))
    }
}

/// One requested block: the block blob, each transaction in either form,
/// and the attestation witness the header's root commits.
#[derive(Clone, PartialEq, Eq)]
pub struct BlockBody {
    /// [`crate::Block::serialize`].
    pub block: Vec<u8>,
    /// Listed transactions, in the block's order. The coinbase rides inside
    /// `block`.
    pub txs: Vec<TxBody>,
    /// The witness beside the block. Empty when the set is empty.
    pub attestation_witness: Vec<u8>,
}

/// A blob in `Debug` is its length and its keccak, never its bytes. A
/// response is a peer's input; printing it is the log amplifier a large
/// payload was.
fn digest(bytes: &[u8]) -> String {
    let hash = keccak256(bytes);
    format!(
        "{}B#{:02x}{:02x}{:02x}{:02x}",
        bytes.len(),
        hash[0],
        hash[1],
        hash[2],
        hash[3]
    )
}

impl fmt::Debug for TxBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(bytes) => f.debug_tuple("Full").field(&digest(bytes)).finish(),
            Self::Skeleton(tx) => f.debug_tuple("Skeleton").field(tx).finish(),
        }
    }
}

impl fmt::Debug for SkeletonTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkeletonTx")
            .field("unprunable", &digest(&self.unprunable))
            .field("prunable_hash", &self.prunable_hash)
            .field("pqc_auth_hash", &self.pqc_auth_hash)
            .field("archival_len", &self.archival_len)
            .finish()
    }
}

impl fmt::Debug for BlockBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockBody")
            .field("block", &digest(&self.block))
            .field("txs", &self.txs)
            .field("witness", &digest(&self.attestation_witness))
            .finish()
    }
}
