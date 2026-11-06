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

use crate::transaction::{Ct, Transaction};

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
    /// and proof data, and the txid below ignores both. A `pqc_auth_hash`
    /// the prefix cannot carry is refused too (`SB-Q2`): the mixer would
    /// drop it and hash to a real identity, and a skeleton whose operands
    /// are not all the transaction's is not that transaction's skeleton.
    pub fn txid(&self) -> io::Result<TxHash> {
        self.parse().map(|(_, txid)| txid)
    }

    /// Bind this skeleton to `txid`: parse the unprunable bytes, mix them
    /// with the supplied operands, and refuse unless the result is `txid`.
    /// The [`BoundTx`] is the body **and** the identity it was bound to,
    /// and nothing else constructs one, so a consumer that takes a
    /// [`BoundTx`] cannot be handed a body whose txid was only claimed.
    ///
    /// The supplier chose the bytes and the three operands alike, and gains
    /// nothing by it: to answer `txid` with another body it would have to
    /// solve `H(prefix ‖ base ‖ P ‖ X ‖ len) = txid` for `P`, `X` and `len`,
    /// a keccak preimage, not a substitution.
    ///
    /// # Errors
    ///
    /// [`Self::txid`]'s, and a mismatch between the mixed identity and
    /// `txid`.
    pub fn bind(&self, txid: TxHash) -> io::Result<BoundTx> {
        let (tx, mixed) = self.parse()?;
        if mixed != txid {
            return Err(io::Error::other(format!(
                "shekyl-wire: the skeleton's bytes and operands hash to {mixed}, not {txid}"
            )));
        }
        Ok(BoundTx { tx, txid })
    }

    /// The parsed body and the identity its supplied operands mix to.
    fn parse(&self) -> io::Result<(Transaction, TxHash)> {
        let tx = Transaction::from_pruned_bytes(&self.unprunable)?;
        // A null transaction is the coinbase, and the coinbase rides in the
        // block. It has no prunable region and no authentication hash, so a
        // skeleton's supplied components would not be part of its txid.
        if matches!(tx.ct, Ct::Null(_)) {
            return Err(io::Error::other(
                "shekyl-wire: a null transaction is not a skeleton",
            ));
        }
        // The other direction, a carrying prefix supplied `None`, needs no
        // check here: the accepted identity mixed the component, so the
        // mix below reaches another txid and `bind` refuses it. (A carrying
        // prefix whose auths are empty hashes 3-part on chain, so `None`
        // there is the transaction's own arity, not a lie.)
        if self.pqc_auth_hash.is_some() && !tx.prefix_carries_pqc_component() {
            return Err(io::Error::other(
                "shekyl-wire: a pqc_auth_hash was supplied for a prefix that carries none",
            ));
        }
        let txid = tx.hash_with_supplied_components(
            self.pqc_auth_hash,
            self.prunable_hash,
            self.archival_len,
        );
        Ok((tx, txid))
    }
}

/// A transaction body bound to its txid.
///
/// Constructed by [`SkeletonTx::bind`] alone: the body was parsed from a
/// skeleton whose supplied operands mix with it to exactly the identity
/// the holder asked for. A consumer that takes this type, not a bare
/// [`Transaction`], is therefore reading a body whose identity was
/// **recomputed**, never one whose identity was a label beside it. A
/// pruned body's own [`Transaction::hash`] is an identity no transaction
/// has, which is why the txid rides here instead of being asked of the
/// body (`SB-Q2`; `GENESIS_TX_WIRE_FORMAT.md` §11).
///
/// The body is readable through [`Self::tx`] and never writable: a
/// mutation would unbind it. [`Self::into_tx`] gives the body up and the
/// binding with it. There is no [`Deref`](std::ops::Deref). A pruned
/// body's [`Transaction::hash`] is not this binding's identity, and a
/// deref would let a caller ask for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoundTx {
    tx: Transaction,
    txid: TxHash,
}

impl BoundTx {
    /// The bound body.
    #[must_use]
    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    /// The identity the body was bound to.
    #[must_use]
    pub fn txid(&self) -> TxHash {
        self.txid
    }

    /// The body, unbound.
    #[must_use]
    pub fn into_tx(self) -> Transaction {
        self.tx
    }

    /// A whole body in hand, bound to the identity it hashes to itself.
    ///
    /// For fixtures only: a test that builds a [`Transaction`] has the whole
    /// body and its [`Transaction::hash`] is its identity. Production code
    /// never holds a whole non-coinbase body it did not bind through a
    /// skeleton, and a body parsed from a pruned segment hashes to an
    /// identity no transaction has, so this constructor is gated out of
    /// every production build.
    #[cfg(feature = "test-fixtures")]
    #[must_use]
    pub fn whole(tx: Transaction) -> Self {
        let txid = tx.hash();
        Self { tx, txid }
    }

    /// Edit the body and rebind it to what the edited whole body hashes
    /// to. For fixtures only, as [`Self::whole`].
    #[cfg(feature = "test-fixtures")]
    pub fn modify(&mut self, edit: impl FnOnce(&mut Transaction)) {
        edit(&mut self.tx);
        self.txid = self.tx.hash();
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
