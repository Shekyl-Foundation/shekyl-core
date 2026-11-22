// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The checks a record must pass before it is kept, and again when it is read.
//!
//! The writer runs them on the blobs a source handed over. The reader runs
//! the same functions on the blobs it cut out of the file. Completeness is
//! a property the bytes demonstrate, never a byte they assert (RD-F15).
//! An `extend` and an `offer` carry the same block, bodies and section, so
//! they pass the same checks ([`verified_block`]).

use shekyl_archival_retention::{BundleBody, BundleRef};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHeight, TxHash};
use shekyl_wire::{Block, Transaction};

use crate::fault::{CorpusFault, RecordAt};
use crate::record::{Extend, Offer};

/// A complete length-delimited block. `Block::read` would drop trailing
/// bytes inside the prefix and store them as if verified.
pub(crate) fn parse_block(at: RecordAt, blob: &[u8]) -> Result<Block, CorpusFault> {
    Block::from_bytes(blob).map_err(|cause| CorpusFault::Malformed {
        at,
        what: "block",
        cause,
    })
}

fn parse_tx(at: RecordAt, blob: &[u8]) -> Result<Transaction, CorpusFault> {
    Transaction::from_bytes(blob).map_err(|cause| CorpusFault::Malformed {
        at,
        what: "transaction",
        cause,
    })
}

/// One listed body, hashed against the header's `index`th hash (RD-F15).
pub(crate) fn verified_tx(
    at: RecordAt,
    index: usize,
    want: TxHash,
    blob: &[u8],
) -> Result<Transaction, CorpusFault> {
    let tx = parse_tx(at, blob)?;
    let got = tx.hash();
    if got != want {
        return Err(CorpusFault::BodyMismatch {
            at,
            index,
            listed: want,
            present: got,
        });
    }
    Ok(tx)
}

/// A block with its listed bodies and its bundle section, verified: what
/// an `extend` and an `offer` both carry.
pub(crate) struct Verified {
    pub(crate) block: Block,
    pub(crate) transactions: Vec<Transaction>,
    pub(crate) bundle_references: Option<BundleReferences>,
    pub(crate) bundle_bodies: Vec<BundleBody>,
}

impl Verified {
    /// The `extend` at `height`.
    pub(crate) fn into_extend(self, height: BlockHeight) -> Extend {
        Extend {
            height,
            block: self.block,
            transactions: self.transactions,
            bundle_references: self.bundle_references,
            bundle_bodies: self.bundle_bodies,
        }
    }

    /// The `offer`.
    pub(crate) fn into_offer(self) -> Offer {
        Offer {
            block: self.block,
            transactions: self.transactions,
            bundle_references: self.bundle_references,
            bundle_bodies: self.bundle_bodies,
        }
    }
}

/// The bodies match the header's list in count, order and hash (RD-F15),
/// and the section holds.
pub(crate) fn verified_block(
    at: RecordAt,
    block_blob: &[u8],
    tx_blobs: &[Vec<u8>],
    references: &[Vec<u8>],
    bodies: &[Vec<u8>],
) -> Result<Verified, CorpusFault> {
    let block = parse_block(at, block_blob)?;
    let listed = block.transaction_hashes.len();
    if tx_blobs.len() != listed {
        return Err(CorpusFault::IncompleteBodies {
            at,
            listed,
            present: tx_blobs.len(),
        });
    }
    let mut transactions = Vec::with_capacity(listed);
    for (index, (blob, want)) in tx_blobs.iter().zip(&block.transaction_hashes).enumerate() {
        transactions.push(verified_tx(at, index, *want, blob)?);
    }
    let (bundle_references, bundle_bodies) = verified_section(at, references, bodies)?;
    Ok(Verified {
        block,
        transactions,
        bundle_references,
        bundle_bodies,
    })
}

/// References that form a section, and in the same order the body each
/// names, held to it by length and hash (§7.5).
pub(crate) fn verified_section(
    at: RecordAt,
    references: &[Vec<u8>],
    bodies: &[Vec<u8>],
) -> Result<(Option<BundleReferences>, Vec<BundleBody>), CorpusFault> {
    let bad = || CorpusFault::BadSection { at };
    let section = BundleReferences::from_sidecar(references.to_vec()).map_err(|_| bad())?;
    if bodies.len() != references.len() {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(bodies.len());
    for (bytes, body) in references.iter().zip(bodies) {
        let reference = BundleRef::decode(bytes).map_err(|_| bad())?;
        out.push(reference.accept_body(body).map_err(|_| bad())?);
    }
    Ok((section, out))
}
