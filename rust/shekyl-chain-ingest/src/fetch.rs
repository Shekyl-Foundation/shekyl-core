// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Building a corpus from a daemon: `block_list` in the full form, zero
//! C++ (RD-Q2, §3.4; `RPC_WIRE.md` RW-Q5).
//!
//! The fetcher asks for heights in batches through the workspace's
//! [`Rpc`] trait and the method table's types, so this is not a second
//! definition of the wire, and hands each `(block, txs)` to the
//! [`CorpusWriter`]. A corpus replays whole bodies, so a transaction the
//! daemon answers as `archived` (a body discarded at the archival horizon,
//! `PDM-Q10`, `SB-Q2`) is refused here, naming the height, the transaction
//! and its shard ([`FetchFault::Archived`]). The writer's verification
//! (RD-F15) still holds every record to its block's list in count, order
//! and hash, so completeness is a property the artifact demonstrates, not
//! one this module trusts the reply to assert. The module's other refusals
//! are about the conversation: a height the daemon does not hold, a reply
//! with the wrong number of slots.
//!
//! Generic over `Rpc` so the loop is tested against a scripted transport;
//! the binary supplies `shekyl_rpc_transport::HttpRpc`.

use std::io::{Seek, Write};
use std::num::NonZeroUsize;
use std::ops::Range;

use shekyl_rpc_client::{wire, Rpc, RpcError};
use shekyl_rpc_types::kinds::{Bytes, Height};
use shekyl_rpc_types::wire::shared::{ArchivedState, OrArchived, Slot, SlotState};
use shekyl_types::{BlockHeight, TxHash};

use crate::corpus::{CorpusFault, CorpusWriter};

/// Why the corpus could not be fetched.
#[derive(Debug, thiserror::Error)]
pub enum FetchFault {
    /// A block's bundle section names a body the daemon no longer holds:
    /// it was released past the undo retention, and a corpus without it
    /// cannot be replayed.
    #[error("the bundle body of a reference at height {height} is not held")]
    BundleBodyNotHeld {
        /// The block's height.
        height: BlockHeight,
    },
    /// The transport failed.
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    /// The daemon holds no block at a height the fetch asked for: the
    /// range runs past its tip, or its source could not be asked.
    #[error("the daemon holds no block at height {height}")]
    Missing {
        /// The height asked for.
        height: BlockHeight,
    },
    /// The reply carried a different number of slots than heights asked.
    #[error("asked for {asked} heights from {first}, got {got} slots")]
    CountMismatch {
        /// First height of the batch.
        first: u64,
        /// Heights requested.
        asked: usize,
        /// Entries returned.
        got: usize,
    },
    /// A listed body this daemon discarded at the archival horizon
    /// (`PDM-Q10`): the corpus needs it whole, and the archive is where it
    /// is served from.
    #[error("the body of {tx_hash} at height {height} is archived in shard {shard}; a corpus needs it whole")]
    Archived {
        /// The block's height.
        height: BlockHeight,
        /// The transaction.
        tx_hash: TxHash,
        /// The shard the archive serves it from.
        shard: u64,
    },
    /// The writer refused a record (RD-F15 and the rest of the corpus's
    /// verification).
    #[error(transparent)]
    Corpus(#[from] CorpusFault),
}

/// Fetch `heights` in batches of `batch` and write them through `writer`,
/// which must be positioned at `heights.start`. Returns the block records
/// written. A batch is non-zero by type: a
/// batch of zero heights would fetch nothing forever, and the caller's
/// flag refuses it before a file is created.
///
/// # Errors
///
/// Any [`FetchFault`]. The writer is left at the height that failed, so
/// a caller can report exactly how far the corpus reached.
pub async fn fetch_corpus<R: Rpc, W: Write + Seek>(
    rpc: &R,
    heights: Range<u64>,
    batch: NonZeroUsize,
    writer: &mut CorpusWriter<W>,
) -> Result<u64, FetchFault> {
    let mut written = 0u64;
    let mut first = heights.start;
    while first < heights.end {
        let end = first.saturating_add(batch.get() as u64).min(heights.end);
        let asked: Vec<u64> = (first..end).collect();
        let slots = rpc
            .call::<wire::BlockList>(wire::block::BlockListQuery {
                height: asked.iter().copied().map(Height).collect(),
                prune: false,
            })
            .await?;
        if slots.len() != asked.len() {
            return Err(FetchFault::CountMismatch {
                first,
                asked: asked.len(),
                got: slots.len(),
            });
        }
        for (height, slot) in asked.iter().zip(slots) {
            let at = BlockHeight::from_raw(*height);
            let block = match slot {
                Slot::Item(block) => block,
                Slot::State(SlotState::Missing(_) | SlotState::Archived(_)) | Slot::Unasked => {
                    return Err(FetchFault::Missing { height: at });
                }
            };
            let mut txs = Vec::with_capacity(block.tx.len());
            for tx in block.tx {
                match tx {
                    OrArchived::Item(listed) => txs.push(listed.body.into_vec()),
                    OrArchived::Archived(ArchivedState::Archived(archived)) => {
                        return Err(FetchFault::Archived {
                            height: at,
                            tx_hash: TxHash::from_bytes(archived.id.to_bytes()),
                            shard: archived.shard.0,
                        });
                    }
                }
            }
            // The section's bodies in section order, each the one its
            // reference names. A body the daemon no longer holds cannot be
            // replayed, so the capture stops there (`corpus.rs`, version 4).
            let references: Vec<Vec<u8>> = block.section.into_iter().map(Bytes::into_vec).collect();
            let carried: Vec<Vec<u8>> = block
                .section_body
                .into_iter()
                .map(Bytes::into_vec)
                .collect();
            let bodies = section_bodies(at, &references, &carried)?;
            writer.append_carrying(&block.body.0, &txs, &references, &bodies)?;
            written += 1;
        }
        first = end;
    }
    Ok(written)
}

/// The body of each of `references`, in section order, from `carried`,
/// matched by length and hash (§7.5). Each carried body is hashed once
/// ([`shekyl_archival_retention::CarriedBodies`]).
///
/// # Errors
///
/// [`FetchFault::BundleBodyNotHeld`] when a reference's body is not among
/// them: the daemon has released it, and a corpus without it cannot be
/// replayed.
fn section_bodies(
    height: BlockHeight,
    references: &[Vec<u8>],
    carried: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, FetchFault> {
    let by_hash =
        shekyl_archival_retention::CarriedBodies::index(carried.iter().map(Vec::as_slice));
    let mut bodies = Vec::with_capacity(references.len());
    for bytes in references {
        let found = shekyl_archival_retention::BundleRef::decode(bytes)
            .ok()
            .and_then(|reference| {
                by_hash
                    .named_by(&reference)
                    .filter(|named| reference.accept_body(named).is_ok())
                    .map(<[u8]>::to_vec)
            });
        match found {
            Some(body) => bodies.push(body),
            None => return Err(FetchFault::BundleBodyNotHeld { height }),
        }
    }
    Ok(bodies)
}
