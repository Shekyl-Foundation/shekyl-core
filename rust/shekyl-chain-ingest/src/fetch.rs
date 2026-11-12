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
//!
//! **Injections** (DRS-E4 §3.8 item 3). A regtest daemon's state can carry
//! one row no block produced — a serve credit the injector wrote at the
//! tip of the moment — and `block_list` cannot see it. The
//! caller hands the fetch the injector's receipts ([`Injection`]: the
//! credit and the height it was attributed to), and the fetch writes each
//! `Inject` record right after the block at its height, so the corpus
//! carries the event at its capture position. A receipt whose height the
//! fetch does not reach is refused before any block is requested
//! ([`FetchFault::InjectionOutOfRange`]): a receipt silently dropped would
//! be a corpus mislabelled as wholly block-derived.

use std::io::{Seek, Write};
use std::num::NonZeroUsize;
use std::ops::Range;

use shekyl_rpc_client::{wire, Rpc, RpcError};
use shekyl_rpc_types::kinds::Height;
use shekyl_rpc_types::wire::shared::{ArchivedState, OrArchived, Slot, SlotState};
use shekyl_types::{BlockHeight, TxHash};

use crate::corpus::{CorpusFault, CorpusWriter};
use crate::source::Injection;

/// Why the corpus could not be fetched.
#[derive(Debug, thiserror::Error)]
pub enum FetchFault {
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
    /// An injection receipt names a height the fetch does not reach, so
    /// its record could never be placed beside its block.
    #[error("injection {injection} is attributed to a height outside the fetched range")]
    InjectionOutOfRange {
        /// The receipt.
        injection: Injection,
    },
}

/// Fetch `heights` in batches of `batch` and write them through `writer`,
/// which must be positioned at `heights.start`, placing each of
/// `injections` right after the block at its height (module docs; any
/// order, any count — several at one height land in the order given).
/// Returns the **block** records written. A batch is non-zero by type: a
/// batch of zero heights would fetch nothing forever, and the caller's
/// flag refuses it before a file is created.
///
/// # Errors
///
/// Any [`FetchFault`]; [`FetchFault::InjectionOutOfRange`] before any
/// block is requested. Otherwise the writer is left at the height that
/// failed, so a caller can report exactly how far the corpus reached.
pub async fn fetch_corpus<R: Rpc, W: Write + Seek>(
    rpc: &R,
    heights: Range<u64>,
    batch: NonZeroUsize,
    injections: &[Injection],
    writer: &mut CorpusWriter<W>,
) -> Result<u64, FetchFault> {
    if let Some(stray) = injections
        .iter()
        .find(|i| !heights.contains(&i.at.to_raw()))
    {
        return Err(FetchFault::InjectionOutOfRange { injection: *stray });
    }
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
            writer.append(&block.body.0, &txs)?;
            written += 1;
            for injection in injections.iter().filter(|i| i.at == at) {
                writer.inject(at, injection.credit)?;
            }
        }
        first = end;
    }
    Ok(written)
}
