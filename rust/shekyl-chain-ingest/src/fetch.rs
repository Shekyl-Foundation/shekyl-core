// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Building a corpus from a daemon: `/get_blocks_by_height.bin` against an
//! **unpruned** node, zero C++ (RD-Q2, §3.4).
//!
//! The fetcher asks for heights in batches through the workspace's
//! [`Rpc`] trait — the same shared request/response types the daemon
//! serves (`shekyl_rpc_types::bin_commands`), so this is not a second
//! definition of the wire — and hands each `(block, txs)` to the
//! [`CorpusWriter`], whose verification is the whole of RD-F15: a pruned
//! node returns fewer bodies than the header lists with no signal, and it
//! is the writer, not this module, that catches that and names the height.
//! This module's own refusals are about the conversation, not the content:
//! a non-OK status, a reply with the wrong number of entries.
//!
//! Generic over `Rpc` so the loop is tested against a scripted transport;
//! the binary supplies `shekyl_rpc_transport::HttpRpc`.
//!
//! **Injections** (DRS-E4 §3.8 item 3). A regtest daemon's state can carry
//! one row no block produced — a serve credit the injector wrote at the
//! tip of the moment — and `/get_blocks_by_height.bin` cannot see it. The
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

use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{BinError, GetBlocksByHeightRequest, GetBlocksByHeightResponse, RpcStatus};
use shekyl_types::BlockHeight;

use crate::corpus::{CorpusFault, CorpusWriter};
use crate::source::Injection;

/// The daemon route, as the wallet's client already spells it.
pub const ROUTE: &str = "get_blocks_by_height.bin";

/// Why the corpus could not be fetched.
#[derive(Debug, thiserror::Error)]
pub enum FetchFault {
    /// The transport failed.
    #[error("rpc: {0}")]
    Rpc(#[from] RpcError),
    /// The reply was not the message the route promises.
    #[error("reply is not a get_blocks_by_height.bin response: {0}")]
    Bin(#[from] BinError),
    /// The daemon answered with a status other than OK.
    #[error("daemon refused heights {first}..{end}: status {status:?}")]
    Refused {
        /// First height of the refused batch.
        first: u64,
        /// One past the last.
        end: u64,
        /// The status the daemon returned.
        status: RpcStatus,
    },
    /// The reply carried a different number of entries than requested.
    #[error("asked for {asked} heights from {first}, got {got} entries")]
    CountMismatch {
        /// First height of the batch.
        first: u64,
        /// Heights requested.
        asked: usize,
        /// Entries returned.
        got: usize,
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
        let body = GetBlocksByHeightRequest {
            heights: asked.clone(),
        }
        .to_bin()?;
        let reply = rpc.bin_call(ROUTE, body).await?;
        let reply = GetBlocksByHeightResponse::from_bin(&reply)?;
        if !reply.status.is_ok() {
            return Err(FetchFault::Refused {
                first,
                end,
                status: reply.status,
            });
        }
        if reply.blocks.len() != asked.len() {
            return Err(FetchFault::CountMismatch {
                first,
                asked: asked.len(),
                got: reply.blocks.len(),
            });
        }
        for (height, entry) in asked.iter().zip(reply.blocks) {
            writer.append(&entry.block, &entry.txs)?;
            written += 1;
            let at = BlockHeight::from_raw(*height);
            for injection in injections.iter().filter(|i| i.at == at) {
                writer.inject(at, injection.credit)?;
            }
        }
        first = end;
    }
    Ok(written)
}
