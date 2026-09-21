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

use std::io::{Seek, Write};
use std::ops::Range;

use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{BinError, GetBlocksByHeightRequest, GetBlocksByHeightResponse, RpcStatus};

use crate::corpus::{CorpusFault, CorpusWriter};

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
}

/// Fetch `heights` in batches of `batch` and write them through `writer`,
/// which must be positioned at `heights.start`. Returns the records written.
///
/// # Errors
///
/// Any [`FetchFault`]; the writer is left at the height that failed, so a
/// caller can report exactly how far the corpus reached.
pub async fn fetch_corpus<R: Rpc, W: Write + Seek>(
    rpc: &R,
    heights: Range<u64>,
    batch: usize,
    writer: &mut CorpusWriter<W>,
) -> Result<u64, FetchFault> {
    assert!(batch > 0, "a batch of zero heights fetches nothing forever");
    let mut written = 0u64;
    let mut first = heights.start;
    while first < heights.end {
        let end = first.saturating_add(batch as u64).min(heights.end);
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
        for entry in reply.blocks {
            writer.append(&entry.block, &entry.txs)?;
            written += 1;
        }
        first = end;
    }
    Ok(written)
}
