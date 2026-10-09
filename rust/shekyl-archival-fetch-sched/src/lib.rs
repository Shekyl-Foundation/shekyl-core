// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The daemon's scheduler of `shekyl-p-fetch` (`ARCHIVAL_SHARD_FETCH.md`
//! `SF-D1`, `SF-D6`, `SF-D10`, `SF-D12`; `SHARD_VIEW_FETCH.md`).
//!
//! Every reason a daemon reads a shard body from a holder — a challenge it
//! must answer, an organic re-read, a test probe, a wallet's view — is one
//! [`FetchScheduler::read`]: a shard id, a sink, a budget. The request on
//! the wire carries no caller tag (`SF-D1`); the holder is drawn uniformly
//! from the shard's holders with no memory of earlier needs (`SF-D10`); a
//! failed dial moves as the client's taxonomy directs (`SF-D6`) and is
//! reported, never held against anyone (`SF-D12`).
//!
//! The view ([`ViewDesk`]) is the one caller with something to keep: the
//! aggregate a viewer renders, cached per closed shard and keyed on the
//! block that closed it (`SV-D4`, `SV-D5`).
//!
//! Linked only from `shekyl-daemon-image` (`SF-D4`; the dep-cut gate holds
//! it). What the scheduler reads — the skeleton and the holder set — comes
//! through two traits ([`ShardFacts`], [`HolderSource`]) whose production
//! implementation is the daemon's store adapter; the scheduler decides
//! nothing it could not decide against in-memory facts.
//!
//! A pass record is not built here. [`Read`] carries what one needs — the
//! header, the delivery digest, `P`'s signature — and the caller that
//! answers a challenge is the one that writes it.

mod draw;
mod facts;
mod read;
mod view;

pub use draw::DrawFault;
pub use facts::{
    BlockSpan, ClosedShard, FactsFault, Holder, HolderSource, ShardClose, ShardFacts, ShardStanding,
};
pub use read::{Attempt, FetchScheduler, NeedBudget, Read, ReadFailure};
pub use shekyl_p_fetch::{
    DiscardTxs, ExpectedShard, FetchError, FetchTarget, NextMove, PFetchClient, Timeouts, TxSink,
    VerifiedShard, VerifiedTx, MAX_INFLIGHT,
};
pub use view::{ShardView, ViewDesk, ViewRefusal};

/// Re-export so the daemon image cannot drop the in-flight pin by accident.
pub const OPERATOR_FETCH_MAX_INFLIGHT: usize = MAX_INFLIGHT;

pub const SHEKYL_DAEMON_SHARD_FETCH_OK: u8 = 0;
pub const SHEKYL_DAEMON_SHARD_FETCH_MISS: u8 = 1;

/// Packed aggregate for the C++ `request_archival_shard` shim. Field order
/// is the ABI; keep in lockstep with `ShekylArchivalShardAggregateOut` in
/// `shekyl_daemon_fetch.h`.
///
/// Leaves with its last C++ caller when `request_archival_shard` is served
/// natively in `shekyl-daemon-rpc` (`SHARD_VIEW_FETCH.md` §4, 2c). Until
/// then the shim's answer is a typed MISS: the C++ path has no facts
/// adapter and will not grow one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylArchivalShardAggregateOut {
    pub shard_id: u64,
    pub shard_hash: [u8; 32],
    pub block_count: u64,
    pub tx_count: u64,
    pub output_count: u64,
    pub coinbase_output_count: u64,
    pub time_range_seconds: u64,
}

/// The C++ shim's entry. Typed MISS: the view is served by [`ViewDesk`]
/// from the Rust RPC, not through this ABI. `out` is never written.
#[no_mangle]
pub extern "C" fn shekyl_daemon_operator_shard_fetch(
    _shard_id: u64,
    _out: *mut ShekylArchivalShardAggregateOut,
) -> u8 {
    SHEKYL_DAEMON_SHARD_FETCH_MISS
}

#[cfg(test)]
mod tests;
