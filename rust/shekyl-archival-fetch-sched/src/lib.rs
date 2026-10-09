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
//! nothing it could not decide against in-memory facts. **That adapter
//! does not exist yet** (`SHARD_VIEW_FETCH.md` `SV-D9`): the daemon runs
//! on a store with no shard-range read and no bond-record read, so the
//! daemon image composes no [`ViewDesk`] and `request_archival_shard`
//! answers that the skeleton is absent. The image is the named consumer;
//! the `DRS-E3` cutover is what lifts the block.
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
pub use shekyl_types::ShardView;
pub use view::{ViewDesk, ViewRefusal};

#[cfg(test)]
mod tests;
