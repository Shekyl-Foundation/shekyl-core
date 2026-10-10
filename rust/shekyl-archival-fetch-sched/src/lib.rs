// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The daemon's scheduler of `shekyl-p-fetch` (`ARCHIVAL_SHARD_FETCH.md`
//! `SF-D1`, `SF-D6`, `SF-D10`, `SF-D12`; `SHARD_VIEW_FETCH.md`).
//!
//! Every reason a daemon reads a shard body from a holder — a challenge it
//! must answer, an organic re-read, a test probe, a wallet's view — is one
//! [`FetchScheduler::read`] (or [`challenge_read`], which is `read_from`
//! with a derived nonce): a shard id, a sink, a budget. The request on
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
//! implementation is the daemon image's store adapter
//! (`shekyl-daemon-image::shard_view`, `SHARD_VIEW_FETCH.md` `SV-D9`).
//! The scheduler decides nothing it could not decide against in-memory
//! facts. The running daemon still opens LMDB, so `ServerConfig` keeps
//! `SkeletonAbsent` until the `DRS-E3` cutover selects the adapter.
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
pub use read::{
    challenge_read, Attempt, ChallengeDraw, ChallengeReadError, FetchScheduler, NeedBudget, Read,
    ReadFailure,
};
pub use shekyl_p_fetch::{
    DiscardTxs, ExpectedShard, FetchError, FetchTarget, NextMove, PFetchClient, RequestHeader,
    Timeouts, TxSink, VerifiedShard, VerifiedTx, MAX_INFLIGHT,
};
pub use shekyl_types::ShardView;
pub use view::{ViewDesk, ViewRefusal};

#[cfg(test)]
mod tests;
