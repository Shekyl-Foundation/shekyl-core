// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! One need: read one closed shard through [`PFetchClient::fetch`], moving
//! across holders as `SF-D6` directs.
//!
//! The shape every caller shares (`SF-D1`): a challenge the daemon must
//! answer, an organic re-read, a test probe, a wallet's view — each is a
//! [`FetchScheduler::read`] of a shard id with a sink, and nothing in the
//! request says which. The caller gets a [`Read`] (a verified body went
//! through its sink; here is the pass material) or a [`ReadFailure`] that
//! names why, with every attempt in it (`SF-D12`: a failed read is
//! observability, never a verdict about `P`).
//!
//! The moves within a need are the client's taxonomy applied
//! ([`FetchError::next_move`]):
//!
//! - a **stall** redials the same `P` with the same header, up to
//!   [`NeedBudget::stall_redials`] times — nothing was decided, and a fresh
//!   nonce would mint a pass record for an exchange that never happened;
//! - a first **rejection** redials the same `P` once with a header built
//!   from a freshly derived anchor; a second is a failed read;
//! - a **miss** or a **failed read** draws the next holder.
//!
//! The draw is the urn's ([`crate::draw`]): uniform over the shard's
//! holders, without replacement within this need, with no memory of any
//! other.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_p_fetch::{
    ExpectedShard, FetchError, NextMove, PFetchClient, RequestHeader, TxSink, VerifiedShard,
};
use shekyl_types::{ArchivalLength, BlockHeight, PCanonicalId, ShardId};

use crate::draw::{DrawFault, Urn};
use crate::facts::{
    ClosedShard, FactsFault, Holder, HolderSource, ShardClose, ShardFacts, ShardStanding,
};

/// How far one need goes before it gives up.
///
/// The defaults are derived from the pass timing the serve side was
/// provisioned at: a cold circuit's body read is bounded by
/// `Timeouts::DEFAULT` (10 min total), and a challenge's answer window is
/// counted in blocks. Three holders with one redial each is six dials at
/// most, which fits the window with the floor device's p99 body time; a
/// need that fails six dials is a shard nobody drawn could serve, and the
/// caller decides whether to open another need.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedBudget {
    /// Distinct holders tried before the need ends `Exhausted`.
    pub holders: NonZeroUsize,
    /// Redials of the same holder with the same header after a stall.
    /// `0` means a stall moves to the next holder at once.
    pub stall_redials: u32,
}

impl NeedBudget {
    /// Three holders, one redial each.
    pub const DEFAULT: Self = Self {
        holders: NonZeroUsize::new(3).expect("three is not zero"),
        stall_redials: 1,
    };
}

impl Default for NeedBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A completed read: the body went through the caller's sink one
/// transaction at a time, and this is what the requester keeps.
#[derive(Clone, Debug)]
pub struct Read {
    /// The verified shard: view hash, delivery digest, `P`'s signature.
    pub shard: VerifiedShard,
    /// Who served it.
    pub holder: PCanonicalId,
    /// The header `P` signed over — the pass record's anchor and nonce.
    pub header: RequestHeader,
    /// What the skeleton said closed the shard when the need opened. The
    /// view caller keys its cache on this.
    pub close: ShardClose,
}

/// One dial that did not end in a verified shard, kept so the caller can
/// log what happened to whom. Not evidence against the holder.
#[derive(Debug)]
pub struct Attempt {
    pub holder: PCanonicalId,
    pub error: FetchError,
}

/// Why a need ended without a shard.
#[derive(Debug, thiserror::Error)]
pub enum ReadFailure {
    /// The skeleton could not be read.
    #[error(transparent)]
    Facts(#[from] FactsFault),
    /// The draw could not be made.
    #[error(transparent)]
    Draw(#[from] DrawFault),
    /// The shard is not closed: `shard_id` is the tip shard
    /// (`shard_id == open_shard`) or past it. Nothing was dialled
    /// (`SV-D5`).
    #[error("shard {shard_id:?} is not closed (open shard {open_shard:?}, archival through tip {archival_through_tip:?})")]
    Open {
        shard_id: ShardId,
        open_shard: ShardId,
        archival_through_tip: ArchivalLength,
    },
    /// The chain is younger than the anchor depth: `tip − 720` does not
    /// exist yet, so no header can be minted.
    #[error("tip {tip:?} is shallower than the pass anchor depth")]
    NoAnchor { tip: BlockHeight },
    /// The skeleton says the shard is closed and no persona is bonded to
    /// it. Nothing was dialled.
    #[error("no holder is bonded to shard {shard_id:?}")]
    NoHolders { shard_id: ShardId },
    /// Every holder the budget allowed was tried.
    #[error("every drawn holder failed ({} attempts)", attempts.len())]
    Exhausted { attempts: Vec<Attempt> },
}

/// The daemon's one fetch scheduler.
///
/// Owns the one [`PFetchClient`] — and so the in-flight cap
/// ([`shekyl_p_fetch::MAX_INFLIGHT`]) every caller shares — and the two
/// facts seams. Cheap to share behind an `Arc`.
pub struct FetchScheduler<F, H> {
    facts: Arc<F>,
    holders: Arc<H>,
    client: PFetchClient,
}

impl<F: ShardFacts, H: HolderSource> FetchScheduler<F, H> {
    /// A scheduler over the daemon's facts, dialling through `client`.
    pub fn new(facts: Arc<F>, holders: Arc<H>, client: PFetchClient) -> Self {
        Self {
            facts,
            holders,
            client,
        }
    }

    /// The skeleton this scheduler reads.
    pub fn facts(&self) -> &F {
        &self.facts
    }

    /// Fetch slots not currently in use (`MAX_INFLIGHT` minus in-flight).
    pub fn available_slots(&self) -> usize {
        self.client.available_slots()
    }

    /// Read shard `shard_id` through `sink`, drawing holders.
    ///
    /// # Errors
    ///
    /// [`ReadFailure`]: the shard is not closed, the skeleton or the draw
    /// could not be read, no holder is bonded, or every holder the budget
    /// allowed failed.
    pub async fn read(
        &self,
        shard_id: ShardId,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
    ) -> Result<Read, ReadFailure> {
        let closed = self.closed(shard_id)?;
        let holders = self.holders.holders_of(shard_id)?;
        if holders.is_empty() {
            return Err(ReadFailure::NoHolders { shard_id });
        }
        let mut urn = Urn::new(holders);
        let mut attempts = Vec::new();
        let mut tried = 0usize;
        while tried < budget.holders.get() {
            let Some(holder) = urn.draw()? else { break };
            tried += 1;
            match self
                .attempt(&holder, &closed.expected, Arc::clone(&sink), budget)
                .await?
            {
                Ok((shard, header)) => {
                    return Ok(Read {
                        shard,
                        holder: holder.id,
                        header,
                        close: closed.close,
                    });
                }
                Err(errors) => attempts.extend(errors),
            }
        }
        Err(ReadFailure::Exhausted { attempts })
    }

    /// Read shard `shard_id` from an assigned holder first — a challenge's
    /// named `P` — drawing others only if it fails. The assigned holder is
    /// not drawn again.
    ///
    /// # Errors
    ///
    /// As [`Self::read`].
    pub async fn read_from(
        &self,
        assigned: &Holder,
        shard_id: ShardId,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
    ) -> Result<Read, ReadFailure> {
        let closed = self.closed(shard_id)?;
        let mut urn = Urn::new(self.holders.holders_of(shard_id)?);
        urn.exclude(assigned.id);
        let mut attempts = Vec::new();
        let mut tried = 0usize;
        let mut next = Some(assigned.clone());
        while let Some(holder) = next.take() {
            tried += 1;
            match self
                .attempt(&holder, &closed.expected, Arc::clone(&sink), budget)
                .await?
            {
                Ok((shard, header)) => {
                    return Ok(Read {
                        shard,
                        holder: holder.id,
                        header,
                        close: closed.close,
                    });
                }
                Err(errors) => attempts.extend(errors),
            }
            if tried < budget.holders.get() {
                next = urn.draw()?;
            }
        }
        Err(ReadFailure::Exhausted { attempts })
    }

    fn closed(&self, shard_id: ShardId) -> Result<ClosedShard, ReadFailure> {
        match self.facts.shard(shard_id)? {
            ShardStanding::Closed(closed) => Ok(*closed),
            ShardStanding::Open {
                open_shard,
                archival_through_tip,
            } => Err(ReadFailure::Open {
                shard_id,
                open_shard,
                archival_through_tip,
            }),
        }
    }

    /// A header over the requester's current anchor: the hash at
    /// `tip − PASS_ANCHOR_DEPTH_BLOCKS`, one fresh nonce.
    fn fresh_header(&self) -> Result<RequestHeader, ReadFailure> {
        let tip = self.facts.tip_height()?;
        let anchor = tip
            .checked_sub_count(PASS_ANCHOR_DEPTH_BLOCKS)
            .ok_or(ReadFailure::NoAnchor { tip })?;
        let hash = self
            .facts
            .block_hash_at(anchor)?
            .ok_or(FactsFault::Inconsistent)?;
        RequestHeader::fresh(anchor, hash.to_bytes()).map_err(|_| DrawFault::Entropy.into())
    }

    /// Every dial of one holder within this need. `Ok(Ok(..))` is a
    /// verified shard; `Ok(Err(errors))` is this holder done with, errors
    /// in dial order; `Err` is a fault of the requester's own (facts,
    /// entropy) that ends the need.
    async fn attempt(
        &self,
        holder: &Holder,
        expected: &ExpectedShard,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
    ) -> Result<Result<(VerifiedShard, RequestHeader), Vec<Attempt>>, ReadFailure> {
        let mut header = self.fresh_header()?;
        let mut stalls = 0u32;
        let mut rejected_before = false;
        let mut errors = Vec::new();
        loop {
            let error = match self
                .client
                .fetch(&holder.target, &header, expected, Arc::clone(&sink))
                .await
            {
                Ok(shard) => return Ok(Ok((shard, header))),
                Err(error) => error,
            };
            let next = error.next_move(rejected_before);
            errors.push(Attempt {
                holder: holder.id,
                error,
            });
            match next {
                NextMove::RetrySameHeader if stalls < budget.stall_redials => stalls += 1,
                NextMove::RetryFreshAnchor => {
                    rejected_before = true;
                    header = self.fresh_header()?;
                }
                NextMove::RetrySameHeader | NextMove::NotHeld | NextMove::FailedRead => {
                    return Ok(Err(errors));
                }
            }
        }
    }
}
