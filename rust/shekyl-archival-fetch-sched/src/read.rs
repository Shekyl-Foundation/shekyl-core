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
//!   [`NeedBudget::stall_redials`] times across this need's attempts
//!   against that `P` — nothing was decided, and a fresh nonce would mint
//!   a pass record for an exchange that never happened;
//! - a first **rejection** redials the same `P` once with a header built
//!   from a freshly derived anchor; a second is a failed read;
//! - a **miss** or a **failed read** draws the next holder.
//!
//! The draw is the urn's ([`crate::draw`]): uniform over the shard's
//! holders, without replacement within this need, with no memory of any
//! other.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_archival_retention::{challenge_nonce, CHALLENGE_READS, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_p_fetch::{
    ExpectedShard, FetchError, NextMove, PFetchClient, RequestHeader, TxSink, VerifiedShard,
};
use shekyl_types::{ArchivalLength, BlockHeight, PCanonicalId, ShardId};

use crate::draw::{DrawFault, Urn};
use crate::facts::{
    BlockSpan, ClosedShard, FactsFault, Holder, HolderSource, ShardClose, ShardFacts, ShardStanding,
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
    ///
    /// Counted **per holder within the need**, not per header: a first
    /// 400 earns a fresh anchor and a new circuit, and a stall on that
    /// circuit draws on the same budget the stalls before the 400 did.
    /// The budget is what one `P` may cost the requester — `SF-D6`'s
    /// "2 retries (three attempts)" is sized so that a `P` which
    /// truncates every attempt holds a witness for three reads, not
    /// `CHALLENGE_RESPONSE_BLOCKS` — and a `P` that can reset it by
    /// answering 400 between stalls has doubled it.
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
    /// Where the skeleton placed the shard's transactions when the need
    /// opened — the same snapshot as `close` and as the rows the body was
    /// verified against. A view is assembled from this and the body, never
    /// from a second read of the skeleton: a reorg between two reads would
    /// pair one standing's span with another's body and hash.
    pub span: BlockSpan,
}

/// One dial that did not end in a verified shard, kept so the caller can
/// log what happened to whom. Not evidence against the holder.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub holder: PCanonicalId,
    pub error: FetchError,
}

/// Why a need ended without a shard.
#[derive(Clone, Debug, thiserror::Error)]
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

/// A nonce names one persona. [`FetchScheduler::read_from_nonce`] dials
/// that holder and no other, whatever holder count the caller passed.
const CHALLENGE_HOLDERS: NonZeroUsize = NonZeroUsize::MIN;

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
        self.drive(shard_id, sink, budget, None, None).await
    }

    /// Read shard `shard_id` from an assigned holder first — a challenge's
    /// named `P` — drawing others only if it fails. The assigned holder is
    /// not drawn again. An empty drawable set still dials the assigned
    /// holder: the challenge named it, and the urn being empty is not
    /// [`ReadFailure::NoHolders`].
    ///
    /// # Errors
    ///
    /// As [`Self::read`], except [`ReadFailure::NoHolders`], which a drawn
    /// read returns when the urn starts empty and this one does not.
    pub async fn read_from(
        &self,
        assigned: &Holder,
        shard_id: ShardId,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
    ) -> Result<Read, ReadFailure> {
        self.drive(shard_id, sink, budget, Some(assigned), None)
            .await
    }

    /// As [`Self::read_from`], with the caller's nonce on every header of
    /// this need — a challenge's derived nonce, or any other caller that
    /// already minted one. A 400 retry derives a fresh anchor and keeps
    /// it (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.2).
    ///
    /// A nonce is bound to one persona, so this dials only `assigned`.
    /// `budget.holders` is not an input: a second holder would see a nonce
    /// the draw did not name for them. Stall redials stay the caller's,
    /// on that one holder.
    ///
    /// # Errors
    ///
    /// As [`Self::read_from`].
    pub async fn read_from_nonce(
        &self,
        assigned: &Holder,
        shard_id: ShardId,
        nonce: [u8; 32],
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
    ) -> Result<Read, ReadFailure> {
        let one_holder = NeedBudget {
            holders: CHALLENGE_HOLDERS,
            stall_redials: budget.stall_redials,
        };
        self.drive(shard_id, sink, one_holder, Some(assigned), Some(nonce))
            .await
    }

    /// The one need. `assigned` is dialled first and removed from the urn
    /// when the caller named a holder; otherwise the urn is drawn from the
    /// start, and an empty urn is [`ReadFailure::NoHolders`] before any
    /// dial. The stall budget is the attempt's, counted per holder across
    /// a fresh anchor — this loop does not reset it.
    async fn drive(
        &self,
        shard_id: ShardId,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
        assigned: Option<&Holder>,
        nonce: Option<[u8; 32]>,
    ) -> Result<Read, ReadFailure> {
        let closed = self.closed(shard_id)?;
        let holders = self.holders.holders_of(shard_id)?;
        if assigned.is_none() && holders.is_empty() {
            return Err(ReadFailure::NoHolders { shard_id });
        }
        let mut urn = Urn::new(holders);
        if let Some(assigned) = assigned {
            urn.exclude(assigned.id);
        }
        let mut attempts = Vec::new();
        let mut tried = 0usize;
        // Dialled before the urn, then cleared so every later holder is drawn.
        let mut first = assigned.cloned();
        while tried < budget.holders.get() {
            let holder = if let Some(holder) = first.take() {
                holder
            } else {
                match urn.draw()? {
                    Some(holder) => holder,
                    None => break,
                }
            };
            tried += 1;
            match self
                .attempt(&holder, &closed.expected, Arc::clone(&sink), budget, nonce)
                .await?
            {
                HolderOutcome::Served(shard, header) => {
                    return Ok(Read {
                        shard,
                        holder: holder.id,
                        header,
                        close: closed.close,
                        span: closed.span,
                    });
                }
                HolderOutcome::Spent(errors) => attempts.extend(errors),
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
    /// `tip − PASS_ANCHOR_DEPTH_BLOCKS`. `nonce` is the caller's when
    /// supplied (a challenge, a 400 retry); otherwise a fresh OS-random
    /// one.
    fn fresh_header(&self, nonce: Option<[u8; 32]>) -> Result<RequestHeader, ReadFailure> {
        let tip = self.facts.tip_height()?;
        let anchor = tip
            .checked_sub_count(PASS_ANCHOR_DEPTH_BLOCKS)
            .ok_or(ReadFailure::NoAnchor { tip })?;
        let hash = self
            .facts
            .block_hash_at(anchor)?
            .ok_or(FactsFault::Inconsistent)?;
        match nonce {
            Some(nonce) => Ok(RequestHeader::with_nonce(nonce, anchor, hash.to_bytes())),
            None => {
                RequestHeader::fresh(anchor, hash.to_bytes()).map_err(|_| DrawFault::Entropy.into())
            }
        }
    }

    /// Every dial of one holder within this need.
    /// [`HolderOutcome::Served`] is a verified shard;
    /// [`HolderOutcome::Spent`] is this holder done with, errors in dial
    /// order. `Err` is a fault of the requester's own (facts, entropy)
    /// that ends the need — a different type from a spent holder, so `?`
    /// cannot turn one into the other.
    async fn attempt(
        &self,
        holder: &Holder,
        expected: &ExpectedShard,
        sink: Arc<dyn TxSink>,
        budget: NeedBudget,
        nonce: Option<[u8; 32]>,
    ) -> Result<HolderOutcome, ReadFailure> {
        let mut header = self.fresh_header(nonce)?;
        let mut stalls = 0u32;
        let mut rejected_before = false;
        let mut errors = Vec::new();
        loop {
            let error = match self
                .client
                .fetch(&holder.target, &header, expected, Arc::clone(&sink))
                .await
            {
                Ok(shard) => return Ok(HolderOutcome::Served(shard, header)),
                Err(error) => error,
            };
            let next = error.next_move(rejected_before);
            errors.push(Attempt {
                holder: holder.id,
                error,
            });
            match next {
                // The stall count is this holder's across the need, including
                // stalls from before a 400 minted a fresh header. Resetting
                // it there would let one `P` double what it may cost.
                NextMove::RetrySameHeader if stalls < budget.stall_redials => stalls += 1,
                NextMove::RetryFreshAnchor => {
                    rejected_before = true;
                    // Fresh anchor, same nonce: a 400 minted no record, and
                    // a challenge's nonce is bound to `(h, j, attempt)`.
                    header = self.fresh_header(Some(*header.nonce()))?;
                }
                NextMove::RetrySameHeader | NextMove::NotHeld | NextMove::FailedRead => {
                    return Ok(HolderOutcome::Spent(errors));
                }
            }
        }
    }
}

/// One draw's read: the seed, the issuing block's hash, `j`, and this
/// read's `attempt`. The nonce is derived; nothing else on the request
/// is the challenger's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeDraw {
    /// The block's unrevealed draw seed.
    pub seed: [u8; 32],
    /// `block_hash(h)` of the issuing block.
    pub block_hash: [u8; 32],
    /// Draw index `j` at `h`.
    pub draw: u32,
    /// This read of the draw, from 0. Admission refuses `≥ K`.
    pub attempt: u8,
}

impl ChallengeDraw {
    /// The nonce this read presents. Bound to `(seed, block_hash, j,
    /// attempt)` so one receipt cannot serve two draws.
    #[must_use]
    pub fn nonce(&self) -> [u8; 32] {
        challenge_nonce(&self.seed, &self.block_hash, self.draw, self.attempt)
    }
}

/// Why [`challenge_read`] did not produce a [`Read`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum ChallengeReadError {
    /// `attempt ≥ K`. Admission would refuse the record; the challenger
    /// does not dial.
    #[error("challenge attempt {attempt} is at or past K = {bound}")]
    AttemptBound { attempt: u8, bound: u8 },
    /// The need failed as any other read does.
    #[error(transparent)]
    Read(#[from] ReadFailure),
}

/// One challenge read: derive the nonce for `draw` and
/// [`FetchScheduler::read_from_nonce`] the assigned holder.
///
/// The request on the wire is an ordinary read. What is the challenger's
/// own is the nonce and the named `P` (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
/// §5.1). [`FetchScheduler::read_from_nonce`] dials only that persona,
/// so the caller's holder count is not used. Stall redials, and the 400
/// retry that keeps the nonce, stay on that one holder (§5.2–§5.3).
///
/// # Errors
///
/// [`ChallengeReadError::AttemptBound`] when `attempt ≥ K`; otherwise a
/// [`ReadFailure`].
pub async fn challenge_read<F: ShardFacts, H: HolderSource>(
    scheduler: &FetchScheduler<F, H>,
    assigned: &Holder,
    shard_id: ShardId,
    draw: ChallengeDraw,
    sink: Arc<dyn TxSink>,
    budget: NeedBudget,
) -> Result<Read, ChallengeReadError> {
    if draw.attempt >= CHALLENGE_READS {
        return Err(ChallengeReadError::AttemptBound {
            attempt: draw.attempt,
            bound: CHALLENGE_READS,
        });
    }
    Ok(scheduler
        .read_from_nonce(assigned, shard_id, draw.nonce(), sink, budget)
        .await?)
}

/// What one holder's dials came to. Not a [`ReadFailure`]: a spent holder
/// moves the need on, and a requester fault ends it.
enum HolderOutcome {
    /// The body verified. The header is the one `P` signed over.
    Served(VerifiedShard, RequestHeader),
    /// This holder is done with. The attempts are in dial order.
    Spent(Vec<Attempt>),
}
