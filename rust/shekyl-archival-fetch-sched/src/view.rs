// Copyright (c) 2025-2026, The Shekyl Foundation
// SPDX-License-Identifier: BSD-3-Clause

//! The shard view (`SHARD_VIEW_FETCH.md`): a wallet asks its daemon for a
//! shard by id; the daemon reads the body from a holder through the same
//! [`FetchScheduler::read`] every other caller uses (`SF-D1`), folds the
//! view hash over what streamed, and answers with the aggregate the
//! viewer renders.
//!
//! What the view adds to a read is small and all of it is here:
//!
//! - **the aggregate** ([`ShardView`], `SV-D4`) — the body's transaction
//!   count and view hash from the verified stream, the span's block count,
//!   output counts and time range from the skeleton;
//! - **the cache** (`SV-D5`) — one closed shard's view is a pure function
//!   of its body and its span, so it is computed once per close and kept,
//!   keyed on the hash of the block that closed it; a reorg past that
//!   height changes the hash and the entry is dropped and re-fetched;
//! - **the refusals** — an open shard is a typed answer, never a fetch
//!   ([`ViewRefusal::Open`]); a shard nobody could serve is a typed answer
//!   with the attempts behind it ([`ViewRefusal::Unavailable`]), never an
//!   empty picture (`SV-D2`: the skeleton alone is not a view).
//!
//! A view fetch is a real fetch — the point of the surface is that it
//! generates shard-fetch traffic — so the body streams through a
//! discarding sink and the only things kept are the aggregate's fields.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use shekyl_p_fetch::DiscardTxs;
use shekyl_types::{ArchivalLength, BlockHash, ShardId, ShardView};

use crate::facts::{BlockSpan, FactsFault, HolderSource, ShardFacts, ShardStanding};
use crate::read::{Attempt, FetchScheduler, NeedBudget, Read, ReadFailure};

/// The scheduler fills [`ShardView`] (`shekyl-types`) from a read and the
/// span; the type lives beside the ids it is keyed on so the RPC crate on
/// the far side of the fetch-client dep cut shares it rather than copying it.
fn assemble(read: &Read, span: &BlockSpan) -> ShardView {
    ShardView {
        shard_id: read.shard.shard_id(),
        shard_hash: read.shard.view_hash(),
        archival_len: read.shard.archival_len(),
        block_count: span.block_count(),
        tx_count: read.shard.tx_count(),
        output_count: span.tx_outputs.saturating_add(span.coinbase_outputs),
        coinbase_output_count: span.coinbase_outputs,
        time_range_seconds: span.time_range_seconds(),
        close_height: read.close.height,
    }
}

/// Why a view was not produced. Each is a state the viewer shows, never a
/// blank.
#[derive(Debug, thiserror::Error)]
pub enum ViewRefusal {
    /// The shard is still filling (`shard_id == open_shard`) or does not
    /// exist yet (`shard_id > open_shard`). `remaining_to_close` is how many
    /// archival bytes the tip shard still needs; `None` for an id past it.
    #[error("shard {shard_id:?} is not closed")]
    Open {
        shard_id: ShardId,
        open_shard: ShardId,
        remaining_to_close: Option<ArchivalLength>,
    },
    /// The shard is closed and no holder served it this time: nobody is
    /// bonded, or every drawn holder failed. The attempts are the
    /// observability (`SF-D12`); the viewer says "could not be retrieved".
    #[error("shard {shard_id:?} could not be retrieved")]
    Unavailable {
        shard_id: ShardId,
        attempts: Vec<Attempt>,
    },
    /// The requester's own state could not serve the request: the skeleton
    /// could not be read, the chain is younger than the anchor depth, no
    /// entropy. This daemon's fault, not the shard's.
    #[error("the daemon could not form the request: {0}")]
    Local(#[source] ReadFailure),
}

/// A view kept for a closed shard, and what it was keyed on.
#[derive(Clone, Copy, Debug)]
struct Cached {
    view: ShardView,
    close_hash: BlockHash,
}

/// The view desk: the cache in front of the scheduler.
pub struct ViewDesk<F, H> {
    scheduler: Arc<FetchScheduler<F, H>>,
    budget: NeedBudget,
    cache: Mutex<HashMap<ShardId, Cached>>,
    /// One gate per shard with a view in progress, so two viewers asking
    /// for the same shard at once cost one fetch: the second waits on the
    /// first and then reads the cache.
    in_progress: Mutex<HashMap<ShardId, Arc<tokio::sync::Mutex<()>>>>,
}

impl<F: ShardFacts, H: HolderSource> ViewDesk<F, H> {
    /// A desk over `scheduler`, opening each view's need with `budget`.
    pub fn new(scheduler: Arc<FetchScheduler<F, H>>, budget: NeedBudget) -> Self {
        Self {
            scheduler,
            budget,
            cache: Mutex::new(HashMap::new()),
            in_progress: Mutex::new(HashMap::new()),
        }
    }

    /// The scheduler behind this desk.
    pub fn scheduler(&self) -> &FetchScheduler<F, H> {
        &self.scheduler
    }

    /// The view of shard `shard_id`: from the cache when the block that
    /// closed it still has the hash it had, otherwise through a fresh read.
    /// Concurrent calls for one shard share one read.
    ///
    /// # Errors
    ///
    /// [`ViewRefusal`]: the shard is open, could not be retrieved, or the
    /// daemon could not form the request.
    pub async fn view(&self, shard_id: ShardId) -> Result<ShardView, ViewRefusal> {
        let gate = Arc::clone(
            self.in_progress
                .lock()
                .expect("in-progress lock")
                .entry(shard_id)
                .or_default(),
        );
        let result = {
            let _held = gate.lock().await;
            self.view_uncontended(shard_id).await
        };
        let mut in_progress = self.in_progress.lock().expect("in-progress lock");
        // Only this call holds the gate: nobody is waiting behind it.
        if Arc::strong_count(&gate) == 2 {
            in_progress.remove(&shard_id);
        }
        result
    }

    async fn view_uncontended(&self, shard_id: ShardId) -> Result<ShardView, ViewRefusal> {
        let facts = self.scheduler.facts();
        let span = match facts.shard(shard_id).map_err(local)? {
            ShardStanding::Closed(closed) => {
                if let Some(view) = self.cached(shard_id, closed.close.hash) {
                    return Ok(view);
                }
                closed.span
            }
            ShardStanding::Open {
                open_shard,
                archival_through_tip,
            } => {
                return Err(open_refusal(shard_id, open_shard, archival_through_tip));
            }
        };
        let read = match self
            .scheduler
            .read(shard_id, Arc::new(DiscardTxs), self.budget)
            .await
        {
            Ok(read) => read,
            Err(ReadFailure::Exhausted { attempts }) => {
                return Err(ViewRefusal::Unavailable { shard_id, attempts });
            }
            Err(ReadFailure::NoHolders { .. }) => {
                return Err(ViewRefusal::Unavailable {
                    shard_id,
                    attempts: Vec::new(),
                });
            }
            Err(ReadFailure::Open {
                shard_id,
                open_shard,
                archival_through_tip,
            }) => return Err(open_refusal(shard_id, open_shard, archival_through_tip)),
            Err(other) => return Err(ViewRefusal::Local(other)),
        };
        let view = assemble(&read, &span);
        self.cache.lock().expect("view cache lock").insert(
            shard_id,
            Cached {
                view,
                close_hash: read.close.hash,
            },
        );
        Ok(view)
    }

    /// The cached view of `shard_id` if its close hash is still
    /// `close_hash`; otherwise drop the stale entry and return `None`.
    fn cached(&self, shard_id: ShardId, close_hash: BlockHash) -> Option<ShardView> {
        let mut cache = self.cache.lock().expect("view cache lock");
        match cache.get(&shard_id) {
            Some(entry) if entry.close_hash == close_hash => Some(entry.view),
            Some(_) => {
                cache.remove(&shard_id);
                None
            }
            None => None,
        }
    }

    /// Views kept. For tests and the daemon's status line.
    pub fn cached_count(&self) -> usize {
        self.cache.lock().expect("view cache lock").len()
    }
}

fn local(fault: FactsFault) -> ViewRefusal {
    ViewRefusal::Local(ReadFailure::Facts(fault))
}

fn open_refusal(
    shard_id: ShardId,
    open_shard: ShardId,
    archival_through_tip: ArchivalLength,
) -> ViewRefusal {
    let remaining_to_close = (shard_id == open_shard).then(|| {
        let next = ShardId::from_raw(shard_id.to_raw().saturating_add(1));
        shekyl_types::shard_start(next)
            .map(|start| {
                ArchivalLength::from_raw(
                    start.to_raw().saturating_sub(archival_through_tip.to_raw()),
                )
            })
            .unwrap_or(ArchivalLength::ZERO)
    });
    ViewRefusal::Open {
        shard_id,
        open_shard,
        remaining_to_close,
    }
}
