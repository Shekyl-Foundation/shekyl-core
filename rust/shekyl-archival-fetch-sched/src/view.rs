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
//!   height changes the hash and the entry is dropped and re-fetched.
//!   A refusal is not cached: it is true of this attempt, not of the shard;
//! - **the refusals** — an open shard is a typed answer, never a fetch
//!   ([`ViewRefusal::Open`]); a shard nobody could serve is a typed answer
//!   with the attempts behind it ([`ViewRefusal::Unavailable`]), never an
//!   empty picture (`SV-D2`: the skeleton alone is not a view).
//!
//! Two callers of one shard share one flight. The leader publishes the
//! outcome, view or refusal, and every waiter takes that outcome. When
//! the leader drops — it finished, or its read was cancelled — the flight
//! leaves the map. A refusal leaves with it.
//!
//! **What a flight may cost** (`INPUT_GRAMMAR.md` IG-Q90). A bounded
//! caller that would open a flight takes the desk's one bounded permit; a
//! cached view and a flight already in the air take none. While the
//! permit is out, a bounded caller that would open another is refused
//! ([`ViewRefusal::Busy`]) and nothing is queued; that refusal is the
//! caller's, so it is never published to a flight's waiters. The host
//! takes no permit. Every flight then takes one of the desk's
//! [`VIEW_SLOTS`] lane slots before it reads, so views never hold more of
//! the fetch client than that: the client is sized to the bundle
//! producer's reads plus this lane, and a producer read never waits
//! behind a view.
//!
//! A view fetch is a real fetch — the point of the surface is that it
//! generates shard-fetch traffic — so the body streams through a
//! discarding sink and the only things kept are the aggregate's fields.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use shekyl_p_fetch::DiscardTxs;
use shekyl_types::{ArchivalLength, BlockHash, ShardId, ShardView};
use tokio::sync::{watch, Semaphore};

use crate::facts::{FactsFault, HolderSource, ShardFacts, ShardStanding};
use crate::read::{Attempt, FetchScheduler, NeedBudget, Read, ReadFailure};

/// The scheduler fills [`ShardView`] (`shekyl-types`) from one read: the
/// body's figures and the span the read's own skeleton snapshot placed the
/// shard in ([`Read::span`]), so every field describes one standing of the
/// chain. The type lives beside the ids it is keyed on so the RPC crate on
/// the far side of the fetch-client dep cut shares it rather than copying it.
fn assemble(read: &Read) -> ShardView {
    let span = &read.span;
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

/// The fetch client's slots the shard view's flights may hold at once,
/// the host's and the bounded caller's together: one for the bounded
/// permit's flight and one the host's flight takes beside it, so the host
/// does not wait behind a stranger. The node sizes its client to the
/// producer's reads plus these.
pub const VIEW_SLOTS: NonZeroUsize = match NonZeroUsize::new(2) {
    Some(slots) => slots,
    None => panic!("the view lane has a slot"),
};

/// Who asks for a view (`RPC_CHANNEL.md` §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewCaller {
    /// The host's administrator: no permit.
    Host,
    /// A bounded connection: a flight it opens takes the bounded permit.
    Bounded,
}

/// Why a view was not produced. Each is a state the viewer shows, never a
/// blank.
#[derive(Clone, Debug, thiserror::Error)]
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
    /// A bounded caller would open a flight while another bounded
    /// caller's holds the permit. Nothing was fetched or queued; a cached
    /// view or a flight in the air would have answered.
    #[error("another bounded caller's view of a shard is being fetched")]
    Busy { shard_id: ShardId },
}

/// A view kept for a closed shard, and what it was keyed on.
#[derive(Clone, Copy, Debug)]
struct Cached {
    view: ShardView,
    close_hash: BlockHash,
}

/// One view computation for a shard, shared by every caller that arrives
/// while it runs. The outcome is published once — a view or a refusal —
/// and the flight is forgotten when the leader drops, so a refusal is not
/// kept and a cancelled leader does not leave the shard occupied.
struct Flight {
    outcome: watch::Sender<Option<SharedView>>,
}

/// The leader's permit. Dropping it without [`Leader::publish`] removes
/// the flight, which drops the sender; waiters see the close and one of
/// them may lead the next flight.
struct Leader {
    shard_id: ShardId,
    flight: Arc<Flight>,
    flights: Arc<Mutex<HashMap<ShardId, Arc<Flight>>>>,
}

impl Leader {
    fn publish(&self, shared: SharedView) {
        // A late subscriber still reads the last value after the sender
        // drops with the leader, so publishing before the flight is removed
        // is the whole hand-off. `Err` means every waiter has gone; the
        // leader still returns the outcome itself.
        let _published = self.flight.outcome.send(Some(shared));
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        let mut flights = self.flights.lock().expect("view flight lock");
        if flights
            .get(&self.shard_id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            flights.remove(&self.shard_id);
        }
    }
}

type SharedView = Arc<Result<ShardView, ViewRefusal>>;

/// The view desk: the cache in front of the scheduler, and one flight per
/// shard currently being read.
pub struct ViewDesk<F, H> {
    scheduler: Arc<FetchScheduler<F, H>>,
    budget: NeedBudget,
    /// The bounded callers' one flight (IG-Q90).
    bounded: Semaphore,
    /// The fetch client's slots every view flight holds one of
    /// ([`VIEW_SLOTS`]).
    lane: Semaphore,
    cache: Mutex<HashMap<ShardId, Cached>>,
    /// Flights in progress, shared with each [`Leader`] so a cancelled
    /// read removes its own entry and no other shard's.
    flights: Arc<Mutex<HashMap<ShardId, Arc<Flight>>>>,
}

impl<F: ShardFacts, H: HolderSource> ViewDesk<F, H> {
    /// A desk over `scheduler`, opening each view's need with `budget`.
    pub fn new(scheduler: Arc<FetchScheduler<F, H>>, budget: NeedBudget) -> Self {
        Self {
            scheduler,
            budget,
            bounded: Semaphore::new(1),
            lane: Semaphore::new(VIEW_SLOTS.get()),
            cache: Mutex::new(HashMap::new()),
            flights: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The scheduler behind this desk.
    pub fn scheduler(&self) -> &FetchScheduler<F, H> {
        &self.scheduler
    }

    /// The view of shard `shard_id`: from the cache when the block that
    /// closed it still has the hash it had, otherwise through a fresh read.
    ///
    /// Concurrent calls for one shard share that read's outcome, including
    /// a refusal. The refusal is not cached: a caller that arrives after
    /// the flight has ended leads a new one. A cache hit does not open a
    /// flight's fetch — the leader's cache check is the one that decides,
    /// and the read it then starts takes its own skeleton snapshot.
    ///
    /// # Errors
    ///
    /// [`ViewRefusal`]: the shard is open, could not be retrieved, the
    /// daemon could not form the request, or (a bounded `caller` only) the
    /// bounded permit is out.
    pub async fn view(
        &self,
        shard_id: ShardId,
        caller: ViewCaller,
    ) -> Result<ShardView, ViewRefusal> {
        loop {
            let (leader, mut waiting) = self.enlist(shard_id);
            let Some(leader) = leader else {
                match shared_view(&mut waiting).await {
                    Some(shared) => return owned_view(&shared),
                    // The leader was cancelled, or refused for its own
                    // permit, before it published. This caller may lead
                    // the next flight.
                    None => continue,
                }
            };
            let outcome = self.view_uncontended(shard_id, caller).await;
            if let Err(busy @ ViewRefusal::Busy { .. }) = outcome {
                // The leader's own refusal: the flight ends unpublished,
                // and a waiter leads it under its own permit.
                return Err(busy);
            }
            let shared = Arc::new(outcome);
            leader.publish(Arc::clone(&shared));
            return owned_view(&shared);
        }
    }

    /// Join the flight for `shard_id`, or open one and return its leader.
    fn enlist(&self, shard_id: ShardId) -> (Option<Leader>, watch::Receiver<Option<SharedView>>) {
        let mut flights = self.flights.lock().expect("view flight lock");
        if let Some(flight) = flights.get(&shard_id) {
            return (None, flight.outcome.subscribe());
        }
        let (outcome, waiting) = watch::channel(None);
        let flight = Arc::new(Flight { outcome });
        flights.insert(shard_id, Arc::clone(&flight));
        let leader = Leader {
            shard_id,
            flight,
            flights: Arc::clone(&self.flights),
        };
        (Some(leader), waiting)
    }

    async fn view_uncontended(
        &self,
        shard_id: ShardId,
        caller: ViewCaller,
    ) -> Result<ShardView, ViewRefusal> {
        // This standing serves the cache check only. The read takes its own
        // snapshot and the view is assembled from that one, so a reorg
        // between here and the read costs at most a fetch the cache could
        // have answered — never a view with fields from two standings.
        match self.scheduler.facts().shard(shard_id).map_err(local)? {
            ShardStanding::Closed(closed) => {
                if let Some(view) = self.cached(shard_id, closed.close.hash) {
                    return Ok(view);
                }
            }
            ShardStanding::Open {
                open_shard,
                archival_through_tip,
            } => {
                return Err(open_refusal(shard_id, open_shard, archival_through_tip));
            }
        }
        // A flight opens here, and only here: the cache missed.
        let _permit = match caller {
            ViewCaller::Host => None,
            ViewCaller::Bounded => Some(
                self.bounded
                    .try_acquire()
                    .map_err(|_| ViewRefusal::Busy { shard_id })?,
            ),
        };
        let _slot = self
            .lane
            .acquire()
            .await
            .expect("the view lane is never closed");
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
        let view = assemble(&read);
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

/// Wait until the flight publishes, or until its leader drops without
/// publishing. `None` is the second case: the caller may lead next.
async fn shared_view(waiting: &mut watch::Receiver<Option<SharedView>>) -> Option<SharedView> {
    loop {
        if let Some(shared) = waiting.borrow().clone() {
            return Some(shared);
        }
        if waiting.changed().await.is_err() {
            // The sender is gone. A publish that raced the drop is still
            // the receiver's last value; an abandon leaves `None`.
            return waiting.borrow().clone();
        }
    }
}

fn owned_view(shared: &SharedView) -> Result<ShardView, ViewRefusal> {
    match shared.as_ref() {
        Ok(view) => Ok(*view),
        Err(refusal) => Err(refusal.clone()),
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
