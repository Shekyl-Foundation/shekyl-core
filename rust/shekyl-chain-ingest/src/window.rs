// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two cache slots, and the pool steps that run beside them.
//!
//! [`install_blocking`] reads the seeds the reorg cap can name and pins
//! them, transient then canonical, under one chain permit. A hash looks a
//! cache up; it does not build one. A pool-file fault retires the pool.
//! A chain-store fault stops the service.

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use shekyl_chain_rules::{AdmissionPolicy, Corrupt, Fault, RuleSet, Substrate, ViewRead};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView, StoreError};
use shekyl_hash_budget::Class;
use shekyl_mempool::{Pool, PoolFault};
use shekyl_types::{BlockHash, BlockHeight, TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use super::{
    Accepted, Arrival, ArrivalLengths, Door, Refusal, ReplySlot, ServiceFault, SessionId, Shared,
    Ticket,
};
use crate::cache_window::{self, SeedPair};
use crate::schedule::ChainRules;
use tokio::sync::oneshot;

/// Install the seed window, or leave it when it is already the pair the
/// slots hold. A stop returns before a pin. A store read that fails is the
/// caller's to record ([`record_store_read`]).
///
/// # Errors
///
/// The store's, while reading the seeds, or a hole below the tip where a
/// seed block belongs.
pub(super) fn install_blocking<S>(shared: &Shared<S>) -> Result<(), ViewRead<StoreError>>
where
    S: Substrate + Send + Sync,
    S::Fault: core::fmt::Debug,
{
    if shared.stopping() {
        return Ok(());
    }
    let pair = cache_window::seeds_for(&shared.store, shared.rules)?;
    if shared.published_seeds() == Some(pair) {
        return Ok(());
    }
    let Some(_permit) = shared
        .budget
        .acquire_unless(Class::Chain, &shared.stop_flag)
    else {
        return Ok(());
    };
    {
        let _gate = shared
            .pin_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Older endpoint first, so the second pin leaves it in the
        // transient slot and the connecting height's seed canonical.
        if let Some(transient) = pair.transient {
            shared.substrate.pin_seed(&transient);
        }
        shared.substrate.pin_seed(&pair.canonical);
    }
    if !shared.stopping() {
        shared.seeds.send_replace(Some(pair));
    }
    Ok(())
}

/// [`install_blocking`] off the runtime.
///
/// # Errors
///
/// As [`install_blocking`].
pub(crate) async fn install_window<S>(shared: &Arc<Shared<S>>) -> Result<(), ViewRead<StoreError>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let shared = Arc::clone(shared);
    tokio::task::spawn_blocking(move || install_blocking(&shared))
        .await
        .expect("installing the seed window does not panic")
}

/// Record a door-side store read that failed, and stop. The door still
/// answers [`super::Refusal::NoRoom`]: the span was not accepted.
pub(crate) fn record_store_read<S>(shared: &Shared<S>, read: ViewRead<StoreError>)
where
    S: Substrate,
    S::Fault: core::fmt::Debug,
{
    let fault = match read {
        ViewRead::View(store) => ServiceFault::Store(store),
        ViewRead::Corrupt(corrupt) => ServiceFault::Corrupt {
            height: height_of(&corrupt),
            corrupt,
        },
    };
    shared.fail(fault);
}

/// The height a corrupt view names, when it names one.
fn height_of(corrupt: &Corrupt) -> BlockHeight {
    match corrupt {
        Corrupt::CumulativeDifficultyNotMonotone { at }
        | Corrupt::TxCountNotMonotone { at }
        | Corrupt::ShardCloseUnplaced { at, .. }
        | Corrupt::HoleBelowTip { at, .. }
        | Corrupt::RelayFloorUnpriceable { at, .. } => *at,
        Corrupt::DrawCount { height, .. } => *height,
        Corrupt::CumulativeDifficultyOverflow
        | Corrupt::BurnExceedsEmission { .. }
        | Corrupt::LeafNotConstructible { .. }
        | Corrupt::TreeUnservable { .. }
        | Corrupt::BondRecordInvariant { .. }
        | Corrupt::BondHybridKeyMalformed { .. }
        | Corrupt::AccrualOverflow { .. }
        | Corrupt::SettlementIntegrity { .. }
        // An epoch's drawable set or its frozen complete-tree set, like
        // settlement: the fault names the epoch, not a block.
        | Corrupt::DrawableEpoch { .. }
        | Corrupt::CompleteTreesAbsent { .. } => BlockHeight::ZERO,
    }
}

/// Run `f` over the pool against the chain the store holds now.
/// `None` when no pool is wired, or the pool file has been retired.
pub(crate) async fn with_pool<S, R, F>(
    shared: &Arc<Shared<S>>,
    f: F,
) -> Option<Result<R, StoreError>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
    R: Send + 'static,
    F: FnOnce(
            &mut Pool,
            &ReadSnapshot<'_>,
            &SnapshotView<'_>,
            &RuleSet,
            &AdmissionPolicy,
            UnixSeconds,
        ) -> R
        + Send
        + 'static,
{
    if !shared.pool_is_live() {
        return None;
    }
    let wiring = shared.pool.clone()?;
    let store = Arc::clone(&shared.store);
    let rules: ChainRules = shared.rules;
    Some(
        tokio::task::spawn_blocking(move || {
            let snap = store.begin_read()?;
            let view = SnapshotView::new(&snap);
            let tip = shekyl_chain_rules::HeaderView::tip(&view)?;
            let rule_set = rules.in_force(shekyl_chain_rules::Tip::connecting_height(tip.as_ref()));
            let mut pool = wiring.pool.lock().unwrap_or_else(PoisonError::into_inner);
            Ok(f(
                &mut pool,
                &snap,
                &view,
                &rule_set,
                &wiring.policy,
                (wiring.wall)(),
            ))
        })
        .await
        .expect("a pool step does not panic"),
    )
}

/// How one pool door's faults divide.
///
/// A moved tip parks its bodies to be judged again. A file fault retires
/// the pool. A chain fault stops the service. The caller applies them by
/// severity — chain, then file — and parks only when neither is set. The
/// chain is the record; the pool file is discardable.
#[derive(Default)]
pub(crate) struct PoolDivision {
    /// Bodies whose connecting height moved.
    pub parked: Vec<Transaction>,
    /// The pool file faulted.
    pub file: Option<StoreError>,
    /// The chain view faulted.
    pub chain: Option<Fault<StoreError>>,
}

/// Divide `faults` against the bodies that produced them.
///
/// A moved tip whose body is not in `bodies` parks nothing: there is
/// nothing left to judge. The first file fault and the first chain fault
/// are the ones kept.
pub(crate) fn divide_pool_faults(
    faults: Vec<(TxHash, PoolFault<StoreError>)>,
    bodies: &[Transaction],
) -> PoolDivision {
    let mut parked = Vec::new();
    let mut file = None;
    let mut chain = None;
    for (txid, fault) in faults {
        match fault {
            PoolFault::TipMoved { .. } => {
                if let Some(body) = body_of(bodies, &txid) {
                    parked.push(body);
                }
            }
            PoolFault::Store(store) => {
                if file.is_none() {
                    file = Some(store);
                }
            }
            PoolFault::Chain(fault) => {
                if chain.is_none() {
                    chain = Some(fault);
                }
            }
        }
    }
    PoolDivision {
        parked,
        file,
        chain,
    }
}

fn body_of(bodies: &[Transaction], txid: &TxHash) -> Option<Transaction> {
    bodies
        .iter()
        .find(|tx| tx.txid_parts().hash == *txid)
        .cloned()
}

/// The seeds a pin just put in the slots: the last is canonical, and the
/// distinct seed before it is transient. One seed demotes the previous
/// canonical into the transient slot, which is what the cache store did.
pub(super) fn note_pins<S>(shared: &Shared<S>, pinned: &[BlockHash])
where
    S: Substrate,
    S::Fault: core::fmt::Debug,
{
    let Some(&canonical) = pinned.last() else {
        return;
    };
    let earlier = pinned
        .iter()
        .rev()
        .skip(1)
        .find(|seed| **seed != canonical)
        .copied();
    let transient = earlier.or_else(|| {
        shared
            .published_seeds()
            .and_then(|pair| (pair.canonical != canonical).then_some(pair.canonical))
    });
    shared.seeds.send_replace(Some(SeedPair {
        canonical,
        transient,
    }));
}

impl super::Admission {
    /// The size bound at the store's tip now, derived once per tip.
    ///
    /// # Errors
    ///
    /// The store's. The bound hook records it and the service stops; the
    /// door answers [`super::Refusal::StoreUnreadable`].
    pub(super) fn bound(&self) -> Result<crate::admission::ArrivalBound, ()> {
        #[cfg(test)]
        if self.refuse_reads.load(std::sync::atomic::Ordering::Acquire) {
            return Err(());
        }
        let tip = match self.store.begin_read().and_then(|snap| snap.tip()) {
            Ok(state) => state.recorded.map(|recorded| recorded.hash),
            Err(store) => {
                self.note_read_fault(shekyl_chain_rules::ViewRead::View(store));
                return Err(());
            }
        };
        let mut cached = self.bound.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, bound)) = *cached {
            if at == tip {
                return Ok(bound);
            }
        }
        let (at, bound) = match crate::admission::ArrivalBound::at(&self.store) {
            Ok(pair) => pair,
            Err(read) => {
                drop(cached);
                self.note_read_fault(read);
                return Err(());
            }
        };
        *cached = Some((at, bound));
        Ok(bound)
    }

    pub(super) fn bind_read_fault(&self, hook: super::ReadFault) {
        *self
            .on_read_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    fn note_read_fault(&self, read: shekyl_chain_rules::ViewRead<StoreError>) {
        let hook = self
            .on_read_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook(read);
        }
    }
}

/// Seats and bucket tokens held for a span whose bytes are not copied yet.
///
/// Dropped without [`commit`](Self::commit), both go back: the span was
/// not accepted. Committed, the tokens stay spent and each seat rides its
/// reply.
#[must_use = "dropping a reservation refunds it; commit accepts the span"]
pub struct Reservation {
    door: Door,
    seats: Vec<crate::room::Seat>,
    taken: Vec<(SessionId, u32)>,
    now: Duration,
    committed: bool,
}

impl Reservation {
    /// Accept `span`. It is the arrivals [`Door::reserve`] judged, in that
    /// order, now carrying their bytes.
    pub fn commit(mut self, span: Vec<Arrival>) -> Vec<Ticket> {
        assert_eq!(
            span.len(),
            self.seats.len(),
            "a reservation commits the arrivals it reserved"
        );
        let seats = std::mem::take(&mut self.seats);
        self.committed = true;
        let mut tickets = Vec::with_capacity(span.len());
        let mut accepted = Vec::with_capacity(span.len());
        for (arrival, seat) in span.into_iter().zip(seats) {
            let (sender, receiver) = oneshot::channel();
            tickets.push(Ticket {
                tag: arrival.tag,
                reply: receiver,
            });
            accepted.push(Accepted {
                slot: ReplySlot {
                    sender: Some(sender),
                    seat: Some(seat),
                },
                tag: arrival.tag,
                origin: arrival.origin,
                block: arrival.block,
                bodies: arrival.bodies,
                judged: None,
                witness: Vec::new(),
            });
        }
        // A service that has ended drops the span here, and each slot
        // answers `Stopped`.
        let _ended = self.door.spans.send(accepted);
        tickets
    }

    /// Accept a bound `span` ([`super::BoundArrival`]): the arrivals
    /// [`Door::reserve`] judged, in that order.
    pub fn commit_bound(mut self, span: Vec<super::BoundArrival>) -> Vec<Ticket> {
        assert_eq!(
            span.len(),
            self.seats.len(),
            "a reservation commits the arrivals it reserved"
        );
        let seats = std::mem::take(&mut self.seats);
        self.committed = true;
        let mut tickets = Vec::with_capacity(span.len());
        let mut accepted = Vec::with_capacity(span.len());
        for (arrival, seat) in span.into_iter().zip(seats) {
            let (sender, receiver) = oneshot::channel();
            tickets.push(Ticket {
                tag: arrival.tag,
                reply: receiver,
            });
            accepted.push(Accepted {
                slot: ReplySlot {
                    sender: Some(sender),
                    seat: Some(seat),
                },
                tag: arrival.tag,
                origin: super::Origin::Peer {
                    session: arrival.session,
                    solicited: true,
                },
                block: arrival.block,
                bodies: arrival.bodies,
                judged: Some(Box::new(arrival.judged)),
                witness: arrival.attestation_witness,
            });
        }
        let _ended = self.door.spans.send(accepted);
        tickets
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (session, count) in self.taken.drain(..) {
            self.door
                .admission
                .buckets
                .give_back(session, count, self.now);
        }
    }
}

impl Door {
    /// Judge `lengths` and hold what an accepted span needs.
    ///
    /// In order, before any byte of the span is copied: the size of every
    /// arrival ([`Refusal::Oversize`]), the seats ([`Refusal::NoRoom`]),
    /// and one take from each session's bucket ([`Refusal::Throttled`]).
    /// A refused span holds nothing. A span is one session's; a mix still
    /// refunds every take that succeeded.
    ///
    /// # Errors
    ///
    /// [`Refusal`].
    pub fn reserve(&self, lengths: &[ArrivalLengths]) -> Result<Reservation, Refusal> {
        if self.room.is_closed() {
            return Err(Refusal::NoRoom);
        }
        // A store the door cannot read is its own refusal, never "no room":
        // a local arrival waits out no room, and a seat being free would
        // send it straight back here.
        let Ok(bound) = self.admission.bound() else {
            return Err(Refusal::StoreUnreadable);
        };
        let oversize = lengths
            .iter()
            .any(|arrival| !bound.admits(u64::try_from(arrival.bytes()).unwrap_or(u64::MAX)));
        if oversize {
            return Err(Refusal::Oversize);
        }
        let kinds: Vec<_> = lengths
            .iter()
            .map(|arrival| super::seat_kind(arrival.origin))
            .collect();
        let Some(seats) = self.room.try_take(&kinds) else {
            return Err(Refusal::NoRoom);
        };
        let now = (self.admission.clock)();
        let taken = match super::take_unsolicited(&self.admission.buckets, lengths, now) {
            Ok(taken) => taken,
            Err(refused) => {
                drop(seats);
                return Err(refused);
            }
        };
        Ok(Reservation {
            door: self.clone(),
            seats,
            taken,
            now,
            committed: false,
        })
    }
}
