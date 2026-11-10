// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two cache slots, and the pool steps that run beside them.
//!
//! [`install_blocking`] reads the seeds the reorg cap can name and pins
//! them, transient then canonical, under one chain permit, and releases a
//! seed the window it replaces named and it does not. A hash looks a
//! cache up; it does not build one. A pool-file fault retires the pool.
//! A chain-store fault stops the service.

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use shekyl_chain_rules::{AdmissionPolicy, Corrupt, Fault, RuleSet, Substrate, ViewRead};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView, StoreError};
use shekyl_hash_budget::Class;
use shekyl_mempool::{Pool, PoolFault};
use shekyl_types::{BlockHeight, TxHash, UnixSeconds, MAX_ATTESTATION_WITNESS_BYTES};
use shekyl_wire::Transaction;

use super::{
    Accepted, Arrival, ArrivalLengths, Door, Refusal, ReplySlot, ServiceFault, SessionId, Shared,
    Ticket,
};
use crate::cache_window::{self, SeedPair, SlotPair};
use crate::schedule::ChainRules;
use tokio::sync::oneshot;

/// Install the seed window, or leave it when it is the window last
/// installed and the slots hold exactly it. A stop returns before a pin. A
/// store read that fails is the caller's to record ([`record_store_read`]).
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
    install_pair(shared, pair);
    Ok(())
}

/// Install `pair`, the seed window read at the committed tip: pin it,
/// release what the window last installed named and `pair` does not, and
/// publish the slots. Leaves everything as it is when `pair` is the window
/// last installed and the slots hold exactly it. A stop before the permit
/// pins nothing.
pub(super) fn install_pair<S>(shared: &Shared<S>, pair: SeedPair)
where
    S: Substrate + Send + Sync,
    S::Fault: core::fmt::Debug,
{
    // Both, read together under the pin lock (taken and dropped here, before
    // the permit): slots that hold the window are not enough, since the
    // window last installed may name a seed this one does not, still to be
    // released (A2).
    if shared.window_is_settled(pair) {
        return;
    }
    let Some(_permit) = shared
        .budget
        .acquire_unless(Class::Chain, &shared.stop_flag)
    else {
        return;
    };
    // The substrate is cloned so the closure does not borrow the service
    // the pin lock borrows. Older endpoint first, so the second pin leaves
    // it in the transient slot and the connecting height's seed canonical.
    let substrate = Arc::clone(&shared.substrate);
    shared.with_pin_lock(|installed| {
        if let Some(transient) = pair.transient {
            substrate.pin_seed(&transient);
        }
        substrate.pin_seed(&pair.canonical);
        // A seed the previous window named and this one does not is
        // released: nothing else would empty its slot before the next
        // epoch's pin (A2). Only those. A run in flight pins the seeds of
        // blocks it has not committed yet, and this window, read at the
        // committed tip, cannot name them; a release by "whatever the
        // second slot holds" evicted them under the run's forms.
        if let Some(previous) = installed.replace(pair) {
            for seed in [Some(previous.canonical), previous.transient]
                .into_iter()
                .flatten()
            {
                if !pair.holds(&seed) {
                    substrate.release_seed(&seed);
                }
            }
        }
    });
}

/// Why installing the seed window stops its caller.
pub(crate) enum WindowStop {
    /// A store read failed ([`install_blocking`]'s error).
    Read(ViewRead<StoreError>),
    /// The install panicked: a defect in this node.
    Panicked,
}

/// [`install_blocking`] off the runtime.
///
/// # Errors
///
/// [`WindowStop::Read`] as [`install_blocking`]; [`WindowStop::Panicked`]
/// when the blocking install panicked. The workspace's dev and release
/// profiles abort on panic, so the second is reached only where a panic
/// unwinds (the test profile). Either way the caller stops through
/// [`record_window_stop`].
pub(crate) async fn install_window<S>(shared: &Arc<Shared<S>>) -> Result<(), WindowStop>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let shared = Arc::clone(shared);
    match tokio::task::spawn_blocking(move || install_blocking(&shared)).await {
        Ok(installed) => installed.map_err(WindowStop::Read),
        Err(join) => {
            tracing::error!("installing the seed window panicked: {join}");
            Err(WindowStop::Panicked)
        }
    }
}

/// Stop the service on a failed install. A failed read is recorded as
/// [`record_store_read`] records it. A panic stops it as the follower's
/// end does ([`ServiceFault::FollowerEnded`]): the follower then leaves its
/// loop, and the miner's job is withdrawn with it.
pub(crate) fn record_window_stop<S>(shared: &Shared<S>, stop: WindowStop)
where
    S: Substrate,
    S::Fault: core::fmt::Debug,
{
    match stop {
        WindowStop::Read(read) => record_store_read(shared, read),
        WindowStop::Panicked => shared.fail(ServiceFault::FollowerEnded),
    }
}

/// Record a store read that failed, and stop. On the door's side the
/// arrival is refused with what the failed read is
/// ([`super::Refusal::StoreUnreadable`]); the span was not accepted, and
/// the caller does not wait it out.
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

/// The window last installed, and the slots, read under the pin lock.
pub(super) struct PinView {
    /// The window last installed. `None` until the first install.
    pub(super) window: Option<SeedPair>,
    /// The seeds the slots hold. `None` until a seed is canonical.
    pub(super) slots: Option<SlotPair>,
    /// The pair last published, read under the same lock as `slots`.
    /// The tests compare the two. Production reads `slots` for the
    /// settled check, and the watch for everyone else.
    #[cfg(test)]
    pub(super) published: Option<SlotPair>,
}

impl<S: Substrate> Shared<S> {
    /// Run `body` under the pin lock, then publish the slots before the
    /// lock drops. A pin, a preparation and the install all enter here, so
    /// a change to the slots cannot forget the publish. An unchanged pair
    /// does not wake a waiter.
    pub(super) fn with_pin_lock<R>(&self, body: impl FnOnce(&mut Option<SeedPair>) -> R) -> R {
        // The guard, the slot read and the watch are three fields. Naming
        // them keeps the publish inside the critical section: the slots are
        // read and sent before the guard drops.
        let Self {
            pin_lock,
            substrate,
            seeds,
            ..
        } = self;
        let mut installed = pin_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let result = body(&mut installed);
        let next = SlotPair::from_stored(substrate.slots());
        seeds.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
        drop(installed);
        result
    }

    /// The window and the slots, read together under the pin lock.
    pub(super) fn pin_view(&self) -> PinView {
        let Self {
            pin_lock,
            substrate,
            #[cfg(test)]
            seeds,
            ..
        } = self;
        let installed = pin_lock.lock().unwrap_or_else(PoisonError::into_inner);
        PinView {
            window: *installed,
            slots: SlotPair::from_stored(substrate.slots()),
            #[cfg(test)]
            published: *seeds.borrow(),
        }
    }

    /// `pair` is the window last installed and the slots hold exactly it.
    fn window_is_settled(&self, pair: SeedPair) -> bool {
        let view = self.pin_view();
        view.window == Some(pair) && view.slots.is_some_and(|slots| slots.same_seeds(pair))
    }
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
    /// order, now carrying their bytes. Each one is hashed here.
    pub fn commit(self, span: Vec<Arrival>) -> Vec<Ticket> {
        self.accept(span.into_iter().map(super::Staged::hashed).collect())
    }

    /// Accept `span`. It is the arrivals [`Door::reserve`] judged, in that
    /// order. A hashed arrival and a judged one take the same seats.
    pub(super) fn accept(mut self, span: Vec<super::Staged>) -> Vec<Ticket> {
        assert_eq!(
            span.len(),
            self.seats.len(),
            "a reservation commits the arrivals it reserved"
        );
        let seats = std::mem::take(&mut self.seats);
        self.committed = true;
        let mut tickets = Vec::with_capacity(span.len());
        let mut accepted = Vec::with_capacity(span.len());
        for (staged, seat) in span.into_iter().zip(seats) {
            let (sender, receiver) = oneshot::channel();
            tickets.push(Ticket {
                tag: staged.tag,
                reply: receiver,
            });
            accepted.push(Accepted {
                slot: ReplySlot {
                    sender: Some(sender),
                    seat: Some(seat),
                },
                tag: staged.tag,
                block: staged.block,
                bodies: staged.bodies,
                proof: staged.proof,
                witness: staged.witness,
            });
        }
        // A service that has ended drops the span here, and each slot
        // answers `Stopped`.
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
        let oversize = lengths.iter().any(|arrival| {
            !bound.admits(u64::try_from(arrival.bytes()).unwrap_or(u64::MAX))
                || arrival.witness_len > MAX_ATTESTATION_WITNESS_BYTES
        });
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
