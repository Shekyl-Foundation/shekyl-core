// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One attempt, from the moment it joins the in-flight table until its
//! result is applied.
//!
//! Joining the table and reading the stop flag are one lock section
//! ([`Dialer::enlist`]). [`Dialer::stop`] drains that table under the same
//! lock. An attempt that is inserted first is in the drain. An attempt
//! that finds the flag set is cancelled there: the pending address leaves
//! [`crate::Attempts`] with no outcome, so its gray draw stays seated.
//!
//! Two drivers share that enlist. The owner loop [`Dialer::launch`]es a
//! task. The task races the attempt against its cancel and posts a result
//! onto [`Completions`]; the loop is the only consumer. [`Dialer::wake`]
//! and [`Dialer::dial`] run the same race on the calling thread and apply
//! the result before they return. They never touch the queue.
//!
//! The attempt's [`FlightGuard`] is held by whichever driver runs it.
//! Dropping the guard while it is still armed removes the row and cancels
//! the pending address. That is how a task dropped before it posts — stop,
//! or a runtime that never polls the task — releases the row. Applying
//! disarms the guard first, so a posted result stays until the loop takes it.
//!
//! [`Dialer::abandon_flight`] is stop's half of the same table: it drains
//! every row, drops the cancel senders after the dialer lock, then closes
//! the queue and drops what was already posted. A post after that close is
//! rejected, and the task drops the result. An application that has already
//! taken its row is counted. Stop waits for that count, and it does not
//! hold the dialer lock across the hub calls that finish the application.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{CloseCause, CloseKind, ConnectorId, DialOutcome, NetworkAddress};
use shekyl_seam::{Hub, SocketId};

use super::handshake::{attempt_task, Attempt, Prepared, TaskResult};
use super::ready::block_on_future;
use super::{Dialer, Shared};
use crate::fill::DialAim;
use crate::nonce::InFlightNonce;

/// What one [`Dialer::launch`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Launch {
    /// Nothing was drawn, or the connector cannot dial.
    Nothing,
    /// An attempt task is running. The loop applies its result by id.
    Running(u64),
    /// The attempt ended before any I/O (no endpoint, no tip, no network
    /// id) and was recorded at once.
    Recorded,
    /// The dialer had stopped. The pending draw was cancelled and stays
    /// seated. Nothing was spawned and nothing was recorded.
    Stopped,
}

/// One result the loop applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The attempt.
    pub id: u64,
    /// The address dialed.
    pub address: NetworkAddress,
    /// The kept session, when a `Keep` was kept.
    pub kept: Option<SocketId>,
}

/// One enlisted attempt, as the driver holds it until the result is applied
/// or the task is dropped.
pub(super) struct InFlight {
    connector: ConnectorId,
    address: NetworkAddress,
    aim: DialAim,
    /// Held for its drop: the nonce is in the set until this record is
    /// dropped, after the result is applied or the attempt is cancelled.
    _nonce: InFlightNonce,
    /// Held for its drop: dropping it completes the attempt's cancel.
    _cancel: tokio::sync::oneshot::Sender<()>,
}

/// An attempt task's result, and how long the attempt ran.
pub(super) struct Finished {
    result: TaskResult,
    /// Nanoseconds from the task's first poll to its result, on the hub's
    /// clock. Neither the spawn's scheduling nor the wait in the completion
    /// queue counts, so a timeout's place against the Tor window
    /// ([`Dialer::set_tor_window`]) is the attempt's own.
    ran_nanos: u64,
}

/// `attempt`, timed inside its task ([`Finished::ran_nanos`]).
async fn timed(hub: Hub, attempt: impl Future<Output = TaskResult>) -> Finished {
    let started = hub.now();
    let result = attempt.await;
    let ran_nanos = hub.now().get().saturating_sub(started.get());
    Finished { result, ran_nanos }
}

/// The results attempt tasks have posted and the loops have not taken.
///
/// Its lock is its own. A task takes nothing else, and no hub call is made
/// under it. The loop is the only consumer: [`Self::take`] removes one
/// connector's results, in the order posted. [`Self::close`] is permanent:
/// stop closes the queue, and a dialer does not start again.
#[derive(Default)]
pub(super) struct Completions {
    queue: Mutex<Inbox>,
    posted: Condvar,
}

#[derive(Default)]
struct Inbox {
    /// Set by [`Completions::close`]. A post after that is rejected.
    closed: bool,
    items: VecDeque<(u64, ConnectorId, Finished)>,
}

impl Completions {
    /// Queue `result`. `false` when the queue is closed: the result is
    /// dropped after this lock, which releases its channel, and the caller
    /// still holds the row.
    fn post(&self, id: u64, connector: ConnectorId, result: Finished) -> bool {
        let rejected = {
            let mut inbox = self.queue.lock().expect("completions");
            if inbox.closed {
                Some(result)
            } else {
                inbox.items.push_back((id, connector, result));
                None
            }
        };
        match rejected {
            Some(result) => {
                drop(result);
                false
            }
            None => {
                self.posted.notify_all();
                true
            }
        }
    }

    /// Take every result posted for `connector`, in the order posted.
    /// Other connectors' results stay, in their relative order.
    fn take(&self, connector: ConnectorId) -> Vec<(u64, Finished)> {
        let mut inbox = self.queue.lock().expect("completions");
        let mut taken = Vec::new();
        let mut kept = VecDeque::with_capacity(inbox.items.len());
        for (id, of, result) in inbox.items.drain(..) {
            if of == connector {
                taken.push((id, result));
            } else {
                kept.push_back((id, of, result));
            }
        }
        inbox.items = kept;
        taken
    }

    /// Refuse every later post and drop every posted result. Each channel
    /// is released as it drops, outside this lock. A waiter is woken: stop
    /// has happened, and the result will not arrive.
    pub(super) fn close(&self) {
        let dropped: Vec<_> = {
            let mut inbox = self.queue.lock().expect("completions");
            inbox.closed = true;
            inbox.items.drain(..).collect()
        };
        drop(dropped);
        self.posted.notify_all();
    }

    /// Whether attempt `id`'s result is posted and not yet taken.
    #[cfg(feature = "test-seams")]
    fn holds(&self, id: u64) -> bool {
        self.queue
            .lock()
            .expect("completions")
            .items
            .iter()
            .any(|(posted, _, _)| *posted == id)
    }

    /// Wait until attempt `id` is posted, the queue is closed, or `stop`
    /// is set.
    ///
    /// The predicate is checked under this queue's lock, so a post or a
    /// close that arrives first is seen and the wait is not timed. This
    /// does not take the result.
    #[cfg(feature = "test-seams")]
    fn wait_until_posted(&self, id: u64, stop: &std::sync::atomic::AtomicBool) {
        let mut inbox = self.queue.lock().expect("completions");
        loop {
            if stop.load(Ordering::Acquire)
                || inbox.closed
                || inbox.items.iter().any(|(posted, _, _)| *posted == id)
            {
                return;
            }
            inbox = self.posted.wait(inbox).expect("completions");
        }
    }
}

/// Removes its attempt from the in-flight table on drop, unless
/// [`Self::disarm`]ed. Armed means the result was never posted: the pending
/// address is cancelled and the nonce leaves the set with the record.
struct FlightGuard {
    shared: Arc<Mutex<Shared>>,
    id: u64,
    armed: bool,
}

impl FlightGuard {
    /// The row stays until [`Self::disarm`] or this drops.
    fn arm(shared: Arc<Mutex<Shared>>, id: u64) -> Self {
        Self {
            shared,
            id,
            armed: true,
        }
    }

    /// The result is about to be posted or applied. Dropping the guard
    /// leaves the row for the applier.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut shared = self.shared.lock().expect("dialer state");
        if let Some(record) = shared.in_flight.remove(&self.id) {
            shared.attempts(record.connector).cancel(&record.address);
        }
    }
}

/// An attempt that joined the table: its id, the cancel the driver races,
/// and the guard that releases the row if the driver is dropped.
struct Enlisted {
    id: u64,
    cancel: tokio::sync::oneshot::Receiver<()>,
    guard: FlightGuard,
}

/// What a dial run on the calling thread became.
enum Drove {
    /// Stop cancelled it. Nothing was recorded.
    Stopped,
    /// The result was applied. `kept` is the session when one was kept.
    Settled { kept: Option<SocketId> },
}

/// An attempt that ended before its task ran.
enum BeforeIo {
    /// `DialFailed` was recorded. The outstanding gray cools: this cause
    /// carries no proof.
    Recorded,
    /// Stop won. The gray draw stays seated.
    Stopped,
}

impl BeforeIo {
    fn launch(self) -> Launch {
        match self {
            Self::Recorded => Launch::Recorded,
            Self::Stopped => Launch::Stopped,
        }
    }

    fn drove(self) -> Drove {
        match self {
            Self::Recorded => Drove::Settled { kept: None },
            Self::Stopped => Drove::Stopped,
        }
    }
}

/// The attempt, or `None` when `cancel` wins.
///
/// Cancel is biased: a stop that has already dropped the sender wins over
/// a result that became ready in the same wake, and the attempt is dropped
/// without being posted. Dropping it releases the channel.
async fn drive_attempt(
    mut cancel: tokio::sync::oneshot::Receiver<()>,
    attempt: impl Future<Output = Finished> + Send,
) -> Option<Finished> {
    tokio::pin!(attempt);
    tokio::select! {
        biased;
        _ = &mut cancel => None,
        result = attempt.as_mut() => Some(result),
    }
}

impl Dialer {
    /// One wake's launch: the plan, the draw, and the attempt task it
    /// starts. The loop calls this when its wake fires. It does not wait
    /// for the dial.
    pub fn launch<R: RelayRng + ?Sized>(&self, connector: ConnectorId, rng: &mut R) -> Launch {
        let Some((address, aim, nonce)) = self.choose(connector, rng) else {
            return Launch::Nothing;
        };
        self.spawn_drawn(connector, address, aim, nonce, rng)
    }

    /// Apply every result posted for `connector`, in the order posted, each
    /// through the layer that owns its decision. The attempt leaves
    /// [`crate::Attempts`] and its nonce leaves the set only here. A result
    /// whose attempt is no longer held (cancelled at stop) is dropped,
    /// which releases its channel.
    pub fn apply_completions<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        rng: &mut R,
    ) -> Vec<Applied> {
        self.completions
            .take(connector)
            .into_iter()
            .filter_map(|(id, result)| self.apply_taken(connector, id, result, rng))
            .collect()
    }

    /// One wake's work, run to its end on the calling thread. Returns
    /// whether a dial was made. A test calls this to run wakes without the
    /// clock. The owner loop never does: it uses [`Self::launch`] and never
    /// waits on a dial.
    pub fn wake<R: RelayRng + ?Sized>(&self, connector: ConnectorId, rng: &mut R) -> bool {
        let Some((address, aim, nonce)) = self.choose(connector, rng) else {
            return false;
        };
        match self.drive_here(connector, address, aim, nonce, rng) {
            Drove::Stopped => false,
            Drove::Settled { .. } => true,
        }
    }

    /// One dial of `address` with `aim`, outside the wake loop, run to its
    /// end on the calling thread. Returns the kept session's id. A confirm
    /// dial, a refusal and a failure return [`None`]: each is recorded
    /// before this returns, and a confirm dial posts nothing. The owner
    /// loop draws through [`Self::choose`]; a test dials one named address
    /// here.
    ///
    /// Readiness comes first, as in [`Self::choose`]. A connector that
    /// cannot dial returns [`None`] before any draw: a draw it cannot dial
    /// ends as `DialFailed(LocalClose)`, and that cause carries no proof,
    /// so the outstanding gray address cools.
    ///
    /// A gray address is drawn here, so the outcome resolves an outstanding
    /// draw as the lists require. A white address is a re-contact and is
    /// not drawn. An address on neither list is not dialed. The clock is
    /// read before the dialer lock: the draw thaws a cooldown that has
    /// ended, and the hub is never called under that lock.
    pub fn dial<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        aim: DialAim,
        rng: &mut R,
    ) -> Option<SocketId> {
        if let Err(missing) = self.readiness(connector) {
            tracing::debug!(
                "{connector:?} dial {address:?} not made: {}",
                missing.describe()
            );
            return None;
        }
        let now = self.hub.now();
        {
            let mut shared = self.shared();
            if shared.lists.is_gray(address) {
                let drawn = shared.lists.draw_gray_where(
                    connector,
                    now,
                    &mut |candidate| candidate == address,
                    rng,
                )?;
                debug_assert_eq!(&drawn, address);
            } else if !shared.lists.is_white(address) {
                return None;
            }
            if !shared.begin_or_release(connector, address, aim) {
                tracing::debug!(
                    "{connector:?} dial {address:?} not made: an attempt is already open"
                );
                return None;
            }
        }
        let nonce = self.nonces.mint(connector, rng);
        match self.drive_here(connector, address.clone(), aim, nonce, rng) {
            Drove::Stopped => None,
            Drove::Settled { kept } => kept,
        }
    }

    /// Whether attempt `id`'s result is posted and not yet applied.
    /// A test seam: the loop is the consumer, and this does not take.
    #[cfg(feature = "test-seams")]
    #[must_use]
    pub fn completed(&self, id: u64) -> bool {
        self.completions.holds(id)
    }

    /// Wait until attempt `id`'s result is posted or the dialer has stopped.
    /// A test seam. The result stays posted for [`Self::apply_completions`].
    #[cfg(feature = "test-seams")]
    pub fn wait_posted(&self, id: u64) {
        self.completions.wait_until_posted(id, &self.stop);
    }

    /// Cancel every enlisted attempt and drop every posted result.
    ///
    /// The cancel senders are dropped after the dialer lock, so an inline
    /// drive unparks outside that lock. The queue is cleared after the
    /// senders, so a result posted as a task winds down is released here.
    /// Returns how many attempts were enlisted.
    pub(super) fn abandon_flight(&self) -> usize {
        let cancelled = {
            let mut shared = self.shared();
            let cancelled: Vec<InFlight> = std::mem::take(&mut shared.in_flight)
                .into_values()
                .collect();
            for record in &cancelled {
                shared.attempts(record.connector).cancel(&record.address);
            }
            cancelled
        };
        let count = cancelled.len();
        drop(cancelled);
        self.completions.close();
        count
    }

    /// Spawn the attempt for a draw [`Self::choose`] already began.
    fn spawn_drawn<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        aim: DialAim,
        nonce: InFlightNonce,
        rng: &mut R,
    ) -> Launch {
        tracing::debug!("{connector:?} dial {address:?} aim {aim:?}");
        let prepared = match self.prepare(connector, &address, &nonce) {
            Ok(prepared) => prepared,
            Err(cause) => {
                return self
                    .record_local(connector, address, nonce, cause, rng)
                    .launch();
            }
        };
        let Some(enlisted) = self.enlist(connector, address.clone(), aim, nonce) else {
            return Launch::Stopped;
        };
        let id = enlisted.id;
        if !self.spawn_enlisted(connector, address.clone(), prepared, enlisted) {
            tracing::warn!("{connector:?}: the dial attempt task could not start");
            return self.record_unstarted(connector, address, rng).launch();
        }
        // A posted result stays in the table until the loop applies it.
        // Absence means the guard already released the row: stop drained
        // it, or the task was dropped before it posted. An attempt that
        // finished is still here, so this is not `DialFailed`.
        if self.still_enlisted(id) {
            Launch::Running(id)
        } else {
            Launch::Stopped
        }
    }

    /// Run the attempt on this thread and apply its result before returning.
    fn drive_here<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        aim: DialAim,
        nonce: InFlightNonce,
        rng: &mut R,
    ) -> Drove {
        tracing::debug!("{connector:?} dial {address:?} aim {aim:?}");
        let prepared = match self.prepare(connector, &address, &nonce) {
            Ok(prepared) => prepared,
            Err(cause) => {
                return self
                    .record_local(connector, address, nonce, cause, rng)
                    .drove();
            }
        };
        let Some(enlisted) = self.enlist(connector, address.clone(), aim, nonce) else {
            return Drove::Stopped;
        };
        let Enlisted {
            id,
            cancel,
            mut guard,
        } = enlisted;
        let hub = self.hub.clone();
        let attempt = attempt_task(hub.clone(), connector, address, prepared);
        let outcome = block_on_future(drive_attempt(cancel, timed(hub, attempt)));
        match outcome {
            None => Drove::Stopped,
            Some(result) => {
                guard.disarm();
                match self.apply_taken(connector, id, result, rng) {
                    Some(applied) => Drove::Settled { kept: applied.kept },
                    // Stop took the row before the result was recorded.
                    None => Drove::Stopped,
                }
            }
        }
    }

    /// Put the begun attempt in the table, or cancel it when the dialer
    /// has stopped. The flag and the insert share this lock section.
    /// `None` when it was cancelled: the nonce is dropped, and nothing
    /// is recorded.
    fn enlist(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        aim: DialAim,
        nonce: InFlightNonce,
    ) -> Option<Enlisted> {
        let (sender, cancel) = tokio::sync::oneshot::channel();
        let shared = Arc::clone(&self.shared);
        let id = {
            let mut state = shared.lock().expect("dialer state");
            if self.stop.load(Ordering::Acquire) {
                state.attempts(connector).cancel(&address);
                drop(state);
                drop(nonce);
                return None;
            }
            let id = state.next_attempt;
            state.next_attempt = id.wrapping_add(1);
            state.in_flight.insert(
                id,
                InFlight {
                    connector,
                    address,
                    aim,
                    _nonce: nonce,
                    _cancel: sender,
                },
            );
            id
        };
        Some(Enlisted {
            id,
            cancel,
            guard: FlightGuard::arm(shared, id),
        })
    }

    /// Hand `enlisted` to the hub's attempt spawner. The guard moves into
    /// the task, so a task that is dropped before it posts releases the row.
    /// `false` when the task could not be started; it was dropped.
    fn spawn_enlisted(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        prepared: Prepared,
        enlisted: Enlisted,
    ) -> bool {
        let Enlisted { id, cancel, guard } = enlisted;
        let hub = self.hub.clone();
        let completions = Arc::clone(&self.completions);
        let bell = Arc::clone(&self.bell);
        let task = async move {
            let mut guard = guard;
            let attempt = attempt_task(hub.clone(), connector, address, prepared);
            let posted = drive_attempt(cancel, timed(hub, attempt)).await;
            // Disarm only once the queue has accepted the result. A rejected
            // post was dropped inside `post`, after its lock, and the guard
            // still releases the row when stop has not already drained it.
            if let Some(result) = posted {
                if completions.post(id, connector, result) {
                    guard.disarm();
                    bell.ring();
                }
            }
        };
        self.hub.spawn_attempt(Box::pin(task))
    }

    /// Record a local failure that ended before any I/O, unless the dialer
    /// has stopped: then the pending draw is cancelled and stays seated.
    /// The nonce is dropped on both paths. The hub clock is read before
    /// the dialer lock.
    fn record_local<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        nonce: InFlightNonce,
        cause: CloseCause,
        rng: &mut R,
    ) -> BeforeIo {
        drop(nonce);
        let now = self.hub.now();
        let mut shared = self.shared();
        if self.stop.load(Ordering::Acquire) {
            shared.attempts(connector).cancel(&address);
            return BeforeIo::Stopped;
        }
        let outcome = DialOutcome::DialFailed(address, cause);
        Self::record(&mut shared, connector, &outcome, now, rng);
        BeforeIo::Recorded
    }

    /// The task never started, and its guard has already cancelled the
    /// open test. Record the local failure so the outstanding gray cools:
    /// the cause carries no proof, and the open test is already gone, so
    /// there is nothing left to defer. Unless stop has won: then the draw
    /// stays seated and nothing is recorded.
    fn record_unstarted<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: NetworkAddress,
        rng: &mut R,
    ) -> BeforeIo {
        let now = self.hub.now();
        let mut shared = self.shared();
        if self.stop.load(Ordering::Acquire) {
            return BeforeIo::Stopped;
        }
        let outcome = DialOutcome::DialFailed(address, CloseCause::new(CloseKind::LocalClose));
        Self::record(&mut shared, connector, &outcome, now, rng);
        BeforeIo::Recorded
    }

    /// Whether `id` is still enlisted. A posted result stays until it is
    /// applied; absence means the guard released the row.
    fn still_enlisted(&self, id: u64) -> bool {
        self.shared().in_flight.contains_key(&id)
    }

    /// Take `id`'s row for application, or leave it when stop has won.
    ///
    /// The stop flag and the remove share this lock section, the same one
    /// as the insert. Stop set the flag before it drains, so this either
    /// leaves the row for that drain or counts an application stop must
    /// wait for. The count's permit is built after the lock drops: the hub
    /// work that follows is not done under it.
    fn begin_apply(&self, id: u64) -> Option<(InFlight, ApplyPermit<'_>)> {
        let record = {
            let mut shared = self.shared();
            if self.stop.load(Ordering::Acquire) {
                return None;
            }
            let record = shared.in_flight.remove(&id)?;
            shared.applying += 1;
            record
        };
        Some((record, ApplyPermit { dialer: self }))
    }

    /// Apply one taken result. `None` when stop has won or the attempt is
    /// no longer held: the result is dropped, releasing its channel, and a
    /// row stop has not yet drained is left for it.
    fn apply_taken<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        id: u64,
        finished: Finished,
        rng: &mut R,
    ) -> Option<Applied> {
        let Finished { result, ran_nanos } = finished;
        let Some((record, permit)) = self.begin_apply(id) else {
            drop(result);
            return None;
        };
        let address = record.address.clone();
        let kept = match self.apply_result(connector, &address, record.aim, result, rng) {
            Attempt::Done(outcome) => {
                tracing::debug!("{connector:?} dial {address:?} ended: {outcome:?}");
                self.settle_or_retry(connector, &outcome, ran_nanos, rng);
                None
            }
            Attempt::Kept(kept) => {
                let socket = kept.id;
                self.accept_and_notify(connector, &address, kept, rng)
                    .then_some(socket)
            }
        };
        // The nonce leaves the set here, after the result is applied and
        // before stop is told this application is finished.
        drop(record);
        drop(permit);
        Some(Applied { id, address, kept })
    }
}

/// One application [`Dialer::stop`] is waiting on. The decrement takes the
/// dialer lock and wakes stop when it was the last. Drop covers the panic
/// path, so a count cannot outlive the application that incremented it.
struct ApplyPermit<'a> {
    dialer: &'a Dialer,
}

impl Drop for ApplyPermit<'_> {
    fn drop(&mut self) {
        let mut shared = self.dialer.shared();
        shared.applying -= 1;
        if shared.applying == 0 {
            self.dialer.apply_idle.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Completions, Finished};
    use crate::owner::handshake::TaskResult;
    use shekyl_peerlist::{CloseCause, CloseKind, ConnectorId};

    fn failed() -> Finished {
        Finished {
            result: TaskResult::Failed(CloseCause::new(CloseKind::LocalClose)),
            ran_nanos: 0,
        }
    }

    #[test]
    fn a_post_after_the_queue_closes_is_rejected() {
        let completions = Completions::default();
        assert!(completions.post(1, ConnectorId::Clearnet, failed()));
        completions.close();
        assert!(!completions.post(2, ConnectorId::Tor, failed()));
        assert!(completions.take(ConnectorId::Clearnet).is_empty());
        assert!(completions.take(ConnectorId::Tor).is_empty());
    }
}
