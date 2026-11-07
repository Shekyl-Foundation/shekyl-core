// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the Tor supervisor's loop waits on (`TOR_SUPERVISOR.md` §5): one
//! queue and one doorbell.
//!
//! - **The queue** holds what happened, in the order it happened: Tor's
//!   events, a process's death and its bootstrap transitions, a probe's
//!   arrival, a deadline, and the stop. Every producer posts and never
//!   waits.
//! - **The cells** hold state, latest value only: the dial tally, the
//!   relay's verdict, the sessions each connector holds, and the forward
//!   listener. A change rings the doorbell. A value the loop has not taken
//!   is replaced, never queued.
//!
//! A producer that ends stops posting and stops ringing, and nothing in the
//! loop waits on its end: the loop cannot spin on a closed source. Only the
//! [`Owner`], which [`super::Supervisor`] holds, keeps the queue open; every
//! other producer holds it weakly. The queue closing is the stop.
//!
//! The deadline is a producer too. The [`Timer`] keeps the engine armed for
//! the deadline the loop wants and posts it, tagged with the generation the
//! loop gave it, when it comes due. A deadline the loop has since replaced
//! carries an old generation and is ignored. No arm is cleared and armed
//! again, and no wake already delivered can fire a deadline the loop no
//! longer wants.
//!
//! A deadline is the one arrival that carries no fact: it says the clock
//! passed an instant, and the loop judges it at the moment it folds it.
//! Everything already queued behind it happened before that moment, so the
//! inbox hands those out first ([`Inbox::wait`]): a probe's nonce taken
//! inside its bound is folded before the deadline that would time it out.
//!
//! A control ask to Tor runs between waits and can take seconds. The stop
//! must still end it, and the ask cannot read the queue without taking the
//! inputs behind the stop. So closing the queue also sets the inbox's stop
//! latch, which an ask races ([`StopLatch`]). The stop itself is still the
//! queue's close, said once: the loop folds it in its turn.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use shekyl_p2p::{
    OriginVerdict, PerConnector, ProbeArrival, ProbeSink, SupervisorFeeds, TorLinkTally,
};
use shekyl_timing_engine::{Clock, OwnerHandle, Tick};
use shekyl_tor_control_client::control::{
    BootstrapState, ControlReply, EventSink, Fed, EVENT_QUEUE_EVENTS,
};
use shekyl_tor_control_daemon::TorDeath;
use tokio::sync::{mpsc, watch, Notify};

/// One thing that happened, in the order it was posted.
#[derive(Debug)]
pub(super) enum Arrival {
    /// An event from Tor.
    Event(ControlReply),
    /// The process of `generation` ended.
    Death { generation: u64, how: TorDeath },
    /// The bootstrap of `generation` moved, to this state.
    Bootstrap {
        generation: u64,
        state: BootstrapState,
    },
    /// A probe's nonce came back through this node's onion.
    Probe(ProbeArrival),
    /// The deadline the loop gave `generation` came due.
    Deadline { generation: u64 },
    /// The daemon is stopping.
    Stop,
}

/// The cells: each holds a value the loop has not taken yet, or nothing.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Changed {
    /// The dialer's tally of this node's Tor dials.
    pub(super) tally: Option<TorLinkTally>,
    /// The relay's hop-0 verdict for a local origin.
    pub(super) verdict: Option<OriginVerdict>,
    /// The sessions each connector holds.
    pub(super) sessions: Option<PerConnector<u32>>,
    /// The zone host's forward listener, once bound.
    pub(super) forward: Option<SocketAddr>,
}

/// What the loop and every producer share.
struct Shared {
    cells: Mutex<Changed>,
    doorbell: Notify,
    stopping: AtomicBool,
    stop_rung: Notify,
    /// Tor events posted and not yet taken: the event feed's bound.
    events_held: AtomicUsize,
}

impl Shared {
    /// Store a value into its cell and ring. Never waits: the lock is held
    /// for the store alone.
    fn set(&self, store: impl FnOnce(&mut Changed)) {
        store(&mut self.cells.lock().expect("supervisor cells"));
        self.doorbell.notify_one();
    }

    fn latch_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.stop_rung.notify_waiters();
    }
}

/// Make the supervisor's inbox: its owner, the loop's end, and the feeds
/// the network publishes into. Made before the network starts, so its
/// producers publish into it from their first value.
pub(super) fn inbox() -> (Owner, Inbox, SupervisorFeeds) {
    let shared = Arc::new(Shared {
        cells: Mutex::new(Changed::default()),
        doorbell: Notify::new(),
        stopping: AtomicBool::new(false),
        stop_rung: Notify::new(),
        events_held: AtomicUsize::new(0),
    });
    let (queue, receiver) = mpsc::unbounded_channel();
    let poster = Poster {
        queue: queue.downgrade(),
        shared: Arc::downgrade(&shared),
    };
    let feeds = poster.feeds();
    let owner = Owner {
        queue: Some(queue),
        shared: Arc::clone(&shared),
    };
    let inbox = Inbox {
        queue: receiver,
        ahead: VecDeque::new(),
        closed: false,
        shared,
        poster,
    };
    (owner, inbox, feeds)
}

/// The end that keeps the queue open: [`super::Supervisor`]'s. Dropping it
/// closes the queue, which the loop reads as the stop.
pub(super) struct Owner {
    queue: Option<mpsc::UnboundedSender<Arrival>>,
    shared: Arc<Shared>,
}

impl Owner {
    /// The forward listener is bound.
    pub(super) fn forward(&self, at: SocketAddr) {
        self.shared.set(|cells| cells.forward = Some(at));
    }

    /// Close the queue. That close is the stop, said once, and it sets the
    /// latch an ask races. Posting a stop as well would say it a second time
    /// when the loop reads the close.
    pub(super) fn stop(&mut self) {
        self.queue.take();
        self.shared.latch_stop();
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A producer's end: it posts and rings while the inbox lives, and does
/// nothing after.
#[derive(Clone)]
pub(super) struct Poster {
    queue: mpsc::WeakUnboundedSender<Arrival>,
    shared: Weak<Shared>,
}

impl Poster {
    /// Post `arrival`. Nothing happens when the inbox is gone.
    pub(super) fn post(&self, arrival: Arrival) {
        if let Some(queue) = self.queue.upgrade() {
            let _posted = queue.send(arrival);
        }
    }

    fn set(&self, store: impl FnOnce(&mut Changed)) {
        if let Some(shared) = self.shared.upgrade() {
            shared.set(store);
        }
    }

    /// The feeds the network publishes into.
    fn feeds(&self) -> SupervisorFeeds {
        let tally = self.clone();
        let verdict = self.clone();
        let sessions = self.clone();
        SupervisorFeeds {
            tally: Arc::new(move |value| tally.set(|cells| cells.tally = Some(value))),
            probes: Arc::new(self.clone()),
            verdict: Arc::new(move |value| verdict.set(|cells| cells.verdict = Some(value))),
            sessions: Arc::new(move |value| sessions.set(|cells| cells.sessions = Some(value))),
        }
    }

    /// The sink Tor's control connection routes its events into: the queue,
    /// holding at most [`EVENT_QUEUE_EVENTS`] not yet taken (`TSR-F2`). A
    /// full one drops the event, and the sink counts it.
    pub(super) fn events(&self) -> EventSink {
        let poster = self.clone();
        EventSink::feeding(move |reply| {
            let (Some(queue), Some(shared)) = (poster.queue.upgrade(), poster.shared.upgrade())
            else {
                return Fed::Gone;
            };
            if shared.events_held.fetch_add(1, Ordering::AcqRel) >= EVENT_QUEUE_EVENTS {
                shared.events_held.fetch_sub(1, Ordering::AcqRel);
                return Fed::Full;
            }
            if queue.send(Arrival::Event(reply)).is_err() {
                shared.events_held.fetch_sub(1, Ordering::AcqRel);
                return Fed::Gone;
            }
            Fed::Held
        })
    }
}

impl ProbeSink for Poster {
    fn probe_arrived(&self, arrival: ProbeArrival) {
        self.post(Arrival::Probe(arrival));
    }
}

/// What ended a wait: the next arrival, or the doorbell.
#[derive(Debug)]
pub(super) enum Woken {
    /// The next thing that happened.
    Arrived(Arrival),
    /// A cell changed.
    Rang,
}

/// The loop's end.
pub(super) struct Inbox {
    queue: mpsc::UnboundedReceiver<Arrival>,
    /// Arrivals taken from the queue to go ahead of a deadline, the
    /// deadline last. Handed out before the queue is read again.
    ahead: VecDeque<Arrival>,
    /// The queue has closed and said so: it is read no more.
    closed: bool,
    shared: Arc<Shared>,
    poster: Poster,
}

impl Inbox {
    /// The next arrival, or the doorbell. Arrivals come first, in order,
    /// except that a deadline goes after every arrival already queued
    /// behind it when it is taken ([`Self::behind_queued`]).
    ///
    /// A closed queue is the stop, said once. A closed queue answers at
    /// once, every time, so after that it is not read: the loop that keeps
    /// waiting hears only the doorbell, and cannot spin.
    pub(super) async fn wait(&mut self) -> Woken {
        if let Some(arrival) = self.ahead.pop_front() {
            return Woken::Arrived(arrival);
        }
        if self.closed {
            self.shared.doorbell.notified().await;
            return Woken::Rang;
        }
        tokio::select! {
            biased;
            arrival = self.queue.recv() => match arrival {
                Some(Arrival::Deadline { generation }) => self.behind_queued(generation),
                Some(arrival) => self.taken(arrival),
                None => {
                    self.closed = true;
                    Woken::Arrived(Arrival::Stop)
                }
            },
            () = self.shared.doorbell.notified() => Woken::Rang,
        }
    }

    fn taken(&self, arrival: Arrival) -> Woken {
        self.count_taken(&arrival);
        Woken::Arrived(arrival)
    }

    /// A Tor event taken off the queue makes room for another
    /// ([`EVENT_QUEUE_EVENTS`]).
    fn count_taken(&self, arrival: &Arrival) {
        if matches!(arrival, Arrival::Event(_)) {
            self.shared.events_held.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// The deadline `generation`, after the arrivals queued behind it now.
    ///
    /// The loop folds a deadline at the moment it takes it, and an arrival
    /// already queued happened before that moment. Folded after it, a
    /// probe's nonce taken inside its bound would find the probe already
    /// timed out by a deadline the loop reached late, a control ask having
    /// held it. Only what is queued when the deadline is taken goes ahead:
    /// an event stream that keeps arriving cannot hold the deadline back.
    fn behind_queued(&mut self, generation: u64) -> Woken {
        let queued = self.queue.len();
        for _ in 0..queued {
            let Ok(arrival) = self.queue.try_recv() else {
                break;
            };
            self.count_taken(&arrival);
            self.ahead.push_back(arrival);
        }
        let deadline = Arrival::Deadline { generation };
        match self.ahead.pop_front() {
            Some(first) => {
                self.ahead.push_back(deadline);
                Woken::Arrived(first)
            }
            None => Woken::Arrived(deadline),
        }
    }

    /// Every cell's value not yet taken.
    pub(super) fn take_changed(&self) -> Changed {
        std::mem::take(&mut self.shared.cells.lock().expect("supervisor cells"))
    }

    /// The stop latch, for an ask that borrows the driver.
    pub(super) fn latch(&self) -> StopLatch {
        StopLatch {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A producer's end.
    pub(super) fn poster(&self) -> Poster {
        self.poster.clone()
    }
}

/// The stop as an ask sees it: set once the owner closes the queue.
#[derive(Clone)]
pub(super) struct StopLatch {
    shared: Arc<Shared>,
}

impl StopLatch {
    /// Resolves once the owner has closed the queue.
    pub(super) async fn stopped(&self) {
        loop {
            let rung = self.shared.stop_rung.notified();
            if self.shared.stopping.load(Ordering::Acquire) {
                return;
            }
            rung.await;
        }
    }
}

/// The deadline the loop wants, and the generation it gave it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Wanted {
    pub(super) generation: u64,
    pub(super) at: u64,
}

/// The producer that keeps the engine armed for the loop's deadline and
/// posts it when due.
pub(super) struct Timer {
    wanted: watch::Sender<Option<Wanted>>,
    next: u64,
}

impl Timer {
    /// Start the timer on `owner`, posting through `poster`. It ends when
    /// this handle drops or the engine closes: then nothing posts a
    /// deadline, and nothing waits on that end.
    pub(super) fn start<C: Clock + Send + Sync + 'static>(
        owner: OwnerHandle<C>,
        poster: Poster,
    ) -> Self {
        let (wanted, watched) = watch::channel(None);
        tokio::spawn(keep_armed(owner, watched, poster));
        Self { wanted, next: 0 }
    }

    /// The loop folded the deadline it wanted: the next one it wants gets a
    /// new generation, even at the same instant, and is armed again.
    pub(super) fn spent(&mut self) {
        self.wanted.send_replace(None);
    }

    /// The loop wants `deadline`, or none. A deadline unchanged keeps its
    /// generation; a new one gets the next. The generation does not wrap:
    /// zero is never issued, and a wrapped zero would alias a generation
    /// the loop has already folded.
    pub(super) fn want(&mut self, deadline: Option<u64>) -> Option<Wanted> {
        let current = *self.wanted.borrow();
        let wanted = match (current, deadline) {
            (_, None) => None,
            (Some(current), Some(at)) if current.at == at => Some(current),
            (_, Some(at)) => {
                self.next = self
                    .next
                    .checked_add(1)
                    .expect("deadline generation space exhausted");
                Some(Wanted {
                    generation: self.next,
                    at,
                })
            }
        };
        self.wanted.send_if_modified(|held| {
            let moved = *held != wanted;
            *held = wanted;
            moved
        });
        wanted
    }
}

/// Keep `owner` armed for the deadline `wanted` holds, and post it once,
/// when the clock reaches it. The engine keeps only the earlier of two
/// hints, so a deadline moved later fires its old hint first: the clock is
/// short of the new one, and it is armed again. A generation already posted
/// is not armed again, and its timer waits only for the loop to want
/// another. A wake that names no deadline still wanted, one delivered
/// before the deadline moved among them, posts nothing.
async fn keep_armed<C: Clock + Send + Sync + 'static>(
    owner: OwnerHandle<C>,
    mut wanted: watch::Receiver<Option<Wanted>>,
    poster: Poster,
) {
    let mut posted = None;
    loop {
        let armed =
            (*wanted.borrow_and_update()).filter(|current| Some(current.generation) != posted);
        if let Some(Wanted { at, .. }) = armed {
            if owner.arm(Tick::new(at)).is_err() {
                return;
            }
        }
        tokio::select! {
            moved = wanted.changed() => {
                if moved.is_err() {
                    return;
                }
            }
            wake = owner.wait_wake_async(), if armed.is_some() => {
                if wake.is_err() {
                    return;
                }
                let now = owner.clock().now().get();
                if let Some(Wanted { generation, at }) = armed {
                    if now >= at {
                        poster.post(Arrival::Deadline { generation });
                        posted = Some(generation);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
