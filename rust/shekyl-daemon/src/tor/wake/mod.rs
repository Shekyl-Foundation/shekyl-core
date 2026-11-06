// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What ends one wait of the Tor supervisor's loop (`TOR_SUPERVISOR.md` §5).
//!
//! The wait classifies a sleep after it returns, whichever branch won. The
//! timer stands ahead of control events, so a stream of events cannot hold
//! a deadline off. Events already queued when the timer wins are drained
//! here and folded before that deadline.
//!
//! A closed sender takes its own source out of the wait ([`live`]). The
//! wait does not return for that close, except the stop's: the daemon is
//! stopping, and it is said once. The bootstrap watch is the other end
//! that means something. It leaves after `Ready` or `Failed`, or when its
//! sender closes with nothing new to say. The timer closing ends the
//! driver; that close is a wake.

mod live;

pub(super) use live::Live;

use std::net::SocketAddr;
use std::time::Duration;

use shekyl_p2p::{OriginVerdict, ProbeArrival, TorLinkTally};
use shekyl_timing_engine::{Clock, OwnerHandle};
use shekyl_tor_control_client::control::{
    resume_lateness, BootstrapState, ControlReply, EventReceiver, Resume,
};
use shekyl_tor_control_client::supervisor::Input;
use shekyl_tor_control_daemon::TorDeath;
use tokio::sync::{mpsc, watch};

/// What the loop waits on, borrowed from the driver for one wait.
///
/// Each [`Live`] source leaves on its own when its sender closes. The
/// bootstrap watch is an incarnation's receiver: [`next_bootstrap`] takes
/// it out of this `Option`.
pub(super) struct Sources<'a> {
    pub(super) stop: &'a mut Live<watch::Receiver<bool>>,
    pub(super) forward: &'a mut Live<watch::Receiver<Option<SocketAddr>>>,
    pub(super) origin: &'a mut Live<watch::Receiver<OriginVerdict>>,
    pub(super) tor_link: &'a mut Live<watch::Receiver<TorLinkTally>>,
    pub(super) probe_arrivals: &'a mut Live<watch::Receiver<Option<ProbeArrival>>>,
    pub(super) incoming: &'a mut Live<EventReceiver>,
    pub(super) death: &'a mut Live<mpsc::Receiver<(u64, TorDeath)>>,
    pub(super) bootstrap: &'a mut Option<watch::Receiver<BootstrapState>>,
}

/// What ended a wait. Each branch reads its value and nothing more; the
/// driver folds it after the sleep check.
#[derive(Debug)]
pub(super) enum Woken {
    /// The stop flag moved. `stopping` when the daemon is stopping, or the
    /// sender is gone. The sender's end is said once, then the source has
    /// left the wait.
    Stop { stopping: bool },
    /// The forward listener moved. `bound` when it is bound. The first wait
    /// also sees a forward bound before the loop: the receiver has not
    /// marked the current value seen.
    Forward { bound: bool },
    /// The relay's hop-0 verdict moved.
    Origin(OriginVerdict),
    /// The Tor dial tally moved.
    TorLink(TorLinkTally),
    /// A probe's nonce came back. Biased ahead of the timer, so a take
    /// already in the cell is folded before a bound that has also elapsed;
    /// the core still compares the take's own time with the bound.
    ProbeArrived(Option<ProbeArrival>),
    /// The armed deadline fired, or the scheduler closed.
    Timer { closed: bool },
    /// An event from Tor. The sink closing is not an event: the source
    /// leaves the wait.
    Event(ControlReply),
    /// A Tor process ended. The channel closing is not a death: the source
    /// leaves the wait.
    Death { generation: u64, how: TorDeath },
    /// The bootstrap watch moved, to this state. After `Ready` or
    /// `Failed` the watch has left the wait.
    Bootstrap(BootstrapState),
}

/// A wait that returned: what woke it, when, and the sleep it observed.
#[derive(Debug)]
pub(super) struct Wake {
    pub(super) what: Woken,
    pub(super) woke: u64,
    resumed: Option<Duration>,
}

impl Wake {
    /// The sleep the wait observed, as the input folded ahead of what woke it.
    pub(super) fn lead(&self) -> Option<Input> {
        self.resumed.map(|late_by| Input::Resumed { late_by })
    }
}

/// Wait for the next thing to do. The wait itself says whether the machine
/// slept (§5, "Resumed from suspend"): it returned at `woke`, and a return
/// more than `control::RESUMED_AFTER` past the deadline it was armed with
/// means the process did not run, whatever woke it. At a wake the dialer's
/// timers fire too, so a dial result can be ready with the late timer and
/// win the biased order; it is judged after the sleep is folded, on windows
/// that start at the wake. With no deadline armed nothing can be late.
pub(super) async fn wait<C: Clock>(
    sources: Sources<'_>,
    owner: &OwnerHandle<C>,
    armed: Option<u64>,
    entered: u64,
) -> Wake {
    // Each pass either returns what woke it or has taken a closed source
    // out of the wait. A source that has left pends, and the timer stays
    // in, so the select always has a branch.
    let what = loop {
        tokio::select! {
            biased;
            // The flag's value, or the sender closing. Closing is the
            // daemon stopping, and `None` has taken the source out, so
            // it is said once.
            moved = sources.stop.changed() => {
                break Woken::Stop {
                    stopping: moved.unwrap_or(true),
                };
            }
            moved = sources.forward.changed() => {
                if let Some(bound) = moved {
                    break Woken::Forward {
                        bound: bound.is_some(),
                    };
                }
            }
            moved = sources.origin.changed() => {
                if let Some(verdict) = moved {
                    break Woken::Origin(verdict);
                }
            }
            moved = sources.tor_link.changed() => {
                if let Some(tally) = moved {
                    break Woken::TorLink(tally);
                }
            }
            moved = sources.probe_arrivals.changed() => {
                if let Some(arrival) = moved {
                    break Woken::ProbeArrived(arrival);
                }
            }
            wake = owner.wait_wake_async() => break Woken::Timer { closed: wake.is_err() },
            event = sources.incoming.recv() => {
                if let Some(event) = event {
                    break Woken::Event(event);
                }
            }
            death = sources.death.recv() => {
                if let Some((generation, how)) = death {
                    break Woken::Death { generation, how };
                }
            }
            state = next_bootstrap(sources.bootstrap) => {
                if let Some(state) = state {
                    break Woken::Bootstrap(state);
                }
            }
        }
    };
    let woke = super::now(owner);
    Wake {
        what,
        woke,
        resumed: slept(armed, entered, woke),
    }
}

/// How late a wait armed with `armed` at `entered` returned at `woke`, when
/// that is a sleep ([`resume_lateness`]). A deadline already past when the
/// wait began has no time left: a return more than `RESUMED_AFTER` later
/// is still a sleep.
fn slept(armed: Option<u64>, entered: u64, woke: u64) -> Option<Duration> {
    let due = armed?;
    let until_due = Duration::from_nanos(due.saturating_sub(entered));
    let waited = Duration::from_nanos(woke.saturating_sub(entered));
    match resume_lateness(until_due, waited) {
        Resume::Slept { late_by } => Some(late_by),
        Resume::Awake => None,
    }
}

/// The batch a wait folds: the sleep it observed first, then what woke it.
pub(super) fn led(lead: Option<Input>, inputs: Vec<Input>) -> Vec<Input> {
    lead.into_iter().chain(inputs).collect()
}

/// The inputs of a wake that needs none of the driver's state. The timer,
/// an event, a death and the bootstrap watch are the driver's to read
/// and give nothing here.
pub(super) fn plain_inputs(what: &Woken) -> Vec<Input> {
    match what {
        Woken::Stop { stopping } => stopping.then_some(Input::Shutdown).into_iter().collect(),
        Woken::Forward { bound } => bound.then_some(Input::EndpointReady).into_iter().collect(),
        Woken::Origin(verdict) => vec![super::verdict_input(*verdict)],
        Woken::TorLink(tally) => vec![super::tally_input(*tally)],
        Woken::ProbeArrived(arrival) => arrival
            .map(|arrival| {
                tracing::info!(target: "tor", "this node's onion probe arrived");
                Input::ProbeArrived {
                    minted_at: arrival.minted_at.get(),
                    arrived_at: arrival.arrived_at.get(),
                }
            })
            .into_iter()
            .collect(),
        Woken::Timer { .. } | Woken::Event(_) | Woken::Death { .. } | Woken::Bootstrap(_) => {
            Vec::new()
        }
    }
}

/// The bootstrap watch's next state. `None` when its sender closed with
/// nothing new to say: the watch has left the wait. After `Ready` or
/// `Failed` it leaves the wait too; nothing follows either, and the
/// sender may still be held, which is why this is not a [`Live`]. With
/// no watch in hand this never resolves.
async fn next_bootstrap(
    bootstrap: &mut Option<watch::Receiver<BootstrapState>>,
) -> Option<BootstrapState> {
    let Some(watch) = bootstrap else {
        return std::future::pending().await;
    };
    if watch.changed().await.is_err() {
        *bootstrap = None;
        return None;
    }
    let state = *watch.borrow_and_update();
    if matches!(state, BootstrapState::Ready | BootstrapState::Failed) {
        *bootstrap = None;
    }
    Some(state)
}

/// Events already held when a wait ends. The first empty read stops it, so
/// an event that arrives while this runs waits for the next loop: the timer
/// that won this wait is not held off by a stream of new ones.
pub(super) fn take_queued(incoming: &mut EventReceiver) -> Vec<ControlReply> {
    let mut queued = Vec::new();
    while let Ok(reply) = incoming.try_recv() {
        queued.push(reply);
    }
    queued
}

#[cfg(test)]
mod tests;
