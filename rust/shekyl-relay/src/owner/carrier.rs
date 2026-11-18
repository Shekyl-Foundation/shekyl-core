// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier task: the schedule, the bindings, the queue and the windows
//! on the wire, apart from the relay owner (`CVR-R6`; Rick, 2026-11-18).
//!
//! **Why apart.** On 2026-11-05 the relay owner blocked behind the pool's
//! commit for 28 s and 32 s, and the carrier, which wrote its windows from
//! that owner's turn, went silent on both channels for as long: an
//! observable timing event on the cover link. Staging one window ahead
//! would survive a stall of one gap, and a gap can be ten milliseconds; to
//! survive a long one, whatever emits needs the next deadline, the peer,
//! the tail count, the queue and a dummy without asking the owner. So all
//! of them live here, and a busy owner delays what it hands the carrier —
//! a new message, a new view of the slots — never a window.
//!
//! **What crosses.** The owner sends [`CarrierCmd`]s: its view of the stem
//! slots and the covered sessions (and whether an epoch began since the
//! last view), each message to carry, and the session handles. The task
//! sends back what became of each message — sent to a peer, or discarded,
//! a refusal at the door included — as one [`super::actor::Cmd`] per batch
//! of outcomes. The task never reads the zone; the owner never reads the
//! queue.

use std::collections::HashMap;

use shekyl_draw_rng::RelayRng;
use shekyl_p2p_session::Established;
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::{Clock, OwnerHandle};
use tokio::sync::mpsc;

use super::actor::{millis, tick_of, Cmd};
use crate::carrier::{Carrier, CarrierView, NoiseDue};
use crate::noise_queue::{CarrierOutcome, CarrierToken, NoiseQueues};

/// What the relay owner tells the carrier task.
pub(super) enum CarrierCmd {
    /// The owner's view of the slots and the covered sessions changed.
    /// `boundary` when an epoch began since the last view: every channel
    /// starts its tail.
    View { view: CarrierView, boundary: bool },
    /// Carry `message` on `channel`. A refusal comes back as a discard.
    Enqueue {
        channel: usize,
        message: Vec<u8>,
        token: CarrierToken,
    },
    /// A session the carrier may write to, or `None` once it is gone.
    Session {
        id: ConnectionId,
        session: Option<Established>,
    },
    /// End the task.
    Stop,
}

/// The task's state.
pub(super) struct CarrierTask<C: Clock + Clone + Send + Sync + 'static> {
    pub(super) carrier: Carrier,
    pub(super) queues: NoiseQueues,
    pub(super) sessions: HashMap<ConnectionId, Established>,
    pub(super) rng: Box<dyn RelayRng + Send>,
    pub(super) owner: OwnerHandle<C>,
    pub(super) inbox: mpsc::UnboundedReceiver<CarrierCmd>,
    pub(super) to_owner: mpsc::UnboundedSender<Cmd>,
}

impl<C: Clock + Clone + Send + Sync + 'static> CarrierTask<C> {
    pub(super) async fn run(mut self) {
        self.arm();
        loop {
            tokio::select! {
                biased;
                cmd = self.inbox.recv() => match cmd {
                    None | Some(CarrierCmd::Stop) => break,
                    Some(cmd) => self.on_cmd(cmd),
                },
                wake = self.owner.wait_wake_async() => {
                    if wake.is_err() {
                        break;
                    }
                    self.on_wake();
                }
            }
        }
        if let Err(_engine_closing) = self.owner.deregister() {}
    }

    fn on_cmd(&mut self, cmd: CarrierCmd) {
        match cmd {
            CarrierCmd::View { view, boundary } => {
                self.carrier.set_view(view);
                if boundary {
                    self.carrier.begin_tails();
                }
            }
            CarrierCmd::Enqueue {
                channel,
                message,
                token,
            } => {
                if !self.queues.enqueue(channel, message, token) {
                    self.report(vec![CarrierOutcome::Discarded(token)]);
                }
            }
            CarrierCmd::Session { id, session } => match session {
                Some(session) => {
                    self.sessions.insert(id, session);
                }
                None => {
                    self.sessions.remove(&id);
                }
            },
            CarrierCmd::Stop => {}
        }
    }

    /// One due channel per wake: several at one instant would be a
    /// synchronized burst. A channel still past due re-arms the wake at once.
    fn on_wake(&mut self) {
        let now = millis(self.owner.clock().now());
        match self.carrier.due(now, &mut *self.rng) {
            Some(NoiseDue::Send {
                channel,
                peer,
                starts,
            }) => {
                // `take_for_send` hands back the same window until a
                // resolution: `sent` advances one fragment, `failed`
                // restarts the channel so a partly sent message is never
                // finished to a different successor.
                if let Some(send) = self.queues.take_for_send(channel, peer, starts) {
                    let written = self
                        .sessions
                        .get(&peer)
                        .is_some_and(|session| session.send_window(send.bytes()).is_ok());
                    if written {
                        // Timestamp and size only: the realised cadence is
                        // read from these lines (`DAEMON_RELAY_PRIVACY.md`
                        // §97); whether a window carried a stem or a dummy
                        // is not written down.
                        tracing::debug!(
                            channel,
                            ?peer,
                            bytes = send.bytes().len(),
                            "a carrier window was written"
                        );
                        send.sent(&mut self.queues);
                    } else {
                        send.failed(&mut self.queues);
                    }
                }
            }
            Some(NoiseDue::Unbind { channel }) => self.queues.unbind(channel),
            None => {}
        }
        let outcomes = self.queues.take_resolved();
        if !outcomes.is_empty() {
            self.report(outcomes);
        }
        self.arm();
    }

    fn report(&self, outcomes: Vec<CarrierOutcome>) {
        // The owner gone means the node is stopping: nothing to report to.
        let _gone = self.to_owner.send(Cmd::Carrier(outcomes));
    }

    fn arm(&self) {
        if let Err(_engine_closing) = self.owner.clear() {}
        if let Some(deadline) = self.carrier.deadline() {
            if let Err(_engine_closing) = self.owner.arm(tick_of(deadline)) {}
        }
    }
}
