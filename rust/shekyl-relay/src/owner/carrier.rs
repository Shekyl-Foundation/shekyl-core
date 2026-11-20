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
use shekyl_levin::{fragmented_notify, NewTransactions, PortableMap, NOTIFY_NEW_TRANSACTIONS};
use shekyl_p2p_session::Established;
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::{Clock, OwnerHandle};
use tokio::sync::mpsc;

use super::actor::{millis, tick_of, Cmd};
use crate::carrier::{Carrier, CarrierView, NoiseDue};
use crate::graph::{Relay, TxBlob};
use crate::noise_queue::{CarrierOutcome, CarrierToken, NoiseQueues};
use crate::stem_watch::TxId;

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
        while self.turn().await {}
        if let Err(_engine_closing) = self.owner.deregister() {}
    }

    /// One turn of the task: a due window, or else one command. `false`
    /// ends the task.
    ///
    /// The wake is served before the inbox: a burst of commands must not
    /// delay a due window, or the delay would follow the node's traffic
    /// (`CVR-R6`). A window sent before a pending view or session change is
    /// applied goes to the old binding or fails its write; both are handled.
    pub(super) async fn turn(&mut self) -> bool {
        tokio::select! {
            biased;
            wake = self.owner.wait_wake_async() => {
                if wake.is_err() {
                    return false;
                }
                self.on_wake();
                true
            }
            cmd = self.inbox.recv() => match cmd {
                None | Some(CarrierCmd::Stop) => false,
                Some(cmd) => {
                    self.on_cmd(cmd);
                    true
                }
            },
        }
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
                    self.report(vec![CarrierOutcome::Discarded {
                        token,
                        started: false,
                    }]);
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
                        // is not written down. The time is when the window
                        // was queued on its session; it can wait at the
                        // link's limiter before it reaches the wire (§93.2a).
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

    pub(super) fn arm(&self) {
        if let Err(_engine_closing) = self.owner.clear() {}
        if let Some(deadline) = self.carrier.deadline() {
            if let Err(_engine_closing) = self.owner.arm(tick_of(deadline)) {}
        }
    }
}

/// A stem the carrier task holds, until it reports what became of it.
pub(super) struct PendingStem {
    pub(super) tx: TxId,
    pub(super) blob: TxBlob,
    pub(super) source: Option<ConnectionId>,
    /// Originated here. Before any byte leaves, a failure waits.
    pub(super) local: bool,
}

/// The relay owner's side of the carrier task.
///
/// The task owns the schedule, the queue and the writers. This owns the
/// tokens, the window the messages are framed to, and the last view the
/// task was told. Cover off is the absence of a link, not a second flag.
pub(super) struct CarrierLink {
    tx: mpsc::UnboundedSender<CarrierCmd>,
    /// The dummy's length: what a carried message is framed to.
    window: usize,
    last_view: CarrierView,
    last_epochs: u64,
    pending: HashMap<u64, PendingStem>,
    next_token: u64,
}

impl CarrierLink {
    pub(super) fn new(tx: mpsc::UnboundedSender<CarrierCmd>, window: usize) -> Self {
        Self {
            tx,
            window,
            last_view: CarrierView::default(),
            last_epochs: 0,
            pending: HashMap::new(),
            next_token: 0,
        }
    }

    pub(super) fn stop(&self) {
        let _gone = self.tx.send(CarrierCmd::Stop);
    }

    pub(super) fn set_session(&self, id: ConnectionId, session: Option<Established>) {
        let _gone = self.tx.send(CarrierCmd::Session { id, session });
    }

    /// The zone's slots and covered sessions, when either changed, and an
    /// epoch boundary when the epoch count moved.
    pub(super) fn tell(&mut self, zone: &Relay) {
        let view = zone.carrier_view();
        let epochs = zone.epochs_started();
        let boundary = epochs != self.last_epochs;
        if view == self.last_view && !boundary {
            return;
        }
        let _gone = self.tx.send(CarrierCmd::View {
            view: view.clone(),
            boundary,
        });
        self.last_view = view;
        self.last_epochs = epochs;
    }

    pub(super) fn holds(&self, tx: &TxId) -> bool {
        self.pending.values().any(|pending| pending.tx == *tx)
    }

    /// Frame `blob` and hand it to `channel`. `true` when the carrier holds
    /// it, including when it already did. `false` when the frame or the
    /// task refused it: the caller takes the no-window path.
    pub(super) fn offer(&mut self, channel: usize, blob: &TxBlob, stem: PendingStem) -> bool {
        if self.holds(&stem.tx) {
            return true;
        }
        let Some(message) = self.frame(blob) else {
            return false;
        };
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.pending.insert(token, stem);
        let handed = self
            .tx
            .send(CarrierCmd::Enqueue {
                channel,
                message,
                token: CarrierToken(token),
            })
            .is_ok();
        if !handed {
            self.pending.remove(&token);
        }
        handed
    }

    pub(super) fn take(&mut self, token: CarrierToken) -> Option<PendingStem> {
        self.pending.remove(&token.0)
    }

    /// One 2002 with the one blob, cut into the carrier's windows.
    fn frame(&self, blob: &TxBlob) -> Option<Vec<u8>> {
        let payload = NewTransactions {
            txs: vec![blob.to_vec()],
            padding: Vec::new(),
            dandelionpp_fluff: false,
        }
        .store()
        .ok()?;
        fragmented_notify(self.window, NOTIFY_NEW_TRANSACTIONS, &payload).ok()
    }
}
