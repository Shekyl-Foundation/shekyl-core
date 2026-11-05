// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One session's task (brief §7.1–§7.7).
//!
//! The task owns the receive half, the bucket reader, the session's
//! timing-engine owner and the one-permit semaphore. It is the one writer
//! of the session's state: `Handshaking` until the handshake completes in
//! the direction the connection was made, `Established` until an end is
//! recorded, then gone. Every bucket it reads goes through one `match`
//! over [`Command`]; a bucket the state does not accept is a form failure
//! and closes the session.
//!
//! The permit (`SESSION_QUEUE_DEPTH` = 1) is taken before a bucket is
//! parsed. A bucket the layer handles itself returns it at once; a bucket
//! an owner handles travels with it as the owner's [`Taken`], and the
//! next frame is read when the owner drops it.

use std::sync::Arc;

use shekyl_capped_stream::Session;
use shekyl_levin::{
    BucketReader, Command, CoreSyncData, GetTxpoolComplement, NewTransactions, PortableMap,
    Received, TimedSyncRequest, TimedSyncResponse, DEFAULT_MAX_PACKET_SIZE,
};
use shekyl_timing_engine::{Clock, OwnerClass};
use shekyl_transport_layer::{ConnectorId, DialEnd, SocketId, StreamEnd};
use tokio::sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore};

use crate::handle::Established;
use crate::handshake;
use crate::layer::{DialAim, DialOutcome, Shared, SESSION_QUEUE_DEPTH};
use crate::nonce::{InFlightNonce, NonceTake};
use crate::owners::{ClaimCarrier, ProbeArrival, SyncInbound, Taken};
use crate::timing::{after, ticks, Deadlines, Due};

/// Which direction the connection was made, and what the outbound side
/// carries until its response arrives.
pub(crate) enum Role {
    Inbound,
    Outbound {
        request: Vec<u8>,
        nonce: InFlightNonce,
        aim: DialAim,
        reply: oneshot::Sender<Result<DialOutcome, DialEnd>>,
    },
}

enum State {
    Handshaking(Role),
    Established(Established),
    /// A form failure, a deadline, or the peer's end was observed in the
    /// task: the end is recorded and the task is leaving.
    Closing,
}

/// Why the read loop stopped.
enum Stop {
    /// The layer recorded an end; the task was told.
    Told,
    /// The task observed the end itself.
    Observed(DialEnd),
}

/// The session task. Runs until an end is recorded or observed; then the
/// row is taken out and the owners told.
pub(crate) async fn run<C: Clock + Clone + Send + Sync + 'static>(
    shared: Arc<Shared<C>>,
    id: SocketId,
    connector: ConnectorId,
    session: Session,
    gap: Option<oneshot::Sender<()>>,
    stop: Arc<Notify>,
    role: Role,
) {
    let (fallback, left) = {
        let mut task = match Task::start(&shared, id, connector, session, gap, role) {
            Ok(task) => task,
            Err(role) => {
                // No timing-engine owner: the daemon is stopping.
                let end = DialEnd::local_close_after_channel();
                shared.close(id, end);
                let (_, end) = shared.finish(id, end);
                if let Role::Outbound { reply, .. } = role {
                    answer(reply.send(Err(end)));
                }
                return;
            }
        };
        let stop = match task.serve(&stop).await {
            Stop::Told => DialEnd::local_close_after_channel(),
            Stop::Observed(end) => end,
        };
        (stop, std::mem::replace(&mut task.state, State::Closing))
    };
    let (facts, end) = shared.finish(id, fallback);
    // A dial whose handshake never completed learns the row's end.
    if let State::Handshaking(Role::Outbound { reply, .. }) = left {
        answer(reply.send(Err(end)));
    }
    tracing::debug!(
        id = ?facts.id,
        connector = ?facts.connector(),
        established = facts.established,
        cause = ?end.cause().kind(),
        "session finished"
    );
}

struct Task<'a, C: Clock + Clone> {
    shared: &'a Arc<Shared<C>>,
    id: SocketId,
    session: Session,
    reader: BucketReader,
    deadlines: Deadlines<C>,
    permits: Arc<Semaphore>,
    gap: Option<oneshot::Sender<()>>,
    state: State,
    connector: ConnectorId,
}

impl<'a, C: Clock + Clone + Send + Sync + 'static> Task<'a, C> {
    fn start(
        shared: &'a Arc<Shared<C>>,
        id: SocketId,
        connector: ConnectorId,
        session: Session,
        gap: Option<oneshot::Sender<()>>,
        role: Role,
    ) -> Result<Self, Role> {
        let Ok(owner) = shared.timing.register(OwnerClass::TimedSync) else {
            return Err(role);
        };
        Ok(Self {
            shared,
            id,
            session,
            reader: BucketReader::new(),
            deadlines: Deadlines::new(owner),
            permits: Arc::new(Semaphore::new(SESSION_QUEUE_DEPTH)),
            gap,
            state: State::Handshaking(role),
            connector,
        })
    }

    /// Arm the opening deadline and send the opening request, then read
    /// until the session ends.
    async fn serve(&mut self, stop: &Notify) -> Stop {
        let now = self.deadlines.now();
        match &mut self.state {
            State::Handshaking(Role::Inbound) => {
                let within = self.shared.config.handshake_within.get(self.connector);
                self.deadlines.set_handshake(after(now, ticks(within)));
            }
            State::Handshaking(Role::Outbound { request, .. }) => {
                let request = std::mem::take(request);
                if let Err(refused) = self.shared.send_bytes(self.id, request) {
                    tracing::debug!(id = ?self.id, %refused, "handshake request not queued");
                    return Stop::Told;
                }
                let timeout = ticks(self.shared.config.intervals.invoke_timeout);
                self.deadlines.set_invoke(after(now, timeout));
            }
            State::Established(_) | State::Closing => {}
        }
        self.read_loop(stop).await
    }

    async fn read_loop(&mut self, stop: &Notify) -> Stop {
        loop {
            if let State::Closing = self.state {
                return Stop::Told;
            }
            // The permit first: a message the owner still holds stalls
            // the parse, and the peer's bytes wait in the stream.
            let permit = tokio::select! {
                biased;
                () = stop.notified() => return Stop::Told,
                wake = self.deadlines.owner().wait_wake_async() => {
                    if wake.is_err() {
                        // The engine closed: the daemon is stopping.
                        return Stop::Told;
                    }
                    self.on_wake();
                    continue;
                }
                permit = Arc::clone(&self.permits).acquire_owned() => {
                    permit.expect("the session's semaphore is never closed")
                }
            };
            let received = loop {
                match self.reader.next_message() {
                    Ok(Some(received)) => break received,
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(id = ?self.id, ?error, "levin framing error");
                        self.close(self.form_end());
                        return Stop::Told;
                    }
                }
                tokio::select! {
                    biased;
                    () = stop.notified() => return Stop::Told,
                    wake = self.deadlines.owner().wait_wake_async() => {
                        if wake.is_err() {
                            return Stop::Told;
                        }
                        self.on_wake();
                        if let State::Closing = self.state {
                            return Stop::Told;
                        }
                    }
                    frame = self.session.recv() => {
                        let Some(frame) = frame else {
                            // The connector closed the inbound end and
                            // stored what it saw, or nothing.
                            let end = self
                                .session
                                .stored_end()
                                .unwrap_or_else(|| {
                                    self.shared.stream_end(self.connector, StreamEnd::PeerClosed)
                                });
                            return Stop::Observed(end);
                        };
                        if let Err(error) = self.reader.feed(&frame) {
                            tracing::debug!(id = ?self.id, ?error, "levin framing error");
                            self.close(self.form_end());
                            return Stop::Told;
                        }
                    }
                }
            };
            self.dispatch(received, permit);
        }
    }

    /// The end a bucket the session's form does not admit carries: while
    /// this node's own dial waits for its handshake response, the dialed
    /// peer's refusal (`handshake::handshake_refused`, judged against the
    /// address); on an inbound handshake or an established session, a form
    /// failure (`handshake::form_failure`, local).
    fn form_end(&self) -> DialEnd {
        match self.state {
            State::Handshaking(Role::Outbound { .. }) => {
                handshake::handshake_refused(self.connector)
            }
            State::Handshaking(Role::Inbound) | State::Established(_) | State::Closing => {
                handshake::form_failure()
            }
        }
    }

    /// Record `end` through the layer and leave. The layer closes the
    /// socket; the next turn of the loop returns. A dial still waiting on
    /// its handshake learns the end the row kept, which is `end` unless an
    /// earlier close got there first.
    fn close(&mut self, end: DialEnd) {
        self.shared.close(self.id, end);
        if let State::Handshaking(Role::Outbound { reply, .. }) =
            std::mem::replace(&mut self.state, State::Closing)
        {
            let kept = self.shared.ended(self.id).unwrap_or(end);
            answer(reply.send(Err(kept)));
        }
    }

    fn on_wake(&mut self) {
        let now = self.deadlines.now();
        for due in self.deadlines.due(now) {
            match due {
                Due::Handshake => {
                    tracing::debug!(id = ?self.id, "inbound handshake did not arrive in time");
                    self.close(DialEnd::levin_handshake_timeout());
                    return;
                }
                Due::Invoke => {
                    tracing::debug!(id = ?self.id, "no response within the invoke deadline");
                    self.close(handshake::invoke_timeout());
                    return;
                }
                Due::TimedSync => self.send_timed_sync(),
            }
        }
    }

    /// Send this session's own 1002 and arm the invoke deadline. Never
    /// while an invoke is outstanding: the draw waits for the response.
    fn send_timed_sync(&mut self) {
        if self.deadlines.invoke_pending() {
            return;
        }
        let tip = self.shared.tip.borrow().clone();
        let Some(bucket) = handshake::timed_sync_request_bucket(tip) else {
            self.close(DialEnd::local_close_after_channel());
            return;
        };
        if self.shared.send_bytes(self.id, bucket).is_err() {
            // The layer closed the session on a full queue, or it is gone.
            self.state = State::Closing;
            return;
        }
        let now = self.deadlines.now();
        let timeout = ticks(self.shared.config.intervals.invoke_timeout);
        self.deadlines.set_invoke(after(now, timeout));
    }

    /// Draw the next timed sync for this session.
    fn draw_timed_sync(&mut self) {
        let span = {
            let mut rng = self.shared.rng.lock().expect("session rng");
            self.shared.config.intervals.draw_timed_sync(&mut **rng)
        };
        let now = self.deadlines.now();
        self.deadlines.set_timed_sync(after(now, span));
    }

    /// One bucket, by state and command. The permit goes with the message
    /// to an owner, or is dropped here.
    fn dispatch(&mut self, received: Received, permit: OwnedSemaphorePermit) {
        let (command, payload, shape) = match received {
            Received::Request { command, payload } => (command, payload, Shape::Request),
            Received::Response { command, payload } => (command, payload, Shape::Response),
            Received::Notification { command, payload } => (command, payload, Shape::Notification),
        };
        let Some(command) = Command::from_wire(command) else {
            // Ingress admits only the ten; a reader that let another through
            // is a defect, and the session is refused all the same.
            self.close(self.form_end());
            return;
        };
        match std::mem::replace(&mut self.state, State::Closing) {
            State::Handshaking(role) => self.handshaking(role, command, shape, &payload),
            State::Established(session) => {
                self.state = State::Established(session.clone());
                self.established(&session, command, shape, payload, permit);
            }
            State::Closing => {}
        }
    }

    /// `Handshaking`: the only bucket accepted is the 1001 of this
    /// session's direction.
    fn handshaking(&mut self, role: Role, command: Command, shape: Shape, payload: &[u8]) {
        match (role, command, shape) {
            (Role::Inbound, Command::Handshake, Shape::Request) => self.inbound_request(payload),
            (
                Role::Outbound {
                    nonce,
                    aim,
                    reply,
                    request: _,
                },
                Command::Handshake,
                Shape::Response,
            ) => self.outbound_response(nonce, aim, reply, payload),
            (role, _, _) => {
                tracing::debug!(id = ?self.id, ?command, "a bucket before the handshake; refused");
                let end = if let Role::Outbound { reply, .. } = role {
                    // The dialed peer answered with something else: its
                    // refusal, judged.
                    let end = handshake::handshake_refused(self.connector);
                    answer(reply.send(Err(end)));
                    end
                } else {
                    handshake::form_failure()
                };
                self.close(end);
            }
        }
    }

    fn inbound_request(&mut self, payload: &[u8]) {
        let network_id = self.shared.config.network_id;
        let (checked, nonce) = match handshake::check_request(payload, network_id, self.connector) {
            Ok(ok) => ok,
            Err(end) => {
                self.close(end);
                return;
            }
        };
        match self.shared.nonces.take(self.connector, &nonce) {
            NonceTake::NotOurs => {}
            NonceTake::SelfConnection => {
                tracing::debug!(id = ?self.id, "this node's own dial arrived; dropped");
                self.close(DialEnd::local_close_after_channel());
                return;
            }
            NonceTake::Probe { minted_at } => {
                let arrived_at = self.deadlines.now();
                self.shared.owners.probes.probe_arrived(ProbeArrival {
                    minted_at,
                    arrived_at,
                });
                self.close(DialEnd::local_close_after_channel());
                return;
            }
            NonceTake::MisroutedProbe => {
                tracing::error!(
                    id = ?self.id,
                    connector = ?self.connector,
                    "a probe of this node's onion arrived on a connector that is not Tor's; dropped, not evidence"
                );
                self.close(handshake::form_failure());
                return;
            }
        }
        // The response goes ahead of anything an owner may send.
        let tip = self.shared.tip.borrow().clone();
        let disclosure = self.shared.owners.peers.disclosure(self.connector);
        let Some(bucket) = handshake::response_bucket(network_id, tip, disclosure) else {
            self.close(DialEnd::local_close_after_channel());
            return;
        };
        if self.shared.send_bytes(self.id, bucket).is_err() {
            self.state = State::Closing;
            return;
        }
        self.deadlines.clear_handshake();
        let Some(session) = self.establish() else {
            return;
        };
        self.shared
            .owners
            .sync
            .claim(&session, checked.sync, ClaimCarrier::Handshake);
    }

    fn outbound_response(
        &mut self,
        nonce: InFlightNonce,
        aim: DialAim,
        reply: oneshot::Sender<Result<DialOutcome, DialEnd>>,
        payload: &[u8],
    ) {
        // The response arrived: the nonce leaves the set.
        drop(nonce);
        let network_id = self.shared.config.network_id;
        let (checked, list) = match handshake::check_response(payload, network_id, self.connector) {
            Ok(ok) => ok,
            Err(end) => {
                answer(reply.send(Err(end)));
                self.close(end);
                return;
            }
        };
        self.deadlines.clear_invoke();
        match aim {
            DialAim::Confirm => {
                let end = DialEnd::local_close_after_channel();
                self.close(end);
                answer(reply.send(Ok(DialOutcome::Confirmed {
                    id: self.id,
                    node_data: checked.node_data,
                    list,
                    sync: checked.sync,
                })));
            }
            DialAim::Keep => {
                let Some(session) = self.establish() else {
                    answer(
                        reply.send(Err(self
                            .shared
                            .ended(self.id)
                            .unwrap_or_else(DialEnd::local_close_after_channel))),
                    );
                    return;
                };
                self.shared.owners.sync.claim(
                    &session,
                    checked.sync.clone(),
                    ClaimCarrier::Handshake,
                );
                answer(reply.send(Ok(DialOutcome::Kept {
                    session,
                    node_data: checked.node_data,
                    list,
                    sync: checked.sync,
                })));
            }
        }
    }

    /// The handshake completed: lift the ingress cap, fire the gap, mark
    /// the row, tell the owners, draw the first timed sync.
    fn establish(&mut self) -> Option<Established> {
        let session = self.shared.establish(self.id)?;
        self.reader.complete_handshake(DEFAULT_MAX_PACKET_SIZE);
        if let Some(gap) = self.gap.take() {
            // A connector that no longer waits is one that closed the
            // channel; the row's end says so.
            answer(gap.send(()));
        }
        self.state = State::Established(session.clone());
        self.shared.owners.established(&session);
        self.draw_timed_sync();
        Some(session)
    }

    /// `Established`: the dispatch table (brief §7.2).
    fn established(
        &mut self,
        session: &Established,
        command: Command,
        shape: Shape,
        payload: Vec<u8>,
        permit: OwnedSemaphorePermit,
    ) {
        match (command, shape) {
            (Command::Handshake, _) => {
                tracing::debug!(id = ?self.id, "a second handshake on an established session; refused");
                self.close(handshake::form_failure());
            }
            (Command::TimedSync, Shape::Request) => self.timed_sync_request(session, &payload),
            (Command::TimedSync, Shape::Response) => self.timed_sync_response(session, &payload),
            (Command::TimedSync, Shape::Notification) => self.close(handshake::form_failure()),
            (Command::NewTransactions, Shape::Notification) => {
                match NewTransactions::load(&payload) {
                    Ok(batch) => self.shared.owners.relay.new_transactions(
                        session,
                        batch,
                        Taken::new(permit),
                    ),
                    Err(_) => self.close(handshake::form_failure()),
                }
            }
            (Command::GetTxpoolComplement, Shape::Notification) => {
                match GetTxpoolComplement::load(&payload) {
                    Ok(request) => self.shared.owners.relay.txpool_complement(
                        session,
                        request,
                        Taken::new(permit),
                    ),
                    Err(_) => self.close(handshake::form_failure()),
                }
            }
            (Command::NewCompactBlock, Shape::Notification) => {
                self.to_sync(session, SyncInbound::NewCompactBlock(payload), permit)
            }
            (Command::RequestCompactMissingTx, Shape::Notification) => self.to_sync(
                session,
                SyncInbound::RequestCompactMissingTx(payload),
                permit,
            ),
            (Command::RequestHeaders, Shape::Notification) => {
                self.to_sync(session, SyncInbound::RequestHeaders(payload), permit);
            }
            (Command::ResponseHeaders, Shape::Notification) => {
                self.to_sync(session, SyncInbound::ResponseHeaders(payload), permit);
            }
            (Command::RequestBodies, Shape::Notification) => {
                self.to_sync(session, SyncInbound::RequestBodies(payload), permit);
            }
            (Command::ResponseBodies, Shape::Notification) => {
                self.to_sync(session, SyncInbound::ResponseBodies(payload), permit);
            }
            (
                Command::NewTransactions
                | Command::GetTxpoolComplement
                | Command::NewCompactBlock
                | Command::RequestCompactMissingTx
                | Command::RequestHeaders
                | Command::ResponseHeaders
                | Command::RequestBodies
                | Command::ResponseBodies,
                Shape::Request | Shape::Response,
            ) => {
                tracing::debug!(id = ?self.id, ?command, "a notification command framed as an invoke; refused");
                self.close(handshake::form_failure());
            }
        }
    }

    fn to_sync(&self, session: &Established, message: SyncInbound, permit: OwnedSemaphorePermit) {
        self.shared
            .owners
            .sync
            .message(session, message, Taken::new(permit));
    }

    /// A peer's 1002: its claim to the sync owner, our tip and disclosure
    /// back.
    fn timed_sync_request(&mut self, session: &Established, payload: &[u8]) {
        let Ok(request) = TimedSyncRequest::load(payload) else {
            self.close(handshake::form_failure());
            return;
        };
        let tip = self.shared.tip.borrow().clone();
        let disclosure = self.shared.owners.peers.disclosure(self.connector);
        let Some(bucket) = handshake::timed_sync_response_bucket(tip, disclosure) else {
            self.close(DialEnd::local_close_after_channel());
            return;
        };
        if self.shared.send_bytes(self.id, bucket).is_err() {
            self.state = State::Closing;
            return;
        }
        self.shared
            .owners
            .sync
            .claim(session, request.payload_data, ClaimCarrier::TimedSync);
    }

    /// The response to this session's own 1002. With no request
    /// outstanding it is a form failure (PWD-B1).
    fn timed_sync_response(&mut self, session: &Established, payload: &[u8]) {
        if !self.deadlines.invoke_pending() {
            tracing::debug!(id = ?self.id, "a timed-sync response with no request outstanding; refused");
            self.close(handshake::form_failure());
            return;
        }
        let Ok(response) = TimedSyncResponse::load(payload) else {
            self.close(handshake::form_failure());
            return;
        };
        self.deadlines.clear_invoke();
        let TimedSyncResponse {
            payload_data,
            local_peerlist_new,
        } = response;
        let sync: CoreSyncData = payload_data;
        self.shared
            .owners
            .sync
            .claim(session, sync, ClaimCarrier::TimedSync);
        self.shared
            .owners
            .peers
            .list_received(session, local_peerlist_new);
        self.draw_timed_sync();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Request,
    Response,
    Notification,
}

/// A reply to a waiter that may have gone: the dial's task was dropped at
/// stop, or the connector stopped waiting on the gap. Nothing to do.
fn answer<T>(sent: Result<(), T>) {
    if let Err(_gone) = sent {}
}
