// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One outbound dial, in two halves (the dialer in-flight bound, Rick,
//! 2026-10-25: decisions 1 and 2; `P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1).
//!
//! The owner loop decides the address and the aim and launches the
//! attempt. The **attempt task** ([`attempt_task`]) runs on the transport
//! runtime and asks the session layer for the dial: the layer opens the
//! channel ([`SessionLayer::connect`]), writes the request, reads the
//! response, checks the network id, and for a `Keep` establishes the
//! session and tells the owners. The task decides nothing and holds no lock
//! of the dialer's; it only dates the open and the end on the judge's
//! clock. The **loop** applies the outcome ([`Dialer::apply_result`]) by
//! calling the layer that owns each decision: the peer lists admit or
//! refuse the received list, and the aim's outcome goes to the lists.
//!
//! The nonce is the layer's: minted at `connect`, held until the response
//! or the end, so a cancelled attempt erases it with the task. Rust refuses
//! three things: a frame that is not a well-formed 1001 response, a network
//! id that is not ours (both the layer's, as the dial's end), and a peerlist
//! the lists refuse (this module's, as the same failure). A later refusal
//! of a kept session is the payload owner closing it.

use std::sync::{Arc, Mutex};

use shekyl_draw_rng::RelayRng;
use shekyl_p2p_session::{DialOutcome as SessionOutcome, Endpoint, Established, SessionLayer};
use shekyl_peerlist::{ConnectorId, DialOutcome, NetworkAddress, SessionRow};
use shekyl_timing_engine::Clock;
use shekyl_transport_layer::{CloseCause, CloseKind, DialEnd, DialFailure, Reached, SocketId};

use super::address::endpoint_of;
use super::{session_of, Dialer, Shared};
use crate::fill::DialAim;

/// How one attempt ended, once the loop has applied it.
pub(super) enum Attempt {
    /// A total outcome. The owner records it.
    Done(DialOutcome),
    /// Established by the layer and admitted by the lists. The owner
    /// records `SessionAccepted` and the kept row.
    Kept(KeptDial),
}

/// A kept dial the owner has not yet recorded.
pub(super) struct KeptDial {
    pub(super) id: SocketId,
    /// The window a close before the kept row is written reports into.
    pub(super) window: Window,
}

/// The dial reached a response that passed the layer's checks, and the
/// window its session reports into until the loop has applied it.
pub(super) struct Answered {
    outcome: SessionOutcome,
    window: Window,
}

/// What the attempt task hands the loop.
pub(super) enum TaskResult {
    /// A well-formed handshake response on our network.
    Answered(Answered),
    /// The dial never reached one: the connector's end, the layer's
    /// refusal, or this dialer's own failure.
    Failed(DialEnd),
}

/// The peer list's outcome for a failed attempt: the judge's input, the
/// end's failure. Its D12 cause is logged here and goes no further.
pub(super) fn failed_outcome(address: NetworkAddress, end: DialEnd) -> DialOutcome {
    tracing::debug!("dial {address:?} ended {:?}", end.cause().kind());
    DialOutcome::DialFailed(address, end.failure())
}

/// The Levin layer's refusal on `connector`, after the stream opened: the
/// peer sent a peer list the lists refuse. Proof of misbehaviour only
/// where the connector authenticates the destination (§2.2), and always
/// final. The layer's own refusals (a malformed response, another
/// network) arrive with the same shape as the dial's end.
fn refused_by_peer(connector: ConnectorId) -> DialEnd {
    DialEnd::new(
        DialFailure::refused_by_peer(connector, Reached::StreamOpened),
        CloseCause::new(CloseKind::LevinHandshakeRejected),
    )
}

/// What the task needs, worked out on the loop before launch.
pub(super) struct Prepared {
    endpoint: Endpoint,
    /// The judge's clock, read when the channel opens and when the dial
    /// ends.
    stamp: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// The span from the channel's open until the loop has applied the
/// outcome, during which a close of the session finds no kept row. It
/// records its end here instead ([`Dialer::session_closed`]), and the
/// owner does not keep the dial. Opened in the task before the layer can
/// place the row; dropped, armed or not, it leaves no entry, so a
/// cancelled task and a dropped result leave nothing behind.
pub(super) struct Window {
    shared: Arc<Mutex<Shared>>,
    id: u64,
    armed: bool,
}

impl Window {
    fn open(shared: Arc<Mutex<Shared>>, id: SocketId) -> Self {
        shared
            .lock()
            .expect("dialer state")
            .adopting
            .insert(id.get(), None);
        Self {
            shared,
            id: id.get(),
            armed: true,
        }
    }

    /// Take the window out under the caller's lock: the end a close
    /// recorded in it, if one did. The kept row is written in the same
    /// lock section, so no close falls between.
    pub(super) fn settle(&mut self, shared: &mut Shared) -> Option<DialEnd> {
        self.armed = false;
        shared.adopting.remove(&self.id).flatten()
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if self.armed {
            self.shared
                .lock()
                .expect("dialer state")
                .adopting
                .remove(&self.id);
        }
    }
}

impl<C: Clock + Clone + Send + Sync + 'static> Dialer<C> {
    /// The attempt's inputs: the endpoint and the judge's clock. An address
    /// with no endpoint is a local failure the loop records at once.
    pub(super) fn prepare(&self, address: &NetworkAddress) -> Result<Prepared, DialEnd> {
        let endpoint = endpoint_of(address).ok_or_else(DialEnd::local_close)?;
        let stamp = Arc::clone(&self.shared().life_clock.now_ms);
        Ok(Prepared { endpoint, stamp })
    }

    /// Apply one task result, on the loop, through the layer that owns each
    /// decision. The shared lock is taken only to admit the received list;
    /// no session-layer call is made under it (#1092).
    pub(super) fn apply_result<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        address: &NetworkAddress,
        result: TaskResult,
        rng: &mut R,
    ) -> Attempt {
        let failed = |end: DialEnd| Attempt::Done(failed_outcome(address.clone(), end));
        let Answered { outcome, window } = match result {
            TaskResult::Failed(end) => return failed(end),
            TaskResult::Answered(answered) => answered,
        };
        match outcome {
            SessionOutcome::Confirmed { id, list, .. } => {
                let addresses: Vec<NetworkAddress> =
                    list.into_iter().map(|entry| entry.adr).collect();
                if !self.admit_list(connector, id, &addresses, rng) {
                    return failed(refused_by_peer(connector));
                }
                drop(window);
                Attempt::Done(DialOutcome::Confirmed(address.clone()))
            }
            SessionOutcome::Kept { session, list, .. } => {
                let addresses: Vec<NetworkAddress> =
                    list.into_iter().map(|entry| entry.adr).collect();
                if !self.admit_list(connector, session.id(), &addresses, rng) {
                    // A list the lists refuse (D3, D-S1, the foreign-connector
                    // rule, R4) is the peer's doing: the same failure as a
                    // rejection, and the session the layer established is
                    // closed with it.
                    session.close(CloseCause::new(CloseKind::LevinHandshakeRejected));
                    return failed(refused_by_peer(connector));
                }
                Attempt::Kept(KeptDial {
                    id: session.id(),
                    window,
                })
            }
        }
    }

    /// Admit the list a handshake response on `id` carried. `false` is the
    /// lists' refusal.
    fn admit_list<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        id: SocketId,
        addresses: &[NetworkAddress],
        rng: &mut R,
    ) -> bool {
        let now = self.now();
        self.shared()
            .lists
            .admit_received_list(
                addresses,
                SessionRow {
                    id: session_of(id),
                    connector,
                },
                now,
                rng,
            )
            .is_ok()
    }

    /// Admit a list a peer sent on an established session (a timed-sync
    /// response, or the request's reply on an inbound session). A list the
    /// lists refuse closes the session: the delivery was refused.
    pub(super) fn admit_on_established(&self, session: &Established, addresses: &[NetworkAddress]) {
        let admitted = {
            let mut rng = self.rng.lock().expect("dialer rng");
            self.admit_list(session.connector(), session.id(), addresses, &mut **rng)
        };
        if !admitted {
            tracing::debug!(
                "{:?} session {:?}: the peer list it sent was refused; the session is closed",
                session.connector(),
                session.id()
            );
            session.close(CloseCause::new(CloseKind::SessionRefused));
        }
    }
}

/// What one attempt resolved, dated on the judge's clock.
pub(super) struct AttemptEnd {
    pub(super) result: TaskResult,
    /// When the stream opened, if one did: the instant the channel arrived.
    pub(super) opened_ms: Option<u64>,
    /// When the attempt resolved. A failure is dated here, so the bracket
    /// does not move because the result waited to be applied.
    pub(super) ended_ms: u64,
}

/// The attempt task: the layer's dial and the judge's two stamps, nothing
/// else. The open is the instant the channel arrived, before the
/// handshake. The end is the last thing the task reads, before the result
/// can wait. It takes no lock of the dialer's but the window's insert and
/// draws no random number. Dropped before it resolves (a cancelled
/// attempt), it releases whatever it holds: the connect future aborts the
/// connector's dial, an unhandshaken channel is closed by its drop, and a
/// placed session is closed by the layer as this node's own.
pub(super) async fn attempt_task<C: Clock + Clone + Send + Sync + 'static>(
    layer: SessionLayer<C>,
    shared: Arc<Mutex<Shared>>,
    connector: ConnectorId,
    address: NetworkAddress,
    aim: DialAim,
    prepared: Prepared,
) -> AttemptEnd {
    let Prepared { endpoint, stamp } = prepared;
    let dialed = match layer.connect(endpoint).await {
        Ok(dialed) => dialed,
        Err(end) => {
            return AttemptEnd {
                result: TaskResult::Failed(end),
                opened_ms: None,
                ended_ms: stamp(),
            };
        }
    };
    let opened_ms = stamp();
    let window = Window::open(shared, dialed.id());
    tracing::debug!(
        "{connector:?} dial {address:?}: channel {:?} open, handshake {aim:?}",
        dialed.id()
    );
    let result = match dialed.handshake(aim).await {
        Ok(outcome) => TaskResult::Answered(Answered { outcome, window }),
        Err(end) => TaskResult::Failed(end),
    };
    AttemptEnd {
        result,
        opened_ms: Some(opened_ms),
        ended_ms: stamp(),
    }
}

#[cfg(test)]
mod tests {
    use shekyl_peerlist::ConnectorId;
    use shekyl_transport_layer::{CloseKind, Evidence, Reached, Retry};

    use super::refused_by_peer;

    /// The Levin layer's refusal (§2.2): after the stream opened, final, and
    /// proof of misbehaviour only on the connector that authenticates the
    /// destination. The edit that makes this red is building it as
    /// Uncertain, or proving misbehaviour on clearnet.
    #[test]
    fn a_peers_refusal_is_the_levin_layers_and_proves_only_where_authenticated() {
        for (connector, proves) in [(ConnectorId::Tor, true), (ConnectorId::Clearnet, false)] {
            let end = refused_by_peer(connector);
            assert!(matches!(end.failure().evidence(), Evidence::Destination(_)));
            assert_eq!(end.failure().proves_misbehaviour(), proves, "{connector:?}");
            assert_eq!(end.failure().retry(), Retry::Final);
            assert_eq!(end.failure().reached(), Reached::StreamOpened);
            assert_eq!(end.cause().kind(), CloseKind::LevinHandshakeRejected);
        }
    }
}
