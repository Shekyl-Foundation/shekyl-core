// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The probe of this node's own onion, and the descriptor rounds that
//! fire it (`TOR_SUPERVISOR.md` §4.5).
//!
//! [`Flight`] owns the probe nonce. The dial task holds only the request
//! bytes, so ending the dial cannot erase a nonce. Cancelling drops the
//! nonce on this task first: a handshake that arrives after that is not
//! this probe, and the next probe's nonce is never the one removed.
//!
//! A descriptor round's marks are one fold. The two ways an open round is
//! ended here, a round stuck for five minutes and a sink that dropped
//! events, share [`Drive::end_round`].

use shekyl_ffi::dialer_ffi::ProbeHandshake;
use shekyl_timing_engine::Tick;
use shekyl_tor_control_client::control::{Command, TorEvent, UploadRounds};
use shekyl_tor_control_client::supervisor::{round_inputs, Inbound, InboundCause, Input};
use shekyl_tor_control_daemon::{probe_own_onion, ProbeDial};
use tokio::task::JoinHandle;

use super::Drive;

/// The probe in flight: its nonce, and the dial carrying the request.
///
/// Drop removes the nonce on this task, then aborts the dial. The dial
/// task holds only the request bytes, so aborting it cannot erase a nonce
/// a later probe has minted.
pub(super) struct Flight {
    handshake: Option<ProbeHandshake>,
    task: JoinHandle<()>,
}

impl Drop for Flight {
    fn drop(&mut self) {
        // The nonce leaves the set before the dial is aborted, and it
        // leaves on this task. A handshake that arrives after that is not
        // this probe. Fields drop after this body, so the nonce has to go
        // here, ahead of the abort.
        self.handshake.take();
        self.task.abort();
    }
}

impl Drive {
    /// Dial this node's own onion with a fresh probe nonce (§4.5). The
    /// managed route and the onion are read now (`TSR-F10`). The nonce
    /// stays on this driver until [`Self::cancel_probe`].
    pub(super) fn probe(&mut self) -> Input {
        self.cancel_probe();
        let Some(service) = self.service.clone() else {
            return Input::ProbeNotDialed;
        };
        let Some(proxy) = shekyl_ffi::zone_ffi::managed_route(self.probe_pair.shared()) else {
            return Input::ProbeNotDialed;
        };
        let Some(mut handshake) = shekyl_ffi::dialer_ffi::mint_probe() else {
            return Input::ProbeNotDialed;
        };
        let minted_at = handshake.minted_at.get();
        let request = std::mem::take(&mut handshake.request);
        let port = self.virtual_port;
        let task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            let dialed = probe_own_onion(&proxy, &service, port, &request).await;
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match dialed {
                ProbeDial::Delivered => {
                    tracing::info!(
                        target: "tor",
                        elapsed_ms,
                        "the onion probe's request was delivered"
                    );
                }
                other => {
                    tracing::info!(
                        target: "tor",
                        elapsed_ms,
                        "the onion probe's dial ended: {other:?}"
                    );
                }
            }
        });
        self.probe = Some(Flight {
            handshake: Some(handshake),
            task,
        });
        tracing::info!(target: "tor", "probing this node's onion");
        Input::ProbeDialed { minted_at }
    }

    /// End the probe in flight. Its [`Flight`] removes the nonce on this
    /// task, then aborts the dial, before another probe can mint.
    pub(super) fn cancel_probe(&mut self) {
        self.probe.take();
    }

    /// `HSFETCH` this node's own onion after a first probe miss: Tor refreshes
    /// its client view of that one address (`TSR-Q14`). Whatever Tor answers,
    /// the second probe follows, a fresh delay later; the fetch's `HS_DESC`
    /// events carry the descriptor id, so no upload round counts them.
    pub(super) async fn refetch(&self) -> Input {
        let draw = shekyl_ffi::tor_link::probe_delay_draw();
        let (Some(control), Some(service)) = (self.control.as_ref(), self.service.clone()) else {
            return Input::DescriptorRefetched { draw };
        };
        match control.ask(Command::HsFetch(service)).await {
            Ok(reply) if reply.status() == 250 => {
                tracing::info!(
                    target: "tor",
                    "the onion probe missed; Tor refetches this node's descriptor"
                );
            }
            Ok(reply) => {
                tracing::info!(
                    target: "tor",
                    status = reply.status(),
                    "the onion probe missed; Tor did not take the refetch"
                );
            }
            Err(error) => {
                tracing::info!(
                    target: "tor",
                    "the onion probe missed; the refetch was not asked ({error})"
                );
            }
        }
        Input::DescriptorRefetched { draw }
    }

    /// This node's own onion's `HS_DESC` events, coalesced into rounds
    /// (`TSR-Q5`). Each round's first upload carries a CSPRNG draw for the
    /// probe's delay.
    pub(super) fn round_marks(&mut self, event: &TorEvent) -> Vec<Input> {
        let (TorEvent::HsDesc(desc), Some(rounds)) = (event, self.rounds.as_mut()) else {
            return Vec::new();
        };
        let marks = rounds.observe(desc);
        round_inputs(&marks, shekyl_ffi::tor_link::probe_delay_draw)
    }

    /// A descriptor round has been open five minutes: uploads with neither
    /// `UPLOADED` nor `FAILED`, no event lost on our side unless the sink
    /// says so. Said once at debug (Status counts it), and ended in the
    /// coalescer, so the next round's uploads start a round of their own
    /// instead of joining one that will never end (§10).
    pub(super) fn round_stuck(&mut self) -> Vec<Input> {
        tracing::debug!(
            target: "tor",
            events_dropped = self.incoming.dropped(),
            "a descriptor upload round has been open for five minutes; ending it"
        );
        self.end_round()
    }

    /// The sink dropped events since the last look: an open round's ends may
    /// be among them, so it ends now and the next round can trigger.
    pub(super) fn round_resync(&mut self) -> Vec<Input> {
        let dropped = self.incoming.dropped();
        if dropped == self.dropped_seen {
            return Vec::new();
        }
        self.dropped_seen = dropped;
        self.end_round()
    }

    /// End the open round in the coalescer. A stuck round and a dropped
    /// sink share this. No mark when nothing is open. The end is not said
    /// by [`say_round`]: the stuck path has its own line.
    fn end_round(&mut self) -> Vec<Input> {
        let Some(mark) = self.rounds.as_mut().and_then(UploadRounds::resync) else {
            return Vec::new();
        };
        round_inputs(&[mark], shekyl_ffi::tor_link::probe_delay_draw)
    }

    /// Publish the inbound facet on the managed route's link. Before a route
    /// is installed there is nothing to name; [`Self::publish_route`]
    /// publishes the core's facet when one is.
    pub(super) fn publish_inbound(&self, inbound: Inbound) {
        let Some(incarnation) = self.incarnation else {
            return;
        };
        let facet = link_inbound(inbound);
        if shekyl_ffi::zone_ffi::publish_tor_inbound(incarnation, facet) {
            tracing::info!(target: "tor", "this node's onion: {facet:?}");
        }
    }
}

/// A descriptor round's mark, said as it arrives. The probe's delay draw is
/// not said: its point is that no directory can predict the probe, and a
/// log line is one more copy of it.
pub(super) fn say_round(input: &Input) {
    if let Input::UploadRoundEnded { end, .. } = input {
        tracing::info!(target: "tor", ?end, "descriptor round: ended");
    }
}

/// The core's inbound facet as the link carries it. The core's clock is the
/// process clock the link's ticks read.
fn link_inbound(inbound: Inbound) -> shekyl_ffi::zone_ffi::InboundFacet {
    use shekyl_ffi::zone_ffi::{InboundCause as LinkCause, InboundFacet};
    match inbound {
        Inbound::NotOffered => InboundFacet::NotOffered,
        Inbound::Publishing => InboundFacet::Publishing,
        Inbound::Reachable { evidence_at } => InboundFacet::Reachable {
            evidence_at: Tick::new(evidence_at),
        },
        Inbound::Unreachable { cause, since } => InboundFacet::Unreachable {
            cause: match cause {
                InboundCause::ProbeTimedOut => LinkCause::ProbeTimedOut,
                InboundCause::DescriptorRejected => LinkCause::DescriptorRejected,
            },
            since: Tick::new(since),
        },
    }
}
