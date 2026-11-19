// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! How a batch leaves this node.
//!
//! The zone decides the phase and the carrier. This sends: an ordinary
//! write is recorded when it lands, a window is handed to the carrier
//! link, and a stem that cannot leave is held or broadcast.

use shekyl_levin::NewTransactions;
use shekyl_p2p_session::{Established, Message};
use shekyl_relay_privacy::schedule::Millis;
use shekyl_relay_privacy::stem_map::ConnectionId;
use shekyl_timing_engine::Clock;

use super::super::carrier::PendingStem;
use super::{StemFallback, StemOut};
use crate::graph::{OriginVerdict, RelayCarrier, RelayDispatch, RelayPlan, TxBlob};
use crate::stem_watch::TxId;

impl<C: Clock + Clone + Send + Sync + 'static> super::Actor<C> {
    /// Hold this node's own transactions and say why.
    ///
    /// The class report beside the stem map is an info line. This is the
    /// line that says a transaction this node originates is not leaving.
    /// [`OriginVerdict::Absent`] and [`OriginVerdict::Connected`] are
    /// different holds. A routable verdict means the plan and the verdict
    /// disagree; the origin is still held, and the line does not invent a cause.
    fn hold_own_origin(&mut self, txs: &[(TxId, TxBlob)], now: Millis) {
        let verdict = self.driver.zone().origin_verdict();
        debug_assert!(
            !matches!(verdict, OriginVerdict::Routable),
            "NoOwnEdge while a local origin still leaves on an address-hiding session"
        );
        let line = match verdict.origin_hold() {
            Some(hold) => hold.line(),
            None => "this node's transaction is held",
        };
        tracing::warn!(count = txs.len(), "{line}");
        self.driver.zone_mut().hold_origin(txs, now);
    }

    /// `dandelionpp_notify`: plan, then send as the plan's carrier says,
    /// retry a failed ordinary write once over refreshed stems, and end the
    /// stem phase of what could not stem.
    ///
    /// On a covered session a stem leaves only inside a window (`CVR-R6`):
    /// what its channel refuses, or a covered successor with no slot, ends
    /// a relayed stem here and holds this node's own. Cover off is a fluff
    /// epoch for a received stem (`CVR-R1`), decided by the zone. Before its
    /// first send this node's own transaction waits: every arm here that would
    /// end its stem phase holds it instead. The one exception is a node
    /// built with no connector: it has no network to wait for, so its own
    /// transaction is shown at once. A relayed stem whose phase ends
    /// here is broadcast. Once a transaction has been sent, nothing treats
    /// this node's own differently (`graph::embargo`).
    pub(super) fn dispatch(
        &mut self,
        txs: &[(TxId, TxBlob)],
        source: Option<ConnectionId>,
        local: bool,
    ) {
        let node_sync = *self.node_sync.borrow();
        let now = self.now();
        let RelayDispatch { plan, carrier } = self.driver.zone_mut().plan_dispatch_with_refresh(
            source,
            local,
            node_sync,
            &mut *self.rng,
        );
        let destination = match plan {
            RelayPlan::AwaitSync => {
                tracing::debug!("unsynchronised node originates no stem; the zone holds it");
                self.driver.zone_mut().hold_origin(txs, now);
                return;
            }
            RelayPlan::NoOwnEdge => {
                self.hold_own_origin(txs, now);
                return;
            }
            RelayPlan::FluffEpoch if !local => {
                // This node's fluff decision ends the stem phase.
                self.fluff_and_record(txs, source);
                return;
            }
            RelayPlan::Stem(destination) | RelayPlan::OwnEdge(destination) => Some(destination),
            RelayPlan::NoRoute | RelayPlan::FluffEpoch => None,
        };
        if let Some(destination) = destination {
            match self.stem_out(txs, destination, carrier, source, local, now) {
                StemOut::Written | StemOut::Carried | StemOut::Ended => return,
                StemOut::WriteFailed => {}
            }
        }
        if local && self.offline {
            // A node with no connector has no network: there is no stem to
            // send and no peer to hide it from. Its own transaction is shown
            // at once, so its own blocks can carry it, and sent nowhere.
            self.fluff_and_record(txs, source);
            return;
        }
        if local {
            // This node's own transaction: no route, or its ordinary write
            // failed, before any send. Held and planned again.
            tracing::debug!("this node's stem did not leave; the zone holds it");
            self.driver.zone_mut().hold_origin(txs, now);
            return;
        }
        self.driver.zone_mut().update_stems(&mut *self.rng);
        let retry = self
            .driver
            .zone_mut()
            .plan_dispatch(source, local, node_sync, &mut *self.rng);
        let fallback = match retry.plan {
            RelayPlan::AwaitSync | RelayPlan::NoOwnEdge => return,
            RelayPlan::Stem(destination) | RelayPlan::OwnEdge(destination) => {
                match self.stem_out(txs, destination, retry.carrier, source, local, now) {
                    StemOut::Written | StemOut::Carried | StemOut::Ended => return,
                    StemOut::WriteFailed => StemFallback::WriteFailed,
                }
            }
            RelayPlan::NoRoute => StemFallback::NoSuccessor,
            RelayPlan::FluffEpoch => StemFallback::EpochFluffs,
        };
        self.end_stem(txs, source, fallback);
    }

    /// Send one stem as `carrier` says (`CVR-R6`).
    ///
    /// Through a window: each transaction is queued on the channel as its own
    /// message, and the carrier's verdict records it; what the queue refuses
    /// takes [`Self::no_window`]. No window for a covered successor: the same.
    /// On the ordinary connection, a session that carries no cover: written
    /// now and recorded, or reported as a failed write for the caller's
    /// retry.
    pub(super) fn stem_out(
        &mut self,
        txs: &[(TxId, TxBlob)],
        destination: ConnectionId,
        carrier: RelayCarrier,
        source: Option<ConnectionId>,
        local: bool,
        now: Millis,
    ) -> StemOut {
        match carrier {
            RelayCarrier::Noise { channel } => {
                let refused = self.carry(txs, channel.get(), source, local);
                if !refused.is_empty() {
                    self.no_window(&refused, source, local, false, now);
                }
                StemOut::Carried
            }
            RelayCarrier::NoWindow => {
                self.no_window(txs, source, local, false, now);
                StemOut::Ended
            }
            RelayCarrier::Ordinary => {
                if self.send_stem(destination, txs) {
                    self.driver.zone_mut().record_stem(
                        txs,
                        destination,
                        source,
                        now,
                        &mut *self.rng,
                    );
                    StemOut::Written
                } else {
                    StemOut::WriteFailed
                }
            }
        }
    }

    /// Queue each transaction on `channel` as its own carrier message and
    /// return those the queue refused. One transaction per message: two in
    /// one would share a window, a slot and a successor. A transaction the
    /// carrier already holds is left to its verdict.
    fn carry(
        &mut self,
        txs: &[(TxId, TxBlob)],
        channel: usize,
        source: Option<ConnectionId>,
        local: bool,
    ) -> Vec<(TxId, TxBlob)> {
        let Some(carrier) = self.carrier.as_mut() else {
            return txs.to_vec();
        };
        let mut refused = Vec::new();
        for (tx, blob) in txs {
            let stem = PendingStem {
                tx: *tx,
                blob: TxBlob::clone(blob),
                source,
                local,
            };
            if !carrier.offer(channel, blob, stem) {
                refused.push((*tx, TxBlob::clone(blob)));
            }
        }
        refused
    }

    /// An ordinary write the zone asked for did not land.
    ///
    /// Before the first send, this node's own transaction waits. A reshape
    /// has already been sent once: one embargo, then the next fire ends the
    /// phase. When that embargo cannot be armed, the phase ends now.
    pub(super) fn missed_ordinary_write(
        &mut self,
        txs: &[(TxId, TxBlob)],
        peer: ConnectionId,
        source: Option<ConnectionId>,
        now: Millis,
    ) {
        let (sent, waiting): (Vec<_>, Vec<_>) = txs
            .iter()
            .cloned()
            .partition(|(tx, _)| self.driver.zone().stem_sent(tx));
        if !waiting.is_empty() {
            self.driver.zone_mut().hold_origin(&waiting, now);
        }
        let mut ends = Vec::new();
        for (tx, blob) in sent {
            let armed =
                self.driver
                    .zone_mut()
                    .arm_missed_reshape(tx, peer, source, now, &mut *self.rng);
            if !armed {
                self.driver.zone_mut().release(&tx);
                ends.push((tx, blob));
            }
        }
        if !ends.is_empty() {
            self.end_stem(&ends, source, StemFallback::WriteFailed);
        }
    }

    /// A stem no window could take, or whose window the carrier dropped
    /// (`CVR-R6`).
    ///
    /// This node's own transaction waits, held and planned again, only while
    /// it has never been sent: no stem of it is recorded and no window of it
    /// left (`started`). A transaction that has been sent is treated as a
    /// relayed one whoever originated it (Rick, 2026-11-18): its stem phase
    /// ends here, its relay state is dropped, and it is broadcast.
    pub(super) fn no_window(
        &mut self,
        txs: &[(TxId, TxBlob)],
        source: Option<ConnectionId>,
        local: bool,
        started: bool,
        now: Millis,
    ) {
        let (waits, ends): (Vec<_>, Vec<_>) = txs
            .iter()
            .cloned()
            .partition(|(tx, _)| local && !started && !self.driver.zone().stem_sent(tx));
        if !waits.is_empty() {
            self.driver.zone_mut().hold_origin(&waits, now);
        }
        if ends.is_empty() {
            return;
        }
        for (tx, _) in &ends {
            self.driver.zone_mut().release(tx);
        }
        self.end_stem(&ends, source, StemFallback::NoWindow);
    }

    /// A stem's phase ends here: it is broadcast.
    fn end_stem(
        &mut self,
        txs: &[(TxId, TxBlob)],
        source: Option<ConnectionId>,
        fallback: StemFallback,
    ) {
        tracing::debug!(
            count = txs.len(),
            "fluffing what could not stem: {}",
            fallback.reason()
        );
        self.fluff_and_record(txs, source);
    }

    /// The pool is told the transactions are shown, then the zone queues
    /// them for the next fluff release. One argument for both, so what is
    /// recorded is what is sent.
    pub(super) fn fluff_and_record(
        &mut self,
        txs: &[(TxId, TxBlob)],
        source: Option<ConnectionId>,
    ) {
        for (tx, _) in txs {
            self.pool.shown(tx);
        }
        let blobs: Vec<TxBlob> = txs.iter().map(|(_, blob)| TxBlob::clone(blob)).collect();
        let now = self.now();
        let accepted = self
            .driver
            .zone_mut()
            .queue_fluff(&blobs, source, now, &mut *self.rng);
        if accepted == 0 {
            tracing::warn!("unable to send transaction(s), no available connections");
        } else {
            tracing::debug!(
                accepted,
                txs = super::measured_ids(txs).as_deref(),
                "transactions queued for fluff"
            );
        }
    }

    fn send_stem(&self, destination: ConnectionId, txs: &[(TxId, TxBlob)]) -> bool {
        let blobs: Vec<TxBlob> = txs.iter().map(|(_, blob)| TxBlob::clone(blob)).collect();
        let sent = self.send_batch(destination, &blobs, false);
        if sent {
            tracing::debug!(
                count = txs.len(),
                txs = super::measured_ids(txs).as_deref(),
                "a stem was forwarded"
            );
        }
        sent
    }

    /// One 2002 to `peer`, `fluff` as the batch's flag. `false` when the
    /// session is not held or the write was refused.
    pub(super) fn send_batch(&self, peer: ConnectionId, blobs: &[TxBlob], fluff: bool) -> bool {
        let Some(session): Option<&Established> = self.sessions.get(&peer) else {
            return false;
        };
        let message = Message::NewTransactions(NewTransactions {
            txs: blobs.iter().map(|blob| blob.to_vec()).collect(),
            padding: Vec::new(),
            dandelionpp_fluff: fluff,
        });
        match session.send(&message) {
            Ok(()) => true,
            // A stem's successor is not named (§6.4); a fluff's peer is.
            Err(refused) if fluff => {
                tracing::debug!(?peer, %refused, "a fluff batch was not sent");
                false
            }
            Err(refused) => {
                tracing::debug!(%refused, "a stem batch was not sent");
                false
            }
        }
    }
}
