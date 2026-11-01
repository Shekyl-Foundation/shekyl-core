// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The embargo on every stem this node holds, and what happens when it fires.
//!
//! **One owner** (`DAEMON_RELAY_PRIVACY.md` acceptance criteria 1 and 2):
//! the zone holds each stem's relay state, keyed on the transaction hash,
//! node-local and never on the wire (§12.2 item 5). The pool knows one bit,
//! shown, and the zone sets it through the FFI's existing `note_shown` path.
//!
//! **The embargo is the stem watch's observation.** Every successful stem
//! send records one (`Relay::record_stem`) with a deadline: a relay
//! position's is its connector's memoryless draw (D-1, F-7), the origin's is
//! the derived retry interval (§92.5c, [`origin_retry_ms`]; RX-1, Rick
//! 2026-10-29). Disarm is the watch's predicate, not a timer: the
//! transaction arrived from somewhere other than where this node sent it
//! (F-10). An observation that resolves silent is the embargo firing.
//!
//! **On fire, reshape** (§12.2, adopted unconditionally at §14.7): the first
//! fire re-stems to the source's alternate, taken from its frozen pin
//! (never `stem_for` again, W1; never a new edge, §12.2 item 6; stable
//! across a churn refill within the epoch, W3c). The second fire, or a first
//! fire with no live alternate, fluffs to every session but the source and
//! marks the transaction shown: the W3/W3b last resort (§14.6). Fluff on
//! expiry, which the C++ pool did, is not ported (§14).
//!
//! **An origin that never sent** (`AwaitSync`, `NoOwnEdge`, a write that
//! failed) is held unsent, not shown and not fluffed (RX-2), and re-planned
//! on the record's short grid ([`NEVER_SENT_RETRY_MS`]), at once when this
//! node turns synchronised, and at once when a session is established. The
//! 1,148 s interval is for a transaction that was sent (§92.5c).
//!
//! **Bounded by the pool:** every pool departure releases the state
//! (`Relay::release`, `DRS_X_STORE_FLIP.md` §2).

use std::collections::HashMap;
use std::sync::OnceLock;

use shekyl_draw_rng::RelayRng;
use shekyl_relay_privacy::params::{origin_retry_one_in, DandelionParams};
use shekyl_relay_privacy::schedule::{EmbargoTimer, Millis};
use shekyl_relay_privacy::stem_map::ConnectionId;

use super::{embargo_timer, NodeSync, Relay, RelayPlan, TxBlob};
use crate::stem_watch::TxId;

/// How long an originated transaction that was never sent waits before the
/// zone plans it again: the inherited `MIN_RELAY_TIME`, 300 s, which the
/// record keeps for an unsent entry because "no stem was ever launched"
/// (`DAEMON_RELAY_PRIVACY.md` §92.5c, the carrier-discard paragraph). A
/// sync turn and a new session re-plan sooner; this is the backstop.
pub const NEVER_SENT_RETRY_MS: Millis = 300_000;

/// The origin's retry interval, in milliseconds: the 1-in-`origin_retry_one_in`
/// survival quantile of the adopted anonymity timer over the longest
/// declared transit (§92.5c; 1,148 s at the shipped terms). Asked at the
/// same confidence a relay asks whether a stem completed.
#[must_use]
pub fn origin_retry_ms() -> Millis {
    static RETRY_MS: OnceLock<Millis> = OnceLock::new();
    *RETRY_MS.get_or_init(|| Millis::from(origin_retry_secs()) * 1_000)
}

/// [`origin_retry_ms`] in whole seconds, the unit the FFI export carries.
#[must_use]
pub fn origin_retry_secs() -> u32 {
    let params = DandelionParams::adopted_for_transit_ms(super::longest_transit());
    EmbargoTimer::adopted(&params).judge_failed_after_secs(origin_retry_one_in())
}

/// A stem this node sent and has not seen circulate.
#[derive(Debug)]
pub(super) struct Held {
    /// The bytes, to re-stem or fluff on fire. A shared handle.
    pub(super) blob: TxBlob,
    /// Where it came from: `None` for this node's own transaction.
    pub(super) source: Option<ConnectionId>,
    /// The reshape alternate, captured at the first stem from the source's
    /// frozen pin. Not re-read at fire, so a churn refill cannot change it.
    pub(super) alternate: Option<ConnectionId>,
    /// The one re-stem the cap allows has been spent (cap `STEMS - 1 = 1`,
    /// §12.3).
    pub(super) restemmed: bool,
}

/// An originated transaction that was never sent.
#[derive(Debug)]
pub(super) struct Unsent {
    pub(super) blob: TxBlob,
    /// When the zone plans it again.
    pub(super) due: Millis,
}

/// The zone's per-transaction relay state.
#[derive(Debug, Default)]
pub(super) struct Embargoes {
    pub(super) held: HashMap<TxId, Held>,
    pub(super) unsent: HashMap<TxId, Unsent>,
}

/// What a poll's embargo and held-origin work produced.
#[derive(Debug, Default)]
pub struct EmbargoWork {
    /// Stem these bytes to this peer on the ordinary wire: a reshape, or a
    /// held origin's first send.
    pub stems: Vec<(ConnectionId, TxBlob)>,
    /// Transactions the zone published (fluffed): the pool's shown bit is
    /// set for each.
    pub published: Vec<TxId>,
}

impl Relay {
    /// Record that `txs` were stemmed to `successor`, keyed under `source`
    /// (`None` = this node's own), and arm each one's embargo.
    ///
    /// A relay position's deadline is drawn from the successor's connector,
    /// the origin's is the derived retry interval (RX-1), and a connector
    /// with no assessed transit records nothing. The first
    /// stem of a transaction captures its reshape alternate; a later record
    /// of the same transaction keeps what it has.
    pub fn record_stem<R: RelayRng + ?Sized>(
        &mut self,
        txs: &[(TxId, TxBlob)],
        successor: ConnectionId,
        source: Option<ConnectionId>,
        now: Millis,
        rng: &mut R,
    ) {
        let Some(peer) = self.contexts.get(&successor) else {
            return;
        };
        let connector = peer.connector;
        // A connector with no assessed transit records nothing: it is not a
        // stem path the embargo can be judged on.
        let Some(timer) = embargo_timer(&peer.declaration) else {
            return;
        };
        let deadline = if source.is_none() {
            now.saturating_add(origin_retry_ms())
        } else {
            timer.deadline(now, rng)
        };
        for (tx, blob) in txs {
            self.stem_watch
                .stemmed(*tx, successor, source, connector, deadline);
            self.embargoes.unsent.remove(tx);
            let alternate = self.map.alternate_for(source, successor);
            self.embargoes.held.entry(*tx).or_insert_with(|| Held {
                blob: TxBlob::clone(blob),
                source,
                alternate,
                restemmed: false,
            });
        }
    }

    /// Act on every embargo that fired by `now`: re-stem once to the
    /// alternate, else fluff and publish (§12.2, §14.7; RX-1 for the origin).
    pub fn fire_embargoes<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        rng: &mut R,
    ) -> EmbargoWork {
        let mut work = EmbargoWork::default();
        for tx in self.stem_watch.expire(now) {
            let Some(held) = self.embargoes.held.get(&tx) else {
                // An observation with no held state: telemetry only, or a
                // transaction the pool already dropped.
                continue;
            };
            let alternate = (!held.restemmed)
                .then_some(held.alternate)
                .flatten()
                .filter(|alternate| self.contexts.contains_key(alternate));
            let restem = alternate.and_then(|alternate| {
                let peer = self.contexts.get(&alternate)?;
                let timer = embargo_timer(&peer.declaration)?;
                let deadline = if held.source.is_none() {
                    now.saturating_add(origin_retry_ms())
                } else {
                    timer.deadline(now, rng)
                };
                Some((alternate, peer.connector, deadline))
            });
            match restem {
                Some((alternate, connector, deadline)) => {
                    let held = self
                        .embargoes
                        .held
                        .get_mut(&tx)
                        .expect("held checked present above");
                    held.restemmed = true;
                    self.stem_watch
                        .stemmed(tx, alternate, held.source, connector, deadline);
                    work.stems.push((alternate, TxBlob::clone(&held.blob)));
                }
                None => {
                    let held = self
                        .embargoes
                        .held
                        .remove(&tx)
                        .expect("held checked present above");
                    self.queue_fluff(&[held.blob], held.source, now, rng);
                    work.published.push(tx);
                }
            }
        }
        work
    }

    /// Hold this node's own `txs`, which were not sent: not shown, not
    /// fluffed (RX-2), planned again by [`Self::due_unsent`].
    pub fn hold_origin(&mut self, txs: &[(TxId, TxBlob)], now: Millis) {
        for (tx, blob) in txs {
            if self.embargoes.held.contains_key(tx) {
                continue;
            }
            self.embargoes.unsent.entry(*tx).or_insert_with(|| Unsent {
                blob: TxBlob::clone(blob),
                due: now.saturating_add(NEVER_SENT_RETRY_MS),
            });
        }
    }

    /// The node's sync state, as the handler reports it until CS-5. A turn
    /// to synchronised makes every held origin due now.
    pub fn set_node_sync(&mut self, sync: NodeSync, now: Millis) {
        if self.node_sync == NodeSync::Unsynchronised && sync == NodeSync::Synchronised {
            self.unsent_due_now(now);
        }
        self.node_sync = sync;
    }

    /// Every held origin is due at `now`: a session was established, so an
    /// own edge may exist.
    pub(super) fn unsent_due_now(&mut self, now: Millis) {
        for unsent in self.embargoes.unsent.values_mut() {
            unsent.due = unsent.due.min(now);
        }
    }

    /// Plan every held origin that is due. A route sends and arms the
    /// embargo; a hold waits another grid; no route after the refresh
    /// fluffs, as a fresh origin's plan does.
    pub fn due_unsent<R: RelayRng + ?Sized>(&mut self, now: Millis, rng: &mut R) -> EmbargoWork {
        let mut work = EmbargoWork::default();
        let mut due: Vec<TxId> = self
            .embargoes
            .unsent
            .iter()
            .filter(|(_, unsent)| unsent.due <= now)
            .map(|(tx, _)| *tx)
            .collect();
        due.sort_unstable();
        for tx in due {
            let plan = self.plan_relay_with_refresh(None, true, self.node_sync, rng);
            match plan {
                RelayPlan::Stem(peer) | RelayPlan::OwnEdge(peer) => {
                    let unsent = self
                        .embargoes
                        .unsent
                        .remove(&tx)
                        .expect("due ids come from the map");
                    self.record_stem(&[(tx, TxBlob::clone(&unsent.blob))], peer, None, now, rng);
                    work.stems.push((peer, unsent.blob));
                }
                RelayPlan::AwaitSync | RelayPlan::NoOwnEdge => {
                    if let Some(unsent) = self.embargoes.unsent.get_mut(&tx) {
                        unsent.due = now.saturating_add(NEVER_SENT_RETRY_MS);
                    }
                }
                RelayPlan::NoRoute | RelayPlan::FluffEpoch => {
                    let unsent = self
                        .embargoes
                        .unsent
                        .remove(&tx)
                        .expect("due ids come from the map");
                    self.queue_fluff(&[unsent.blob], None, now, rng);
                    work.published.push(tx);
                }
            }
        }
        work
    }

    /// The earliest held origin's next plan, if any.
    #[must_use]
    pub fn unsent_deadline(&self) -> Option<Millis> {
        self.embargoes
            .unsent
            .values()
            .map(|unsent| unsent.due)
            .min()
    }

    /// The pool dropped `tx` (mined, evicted, removed): the zone forgets it.
    pub fn release(&mut self, tx: &TxId) {
        self.embargoes.held.remove(tx);
        self.embargoes.unsent.remove(tx);
    }

    /// Transactions the zone holds relay state for, held and unsent.
    #[must_use]
    pub fn relay_state_len(&self) -> usize {
        self.embargoes.held.len() + self.embargoes.unsent.len()
    }

    /// Whether `tx` is held unsent. A witness reads it.
    #[must_use]
    pub fn holds_unsent(&self, tx: &TxId) -> bool {
        self.embargoes.unsent.contains_key(tx)
    }

    /// The reshape alternate captured for `tx`, if it is held. A witness
    /// reads it.
    #[must_use]
    pub fn alternate_of(&self, tx: &TxId) -> Option<ConnectionId> {
        self.embargoes.held.get(tx).and_then(|held| held.alternate)
    }

    /// `txs` arrived from somewhere other than where this node sent them:
    /// each one's embargo is disarmed and its state dropped. An arrival from
    /// a peer of a transaction this node holds unsent means it circulates
    /// already; that state goes too. Returns the ids now known to circulate,
    /// for the FFI to mark shown (Q9).
    pub(super) fn disarm(
        &mut self,
        propagated: Vec<TxId>,
        txs: &[TxId],
        from: Option<ConnectionId>,
    ) -> Vec<TxId> {
        let mut circulating = propagated;
        for tx in &circulating {
            self.embargoes.held.remove(tx);
        }
        if from.is_some() {
            for tx in txs {
                if self.embargoes.unsent.remove(tx).is_some() {
                    circulating.push(*tx);
                }
            }
        }
        circulating
    }
}
