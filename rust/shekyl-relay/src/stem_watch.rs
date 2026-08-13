// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-successor stem outcomes — the signal §12.11 specifies, recorded here.
//! (`DAEMON_RELAY_PRIVACY.md` §33.2 named the gap this type closed; the
//! wiring is live — see the call-chain diagram below. Recording is all that
//! is live: nothing consumes the tallies as reputation yet, per the
//! deliberately-open parameters listed further down.)
//!
//! # Why this derives the outcome instead of importing it
//!
//! The obvious wiring is to let `tx_pool` report each embargo's resolution,
//! since that is where the embargo arms and fires today. **Rejected under rule
//! 20.** `tx_pool` holds no relay-zone handle, so importing the outcome means
//! building a new C++ path from the mempool into the relay layer, and every
//! byte of that path is C++ deciding something Rust could decide.
//!
//! The relay layer already sees **both directions**: it *chooses* the stem
//! successor, and it is told the `source` of every transaction that arrives.
//! So *"did my successor propagate this?"* is answerable here, from facts this
//! layer already owns, and the only thing C++ must hand over is the
//! transaction's identity — data, not a decision.
//!
//! **The definitions differ slightly, and this one is the more correct for the
//! purpose.** `tx_pool` disarms on `upgrade_relay_method` — pool *admission*.
//! This disarms on re-arrival — *propagation*. A transaction that comes back
//! and is then rejected by the pool still proves the successor relayed it,
//! which is exactly what the reputation signal is asking about. The divergence
//! is named here rather than discovered when the two are compared.
//!
//! # What is deliberately NOT decided here
//!
//! This type **records**; it does not judge. Three parameters are open in the
//! design doc and none is baked in:
//!
//! - **Accumulator memory** (§37.3) — windowed versus cumulative is *upstream*
//!   of every threshold, and under cumulative memory §36.1's integer-ladder
//!   finding does not even apply. [`StemTally`] therefore exposes raw counts
//!   and lets a consumer window them; it does not decay, reset, or average.
//! - **The `(n_min, cut)` pair** (§36.1) — a *rate* threshold is the wrong
//!   parameterisation at these counts, so nothing here compares a ratio.
//! - **Distinct source-mappings** (§35.4) — tracked, because `in_mapping_`
//!   already holds the information and it is the admissibility gate's input,
//!   but not thresholded.
//!
//! Baking any of them in would freeze a decision the round has explicitly left
//! open, and would do it in the layer hardest to change later.
//!
//! # Scope: every zone that stems is observed
//!
//! Nothing on this side chooses which zones are observed; the caller does.
//! Since §89.5 (GATE 3 of 3 deleted) Dandelion++ runs on **every** zone, not
//! only clearnet -- `dandelionpp_notify` is no longer gated on
//! `nzone == public_`. An i2p/tor zone that stems produces stem observations
//! like any other. Q12-U3's `/get_stem_tallies` row carries a `zone` label
//! at the C++ merge so those observations are distinguishable.
//!
//! ```text
//! levin_notify.cpp  dandelionpp_notify        <- every zone, noise-off
//!         |
//!         v
//! levin_notify.cpp  record_stem_observation
//!         |
//!         v
//! shekyl-ffi        shekyl_relay_zone_record_stem
//!         |
//!         v
//! shekyl-relay      Zone::record_stem  ->  StemWatch::stemmed
//! ```
//!
//! **An empty tally for a zone that is not configured still means "no
//! stems", not "no drops".** The two read identically off [`StemTally`] and
//! mean opposite things. The zone label is how an operator tells a zone
//! that is not running from one that is running clean. The endpoint stays
//! AdminOnly: a per-successor tally set is the node's anonymity-graph
//! edge set, and a zone label is strictly more disclosive than the
//! flattened list.

use std::collections::HashMap;

use shekyl_relay_privacy::schedule::Millis;
use shekyl_relay_privacy::stem_map::ConnectionId;

/// A transaction's identity, as the relay layer sees it.
///
/// Opaque 32 bytes: this layer never interprets them, it only joins on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Wrap 32 bytes of transaction identity.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    // A `from_blob` constructor briefly lived here, deriving the key from
    // blob bytes on the rule-20 argument that the join is local. Deleted at
    // F-9 (§48): the join is local but its INPUTS are not — the stem side
    // hashes what it sent, the arrival side what the network returned, and
    // nothing enforces that intermediate nodes preserve encoding. The key
    // must be the canonical transaction hash, which is computed from the
    // parsed transaction and is what the consensus hash exists FOR.

    /// The underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// What a stem observation resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StemOutcome {
    /// The transaction came back before its deadline — the successor relayed
    /// it. `tx_pool`'s embargo would have disarmed.
    Propagated,
    /// The deadline passed with no re-arrival. Either the successor dropped
    /// it, or this is an **ambient** failure — and the two are
    /// indistinguishable *by construction*, which is why the ambient rate is a
    /// security input (§37.1) and not merely a calibration constant.
    Silent,
}

/// Per-successor outcome counts, plus the admissibility-gate input.
///
/// **Raw counts only.** See the module note: memory policy, thresholds and the
/// `(n_min, cut)` pair are all open decisions, and a tally that decayed or
/// compared would have chosen one. Counters are `u64` so a long-lived node
/// under cumulative memory (§37.3 still open) cannot wrap a `u32` and corrupt
/// the future selection consumer's `n`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StemTally {
    /// Observations that resolved as [`StemOutcome::Propagated`].
    pub propagated: u64,
    /// Observations that resolved as [`StemOutcome::Silent`].
    pub silent: u64,
    /// Distinct `in_mapping_` keys that contributed observations — the
    /// §35.4 admissibility-gate input. Farmed observations all arrive under
    /// **one** key (the farmer's own), honest traffic under many.
    ///
    /// A locally-originated transaction has no source, and its key is
    /// recorded as `None`, matching `in_mapping_[nil]`.
    sources: std::collections::BTreeSet<Option<ConnectionId>>,
}

impl StemTally {
    /// Total resolved observations — `n` in §36's `(n_min, cut)`.
    #[must_use]
    pub fn observations(&self) -> u64 {
        self.propagated.saturating_add(self.silent)
    }

    /// How many distinct source-mappings contributed (§35.4).
    #[must_use]
    pub fn distinct_sources(&self) -> usize {
        self.sources.len()
    }
}

/// Light export of a [`StemTally`] for telemetry and off-strand publish.
///
/// Three numbers only — no source-set clone. The readout (§55) and any
/// future FFI/RPC path should take this rather than cloning [`StemTally`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StemTallySnapshot {
    pub propagated: u64,
    pub silent: u64,
    /// Distinct `in_mapping_` keys that contributed (§35.4).
    pub distinct_sources: u64,
}

impl From<&StemTally> for StemTallySnapshot {
    fn from(t: &StemTally) -> Self {
        Self {
            propagated: t.propagated,
            silent: t.silent,
            // `BTreeSet::len` is `usize`; cast once at the export edge so the
            // wire/readout contract stays a fixed-width counter.
            distinct_sources: t.distinct_sources() as u64,
        }
    }
}

/// Stem observations in flight, and their per-successor resolutions.
///
/// One instance per zone, owned by [`crate::Zone`]. Sync by construction:
/// nothing here sleeps or spawns — [`StemWatch::expire`] is driven from the
/// same `now` the rest of the zone's schedule uses, so the outcome is a
/// function of the poll clock exactly as every other relay decision is.
#[derive(Debug, Default)]
pub struct StemWatch {
    /// `tx → (successor, source, deadline)` for observations not yet resolved.
    pending: HashMap<TxId, Pending>,
    /// Resolved counts, per successor.
    tallies: HashMap<ConnectionId, StemTally>,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    successor: ConnectionId,
    source: Option<ConnectionId>,
    deadline: Millis,
}

impl StemWatch {
    /// Record that `tx` was stemmed to `successor`, keyed under `source`
    /// (`None` for locally originated — `in_mapping_[nil]`), and must be seen
    /// again by `deadline`.
    ///
    /// A repeat stem of the same `tx` **replaces** the pending entry rather
    /// than adding a second: the reshape path re-stems a transaction to a
    /// different successor, and the observation belongs to whoever holds it
    /// now. Without this the original successor would be charged for a
    /// silence it was never given the chance to break.
    pub fn stemmed(
        &mut self,
        tx: TxId,
        successor: ConnectionId,
        source: Option<ConnectionId>,
        deadline: Millis,
    ) {
        self.pending.insert(
            tx,
            Pending {
                successor,
                source,
                deadline,
            },
        );
    }

    /// Record that `tx` was seen again, arriving `from` a peer (`None` when
    /// the arrival has no peer — a local re-relay or a synthetic call).
    ///
    /// Resolves a pending observation as [`StemOutcome::Propagated`] — unless
    /// the arrival came **from the successor the observation is charged to**,
    /// which resolves nothing (F-10, §49).
    ///
    /// **The exclusion is the whole signal.** Without it the successor
    /// holding `O`'s stem slot drops the transaction, echoes the same bytes
    /// back, and resolves its own observation for the cost of one message —
    /// a total defeat available to precisely the adversary this mechanism
    /// exists to detect. *Any peer* and *any zone* are different relaxations:
    /// the zone must be unconstrained (a stem placed on one zone can return
    /// through another), the peer must not be.
    ///
    /// The narrowest form that works: *"someone else has it"* is propagation;
    /// *"the peer I gave it to gave it back"* is nothing. An arrival with no
    /// peer (`None`) can never equal a successor, which is always a real
    /// connection — including for a locally-originated stem, whose `source`
    /// is `None` but whose `successor` is not — so no special case is needed.
    ///
    /// Unknown transactions are ignored: this node either never stemmed it or
    /// already resolved it, and neither is an error.
    pub fn seen(&mut self, tx: &TxId, from: Option<ConnectionId>) {
        let Some(p) = self.pending.get(tx) else {
            return;
        };
        if from.is_some_and(|f| f == p.successor) {
            return;
        }
        let p = self.pending.remove(tx).expect("checked present above");
        self.resolve(p, StemOutcome::Propagated);
    }

    /// Resolve every observation whose deadline has passed as
    /// [`StemOutcome::Silent`]. Driven from the zone's poll clock.
    ///
    /// Returns how many resolved, so a caller can assert the drive ran rather
    /// than inferring it from an unchanged tally — the liveness half of the
    /// standing witness discipline.
    pub fn expire(&mut self, now: Millis) -> usize {
        let due: Vec<TxId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(tx, _)| *tx)
            .collect();
        for tx in &due {
            if let Some(p) = self.pending.remove(tx) {
                self.resolve(p, StemOutcome::Silent);
            }
        }
        due.len()
    }

    fn resolve(&mut self, p: Pending, outcome: StemOutcome) {
        let tally = self.tallies.entry(p.successor).or_default();
        match outcome {
            StemOutcome::Propagated => tally.propagated += 1,
            StemOutcome::Silent => tally.silent += 1,
        }
        tally.sources.insert(p.source);
    }

    /// The tally for one successor, if it has any resolved observations.
    #[must_use]
    pub fn tally(&self, successor: &ConnectionId) -> Option<&StemTally> {
        self.tallies.get(successor)
    }

    /// Every successor with resolved observations, and its raw counts.
    ///
    /// **The telemetry readout (§55).** §12.11's remaining parameters are
    /// locally adaptive — they may ship reasonable and be tuned on operating
    /// data — but that argument is only honest if the data can be *read*,
    /// which makes this a precondition of shipping with them deferred rather
    /// than a follow-up to it.
    ///
    /// Raw counts, deliberately: §38.2's three open decisions (accumulator
    /// memory, the `(n_min, cut)` pair, persistence) stay open here too. **A
    /// snapshot that returned a *rate* would have chosen the memory policy on
    /// the tuner's behalf** — the one thing a readout must not do is
    /// pre-empt the decision it exists to inform.
    ///
    /// Only successors with at least one *resolved* observation appear.
    /// Absent and all-zero are different facts: an unproven peer and a
    /// perfect one must not read alike.
    ///
    /// Returns a light [`StemTallySnapshot`] — the three numbers a readout
    /// needs — rather than cloning the full [`StemTally`] (and its source
    /// set). In-process selection keeps using [`Self::tally`].
    #[must_use]
    pub fn snapshot(&self) -> Vec<(ConnectionId, StemTallySnapshot)> {
        let mut out: Vec<(ConnectionId, StemTallySnapshot)> = self
            .tallies
            .iter()
            .map(|(k, v)| (*k, StemTallySnapshot::from(v)))
            .collect();
        // Deterministic order: `HashMap` iteration is randomised per process,
        // and an operator diffing two snapshots should see content changes,
        // not ordering churn.
        out.sort_unstable_by_key(|(k, _)| *k);
        out
    }

    /// Observations still in flight — for the liveness assertions a witness
    /// needs, and for bounding the pending map in review.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Drop all state for a peer that is gone.
    ///
    /// **Two different things happen here and only one of them is obvious.**
    ///
    /// Dropping the **in-flight** observations is uncontroversial: a peer that
    /// disconnected was not given its deadline, so charging it a silence would
    /// be charging it for our own disconnect.
    ///
    /// Dropping the **tally** is a decision, not cleanup — **it answers
    /// §33.6's persistence question, and the answer is "no"** (F-8, §39). An
    /// earlier version of this comment claimed the type "does not quietly
    /// decide" persistence; it does, and the consequence is tighter than
    /// §33.6 analysed: reset happens at **connection** granularity, not
    /// process granularity, so the convergence condition is
    /// `warm-up ≪ mean outbound connection lifetime` — strictly stronger,
    /// since connection lifetime is bounded above by uptime.
    ///
    /// **Retention is not a one-line alternative.** [`ConnectionId`] is
    /// per-connection, so retaining across a disconnect needs a **durable peer
    /// key**, which is an address or an onion identity — a p2p-owned fact this
    /// layer deliberately does not hold. So retention pulls against Q-10.1's
    /// own answer (Rust owns the reputation state) and is a seam question in
    /// its own right, not a change of one line.
    pub fn forget(&mut self, peer: &ConnectionId) {
        self.tallies.remove(peer);
        self.pending.retain(|_, p| p.successor != *peer);
    }

    /// Earliest in-flight observation deadline, if any.
    ///
    /// Folded into [`crate::Driver::next_wake`] so silences resolve on the
    /// observation clock rather than waiting for an unrelated fluff/epoch
    /// wake. `None` when the map is empty — the other schedules carry the
    /// wake alone.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        self.pending.values().map(|p| p.deadline).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(b: u8) -> TxId {
        let mut x = [0u8; 32];
        x[0] = b;
        TxId::from_bytes(x)
    }
    fn peer(b: u8) -> ConnectionId {
        let mut x = [0u8; 16];
        x[0] = b;
        ConnectionId::from_bytes(x)
    }

    #[test]
    fn a_transaction_that_returns_before_its_deadline_counts_as_propagated() {
        let mut w = StemWatch::default();
        w.stemmed(tx(1), peer(9), None, 1_000);
        assert_eq!(w.in_flight(), 1, "fixture: the observation is armed");
        w.seen(&tx(1), Some(peer(3)));
        assert_eq!(w.in_flight(), 0, "resolution clears the pending entry");
        let t = w.tally(&peer(9)).expect("resolved against its successor");
        assert_eq!((t.propagated, t.silent), (1, 0));
        assert_eq!(t.observations(), 1);
    }

    #[test]
    fn a_transaction_that_never_returns_counts_as_silent_at_its_deadline() {
        let mut w = StemWatch::default();
        w.stemmed(tx(1), peer(9), None, 1_000);
        assert_eq!(w.expire(999), 0, "not due yet");
        assert!(w.tally(&peer(9)).is_none(), "nothing resolved before due");
        assert_eq!(w.expire(1_000), 1, "due at exactly the deadline");
        let t = w.tally(&peer(9)).expect("resolved");
        assert_eq!((t.propagated, t.silent), (0, 1));
    }

    #[test]
    fn a_re_stem_moves_the_observation_to_the_new_successor() {
        // The reshape path re-stems to a different successor. Charging the
        // ORIGINAL peer for the silence would blame it for a deadline it was
        // no longer holding — and reshape fires precisely when a successor
        // looks dark, so this is the operative case, not an edge one.
        let mut w = StemWatch::default();
        w.stemmed(tx(1), peer(1), None, 1_000);
        w.stemmed(tx(1), peer(2), None, 2_000);
        assert_eq!(w.in_flight(), 1, "one observation, not two");
        assert_eq!(w.expire(2_000), 1);
        assert!(
            w.tally(&peer(1)).is_none(),
            "the original successor is not charged for a silence it was not \
             given the chance to break"
        );
        assert_eq!(w.tally(&peer(2)).expect("re-stem target").silent, 1);
    }

    #[test]
    fn distinct_sources_counts_mappings_not_observations() {
        // §35.4's admissibility-gate input. Farmed observations arrive under
        // one key; this must count the keys, not the volume — a farmer
        // supplying 100 transactions still contributes ONE distinct source.
        let mut w = StemWatch::default();
        for i in 0..100u8 {
            w.stemmed(tx(i), peer(9), Some(peer(42)), 1_000);
            w.seen(&tx(i), Some(peer(42)));
        }
        let t = w.tally(&peer(9)).expect("resolved");
        assert_eq!(t.observations(), 100, "volume is counted");
        assert_eq!(
            t.distinct_sources(),
            1,
            "but 100 observations under one mapping are ONE source — if this \
             counts 100, the gate cannot distinguish farming from breadth"
        );

        w.stemmed(tx(200), peer(9), None, 1_000);
        w.seen(&tx(200), Some(peer(7)));
        assert_eq!(
            w.tally(&peer(9)).expect("resolved").distinct_sources(),
            2,
            "local origin is its own mapping (in_mapping_[nil])"
        );
    }

    #[test]
    fn a_successor_cannot_resolve_its_own_observation_by_echoing() {
        // F-10: the dropper's cheapest attack. It receives the stem, drops
        // it, and echoes the same bytes back — same canonical hash, so F-9's
        // fix does not help. If the echo resolves, the signal is defeated by
        // one message, by exactly the adversary it exists to detect.
        let mut w = StemWatch::default();
        w.stemmed(tx(1), peer(9), None, 1_000);

        w.seen(&tx(1), Some(peer(9)));
        assert_eq!(
            w.in_flight(),
            1,
            "an echo from the charged successor must resolve NOTHING — if this \
             is 0, a black hole clears its own record for the cost of one message"
        );
        assert!(w.tally(&peer(9)).is_none(), "and records no outcome");

        // Any other peer having it IS propagation — the exclusion must be
        // exactly one peer wide, or a real relay stops counting.
        w.seen(&tx(1), Some(peer(4)));
        assert_eq!(w.tally(&peer(9)).expect("resolved").propagated, 1);

        // And an arrival with no peer resolves: it cannot be the successor,
        // which is always a real connection.
        w.stemmed(tx(2), peer(9), None, 1_000);
        w.seen(&tx(2), None);
        assert_eq!(w.tally(&peer(9)).expect("resolved").propagated, 2);
    }

    #[test]
    fn the_snapshot_is_ordered_and_omits_peers_with_no_resolved_observations() {
        let mut w = StemWatch::default();
        // Inserted out of order; only peer 2 and peer 7 resolve anything.
        w.stemmed(tx(1), peer(7), None, 1_000);
        w.seen(&tx(1), Some(peer(3)));
        w.stemmed(tx(2), peer(2), None, 1_000);
        assert_eq!(w.expire(1_000), 1);
        w.stemmed(tx(3), peer(5), None, 9_000); // still pending — no outcome

        let snap = w.snapshot();
        assert_eq!(
            snap.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            vec![peer(2), peer(7)],
            "sorted, and peer 5 is ABSENT — pending is not an outcome, and an \
             unproven peer must not read as a measured-at-zero one"
        );
        assert_eq!(snap[0].1.silent, 1);
        assert_eq!(snap[1].1.propagated, 1);
    }

    #[test]
    fn forgetting_a_peer_drops_its_tally_and_its_in_flight_observations() {
        let mut w = StemWatch::default();
        w.stemmed(tx(1), peer(9), None, 1_000);
        w.seen(&tx(1), Some(peer(3)));
        w.stemmed(tx(2), peer(9), None, 5_000);
        assert!(w.tally(&peer(9)).is_some());
        w.forget(&peer(9));
        assert!(w.tally(&peer(9)).is_none(), "tally dropped, not retained");
        assert_eq!(
            w.in_flight(),
            0,
            "a disconnected peer is not charged for a deadline it never had"
        );
    }

    #[test]
    fn the_tally_records_and_does_not_judge() {
        // The type must not encode §37.3's memory policy or §36.1's (n_min,
        // cut) pair — both are open, and a tally that decayed or compared
        // would have chosen one. This asserts the surface stays raw: counts
        // in, counts out, no ratio and no decay.
        let mut w = StemWatch::default();
        for i in 0..10u8 {
            w.stemmed(tx(i), peer(9), None, 1_000);
        }
        assert_eq!(w.expire(1_000), 10);
        let t = w.tally(&peer(9)).expect("resolved");
        assert_eq!(
            (t.propagated, t.silent, t.observations()),
            (0, 10, 10),
            "counts are exact and undecayed after ten silences"
        );
    }

    #[test]
    fn next_deadline_is_the_earliest_in_flight_observation() {
        let mut w = StemWatch::default();
        assert!(w.next_deadline().is_none(), "empty watch has no wake");
        w.stemmed(tx(1), peer(9), None, 5_000);
        w.stemmed(tx(2), peer(8), None, 3_000);
        w.stemmed(tx(3), peer(7), None, 9_000);
        assert_eq!(w.next_deadline(), Some(3_000));
        w.seen(&tx(2), Some(peer(1)));
        assert_eq!(
            w.next_deadline(),
            Some(5_000),
            "resolving the earliest moves the wake to the next"
        );
    }
}
