// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The relay timing state machine: epoch rotation, fluff batching, and the
//! stem embargo.
//!
//! This module owns *when*, never *how*. It never serializes a message, never
//! chooses which peers are eligible, and never touches a socket — the caller
//! supplies the eligible peer set and acts on the deadlines returned. That
//! split is deliberate and is the seam a future FFI cut would follow: message
//! construction in the inherited C++ is epee binary serialization plus levin
//! framing, fragmentation and compression, none of which has a Rust
//! implementation in this workspace and none of which needs one for the
//! timing to be correct.
//!
//! # No async runtime
//!
//! Every type here is a plain `&mut self` state machine that returns the next
//! deadline in monotonic milliseconds. Nothing spawns, sleeps, or awaits. The
//! daemon's relay path lives inside a `boost::asio` strand; a Rust core that
//! demanded its own reactor would mean reconciling two event loops for no
//! gain. The caller arms whatever timer it already has.
//!
//! # Time
//!
//! Milliseconds on an unspecified monotonic origin — the `steady_clock` the
//! inherited code uses, with the units made explicit. Nothing here reads a
//! wall clock, which is what makes a whole epoch replayable from a seed.

use std::collections::BTreeMap;

use crate::geometric::GeometricTable;
use crate::params::{inherited, DandelionParams};
use crate::poisson::PoissonTable;
use crate::rng::{bernoulli, bounded_uniform, RelayRng};
use crate::stem_map::ConnectionId;

/// Monotonic milliseconds. Not a wall-clock time and not comparable across
/// processes.
pub type Millis = u64;

/// Which side opened a connection.
///
/// The inherited code gives outbound peers half the fluff delay of inbound
/// ones, on the reasoning — borrowed from Bitcoin Core, and consistent with
/// Dandelion++'s own stem assumptions — that a node controls who it connects
/// *to* but not who connects *to it*, so an adversary learns less from the
/// timing of an outbound send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDirection {
    /// The peer connected to us.
    Inbound,
    /// We connected to the peer.
    Outbound,
}

/// The state of one Dandelion++ epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch {
    /// True if this node spends the epoch fluffing everything it receives
    /// rather than stemming. Drawn once per epoch, per the paper's `q`.
    pub fluffing: bool,
    /// Monotonic deadline at which this epoch ends and the next is drawn.
    pub ends_at: Millis,
}

/// Draws epoch boundaries and the per-epoch fluff/stem role.
#[derive(Debug, Clone, Copy)]
pub struct EpochScheduler {
    params: DandelionParams,
}

impl EpochScheduler {
    /// Construct over a parameter set.
    #[must_use]
    pub const fn new(params: DandelionParams) -> Self {
        Self { params }
    }

    /// Parameters in force.
    #[must_use]
    pub const fn params(&self) -> &DandelionParams {
        &self.params
    }

    /// Begin an epoch at `now`.
    ///
    /// The duration is `min_epoch + U[0, jitter]`, matching
    /// `levin_notify.cpp:718`. The jitter is what stops every node on the
    /// network from rotating its stem peers in lockstep, which would give an
    /// observer a global synchronization signal to align traffic against.
    pub fn start<R: RelayRng + ?Sized>(&self, now: Millis, rng: &mut R) -> Epoch {
        let fluffing = bernoulli(rng, u64::from(self.params.fluff_probability_pct), 100);
        let jitter_ms = u64::from(self.params.epoch_jitter_secs) * 1_000;
        let offset = if jitter_ms == 0 {
            0
        } else {
            bounded_uniform(rng, jitter_ms)
        };
        let span = u64::from(self.params.min_epoch_secs)
            .saturating_mul(1_000)
            .saturating_add(offset);
        Epoch {
            fluffing,
            ends_at: now.saturating_add(span),
        }
    }
}

/// Per-peer fluff batching with a single next-deadline.
///
/// Every peer accumulates a batch and flushes on its own randomized deadline.
/// The inherited implementation keeps one system timer per zone and re-arms it
/// to the minimum pending deadline rather than holding a timer per peer;
/// [`FluffScheduler::next_deadline`] is that minimum, so a caller can keep the
/// same single-timer shape.
///
/// This type tracks deadlines only. The transaction payloads stay with the
/// caller: batching *content* is transport, batching *time* is privacy.
#[derive(Debug, Clone)]
pub struct FluffScheduler {
    inbound: DelayTable,
    outbound: DelayTable,
    family: DelayFamily,
    /// Peers with a batch in flight, and when it flushes.
    pending: BTreeMap<ConnectionId, Millis>,
}

/// One of the two delay tables, chosen at construction.
///
/// Shared by [`FluffScheduler`], [`EmbargoTimer`], and the flood instruments in
/// [`crate::conformance`]: a single enum so nothing re-implements dual-`Option`
/// table state.
#[derive(Debug, Clone)]
pub(crate) enum DelayTable {
    Poisson(PoissonTable),
    Geometric(GeometricTable),
}

impl DelayTable {
    /// Build a table at a mean expressed in the caller's tick unit (seconds,
    /// quarter-seconds, or derived embargo ticks — unit-agnostic).
    pub(crate) fn build(mean_ticks: u32, family: DelayFamily) -> Self {
        match family {
            DelayFamily::Poisson => Self::Poisson(PoissonTable::new(mean_ticks)),
            DelayFamily::Geometric => Self::Geometric(GeometricTable::new(mean_ticks)),
        }
    }

    pub(crate) fn draw<R: RelayRng + ?Sized>(&self, rng: &mut R) -> u64 {
        match self {
            Self::Poisson(t) => t.draw(rng),
            Self::Geometric(t) => t.draw(rng),
        }
    }

    pub(crate) fn family(&self) -> DelayFamily {
        match self {
            Self::Poisson(_) => DelayFamily::Poisson,
            Self::Geometric(_) => DelayFamily::Geometric,
        }
    }

    pub(crate) fn is_truncated(&self) -> bool {
        match self {
            Self::Poisson(_) => false,
            Self::Geometric(t) => t.is_truncated(),
        }
    }
}

impl FluffScheduler {
    /// Construct exactly what the daemon ships: `std::poisson_distribution` at
    /// λ = 20 quarter-seconds inbound (5 s) and λ = 10 outbound (2.5 s).
    ///
    /// **This carries the same defect as the inherited embargo, and it matters
    /// more.** The `levin_notify.cpp:84-88` comment names Bitcoin Core as the
    /// reference for the outbound/inbound asymmetry. Bitcoin Core's send timer
    /// (`PoissonNextSend`) draws `-ln(U)·mean` — the *inter-arrival time of a
    /// Poisson process*, which is an **exponential**. The inherited code
    /// implements `std::poisson_distribution` instead, which is the discrete
    /// *count* of a Poisson process, not its inter-arrival time. The names
    /// coincide; the distributions do not.
    ///
    /// The consequence is worse here than for the embargo. The embargo is a
    /// rare backstop; the fluff delay is applied by every node to every
    /// transaction, and its entire purpose is to stop an observer inferring
    /// *when a node received a transaction* from *when it relayed it*. A
    /// Poisson at λ = 20 has a coefficient of variation of 0.22 — relay lands
    /// at receipt + 5 s ± 1.1 s, which inverts almost perfectly. An exponential
    /// at the same mean has CV = 1 and does not. See
    /// `conformance::fluff_timing_inference` for the measured attack.
    ///
    /// The quarter-second granularity, by contrast, is sound and its comment at
    /// `levin_notify.cpp:75-80` is the one derivation in this subsystem that
    /// survives checking.
    #[must_use]
    pub fn inherited() -> Self {
        Self::new(
            inherited::FLUFF_AVERAGE_IN_QUARTER_SECS,
            inherited::FLUFF_AVERAGE_OUT_QUARTER_SECS,
            DelayFamily::Poisson,
        )
    }

    /// Construct with the memoryless delay Bitcoin Core actually uses and the
    /// Dandelion++ diffusion phase assumes, at the inherited means.
    #[must_use]
    pub fn memoryless() -> Self {
        Self::new(
            inherited::FLUFF_AVERAGE_IN_QUARTER_SECS,
            inherited::FLUFF_AVERAGE_OUT_QUARTER_SECS,
            DelayFamily::Geometric,
        )
    }

    /// Construct with explicit means (both in quarter-seconds) and an explicit
    /// delay family.
    #[must_use]
    pub fn new(inbound_quarter_secs: u32, outbound_quarter_secs: u32, family: DelayFamily) -> Self {
        Self {
            inbound: DelayTable::build(inbound_quarter_secs, family),
            outbound: DelayTable::build(outbound_quarter_secs, family),
            family,
            pending: BTreeMap::new(),
        }
    }

    /// Delay family in force.
    #[must_use]
    pub const fn family(&self) -> DelayFamily {
        self.family
    }

    /// Alias retained for call sites that still say "distribution".
    #[must_use]
    pub const fn distribution(&self) -> DelayFamily {
        self.family
    }

    /// Queue a peer for fluffing at `now`, returning the earliest pending
    /// deadline across all peers.
    ///
    /// If the peer already has a batch in flight its deadline is **not**
    /// redrawn — the new transactions join the existing batch. That is load
    /// bearing: redrawing on every arrival would let a steady stream of
    /// transactions push a peer's flush indefinitely into the future, and
    /// would leak arrival timing into flush timing.
    pub fn queue<R: RelayRng + ?Sized>(
        &mut self,
        now: Millis,
        peer: ConnectionId,
        direction: PeerDirection,
        rng: &mut R,
    ) -> Millis {
        self.pending.entry(peer).or_insert_with(|| {
            let table = match direction {
                PeerDirection::Inbound => &self.inbound,
                PeerDirection::Outbound => &self.outbound,
            };
            let quarter_secs = table.draw(rng);
            now.saturating_add(quarter_secs.saturating_mul(250))
        });
        self.next_deadline()
            .expect("a peer was just queued, so a deadline exists")
    }

    /// Peers whose batch is due at `now`, removed from the pending set.
    ///
    /// Returned in `ConnectionId` order, not insertion order. The inherited
    /// code sorts and de-duplicates each batch before sending for the same
    /// reason — receive order is information, and echoing it back out hands an
    /// observer a correlation handle it did not otherwise have.
    pub fn due(&mut self, now: Millis) -> Vec<ConnectionId> {
        let ready: Vec<ConnectionId> = self
            .pending
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &ready {
            self.pending.remove(peer);
        }
        ready
    }

    /// Flush everything regardless of deadline, as the inherited code does
    /// when its timer is cancelled (peer teardown, or the test hook
    /// `notify::run_fluff`).
    pub fn drain(&mut self) -> Vec<ConnectionId> {
        let all: Vec<ConnectionId> = self.pending.keys().copied().collect();
        self.pending.clear();
        all
    }

    /// Forget a peer entirely — it disconnected before its batch flushed.
    pub fn forget(&mut self, peer: ConnectionId) {
        self.pending.remove(&peer);
    }

    /// Earliest pending flush deadline, or `None` if nothing is queued.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Millis> {
        self.pending.values().copied().min()
    }

    /// Number of peers with a batch in flight.
    #[must_use]
    pub fn pending_peers(&self) -> usize {
        self.pending.len()
    }
}

/// The delay-shape family for a randomized relay delay — `Poisson` (what the
/// inherited daemon draws) versus `Geometric` (the memoryless family the
/// derivation assumes).
///
/// Shared by *all* the relay delays this crate models: the stem embargo, the
/// fluff delay ([`FluffScheduler`]), and the flood-return instruments in
/// [`crate::conformance`]. Pure distribution-family choice; no embargo-specific
/// semantics.
///
/// For the embargo it is not a tuning knob but a correctness question: the
/// Dandelion++ embargo formula is derived from an exponential survival function,
/// while the inherited daemon draws from a Poisson. See [`crate::geometric`] for
/// the full argument and the measurement tests for the measured consequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelayFamily {
    /// What the inherited C++ does: `crypto::random_poisson_seconds`. Tightly
    /// clustered around the mean (`CV = 1/√λ`).
    Poisson,
    /// The discrete memoryless delay the derivation actually assumes
    /// (`CV ≈ 1`).
    Geometric,
}

/// Historical name for [`DelayFamily`]. Prefer the new name at new call sites.
#[deprecated(note = "renamed to DelayFamily — shared by all relay delays, not embargo-only")]
pub type EmbargoDistribution = DelayFamily;

/// The stem embargo: how long a node waits for a stemmed transaction to come
/// back to it as fluff before giving up and fluffing it itself.
///
/// This is the black-hole backstop. The **adopted** configuration is
/// [`Self::adopted`] — exact survival solve + memoryless draws at the default
/// tick. The closed-form helpers ([`Self::closed_form_poisson`],
/// [`Self::paper_faithful`]) exist only as measurement baselines against the
/// paper formula; they are not what this crate recommends shipping.
///
/// See [`crate::derive`] for the exact equation and [`crate::geometric`] for
/// why the distribution family differs from the inherited Poisson.
#[derive(Debug, Clone)]
pub struct EmbargoTimer {
    table: DelayTable,
    mean_secs: u32,
    tick_millis: u64,
}

/// Default tick for the memoryless embargo: a quarter second.
///
/// The same granularity the fluff flush already uses, and for the same reason.
/// The inherited embargo ticks in **whole seconds**
/// (`crypto::random_poisson_seconds`), which is coarse against a stem that
/// completes in ~700 ms: at a one-second tick, "fires within the first tick"
/// collapses to "fires at zero", and a measurable share of draws preempt
/// instantly for no reason other than rounding. Quarter seconds put the
/// discretization error below the effect being measured.
pub const DEFAULT_EMBARGO_TICK_MILLIS: u64 = 250;

impl EmbargoTimer {
    /// The configuration this crate recommends shipping: exact discrete survival
    /// solve ([`crate::derive_embargo`]) at [`DEFAULT_EMBARGO_TICK_MILLIS`],
    /// memoryless draws.
    ///
    /// This is the single authoritative production path. Prefer it over
    /// [`Self::closed_form_poisson`] / [`Self::paper_faithful`], which evaluate
    /// the paper's under-provisioning closed form for measurement only.
    ///
    /// # Panics
    ///
    /// Panics if the target full-travel probability is unreachable (it is not
    /// for any representable target strictly below 1).
    #[must_use]
    pub fn adopted(params: &DandelionParams) -> Self {
        let d = crate::derive::derive_embargo(
            params,
            DEFAULT_EMBARGO_TICK_MILLIS,
            crate::params::EMBARGO_FULL_TRAVEL_PROBABILITY,
        )
        .expect("full-travel target reachable below 1");
        Self::geometric_from_ticks(d.mean_ticks, d.tick_millis)
    }

    /// Closed-form mean + Poisson — measurement isolation only.
    ///
    /// Same distribution family as the daemon ships, mean corrected to what the
    /// paper formula yields. **Not** the adopted path; see [`Self::adopted`].
    #[must_use]
    pub fn closed_form_poisson(params: &DandelionParams) -> Self {
        Self::new(params.closed_form_embargo_secs(), DelayFamily::Poisson)
    }

    /// Historical name for [`Self::closed_form_poisson`].
    #[deprecated(
        note = "use closed_form_poisson for the diagnosis path, or adopted for production"
    )]
    #[must_use]
    pub fn derived(params: &DandelionParams) -> Self {
        Self::closed_form_poisson(params)
    }

    /// Build exactly what the daemon ships: 39 s, Poisson.
    ///
    /// Present so a measurement run can compare against it; it is not the
    /// configuration a design round should adopt without re-deriving it.
    #[must_use]
    pub fn inherited() -> Self {
        Self::new(
            DandelionParams::INHERITED_EMBARGO_SECS,
            DelayFamily::Poisson,
        )
    }

    /// Closed-form mean + memoryless delay — measurement isolation only.
    ///
    /// Isolates the distribution fix at the paper's plug-in mean. The adopted
    /// mean is longer ([`Self::adopted`]); this row exists so a table can
    /// separate "distribution" from "mean" without claiming either is shipped.
    #[must_use]
    pub fn paper_faithful(params: &DandelionParams) -> Self {
        Self::new(params.closed_form_embargo_secs(), DelayFamily::Geometric)
    }

    /// Build at an explicit mean and delay family, at the default tick.
    ///
    /// Poisson always ticks in whole seconds, because that is what the
    /// inherited `crypto::random_poisson_seconds` does and the point of this
    /// variant is to reproduce shipped behaviour. Geometric uses
    /// [`DEFAULT_EMBARGO_TICK_MILLIS`].
    ///
    /// # Panics
    ///
    /// Panics if `mean_secs` is zero: a zero embargo fluffs every stemmed
    /// transaction immediately, which silently disables the stem phase. That
    /// must fail loudly rather than ship as "very fast relay".
    #[must_use]
    pub fn new(mean_secs: u32, family: DelayFamily) -> Self {
        match family {
            DelayFamily::Poisson => {
                assert!(
                    mean_secs > 0,
                    "embargo mean must be non-zero — a zero embargo disables the stem phase"
                );
                Self {
                    table: DelayTable::build(mean_secs, DelayFamily::Poisson),
                    mean_secs,
                    tick_millis: 1_000,
                }
            }
            DelayFamily::Geometric => {
                Self::geometric_with_tick(mean_secs, DEFAULT_EMBARGO_TICK_MILLIS)
            }
        }
    }

    /// Build a memoryless embargo with an explicit tick.
    ///
    /// The tick is not cosmetic. A discrete geometric is the exact
    /// discretization of an exponential *at that tick*, so a coarse tick
    /// systematically over-reports early firing: at a one-second tick against
    /// a sub-second stem, roughly a fifth of the measured preemption is
    /// rounding rather than mechanism. Shrinking the tick converges on the
    /// continuous result. The measurement tests measure the convergence rather
    /// than asserting it.
    ///
    /// # Panics
    ///
    /// Panics if `mean_secs` or `tick_millis` is zero, or if the mean rounds
    /// to zero ticks — each of which silently disables the embargo.
    #[must_use]
    pub fn geometric_with_tick(mean_secs: u32, tick_millis: u64) -> Self {
        assert!(
            mean_secs > 0,
            "embargo mean must be non-zero — a zero embargo disables the stem phase"
        );
        assert!(tick_millis > 0, "embargo tick must be non-zero");
        // Round the mean UP at a tick that does not divide 1000ms evenly:
        // under-provisioning the embargo fluffs prematurely, which is a privacy
        // loss (D-5's asymmetry), so the conservative direction is longer, not
        // shorter. Matches the `div_ceil` used for the reverse conversion below.
        let mean_ticks_u64 = (u64::from(mean_secs) * 1_000).div_ceil(tick_millis);
        let mean_ticks = u32::try_from(mean_ticks_u64).unwrap_or(u32::MAX);
        assert!(
            mean_ticks > 0,
            "embargo mean of {mean_secs}s rounds to zero at a {tick_millis}ms tick"
        );
        Self {
            table: DelayTable::build(mean_ticks, DelayFamily::Geometric),
            mean_secs,
            tick_millis,
        }
    }

    /// Build a memoryless embargo directly from a tick count.
    ///
    /// [`Self::geometric_with_tick`] takes seconds and reconverts, which loses
    /// the sub-second precision [`crate::derive`] produces — the derived 446
    /// ticks (111.5 s) becomes 448 ticks if round-tripped through `112 s`. When
    /// the mean *is* the derivation's own `mean_ticks`, use this so the
    /// measurement is taken at exactly the value that was solved for.
    ///
    /// # Panics
    ///
    /// Panics if `mean_ticks` or `tick_millis` is zero.
    #[must_use]
    pub fn geometric_from_ticks(mean_ticks: u32, tick_millis: u64) -> Self {
        assert!(mean_ticks > 0, "embargo mean must be non-zero");
        assert!(tick_millis > 0, "embargo tick must be non-zero");
        let mean_secs = u32::try_from((u64::from(mean_ticks) * tick_millis).div_ceil(1_000))
            .unwrap_or(u32::MAX);
        Self {
            table: DelayTable::build(mean_ticks, DelayFamily::Geometric),
            mean_secs,
            tick_millis,
        }
    }

    /// Mean in force, in seconds.
    #[must_use]
    pub const fn mean_secs(&self) -> u32 {
        self.mean_secs
    }

    /// Timer granularity in milliseconds.
    #[must_use]
    pub const fn tick_millis(&self) -> u64 {
        self.tick_millis
    }

    /// Delay family in force.
    #[must_use]
    pub fn family(&self) -> DelayFamily {
        self.table.family()
    }

    /// Alias retained for call sites that still say "distribution".
    #[must_use]
    pub fn distribution(&self) -> DelayFamily {
        self.family()
    }

    /// True if the underlying table clipped its upper tail — see
    /// [`GeometricTable::is_truncated`]. Always false for Poisson.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.table.is_truncated()
    }

    /// Draw an embargo deadline relative to `now`.
    pub fn deadline<R: RelayRng + ?Sized>(&self, now: Millis, rng: &mut R) -> Millis {
        let ticks = self.table.draw(rng);
        now.saturating_add(ticks.saturating_mul(self.tick_millis))
    }
}

/// Noise-channel send cadence for the I2P/Tor zones.
///
/// Constant-rate cover traffic, a different mechanism from Dandelion++ that
/// happens to share the inherited `zone` struct and its timers. It is here
/// because it draws from the same uniform primitive and raises the same
/// conformance question, not because it is part of Dandelion++.
#[derive(Debug, Clone, Copy)]
pub struct NoiseCadence {
    min_delay_secs: u32,
    jitter_secs: u32,
}

impl NoiseCadence {
    /// The inherited cadence: 10 s + U[0, 5 s] between covert sends.
    #[must_use]
    pub const fn inherited() -> Self {
        Self {
            min_delay_secs: inherited::NOISE_MIN_DELAY_SECS,
            jitter_secs: inherited::NOISE_DELAY_JITTER_SECS,
        }
    }

    /// Next covert-send deadline relative to `start`.
    pub fn next_send<R: RelayRng + ?Sized>(&self, start: Millis, rng: &mut R) -> Millis {
        let jitter_ms = u64::from(self.jitter_secs) * 1_000;
        let offset = if jitter_ms == 0 {
            0
        } else {
            bounded_uniform(rng, jitter_ms)
        };
        start
            .saturating_add(u64::from(self.min_delay_secs).saturating_mul(1_000))
            .saturating_add(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;

    fn peer(i: u8) -> ConnectionId {
        let mut b = [0_u8; 16];
        b[0] = i;
        ConnectionId::from_bytes(b)
    }

    #[test]
    fn epoch_spans_the_configured_band() {
        let s = EpochScheduler::new(DandelionParams::inherited());
        let mut rng = SplitMix64::new(1);
        for _ in 0..2_000 {
            let e = s.start(1_000, &mut rng);
            // 10 min .. 10 min + 30 s.
            assert!(
                (601_000..=631_000).contains(&e.ends_at),
                "epoch end {} outside band",
                e.ends_at
            );
        }
    }

    #[test]
    fn epoch_fluff_rate_tracks_the_parameter() {
        let s = EpochScheduler::new(DandelionParams::inherited());
        let mut rng = SplitMix64::new(2);
        let n = 20_000;
        let fluffing = (0..n).filter(|_| s.start(0, &mut rng).fluffing).count();
        // q = 20%; coarse band, the strict grade lives in `conformance`.
        assert!(
            (3_600..4_400).contains(&fluffing),
            "fluff epochs {fluffing}/{n}"
        );
    }

    #[test]
    fn outbound_peers_flush_sooner_than_inbound_on_average() {
        // The half-average asymmetry is a design claim; assert it holds.
        let mut f = FluffScheduler::inherited();
        let mut rng = SplitMix64::new(3);
        let n = 5_000_u64;

        let mut in_total = 0_u64;
        let mut out_total = 0_u64;
        for i in 0..n {
            let p = peer(1);
            f.queue(0, p, PeerDirection::Inbound, &mut rng);
            in_total += f.next_deadline().unwrap();
            f.forget(p);
            let q = peer(2);
            f.queue(0, q, PeerDirection::Outbound, &mut rng);
            out_total += f.next_deadline().unwrap();
            f.forget(q);
            let _ = i;
        }
        let in_mean = in_total / n;
        let out_mean = out_total / n;
        assert!(
            out_mean * 2 < in_mean * 3 && out_mean < in_mean,
            "inbound mean {in_mean} ms, outbound mean {out_mean} ms — expected ~2:1"
        );
        // Inbound λ = 20 quarter-seconds = 5000 ms.
        assert!((4_700..5_300).contains(&in_mean), "inbound mean {in_mean}");
        assert!(
            (2_300..2_700).contains(&out_mean),
            "outbound mean {out_mean}"
        );
    }

    #[test]
    fn requeueing_a_peer_does_not_push_its_deadline() {
        let mut f = FluffScheduler::inherited();
        let mut rng = SplitMix64::new(4);
        let p = peer(9);
        let first = f.queue(0, p, PeerDirection::Inbound, &mut rng);
        for t in 1..500 {
            let again = f.queue(t, p, PeerDirection::Inbound, &mut rng);
            assert_eq!(again, first, "a second queue redrew the deadline");
        }
    }

    #[test]
    fn due_returns_only_expired_peers_and_clears_them() {
        let mut f = FluffScheduler::inherited();
        let mut rng = SplitMix64::new(5);
        for i in 0..10 {
            f.queue(0, peer(i), PeerDirection::Inbound, &mut rng);
        }
        assert_eq!(f.pending_peers(), 10);

        let cutoff = f.next_deadline().unwrap();
        let ready = f.due(cutoff);
        assert!(!ready.is_empty(), "the minimum deadline must be due");
        assert_eq!(f.pending_peers(), 10 - ready.len());

        // Far future clears the rest.
        let rest = f.due(Millis::MAX);
        assert_eq!(rest.len(), 10 - ready.len());
        assert_eq!(f.next_deadline(), None);
    }

    #[test]
    fn due_is_ordered_not_insertion_ordered() {
        let mut f = FluffScheduler::inherited();
        let mut rng = SplitMix64::new(6);
        for i in (0..8).rev() {
            f.queue(0, peer(i), PeerDirection::Inbound, &mut rng);
        }
        let ready = f.due(Millis::MAX);
        let mut sorted = ready.clone();
        sorted.sort_unstable();
        assert_eq!(ready, sorted, "flush order leaked insertion order");
    }

    #[test]
    fn drain_and_forget_clear_state() {
        let mut f = FluffScheduler::inherited();
        let mut rng = SplitMix64::new(7);
        f.queue(0, peer(1), PeerDirection::Inbound, &mut rng);
        f.queue(0, peer(2), PeerDirection::Outbound, &mut rng);
        f.forget(peer(1));
        assert_eq!(f.pending_peers(), 1);
        assert_eq!(f.drain().len(), 1);
        assert_eq!(f.next_deadline(), None);
        assert!(f.due(Millis::MAX).is_empty());
    }

    #[test]
    fn closed_form_poisson_mean_matches_its_parameter() {
        let closed = EmbargoTimer::closed_form_poisson(&DandelionParams::inherited());
        assert_eq!(closed.mean_secs(), 17);
        assert_eq!(EmbargoTimer::inherited().mean_secs(), 39);

        let mut rng = SplitMix64::new(8);
        let n = 20_000_u64;
        let total: u64 = (0..n).map(|_| closed.deadline(0, &mut rng)).sum();
        let mean_secs = total / n / 1_000;
        assert!((16..=18).contains(&mean_secs), "embargo mean {mean_secs}s");
    }

    #[test]
    fn adopted_embargo_is_exact_solve_memoryless() {
        let params = DandelionParams::inherited();
        let adopted = EmbargoTimer::adopted(&params);
        assert_eq!(adopted.family(), DelayFamily::Geometric);
        assert_eq!(adopted.tick_millis(), DEFAULT_EMBARGO_TICK_MILLIS);
        // Exact solve under-provisions the closed form; adopted mean is the
        // longer one (RD-1/RD-4 corrections push it past 100 s).
        assert!(
            adopted.mean_secs() > params.closed_form_embargo_secs(),
            "adopted {}s should exceed closed form {}s",
            adopted.mean_secs(),
            params.closed_form_embargo_secs()
        );
        assert!(!adopted.is_truncated());
    }

    #[test]
    fn paper_faithful_embargo_shares_the_mean_but_not_the_spread() {
        let params = DandelionParams::inherited();
        let poisson = EmbargoTimer::closed_form_poisson(&params);
        let geometric = EmbargoTimer::paper_faithful(&params);
        assert_eq!(poisson.mean_secs(), geometric.mean_secs());
        assert_eq!(poisson.family(), DelayFamily::Poisson);
        assert_eq!(geometric.family(), DelayFamily::Geometric);

        // Only the geometric can produce a near-immediate embargo, which is
        // exactly the behaviour the derivation assumes is available.
        let mut rng = SplitMix64::new(31);
        let n = 20_000;
        let early_geo = (0..n)
            .filter(|_| geometric.deadline(0, &mut rng) < 2_000)
            .count();
        let early_poi = (0..n)
            .filter(|_| poisson.deadline(0, &mut rng) < 2_000)
            .count();
        assert!(
            early_geo > 500,
            "memoryless embargo should fire early sometimes: {early_geo}/{n}"
        );
        assert_eq!(
            early_poi, 0,
            "Poisson at mean 17 should essentially never fire inside 2s"
        );
    }

    #[test]
    #[should_panic(expected = "disables the stem phase")]
    fn zero_embargo_is_rejected() {
        let timer = EmbargoTimer::new(0, DelayFamily::Poisson);
        assert_eq!(
            timer.mean_secs(),
            0,
            "unreachable: construction panics above"
        );
    }

    #[test]
    fn noise_cadence_spans_its_band() {
        let c = NoiseCadence::inherited();
        let mut rng = SplitMix64::new(9);
        for _ in 0..2_000 {
            let t = c.next_send(500, &mut rng);
            assert!((10_500..=15_500).contains(&t), "noise send at {t}");
        }
    }
}
