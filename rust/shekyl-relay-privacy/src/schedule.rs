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

/// Walk a quantized table's masses until the remaining tail is within budget.
///
/// The masses partition `2^64` exactly (see `quantized_mass`), so the tail after
/// outcome `k` is `2^64 - cumulative`, computed in `u128` to avoid the boundary
/// case where the whole domain is one value.
fn survival_quantile(max_support: u64, mass: impl Fn(u64) -> u64, one_in: u64) -> u64 {
    assert!(one_in > 0, "false-fail rate must be a positive 1/n");
    const TOTAL: u128 = 1_u128 << 64;
    let allowed_tail = TOTAL / u128::from(one_in);

    let mut cumulative: u128 = 0;
    for k in 0..=max_support {
        cumulative += u128::from(mass(k));
        if TOTAL - cumulative <= allowed_tail {
            return k;
        }
    }
    // The table is finite, so its own top outcome always satisfies the bound.
    max_support
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

    /// The smallest tick count `t` for which at most `1 / one_in` of the mass
    /// remains **above** `t` — the exact survival quantile of the shipped table.
    ///
    /// Computed from the table's own quantized masses, which partition `2^64`
    /// exactly. That makes it integer, identical on every platform, and — the
    /// part that matters — faithful to the table's *truncation*. Reading the
    /// quantile off an idealised continuous tail instead would be the same
    /// species of error as F-1: a number that does not follow from the
    /// distribution actually shipped.
    ///
    /// # Panics
    ///
    /// Panics if `one_in` is zero.
    pub(crate) fn survival_quantile_ticks(&self, one_in: u64) -> u64 {
        match self {
            Self::Poisson(t) => survival_quantile(t.max_support(), |k| t.quantized_mass(k), one_in),
            Self::Geometric(t) => {
                survival_quantile(t.max_support(), |k| t.quantized_mass(k), one_in)
            }
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
///
/// # The shipped value, and why it is not 39 s
///
/// The daemon draws from [`Self::adopted`] — **mean 190 s, memoryless** — and
/// carries no embargo constant of its own (`DAEMON_RELAY_PRIVACY.md` §17). It
/// replaced an inherited `39 s` that was wrong three ways, each of which this
/// type is shaped to prevent recurring:
///
/// - The 39 s did not follow from the derivation printed beside it: that
///   formula, over its own stated `k=5, ep=0.10, hop=175 ms`, gives 16.61 s.
///   39 s reproduces only if `log10` is read for `ln`. **F-1.**
/// - It was drawn from a Poisson while the derivation assumed *exponential*
///   survival, so the backstop measurably never fired. **F-2.**
/// - The closed form substituted `E[K]` into an expression in `K(K-1)`; stem
///   length is geometric, so `E[K(K-1)] = 2·E[K](E[K]-1)` and the value
///   under-provisioned at every `q`. The exact solve gives 190 s at the
///   F-7-corrected `fluff_return_ms` (144 s at the old, defective input). **F-3.**
///
/// The lesson the type encodes: a timing constant and its derivation must live
/// in the same place. Anything that needs a number from this distribution
/// derives it here — see [`Self::judge_failed_after_secs`] — rather than
/// applying a multiplier at the call site.
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

/// The false-fail rate a sender's "this transaction failed" deadline is
/// provisioned at: **at most 1 in 100** embargoes is still running when a
/// still-unseen transaction is judged failed.
///
/// The rate is the decision; the seconds follow from it via
/// [`EmbargoTimer::judge_failed_after_secs`] over the shipped table. Stating it
/// this way is deliberate — a bare multiple of the mean (the inherited wallet
/// used `3/2`) is only the ~78th percentile of a memoryless distribution, so it
/// silently mislabels roughly a fifth of black-holed transactions as failed and
/// un-reserves their inputs. One in a hundred is the point where the deadline
/// stops being a coin-flip against the backstop it is waiting for.
///
/// The seconds this rate buys are pinned by
/// [`ADOPTED_PROPAGATION_TIMEOUT_SECS`] — **2 297 s**, drawn on the *worst
/// zone's* embargo since §89.2 made the embargo per-zone (it was 874 s when
/// the wait was the adopted clearnet embargo, and 664 s before F-7 corrected
/// `fluff_return_ms`; §44). Which zone the quantile is taken over is the
/// wallet-coupling defect §89.6 records, not a property of this rate.
///
/// Pin the seconds, not only the rate: the same F-1 class of defect reappears
/// if the wait is left as a loose bound that can drift when the table, tick,
/// or rounding changes.
pub const PROPAGATION_FALSE_FAIL_ONE_IN: u64 = 100;

/// Sender "still unseen → failed" wait, in seconds, at
/// [`PROPAGATION_FALSE_FAIL_ONE_IN`] — the **worst zone's**, deliberately.
///
/// **This constant is a deletion target (§89.6.)** A wallet safety invariant
/// should not be a function of a relay-privacy constant; the wallet should ask
/// the daemon whether a transaction is still in flight rather than time it. The
/// worst-zone global is the interim precisely because it needs no machinery and
/// is the cheapest thing to remove. Do not make it per-zone, and do not grow it
/// — the reasoning lives in §89.6, not here.
///
/// Cost of the interim, stated: a clearnet send reports failure at ~38 minutes
/// rather than ~15.
pub const ADOPTED_PROPAGATION_TIMEOUT_SECS: u32 = 2_297;

/// Mean of the i2p/tor → clearnet forwarding delay, in seconds.
///
/// **Unchanged at 22 s, deliberately.** This constant is Q-12's to derive and
/// this module does not derive it — what moves here is the *family*, not the
/// value. `CRYPTONOTE_FORWARD_DELAY_AVERAGE` remains the C++ mirror of this
/// number until Q-12 settles whether it survives at all.
///
/// Its provenance is unchanged too, and unflattering: inherited, with a stated
/// objective (*"2+ incoming connections could have sent the tx"*) that no
/// derivation has been shown to satisfy. Porting the family does not launder
/// that — see `DAEMON_RELAY_PRIVACY.md` §22.2.
pub const ADOPTED_FORWARD_DELAY_MEAN_SECS: u32 = 22;

/// The i2p/tor → clearnet forwarding delay, drawn **memoryless**.
///
/// # Why this exists, and why it is not a cleanup
///
/// The inherited draw is `crypto::random_poisson_seconds{22 s}` — a Poisson,
/// σ ≈ 4.7 s about a 22 s mean, against σ ≈ 22 s for the memoryless
/// equivalent. That is the **F-2/F-4 family signature**, and F-4 measured what
/// it costs: up to 93 % invertibility for a transaction arriving late in a
/// batching window, ~1.96× more invertible overall.
///
/// **The defect is live, and it sits on the worst boundary for it.** This delay
/// governs the tor→clearnet bridge — the one moment an anonymity-arrived
/// transaction becomes clearnet-visible, and therefore the moment
/// arrival-time inference is worth most to an observer.
///
/// # What this does and does not change
///
/// It is F-4's move, one call site later: **fix the family at the current
/// mean.** The mean is Q-12's (`ADOPTED_FORWARD_DELAY_MEAN_SECS`); the family
/// was settled by F-2/F-4 and does not depend on Q-12's open fork at all.
/// Value-neutral, family-correct, provenance stated — the same shape as
/// Q-11 Unit 0's decoupling, and it leaves Q-12 free to move the mean later.
///
/// **Retiring `crypto::random_poisson_duration` is certain in every branch.**
/// If Q-12 deletes `relay_method::forward`, the call site goes with it and the
/// retirement stands; if `forward` survives, the draw is memoryless either way.
#[derive(Debug, Clone)]
pub struct ForwardDelay {
    table: GeometricTable,
}

impl ForwardDelay {
    /// The shipped forward delay: memoryless at
    /// [`ADOPTED_FORWARD_DELAY_MEAN_SECS`], one-second granularity.
    ///
    /// Seconds rather than the embargo's 250 ms ticks because the consumer
    /// stores a whole-second `time_t` (`tx_pool.cpp`'s `last_relayed_time`);
    /// a finer tick would be discarded at the boundary and would only make the
    /// table's granularity disagree with the deadline's.
    #[must_use]
    pub fn adopted() -> Self {
        Self {
            table: GeometricTable::new(ADOPTED_FORWARD_DELAY_MEAN_SECS),
        }
    }

    /// Draw one forward delay, in **seconds**.
    ///
    /// A 0 s draw is legitimate: a memoryless family has support
    /// `{0, 1, 2, …}`, and clamping it would ship something other than the
    /// distribution this type claims to be — the same reasoning the embargo
    /// draw records for its own zero.
    pub fn draw<R: RelayRng + ?Sized>(&self, rng: &mut R) -> u64 {
        self.table.draw(rng)
    }

    /// The mean this was built at, in seconds.
    #[must_use]
    pub const fn mean_secs(&self) -> u32 {
        ADOPTED_FORWARD_DELAY_MEAN_SECS
    }
}

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

    /// How long a sender must wait before a transaction it has still not seen
    /// may be judged to have failed, at a stated false-fail rate of `1 / one_in`.
    ///
    /// A transaction under embargo is invisible to its sender until the backstop
    /// fires (it is not yet in the broadcast category), so any "did it fail?"
    /// deadline is a quantile of *this* distribution. Set it too low and a
    /// perfectly healthy transaction is declared failed while its backstop is
    /// still running — which is worse than it sounds, because the sender then
    /// releases the inputs it had reserved and may re-spend them.
    ///
    /// Provisioned from the shipped table (see
    /// [`DelayTable::survival_quantile_ticks`]) and rounded **up** to whole
    /// seconds, so the wait never comes in under the stated rate. On the adopted
    /// timer at [`PROPAGATION_FALSE_FAIL_ONE_IN`] the result is pinned as
    /// [`ADOPTED_PROPAGATION_TIMEOUT_SECS`].
    ///
    /// # Panics
    ///
    /// Panics if `one_in` is zero.
    #[must_use]
    pub fn judge_failed_after_secs(&self, one_in: u64) -> u32 {
        let ticks = self.table.survival_quantile_ticks(one_in);
        u32::try_from(ticks.saturating_mul(self.tick_millis).div_ceil(1_000)).unwrap_or(u32::MAX)
    }

    /// Draw an embargo deadline relative to `now`, in monotonic milliseconds.
    ///
    /// The draw is the table's tick count times this timer's tick; callers that
    /// store a whole-second `time_t` should round **up** when converting
    /// (under-provisioning fluffs early — the privacy-losing direction).
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

    #[test]
    fn propagation_timeout_follows_from_the_shipped_table() {
        let t = EmbargoTimer::adopted(&DandelionParams::adopted_for(crate::zone::RelayZone::Tor));
        let secs = t.judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN);

        // Exact pin: the number and the table must not drift apart. A loose
        // bound would re-admit F-1 (a timing figure that does not follow from
        // the distribution actually shipped).
        assert_eq!(
            secs, ADOPTED_PROPAGATION_TIMEOUT_SECS,
            "adopted 1-in-{PROPAGATION_FALSE_FAIL_ONE_IN} wait moved: got {secs}s, pin is {ADOPTED_PROPAGATION_TIMEOUT_SECS}s — update the pin only with the derivation"
        );
        // Sanity relative to the backstop the deadline is waiting on.
        assert!(
            secs > t.mean_secs(),
            "a 1-in-100 wait must exceed the mean ({secs}s vs {}s)",
            t.mean_secs()
        );
        // Must clear the origin-alone black-hole recovery p90 (~331 s, §10),
        // which is exactly the case a sender would otherwise mislabel.
        assert!(
            secs >= 331,
            "must outlast the origin-alone recovery p90, got {secs}s"
        );
        // Tightening the stated rate must lengthen the wait, monotonically.
        assert!(
            t.judge_failed_after_secs(1_000) > secs,
            "a 1-in-1000 deadline must wait longer than 1-in-100"
        );
    }

    #[test]
    fn the_shipped_wait_clears_every_zones_embargo() {
        // The one property the worst-zone interim must have: no zone's embargo
        // outlasts it. A wait that clears only the zone it was derived from is
        // how 874 s came to be wrong for the anonymity path.
        for zone in [
            crate::zone::RelayZone::Public,
            crate::zone::RelayZone::I2p,
            crate::zone::RelayZone::Tor,
            crate::zone::RelayZone::Invalid,
        ] {
            let t = EmbargoTimer::adopted(&DandelionParams::adopted_for(zone));
            assert!(
                ADOPTED_PROPAGATION_TIMEOUT_SECS
                    >= t.judge_failed_after_secs(PROPAGATION_FALSE_FAIL_ONE_IN),
                "{zone:?} needs a longer wait than the shipped {ADOPTED_PROPAGATION_TIMEOUT_SECS}s"
            );
        }
    }

    #[test]
    fn survival_quantile_handles_both_rate_extremes() {
        // A geometric with mean 1 tick, so `p = 1/2` and the mass decays fast
        // enough that both ends of the `one_in` range are reachable in a short
        // table. (Not a degenerate one-outcome table — the support is still
        // {0, 1, 2, ...}; what is being pinned here is the walk's behaviour at
        // the extremes of the *rate*, not of the distribution.)
        let t = EmbargoTimer::geometric_from_ticks(1, 1_000);

        // Loosest possible budget: `one_in = 1` permits the whole domain as
        // tail, so the first outcome satisfies it and the walk exits on its
        // first iteration.
        assert_eq!(
            t.judge_failed_after_secs(1),
            0,
            "a 1-in-1 budget is already met at k = 0"
        );

        // Tightest: `2^64 / u64::MAX` truncates to a single quantum, a budget no
        // outcome clears until the tail is all but exhausted. The walk must
        // still terminate *inside* the table — its top outcome is the fallback —
        // rather than run past the support. This is the case the u128
        // accumulation keeps exact, since the masses partition 2^64 rather than
        // 2^64 - 1 and a u64 subtraction would wrap at the last bin.
        let fine = t.judge_failed_after_secs(u64::MAX);
        assert!(
            fine > 0,
            "a vanishing tail budget must land deep in the table"
        );
    }
}
