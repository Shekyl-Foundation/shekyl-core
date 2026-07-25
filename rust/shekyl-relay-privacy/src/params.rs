// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dandelion++ parameters — **derived from the paper, not inherited as
//! constants**.
//!
//! This is the module PR-1 exists for. The inherited daemon hard-codes six
//! `#define`s in `src/cryptonote_config.h` and explains one of them in a
//! comment in `src/cryptonote_core/tx_pool.cpp`. That comment states the
//! derivation inputs — `k = 5`, `ep = 0.10`, `hop = 175 ms` — and then states
//! the answer: 39 seconds. **The stated inputs do not produce the stated
//! answer.** Under the Dandelion++ paper's formula they produce 16.61 s; the
//! 39 s figure is reproduced only by substituting a base-10 logarithm for the
//! natural logarithm the formula calls for.
//!
//! That is not a rounding quibble — it is a factor of 2.3 on the black-hole
//! recovery timer of the whole relay layer, carried into Shekyl unexamined
//! because it arrived as a `#define`. The counter-check is
//! [`reconciles_under_log10`]: the discrepancy is asserted here, in code, so
//! nobody has to take this doc comment's word for it.
//!
//! The fix is structural rather than a new magic number. [`DandelionParams`]
//! takes the *design inputs* (hop latency, fluff probability, target travel
//! probability) and **computes** the embargo timeout, so the parameter can no
//! longer drift from its own justification. `Cuprate`'s
//! `p2p/dandelion-tower/src/config.rs` reaches the same conclusion
//! independently and is the prior art for this shape; the derivation below is
//! written from the paper rather than adapted from that crate (see the crate
//! docs on why the crate itself is not a dependency).
//!
//! # Which direction is the inherited value wrong in
//!
//! The embargo is a liveness backstop: if a stem stalls (a black hole, or just
//! a peer that went away), the embargo fires and the node fluffs anyway. A
//! *longer* embargo raises the probability that a transaction completes its
//! full stem before any node's timer fires — better for the privacy property
//! the parameter is nominally tuned for — at the cost of a transaction sitting
//! undiffused for longer when something genuinely goes wrong. So the inherited
//! 39 s is conservative-for-privacy and worse-for-liveness. It is not a
//! vulnerability. It is an unexamined trade the design round should make
//! deliberately rather than inherit.
#![allow(clippy::cast_precision_loss)]
// ^ Small integer parameters (`k`, hop milliseconds) widen to `f64` for the
//   closed-form derivation below. Every value involved is far below 2^53.

/// Probability that a stem transaction travels its full expected length before
/// *any* node on the path fires its embargo timer.
///
/// This is `1 - ep` in the Dandelion++ paper's appendix B.5 formula. The
/// inherited C++ comment names `ep = 0.10`, so `0.90` reproduces its stated
/// intent; it is a design input here rather than a buried literal precisely so
/// the design round can move it and watch the embargo follow.
pub const EMBARGO_FULL_TRAVEL_PROBABILITY: f64 = 0.90;

/// The stem-graph shape, which fixes how many outbound peers carry stem
/// traffic in an epoch — i.e. the stem graph's out-degree.
///
/// The count is a topological corner, not a tuning knob (derivation:
/// `DAEMON_RELAY_PRIVACY.md` §12.7). Privacy alone wants out-degree 1 (a pure
/// line, maximal anonymity-set per hop), but 1 makes every stem a single-node
/// black-hole point-of-failure; out-degree ≥ 3 fans the stem toward a tree and
/// leaks more to the first-spy estimator. 2 is the *minimum* out-degree at which
/// the stem graph becomes a low-degree expander (the paper's ~4-regular
/// construction: no small cuts, short paths) rather than a set of severable lines
/// — the least robustness privacy can afford. So the slot-occupancy attack
/// (W3/ProxyMark) is *not* fixed by raising the count (that is a privacy
/// regression); it is defended at the selection layer (`g_max`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StemGraph {
    /// One stem peer per epoch (out-degree 1). Most private in the honest case,
    /// but a single black-holing successor severs the whole stem — the
    /// point-of-failure `QuasiFourRegular` exists to remove. Not the shipped
    /// value.
    Line,
    /// Two stem peers per epoch, each source pinned to one of them (out-degree 2).
    /// The paper's recommendation and what the inherited
    /// `CRYPTONOTE_DANDELIONPP_STEMS = 2` implements: the expander-minimum that is
    /// robust to a single dropper while staying as near a line as a robust graph
    /// can be. Do not raise to harden occupancy — see the type-level note above.
    #[default]
    QuasiFourRegular,
}

impl StemGraph {
    /// Number of outbound peers used to stem transactions in an epoch.
    #[must_use]
    pub const fn stem_count(self) -> usize {
        match self {
            Self::Line => 1,
            Self::QuasiFourRegular => 2,
        }
    }
}

/// The complete Dandelion++ parameter set, expressed as design inputs.
///
/// Every derived quantity is a method, never a stored field: a caller cannot
/// construct a parameter set whose embargo disagrees with its fluff
/// probability, which is exactly the failure the inherited `#define` layout
/// permitted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DandelionParams {
    /// Time for a stem transaction to traverse one node, including network
    /// latency. Better to overestimate: it scales the embargo directly.
    pub time_between_hop_ms: u32,
    /// Minimum epoch duration in seconds, before jitter.
    pub min_epoch_secs: u32,
    /// Width of the uniform jitter added to each epoch, in seconds.
    pub epoch_jitter_secs: u32,
    /// `q` in the paper: probability that a node spends an epoch in the fluff
    /// state, as a percentage. The paper recommends a small value; smaller
    /// means longer stems (better anonymity) and higher broadcast latency.
    pub fluff_probability_pct: u32,
    /// Time for the fluff flood to travel *back* from the terminal stem node
    /// to an arbitrary stem node, in milliseconds.
    ///
    /// **RD-1.** A stem node's embargo is not disarmed when the terminal node
    /// emits the fluff — it is disarmed when that fluff *reaches it* and
    /// `upgrade_relay_method` transitions the transaction out of stem state
    /// (`tx_pool.cpp` `add_tx` / `set_relayed`). Every stem node's exposure
    /// window therefore carries a diffusion-return term on top of its stem
    /// slack, and the closed form has no place to put it.
    ///
    /// Measured by [`crate::conformance::simulate_fluff_return`], not assumed.
    /// Like [`Self::time_between_hop_ms`] this is a topology input with a
    /// testnet reopening trigger, and it is set from a high quantile rather
    /// than a mean because over-estimating lengthens the embargo (safe) while
    /// under-estimating shortens it (a privacy loss).
    pub fluff_return_ms: u32,
    /// Stem-graph shape.
    pub graph: StemGraph,
}

impl DandelionParams {
    /// The parameter set Shekyl currently inherits, transcribed from
    /// `src/cryptonote_config.h` lines 101-106.
    ///
    /// This constructor exists to be *measured against*, not to be shipped.
    /// It is the baseline the design round compares its own derivation to.
    #[must_use]
    pub const fn inherited() -> Self {
        Self {
            // The `hop = 175 ms` fudge factor named in the `tx_pool.cpp`
            // comment. Not a config constant in C++ — it exists only inside
            // that comment's arithmetic, which is part of the problem.
            time_between_hop_ms: 175,
            // CRYPTONOTE_DANDELIONPP_MIN_EPOCH = 10 minutes.
            min_epoch_secs: 600,
            // CRYPTONOTE_DANDELIONPP_EPOCH_RANGE = 30 seconds.
            epoch_jitter_secs: 30,
            // CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY = 20, out of 100.
            fluff_probability_pct: 20,
            // Measured p90 first-passage for a memoryless fluff flood at 8
            // peers (`simulate_fluff_return`). Under the *inherited* Poisson
            // delay the same measurement gives ~13.75 s — see F-5.
            fluff_return_ms: 2_250,
            // CRYPTONOTE_DANDELIONPP_STEMS = 2.
            graph: StemGraph::QuasiFourRegular,
        }
    }

    /// The embargo timeout the inherited daemon actually uses:
    /// `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE` = 39 seconds.
    ///
    /// Deliberately *not* a field of [`DandelionParams`] — it is not an input,
    /// it is an output that the inherited code froze by hand. Compare it with
    /// [`Self::average_embargo_secs`].
    pub const INHERITED_EMBARGO_SECS: u32 = 39;

    /// Expected stem length `k`, the reciprocal of the fluff probability.
    ///
    /// # Panics
    ///
    /// Panics if the fluff probability is zero: a node that never fluffs gives
    /// an infinite expected stem, and the embargo derivation below has no
    /// finite answer.
    #[must_use]
    pub fn expected_stem_length(&self) -> f64 {
        assert!(
            self.fluff_probability_pct > 0,
            "fluff probability must be non-zero — k = 1/q is otherwise unbounded"
        );
        100.0 / f64::from(self.fluff_probability_pct)
    }

    /// Average embargo timeout `Tbase`, derived from the paper's appendix B.5
    /// formula:
    ///
    /// ```text
    /// Tbase = (-k * (k - 1) * hop) / (2 * ln(1 - ep))
    /// ```
    ///
    /// with `k` the expected stem length, `hop` the per-node traversal time,
    /// and `1 - ep` = [`EMBARGO_FULL_TRAVEL_PROBABILITY`]. Rounded up to whole
    /// seconds, matching the granularity the timer actually has.
    ///
    /// Note the logarithm is **natural**. Substituting `log10` here is what
    /// reproduces the inherited 39 s — see [`reconciles_under_log10`].
    #[must_use]
    pub fn average_embargo_secs(&self) -> u32 {
        let k = self.expected_stem_length();
        let hop = f64::from(self.time_between_hop_ms) / 1000.0;
        let secs = (-k * (k - 1.0) * hop) / (2.0 * EMBARGO_FULL_TRAVEL_PROBABILITY.ln());
        // `ceil` before narrowing; the value is a few tens of seconds for any
        // sane input, so the cast cannot truncate meaningfully. Clamp anyway
        // rather than let a pathological input wrap.
        let ceiled = secs.ceil();
        if ceiled.is_finite() && ceiled > 0.0 && ceiled < f64::from(u32::MAX) {
            // Exact: `ceiled` is integral and within u32.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ceiled as u32
            }
        } else {
            0
        }
    }

    /// Number of outbound peers carrying stem traffic this epoch.
    #[must_use]
    pub const fn stem_count(&self) -> usize {
        self.graph.stem_count()
    }

    /// How far the inherited hard-coded embargo departs from this parameter
    /// set's own derivation, as a ratio. `1.0` means they agree.
    #[must_use]
    pub fn inherited_embargo_ratio(&self) -> f64 {
        let derived = self.average_embargo_secs();
        if derived == 0 {
            return f64::INFINITY;
        }
        f64::from(Self::INHERITED_EMBARGO_SECS) / f64::from(derived)
    }
}

/// Reproduce the inherited 39 s constant by substituting a base-10 logarithm
/// for the natural logarithm the Dandelion++ formula specifies.
///
/// This exists as a *diagnosis*, not as an API anyone should call in anger. It
/// is the evidence for the claim in the module docs: the inherited constant is
/// not an independent design choice that happens to differ from the formula,
/// it is the formula evaluated with the wrong logarithm base. Under `log10`
/// the same stated inputs (`k = 5`, `ep = 0.10`, `hop = 175 ms`) give 38.2 s,
/// which rounds to the shipped 39 at `hop = 178 ms`.
#[must_use]
pub fn reconciles_under_log10(params: &DandelionParams) -> f64 {
    let k = params.expected_stem_length();
    let hop = f64::from(params.time_between_hop_ms) / 1000.0;
    (-k * (k - 1.0) * hop) / (2.0 * EMBARGO_FULL_TRAVEL_PROBABILITY.log10())
}

/// Constants transcribed from the inherited `src/cryptonote_config.h` relay
/// block, so this crate is the single Rust mirror of that surface.
///
/// These are *not* re-derived — they are the current values, present so a
/// measurement run and a design round can reference them without re-reading
/// the C++ header, and so a future FFI cut has one place to reconcile.
pub mod inherited {
    /// `CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE` — mean fluff-flush delay for
    /// *inbound* peers, in seconds. Drawn as a Poisson over quarter-seconds
    /// (λ = 20) so the variance is usable; see `levin_notify.cpp:75-90`.
    pub const FLUFF_AVERAGE_IN_SECS: u32 = 5;
    /// Mean fluff-flush delay for *outbound* peers. Half the inbound average,
    /// on the reasoning that the node controls its own outbound connections.
    /// λ = 10 quarter-seconds.
    pub const FLUFF_AVERAGE_OUT_QUARTER_SECS: u32 = 10;
    /// λ for the inbound fluff draw, in quarter-seconds.
    pub const FLUFF_AVERAGE_IN_QUARTER_SECS: u32 = 20;

    /// `CRYPTONOTE_NOISE_MIN_EPOCH` — 5 minutes, in seconds.
    pub const NOISE_MIN_EPOCH_SECS: u32 = 300;
    /// `CRYPTONOTE_NOISE_EPOCH_RANGE`, in seconds.
    pub const NOISE_EPOCH_JITTER_SECS: u32 = 30;
    /// `CRYPTONOTE_NOISE_MIN_DELAY`, in seconds.
    pub const NOISE_MIN_DELAY_SECS: u32 = 10;
    /// `CRYPTONOTE_NOISE_DELAY_RANGE`, in seconds.
    pub const NOISE_DELAY_JITTER_SECS: u32 = 5;
    /// `CRYPTONOTE_NOISE_CHANNELS` — max outbound connections per zone used
    /// for covert sending.
    pub const NOISE_CHANNELS: usize = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The finding, as an executable assertion.
    ///
    /// If someone later "fixes" the inherited constant or the derivation, this
    /// test tells them which of the two moved.
    #[test]
    fn inherited_embargo_disagrees_with_its_own_stated_derivation() {
        let p = DandelionParams::inherited();

        // The stated inputs: k = 1/0.20 = 5, hop = 175 ms, ep = 0.10.
        assert!((p.expected_stem_length() - 5.0).abs() < 1e-12);

        // What the paper's formula actually yields.
        let derived = p.average_embargo_secs();
        assert_eq!(
            derived, 17,
            "paper formula (natural log) over the inherited inputs"
        );

        // What the daemon ships.
        assert_eq!(DandelionParams::INHERITED_EMBARGO_SECS, 39);

        // The gap, stated as a ratio so a reader sees the magnitude.
        let ratio = p.inherited_embargo_ratio();
        assert!(
            (2.2..2.4).contains(&ratio),
            "inherited/derived embargo ratio = {ratio}"
        );
    }

    #[test]
    fn log10_substitution_reproduces_the_inherited_constant() {
        let p = DandelionParams::inherited();
        let under_log10 = reconciles_under_log10(&p);
        // 38.245 s — the shipped 39 with the comment's own rounding slack
        // (39 exactly at hop = 178 ms).
        assert!(
            (38.0..38.5).contains(&under_log10),
            "log10 substitution gives {under_log10}"
        );
    }

    #[test]
    fn embargo_scales_with_stem_length() {
        // Halving the fluff probability doubles k, which more than triples the
        // embargo (the k(k-1) term). This is the coupling the inherited
        // `#define` layout hid: the two constants cannot be tuned separately.
        let mut p = DandelionParams::inherited();
        let base = p.average_embargo_secs();
        p.fluff_probability_pct = 10;
        let doubled_k = p.average_embargo_secs();
        assert!(
            doubled_k > base * 3,
            "k doubled: embargo went {base} -> {doubled_k}, expected >3x"
        );
    }

    #[test]
    fn full_travel_probability_property_holds() {
        // The derived timeout must be long enough that the probability of a
        // transaction travelling its full expected stem is at least the target
        // — the appendix B.5 property the formula is solving for. Swept across
        // the parameter space rather than checked at one point.
        for pct in 1..=100_u32 {
            for hop_ms in [1_u32, 25, 175, 1_000, 10_000] {
                let p = DandelionParams {
                    time_between_hop_ms: hop_ms,
                    fluff_probability_pct: pct,
                    ..DandelionParams::inherited()
                };
                let k = p.expected_stem_length();
                if k <= 1.0 {
                    // q = 100%: the node always fluffs, there is no stem to
                    // protect and the formula degenerates to zero.
                    continue;
                }
                let hop = f64::from(hop_ms) / 1000.0;
                let t = f64::from(p.average_embargo_secs());
                let probability = ((-k * (k - 1.0) * hop) / (2.0 * t)).exp();
                assert!(
                    probability >= EMBARGO_FULL_TRAVEL_PROBABILITY,
                    "q={pct}% hop={hop_ms}ms: travel probability {probability} < target"
                );
            }
        }
    }

    #[test]
    fn stem_counts_match_the_graph() {
        assert_eq!(StemGraph::Line.stem_count(), 1);
        assert_eq!(StemGraph::QuasiFourRegular.stem_count(), 2);
        // The inherited CRYPTONOTE_DANDELIONPP_STEMS = 2.
        assert_eq!(DandelionParams::inherited().stem_count(), 2);
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_fluff_probability_is_rejected() {
        let p = DandelionParams {
            fluff_probability_pct: 0,
            ..DandelionParams::inherited()
        };
        let k = p.expected_stem_length();
        assert!(k.is_finite(), "unreachable: the call panics above");
    }
}
