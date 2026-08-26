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

/// The false-retry rate for an **origin's** re-broadcast, as `1 / one_in` —
/// derived from [`EMBARGO_FULL_TRAVEL_PROBABILITY`], not chosen beside it.
///
/// # Why the origin's retry is the network's question asked by a different actor
///
/// `EMBARGO_FULL_TRAVEL_PROBABILITY` pins the confidence at which a *relaying*
/// node decides a stem has probably completed: at `alpha = 0.90`, a node's
/// embargo is solved so that 9 stems in 10 finish before any node on the path
/// fires. An origin re-broadcasting its own transaction is asking the same
/// question — *has this stem probably completed?* — so it should ask it at the
/// same confidence. The residual `1 - alpha` IS the rate at which retrying is
/// premature, so `one_in = 1 / (1 - alpha)`.
///
/// Deriving rather than choosing is the point (§94.8's argument, one layer
/// down): if `alpha` moves, this follows automatically instead of decoupling
/// silently, and there is no self-invented bar to defend. The alternative on
/// offer was a point inside a bracket, which is a bar of exactly that kind.
///
/// # What it replaces, and why the shipped value was a defect rather than a
/// tuning question
///
/// The inherited `MIN_RELAY_TIME` (300 s) governs the pool's re-broadcast loop
/// for `local`, `fluff` and `block`. §15.4 cleared it from the embargo's
/// neighbourhood on the ground that it *"governs an already-fluffed
/// transaction, a different state from the embargo"* — true when written, and
/// **vacated** by `originated_stays_in_zone`, which pins an anonymity-zone
/// origin at `Local` permanently and so created a class that is never fluffed
/// and lives on that branch for its whole life.
///
/// At 300 s that origin re-emits **below the anonymity embargo's median**
/// (346 s): more than half the embargoes along its own stem are still running,
/// so the retry fires while the transaction is propagating normally. That is
/// the under-provisioning direction, on the origination path, where the thing
/// being protected is the fact of origination.
#[must_use]
pub fn origin_retry_one_in() -> u64 {
    // Rounded, then checked in `origin_retry_rate_is_the_reciprocal_of_alpha`:
    // an `alpha` that is not of the form `1 - 1/N` cannot be expressed as an
    // integer rate, and the test reds rather than this silently asking a
    // different question than the network does.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let one_in = (1.0 / (1.0 - EMBARGO_FULL_TRAVEL_PROBABILITY)).round() as u64;
    one_in
}

/// R-1 mixed eligibility: the chance an *originated* transaction takes the
/// anonymity zone instead of the public one, in hundredths of a percent
/// (so `100` = 1.00 %, `5000` = 50 %). One roll, at origination (Q12-D5a).
/// Relayed traffic does not consult this; it inherits its arrival zone.
///
/// **This is an indifference point on a linear trade, not a measured
/// optimum.** Transport privacy gained and propagation latency paid are
/// both linear in `p` with no threshold on either side, so the midpoint
/// is the point of indifference. Precision is `q/(1+q)` at every value
/// (Q12-D4's cancellation, which holds under once-at-origin and only
/// there), so nothing about privacy varies with `p`.
///
/// **What would replace it:** a measured asymmetry in either term —
/// latency that is not linear in `p`, or a privacy cost that appears on
/// one side of some threshold. Until that measurement exists, do not
/// re-derive this number from prose. Four prior derivations in this arc
/// reasoned about a code path that was dormant.
///
/// **Fixed, not operator-configurable.** A per-operator `p` is weakly
/// observable to peers (the fraction of that node's originations that
/// arrive on each zone) and would partition the node population into
/// distinguishable classes. That is *privacy is never a setting* in a
/// new place.
///
/// Formerly `MIXED_ELIGIBILITY_PER_HOP_PCT_HUNDREDTHS = 200`. The name
/// described the deleted per-arrival divert; the 2 % was conservative
/// under a stem-shortening cost that no longer applies. History:
/// `DAEMON_RELAY_PRIVACY.md` §59–§64 / §89,
/// `Q12_FORWARD_DELAY_AND_ZONE_FIELD.md`.
pub const MIXED_ELIGIBILITY_PCT_HUNDREDTHS: u32 = 5000;

/// Should this *originated* transaction take the anonymity zone?
///
/// **Once-at-origin (Q12-D5a).** The origin rolls; no node re-rolls.
/// Relayed traffic inherits its arrival zone and coherence holds it.
/// Re-rolling per arrival plus coherence was the one-way absorbing
/// process that destroyed Q12-D4's cancellation.
///
/// Callers own the pre-fluff test: this answers *whether to take
/// anonymity*, not *whether the transaction is still stemming*. Once it
/// fluffs it leaves the zone, which is what keeps a transaction that
/// entered over Tor reaching the public network at all.
#[must_use]
pub fn divert_to_anonymity_zone<R: crate::rng::RelayRng + ?Sized>(rng: &mut R) -> bool {
    // `bounded_uniform` rather than `% 10_000` for consistency with every
    // other draw in this crate, not because the bias matters here: at this
    // range it is `2^64 mod 10_000 / 2^64` ≈ 8.8e-17, which needs ~1e32
    // samples to observe. Stated rather than implied, because a comment
    // claiming a bias defence invites a test that cannot fail — one was
    // written here and deleted for exactly that reason.
    crate::rng::bounded_uniform(rng, 9_999) < u64::from(MIXED_ELIGIBILITY_PCT_HUNDREDTHS)
}

/// Outbound connections a node opens per zone by default — the deployed
/// network's out-degree.
///
/// **Rust owns this value; C++ consumes it** through
/// `shekyl_p2p_default_out_peers` (rule 20). It was `#define
/// P2P_DEFAULT_CONNECTIONS_COUNT 12` in `cryptonote_config.h`, mirrored by
/// hand into every Rust instrument that simulates the deployed topology —
/// five copies, no owner, and nothing that fails when the daemon's value
/// moves. That is F-7's failure mode one layer down: an instrument measuring
/// a degree the deployment does not run, feeding derivations that then report
/// numbers for a network that does not exist.
///
/// **Distinct from [`MIN_PROVISIONED_OUT_PEERS`], which is not an alias for
/// it.** They hold the same number today and are derived in opposite
/// directions: this one is the *configuration* the privacy quantities are
/// measured **at**, while the floor below is derived **from** a measurement
/// (`fluff_return_ms`) taken at this degree. Consuming either in place of the
/// other inverts a derivation — if a future re-measure moves the floor, this
/// default does not follow, and if the network default moves, the
/// measurements are re-run rather than the floor being edited.
///
/// It lives in this crate because this crate owns the *relationship* between
/// outbound degree and relay privacy: every consumer is an instrument here,
/// and the one C++ needs is already exported from here.
pub const P2P_DEFAULT_OUT_PEERS: u32 = 12;

/// The per-zone outbound-connection floor the F-7 embargo provisioning
/// assumes (F-8b, §45).
///
/// `fluff_return_ms = 3250` is the measured p90 first passage at usable
/// degree **12** (§44). The worst-zone argument is bounded by that measured
/// range: below degree 12 the real first passage *exceeds* the provisioned
/// value and the embargo is under-provisioned in the direction the
/// `fluff_return_ms` note names as a privacy loss. An operator can reach that
/// region with `--tx-proxy <zone>,<addr>,N` for `N < 12`, so the C++ argument
/// parser refuses such counts, consuming this constant through
/// `shekyl_relay_zone_min_provisioned_out_peers` — one owner, no C++ mirror.
/// If a future re-measure extends the instrument below degree 12, this floor
/// moves with `fluff_return_ms`, not independently of it — which is why it is
/// its own constant and not an alias of [`P2P_DEFAULT_OUT_PEERS`].
pub const MIN_PROVISIONED_OUT_PEERS: u32 = 12;

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

pub use crate::zone::RelayZone;

/// The complete Dandelion++ parameter set, expressed as design inputs.
///
/// Every derived quantity is a method, never a stored field: a caller cannot
/// construct a parameter set whose embargo disagrees with its fluff
/// probability, which is exactly the failure the inherited `#define` layout
/// permitted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DandelionParams {
    /// Elapsed time from a relay **receiving** a stem transaction to that
    /// relay having **forwarded** it. Better to overestimate: it scales the
    /// embargo directly.
    ///
    /// # What it includes (§71) — three terms, not one
    ///
    /// ```text
    /// hop  =  A→B transit  +  B's verification  +  B's scheduling
    /// ```
    ///
    /// **Verification is inside the critical path**, not beside it:
    /// `cryptonote_protocol_handler.inl` calls `handle_incoming_tx` in the
    /// per-transaction loop and reaches `relay_transactions` only after that
    /// loop closes. The term is **FCMP++ membership-proof verification**
    /// (`shekyl_fcmp_verify`, scaling with input count) plus a per-output
    /// prime-order check (`shekyl_check_commitment_masks`) — **not** ML-DSA-65,
    /// whose public-key hashes are bound into the proof as scalars rather than
    /// verified as signatures (§72.2). It is not a rounding error, and **it
    /// moves when the proof system moves** — this is not a network constant
    /// that can be measured once, which is why an instruction-count gate on the
    /// admission path belongs beside it rather than a comment.
    ///
    /// The inherited `175` already carried a processing term: §21 records its
    /// whole justification as *"a testrun from a recent Intel laptop took
    /// ~80 ms […] At least 50 ms will be added to the latency if crossing an
    /// ocean."* The shape was right; the ~80 ms is Monero-era verification.
    ///
    /// **Measure forward-to-forward at the relay layer, never round-trip at
    /// the transport.** An RTT rig omits verification and scheduling, so it
    /// under-estimates — transactions cut short of their stem, which is the
    /// privacy-losing direction (§21's asymmetry). The definition is identical
    /// on clearnet and on the anonymity zone; only the transit term differs,
    /// which is what makes the two arms comparable.
    ///
    /// # Quantile policy (§66) — an *effective* scalar, not a per-hop quantile
    ///
    /// Set so that the hop contribution to `S(h)` — `Σ_{k=1..h} k·hop_k` under
    /// the shipped stem-length distribution — reaches its **p90**. It is the
    /// scalar that reproduces a quantile *of the sum*, **not** the p90 of the
    /// per-hop marginal.
    ///
    /// **Do not set this by parity with [`Self::fluff_return_ms`], which is a
    /// p90 of its own marginal.** The two differ in draw structure, and the
    /// difference is the whole policy: `F` is **one** realisation per
    /// transaction entering every term (the flood returns once), so its
    /// marginal quantile *is* its contribution's quantile. `hop` is **`h`
    /// independent** draws entering with weight `k`, and independent draws
    /// average — the weighted sum concentrates relative to its own marginal.
    /// Substituting a measured per-hop p90 here over-provisions by **1.35×**
    /// at clearnet-plausible dispersion and **1.97×** at SPIKE-F-16's 30×
    /// spread. Safe in direction, unbounded in cost, and §6.7 prices embargo
    /// lengthening as real.
    ///
    /// Consequence for anyone measuring this: the field work must yield a
    /// **distribution**, not a number. A point estimate cannot be converted
    /// into this scalar without the spread, and the spread is the dominant
    /// term. **`175` is not yet such a value** — it is a provenance (§21), and
    /// the clearnet measurement is owed first (§65.3).
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
    /// Production constructs [`Self::adopted`], which re-anchors the `hop`
    /// input to measured provenance and inherits the rest of this set with
    /// its documented dispositions.
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
            // **Provisioned at the worst zone, not at one measurement —
            // F-7 (§26, §40, §44).** Measured p90 first-passage, memoryless
            // fluff flood (`simulate_fluff_return`), by deployed fluff rule at
            // Shekyl's `P2P_DEFAULT_OUT_PEERS = 12`:
            //
            //   clearnet (EveryPeer, usable degree ~24)      ~1250 ms
            //   Tor-C  (OutboundOnly, usable degree 12 exact) ~3250 ms  <- binding
            //
            // The old 2250 was an `EveryPeer` measurement at `peers = 8` fed
            // to the derivation for EVERY transport, so the anonymity zone was
            // provisioned from a fluff rule it does not use (~44 % low). The
            // gap is a DEGREE effect, not a direction effect: at matched
            // usable degree (EveryPeer@8 vs OutboundOnly@16) the two rules
            // measure 2500 vs 2250 ms — the direction constraint costs
            // nothing; halving the usable degree is what costs (§40.1).
            //
            // One process-wide F for every zone: a fluff wave returns over
            // whatever network the *node* is on, so there is no per-zone F to
            // pick (§63.2's keeper; restated at §89.2). Set to the WORST zone's
            // p90. §44.3 prices the over-provisioned zone: this constant's only
            // production consumer is the embargo derivation, so over-estimating
            // F *lengthens* the embargo — which *reduces* the §6.7 prefix-fire
            // leak and pays only in black-hole recovery latency. Privacy-safe
            // on both axes. Under the *inherited* Poisson delay the same
            // instrument gives ~13.75 s — see F-5.
            fluff_return_ms: 3_250,
            // CRYPTONOTE_DANDELIONPP_STEMS = 2.
            graph: StemGraph::QuasiFourRegular,
        }
    }

    /// The parameter set production ships — [`Self::inherited`] with the
    /// `hop` input re-anchored to measured provenance (§80, §85.3).
    ///
    /// # What moved, and what deliberately did not
    ///
    /// **`time_between_hop_ms` is now derived through
    /// [`crate::verify_cost::adopted_hop_ms`]** — the spec machine's modal
    /// verification cell (124.5 ms, Pi 4, genesis tree) plus the labelled
    /// 50 ms transit assumption — instead of restating the inherited `175`.
    /// The two are numerically equal, and that is arithmetic rather than
    /// coincidence: the inherited number was never pure transit (§71.3 — a
    /// ~80 ms Monero-era verification figure plus one ocean crossing), and
    /// re-deriving its shape with our verification cost lands on the same
    /// milliseconds. So the cutover from `inherited()` moved **provenance,
    /// not behaviour on clearnet**: the clearnet embargo stays 190 s.
    /// (Anonymity zones take a longer hop — see [`Self::adopted_for`]. The
    /// wallet failed-send wait is a separate interim at the *worst* zone's
    /// quantile, currently 2297 s — `ADOPTED_PROPAGATION_TIMEOUT_SECS` —
    /// and is a deletion target per §89.6.)
    ///
    /// Every other field carries its own already-recorded disposition:
    /// `fluff_return_ms` is F-7's measurement (worst-zone p90 at degree 12),
    /// `fluff_probability_pct` is D-6's retained `q = 20 %`, the epoch pair
    /// and graph are the inherited values with their §21 ledger entries.
    ///
    /// # What this does NOT close (§65.3, §66.3)
    ///
    /// The hop value here is the **measured floor** of §66.3's effective
    /// scalar, not that scalar: verification is inside every hop's critical
    /// path, so no field measurement can come back below it — but the
    /// clearnet forward-to-forward *distribution* is still owed, and only it
    /// can produce the p90-of-the-sum value the policy defines. When that
    /// measurement lands it replaces this floor; until then the floor with
    /// stated provenance supersedes a comment about a 2019 laptop.
    ///
    /// # Modal shape — an interim the doc prices
    ///
    /// Per-zone embargo timers still use the **modal shape** (1 input, genesis
    /// tree) for each zone's hop. §83.1 prices the choice: the modal embargo
    /// is effectively constant across the whole depth range (~3 s of drift),
    /// while the tail rows are where per-shape derivation pays. Per-shape
    /// consumption is the next RP cut and is blocked on recovering the full
    /// 48-cell surface (`docs/FOLLOWUPS.md`).
    ///
    /// # Panics
    ///
    /// Panics if the modal genesis cell is unpopulated — a build-breaking
    /// contradiction, since [`crate::verify_cost::SPEC_VERIFY_COST`] pins it
    /// and the test suite asserts it.
    #[must_use]
    pub fn adopted() -> Self {
        Self::adopted_for(RelayZone::Public)
    }

    /// How many *distinct* adopted parameter sets exist across all zones.
    ///
    /// Only `time_between_hop_ms` varies by zone, and it takes exactly two
    /// values — the clearnet transit assumption and the anonymity one — so the
    /// four `RelayZone`s partition into two classes. Callers that cache a built
    /// artefact per parameter set size on this rather than on the zone count:
    /// the process-wide embargo tables are ~443 KB each, and one table per zone
    /// would build and hold three byte-identical anonymity copies for the life
    /// of the daemon, on a floor rule 76 pins at a Raspberry Pi 4.
    pub const ADOPTED_CLASSES: usize = 2;

    /// Transit assumption per adopted class, in class order.
    const TRANSIT_BY_CLASS: [f64; Self::ADOPTED_CLASSES] = [
        crate::verify_cost::ADOPTED_TRANSIT_ASSUMPTION_MS,
        crate::verify_cost::ANON_ZONE_TRANSIT_ASSUMPTION_MS,
    ];

    /// One representative zone per adopted class, in class order.
    ///
    /// Lets a caller build exactly one artefact per class without naming the
    /// partition a second time. `zone_classes_partition_the_parameter_sets`
    /// pins that these are in class order and that every zone agrees with its
    /// representative.
    pub const CLASS_REPRESENTATIVES: [RelayZone; Self::ADOPTED_CLASSES] =
        [RelayZone::Public, RelayZone::Tor];

    /// Which of [`Self::ADOPTED_CLASSES`] parameter sets `zone` draws.
    ///
    /// The single owner of the zone→parameters partition: [`Self::adopted_for`]
    /// is defined in terms of it, so a cache indexed by this value cannot fall
    /// out of step with the parameters it caches. Adding a third class is one
    /// edit here plus two compile-visible array lengths.
    #[must_use]
    pub const fn adopted_class(zone: RelayZone) -> usize {
        if zone.is_clearnet() {
            0
        } else {
            1
        }
    }

    /// The adopted parameter set **for one relay zone** (§89.2).
    ///
    /// §89 ruled the embargo per-zone rather than one global provisioned at
    /// the worst zone. F-7's precedent does not transfer, by §63.2's keeper:
    /// `fluff_return_ms` crosses transports because a fluff wave returns over
    /// whatever network the node is on, so there is no per-zone value to pick;
    /// `time_between_hop_ms` cannot cross, because the stem it spaces only
    /// ever runs on one transport — and §59's coherence guarantees that, since
    /// a transaction entering the anonymity zone's stem stays there until it
    /// fluffs. The quantity is well-defined per zone in a way `F` is not.
    ///
    /// Only `time_between_hop_ms` varies. `fluff_return_ms` stays the single
    /// worst-zone value F-7 measured — correctly, for the reason just given —
    /// and `q`, the epoch pair and the graph are network-wide constants
    /// (verified: `relay_zone_params` carries stems and epoch only, and
    /// nothing zone-parameterises the fluff probability).
    ///
    /// # `Invalid` takes the longest embargo, not the shortest
    ///
    /// Out-of-domain FFI bytes and unknown-origin cases resolve to
    /// [`RelayZone::Invalid`], which is provisioned as the anonymity hop.
    /// Under-estimating shortens the embargo (privacy-losing); the cost of
    /// the longer wait is recovery latency only.
    #[must_use]
    pub fn adopted_for(zone: RelayZone) -> Self {
        let transit = Self::TRANSIT_BY_CLASS[Self::adopted_class(zone)];
        let hop = crate::verify_cost::adopted_hop_ms_with_transit(
            1,
            crate::verify_cost::GENESIS_TREE_DEPTH,
            transit,
        )
        .expect("the modal genesis cell is a pinned §85.3 measurement");
        Self {
            time_between_hop_ms: hop,
            ..Self::inherited()
        }
    }

    /// The embargo timeout the inherited daemon actually uses:
    /// `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE` = 39 seconds.
    ///
    /// Deliberately *not* a field of [`DandelionParams`] — it is not an input,
    /// it is an output that the inherited code froze by hand. Compare it with
    /// [`Self::closed_form_embargo_secs`] (diagnosis) and
    /// [`crate::schedule::EmbargoTimer::adopted`] (the production path).
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

    /// Paper appendix B.5 closed-form `Tbase` — **diagnosis only**.
    ///
    /// ```text
    /// Tbase = (-k * (k - 1) * hop) / (2 * ln(1 - ep))
    /// ```
    ///
    /// with `k` the expected stem length, `hop` the per-node traversal time,
    /// and `1 - ep` = [`EMBARGO_FULL_TRAVEL_PROBABILITY`]. Rounded up to whole
    /// seconds.
    ///
    /// This is **not** the embargo this crate recommends shipping. The closed
    /// form under-provisions (Finding 3): it substitutes `E[K]` into an
    /// expression in `K(K-1)`, omits the fluff-return term (RD-1), and lets the
    /// origin fluff (pre-RD-4). The production path is
    /// [`crate::schedule::EmbargoTimer::adopted`] /
    /// [`crate::derive::derive_embargo`].
    ///
    /// Kept so the F-1 log-base defect and the F-3 under-provisioning finding
    /// stay executable. Note the logarithm is **natural**. Substituting
    /// `log10` is what reproduces the inherited 39 s — see
    /// [`reconciles_under_log10`].
    #[must_use]
    pub fn closed_form_embargo_secs(&self) -> u32 {
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

    /// Historical name for [`Self::closed_form_embargo_secs`].
    #[deprecated(note = "closed form is diagnosis-only; use EmbargoTimer::adopted for production")]
    #[must_use]
    pub fn average_embargo_secs(&self) -> u32 {
        self.closed_form_embargo_secs()
    }

    /// Number of outbound peers carrying stem traffic this epoch.
    #[must_use]
    pub const fn stem_count(&self) -> usize {
        self.graph.stem_count()
    }

    /// How far the inherited hard-coded embargo departs from the paper closed
    /// form, as a ratio. `1.0` means they agree. Diagnosis only — see
    /// [`Self::closed_form_embargo_secs`].
    #[must_use]
    pub fn inherited_embargo_ratio(&self) -> f64 {
        let closed = self.closed_form_embargo_secs();
        if closed == 0 {
            return f64::INFINITY;
        }
        f64::from(Self::INHERITED_EMBARGO_SECS) / f64::from(closed)
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

    /// `CRYPTONOTE_NOISE_MIN_DELAY`, in seconds.
    ///
    /// There is no Rust noise-epoch constant. C++ used to select
    /// `CRYPTONOTE_NOISE_MIN_EPOCH` (5 min) via `noise_zone_params`; that
    /// selector and the `#define` are gone. The value that ships is the
    /// Dandelion++ epoch, and it already crosses as `min_epoch_secs`.
    /// Mirroring a runtime FFI argument is the delete-don't-synchronize
    /// class (Q-11 Unit 0).
    pub const NOISE_MIN_DELAY_SECS: u32 = 10;
    /// `CRYPTONOTE_NOISE_DELAY_RANGE`, in seconds.
    ///
    /// **Must stay non-zero, and the reason is §56 rather than arithmetic.**
    /// At zero the cadence has no width: `next_send` returns exactly
    /// `NOISE_MIN_DELAY_SECS` every time, and the covert channel becomes a
    /// **metronome** — the one shape Q-11 Unit 2 disqualified, at a 1.000
    /// re-identification rate, because a fixed period is a permanent
    /// per-stream identifier.
    ///
    /// The build fails rather than the daemon degrading, because the failure
    /// is silent in both places it would land: the daemon would emit a
    /// perfectly periodic carrier while still calling it jittered, and the
    /// Unit 2 sweep would run its `BoundedUniform` and `Metronome` arms on the
    /// *same law under two names* — a reader seeing those columns agree would
    /// conclude the shapes are equivalent, which is the opposite of what §56
    /// found.
    pub const NOISE_DELAY_JITTER_SECS: u32 = 5;
    const _: () = assert!(
        NOISE_DELAY_JITTER_SECS > 0,
        "covert cadence jitter must be non-zero: at zero the carrier is a \
         metronome, which Q-11 Unit 2 (§56) disqualified at a 1.000 \
         re-identification rate"
    );

    /// Windows an epoch of `min_epoch_secs` affords at the slowest noise
    /// cadence (`NOISE_MIN_DELAY_SECS + NOISE_DELAY_JITTER_SECS`).
    ///
    /// Integer division: one second under `MAX_FRAGMENTS * per_send` drops a
    /// whole window (see [`carrier::MAX_FRAGMENTS`](crate::params::carrier::MAX_FRAGMENTS)). A full-size message that still
    /// occupies a window when the epoch rolls is discarded by CV-1 and never
    /// arrives.
    ///
    /// This is the **ceiling** the fragment cap must stay under, not the cap's
    /// definition — see [`carrier::MAX_FRAGMENTS`](crate::params::carrier::MAX_FRAGMENTS), which the inherited value
    /// was silently set equal to.
    #[must_use]
    pub const fn noise_windows_in_epoch(min_epoch_secs: u32) -> u32 {
        min_epoch_secs / (NOISE_MIN_DELAY_SECS + NOISE_DELAY_JITTER_SECS)
    }

    /// `CRYPTONOTE_NOISE_CHANNELS` — max outbound connections per zone used
    /// for covert sending.
    pub const NOISE_CHANNELS: usize = 2;
}

pub mod carrier;

#[cfg(test)]
mod r1_tests {
    use super::*;
    use crate::rng::SplitMix64;

    /// Pins the indifference point and that production's sampler uses it.
    ///
    /// What edit reds the value: change `MIXED_ELIGIBILITY_PCT_HUNDREDTHS`.
    /// What edit reds the sampler: make `divert_to_anonymity_zone` ignore
    /// the constant (hardcode a different threshold). Deleting this test
    /// is not the edit that reds either.
    #[test]
    fn the_roll_matches_the_indifference_point() {
        assert_eq!(
            MIXED_ELIGIBILITY_PCT_HUNDREDTHS, 5000,
            "p = 0.5 is the indifference point; do not re-derive from prose"
        );

        const N: u32 = 200_000;
        let mut rng = SplitMix64::new(0x5211);
        let mut hits = 0_u32;
        for _ in 0..N {
            if divert_to_anonymity_zone(&mut rng) {
                hits += 1;
            }
        }
        let observed = f64::from(hits) / f64::from(N);
        let target = f64::from(MIXED_ELIGIBILITY_PCT_HUNDREDTHS) / 10_000.0;
        assert!(
            (observed - target).abs() < 0.01,
            "sampler rate {observed:.4} should be {target:.4}"
        );
    }

    /// The shipped epoch still carries a full-size message, with named slack
    /// rather than a tautology on integer division.
    ///
    /// The historical 300 s / 20-window coincidence (`MAX_FRAGMENTS` was set
    /// equal to `noise_windows_in_epoch(300)`) is not the derivation. What
    /// this pins is the live relationship: the inherited epoch is 600 s, it
    /// affords 40 windows at the slowest cadence, and the derived cap of 5
    /// sits well under that.
    #[test]
    fn the_shipped_epoch_carries_a_full_noise_message_with_named_slack() {
        let per_send = inherited::NOISE_MIN_DELAY_SECS + inherited::NOISE_DELAY_JITTER_SECS;
        let shipped = DandelionParams::inherited().min_epoch_secs;
        assert_eq!(shipped, 600, "CRYPTONOTE_DANDELIONPP_MIN_EPOCH");
        assert_eq!(
            inherited::noise_windows_in_epoch(shipped),
            shipped / per_send,
            "the epoch-window budget is integer division of the shipped epoch"
        );
        let affords = inherited::noise_windows_in_epoch(shipped);
        assert!(
            affords >= carrier::MAX_FRAGMENTS,
            "a {shipped} s epoch affords {affords} windows; the cap is {} — \
             slack is {affords} − {}, not a coincidence with the cap",
            carrier::MAX_FRAGMENTS,
            carrier::MAX_FRAGMENTS,
        );
        assert_eq!(
            inherited::noise_windows_in_epoch(300),
            20,
            "the historical 300 s boundary still affords 20 — that is the \
             ceiling the inherited cap was silently set equal to, kept so a \
             cadence change that would have moved that coincidence reds here"
        );
    }
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

        // What the paper's formula actually yields (diagnosis, not production).
        let closed = p.closed_form_embargo_secs();
        assert_eq!(
            closed, 17,
            "paper formula (natural log) over the inherited inputs"
        );

        // What the daemon ships.
        assert_eq!(DandelionParams::INHERITED_EMBARGO_SECS, 39);

        // The gap, stated as a ratio so a reader sees the magnitude.
        let ratio = p.inherited_embargo_ratio();
        assert!(
            (2.2..2.4).contains(&ratio),
            "inherited/closed-form embargo ratio = {ratio}"
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
        let base = p.closed_form_embargo_secs();
        p.fluff_probability_pct = 10;
        let doubled_k = p.closed_form_embargo_secs();
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
                let t = f64::from(p.closed_form_embargo_secs());
                let probability = ((-k * (k - 1.0) * hop) / (2.0 * t)).exp();
                assert!(
                    probability >= EMBARGO_FULL_TRAVEL_PROBABILITY,
                    "q={pct}% hop={hop_ms}ms: travel probability {probability} < target"
                );
            }
        }
    }

    /// The adopted set moved the `hop` input's provenance, not its value:
    /// the Pi modal verification cell plus the stated transit assumption
    /// lands on the inherited 175 by arithmetic (§71.3). If this assertion
    /// ever fails, a table cell or the transit assumption moved — which is
    /// a legitimate act, but one that re-derives the embargo (the §80.2
    /// price list moves with it) and owes a CHANGELOG entry saying so.
    #[test]
    fn adopted_params_change_provenance_not_behaviour() {
        assert_eq!(DandelionParams::adopted(), DandelionParams::inherited());
    }

    #[test]
    fn the_clearnet_zone_is_unmoved_by_going_per_zone() {
        // §89.2 changes what the anonymity zones get. It must change nothing
        // on clearnet, which carries the overwhelming majority of traffic —
        // if this moves, per-zone provisioning has become the global-at-worst-
        // zone posture §89.2 rejected, wearing a different shape.
        assert_eq!(
            DandelionParams::adopted(),
            DandelionParams::adopted_for(RelayZone::Public),
            "adopted() must remain exactly the clearnet set"
        );
        assert_eq!(
            DandelionParams::adopted_for(RelayZone::Public).time_between_hop_ms,
            175,
            "the clearnet hop moved off its §88 value"
        );
    }

    #[test]
    fn the_anonymity_zones_take_the_longer_interim_hop() {
        let anon = DandelionParams::adopted_for(RelayZone::Tor);
        assert_eq!(
            anon,
            DandelionParams::adopted_for(RelayZone::I2p),
            "i2p and tor are both rendezvous-addressed; nothing distinguishes them here"
        );
        // §63.2's own worst case — "ten times clearnet latency" — reproduced
        // as verification floor + the labelled rendezvous assumption.
        assert_eq!(anon.time_between_hop_ms, 1_750);
        assert!(
            anon.time_between_hop_ms > DandelionParams::adopted().time_between_hop_ms,
            "the anonymity hop must exceed clearnet's: a rendezvous path is six \
             relays where clearnet is one direct connection. If this ever \
             inverts, the interim has been edited to the privacy-losing side"
        );
    }

    #[test]
    fn an_unknown_origin_takes_the_longer_embargo_not_the_shorter() {
        // Invalid/out-of-domain must be the longer hop — under-estimating
        // shortens the embargo (§65, §66).
        assert_eq!(
            DandelionParams::adopted_for(RelayZone::Invalid).time_between_hop_ms,
            DandelionParams::adopted_for(RelayZone::Tor).time_between_hop_ms,
            "an unknown origin must be provisioned as the worst case it could be"
        );
        assert!(!RelayZone::Invalid.is_clearnet());
    }

    /// The class partition is the single owner of "which zones share a
    /// parameter set", and a cache sized on it must be able to trust three
    /// things: the representatives are in class order, every zone agrees with
    /// its own representative, and the classes are genuinely distinct.
    ///
    /// Without the last one a collapsed partition (both representatives
    /// clearnet, say) would still satisfy the first two and quietly hand every
    /// anonymity zone the clearnet embargo — the §89.2 regression this
    /// partition exists to make impossible.
    #[test]
    fn zone_classes_partition_the_parameter_sets() {
        for (class, zone) in DandelionParams::CLASS_REPRESENTATIVES.iter().enumerate() {
            assert_eq!(
                DandelionParams::adopted_class(*zone),
                class,
                "representatives must be listed in class order"
            );
        }

        for zone in [
            RelayZone::Invalid,
            RelayZone::Public,
            RelayZone::I2p,
            RelayZone::Tor,
        ] {
            let representative =
                DandelionParams::CLASS_REPRESENTATIVES[DandelionParams::adopted_class(zone)];
            assert_eq!(
                DandelionParams::adopted_for(zone).time_between_hop_ms,
                DandelionParams::adopted_for(representative).time_between_hop_ms,
                "{zone:?} must draw exactly its class representative's parameters, \
                 or a per-class cache hands it the wrong embargo"
            );
        }

        let hops: Vec<_> = DandelionParams::CLASS_REPRESENTATIVES
            .iter()
            .map(|zone| DandelionParams::adopted_for(*zone).time_between_hop_ms)
            .collect();
        assert_eq!(
            hops.len(),
            DandelionParams::ADOPTED_CLASSES,
            "one representative per class"
        );
        assert!(
            hops[0] < hops[1],
            "the classes must stay distinct and clearnet-first: {hops:?}"
        );
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
