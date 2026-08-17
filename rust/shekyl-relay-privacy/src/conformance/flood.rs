// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Goodness-of-fit grading / simulation is float math over sample counts.
//   Diagnostic-only and excluded from the default build.

use crate::rng::{bounded_uniform, RelayRng};
use crate::schedule::{DelayFamily, DelayTable};

use super::util::usize_from;

/// Which edges a fluffing node relays across — the instrument's model of the
/// relay crate's `FluffReach` (`shekyl-relay`; this crate deliberately does
/// not depend on it, so the mirroring is by name and test, not by type).
///
/// **Added at F-7 (§26).** The instrument previously inserted every edge in
/// *both* directions, so it modelled `EveryPeer` **by construction** and had
/// no way to express `OutboundOnly` — which is exactly *"traverse only the
/// edges I initiated"*, a directed graph. `fluff_return_ms` was measured under
/// the symmetric build and is fed to the embargo derivation for **every**
/// transport, so on an anonymity zone (outbound-only fluff) the input is
/// measured on a rule that configuration does not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodReach {
    /// Relay to every peer, initiated or not — the clearnet rule. Undirected.
    EveryPeer,
    /// Relay only across edges this node initiated — the i2p/tor rule.
    /// Directed: first passage is strictly slower, because a node has
    /// `peers` usable out-edges rather than ~`2 × peers`, *and* paths must
    /// respect direction.
    OutboundOnly,
}

/// Topology inputs for the fluff-flood first-passage measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodParams {
    /// Nodes in the simulated network.
    pub nodes: usize,
    /// Fluff peers each node **initiates** to.
    ///
    /// # Pinned to [`P2P_DEFAULT_OUT_PEERS`] (§69, §70)
    ///
    /// Consumed from the constant, not re-typed as a literal: an instrument
    /// that hardcodes the degree keeps simulating a network the daemon has
    /// stopped running, which is F-7's failure mode one layer down.
    ///
    /// **Provenance of the old `8`, recorded because it was not (§28.4):** it
    /// is very likely the *measured mean degree of the 2015 Bitcoin server
    /// graph* (Miller et al., via Fanti–Viswanath, who model 8 outbound / 125
    /// total and note the effective average is "closer to 8 due to
    /// nonhomogeneities"). **Not** Bitcoin's outbound default and **not** a
    /// Shekyl quantity. Their figure also excludes NAT'd clients because
    /// "clients do not relay transactions", a Bitcoin fact that does not map:
    /// a NAT'd Shekyl node makes its 12 outbound and relays normally. **A
    /// value that is neither ours nor applicable is not a default, so it is
    /// gone.**
    ///
    /// # Why holding this fixed is *not* F-7's error
    ///
    /// Under [`FloodReach::EveryPeer`] the effective degree is ~`2 × peers`
    /// (each node initiates `peers` and receives ~`peers`); under
    /// [`FloodReach::OutboundOnly`] the out-degree is exactly `peers`. So a
    /// comparison that changes only `reach` *does* see a different usable
    /// degree — **and that is the mechanism by which the rule acts, not a
    /// confound.** F-7's defect was comparing at different *configured*
    /// degrees (`EveryPeer` at 8 against `OutboundOnly` at 16), so a rule
    /// change and a degree change moved together and the attribution was
    /// ambiguous. Here the **configured** degree is held identical in both
    /// arms and the **usable** degree differs downstream of the rule, which is
    /// the causal chain being measured.
    ///
    /// # The caveat that belongs at the number
    ///
    /// 12 is the *default*, and real degree is heterogeneous: a NAT'd node has
    /// 12 out and 0 in, so its `EveryPeer` degree is 12 rather than ~24. Using
    /// the default uniformly is the right **control** for a rule comparison,
    /// but it puts the `EveryPeer` arm at the *optimistic* end of the real
    /// distribution — which makes the measured cost of reverse-parity an
    /// **over**-estimate. Safe direction, and stated so a later reader does
    /// not mistake the bias for precision.
    pub peers: usize,
    /// Which edges relay (see [`FloodReach`]).
    pub reach: FloodReach,
    /// **Per-hop network transit for this flood's link class, in ms.**
    ///
    /// # Why this is a required field and not an `Option` with a default
    ///
    /// Until 2026-08-17 this model had no transit term at all: a hop advanced
    /// by a fluff-flush draw alone. That was harmless while `F′` was a
    /// clearnet quantity — [`crate::verify_cost::ADOPTED_TRANSIT_ASSUMPTION_MS`]
    /// is 50 ms against a 5000 ms flush mean, ~1 % — and became decisive the
    /// moment §91 ruled Design A, under which the **worst zone is the
    /// anonymity graph** at
    /// [`crate::verify_cost::ANON_ZONE_TRANSIT_ASSUMPTION_MS`] = 1625 ms,
    /// ~32 % of the same mean. Omitting it makes the flood look *faster*,
    /// which is the under-provisioning direction (§91.6).
    ///
    /// It is mandatory so that every caller must **declare which link class it
    /// is simulating**. A defaulted field would let the omission recur
    /// silently, and the omission is exactly what invalidated an `F′`
    /// derivation that had already been through a convergence criterion, an
    /// admissible-region boundary and two review rounds.
    pub transit_ms: u64,
}

/// The transit assumption that goes with a reach, so the two cannot be set to
/// different link classes.
///
/// `FluffReach::OutboundOnly` is set from `nzone != public_` in production, so
/// the reach **is** the link class: deriving transit from it removes the one
/// incoherent combination (an anonymity reach at clearnet latency) that §91.6
/// says invalidates a derivation while still looking reasonable.
#[must_use]
pub const fn transit_for(reach: FloodReach) -> u64 {
    match reach {
        // Clearnet: ADOPTED_TRANSIT_ASSUMPTION_MS.
        FloodReach::EveryPeer => 50,
        // Anonymity zone: ANON_ZONE_TRANSIT_ASSUMPTION_MS.
        FloodReach::OutboundOnly => 1_625,
    }
}

/* `Default` was REMOVED with the transit field (§91.6). Its whole affordance
was filling fields the caller did not think about, and the field the caller
must not skip is the one that says which network this flood runs on. A
default transit would have re-created, behind a shorter spelling, the exact
omission that invalidated an `F′` derivation. Callers name all four fields.

The two shipped pairings, so `reach` and `transit_ms` are not set to
different link classes by accident:

  clearnet  -> FloodReach::EveryPeer    + ADOPTED_TRANSIT_ASSUMPTION_MS  (50)
  anonymity -> FloodReach::OutboundOnly + ANON_ZONE_TRANSIT_ASSUMPTION_MS (1625)

(`FluffReach::OutboundOnly` is set from `nzone != public_` in production, so
the reach IS the link class; the transit must agree with it.) */

/// First-passage statistics for a fluff flood, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FloodSummary {
    /// First passages counted — every non-source node of every trial,
    /// including the `unreached` ones.
    pub samples: usize,
    /// Nodes the flood never reached, across all trials. A directed random
    /// graph ([`FloodReach::OutboundOnly`]) can strand nodes at low degree,
    /// and the stranded nodes are precisely the slowest first-passages —
    /// so they enter the percentiles below as `u64::MAX` rather than being
    /// dropped. The p90 here feeds the embargo derivation
    /// (`fluff_return_ms`); dropping the worst passages would bias it low,
    /// which is the privacy-losing direction.
    pub unreached: usize,
    /// Mean over the *reached* nodes only (a mean including `u64::MAX` is
    /// meaningless). Read it beside `unreached`.
    pub mean_ms: f64,
    /// Percentiles over ALL `samples`, unreached-as-`u64::MAX` included: a
    /// topology that strands >10 % of nodes reports `p90_ms == u64::MAX`,
    /// loudly, instead of an optimistic finite number.
    pub p50_ms: u64,
    pub p90_ms: u64,
}

/// The flood's time quantum. Every delay these instruments draw is a whole
/// number of ticks, so **no reading they produce can be finer than this** — a
/// difference below one tick is the grid, not a measurement.
///
/// Named because [`ConvergenceBudget::tolerance_ms`] is defined against it: the
/// point of the convergence check is to stop reporting differences the
/// instrument cannot resolve.
pub const FLOOD_TICK_MS: u64 = 250;

/// Build the flood adjacency shared by the instruments below: each node
/// initiates `peers` *distinct* non-self edges (redraw on a self-hit or a
/// repeat), so every node's effective degree is fixed by [`FloodParams`], not
/// by the collision rate. Under [`FloodReach::EveryPeer`] the receiver also
/// relays back across the link it did not initiate (the reciprocal edge);
/// omitting that reciprocal under [`FloodReach::OutboundOnly`] IS the rule
/// (F-7).
fn build_adjacency<R: RelayRng + ?Sized>(flood: FloodParams, rng: &mut R) -> Vec<Vec<usize>> {
    let degrees = vec![flood.peers; flood.nodes];
    build_adjacency_from_degrees(&degrees, flood.reach, rng)
}

/// Wire a graph where each node initiates its **own** out-degree.
///
/// Extracted from `build_adjacency` so a degree can differ per node. The
/// uniform case delegates here with a constant vector, so there is one wiring
/// rule rather than two that must be kept in step.
///
/// **`degrees.len()` IS the node count**, deliberately: an earlier form took
/// `nodes` alongside and could be handed a slice that disagreed with it,
/// panicking on an index rather than saying so. Two values that must agree are
/// one value.
fn build_adjacency_from_degrees<R: RelayRng + ?Sized>(
    degrees: &[usize],
    reach: FloodReach,
    rng: &mut R,
) -> Vec<Vec<usize>> {
    let nodes = degrees.len();
    // Per-node capacity, not `vec![Vec::with_capacity(d); nodes]`. That form
    // reads as pre-sizing every row and does not: `vec![elem; n]` CLONES, and
    // `Vec::clone` allocates for the length it copies, so only the seed row
    // keeps its capacity and the rest start empty. Under `OutboundOnly` each
    // row takes exactly its own degree, so sizing it here is exact rather than
    // a guess.
    let mut adjacency: Vec<Vec<usize>> = degrees
        .iter()
        .map(|d| Vec::with_capacity((*d).min(nodes.saturating_sub(1))))
        .collect();
    for node in 0..nodes {
        let peers = degrees[node].min(nodes - 1);
        let mut initiated: Vec<usize> = Vec::with_capacity(peers);
        while initiated.len() < peers {
            let other = usize_from(bounded_uniform(rng, (nodes - 1) as u64));
            if other != node && !initiated.contains(&other) {
                initiated.push(other);
                adjacency[node].push(other);
                if reach == FloodReach::EveryPeer {
                    adjacency[other].push(node);
                }
            }
        }
    }
    adjacency
}

/// Measure how long a fluff flood takes to travel back to an arbitrary node.
///
/// RD-1 instrument. See design doc §10.
///
/// # Panics
///
/// Panics if `trials` is zero, if `nodes` is under two, or if `peers` is zero.
#[must_use]
pub fn simulate_fluff_return<R: RelayRng + ?Sized>(
    flood: FloodParams,
    mean_quarter_secs: u32,
    family: DelayFamily,
    trials: usize,
    rng: &mut R,
) -> FloodSummary {
    assert!(flood.peers >= 1, "a flood needs at least one peer per node");
    let degrees = vec![flood.peers; flood.nodes];
    simulate_fluff_return_mixed(flood, &degrees, mean_quarter_secs, family, trials, rng)
}

/// [`simulate_fluff_return`] with a **per-node** out-degree.
///
/// # What this exists to answer, and why the uniform form cannot
///
/// F-8b's floor is justified as a condition on the topology the embargo
/// constants were derived under (`OutboundOnly@12`). A node below it has a
/// slower fluff return, so its own embargo is under-provisioned. Whether that
/// is a **per-node** condition or a **network** one decides whether a live
/// per-node check can exist at all — and the uniform simulator cannot tell
/// them apart, because moving `peers` moves every node at once.
///
/// **Node 0 is the flood source and is excluded from the arrival sample**, so
/// the two questions are asked by *where the degraded node is placed*:
///
/// - `degrees[0]` reduced — the degraded node is the **source**. The sample is
///   how a degraded source slows *everyone else's* first passage.
/// - some `degrees[k]`, `k != 0`, reduced — the degraded node is a peer, and
///   the pooled sample averages it into `nodes - 2` healthy ones.
///
/// # This arm does NOT measure "the degraded node's own fluff return"
///
/// An earlier version of this comment said the `degrees[0]` arm did, and that
/// sentence propagated into a design section and was used to justify a ruling.
/// Two reasons it is false, and they compound:
///
/// 1. **Node 0's own arrival is never sampled** — `skip(1)` excludes it by
///    construction, so no arm here reads the source's own return time.
/// 2. **Under [`FloodReach::OutboundOnly`] a node's own fluff return is
///    governed by its IN-degree, not its out-degree.** A fluff reaches `v`
///    only over links someone else initiated toward `v`. But `degrees[v]`
///    controls only `v`'s *outgoing* draws — every other node picks its
///    targets uniformly, never consulting `degrees[v]` — so lowering
///    `degrees[v]` does not thin the edges pointed *at* `v` and does not slow
///    `v`'s own return at all.
///
/// The split exists **only because the fluff rule is outbound-only**. Under
/// [`FloodReach::EveryPeer`] the receiver relays back over the link it did not
/// initiate, in-degree and out-degree collapse into one quantity, and the
/// intuition is sound. F-7 chose `OutboundOnly`; an `EveryPeer` intuition
/// applied to it is what produced the wrong sentence.
///
/// Measuring a node's own return therefore needs an instrument this builder
/// does not provide: `degrees` parameterizes only *outgoing* draws, so no
/// value passed here can thin the edges pointed *at* a node. It would take
/// either an explicit-adjacency entry point or an in-degree parameter — and
/// the reader is `best[k]` for that node specifically, because the pooled
/// sample averages one degraded node into `nodes - 2` healthy ones. Neither
/// extension exists yet, deliberately: measured on the fleet, the effect it
/// would quantify is a small correction — `r(out, in) = +0.05`, and a
/// below-floor node's in-degree deficit is 0.30 links
/// (`Q12_D6A_PEER_DISCOVERY_RUN.md` §17.6) — so the independence this builder
/// assumes is faithful rather than an artifact, and the missing instrument is
/// recorded rather than built.
///
/// # Panics
///
/// Panics if `trials` is zero, if `nodes` is under two, if `degrees` is not
/// exactly `nodes` long, or if any degree is zero.
#[must_use]
pub fn simulate_fluff_return_mixed<R: RelayRng + ?Sized>(
    flood: FloodParams,
    degrees: &[usize],
    mean_quarter_secs: u32,
    family: DelayFamily,
    trials: usize,
    rng: &mut R,
) -> FloodSummary {
    assert!(trials > 0, "simulation needs at least one trial");
    assert!(flood.nodes >= 2, "a flood needs at least two nodes");
    assert!(
        degrees.len() == flood.nodes,
        "degrees must name every node: got {}, nodes {}",
        degrees.len(),
        flood.nodes
    );
    assert!(
        degrees.iter().all(|d| *d >= 1),
        "a flood needs at least one peer per node"
    );

    let table = DelayTable::build(mean_quarter_secs, family);
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(FLOOD_TICK_MS) };

    let mut arrivals: Vec<u64> = Vec::with_capacity(trials * flood.nodes);

    for _ in 0..trials {
        let adjacency = build_adjacency_from_degrees(degrees, flood.reach, rng);

        let mut best = vec![u64::MAX; flood.nodes];
        let mut frontier = std::collections::BinaryHeap::new();
        best[0] = 0;
        frontier.push(std::cmp::Reverse((0_u64, 0_usize)));
        while let Some(std::cmp::Reverse((at, node))) = frontier.pop() {
            if at > best[node] {
                continue;
            }
            for &next in &adjacency[node] {
                // Flush-scheduler delay PLUS this link class's transit (§91.6).
                let arrival = at
                    .saturating_add(draw_ms(rng))
                    .saturating_add(flood.transit_ms);
                if arrival < best[next] {
                    best[next] = arrival;
                    frontier.push(std::cmp::Reverse((arrival, next)));
                }
            }
        }

        // Unreached nodes stay in as `u64::MAX` — see `FloodSummary::unreached`.
        arrivals.extend(best.iter().skip(1).copied());
    }

    arrivals.sort_unstable();
    let samples = arrivals.len();
    let unreached = arrivals
        .iter()
        .rev()
        .take_while(|t| **t == u64::MAX)
        .count();
    let reached = samples - unreached;
    assert!(
        reached > 0,
        "flood reached no node — check the topology inputs"
    );
    let mean_ms = arrivals[..reached].iter().map(|t| *t as f64).sum::<f64>() / reached as f64;
    let idx = |q: f64| arrivals[(((samples as f64) * q) as usize).min(samples - 1)];

    FloodSummary {
        samples,
        unreached,
        mean_ms,
        p50_ms: idx(0.50),
        p90_ms: idx(0.90),
    }
}

/// First-spy source-attribution precision in the fluff (diffusion) phase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FirstSpyPrecision {
    pub observed: usize,
    pub precision: f64,
    pub mean_first_spy_hops: f64,
}

/// Measure [`FirstSpyPrecision`] on a random graph with spy fraction `f`.
///
/// # Panics
///
/// Panics if `trials` is zero, `spy_fraction` is not in `(0, 1]`, or the
/// topology is degenerate.
#[must_use]
pub fn simulate_diffusion_first_spy<R: RelayRng + ?Sized>(
    flood: FloodParams,
    mean_quarter_secs: u32,
    family: DelayFamily,
    spy_fraction: f64,
    trials: usize,
    rng: &mut R,
) -> FirstSpyPrecision {
    assert!(trials > 0, "need at least one trial");
    assert!(flood.nodes >= 2 && flood.peers >= 1, "degenerate topology");
    assert!(
        spy_fraction > 0.0 && spy_fraction <= 1.0,
        "spy fraction must be in (0, 1]"
    );

    let table = DelayTable::build(mean_quarter_secs, family);
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(FLOOD_TICK_MS) };

    // Scaled Bernoulli, compared with `<=` (not `<`) so `spy_fraction == 1.0`
    // (threshold == u32::MAX) marks every candidate node, per the `(0, 1]` contract.
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;

    let mut correct = 0_usize;
    let mut observed = 0_usize;
    let mut first_spy_hops_total = 0_u64;

    for _ in 0..trials {
        let adjacency = build_adjacency(flood, rng);
        let spies: Vec<bool> = (0..flood.nodes)
            .map(|n| n != 0 && (rng.next_u64() as u32) <= spy_threshold)
            .collect();

        let mut best = vec![u64::MAX; flood.nodes];
        let mut pred = vec![usize::MAX; flood.nodes];
        let mut hops = vec![0_u64; flood.nodes];
        let mut heap = std::collections::BinaryHeap::new();
        best[0] = 0;
        heap.push(std::cmp::Reverse((0_u64, 0_usize)));
        let mut first_spy: Option<(u64, usize)> = None;
        while let Some(std::cmp::Reverse((at, node))) = heap.pop() {
            if at > best[node] {
                continue;
            }
            if spies[node] {
                first_spy = Some((at, node));
                break;
            }
            for &next in &adjacency[node] {
                // Flush-scheduler delay PLUS this link class's transit (§91.6).
                let arrival = at
                    .saturating_add(draw_ms(rng))
                    .saturating_add(flood.transit_ms);
                if arrival < best[next] {
                    best[next] = arrival;
                    pred[next] = node;
                    hops[next] = hops[node] + 1;
                    heap.push(std::cmp::Reverse((arrival, next)));
                }
            }
        }

        if let Some((_, spy)) = first_spy {
            observed += 1;
            first_spy_hops_total += hops[spy];
            if pred[spy] == 0 {
                correct += 1;
            }
        }
    }

    assert!(
        observed > 0,
        "no spy ever received the flood — raise f or trials"
    );
    FirstSpyPrecision {
        observed,
        precision: correct as f64 / observed as f64,
        mean_first_spy_hops: first_spy_hops_total as f64 / observed as f64,
    }
}

/// How hard to try before **refusing** to report a first-passage reading.
///
/// # Why a budget rather than a trial count
///
/// A single `(seed, trials)` pair yields one draw from a distribution, and
/// nothing in the reading says how wide that distribution is. `fluff_return_ms`
/// was set from such a reading; so was the `3250` in `f7_directed.rs`, which
/// takes `SplitMix64::new(0xF7_0000 + peers)` at one trial count and reports
/// whatever comes back. The number may be right — the *procedure* cannot tell,
/// and re-running it at another seed is how you find out, not an optional
/// robustness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvergenceBudget {
    /// Trials per seed on the first pass. Doubles until convergence or
    /// `max_trials`.
    pub start_trials: usize,
    /// The refusal point. Reaching it without collapsing the spread is an
    /// [`ConvergenceRefusal::Spread`], **never** a reported number.
    pub max_trials: usize,
    /// The spread across seeds that counts as converged, in milliseconds.
    ///
    /// Defaults to [`FLOOD_TICK_MS`] — one tick of disagreement admitted.
    ///
    /// Achievable spreads are exact multiples of the tick, so the meaningful
    /// settings are coarse: anything in `0..FLOOD_TICK_MS` demands the seeds
    /// agree *exactly*, and `FLOOD_TICK_MS` admits a single tick. Exact
    /// agreement is a stricter bar, **not an impossible one** — the shipped
    /// topology reaches spread 0 by 64 trials.
    pub tolerance_ms: u64,
}

impl Default for ConvergenceBudget {
    fn default() -> Self {
        Self {
            start_trials: 64,
            max_trials: 8192,
            tolerance_ms: FLOOD_TICK_MS,
        }
    }
}

/// A first-passage reading that survived [`ConvergenceBudget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converged {
    /// The reading to consume, taken as the **maximum** across seeds.
    ///
    /// Max rather than mean or median for the reason
    /// [`FloodSummary::unreached`] gives: a `fluff_return_ms` biased low
    /// under-provisions the embargo, which is the privacy-losing direction.
    /// Once converged the choice moves the answer by under a tick, but the rule
    /// is stated so it is not re-decided by whoever reads this next.
    pub p90_ms: u64,
    /// What it took, so the cost is visible and the run is reproducible.
    pub trials_per_seed: usize,
    /// The surviving disagreement — necessarily `<= tolerance_ms`.
    pub spread_ms: u64,
    /// Every seed's reading, in the order the seeds were given.
    pub readings_ms: Vec<u64>,
}

/// Why a reading was refused. **There is no third state**: the instrument
/// either converges or declines to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvergenceRefusal {
    /// At least one seed stranded more than 10 % of nodes, so its p90 is
    /// `u64::MAX`.
    ///
    /// Separated from [`Self::Spread`] because **more trials cannot fix it** —
    /// stranding is a property of the topology, not of the sample size, so
    /// escalating the budget would burn it against a question it cannot
    /// answer. The input degrees are what is wrong.
    Stranded {
        trials_per_seed: usize,
        seeds_stranded: usize,
        seeds: usize,
    },
    /// The budget ran out with the seeds still disagreeing by more than
    /// `tolerance_ms`.
    Spread {
        trials_per_seed: usize,
        spread_ms: u64,
        tolerance_ms: u64,
        readings_ms: Vec<u64>,
    },
}

impl std::fmt::Display for ConvergenceRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stranded {
                trials_per_seed,
                seeds_stranded,
                seeds,
            } => write!(
                f,
                "REFUSE: {seeds_stranded} of {seeds} seeds stranded >10 % of nodes at \
                 {trials_per_seed} trials — p90 is unreached, and more trials will not \
                 change that. Fix the degrees, not the budget."
            ),
            Self::Spread {
                trials_per_seed,
                spread_ms,
                tolerance_ms,
                readings_ms,
            } => write!(
                f,
                "REFUSE: seeds still spread {spread_ms} ms (tolerance {tolerance_ms} ms) at \
                 {trials_per_seed} trials/seed — readings {readings_ms:?}. Reporting any one \
                 of these would be reporting a draw as a measurement."
            ),
        }
    }
}

impl std::error::Error for ConvergenceRefusal {}

/// Measure the fluff-return p90 across several seeds, escalating trials until
/// the seeds agree — or **refuse to report a number**.
///
/// This is [`simulate_fluff_return_mixed`] with the missing half attached. The
/// simulator answers *"what did this draw give?"*; a constant derived from it
/// needs *"is that the distribution's answer or this seed's?"*, and only
/// re-running at independent seeds can say.
///
/// # The independence that matters is ACROSS SEEDS, not across rungs
///
/// Each escalation rebuilds the RNGs from the **same** seeds, so a rung's draws
/// begin with the previous rung's: the ladder is **nested**, and a higher rung
/// is a longer run of the same stream, not a fresh sample of it.
///
/// **That is the correct shape, not a limitation.** The question being asked is
/// *"at this trial count, do independent seeds agree?"* — which needs the seeds
/// to be independent **of each other** at a given rung, and they are, being
/// distinct `SplitMix64` streams. Independence *between rungs* would actively
/// hurt: it would make each rung a fresh lottery, so the ladder could terminate
/// on a rung where the seeds happened to agree, and stopping early on luck is
/// the failure this whole type exists to prevent. Nesting means more trials is
/// strictly more information about the same estimate, so agreement at a higher
/// rung is stronger evidence rather than another roll.
///
/// # Errors
///
/// [`ConvergenceRefusal::Spread`] when the budget is exhausted with the seeds
/// still disagreeing, and [`ConvergenceRefusal::Stranded`] when the topology
/// leaves a seed's p90 unreached. Both are refusals to report, deliberately:
/// the failure mode this exists to stop is a plausible number with no claim on
/// the distribution behind it.
///
/// # Panics
///
/// Panics if fewer than two seeds are given (one reading has no spread), or if
/// the budget is degenerate (`start_trials` zero, or above `max_trials`).
pub fn converged_fluff_return_mixed<R, F>(
    flood: FloodParams,
    degrees: &[usize],
    mean_quarter_secs: u32,
    family: DelayFamily,
    seeds: &[u64],
    budget: ConvergenceBudget,
    mut make_rng: F,
) -> Result<Converged, ConvergenceRefusal>
where
    R: RelayRng,
    F: FnMut(u64) -> R,
{
    assert!(
        seeds.len() >= 2,
        "convergence needs at least two seeds — one reading has no spread to check"
    );
    assert!(budget.start_trials > 0, "start_trials must be positive");
    assert!(
        budget.start_trials <= budget.max_trials,
        "start_trials {} exceeds max_trials {}",
        budget.start_trials,
        budget.max_trials
    );

    let mut trials = budget.start_trials;
    loop {
        let readings_ms: Vec<u64> = seeds
            .iter()
            .map(|seed| {
                let mut rng = make_rng(*seed);
                simulate_fluff_return_mixed(
                    flood,
                    degrees,
                    mean_quarter_secs,
                    family,
                    trials,
                    &mut rng,
                )
                .p90_ms
            })
            .collect();

        let seeds_stranded = readings_ms.iter().filter(|p| **p == u64::MAX).count();
        if seeds_stranded > 0 {
            return Err(ConvergenceRefusal::Stranded {
                trials_per_seed: trials,
                seeds_stranded,
                seeds: seeds.len(),
            });
        }

        // Unwraps are total: `seeds.len() >= 2` is asserted above, so the
        // iterator is non-empty.
        let hi = *readings_ms.iter().max().unwrap();
        let lo = *readings_ms.iter().min().unwrap();
        let spread_ms = hi - lo;

        if spread_ms <= budget.tolerance_ms {
            return Ok(Converged {
                p90_ms: hi,
                trials_per_seed: trials,
                spread_ms,
                readings_ms,
            });
        }

        if trials >= budget.max_trials {
            return Err(ConvergenceRefusal::Spread {
                trials_per_seed: trials,
                spread_ms,
                tolerance_ms: budget.tolerance_ms,
                readings_ms,
            });
        }
        // `saturating_mul`, not `*`: the loop only reaches here with
        // `trials < max_trials`, so doubling overflows exactly when a caller
        // passes `max_trials > usize::MAX / 2`. In release that wraps to a
        // SMALL trial count, which never reaches `max_trials` — an infinite
        // ladder rather than a refusal, which is the one outcome this type
        // must not have.
        trials = trials.saturating_mul(2).min(budget.max_trials);
    }
}
