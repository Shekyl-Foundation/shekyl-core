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

use crate::params::P2P_DEFAULT_OUT_PEERS;
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
}

impl Default for FloodParams {
    fn default() -> Self {
        Self {
            nodes: 512,
            peers: P2P_DEFAULT_OUT_PEERS as usize,
            reach: FloodReach::EveryPeer,
        }
    }
}

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
/// - `degrees[0]` reduced — the degraded node is the **source**, so the sample
///   is its own fluff return. This is the self-harm axis the floor is
///   justified on.
/// - some `degrees[k]`, `k != 0`, reduced — the degraded node is a peer, so
///   the sample is the rest of the network's first passage. This is the
///   network axis.
///
/// Reading one and concluding about the other is the error this signature
/// exists to make hard to commit.
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
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(250) };

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
                let arrival = at.saturating_add(draw_ms(rng));
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
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(250) };

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
                let arrival = at.saturating_add(draw_ms(rng));
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
