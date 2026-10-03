// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// ^ Diagnostic-only float math; excluded from the default build.

use super::flood::FloodReach;
use crate::rng::{bounded_uniform, RelayRng};

/// What a supernode observer learns from the diffusion phase, for one
/// [`FloodReach`].
///
/// The adversary opens cheap **inbound** edges to a fraction `dial_fraction`
/// of honest nodes and is dialed by none. Under [`FloodReach::EveryPeer`]
/// (production, on every connector) those edges receive the fluff. Under
/// [`FloodReach::OutboundOnly`] (the retired D7 graph) they do not. The
/// connector does not select the edge set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SupernodeObservation {
    /// Reach measured.
    pub reach: FloodReach,
    /// Fraction of transactions whose fluff the supernode observes at all.
    pub observed_fraction: f64,
    /// Among observed floods, P(the supernode's first-received predecessor is
    /// the true source) — the **inbound-fluff** first-spy attribution precision.
    ///
    /// The Tor `0.000` here means "zero via the cheap inbound direction," not
    /// "zero first-spy precision on Tor": a supernode over Tor can still spend
    /// the expensive resource it cannot create for free — an on-path *outbound*
    /// stem-successor position — and there its reach is the black-hole channel's
    /// (measured separately by [`simulate_blackhole_attack`]), not zero. This
    /// field is only the inbound observable.
    pub first_spy_precision: f64,
}

/// Measure [`SupernodeObservation`] under `flood.reach`.
///
/// Honest topology: `flood.nodes` nodes, each dialing `flood.peers` random
/// others (directed edges). Fluff from a source propagates over every edge
/// under [`FloodReach::EveryPeer`] and over outbound edges only under
/// [`FloodReach::OutboundOnly`]. The supernode dials `dial_fraction · nodes`
/// honest nodes (its inbound edges to them) and is dialed by none.
///
/// # Panics
///
/// Panics on a degenerate topology, a `dial_fraction` outside `(0, 1]`, or zero
/// trials.
#[must_use]
pub fn simulate_transport_observation<R: RelayRng + ?Sized>(
    flood: super::flood::FloodParams,
    mean_quarter_secs: u32,
    family: crate::schedule::DelayFamily,
    dial_fraction: f64,
    trials: usize,
    rng: &mut R,
) -> SupernodeObservation {
    assert!(trials > 0, "need at least one trial");
    assert!(flood.nodes >= 3 && flood.peers >= 1, "degenerate topology");
    assert!(
        dial_fraction > 0.0 && dial_fraction <= 1.0,
        "dial fraction must be in (0, 1]"
    );

    let table = crate::schedule::DelayTable::build(mean_quarter_secs, family);
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(250) };

    let n = flood.nodes;
    let peers = flood.peers.min(n - 1);
    // Scaled Bernoulli, compared with `<=` (not `<`) so `dial_fraction == 1.0`
    // (threshold == u32::MAX) marks *every* node, honouring the `(0, 1]` contract;
    // for other fractions the difference is one in 2^32.
    let dial_threshold = (dial_fraction * f64::from(u32::MAX)) as u32;

    let mut observed = 0_usize;
    let mut correct = 0_usize;

    for _ in 0..trials {
        // Honest directed edges u -> v. `out[u]` = nodes u dialed. For an
        // EveryPeer flood we also need the reverse (who dialed u).
        let mut out: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); n];
        let mut inbound: Vec<Vec<usize>> = vec![Vec::new(); n];
        // Each node dials `peers` *distinct* non-self others (redraw on a
        // self-hit or a repeat), so the effective out-degree is exactly `peers`
        // — the topology is fixed by `FloodParams`, not by the self-hit rate.
        // Same fixed-degree model as `simulate_fluff_return`.
        for (u, out_u) in out.iter_mut().enumerate() {
            while out_u.len() < peers {
                let v = usize::try_from(bounded_uniform(rng, (n - 1) as u64)).expect("bounded");
                if v != u && !out_u.contains(&v) {
                    out_u.push(v);
                    inbound[v].push(u);
                }
            }
        }
        // The supernode's inbound edges: the honest nodes it dialed. On
        // clearnet these deliver fluff to it; on Tor they do not.
        let watched: Vec<bool> = (0..n)
            .map(|_| (rng.next_u64() as u32) <= dial_threshold)
            .collect();

        // Source is node 0; Dijkstra over the transport-appropriate edge set.
        let source = 0_usize;
        let mut best = vec![u64::MAX; n];
        let mut pred = vec![usize::MAX; n];
        let mut heap = std::collections::BinaryHeap::new();
        best[source] = 0;
        heap.push(std::cmp::Reverse((0_u64, source)));

        // The supernode observes node w's fluff when w relays across an edge
        // the adversary holds. Under EveryPeer that is the inbound edge the
        // adversary dialed. Under OutboundOnly the node never fluffs inbound,
        // and it never dialed the adversary, so the observation is empty.
        let inbound_carries = matches!(flood.reach, FloodReach::EveryPeer);
        let mut first_obs: Option<usize> = None; // the honest node whose fluff the adversary first caught

        while let Some(std::cmp::Reverse((at, node))) = heap.pop() {
            if at > best[node] {
                continue;
            }
            let caught = inbound_carries && watched[node] && node != source;
            if caught {
                first_obs = Some(node);
                break;
            }
            for &next in &out[node] {
                let arrival = at.saturating_add(draw_ms(rng));
                if arrival < best[next] {
                    best[next] = arrival;
                    pred[next] = node;
                    heap.push(std::cmp::Reverse((arrival, next)));
                }
            }
            // EveryPeer fluff also traverses inbound edges (a node fluffs to
            // peers that dialed it). Model that reverse spread too.
            if inbound_carries {
                for &next in &inbound[node] {
                    let arrival = at.saturating_add(draw_ms(rng));
                    if arrival < best[next] {
                        best[next] = arrival;
                        pred[next] = node;
                        heap.push(std::cmp::Reverse((arrival, next)));
                    }
                }
            }
        }

        if let Some(node) = first_obs {
            observed += 1;
            // The supernode guesses the source is `node`'s predecessor in the
            // flood — its own first-spy estimator. Correct iff that is node 0.
            if pred[node] == source || node == source {
                correct += 1;
            }
        }
    }

    let observed_fraction = observed as f64 / trials as f64;
    let first_spy_precision = if observed == 0 {
        0.0
    } else {
        correct as f64 / observed as f64
    };
    SupernodeObservation {
        reach: flood.reach,
        observed_fraction,
        first_spy_precision,
    }
}

/// The clearnet passive inbound-neighbour channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PassiveNeighborLeak {
    pub reach: FloodReach,
    pub leak_rate: f64,
    pub origin_share_of_leaks: f64,
}

/// Measure [`PassiveNeighborLeak`] at supernode reach `dial_fraction`.
///
/// # Panics
///
/// Panics if `trials` is zero or `dial_fraction` is outside `(0, 1]`.
#[must_use]
pub fn simulate_passive_neighbor_leak<R: RelayRng + ?Sized>(
    params: &crate::params::DandelionParams,
    embargo: &crate::schedule::EmbargoTimer,
    dial_fraction: f64,
    reach: FloodReach,
    trials: usize,
    rng: &mut R,
) -> PassiveNeighborLeak {
    assert!(trials > 0, "need at least one trial");
    assert!(
        dial_fraction > 0.0 && dial_fraction <= 1.0,
        "dial fraction must be in (0, 1]"
    );
    let inbound_observes = matches!(reach, FloodReach::EveryPeer);
    // Scaled Bernoulli, compared with `<=` (not `<`) so `dial_fraction == 1.0`
    // (threshold == u32::MAX) marks *every* node, honouring the `(0, 1]` contract;
    // for other fractions the difference is one in 2^32.
    let dial_threshold = (dial_fraction * f64::from(u32::MAX)) as u32;

    let mut leaks = 0_u64;
    let mut origin_leaks = 0_u64;

    for _ in 0..trials {
        let mut neighboured: Vec<bool> = Vec::new();
        let trace = super::stem::walk_stem_observing(params, embargo, rng, |_pos, _t, rng| {
            let mark = inbound_observes && (rng.next_u64() as u32) <= dial_threshold;
            neighboured.push(mark);
        });
        neighboured.truncate(trace.deadlines.len());

        let mut earliest: Option<(u64, usize)> = None;
        for (i, (fire, is_n)) in trace.deadlines.iter().zip(neighboured.iter()).enumerate() {
            if *is_n && *fire < trace.disarm_ms && earliest.is_none_or(|(best, _)| *fire < best) {
                earliest = Some((*fire, i));
            }
        }
        if let Some((_, i)) = earliest {
            leaks += 1;
            if i == 0 {
                origin_leaks += 1;
            }
        }
    }

    let leak_rate = leaks as f64 / trials as f64;
    let origin_share_of_leaks = if leaks == 0 {
        0.0
    } else {
        origin_leaks as f64 / leaks as f64
    };
    PassiveNeighborLeak {
        reach,
        leak_rate,
        origin_share_of_leaks,
    }
}
