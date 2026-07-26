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

/// Topology inputs for the fluff-flood first-passage measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodParams {
    /// Nodes in the simulated network.
    pub nodes: usize,
    /// Fluff peers each node relays to.
    pub peers: usize,
}

impl Default for FloodParams {
    fn default() -> Self {
        Self {
            nodes: 512,
            peers: 8,
        }
    }
}

/// First-passage statistics for a fluff flood, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FloodSummary {
    pub samples: usize,
    pub mean_ms: f64,
    pub p50_ms: u64,
    pub p90_ms: u64,
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
    assert!(trials > 0, "simulation needs at least one trial");
    assert!(flood.nodes >= 2, "a flood needs at least two nodes");
    assert!(flood.peers >= 1, "a flood needs at least one peer per node");

    let table = DelayTable::build(mean_quarter_secs, family);
    let draw_ms = |rng: &mut R| -> u64 { table.draw(rng).saturating_mul(250) };

    let peers = flood.peers.min(flood.nodes - 1);
    let mut arrivals: Vec<u64> = Vec::with_capacity(trials * flood.nodes);

    for _ in 0..trials {
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); flood.nodes];
        for node in 0..flood.nodes {
            let mut initiated: Vec<usize> = Vec::with_capacity(peers);
            while initiated.len() < peers {
                let other = usize_from(bounded_uniform(rng, (flood.nodes - 1) as u64));
                if other != node && !initiated.contains(&other) {
                    initiated.push(other);
                    adjacency[node].push(other);
                    adjacency[other].push(node);
                }
            }
        }

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

        arrivals.extend(best.iter().skip(1).filter(|t| **t != u64::MAX));
    }

    arrivals.sort_unstable();
    let samples = arrivals.len();
    assert!(
        samples > 0,
        "flood reached no node — check the topology inputs"
    );
    let mean_ms = arrivals.iter().map(|t| *t as f64).sum::<f64>() / samples as f64;
    let idx = |q: f64| arrivals[(((samples as f64) * q) as usize).min(samples - 1)];

    FloodSummary {
        samples,
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

    let peers = flood.peers.min(flood.nodes - 1);
    // Scaled Bernoulli, compared with `<=` (not `<`) so `spy_fraction == 1.0`
    // (threshold == u32::MAX) marks every candidate node, per the `(0, 1]` contract.
    let spy_threshold = (spy_fraction * f64::from(u32::MAX)) as u32;

    let mut correct = 0_usize;
    let mut observed = 0_usize;
    let mut first_spy_hops_total = 0_u64;

    for _ in 0..trials {
        let mut adjacency: Vec<Vec<usize>> = vec![Vec::with_capacity(peers); flood.nodes];
        // Each node initiates `peers` *distinct* non-self edges (redraw on a
        // self-hit or a repeat), so every node's effective degree is fixed by
        // `FloodParams`, not by the collision rate. Same model as
        // `simulate_fluff_return`.
        for node in 0..flood.nodes {
            let mut initiated: Vec<usize> = Vec::with_capacity(peers);
            while initiated.len() < peers {
                let other = usize_from(bounded_uniform(rng, (flood.nodes - 1) as u64));
                if other != node && !initiated.contains(&other) {
                    initiated.push(other);
                    adjacency[node].push(other);
                    adjacency[other].push(node);
                }
            }
        }
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
