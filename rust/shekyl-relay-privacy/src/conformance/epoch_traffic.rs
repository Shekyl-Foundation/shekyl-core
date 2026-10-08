// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One epoch of stem traffic on the two-class graph.
//!
//! The attacker on P's own-edge counts every stem P sends on that link
//! while the epoch's map is pinned: P's originated transactions, and every
//! stem P relays onto the same peer. A single-transaction walk that counts
//! a relay only when the path revisits the pin does not see that. This
//! module keeps one [`crate::stem_map::StemMap`] per node and folds
//! [`super::composition::walk_originated`], the same walk the first-spy
//! estimators fold. Stem length comes from [`super::walk_stem`]. A hop
//! onto a node that already forwarded this stem is fluff in the live
//! pool, so it is not a delivery here either.
//!
//! One originated transaction per node per epoch, unless the caller
//! passes another rate. A common rate cancels in the posterior, because
//! relayed mass is other nodes' stems at the same rate.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::DandelionParams;
use crate::rng::{bounded_uniform, RelayRng};
use crate::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};

use super::composition::{
    build_node_maps, build_two_class, walk_originated, LinkClass, Mix, OriginatedStem, Routing,
    StemRelayBudget, TwoClassGraph,
};
use super::util::usize_from;

/// Own-edge posterior for senders of one inbound degree.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InboundPosterior {
    /// How many peers initiated an edge to the sender.
    pub inbound: usize,
    /// Sender-epochs in this bin.
    pub senders: u64,
    /// `P(originated | arrival on that sender's own-edge)`.
    pub posterior: f64,
    /// Originated stems those senders put on the own-edge.
    pub originated: u64,
    /// Relayed stems those senders put on the own-edge.
    pub relayed: u64,
}

/// Epoch counts. Posteriors are pooled deliveries, not a mean of ratios.
#[derive(Debug, Clone, PartialEq)]
pub struct EpochTraffic {
    /// `P(originated | the sender's own-edge)`, every sender.
    pub posterior_own_edge: f64,
    /// The same, excluding senders with inbound degree 0.
    pub posterior_own_edge_with_inbound: f64,
    /// `P(originated | a hidden-edge delivery)`.
    pub posterior_hidden: f64,
    /// `P(originated | a clearnet-edge delivery)`.
    pub posterior_clearnet: f64,
    /// Senders with no inbound edge. They relay nothing.
    pub posterior_dial_only: f64,
    /// Sender-epochs with inbound degree 0.
    pub dial_only_senders: u64,
    /// Originated stems those dial-only senders put on their own-edge.
    pub dial_only_originated: u64,
    /// Relayed stems on those same edges. Zero when the graph is as built.
    pub dial_only_relayed: u64,
    /// Relayed deliveries on own-edges, per originated own-edge delivery.
    pub own_edge_relayed_per_originated: f64,
    /// Fraction of own-edges that carried at least one relayed stem.
    pub own_edges_carrying_relayed: f64,
    /// Relayed forwards per originated stem. Length is [`super::walk_stem`];
    /// a closing hop the pool would fluff is not a forward.
    pub relayed_per_originated: f64,
    /// Own-edge posterior by the sender's inbound degree. Empty degrees omitted.
    pub by_inbound: Vec<InboundPosterior>,
}

#[derive(Clone, Copy, Default)]
struct Counts {
    originated: u64,
    relayed: u64,
    senders: u64,
    edges_with_relayed: u64,
}

impl Counts {
    fn add_send(&mut self, originated: bool) {
        if originated {
            self.originated += 1;
        } else {
            self.relayed += 1;
        }
    }

    fn posterior(self) -> f64 {
        let total = self.originated + self.relayed;
        if total == 0 {
            0.0
        } else {
            self.originated as f64 / total as f64
        }
    }
}

struct Running {
    own: Counts,
    with_inbound: Counts,
    hidden: Counts,
    clearnet: Counts,
    dial_only: Counts,
    by_inbound: Vec<Counts>,
    originated_txs: u64,
    relayed_forwards: u64,
}

impl Running {
    fn new() -> Self {
        Self {
            own: Counts::default(),
            with_inbound: Counts::default(),
            hidden: Counts::default(),
            clearnet: Counts::default(),
            dial_only: Counts::default(),
            by_inbound: Vec::new(),
            originated_txs: 0,
            relayed_forwards: 0,
        }
    }

    fn finish(self) -> EpochTraffic {
        let by_inbound = self
            .by_inbound
            .iter()
            .enumerate()
            .filter(|(_, bin)| bin.senders > 0)
            .map(|(inbound, bin)| InboundPosterior {
                inbound,
                senders: bin.senders,
                posterior: bin.posterior(),
                originated: bin.originated,
                relayed: bin.relayed,
            })
            .collect();
        let own_edges = self.own.senders;
        EpochTraffic {
            posterior_own_edge: self.own.posterior(),
            posterior_own_edge_with_inbound: self.with_inbound.posterior(),
            posterior_hidden: self.hidden.posterior(),
            posterior_clearnet: self.clearnet.posterior(),
            posterior_dial_only: self.dial_only.posterior(),
            dial_only_senders: self.dial_only.senders,
            dial_only_originated: self.dial_only.originated,
            dial_only_relayed: self.dial_only.relayed,
            own_edge_relayed_per_originated: if self.own.originated == 0 {
                0.0
            } else {
                self.own.relayed as f64 / self.own.originated as f64
            },
            own_edges_carrying_relayed: if own_edges == 0 {
                0.0
            } else {
                self.own.edges_with_relayed as f64 / own_edges as f64
            },
            relayed_per_originated: if self.originated_txs == 0 {
                0.0
            } else {
                self.relayed_forwards as f64 / self.originated_txs as f64
            },
            by_inbound,
        }
    }
}

fn inbound_degrees(graph: &TwoClassGraph) -> Vec<usize> {
    let mut degree = vec![0_usize; graph.nodes()];
    for row in &graph.initiated {
        for edge in row {
            degree[edge.to] += 1;
        }
    }
    degree
}

fn shuffled<R: RelayRng + ?Sized>(n: usize, rng: &mut R) -> Vec<usize> {
    let mut nodes: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let pick = usize_from(bounded_uniform(rng, i as u64));
        nodes.swap(i, pick);
    }
    nodes
}

fn note_class(running: &mut Running, class: LinkClass, originated: bool) {
    match class {
        LinkClass::Hidden => running.hidden.add_send(originated),
        LinkClass::Clearnet => running.clearnet.add_send(originated),
    }
}

fn fold_sender(running: &mut Running, inbound: usize, originated: u64, relayed: u64) {
    if originated == 0 && relayed == 0 {
        return;
    }
    let bin = {
        if running.by_inbound.len() <= inbound {
            running.by_inbound.resize(inbound + 1, Counts::default());
        }
        &mut running.by_inbound[inbound]
    };
    bin.originated += originated;
    bin.relayed += relayed;
    bin.senders += 1;
    running.own.originated += originated;
    running.own.relayed += relayed;
    running.own.senders += 1;
    if relayed > 0 {
        running.own.edges_with_relayed += 1;
        bin.edges_with_relayed += 1;
    }
    if inbound == 0 {
        running.dial_only.originated += originated;
        running.dial_only.relayed += relayed;
        running.dial_only.senders += 1;
    } else {
        running.with_inbound.originated += originated;
        running.with_inbound.relayed += relayed;
        running.with_inbound.senders += 1;
    }
}

/// Own-edge deliveries each sender put on its pin during one epoch.
struct SenderDeliveries {
    originated: Vec<u64>,
    relayed: Vec<u64>,
}

fn record_stem(
    stem: &OriginatedStem,
    local_to: &[Option<usize>],
    running: &mut Running,
    senders: &mut SenderDeliveries,
) {
    let Some(own) = stem.own_edge else {
        return;
    };
    // `path` is `[origin, own.to, …]`, one longer than `relayed` at each end.
    debug_assert_eq!(stem.path.len(), stem.relayed.len() + 2);
    let origin = stem.path[0];
    senders.originated[origin] += 1;
    running.originated_txs += 1;
    note_class(running, own.class, true);
    for (hop_index, hop) in stem.relayed.iter().enumerate() {
        let sender = stem.path[hop_index + 1];
        running.relayed_forwards += 1;
        note_class(running, hop.class, false);
        if local_to[sender] == Some(hop.to) {
            senders.relayed[sender] += 1;
        }
    }
}

fn run_epoch<R, F>(
    graph: &TwoClassGraph,
    routing: Routing,
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    running: &mut Running,
    origin_times: F,
    rng: &mut R,
) -> SenderDeliveries
where
    R: RelayRng + ?Sized,
    F: Fn(usize) -> u32,
{
    let n = graph.nodes();
    let mut maps = build_node_maps(graph, routing, rng);
    let inbound = inbound_degrees(graph);
    let local_to: Vec<Option<usize>> = maps
        .iter()
        .map(|node| node.local.map(|edge| edge.to))
        .collect();
    let mut senders = SenderDeliveries {
        originated: vec![0; n],
        relayed: vec![0; n],
    };

    for origin in shuffled(n, rng) {
        let times = origin_times(origin);
        for _ in 0..times {
            let budget = StemRelayBudget::from_walk(params, embargo, rng);
            let stem = walk_originated(graph, &mut maps, origin, budget, rng);
            record_stem(&stem, &local_to, running, &mut senders);
        }
    }

    for node in 0..n {
        if maps[node].local.is_some() {
            fold_sender(
                running,
                inbound[node],
                senders.originated[node],
                senders.relayed[node],
            );
        }
    }
    senders
}

/// Measure [`EpochTraffic`] on `epochs` independent graphs.
///
/// Each node originates once per epoch. The stem maps are rebuilt with the
/// graph. An unconverged fluff reading is not this function's job.
///
/// # Panics
///
/// Panics if `epochs` is zero.
#[must_use]
pub fn simulate_epoch_traffic<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    epochs: usize,
    rng: &mut R,
) -> EpochTraffic {
    assert!(epochs > 0, "need at least one epoch");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut running = Running::new();
    for _ in 0..epochs {
        let graph = build_two_class(mix, rng);
        run_epoch(&graph, routing, &params, &embargo, &mut running, |_| 1, rng);
    }
    running.finish()
}

/// [`simulate_epoch_traffic`] on one fixed graph, maps rebuilt each epoch.
///
/// The graph's edges stay. A test that strips inbound to one node uses this
/// so the dial-only sender is the one it built, not a fresh draw.
///
/// # Panics
///
/// Panics if `epochs` is zero.
#[must_use]
pub fn epoch_traffic_on<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    routing: Routing,
    epochs: usize,
    rng: &mut R,
) -> EpochTraffic {
    assert!(epochs > 0, "need at least one epoch");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut running = Running::new();
    for _ in 0..epochs {
        run_epoch(graph, routing, &params, &embargo, &mut running, |_| 1, rng);
    }
    running.finish()
}

/// Own-edge posterior of one heavy originator against the other senders.
///
/// A node that originates `heavy_times` stems per epoch, while every other
/// node originates once, sits closer to posterior 1. That is the Dandelion++
/// fact: the posterior tracks the originated-to-relayed ratio on that link,
/// whatever the routing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OriginRateContrast {
    /// `P(originated | the heavy node's own-edge)`.
    pub heavy_posterior: f64,
    /// `P(originated | every other sender's own-edge)`, pooled.
    pub rest_posterior: f64,
}

/// Measure [`OriginRateContrast`]. Node 0 is the heavy originator.
///
/// # Panics
///
/// Panics if `epochs` or `heavy_times` is zero, or node 0 has no legal
/// own-edge under `routing`. The check is the stems node 0 actually
/// originated, so a routing whose pin is absent cannot report a posterior
/// of zero as if the node had sent.
#[must_use]
pub fn simulate_origin_rate_contrast<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    heavy_times: u32,
    epochs: usize,
    rng: &mut R,
) -> OriginRateContrast {
    assert!(
        epochs > 0 && heavy_times > 0,
        "need epochs and a heavy rate"
    );
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut heavy = Counts::default();
    let mut rest = Counts::default();
    for _ in 0..epochs {
        let graph = build_two_class(mix, rng);
        let mut running = Running::new();
        let senders = run_epoch(
            &graph,
            routing,
            &params,
            &embargo,
            &mut running,
            |node| if node == 0 { heavy_times } else { 1 },
            rng,
        );
        assert!(
            senders.originated[0] == u64::from(heavy_times),
            "node 0 originated {} stems in the epoch, expected {heavy_times}: \
             no legal own-edge under {routing:?}",
            senders.originated[0]
        );
        heavy.originated += senders.originated[0];
        heavy.relayed += senders.relayed[0];
        for node in 1..graph.nodes() {
            rest.originated += senders.originated[node];
            rest.relayed += senders.relayed[node];
        }
    }
    OriginRateContrast {
        heavy_posterior: heavy.posterior(),
        rest_posterior: rest.posterior(),
    }
}
