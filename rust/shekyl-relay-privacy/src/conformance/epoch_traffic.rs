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
//! module keeps one [`crate::stem_map::StemMap`] per node, has every node
//! originate once, and walks each stem with [`walk_stem`].
//!
//! One originated transaction per node per epoch. A common rate cancels in
//! the posterior, because relayed mass is other nodes' stems at the same rate.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::DandelionParams;
use crate::rng::{bounded_uniform, RelayRng};
use crate::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};

use super::composition::{
    build_node_maps, build_two_class, relay_edge, LinkClass, Mix, NodeMap, Routing, TwoClassGraph,
};
use super::stem::walk_stem;
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
    /// Relayed forwards per originated stem, from [`walk_stem`].
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

fn run_epoch<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    routing: Routing,
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    running: &mut Running,
    rng: &mut R,
) {
    let n = graph.nodes();
    let mut maps: Vec<NodeMap> = build_node_maps(graph, routing, rng);
    let inbound = inbound_degrees(graph);
    let local_to: Vec<Option<usize>> = maps
        .iter()
        .map(|node| node.local.map(|edge| edge.to))
        .collect();
    let mut own_originated = vec![0_u64; n];
    let mut own_relayed = vec![0_u64; n];

    for origin in shuffled(n, rng) {
        let Some(first) = maps[origin].local else {
            continue;
        };
        own_originated[origin] += 1;
        running.originated_txs += 1;
        note_class(running, first.class, true);
        let extra = walk_stem(params, embargo, rng)
            .stem_hops()
            .saturating_sub(1);
        let mut at = first.to;
        let mut prev = origin;
        for _ in 0..extra {
            let Some(hop) = relay_edge(&mut maps[at], &graph.initiated[at], prev, rng) else {
                break;
            };
            running.relayed_forwards += 1;
            note_class(running, hop.class, false);
            if local_to[at] == Some(hop.to) {
                own_relayed[at] += 1;
            }
            prev = at;
            at = hop.to;
        }
    }

    for node in 0..n {
        if maps[node].local.is_some() {
            fold_sender(
                running,
                inbound[node],
                own_originated[node],
                own_relayed[node],
            );
        }
    }
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
        let graph = build_two_class(
            mix.nodes,
            mix.hidden_out,
            mix.clearnet_out,
            mix.onion_fraction,
            rng,
        );
        run_epoch(&graph, routing, &params, &embargo, &mut running, rng);
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
        run_epoch(graph, routing, &params, &embargo, &mut running, rng);
    }
    running.finish()
}

/// The shipped fluff reference: 512 nodes, outbound-only, transit-free, degree 12.
///
/// This is the graph `fluff_return_ms = 3250` was read from, run through
/// [`super::simulate_fluff_return`], the same shortest path the classed flood
/// uses, with one transit on every edge. A composition's p90 divided by this reading
/// is the ratio to that fail-safe input. It is not a new constant.
#[must_use]
pub fn shipped_fluff_reference<R: RelayRng + ?Sized>(trials: usize, rng: &mut R) -> u64 {
    use super::flood::{simulate_fluff_return, FloodParams, FloodReach};
    use crate::schedule::DelayFamily;

    simulate_fluff_return(
        FloodParams {
            peers: 12,
            nodes: 512,
            reach: FloodReach::OutboundOnly,
            transit_ms: 0,
        },
        20,
        DelayFamily::Geometric,
        trials,
        rng,
    )
    .p90_ms
}
