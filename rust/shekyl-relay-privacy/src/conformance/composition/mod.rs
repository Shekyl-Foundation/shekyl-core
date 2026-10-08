// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-class outbound graph and the one originated-stem walk
//! (`DAEMON_RELAY_PRIVACY.md` §95).
//!
//! Each node initiates `h` hidden edges and `c` clearnet edges, except the
//! leading [`Mix::clearnet_only`] nodes, which initiate no hidden session.
//! [`walk_originated`] is the stem the epoch tally and the first-spy
//! estimators both fold. Stem length comes from [`super::walk_stem`]. A hop
//! onto a node that already forwarded this stem is fluff in the live pool,
//! so the walk stops without recording that delivery. Which peer carries
//! the stem is [`crate::stem_map::StemMap`]. [`Routing::HiddenStemSlot`]
//! pins the local source on a hidden stem slot, so that slot also carries
//! relayed traffic. [`Routing::HiddenOwnEdge`] draws the local source
//! outside the map.
//!
//! Fluff first passage is [`super::simulate_fluff_return_classed`] on
//! [`TwoClassGraph::fluff_hops`]. [`FloodReach`] chooses whether the
//! receiver relays back on the same link. The ruled §95.3 sweep passes
//! [`FloodReach::OutboundOnly`]. [`FloodReach::EveryPeer`] is production
//! fluff, kept for the §96 item 2 re-derivation.
//!
//! Spy folds live in [`first_spy`]. Hidden-pool capture, which never builds
//! this graph, lives in [`capture`].
//!
//! `p_h` is the spy share among onion-publishing nodes. It is not the fluff
//! probability. The fluff probability stays `q` on
//! [`crate::params::DandelionParams`].

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::inherited::FLUFF_AVERAGE_IN_QUARTER_SECS;
use crate::params::{DandelionParams, StemGraph, P2P_DEFAULT_OUT_PEERS};
use crate::rng::{bounded_uniform, RelayRng};
use crate::schedule::{DelayFamily, EmbargoTimer};
use crate::stem_map::{ConnectionId, StemMap};

use super::flood::{
    converged_fluff_return_classed, simulate_fluff_return, simulate_fluff_return_classed,
    ClassedHop, Converged, ConvergenceBudget, ConvergenceRefusal, FloodParams, FloodReach,
};
use super::stem::walk_stem;
use super::util::usize_from;

mod capture;
mod first_spy;

pub use capture::{simulate_own_edge_capture, OwnEdgeCapture};
pub use first_spy::{
    clearnet_arrival_is_relayed, simulate_class_aware_first_spy, simulate_stem_first_spy,
    ClassAwareFirstSpy, OriginIdentification, SpyArm, StemFirstSpy,
};

/// A link is either an anonymity-network session or a clearnet session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkClass {
    /// Hidden-address session. Transit is the anonymity connector's.
    Hidden,
    /// Clearnet session.
    Clearnet,
}

/// One initiated outbound edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutEdge {
    /// The neighbour this node dialed.
    pub to: usize,
    /// Which connector the session sits on.
    pub class: LinkClass,
}

/// Transit, in milliseconds, for the two link classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTransit {
    /// Anonymity-connector transit.
    pub hidden_ms: u64,
    /// Clearnet transit.
    pub clearnet_ms: u64,
}

/// One fluff question on the two-class graph: who dials, how long each
/// class takes, and whether the receiver relays back.
#[derive(Debug, Clone, Copy)]
pub struct CompositionFluff {
    /// The population, including any clearnet-only prefix.
    pub mix: Mix,
    /// Transit for the two link classes.
    pub transit: LinkTransit,
    /// [`FloodReach::OutboundOnly`] is the ruled sweep.
    /// [`FloodReach::EveryPeer`] is production fluff, kept for §96 item 2.
    pub reach: FloodReach,
}
/// The sweep's population: node count, the two outbound degrees, and how
/// many nodes initiate no hidden session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mix {
    /// Nodes in the graph.
    pub nodes: usize,
    /// Hidden outbound `h` for a node that is not clearnet-only.
    pub hidden_out: usize,
    /// Clearnet outbound `c`. Every node initiates this many.
    pub clearnet_out: usize,
    /// Fraction of nodes that publish an onion.
    pub onion_fraction: f64,
    /// Leading nodes that initiate no hidden session. Zero is the uniform
    /// two-class population.
    pub clearnet_only: usize,
}

impl Mix {
    /// A uniform two-class population. No node is clearnet-only.
    #[must_use]
    pub const fn new(
        nodes: usize,
        hidden_out: usize,
        clearnet_out: usize,
        onion_fraction: f64,
    ) -> Self {
        Self {
            nodes,
            hidden_out,
            clearnet_out,
            onion_fraction,
            clearnet_only: 0,
        }
    }

    /// The first `clearnet_only` nodes initiate no hidden session.
    #[must_use]
    pub const fn with_clearnet_only(mut self, clearnet_only: usize) -> Self {
        self.clearnet_only = clearnet_only;
        self
    }
}
/// Where an originated stem is allowed to sit, and where a relay sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routing {
    /// Today's production draw. The epoch's own-edge is one hidden
    /// session, chosen outside the stem map. Relays draw from every
    /// initiated outbound session. The own-edge carries relayed traffic
    /// only when it happens to be one of the two stem slots.
    HiddenOwnEdge,
    /// Ruled 2026-10-08. One stem slot is drawn from the hidden pool,
    /// the other from every other outbound session, and the local source
    /// maps to the hidden slot. Inbound sources map as [`StemMap`] does.
    /// When every outbound session is hidden, both slots are that draw
    /// and the local source is an ordinary stem-map pin: the paper's rule.
    HiddenStemSlot,
    /// Monero's split: own transactions on hidden only, relays on
    /// clearnet only. The two-class instrument's certainty check.
    Split,
    /// The paper's single graph: every session is clearnet, and the
    /// local source is one of the stem slots.
    AllClearnet,
    /// The paper's rule on a two-class graph: both stem slots are drawn
    /// from every outbound session, and the local source is one of those
    /// slots. Hop 0 is not forced onto a hidden session.
    UniformHop0,
}

/// One node's stem map for an epoch, and where its own transactions leave.
#[derive(Debug)]
pub struct NodeMap {
    /// Stem slots and the inbound-source pins.
    pub map: StemMap,
    /// The peer this node's originated stems use. `None` when the routing
    /// has no legal first hop.
    pub local: Option<OutEdge>,
}

/// One node's initiated sessions, plus who publishes an onion.
#[derive(Debug, Clone)]
pub struct TwoClassGraph {
    /// Hidden outbound count `h` a node initiates when it is not clearnet-only.
    pub hidden_out: usize,
    /// Clearnet outbound count `c` each node initiated.
    pub clearnet_out: usize,
    /// `publishes[i]` is whether node `i` is an onion candidate.
    pub publishes: Vec<bool>,
    /// Initiated outbound only. Fluff's reciprocal lives in [`Self::fluff_hops`].
    pub initiated: Vec<Vec<OutEdge>>,
}

impl TwoClassGraph {
    /// Node count.
    #[must_use]
    pub fn nodes(&self) -> usize {
        self.initiated.len()
    }

    /// `h / (h + c)`, or 0 when the node has no outbound.
    #[must_use]
    pub fn hidden_share(&self) -> f64 {
        let total = self.hidden_out + self.clearnet_out;
        if total == 0 {
            0.0
        } else {
            self.hidden_out as f64 / total as f64
        }
    }

    /// Adjacency for `reach`. [`FloodReach::EveryPeer`] adds the receiver's
    /// relay back on the same link. [`FloodReach::OutboundOnly`] does not.
    /// The transit stays the initiator's class either way.
    #[must_use]
    pub fn fluff_hops(
        &self,
        hidden_transit_ms: u64,
        clearnet_transit_ms: u64,
        reach: FloodReach,
    ) -> Vec<Vec<ClassedHop>> {
        let reciprocal = matches!(reach, FloodReach::EveryPeer);
        self.fluff_edges(hidden_transit_ms, clearnet_transit_ms, reciprocal)
    }

    fn fluff_edges(
        &self,
        hidden_transit_ms: u64,
        clearnet_transit_ms: u64,
        reciprocal: bool,
    ) -> Vec<Vec<ClassedHop>> {
        let n = self.nodes();
        let mut edges = vec![Vec::new(); n];
        for (from, row) in self.initiated.iter().enumerate() {
            for edge in row {
                let transit_ms = match edge.class {
                    LinkClass::Hidden => hidden_transit_ms,
                    LinkClass::Clearnet => clearnet_transit_ms,
                };
                edges[from].push(ClassedHop {
                    to: edge.to,
                    transit_ms,
                });
                if reciprocal {
                    edges[edge.to].push(ClassedHop {
                        to: from,
                        transit_ms,
                    });
                }
            }
        }
        edges
    }

    /// Whether this node initiated a hidden session.
    #[must_use]
    pub fn has_hidden_outbound(&self, node: usize) -> bool {
        self.initiated[node]
            .iter()
            .any(|edge| edge.class == LinkClass::Hidden)
    }
}

/// Hidden in-degree of onion publishers.
///
/// The default inbound cap is unset, so these thresholds are reference
/// marks for the tail, not protocol refusals. `above_*` is the fraction
/// of publishers whose hidden in-degree exceeds the mark.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InboundLoad {
    /// Publishers in the draw.
    pub publishers: usize,
    /// Mean hidden in-degree among publishers.
    pub mean: f64,
    /// Median hidden in-degree among publishers.
    pub p50: usize,
    /// 90th percentile hidden in-degree among publishers.
    pub p90: usize,
    /// Maximum hidden in-degree among publishers.
    pub max: usize,
    /// Fraction of publishers above the first tail mark.
    pub above_12: f64,
    /// Fraction of publishers above the second tail mark.
    pub above_24: f64,
    /// Fraction of publishers above the third tail mark.
    pub above_64: f64,
}

/// Tail marks for [`InboundLoad`]. Not a protocol cap: the inbound cap is unset.
const INBOUND_TAIL_MARK_LO: usize = 12;
const INBOUND_TAIL_MARK_MID: usize = 24;
const INBOUND_TAIL_MARK_HI: usize = 64;

/// One graph's hidden in-degree distribution on publishers.
///
/// # Panics
///
/// Panics if nobody publishes.
#[must_use]
pub fn hidden_inbound_load(graph: &TwoClassGraph) -> InboundLoad {
    let n = graph.nodes();
    let mut inbound = vec![0_usize; n];
    for row in &graph.initiated {
        for edge in row {
            if edge.class == LinkClass::Hidden {
                inbound[edge.to] += 1;
            }
        }
    }
    let mut degrees: Vec<usize> = inbound
        .iter()
        .enumerate()
        .filter(|(i, _)| graph.publishes[*i])
        .map(|(_, degree)| *degree)
        .collect();
    assert!(!degrees.is_empty(), "inbound load needs a publisher");
    degrees.sort_unstable();
    let publishers = degrees.len();
    let mean = degrees.iter().sum::<usize>() as f64 / publishers as f64;
    let at =
        |quantile: f64| degrees[(((publishers as f64) * quantile) as usize).min(publishers - 1)];
    let frac = |mark: usize| {
        degrees.iter().filter(|degree| **degree > mark).count() as f64 / publishers as f64
    };
    InboundLoad {
        publishers,
        mean,
        p50: at(0.50),
        p90: at(0.90),
        max: *degrees.last().expect("the publisher list was non-empty"),
        above_12: frac(INBOUND_TAIL_MARK_LO),
        above_24: frac(INBOUND_TAIL_MARK_MID),
        above_64: frac(INBOUND_TAIL_MARK_HI),
    }
}

/// Build the two-class graph described by `mix`.
///
/// Publishers are the first `round(f · nodes)` nodes, at least one when
/// `f > 0`, so the onion pool's size is the fraction and not a second
/// draw. Hidden edges land only on publishers. Clearnet edges land on
/// any other node. The first [`Mix::clearnet_only`] nodes initiate no
/// hidden session; every other node initiates `h`.
///
/// # Panics
///
/// Panics if `nodes < 2`, `clearnet_only` exceeds `nodes`, a degree
/// exceeds the nodes it can reach, or `h > 0` while fewer than `h + 1`
/// nodes publish.
pub fn build_two_class<R: RelayRng + ?Sized>(mix: Mix, rng: &mut R) -> TwoClassGraph {
    let Mix {
        nodes,
        hidden_out,
        clearnet_out,
        onion_fraction,
        clearnet_only,
    } = mix;
    assert!(nodes >= 2, "a composition graph needs two nodes");
    assert!(
        clearnet_only <= nodes,
        "clearnet-only count {clearnet_only} exceeds {nodes} nodes"
    );
    assert!(
        (0.0..=1.0).contains(&onion_fraction),
        "onion fraction must be in [0, 1]"
    );
    let publishers = if onion_fraction == 0.0 {
        0
    } else {
        ((onion_fraction * nodes as f64).round() as usize).clamp(1, nodes)
    };
    assert!(
        hidden_out == 0 || publishers > hidden_out,
        "hidden degree {hidden_out} needs at least {} onion publishers, have {publishers}",
        hidden_out + 1
    );
    assert!(
        hidden_out + clearnet_out <= nodes - 1,
        "outbound {} exceeds the {} other nodes",
        hidden_out + clearnet_out,
        nodes - 1
    );
    let publishes = (0..nodes).map(|i| i < publishers).collect::<Vec<_>>();
    let publisher_idx: Vec<usize> = (0..publishers).collect();
    let mut initiated = Vec::with_capacity(nodes);
    for node in 0..nodes {
        let hidden_degree = if node < clearnet_only { 0 } else { hidden_out };
        let mut row = Vec::with_capacity(hidden_degree + clearnet_out);
        let hidden_candidates: Vec<usize> = publisher_idx
            .iter()
            .copied()
            .filter(|&p| p != node)
            .collect();
        for to in pick_distinct(rng, &hidden_candidates, hidden_degree) {
            row.push(OutEdge {
                to,
                class: LinkClass::Hidden,
            });
        }
        let clear_candidates: Vec<usize> = (0..nodes)
            .filter(|&p| p != node && !row.iter().any(|e| e.to == p))
            .collect();
        for to in pick_distinct(rng, &clear_candidates, clearnet_out) {
            row.push(OutEdge {
                to,
                class: LinkClass::Clearnet,
            });
        }
        initiated.push(row);
    }
    TwoClassGraph {
        hidden_out,
        clearnet_out,
        publishes,
        initiated,
    }
}

fn pick_distinct<R: RelayRng + ?Sized>(rng: &mut R, candidates: &[usize], k: usize) -> Vec<usize> {
    assert!(
        k <= candidates.len(),
        "cannot pick {k} distinct peers from {}",
        candidates.len()
    );
    let mut pool = candidates.to_vec();
    let mut out = Vec::with_capacity(k);
    for _ in 0..k {
        let pick = usize_from(bounded_uniform_len(rng, pool.len()));
        out.push(pool.swap_remove(pick));
    }
    out
}

pub(crate) fn bounded_uniform_len<R: RelayRng + ?Sized>(rng: &mut R, len: usize) -> u64 {
    assert!(len > 0, "a uniform index needs a non-empty pool");
    bounded_uniform(rng, (len - 1) as u64)
}

pub(crate) fn peer_id(node: usize) -> ConnectionId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&(node as u64).to_le_bytes());
    ConnectionId::from_bytes(bytes)
}

pub(crate) fn node_of(id: ConnectionId) -> usize {
    let mut buf = [0_u8; 8];
    buf.copy_from_slice(&id.as_bytes()[..8]);
    usize_from(u64::from_le_bytes(buf))
}

fn edges_of(row: &[OutEdge], class: Option<LinkClass>) -> Vec<OutEdge> {
    row.iter()
        .copied()
        .filter(|e| match class {
            None => true,
            Some(c) => e.class == c,
        })
        .collect()
}

fn map_over<R: RelayRng + ?Sized>(edges: &[OutEdge], rng: &mut R) -> StemMap {
    if edges.is_empty() {
        return StemMap::empty();
    }
    let ids: Vec<ConnectionId> = edges.iter().map(|e| peer_id(e.to)).collect();
    let width = StemGraph::QuasiFourRegular.stem_count().min(ids.len());
    StemMap::new(ids, width, rng)
}

fn pick_edge<R: RelayRng + ?Sized>(rng: &mut R, edges: &[OutEdge]) -> Option<OutEdge> {
    if edges.is_empty() {
        return None;
    }
    let index = usize_from(bounded_uniform_len(rng, edges.len()));
    Some(edges[index])
}

fn edge_to(row: &[OutEdge], to: usize) -> Option<OutEdge> {
    row.iter().copied().find(|edge| edge.to == to)
}

/// Build each node's epoch map.
///
/// [`Routing::HiddenStemSlot`] with a mixed pool draws one slot from the
/// hidden sessions and one from the rest, then pins the local source on
/// the hidden slot. When every outbound session is hidden, the map is the
/// ordinary two-slot draw and the local source is [`StemMap::stem_for`]
/// of `None`. [`Routing::HiddenOwnEdge`] leaves that pin outside the map.
pub fn build_node_maps<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    routing: Routing,
    rng: &mut R,
) -> Vec<NodeMap> {
    graph
        .initiated
        .iter()
        .map(|row| node_map(row, routing, rng))
        .collect()
}

fn node_map<R: RelayRng + ?Sized>(row: &[OutEdge], routing: Routing, rng: &mut R) -> NodeMap {
    let hidden = edges_of(row, Some(LinkClass::Hidden));
    let clear = edges_of(row, Some(LinkClass::Clearnet));
    let all = edges_of(row, None);
    match routing {
        Routing::HiddenOwnEdge => NodeMap {
            map: map_over(&all, rng),
            local: pick_edge(rng, &hidden),
        },
        Routing::Split => NodeMap {
            map: map_over(&clear, rng),
            local: pick_edge(rng, &hidden),
        },
        Routing::AllClearnet => paper_map(row, &clear, rng),
        Routing::UniformHop0 => paper_map(row, &all, rng),
        Routing::HiddenStemSlot => {
            if hidden.is_empty() || hidden.len() == all.len() {
                let pool = if hidden.is_empty() { &all } else { &hidden };
                paper_map(row, pool, rng)
            } else {
                mixed_hidden_slot(row, &hidden, rng)
            }
        }
    }
}

/// The paper's rule: two slots from `pool`, local source pinned by the map.
fn paper_map<R: RelayRng + ?Sized>(row: &[OutEdge], pool: &[OutEdge], rng: &mut R) -> NodeMap {
    let mut map = map_over(pool, rng);
    let local = map
        .stem_for(None, rng)
        .and_then(|id| edge_to(row, node_of(id)));
    NodeMap { map, local }
}

/// One hidden slot, one other outbound slot, local source on the hidden slot.
fn mixed_hidden_slot<R: RelayRng + ?Sized>(
    row: &[OutEdge],
    hidden: &[OutEdge],
    rng: &mut R,
) -> NodeMap {
    let local_edge = pick_edge(rng, hidden).expect("the hidden pool was non-empty");
    let rest: Vec<ConnectionId> = row
        .iter()
        .filter(|edge| edge.to != local_edge.to)
        .map(|edge| peer_id(edge.to))
        .collect();
    let mut slots = vec![peer_id(local_edge.to)];
    if !rest.is_empty() {
        let index = usize_from(bounded_uniform_len(rng, rest.len()));
        slots.push(rest[index]);
    }
    let width = slots.len();
    let mut map = StemMap::new(slots, width, rng);
    let hidden_id = peer_id(local_edge.to);
    let pinned = map.stem_for_among(None, &[hidden_id], rng);
    debug_assert_eq!(pinned, Some(hidden_id));
    NodeMap {
        map,
        local: Some(local_edge),
    }
}

/// Relay `source`'s stem through this node's map, onto one of its outbound edges.
fn relay_edge<R: RelayRng + ?Sized>(
    state: &mut NodeMap,
    row: &[OutEdge],
    source: usize,
    rng: &mut R,
) -> Option<OutEdge> {
    let id = state.map.stem_for(Some(peer_id(source)), rng)?;
    edge_to(row, node_of(id))
}

/// Relay hops [`walk_stem`] allows after the origin's own-edge.
///
/// The hop count is private, so a caller cannot substitute its own length.
/// The caller draws it where the map's lifetime requires: an epoch draws
/// one budget per stem after the maps are pinned, and a first-spy trial
/// draws the budget before it builds that trial's maps.
#[derive(Debug, Clone, Copy)]
pub struct StemRelayBudget {
    extra: usize,
}

impl StemRelayBudget {
    /// The relay hops of one [`walk_stem`] draw.
    #[must_use]
    pub fn from_walk<R: RelayRng + ?Sized>(
        params: &DandelionParams,
        embargo: &EmbargoTimer,
        rng: &mut R,
    ) -> Self {
        Self {
            extra: walk_stem(params, embargo, rng)
                .stem_hops()
                .saturating_sub(1),
        }
    }
}

/// One originated stem after the duplicate cut.
///
/// [`Self::relayed`] is every stem hop after the origin's own-edge.
/// A hop onto a node that already forwarded is absent: that delivery is
/// fluff, and the walk stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginatedStem {
    /// The origin's first hop. `None` when the routing has no legal pin.
    pub own_edge: Option<OutEdge>,
    /// Stem relays after the first hop, in order.
    pub relayed: Vec<OutEdge>,
    /// Nodes on the stem, origin first. A revisited node is not appended.
    pub path: Vec<usize>,
}

/// Walk one originated stem on `maps`, for at most `budget` relay hops.
///
/// The caller owns the maps and the budget. An epoch keeps the maps so
/// every stem in the epoch pins on the same slots, and draws a new budget
/// per stem. A first-spy trial draws the budget, then builds the maps for
/// that transaction. Both call this function, so they stop on the same
/// revisit: a hop onto a node that already forwarded is not recorded.
///
/// # Panics
///
/// Panics if `maps` is not one entry per node, or `origin` is out of range.
pub fn walk_originated<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    maps: &mut [NodeMap],
    origin: usize,
    budget: StemRelayBudget,
    rng: &mut R,
) -> OriginatedStem {
    assert!(
        maps.len() == graph.nodes(),
        "stem maps must cover every node"
    );
    assert!(origin < graph.nodes(), "origin {origin} is not a node");
    let extra = budget.extra;
    let Some(own) = maps[origin].local else {
        return OriginatedStem {
            own_edge: None,
            relayed: Vec::new(),
            path: vec![origin],
        };
    };
    let mut path = vec![origin, own.to];
    let mut relayed = Vec::with_capacity(extra);
    let mut at = own.to;
    let mut prev = origin;
    // A node forwards this stem once. The live pool switches a duplicate
    // to fluff, so a hop onto a node that already forwarded is not a stem
    // delivery and the walk stops.
    let mut forwarded = vec![false; graph.nodes()];
    forwarded[origin] = true;
    for _ in 0..extra {
        if forwarded[at] {
            break;
        }
        forwarded[at] = true;
        let Some(hop) = relay_edge(&mut maps[at], &graph.initiated[at], prev, rng) else {
            break;
        };
        if forwarded[hop.to] {
            break;
        }
        relayed.push(hop);
        prev = at;
        at = hop.to;
        path.push(at);
    }
    OriginatedStem {
        own_edge: Some(own),
        relayed,
        path,
    }
}

/// Node count of the shipped degree-12 reference the 3250 ms reading used.
pub const SHIPPED_REFERENCE_NODES: usize = 512;

/// p90 first passage of the shipped uniform graph.
///
/// Degree is [`P2P_DEFAULT_OUT_PEERS`]. The flush is the inbound
/// quarter-second draw, geometric, the same flush that reading used.
/// `reach` is the caller's: the §95.3 calibration passes
/// [`FloodReach::OutboundOnly`] so a cell does not mix reach with transit.
#[must_use]
pub fn shipped_graph_p90<R: RelayRng + ?Sized>(
    transit_ms: u64,
    reach: FloodReach,
    trials: usize,
    rng: &mut R,
) -> u64 {
    simulate_fluff_return(
        FloodParams {
            peers: P2P_DEFAULT_OUT_PEERS as usize,
            nodes: SHIPPED_REFERENCE_NODES,
            reach,
            transit_ms,
        },
        FLUFF_AVERAGE_IN_QUARTER_SECS,
        DelayFamily::Geometric,
        trials,
        rng,
    )
    .p90_ms
}

/// Transit-free p90 of the shipped outbound-only degree-12 graph.
///
/// This is the graph `fluff_return_ms = 3250` was read from.
#[must_use]
pub fn shipped_fluff_reference<R: RelayRng + ?Sized>(trials: usize, rng: &mut R) -> u64 {
    shipped_graph_p90(0, FloodReach::OutboundOnly, trials, rng)
}

/// Adjacency for one redraw of `question`.
fn hops_for<R: RelayRng + ?Sized>(question: CompositionFluff, rng: &mut R) -> Vec<Vec<ClassedHop>> {
    let CompositionFluff {
        mix,
        transit,
        reach,
    } = question;
    build_two_class(mix, rng).fluff_hops(transit.hidden_ms, transit.clearnet_ms, reach)
}

/// p90 on one composition. The graph is redrawn each trial.
///
/// The flush matches [`shipped_graph_p90`]. An unconverged reading goes
/// through [`converged_composition_fluff`].
#[must_use]
pub fn composition_fluff_p90<R: RelayRng + ?Sized>(
    question: CompositionFluff,
    trials: usize,
    rng: &mut R,
) -> u64 {
    simulate_fluff_return_classed(
        question.mix.nodes,
        FLUFF_AVERAGE_IN_QUARTER_SECS,
        DelayFamily::Geometric,
        trials,
        rng,
        |rng| hops_for(question, rng),
    )
    .p90_ms
}

/// p90 on one fixed graph, same flush as [`composition_fluff_p90`].
///
/// A comparison that holds the edges still and changes only transit uses
/// this. An ensemble redraws through [`composition_fluff_p90`].
#[must_use]
pub fn graph_fluff_p90<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    transit: LinkTransit,
    reach: FloodReach,
    trials: usize,
    rng: &mut R,
) -> u64 {
    let hops = graph.fluff_hops(transit.hidden_ms, transit.clearnet_ms, reach);
    // The classed flood asks for a fresh edge list each trial. The graph is
    // fixed, so every trial is this same adjacency.
    simulate_fluff_return_classed(
        graph.nodes(),
        FLUFF_AVERAGE_IN_QUARTER_SECS,
        DelayFamily::Geometric,
        trials,
        rng,
        |_| hops.clone(),
    )
    .p90_ms
}

/// p90 fluff return on the two-class graph, or a refusal.
///
/// `question` names the population, the two transits, and the reach. The
/// ladder is [`converged_fluff_return_classed`].
pub fn converged_composition_fluff<R: RelayRng>(
    question: CompositionFluff,
    mean_quarter_secs: u32,
    family: DelayFamily,
    seeds: &[u64],
    budget: ConvergenceBudget,
    mut make_rng: impl FnMut(u64) -> R,
) -> Result<Converged, ConvergenceRefusal> {
    converged_fluff_return_classed(
        question.mix.nodes,
        mean_quarter_secs,
        family,
        seeds,
        budget,
        &mut make_rng,
        |rng| hops_for(question, rng),
    )
}
