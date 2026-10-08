// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Two-class outbound composition (`DAEMON_RELAY_PRIVACY.md` §95).
//!
//! Each node initiates `h` hidden edges and `c` clearnet edges. Fluff is
//! [`FloodReach::EveryPeer`](super::FloodReach): the receiver relays back
//! on the same link, so the link's transit stays with the link. First
//! passage is [`super::simulate_fluff_return_classed`], the uniform flood's
//! shortest path. Agreement across seeds is [`super::converge_p90`], the
//! same refusal as [`super::converged_fluff_return_mixed`]. Stem length is
//! [`super::walk_stem`]. Which peer carries the stem is
//! [`crate::stem_map::StemMap`]. [`Routing::HiddenStemSlot`] puts the local
//! source on a stem slot, so that slot also carries relayed traffic.
//! [`Routing::HiddenOwnEdge`] draws the local source outside the map.
//!
//! `p_h` is the spy share among onion-publishing nodes. It is not the
//! fluff probability. The fluff probability stays `q` on
//! [`crate::params::DandelionParams`].

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::{DandelionParams, StemGraph};
use crate::rng::{bounded_uniform, RelayRng, SplitMix64};
use crate::schedule::{DelayFamily, EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};
use crate::stem_map::{ConnectionId, StemMap};

use super::flood::{
    converged_fluff_return_classed, simulate_fluff_return_classed, ClassedHop, Converged,
    ConvergenceBudget, ConvergenceRefusal,
};
use super::stem::walk_stem;
use super::util::usize_from;

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
/// The sweep's node count and the two outbound degrees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mix {
    /// Nodes in the graph.
    pub nodes: usize,
    /// Hidden outbound `h`.
    pub hidden_out: usize,
    /// Clearnet outbound `c`.
    pub clearnet_out: usize,
    /// Fraction of nodes that publish an onion.
    pub onion_fraction: f64,
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
    /// Hidden outbound count `h` each node initiated.
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

    /// EveryPeer adjacency: each initiated edge is also relayed by its target,
    /// and the transit stays the initiator's class.
    #[must_use]
    pub fn fluff_hops(
        &self,
        hidden_transit_ms: u64,
        clearnet_transit_ms: u64,
    ) -> Vec<Vec<ClassedHop>> {
        self.fluff_edges(hidden_transit_ms, clearnet_transit_ms, true)
    }

    /// [`FloodReach::OutboundOnly`](super::FloodReach) adjacency: no reciprocal.
    ///
    /// The calibration holds this reach fixed, including on the shipped
    /// degree-12 graph, so a cell does not mix reach with transit.
    #[must_use]
    pub fn outbound_only_fluff_hops(
        &self,
        hidden_transit_ms: u64,
        clearnet_transit_ms: u64,
    ) -> Vec<Vec<ClassedHop>> {
        self.fluff_edges(hidden_transit_ms, clearnet_transit_ms, false)
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

/// Build the two-class graph.
///
/// Publishers are the first `round(f · nodes)` nodes, at least one when
/// `f > 0`, so the onion pool's size is the fraction and not a second
/// draw. Hidden edges land only on publishers. Clearnet edges land on
/// any other node.
///
/// # Panics
///
/// Panics if `nodes < 2`, a degree exceeds the nodes it can reach, or
/// `h > 0` while fewer than `h + 1` nodes publish.
pub fn build_two_class<R: RelayRng + ?Sized>(
    nodes: usize,
    hidden_out: usize,
    clearnet_out: usize,
    onion_fraction: f64,
    rng: &mut R,
) -> TwoClassGraph {
    assert!(nodes >= 2, "a composition graph needs two nodes");
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
        let mut row = Vec::with_capacity(hidden_out + clearnet_out);
        let hidden_candidates: Vec<usize> = publisher_idx
            .iter()
            .copied()
            .filter(|&p| p != node)
            .collect();
        for to in pick_distinct(rng, &hidden_candidates, hidden_out) {
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

fn bounded_uniform_len<R: RelayRng + ?Sized>(rng: &mut R, len: usize) -> u64 {
    bounded_uniform(rng, (len - 1) as u64)
}

fn peer_id(node: usize) -> ConnectionId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&(node as u64).to_le_bytes());
    ConnectionId::from_bytes(bytes)
}

fn node_of(id: ConnectionId) -> usize {
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
pub(crate) fn relay_edge<R: RelayRng + ?Sized>(
    state: &mut NodeMap,
    row: &[OutEdge],
    source: usize,
    rng: &mut R,
) -> Option<OutEdge> {
    let id = state.map.stem_for(Some(peer_id(source)), rng)?;
    edge_to(row, node_of(id))
}

/// Where one originated transaction's stem hops landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemLanding {
    /// Class of the origin's own-edge. `None` when the routing had no legal pin.
    pub own_edge: Option<LinkClass>,
    /// Classes of the relayed forwards, in hop order, with the neighbour each landed on.
    pub relayed: Vec<(LinkClass, usize)>,
    /// Nodes on the path, origin first, including the node each hop arrived at.
    pub path: Vec<usize>,
}

/// Walk one originated stem on `graph` starting at `origin`.
///
/// The maps are this one transaction's: relays pin on first use, and no
/// other node's originated traffic shares them. The attacker's count of
/// an epoch is [`super::epoch_traffic`], which keeps the maps and walks
/// every node. Stem length is [`walk_stem`].
pub fn land_originated_stem<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    origin: usize,
    routing: Routing,
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
) -> StemLanding {
    let extra = walk_stem(params, embargo, rng)
        .stem_hops()
        .saturating_sub(1);
    let mut maps = build_node_maps(graph, routing, rng);
    let Some(own) = maps[origin].local else {
        return StemLanding {
            own_edge: None,
            relayed: Vec::new(),
            path: vec![origin],
        };
    };
    let mut path = vec![origin, own.to];
    let mut relayed = Vec::with_capacity(extra);
    let mut at = own.to;
    let mut prev = origin;
    for _ in 0..extra {
        let Some(hop) = relay_edge(&mut maps[at], &graph.initiated[at], prev, rng) else {
            break;
        };
        relayed.push((hop.class, hop.to));
        prev = at;
        at = hop.to;
        path.push(at);
    }
    StemLanding {
        own_edge: Some(own.class),
        relayed,
        path,
    }
}

/// First spy along the originated stem, not along the fluff flood.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StemFirstSpy {
    /// Trials that reached a spy.
    pub observed: usize,
    /// Trials run that pinned an own-edge.
    pub pinned: usize,
    /// Among observed trials, the fraction whose first spy's predecessor is the origin.
    pub precision: f64,
    /// Fraction of pinned trials a spy sits on the path at all.
    pub recall: f64,
}

/// `p` everywhere, or `p_h = min(1, 2p)` on publishers and `p` on the rest.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpyArm {
    /// Every non-origin node is a spy with probability `p`.
    Uniform { p: f64 },
    /// Onion publishers are spies with probability `min(1, 2p)`.
    OnionBiased { p: f64 },
}

impl SpyArm {
    fn threshold(self, publishes: bool) -> f64 {
        match self {
            Self::Uniform { p } => p,
            Self::OnionBiased { p } => {
                if publishes {
                    (2.0 * p).min(1.0)
                } else {
                    p
                }
            }
        }
    }

    /// The onion-candidate spy share. A uniform arm's share is `p`.
    #[must_use]
    pub fn p_h(self) -> f64 {
        match self {
            Self::Uniform { p } => p,
            Self::OnionBiased { p } => (2.0 * p).min(1.0),
        }
    }
}

fn is_spy<R: RelayRng + ?Sized>(arm: SpyArm, publishes: bool, rng: &mut R) -> bool {
    let p = arm.threshold(publishes);
    let threshold = (p * f64::from(u32::MAX)) as u32;
    (rng.next_u64() as u32) <= threshold
}

/// Precision and recall of the first spy on the originated stem.
///
/// # Panics
///
/// Panics if `trials` is zero or `p` is outside `(0, 1]`.
#[must_use]
pub fn simulate_stem_first_spy<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    arm: SpyArm,
    trials: usize,
    rng: &mut R,
) -> StemFirstSpy {
    assert!(trials > 0, "need at least one trial");
    let p = match arm {
        SpyArm::Uniform { p } | SpyArm::OnionBiased { p } => p,
    };
    assert!(p > 0.0 && p <= 1.0, "spy fraction must be in (0, 1]");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut observed = 0_usize;
    let mut pinned = 0_usize;
    let mut correct = 0_usize;
    for _ in 0..trials {
        let graph = build_two_class(
            mix.nodes,
            mix.hidden_out,
            mix.clearnet_out,
            mix.onion_fraction,
            rng,
        );
        let landing = land_originated_stem(&graph, 0, routing, &params, &embargo, rng);
        if landing.own_edge.is_none() {
            continue;
        }
        pinned += 1;
        let mut first: Option<usize> = None;
        for (i, &node) in landing.path.iter().enumerate().skip(1) {
            if is_spy(arm, graph.publishes[node], rng) {
                first = Some(i);
                break;
            }
        }
        if let Some(i) = first {
            observed += 1;
            if landing.path[i - 1] == 0 {
                correct += 1;
            }
        }
    }
    StemFirstSpy {
        observed,
        pinned,
        precision: if observed == 0 {
            0.0
        } else {
            correct as f64 / observed as f64
        },
        recall: if pinned == 0 {
            0.0
        } else {
            observed as f64 / pinned as f64
        },
    }
}

/// A clearnet arrival from a sender that also has a hidden session is relayed.
///
/// Under [`Routing::HiddenStemSlot`] that sender's own transactions leave on
/// the hidden slot, so the clearnet edge exonerates them. It does not name
/// them as the origin, and it does not mark them clearnet-only.
#[must_use]
pub fn clearnet_arrival_is_relayed(class: LinkClass, sender_has_hidden: bool) -> bool {
    class == LinkClass::Clearnet && sender_has_hidden
}

/// One estimator's identifications of the origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OriginIdentification {
    /// Trials that pinned a first hop.
    pub pinned: usize,
    /// Trials in which the estimator named a predecessor.
    pub named: usize,
    /// Trials in which the named predecessor is the origin.
    pub named_origin: usize,
    /// `named_origin / named`.
    pub precision: f64,
    /// `named_origin / pinned`.
    pub recall: f64,
}

/// Class-blind and class-aware first spy, plus the clearnet-only mark.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassAwareFirstSpy {
    /// The predecessor of the first spy, whatever the edge class.
    pub blind: OriginIdentification,
    /// Skips a spy whose incoming edge [`clearnet_arrival_is_relayed`].
    pub aware: OriginIdentification,
    /// Clearnet deliveries on the originated stems.
    pub clearnet_arrivals: u64,
    /// Those whose sender initiated no hidden session.
    pub clearnet_sender_clearnet_only: u64,
    /// Aware names that arrived on a clearnet edge. Under `HiddenStemSlot`
    /// these senders are the clearnet-only ones.
    pub aware_clearnet_names: u64,
    /// Of those names, how many senders really had no hidden session.
    pub aware_clearnet_names_clearnet_only: u64,
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn hop_class(landing: &StemLanding, arrival: usize) -> LinkClass {
    if arrival == 1 {
        landing
            .own_edge
            .expect("a pinned path has a first-hop class")
    } else {
        landing.relayed[arrival - 2].0
    }
}

/// First-spy precision and recall with and without the link class.
///
/// The class-aware estimator does not name a predecessor reached by a
/// clearnet edge when that predecessor has a hidden session. The paper's
/// uniform hop 0 is [`Routing::UniformHop0`]: the comparison is whether
/// the class helps only once hop 0 is confined to the hidden slot.
///
/// # Panics
///
/// Panics if `trials` is zero or `p` is outside `(0, 1]`.
#[must_use]
pub fn simulate_class_aware_first_spy<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    arm: SpyArm,
    clearnet_only_nodes: usize,
    trials: usize,
    rng: &mut R,
) -> ClassAwareFirstSpy {
    assert!(trials > 0, "need at least one trial");
    let p = match arm {
        SpyArm::Uniform { p } | SpyArm::OnionBiased { p } => p,
    };
    assert!(p > 0.0 && p <= 1.0, "spy fraction must be in (0, 1]");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut pinned = 0_usize;
    let mut blind_named = 0_usize;
    let mut blind_correct = 0_usize;
    let mut aware_named = 0_usize;
    let mut aware_correct = 0_usize;
    let mut clearnet_arrivals = 0_u64;
    let mut clearnet_only = 0_u64;
    let mut aware_clearnet_names = 0_u64;
    let mut aware_clearnet_only = 0_u64;
    for _ in 0..trials {
        let mut graph = build_two_class(
            mix.nodes,
            mix.hidden_out,
            mix.clearnet_out,
            mix.onion_fraction,
            rng,
        );
        let clearnet_only_n = clearnet_only_nodes.min(graph.nodes());
        for row in graph.initiated.iter_mut().take(clearnet_only_n) {
            row.retain(|edge| edge.class != LinkClass::Hidden);
        }
        let origin = if clearnet_only_n == 0 {
            0
        } else {
            usize_from(bounded_uniform_len(rng, graph.nodes()))
        };
        let landing = land_originated_stem(&graph, origin, routing, &params, &embargo, rng);
        if landing.own_edge.is_none() {
            continue;
        }
        pinned += 1;
        let mut blind: Option<usize> = None;
        let mut aware: Option<usize> = None;
        for (i, &node) in landing.path.iter().enumerate().skip(1) {
            let sender = landing.path[i - 1];
            let class = hop_class(&landing, i);
            let hidden = graph.has_hidden_outbound(sender);
            if class == LinkClass::Clearnet {
                clearnet_arrivals += 1;
                if !hidden {
                    clearnet_only += 1;
                }
            }
            if !is_spy(arm, graph.publishes[node], rng) {
                continue;
            }
            if blind.is_none() {
                blind = Some(sender);
            }
            if aware.is_none() && !clearnet_arrival_is_relayed(class, hidden) {
                aware = Some(sender);
                if class == LinkClass::Clearnet {
                    aware_clearnet_names += 1;
                    if !hidden {
                        aware_clearnet_only += 1;
                    }
                }
            }
        }
        if let Some(sender) = blind {
            blind_named += 1;
            if sender == origin {
                blind_correct += 1;
            }
        }
        if let Some(sender) = aware {
            aware_named += 1;
            if sender == origin {
                aware_correct += 1;
            }
        }
    }
    ClassAwareFirstSpy {
        blind: OriginIdentification {
            pinned,
            named: blind_named,
            named_origin: blind_correct,
            precision: ratio(blind_correct, blind_named),
            recall: ratio(blind_correct, pinned),
        },
        aware: OriginIdentification {
            pinned,
            named: aware_named,
            named_origin: aware_correct,
            precision: ratio(aware_correct, aware_named),
            recall: ratio(aware_correct, pinned),
        },
        clearnet_arrivals,
        clearnet_sender_clearnet_only: clearnet_only,
        aware_clearnet_names,
        aware_clearnet_names_clearnet_only: aware_clearnet_only,
    }
}

/// Own-edge capture: the whole hidden pool, and the pinned session under churn.
///
/// `drawn_all_sessions` checks `p_h^h` by labelling each hidden session
/// independently. The epoch arms follow [`StemMap`]: a churn drops the
/// pinned peer and [`StemMap::update`] refills the slot, but the source
/// walks its frozen set and does not take the new peer. Across epochs the
/// map is rebuilt, which is the refill that can hand the attacker a new pin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OwnEdgeCapture {
    /// `p_h^h`.
    pub closed_form: f64,
    /// Fraction of draws in which every hidden session was a spy.
    pub drawn_all_sessions: f64,
    /// Fraction of epochs whose pinned own-edge was a spy, before churn.
    pub pin_is_spy: f64,
    /// Fraction of epochs in which the frozen walk after churn still sat on a spy.
    pub frozen_after_churn: f64,
    /// Fraction of windows in which any epoch's pin was a spy.
    pub ever_across_epochs: f64,
}

/// Measure [`OwnEdgeCapture`].
///
/// `epochs` is the window. Each epoch rebuilds the stem map. Inside an
/// epoch, `churns` peers are dropped, the dropped one first being the pin,
/// and the map is updated from the survivors plus a refill peer that is a
/// spy with probability `p_h`. The frozen pin does not move onto that refill.
///
/// # Panics
///
/// Panics if `trials` or `epochs` is zero, or `p_h` is outside `[0, 1]`.
#[must_use]
pub fn simulate_own_edge_capture<R: RelayRng + ?Sized>(
    hidden_out: usize,
    p_h: f64,
    epochs: usize,
    churns: usize,
    trials: usize,
    rng: &mut R,
) -> OwnEdgeCapture {
    assert!(trials > 0 && epochs > 0, "need trials and epochs");
    assert!((0.0..=1.0).contains(&p_h), "p_h must be in [0, 1]");
    assert!(hidden_out >= 1, "capture is over the hidden pool");
    let closed_form = p_h.powf(hidden_out as f64);
    let mut all_hits = 0_usize;
    let mut pin_hits = 0_usize;
    let mut frozen_hits = 0_usize;
    let mut ever_hits = 0_usize;
    let epoch_total = trials * epochs;
    for _ in 0..trials {
        let mut ever = false;
        for _ in 0..epochs {
            let spies: Vec<bool> = (0..hidden_out).map(|_| bernoulli_p(rng, p_h)).collect();
            if spies.iter().all(|s| *s) {
                all_hits += 1;
            }
            let ids: Vec<ConnectionId> = (0..hidden_out).map(peer_id).collect();
            let width = StemGraph::QuasiFourRegular.stem_count().min(hidden_out);
            let mut map = StemMap::new(ids.clone(), width, rng);
            let Some(pin) = map.stem_for(None, rng) else {
                continue;
            };
            let pin_node = node_of(pin);
            let pin_spy = spies[pin_node];
            if pin_spy {
                pin_hits += 1;
            }
            // Drop `churns` peers, the pin first. Update refills from whoever
            // remains. The source's next stem_for walks the frozen set.
            let mut live: Vec<ConnectionId> = ids.clone();
            live.retain(|id| *id != pin);
            for _ in 1..churns {
                if live.is_empty() {
                    break;
                }
                let drop = usize_from(bounded_uniform_len(rng, live.len()));
                live.swap_remove(drop);
            }
            // One refill peer, a new session, spy with probability p_h.
            // It is not in the frozen set, so stem_for must not return it.
            if bernoulli_p(rng, p_h) {
                live.push(peer_id(hidden_out));
            }
            let _change = map.update(live, rng);
            let after = map.stem_for(None, rng);
            let frozen_spy = after.is_some_and(|id| {
                let n = node_of(id);
                n < hidden_out && spies[n]
            });
            if frozen_spy {
                frozen_hits += 1;
            }
            if pin_spy || frozen_spy {
                ever = true;
            }
        }
        if ever {
            ever_hits += 1;
        }
    }
    OwnEdgeCapture {
        closed_form,
        drawn_all_sessions: all_hits as f64 / epoch_total as f64,
        pin_is_spy: pin_hits as f64 / epoch_total as f64,
        frozen_after_churn: frozen_hits as f64 / epoch_total as f64,
        ever_across_epochs: ever_hits as f64 / trials as f64,
    }
}

fn bernoulli_p<R: RelayRng + ?Sized>(rng: &mut R, p: f64) -> bool {
    if p <= 0.0 {
        return false;
    }
    if p >= 1.0 {
        return true;
    }
    let threshold = (p * f64::from(u32::MAX)) as u32;
    (rng.next_u64() as u32) <= threshold
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
    /// Fraction of publishers above 12.
    pub above_12: f64,
    /// Fraction of publishers above 24.
    pub above_24: f64,
    /// Fraction of publishers above 64.
    pub above_64: f64,
}

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
        .map(|(_, d)| *d)
        .collect();
    assert!(!degrees.is_empty(), "inbound load needs a publisher");
    degrees.sort_unstable();
    let publishers = degrees.len();
    let mean = degrees.iter().sum::<usize>() as f64 / publishers as f64;
    let at = |q: f64| degrees[(((publishers as f64) * q) as usize).min(publishers - 1)];
    let frac =
        |mark: usize| degrees.iter().filter(|d| **d > mark).count() as f64 / publishers as f64;
    InboundLoad {
        publishers,
        mean,
        p50: at(0.50),
        p90: at(0.90),
        max: *degrees.last().unwrap(),
        above_12: frac(12),
        above_24: frac(24),
        above_64: frac(64),
    }
}

/// p90 fluff return on the two-class EveryPeer graph, or a refusal.
///
/// Hidden hops take `transit.hidden_ms`. Clearnet hops take
/// `transit.clearnet_ms`. The ladder is [`converged_fluff_return_classed`].
pub fn converged_composition_fluff<R: RelayRng>(
    mix: Mix,
    transit: LinkTransit,
    mean_quarter_secs: u32,
    family: DelayFamily,
    seeds: &[u64],
    budget: ConvergenceBudget,
    mut make_rng: impl FnMut(u64) -> R,
) -> Result<Converged, ConvergenceRefusal> {
    converged_fluff_return_classed(
        mix.nodes,
        mean_quarter_secs,
        family,
        seeds,
        budget,
        &mut make_rng,
        |rng| {
            build_two_class(
                mix.nodes,
                mix.hidden_out,
                mix.clearnet_out,
                mix.onion_fraction,
                rng,
            )
            .fluff_hops(transit.hidden_ms, transit.clearnet_ms)
        },
    )
}

/// A single-seed fluff p90, for a comparison that does not claim a level.
#[must_use]
pub fn composition_fluff_p90(
    graph: &TwoClassGraph,
    hidden_transit_ms: u64,
    clearnet_transit_ms: u64,
    trials: usize,
    rng: &mut SplitMix64,
) -> u64 {
    let hops = graph.fluff_hops(hidden_transit_ms, clearnet_transit_ms);
    simulate_fluff_return_classed(
        graph.nodes(),
        20,
        DelayFamily::Geometric,
        trials,
        rng,
        |_| hops.clone(),
    )
    .p90_ms
}
