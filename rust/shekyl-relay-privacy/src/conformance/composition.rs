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
//! [`crate::stem_map::StemMap`]: the local source pins inside the hidden
//! pool, and a relay pins inside the pool its routing rule names.
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
    /// Shekyl's working direction: the epoch's own-edge is one hidden
    /// session. Relays draw from every initiated outbound session.
    HiddenOwnEdge,
    /// Monero's split: own transactions on hidden only, relays on
    /// clearnet only. The two-class instrument's certainty check.
    Split,
    /// The paper's single graph: every session is clearnet.
    AllClearnet,
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
                edges[edge.to].push(ClassedHop {
                    to: from,
                    transit_ms,
                });
            }
        }
        edges
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

/// Relayed stem forwards in one [`walk_stem`]: every armed hop except the
/// origin's. At fluff probability 20% the mean is 4.
fn relayed_forwards<R: RelayRng + ?Sized>(
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
) -> usize {
    walk_stem(params, embargo, rng)
        .stem_hops()
        .saturating_sub(1)
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

/// Pin one stem peer with [`StemMap`], among `pool`.
///
/// Width is the shipped stem count (2) when the pool is large enough, and
/// the pool's length otherwise. The local source is `None`.
fn pin_stem<R: RelayRng + ?Sized>(pool: &[OutEdge], rng: &mut R) -> Option<OutEdge> {
    if pool.is_empty() {
        return None;
    }
    let width = StemGraph::QuasiFourRegular.stem_count().min(pool.len());
    let ids: Vec<ConnectionId> = pool.iter().map(|e| peer_id(e.to)).collect();
    let mut map = StemMap::new(ids, width, rng);
    let chosen = map.stem_for(None, rng)?;
    let to = node_of(chosen);
    pool.iter().copied().find(|e| e.to == to)
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
/// The own-edge is one [`StemMap`] pin in the pool [`Routing`] allows for
/// originated traffic. Each relay is a fresh pin, in the pool the routing
/// allows for relays, at the node that received the previous hop. Stem
/// length is [`walk_stem`], so the fluff coin is the parameter set's `q`
/// and not a second geometric.
pub fn land_originated_stem<R: RelayRng + ?Sized>(
    graph: &TwoClassGraph,
    origin: usize,
    routing: Routing,
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
) -> StemLanding {
    let forwards = relayed_forwards(params, embargo, rng);
    let own_pool = match routing {
        Routing::HiddenOwnEdge | Routing::Split => {
            edges_of(&graph.initiated[origin], Some(LinkClass::Hidden))
        }
        Routing::AllClearnet => edges_of(&graph.initiated[origin], Some(LinkClass::Clearnet)),
    };
    let Some(own) = pin_stem(&own_pool, rng) else {
        return StemLanding {
            own_edge: None,
            relayed: Vec::new(),
            path: vec![origin],
        };
    };
    let mut path = vec![origin, own.to];
    let mut relayed = Vec::with_capacity(forwards);
    let mut at = own.to;
    for _ in 0..forwards {
        let pool = match routing {
            Routing::HiddenOwnEdge => edges_of(&graph.initiated[at], None),
            Routing::Split | Routing::AllClearnet => {
                edges_of(&graph.initiated[at], Some(LinkClass::Clearnet))
            }
        };
        let Some(hop) = pin_stem(&pool, rng) else {
            break;
        };
        relayed.push((hop.class, hop.to));
        at = hop.to;
        path.push(at);
    }
    StemLanding {
        own_edge: Some(own.class),
        relayed,
        path,
    }
}

/// Posterior that a stem arrival on a class was originated, not relayed.
///
/// Counts are deliveries. One originated delivery per trial that pinned,
/// plus one delivery per relayed forward. `hidden_share` is `h / (h + c)`,
/// which is not this posterior: originated mass sits on the own-edge.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassPosterior {
    /// Mean relayed forwards per originated stem, from [`walk_stem`].
    pub relayed_per_originated: f64,
    /// `h / (h + c)`.
    pub hidden_share: f64,
    /// `P(originated | arrival on a hidden edge)`, over every hidden delivery.
    pub posterior_hidden: f64,
    /// `P(originated | arrival on the pinned own-edge)`.
    ///
    /// That peer receives every originated stem for the epoch. `h / (h + c)`
    /// understates this: the share is how relayed forwards spread, and the
    /// originated mass is not spread.
    pub posterior_own_edge: f64,
    /// `P(originated | arrival on a clearnet edge)`. 0 when no clearnet arrival.
    pub posterior_clearnet: f64,
    /// Originated deliveries on hidden edges.
    pub hidden_originated: u64,
    /// Relayed deliveries on hidden edges.
    pub hidden_relayed: u64,
    /// Originated deliveries on clearnet edges.
    pub clearnet_originated: u64,
    /// Relayed deliveries on clearnet edges.
    pub clearnet_relayed: u64,
}

fn posterior(originated: u64, relayed: u64) -> f64 {
    let total = originated + relayed;
    if total == 0 {
        0.0
    } else {
        originated as f64 / total as f64
    }
}

/// Measure [`ClassPosterior`] on fresh graphs.
///
/// # Panics
///
/// Panics if `trials` is zero.
#[must_use]
pub fn simulate_class_posterior<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    trials: usize,
    rng: &mut R,
) -> ClassPosterior {
    assert!(trials > 0, "need at least one trial");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut hidden_originated = 0_u64;
    let mut hidden_relayed = 0_u64;
    let mut clearnet_originated = 0_u64;
    let mut clearnet_relayed = 0_u64;
    let mut own_relayed = 0_u64;
    let mut relayed_total = 0_u64;
    let mut originated_total = 0_u64;
    for _ in 0..trials {
        let graph = build_two_class(
            mix.nodes,
            mix.hidden_out,
            mix.clearnet_out,
            mix.onion_fraction,
            rng,
        );
        let landing = land_originated_stem(&graph, 0, routing, &params, &embargo, rng);
        let Some(own) = landing.own_edge else {
            continue;
        };
        let own_peer = landing.path.get(1).copied();
        originated_total += 1;
        match own {
            LinkClass::Hidden => hidden_originated += 1,
            LinkClass::Clearnet => clearnet_originated += 1,
        }
        for (class, to) in &landing.relayed {
            relayed_total += 1;
            if Some(*to) == own_peer {
                own_relayed += 1;
            }
            match class {
                LinkClass::Hidden => hidden_relayed += 1,
                LinkClass::Clearnet => clearnet_relayed += 1,
            }
        }
    }
    let graph_share = if mix.hidden_out + mix.clearnet_out == 0 {
        0.0
    } else {
        mix.hidden_out as f64 / (mix.hidden_out + mix.clearnet_out) as f64
    };
    ClassPosterior {
        relayed_per_originated: if originated_total == 0 {
            0.0
        } else {
            relayed_total as f64 / originated_total as f64
        },
        hidden_share: graph_share,
        posterior_hidden: posterior(hidden_originated, hidden_relayed),
        posterior_own_edge: posterior(originated_total, own_relayed),
        posterior_clearnet: posterior(clearnet_originated, clearnet_relayed),
        hidden_originated,
        hidden_relayed,
        clearnet_originated,
        clearnet_relayed,
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
