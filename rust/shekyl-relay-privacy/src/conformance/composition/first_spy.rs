// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! First-spy precision on an originated stem.
//!
//! One trial is one transaction. The path is [`super::walk_originated`],
//! so a hop the live pool would fluff is not a spy the stem phase reaches.
//! Spy labels are drawn once per node. The origin is not a spy.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::params::DandelionParams;
use crate::rng::RelayRng;
use crate::schedule::{EmbargoTimer, DEFAULT_EMBARGO_TICK_MILLIS};

use super::super::util::bernoulli_unit;
use super::{
    build_node_maps, build_two_class, walk_originated, LinkClass, Mix, OriginatedStem, Routing,
    StemRelayBudget, TwoClassGraph,
};

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

    fn p(self) -> f64 {
        match self {
            Self::Uniform { p } | Self::OnionBiased { p } => p,
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

/// One trial's graph and stem.
///
/// The stem length is drawn before the trial's maps. That is the order
/// the published first-spy reading used: the length model's coin is not
/// the pin draw.
fn trial_stem<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    origin: usize,
    params: &DandelionParams,
    embargo: &EmbargoTimer,
    rng: &mut R,
) -> (TwoClassGraph, OriginatedStem) {
    let graph = build_two_class(mix, rng);
    let budget = StemRelayBudget::from_walk(params, embargo, rng);
    let mut maps = build_node_maps(&graph, routing, rng);
    let stem = walk_originated(&graph, &mut maps, origin, budget, rng);
    (graph, stem)
}

/// One label per node for this trial. The origin is not a spy.
fn spy_membership<R: RelayRng + ?Sized>(
    publishes: &[bool],
    arm: SpyArm,
    origin: usize,
    rng: &mut R,
) -> Vec<bool> {
    publishes
        .iter()
        .enumerate()
        .map(|(node, publishes_onion)| {
            node != origin && bernoulli_unit(rng, arm.threshold(*publishes_onion))
        })
        .collect()
}

/// Precision and recall of the first spy on the originated stem.
///
/// `origin` is the node that originates. The graph is [`Mix`], including
/// its clearnet-only prefix.
///
/// # Panics
///
/// Panics if `trials` is zero, `origin` is not a node, or `p` is outside
/// `(0, 1]`.
#[must_use]
pub fn simulate_stem_first_spy<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    arm: SpyArm,
    origin: usize,
    trials: usize,
    rng: &mut R,
) -> StemFirstSpy {
    assert!(trials > 0, "need at least one trial");
    assert!(origin < mix.nodes, "origin {origin} is not a node");
    let p = arm.p();
    assert!(p > 0.0 && p <= 1.0, "spy fraction must be in (0, 1]");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut observed = 0_usize;
    let mut pinned = 0_usize;
    let mut correct = 0_usize;
    for _ in 0..trials {
        let (graph, stem) = trial_stem(mix, routing, origin, &params, &embargo, rng);
        if stem.own_edge.is_none() {
            continue;
        }
        pinned += 1;
        let spies = spy_membership(&graph.publishes, arm, origin, rng);
        if let Some(i) = first_spy(&stem.path, &spies) {
            observed += 1;
            if stem.path[i - 1] == origin {
                correct += 1;
            }
        }
    }
    StemFirstSpy {
        observed,
        pinned,
        precision: ratio(correct, observed),
        recall: ratio(observed, pinned),
    }
}

fn first_spy(path: &[usize], spies: &[bool]) -> Option<usize> {
    path.iter()
        .enumerate()
        .skip(1)
        .find(|(_, node)| spies[**node])
        .map(|(i, _)| i)
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

/// Class-blind and class-aware first spy.
///
/// The aware estimator skips a spy whose incoming edge
/// [`clearnet_arrival_is_relayed`] accepts. How often a clearnet arrival
/// comes from a clearnet-only sender, and the precision of naming those
/// origins, are not these fields. That measurement is its own follow-up.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassAwareFirstSpy {
    /// The predecessor of the first spy, whatever the edge class.
    pub blind: OriginIdentification,
    /// Skips a spy whose incoming edge [`clearnet_arrival_is_relayed`].
    pub aware: OriginIdentification,
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

fn hop_class(stem: &OriginatedStem, arrival: usize) -> LinkClass {
    if arrival == 1 {
        stem.own_edge
            .expect("a pinned path has a first-hop class")
            .class
    } else {
        stem.relayed[arrival - 2].class
    }
}

fn identification(pinned: usize, named: usize, named_origin: usize) -> OriginIdentification {
    OriginIdentification {
        pinned,
        named,
        named_origin,
        precision: ratio(named_origin, named),
        recall: ratio(named_origin, pinned),
    }
}

/// First-spy precision and recall with and without the link class.
///
/// The class-aware estimator does not name a predecessor reached by a
/// clearnet edge when that predecessor has a hidden session. The paper's
/// uniform hop 0 is [`Routing::UniformHop0`]: the comparison is whether
/// the class helps only once hop 0 is confined to the hidden slot.
///
/// `origin` is fixed for every trial. A population with clearnet-only
/// nodes is [`Mix::with_clearnet_only`], not a mutation of a built graph.
///
/// # Panics
///
/// Panics if `trials` is zero, `origin` is not a node, or `p` is outside
/// `(0, 1]`.
#[must_use]
pub fn simulate_class_aware_first_spy<R: RelayRng + ?Sized>(
    mix: Mix,
    routing: Routing,
    arm: SpyArm,
    origin: usize,
    trials: usize,
    rng: &mut R,
) -> ClassAwareFirstSpy {
    assert!(trials > 0, "need at least one trial");
    assert!(origin < mix.nodes, "origin {origin} is not a node");
    let p = arm.p();
    assert!(p > 0.0 && p <= 1.0, "spy fraction must be in (0, 1]");
    let params = DandelionParams::adopted();
    let embargo = EmbargoTimer::geometric_from_ticks(1, DEFAULT_EMBARGO_TICK_MILLIS);
    let mut pinned = 0_usize;
    let mut blind_named = 0_usize;
    let mut blind_correct = 0_usize;
    let mut aware_named = 0_usize;
    let mut aware_correct = 0_usize;
    for _ in 0..trials {
        let (graph, stem) = trial_stem(mix, routing, origin, &params, &embargo, rng);
        if stem.own_edge.is_none() {
            continue;
        }
        pinned += 1;
        let spies = spy_membership(&graph.publishes, arm, origin, rng);
        let mut blind: Option<usize> = None;
        let mut aware: Option<usize> = None;
        for (i, &node) in stem.path.iter().enumerate().skip(1) {
            if !spies[node] {
                continue;
            }
            let sender = stem.path[i - 1];
            if blind.is_none() {
                blind = Some(sender);
            }
            if aware.is_none() {
                let class = hop_class(&stem, i);
                let hidden = graph.has_hidden_outbound(sender);
                if !clearnet_arrival_is_relayed(class, hidden) {
                    aware = Some(sender);
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
        blind: identification(pinned, blind_named, blind_correct),
        aware: identification(pinned, aware_named, aware_correct),
    }
}
