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

use crate::rng::{bernoulli, bounded_uniform, RelayRng};

use super::util::usize_from;

/// The **W3 residual**: how often an adversary occupies *both* of the origin's
/// outbound stem slots (`out_mapping_`) — the one exposure reshape cannot route
/// around, and therefore the `δ` a `ρ` decision is taken against (§12, §13.4).
/// This is *not* the demoted §13 table: that measured the leak of a mechanism we
/// replace; this measures the leak that *survives* the replacement.
///
/// **Grounded as an OUTBOUND-occupancy channel, not the inbound reach.**
/// [`dandelionpp.cpp:103-122`] builds `out_mapping_` by selecting `STEMS = 2`
/// distinct peers, *without replacement*, from the origin's **outbound** pool
/// (`P2P_DEFAULT_CONNECTIONS_COUNT = 12`, `cryptonote_config.h:134`). An adversary
/// enters that pool only by being *selected* as an outbound peer — a *different*
/// capability than the cheap inbound dialing that gives
/// [`simulate_transport_observation`]'s `dial_fraction`, so importing that inbound
/// reach here would measure a phantom (a channel the capability cannot reach). But
/// this capability is **not** necessarily costly: the outbound pool is 70 %
/// white-list + 2 anchors (`P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT`,
/// `P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT`), and the white list is gossip-fed, so an
/// eclipse-capable adversary drives `g` **above** the network fraction `f` by cheap
/// peerlist poisoning. This instrument measures `W3(g)` but does **not** bound `g`
/// — that bound is owed by the anti-eclipse peer-selection grounding (§12.6, Q-10),
/// and `ρ` is blocked on it, not decidable against `g = f`.
///
/// Reshape (`retry_cap = STEMS − 1 = 1`) routes around an adversarial primary
/// *iff* the alternate slot is honest, so the residual it cannot remove is exactly
/// `P(both slots adversarial)`. W3b (the adversary pinning the origin to one live
/// slot via induced churn) is a *cheaper*, capability-gated case bounded above by
/// the single-slot occupancy reported here; it needs an eviction capability this
/// instrument does not grant for free.
///
/// **Single-draw occupancy — a lower bound under churn.** This measures one stable
/// epoch map. Mid-epoch, `connection_map::update()` re-rolls a churned slot with a
/// *fresh* draw (`dandelionpp.cpp:160`), so an adversary who induces churn re-rolls
/// the enriched draw repeatedly (W3c, `DAEMON_RELAY_PRIVACY.md` §12.6). The
/// effective per-epoch occupancy under adversary-induced churn is therefore
/// *higher* than this single-draw number, and Q-10's `g`-bound must hold under
/// repeated refills — this instrument does not model churn.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TwoSlotOccupancy {
    /// `g` — the adversary's share of the origin's outbound pool.
    pub outbound_share: f64,
    /// `D_out` — the origin's outbound degree (daemon default 12).
    pub outbound_degree: usize,
    /// **W3.** `P(both stem slots adversarial)` — the exposure that survives
    /// reshape, and the number a `ρ` decision is taken against.
    pub both_slots: f64,
    /// `P(≥ 1 stem slot adversarial)` — the pre-reshape single-slot exposure, and
    /// the ceiling for the churn-gated W3b case.
    pub at_least_one_slot: f64,
    /// `(a/D_out)²` — the with-replacement reference at the *effective* integer
    /// adversary share `a = round(g·D_out)`. `both_slots` sits *below* it:
    /// choosing two *distinct* peers from a finite pool is anti-correlated
    /// (`both_slots = both_slots_with_replacement · (a−1)/a · D_out/(D_out−1)`),
    /// so W3 is bounded above by the independent draw, not merely equal to it.
    pub independent_reference: f64,
}

/// Measure [`TwoSlotOccupancy`] at outbound share `g` over a pool of
/// `outbound_degree` peers, mirroring the partial Fisher-Yates selection of
/// `out_mapping_` at [`dandelionpp.cpp:113-118`].
///
/// The integer rounding of `g · D_out` is deliberate, not a modelling shortcut: a
/// real adversary holds an integer number of the origin's outbound slots, and at
/// `D_out = 12` that granularity *is* the result — `g = 0.10` is ~1 peer, which
/// cannot fill two slots at all, so baseline `both_slots ≈ 0` until enrichment
/// lifts `g` well above the raw node fraction `f`.
///
/// # Panics
///
/// Panics if `trials` is zero, `outbound_degree < 2`, or `outbound_share` is
/// outside `[0, 1]`.
#[must_use]
pub fn simulate_two_slot_occupancy<R: RelayRng + ?Sized>(
    outbound_share: f64,
    outbound_degree: usize,
    trials: usize,
    rng: &mut R,
) -> TwoSlotOccupancy {
    assert!(trials > 0, "need at least one trial");
    assert!(
        outbound_degree >= 2,
        "need at least two outbound peers to fill two stem slots"
    );
    assert!(
        (0.0..=1.0).contains(&outbound_share),
        "outbound share must be in [0, 1]"
    );

    let d = outbound_degree;
    // The adversary holds the first `a` of the `d` outbound peers.
    let a = (outbound_share * d as f64).round() as usize;

    let mut both = 0_usize;
    let mut at_least_one = 0_usize;
    for _ in 0..trials {
        // Two distinct slot indices in `[0, d)`, mirroring the swap-and-pick of
        // dandelionpp.cpp:116 (second draw taken from the remaining `d − 1` and
        // mapped around the first). `bounded_uniform` is inclusive [0, max], so the
        // first draw uses `d - 1` (→ [0, d)) and the second uses `d - 2` (→ the
        // remaining `d − 1` values, mapped around `s0`).
        let s0 = usize_from(bounded_uniform(rng, (d - 1) as u64));
        let r = usize_from(bounded_uniform(rng, (d - 2) as u64));
        let s1 = if r < s0 { r } else { r + 1 };
        let adv0 = s0 < a;
        let adv1 = s1 < a;
        both += usize::from(adv0 && adv1);
        at_least_one += usize::from(adv0 || adv1);
    }

    let effective_share = a as f64 / d as f64;
    TwoSlotOccupancy {
        outbound_share,
        outbound_degree: d,
        both_slots: both as f64 / trials as f64,
        at_least_one_slot: at_least_one as f64 / trials as f64,
        independent_reference: effective_share * effective_share,
    }
}

/// **Q1 layering discriminator (§12.8):** how an adversary holding `adversary_peers`
/// slots in the origin's stem-eligible set is exposed across epochs, as a function
/// of the set size — the number that decides "pin the set of `K`" vs. the current
/// ~12-peer pool, turning the layering call from an argument into a measurement.
///
/// Each epoch the origin's `nil`-keyed stem successor is drawn uniformly from the
/// eligible set (the `change_channels` rebuild, §12.8 G-2). The **pool** regime is
/// `eligible_set_size = D_out` (≈12); the **pinned** regime is `= K`. Holding the
/// adversary's *peer count* `a` fixed (not its share), this isolates the two axes
/// that pull opposite ways under pinning:
///
/// - **Direct-successor exposure** — the occupancy / C1 axis, and the *dominant*
///   one, because a captured successor identifies the origin at precision 1. The
///   per-epoch presence is `a / set`, so shrinking `D → K` **amplifies** a captured
///   slot's presence by `D/K`. This is the advisor-flagged risk: a single pinned
///   adversary's cross-epoch presence rises from `~1/D` to `~1/K`.
/// - **Cross-epoch successor diversity** — the intersection axis (§6.8). A smaller
///   set yields fewer distinct successors, which *slows* the intersection's collapse
///   toward `{origin}` — protective, but secondary to the direct-successor axis.
///
/// The decision this feeds: pinning to a small `K` is net-harmful on the dominant
/// axis unless the pin-admission bound (`g_max`, Q4) makes holding `a` slots in `K`
/// harder than in `D` by **more than the `D/K` amplification**.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpochLayering {
    /// The eligible set size (`D_out` for pool, `K` for pinned).
    pub eligible_set_size: usize,
    /// Adversary slots held in the eligible set (held fixed across the comparison).
    pub adversary_peers: usize,
    /// Epochs observed.
    pub epochs: usize,
    /// Per-epoch `P(adversary is the origin's successor)` = `a / eligible_set_size`.
    pub direct_successor_rate: f64,
    /// `P(adversary is the origin's successor in ≥ 1 of `epochs` epochs)`.
    pub p_identified_direct: f64,
    /// Mean number of distinct successors the origin uses across `epochs` epochs —
    /// the cross-epoch diversity that governs the intersection collapse.
    pub distinct_successors: f64,
}

/// Measure [`EpochLayering`] for `adversary_peers` of `eligible_set_size` over
/// `epochs` epochs. Adversary holds indices `0..adversary_peers`.
///
/// # Panics
///
/// Panics if `trials`/`epochs` is zero, the set is empty, or `adversary_peers`
/// exceeds `eligible_set_size`.
#[must_use]
pub fn simulate_epoch_layering<R: RelayRng + ?Sized>(
    eligible_set_size: usize,
    adversary_peers: usize,
    epochs: usize,
    trials: usize,
    rng: &mut R,
) -> EpochLayering {
    assert!(trials > 0, "need at least one trial");
    assert!(eligible_set_size >= 1, "eligible set must be non-empty");
    assert!(epochs >= 1, "need at least one epoch");
    assert!(
        adversary_peers <= eligible_set_size,
        "adversary cannot hold more slots than the set has"
    );

    let mut present_epochs_total = 0_u64;
    let mut identified_trials = 0_usize;
    let mut distinct_total = 0_u64;

    for _ in 0..trials {
        let mut present_this_trial = false;
        let mut seen = vec![false; eligible_set_size];
        let mut distinct = 0_u64;
        for _ in 0..epochs {
            // `bounded_uniform` is inclusive [0, max], so draw over set_size - 1.
            let s = usize_from(bounded_uniform(rng, (eligible_set_size - 1) as u64));
            if s < adversary_peers {
                present_this_trial = true;
                present_epochs_total += 1;
            }
            if !seen[s] {
                seen[s] = true;
                distinct += 1;
            }
        }
        identified_trials += usize::from(present_this_trial);
        distinct_total += distinct;
    }

    EpochLayering {
        eligible_set_size,
        adversary_peers,
        epochs,
        direct_successor_rate: present_epochs_total as f64 / (trials as f64 * epochs as f64),
        p_identified_direct: identified_trials as f64 / trials as f64,
        distinct_successors: distinct_total as f64 / trials as f64,
    }
}

/// **§12.11 ossification measurement:** pure preference (`ε = 0`) collapses the stem
/// graph to `STEMS = 2` peers and never touches the rest of the pool; even `ε ≈ 0.05`
/// exploration restores the full pool. Reproduces the `ε → distinct-peers` result
/// §12.11 cited from an external model, in-crate per the §13.5 discipline (reproduce
/// the load-bearing number in our own instrument).
///
/// Model: `pool` peers ranked by a *converged* track record — the ossification is a
/// property of the argmax rule, not the learning dynamics, so the ranking is treated
/// as settled (cold-start learning is itself a form of exploration, exactly what
/// `ε > 0` also provides). `STEMS = 2` slots per epoch: slot 0 always exploits the top
/// peer; slot 1 explores (uniform over the non-top peers `[2, pool)`) with *per-epoch*
/// probability `ε` (memoryless, §12.11 edge 2), else exploits the second peer. There is
/// deliberately **no induced-failure dial** — that priced a phantom (§12.11 part D:
/// inducing an honest peer's failure costs the occupancy/eclipse budget already bounded).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpsilonGreedySelection {
    /// Exploration rate measured at.
    pub epsilon: f64,
    /// Outbound pool size `D`.
    pub pool: usize,
    /// Epochs observed.
    pub epochs: usize,
    /// Mean distinct peers exercised as a stem successor over `epochs`: `ε = 0` → 2
    /// (ossified), `ε ≈ 0.05` → the full pool.
    pub distinct_peers: f64,
    /// Fraction of stem-sends to the top-2 peers. Exploration does *not* redistribute
    /// the bulk (top-2 still carry ~`1 − ε/2`); the point is that the `ε/2` escape
    /// fraction reaches non-top peers, so a top-2 occupier no longer sees 100 % and
    /// full eclipse is prevented (§12.10 regime 3).
    pub top2_traffic_share: f64,
}

/// Measure [`EpsilonGreedySelection`] at exploration rate `epsilon` over a `pool` of
/// peers for `epochs` epochs.
///
/// # Panics
///
/// Panics if `trials`/`epochs` is zero, `pool < 3`, or `epsilon` is outside `[0, 1]`.
#[must_use]
pub fn simulate_epsilon_greedy_selection<R: RelayRng + ?Sized>(
    epsilon: f64,
    pool: usize,
    epochs: usize,
    trials: usize,
    rng: &mut R,
) -> EpsilonGreedySelection {
    assert!(trials > 0, "need at least one trial");
    assert!(epochs >= 1, "need at least one epoch");
    assert!(
        pool >= 3,
        "need a pool larger than STEMS to have non-top peers to explore"
    );
    assert!((0.0..=1.0).contains(&epsilon), "epsilon must be in [0, 1]");

    // `bernoulli` takes a rational probability; express epsilon per million.
    const EPS_DENOM: u64 = 1_000_000;
    let eps_num = (epsilon * EPS_DENOM as f64).round() as u64;

    let mut distinct_total = 0_u64;
    let mut top2_sends = 0_u64;
    let mut all_sends = 0_u64;

    for _ in 0..trials {
        let mut used = vec![false; pool];
        for _ in 0..epochs {
            // slot 0: exploit the top peer.
            used[0] = true;
            top2_sends += 1;
            all_sends += 1;
            // slot 1: explore with per-epoch probability epsilon, else exploit peer 1.
            if bernoulli(rng, eps_num, EPS_DENOM) {
                let e = 2 + usize_from(bounded_uniform(rng, (pool - 3) as u64));
                used[e] = true;
                all_sends += 1;
            } else {
                used[1] = true;
                top2_sends += 1;
                all_sends += 1;
            }
        }
        distinct_total += used.iter().filter(|&&u| u).count() as u64;
    }

    EpsilonGreedySelection {
        epsilon,
        pool,
        epochs,
        distinct_peers: distinct_total as f64 / trials as f64,
        top2_traffic_share: top2_sends as f64 / all_sends as f64,
    }
}
