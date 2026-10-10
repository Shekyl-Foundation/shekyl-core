// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The D3 exception instrument (`P2P_3_SLICE_1_PEERLIST_BRIEF.md` §5a,
//! §16.5): does leaving this node's current outbound sessions out of the
//! disclosure sample help, against an observer who polls the cached sample
//! every window?
//!
//! A model, not the network. One connector's white list `W`, this node's
//! outbound sessions `O ⊂ W`, a hidden subset of `O` with one hidden stem
//! slot among it. Each window the node discloses `DISCLOSE_COUNT` members
//! drawn uniformly — the draw `Partition::disclose` makes — from either the
//! whole population (**uniform**, the default) or the population minus `O`
//! (**excluded**, the exception under measurement). The observer sees every
//! window's sample and controls a share of `O` (those it already knows).
//!
//! Two observers, because the rule says the exception is adopted only if it
//! lowers the observer's success *and no observer gains*:
//!
//! - the **presence** observer guesses that every address it has seen
//!   disclosed is one of our outbound sessions;
//! - the **absence** observer knows a population `N ⊇ W` — the network's
//!   nodes it has learned from its own polling and other peers — and
//!   guesses that every member of `N` never disclosed after `k` windows is
//!   one of our outbound sessions.
//!
//! Each reports precision and recall on `O` (controlled members excluded
//! from both the guess and the target: the observer is scoring what it did
//! not already know), and its chance of naming the hidden stem slot by a
//! uniform guess among its hidden guesses.

// Counts become ratios here; the counts are list sizes, far below 2^52.
#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::rng::RelayRng;

use crate::sample::sample_prefix;
use crate::DISCLOSE_COUNT;

/// One observer's score after `windows` polls.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ObserverScore {
    /// Of the addresses it named, the share that are uncontrolled outbound
    /// sessions. `0` when it named none.
    pub precision: f64,
    /// Of the uncontrolled outbound sessions, the share it named.
    pub recall: f64,
    /// Its chance of naming the hidden stem slot: one uniform guess among
    /// the hidden addresses it named, `0` when it named none of them.
    pub hidden_slot_hit: f64,
    /// Mean number of addresses it named.
    pub named: f64,
}

/// Both observers' scores under one sampling rule.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ArmScore {
    /// The presence observer.
    pub presence: ObserverScore,
    /// The absence observer.
    pub absence: ObserverScore,
}

/// The instrument's result: the uniform sample against the sample that
/// leaves `O` out, same trials, same observers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DisclosureExceptionExposure {
    /// `|W|`, the white list.
    pub white: usize,
    /// `|O|`, this node's outbound sessions on the connector.
    pub outbound: usize,
    /// How many of `O` hide the address; one of them is the hidden slot.
    pub hidden_outbound: usize,
    /// Members of `O` the observer controls and so already knows.
    pub controlled: usize,
    /// `|N| − |W|`: nodes the absence observer knows that are not on our
    /// white list. `0` is an observer who knows `W` exactly.
    pub known_beyond_white: usize,
    /// Windows polled.
    pub windows: usize,
    /// The default: every member of the population is a candidate.
    pub uniform: ArmScore,
    /// The exception: the population minus `O`.
    pub excluded: ArmScore,
}

/// Measure [`DisclosureExceptionExposure`].
///
/// Addresses are indices: `0..outbound` are `O`, of which `0..hidden_outbound`
/// hide the address and `0` is the hidden slot; `outbound..white` are the
/// rest of `W`; `white..white + known_beyond_white` are nodes the absence
/// observer knows that we never confirmed. The controlled members are the
/// last `controlled` of `O`, so the hidden slot is never one the observer
/// already holds unless it controls all of `O`'s hidden members.
///
/// # Panics
///
/// Panics if `trials` is zero, `outbound` is zero or exceeds `white`,
/// `hidden_outbound` is zero or exceeds `outbound`, or `controlled` exceeds
/// `outbound`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn simulate_disclosure_exception<R: RelayRng + ?Sized>(
    white: usize,
    outbound: usize,
    hidden_outbound: usize,
    controlled: usize,
    known_beyond_white: usize,
    windows: usize,
    trials: usize,
    rng: &mut R,
) -> DisclosureExceptionExposure {
    assert!(trials > 0, "need at least one trial");
    assert!(
        outbound >= 1 && outbound <= white,
        "outbound sessions are a subset of white"
    );
    assert!(
        hidden_outbound >= 1 && hidden_outbound <= outbound,
        "the hidden slot is one of the outbound sessions"
    );
    assert!(
        controlled <= outbound,
        "controlled sessions are outbound sessions"
    );

    let mut uniform = Accumulator::default();
    let mut excluded = Accumulator::default();
    for _ in 0..trials {
        uniform.add(&run_trial(
            white,
            outbound,
            hidden_outbound,
            controlled,
            known_beyond_white,
            windows,
            false,
            rng,
        ));
        excluded.add(&run_trial(
            white,
            outbound,
            hidden_outbound,
            controlled,
            known_beyond_white,
            windows,
            true,
            rng,
        ));
    }
    DisclosureExceptionExposure {
        white,
        outbound,
        hidden_outbound,
        controlled,
        known_beyond_white,
        windows,
        uniform: uniform.mean(trials),
        excluded: excluded.mean(trials),
    }
}

#[derive(Default)]
struct Accumulator {
    presence: [f64; 4],
    absence: [f64; 4],
}

impl Accumulator {
    fn add(&mut self, arm: &ArmScore) {
        for (sum, score) in [
            (&mut self.presence, arm.presence),
            (&mut self.absence, arm.absence),
        ] {
            sum[0] += score.precision;
            sum[1] += score.recall;
            sum[2] += score.hidden_slot_hit;
            sum[3] += score.named;
        }
    }

    fn mean(&self, trials: usize) -> ArmScore {
        let t = trials as f64;
        let score = |s: &[f64; 4]| ObserverScore {
            precision: s[0] / t,
            recall: s[1] / t,
            hidden_slot_hit: s[2] / t,
            named: s[3] / t,
        };
        ArmScore {
            presence: score(&self.presence),
            absence: score(&self.absence),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_trial<R: RelayRng + ?Sized>(
    white: usize,
    outbound: usize,
    hidden_outbound: usize,
    controlled: usize,
    known_beyond_white: usize,
    windows: usize,
    exclude_outbound: bool,
    rng: &mut R,
) -> ArmScore {
    let is_outbound = |a: usize| a < outbound;
    let is_hidden = |a: usize| a < hidden_outbound;
    let is_controlled = |a: usize| a >= outbound - controlled && a < outbound;
    let hidden_slot = 0_usize;

    // The disclosure population: `W`, minus `O` under the exception.
    let population: Vec<usize> = if exclude_outbound {
        (outbound..white).collect()
    } else {
        (0..white).collect()
    };

    let mut seen = vec![false; white + known_beyond_white];
    for _ in 0..windows {
        // One cached sample per window: `DISCLOSE_COUNT` distinct members,
        // uniform — the same prefix draw `Partition::disclose` makes.
        let mut pool = population.clone();
        let taken = sample_prefix(&mut pool, DISCLOSE_COUNT, rng);
        for address in pool.iter().take(taken) {
            seen[*address] = true;
        }
    }

    // Targets: the outbound sessions the observer does not already control.
    let targets: Vec<usize> = (0..outbound).filter(|a| !is_controlled(*a)).collect();

    // Presence: everything disclosed, minus what it controls.
    let presence_named: Vec<usize> = (0..white + known_beyond_white)
        .filter(|a| seen[*a] && !is_controlled(*a))
        .collect();
    // Absence: everything it knows that was never disclosed, minus what it
    // controls.
    let absence_named: Vec<usize> = (0..white + known_beyond_white)
        .filter(|a| !seen[*a] && !is_controlled(*a))
        .collect();

    let score = |named: &[usize]| -> ObserverScore {
        let hits = named.iter().filter(|a| is_outbound(**a)).count();
        let precision = if named.is_empty() {
            0.0
        } else {
            hits as f64 / named.len() as f64
        };
        let recall = if targets.is_empty() {
            0.0
        } else {
            hits as f64 / targets.len() as f64
        };
        let hidden_named = named.iter().filter(|a| is_hidden(**a)).count();
        let hidden_slot_hit = if hidden_named == 0 || !named.contains(&hidden_slot) {
            0.0
        } else {
            1.0 / hidden_named as f64
        };
        ObserverScore {
            precision,
            recall,
            hidden_slot_hit,
            named: named.len() as f64,
        }
    };

    ArmScore {
        presence: score(&presence_named),
        absence: score(&absence_named),
    }
}
