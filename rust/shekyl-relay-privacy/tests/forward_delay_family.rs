// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
#![allow(clippy::cast_precision_loss)]
// ^ Quantized masses partition 2^64, so — unlike this crate's other sweeps —
//   they are NOT "far below 2^53" and the cast genuinely loses low bits. It is
//   harmless *here* and the reason is specific rather than inherited: every
//   masses-to-f64 cast below feeds a RATIO of sums (a survival weight, or a
//   weighted mean divided by its own weight sum), so the ~1e-16 relative error
//   cancels to first order and cannot move a comparison whose smallest
//   separation is six orders of magnitude (1e-7 drift against a 1e-6
//   tolerance). Copying the other files' "far below 2^53" note would have been
//   a false justification for a true allow.
//! The forward delay's family fix, measured on F-4's own instrument.
//!
//! The inherited i2p/tor → clearnet delay draws
//! `crypto::random_poisson_seconds{22 s}`. This is F-4's move one call site
//! later: **fix the family at the unchanged mean.** The mean is Q-12's to
//! derive (§22.2); the family was settled by F-2/F-4 and does not depend on
//! Q-12's open fork.
//!
//! Measured with [`inference_precision`] and [`residual_masses`] — the same
//! functions that produced F-4's numbers — rather than a spread proxy, so the
//! claim here is comparable to the claim it inherits.
//!
//! # Every phase sweep here is bounded, and that is not cosmetic
//!
//! `residual_masses` conditions on a draw having survived `phase` ticks. Past
//! the point where the table still carries mass, it is conditioning on an event
//! that essentially never happens: the slice shrinks toward empty and
//! `inference_precision` climbs toward `1.0` for **any** family, memoryless
//! included. A sweep over the full table therefore measures **truncation, not
//! the distribution** — an earlier draft of this file did exactly that and
//! reported the memoryless draw as having 0.875 phase drift, which is the
//! instrument degenerating rather than the family failing.
//!
//! So every sweep stops at [`SURVIVAL_FLOOR`], and the tests say what the
//! bound is for.

use shekyl_relay_privacy::conformance::analysis::{inference_precision, residual_masses};
use shekyl_relay_privacy::schedule::{ForwardDelay, ADOPTED_FORWARD_DELAY_MEAN_SECS};
use shekyl_relay_privacy::{GeometricTable, PoissonTable};

/// The adversary's tolerance, in seconds. One second either side: the consumer
/// stores a whole-second `time_t`, so a finer window would grade a precision
/// the deadline cannot express.
const WINDOW: u64 = 1;

/// Sweeps stop once less than this fraction of the mass survives to the phase.
///
/// Below it, `residual_masses` is conditioning on a practically impossible
/// arrival and the instrument's answer is a truncation artifact rather than a
/// property of the family (see the module docs).
const SURVIVAL_FLOOR: f64 = 1e-6;

/// `(phase, inversion precision)` for every phase the table still supports.
fn precision_by_phase(masses: &[u64], window: u64) -> Vec<(usize, f64)> {
    let total: f64 = masses.iter().map(|m| *m as f64).sum();
    let mut survival = total;
    let mut out = Vec::new();
    for (phase, mass) in masses.iter().enumerate() {
        if survival / total < SURVIVAL_FLOOR {
            break;
        }
        out.push((
            phase,
            inference_precision(&residual_masses(masses, phase as u64), window),
        ));
        survival -= *mass as f64;
    }
    out
}

/// Largest deviation of inversion precision from its phase-0 value, over the
/// supported phases.
///
/// Zero for a memoryless family by construction — residual ≡ full — and that
/// is the property being bought, so it is measured directly rather than
/// inferred from an average.
fn max_phase_drift(masses: &[u64], window: u64) -> f64 {
    let p0 = inference_precision(masses, window);
    precision_by_phase(masses, window)
        .into_iter()
        .map(|(_, p)| (p - p0).abs())
        .fold(0.0_f64, f64::max)
}

/// Inversion precision averaged over arrival phase, weighted by how long a
/// draw actually spends at each phase.
///
/// **This is the headline, and neither endpoint is.** Phase 0 flatters the
/// Poisson and its worst phase indicts it; a real observer sees arrivals spread
/// across phases. Weighted by the survival function — the fraction of the
/// delay's lifetime spent at or beyond each phase — which also discounts the
/// rare deep-tail phases that would otherwise dominate a naive mean.
fn phase_averaged_precision(masses: &[u64], window: u64) -> f64 {
    let total: f64 = masses.iter().map(|m| *m as f64).sum();
    let mut survival = total;
    let (mut weighted, mut weight_sum) = (0.0_f64, 0.0_f64);
    for (phase, mass) in masses.iter().enumerate() {
        let w = survival / total;
        if w < SURVIVAL_FLOOR {
            break;
        }
        weighted += w * inference_precision(&residual_masses(masses, phase as u64), window);
        weight_sum += w;
        survival -= *mass as f64;
    }
    weighted / weight_sum
}

fn inherited() -> Vec<u64> {
    PoissonTable::new(ADOPTED_FORWARD_DELAY_MEAN_SECS).masses()
}

fn adopted() -> Vec<u64> {
    GeometricTable::new(ADOPTED_FORWARD_DELAY_MEAN_SECS).masses()
}

#[test]
fn the_family_moves_and_the_mean_does_not() {
    // The mean is NOT this change's to move. If this fails, the commit did
    // something it said it would not.
    assert_eq!(
        ADOPTED_FORWARD_DELAY_MEAN_SECS, 22,
        "the mean is Q-12's to derive; this change is family-only"
    );
    assert_eq!(ForwardDelay::adopted().mean_secs(), 22);
}

/// The tolerance separating a memoryless family from a Poisson one.
///
/// **Meaningful only because the test below proves it separates them.** An
/// earlier draft used `0.05`, which the inherited Poisson *passes*
/// (|0.2976 − 0.2505| = 0.0471) — a flatness assertion the defect satisfies
/// witnesses nothing. Measured over the supported phases: the geometric drifts
/// `1.0e-7` (quantisation) and the Poisson `0.668`, so this sits six orders of
/// magnitude below the defect and one above the noise.
const PHASE_FLATNESS_TOL: f64 = 1e-6;

#[test]
fn the_adopted_family_has_no_phase_axis_and_the_inherited_one_does() {
    let drift_adopted = max_phase_drift(&adopted(), WINDOW);
    let drift_inherited = max_phase_drift(&inherited(), WINDOW);

    println!("\n  max |drift| from phase-0 precision, over supported phases");
    println!("    adopted geometric  {drift_adopted:.9}");
    println!("    inherited Poisson  {drift_inherited:.9}");

    // The property: memorylessness IS the absence of the phase axis.
    assert!(
        drift_adopted <= PHASE_FLATNESS_TOL,
        "the memoryless draw must have no phase dependence; drift \
         {drift_adopted:.9} exceeds {PHASE_FLATNESS_TOL:e}"
    );

    // The NEGATIVE CONTROL, and the reason the tolerance means anything: the
    // same assertion pointed at the family being replaced must FAIL. If a
    // future edit widens the tolerance until the Poisson also passes, this
    // fails first and says so.
    assert!(
        drift_inherited > PHASE_FLATNESS_TOL,
        "negative control: the inherited Poisson must BREACH the flatness \
         tolerance ({drift_inherited:.9} vs {PHASE_FLATNESS_TOL:e}). If it does \
         not, the tolerance is wide enough to pass on the defect and the \
         assertion above is vacuous"
    );
}

#[test]
fn the_inherited_draw_degrades_with_arrival_phase_and_the_adopted_one_does_not() {
    let (inh, adp) = (inherited(), adopted());
    let by_phase_inh = precision_by_phase(&inh, WINDOW);
    let by_phase_adp = precision_by_phase(&adp, WINDOW);

    let worst_inh = by_phase_inh
        .iter()
        .copied()
        .fold((0, 0.0_f64), |a, x| if x.1 > a.1 { x } else { a });

    println!(
        "\n  supported phases: inherited 0..={}, adopted 0..={}",
        by_phase_inh.last().map_or(0, |x| x.0),
        by_phase_adp.last().map_or(0, |x| x.0)
    );
    println!(
        "  inherited worst: {:.4} at phase {}",
        worst_inh.1, worst_inh.0
    );

    // ~0.92 at phase 48 — F-4's "up to 93 % invertible late in the window",
    // reproduced here independently on the forward delay's own parameters.
    assert!(
        worst_inh.1 > 0.85,
        "the inherited draw should leave almost no cover at its worst \
         supported phase; got {:.4} at phase {}",
        worst_inh.1,
        worst_inh.0
    );
    assert!(
        worst_inh.0 > ADOPTED_FORWARD_DELAY_MEAN_SECS as usize,
        "the worst phase should be past the mean — the defect is in the tail, \
         which is why phases are searched rather than chosen (an earlier draft \
         sampled [0,10,20,25,30] and missed it)"
    );
}

#[test]
fn the_phase_averaged_inversion_is_the_headline_and_the_endpoints_mislead() {
    let (inh, adp) = (inherited(), adopted());

    let avg_inh = phase_averaged_precision(&inh, WINDOW);
    let avg_adp = phase_averaged_precision(&adp, WINDOW);
    let p0_inh = inference_precision(&inh, WINDOW);
    let p0_adp = inference_precision(&adp, WINDOW);

    println!("\n  measure                inherited   adopted   ratio");
    println!(
        "  phase 0 (the FLOOR)      {p0_inh:.4}    {p0_adp:.4}   {:.2}x",
        p0_inh / p0_adp
    );
    println!(
        "  phase-averaged           {avg_inh:.4}    {avg_adp:.4}   {:.2}x",
        avg_inh / avg_adp
    );

    // Phase 0 is the FLOOR of the improvement, not its size. If a summary ever
    // quotes it as the headline, this assertion is the record that the real
    // figure is larger.
    assert!(
        avg_inh / avg_adp > p0_inh / p0_adp,
        "the phase-averaged improvement ({:.2}x) must exceed the phase-0 one \
         ({:.2}x); if it does not, the Poisson's phase dependence has changed \
         and the grounds for the family fix need re-reading",
        avg_inh / avg_adp,
        p0_inh / p0_adp
    );

    // The memoryless draw has no phase axis, so its average IS its phase-0
    // value. Tolerance is the same separating one the flatness test proves.
    assert!(
        (avg_adp - p0_adp).abs() <= PHASE_FLATNESS_TOL,
        "memorylessness is the ABSENCE of the axis: averaged {avg_adp:.9} \
         against phase-0 {p0_adp:.9}"
    );
}

#[test]
fn a_zero_draw_is_reachable_and_not_clamped() {
    // Support is {0, 1, 2, ...}. Clamping the boundary would ship something
    // other than the distribution this type claims to be — the same reasoning
    // the embargo draw records for its own zero.
    assert!(
        GeometricTable::new(ADOPTED_FORWARD_DELAY_MEAN_SECS).quantized_mass(0) > 0,
        "a memoryless family must put mass at zero"
    );
}
