// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Measurement instruments — fluff_delay family.
//!
//! Part of the `propagation_measurement` suite. Run with `--nocapture` for tables.

#![allow(clippy::cast_precision_loss)]

use shekyl_relay_privacy::conformance::{
    coefficient_of_variation, inference_precision, residual_masses,
};
use shekyl_relay_privacy::{GeometricTable, PoissonTable};

/// The fluff-delay defect, measured as the attack it enables.
///
/// The embargo is a rare backstop. *This* delay is applied by every node to
/// every transaction, and its whole job is to break the link between when a
/// node received a transaction and when it relayed it. The inherited draw is
/// `std::poisson_distribution`; the Bitcoin Core timer its comment cites
/// (`PoissonNextSend`) is an exponential inter-arrival. Same name, different
/// distribution, and the difference is the entire cover.
#[test]
fn fluff_delay_inference_resistance() {
    println!("\nFluff-delay inversion: P(adversary pins receipt time to within ±w)");
    println!(
        "{:<34} {:>7} {:>12} {:>12} {:>12}",
        "delay draw", "CV", "±0.25s", "±0.5s", "±1s"
    );
    println!("{}", "-".repeat(82));

    let lambda = shekyl_relay_privacy::params::inherited::FLUFF_AVERAGE_IN_QUARTER_SECS;
    let poisson = PoissonTable::new(lambda).masses();
    let geometric = GeometricTable::new(lambda).masses();

    // Windows in quarter-second ticks.
    let windows = [1_u64, 2, 4];
    let row = |label: &str, masses: &[u64]| {
        let cv = coefficient_of_variation(masses);
        let p: Vec<f64> = windows
            .iter()
            .map(|w| inference_precision(masses, *w))
            .collect();
        println!(
            "{label:<34} {cv:>7.3} {:>12.4} {:>12.4} {:>12.4}",
            p[0], p[1], p[2]
        );
        (cv, p)
    };

    let (poisson_cv, poisson_p) = row("inherited: Poisson lambda=20", &poisson);
    let (geometric_cv, geometric_p) = row("memoryless: geometric mean=20", &geometric);

    println!(
        "\n  Both draws have the same 5s mean. Under the inherited Poisson an\n  \
         adversary who subtracts a fixed offset lands within half a second of\n  \
         the true receipt time {:.0}% of the time; under a memoryless delay of\n  \
         the same mean, {:.0}%. The ratio is a near-constant ~{:.2}x across\n  \
         every tolerance an adversary might pick, which is what you expect when\n  \
         the difference is the width of the distribution rather than an artifact\n  \
         of one window.\n\n  \
         This is not a tuning preference. The mechanism is randomized delay; a\n  \
         distribution with CV {:.2} is not providing randomized delay.\n\n  \
         Honest counterweight for the design round: the memoryless draw has its\n  \
         mode at zero, so a real share of relays go out almost immediately —\n  \
         the adversary's best single guess against it is \"barely delayed at\n  \
         all\". That is inherent to an exponential and Bitcoin Core accepts it,\n  \
         but a shifted/floored variant is a live option and this instrument is\n  \
         what should decide it.",
        poisson_p[1] * 100.0,
        geometric_p[1] * 100.0,
        poisson_p[1] / geometric_p[1],
        poisson_cv,
    );

    // The inherited Poisson is near-deterministic: 1/sqrt(20) ~ 0.224.
    assert!(
        (0.20..0.25).contains(&poisson_cv),
        "Poisson CV at lambda=20 should be ~0.22, got {poisson_cv}"
    );
    // The memoryless delay is genuinely dispersed.
    assert!(
        geometric_cv > 0.9,
        "geometric CV should be ~1, got {geometric_cv}"
    );

    // The attack is materially harder under the memoryless draw at every
    // tolerance, by a ratio that barely moves with the window. Bands are set
    // from the measurement, not from a guess about it.
    for (i, w) in windows.iter().enumerate() {
        let ratio = poisson_p[i] / geometric_p[i];
        assert!(
            (1.8..2.2).contains(&ratio),
            "window +/-{w} ticks: Poisson {:.4} vs geometric {:.4} (ratio {ratio:.2}) \
             outside the measured band",
            poisson_p[i],
            geometric_p[i]
        );
    }
    // Concretely: under the inherited draw, a half-second inversion succeeds
    // more than 40% of the time.
    assert!(
        poisson_p[1] > 0.40,
        "inherited draw: +/-0.5s inversion only {:.4}",
        poisson_p[1]
    );
    assert!(
        geometric_p[1] < 0.25,
        "memoryless draw: +/-0.5s inversion still {:.4}",
        geometric_p[1]
    );
}

/// **RD-2.** Which delay *shape* to use, decided by the metric that can
/// actually distinguish them.
///
/// Raw inversion precision cannot: it is a maximum over sliding windows, so it
/// is shift-invariant by construction, and every "add a floor" variant scores
/// identically to its unshifted twin. Conditioning on arrival phase can,
/// because the inherited fluff timer is a re-armed batching flush and a
/// transaction arriving mid-window experiences the *residual* of a draw that
/// already survived that long.
#[test]
fn residual_inversion_decides_the_distribution_shape() {
    fn uniform_masses(max_ticks: usize) -> Vec<u64> {
        vec![u64::MAX / (max_ticks as u64 + 1); max_ticks + 1]
    }
    fn with_floor(masses: &[u64], floor: usize) -> Vec<u64> {
        let mut v = vec![0_u64; floor];
        v.extend_from_slice(masses);
        v
    }

    let geometric = GeometricTable::new(20).masses();
    let poisson = PoissonTable::new(20).masses();
    let uniform = uniform_masses(40); // U[0,40] ticks, same mean 20
    let pure_shift = with_floor(&GeometricTable::new(20).masses(), 8); // mean 28
    let budgeted = with_floor(&GeometricTable::new(12).masses(), 8); // mean 20

    println!("\nInversion precision (+/-0.5s) vs. arrival phase into the flush window");
    println!(
        "{:<40} {:>9} {:>9} {:>9} {:>9}",
        "delay draw", "phase 0", "phase 10", "phase 20", "phase 30"
    );
    println!("{}", "-".repeat(80));
    let at = |m: &[u64], phase: u64| inference_precision(&residual_masses(m, phase), 2);
    let row = |label: &str, m: &[u64]| {
        println!(
            "{label:<40} {:>9.4} {:>9.4} {:>9.4} {:>9.4}",
            at(m, 0),
            at(m, 10),
            at(m, 20),
            at(m, 30)
        );
    };
    row("memoryless geometric (mean 20)", &geometric);
    row("inherited Poisson (lambda 20)", &poisson);
    row("uniform U[0,40] (mean 20)", &uniform);
    row("floor 8 + geo20, PURE SHIFT (mean 28)", &pure_shift);
    row("floor 8 + geo12, FIXED BUDGET (mean 20)", &budgeted);

    println!(
        "\n  Read three things off this table.\n\n  \
         (1) Only the memoryless row is flat. That is the actual argument for\n  \
         D-3, and it is not 'geometric inverts worst' -- uniform beats it at\n  \
         phase 0 ({:.4} vs {:.4}). It is that the flush is re-armed, so a\n  \
         transaction's delay is the residual of an in-flight draw, and only the\n  \
         memoryless family makes the residual identical to the full draw. The\n  \
         headline number then describes every transaction rather than only one\n  \
         that arrived exactly at window start.\n\n  \
         (2) The inherited Poisson degrades catastrophically with phase --\n  \
         {:.4} at phase 30. A transaction arriving late in a Poisson window is\n  \
         almost perfectly invertible. F-4 is worse than its phase-0 number said.\n\n  \
         (3) A floor is dominated in both framings. As a pure shift it scores\n  \
         identically ({:.4}) and costs 8 ticks of latency for nothing -- every\n  \
         inversion metric is shift-invariant, so no measurement can prefer it.\n  \
         Held to the same mean budget it is measurably worse ({:.4} vs {:.4}),\n  \
         because the floor buys its offset by narrowing the random part.",
        at(&uniform, 0),
        at(&geometric, 0),
        at(&poisson, 30),
        at(&pure_shift, 0),
        at(&budgeted, 0),
        at(&geometric, 0),
    );

    // (1) Memorylessness: flat across every phase.
    let g0 = at(&geometric, 0);
    for phase in [5_u64, 10, 20, 30, 50] {
        assert!(
            (at(&geometric, phase) - g0).abs() < 1e-9,
            "geometric residual moved at phase {phase}: {} vs {g0}",
            at(&geometric, phase)
        );
    }
    // Uniform wins at phase 0 and loses by phase 30 -- the adversarial reading
    // of D-3, and its refutation, both pinned.
    assert!(
        at(&uniform, 0) < g0,
        "uniform should invert better at phase 0"
    );
    assert!(
        at(&uniform, 30) > g0 * 2.0,
        "uniform should degrade past geometric by phase 30: {:.4} vs {g0:.4}",
        at(&uniform, 30)
    );

    // (2) Poisson collapses with phase.
    assert!(
        at(&poisson, 30) > 0.9,
        "inherited Poisson at phase 30 should be near-fully invertible, got {:.4}",
        at(&poisson, 30)
    );

    // (3) A floor is dominated either way.
    assert!(
        (at(&pure_shift, 0) - g0).abs() < 1e-9,
        "a pure shift must be invisible to this metric: {:.4} vs {g0:.4}",
        at(&pure_shift, 0)
    );
    assert!(
        at(&budgeted, 0) > g0,
        "a floor at fixed mean must score worse: {:.4} vs {g0:.4}",
        at(&budgeted, 0)
    );
}
