//! Leg-(b) wall-clock sweep-phase arm (`ARCHIVAL_BOND_WI4_MEASUREMENT.md`
//! §19; the WI-3 §3.2 part-3 channel).
//!
//! # What this grades
//!
//! The block-time gate cannot see the channel the dispersal draw exists to
//! defend: live `BondPostDispatched.at` is the due *block*, dispersal is
//! sub-block (`U[0, 60s)`), so every block-resolution timeline — synthesized
//! or live — reproduces the `dispersal = 0` surface (measurement doc §13.3).
//! This module models the wall-clock layer **sub-block** and grades the
//! sweep-phase channel directly: every dispatch fired "at the tick" is
//! phase-locked to the wallet's sweep cadence, a wallet-level fingerprint
//! shared across the wallet's personas (WI-3 §3.2 part 3); the dispersal
//! draw is the defense, and its value is graded here, not assumed.
//!
//! # Emission disposition (measurement doc §19.1)
//!
//! Harness timestamp, **not** a finer hook: the hooks payload ban
//! (`ARCHIVAL_BOND_2C_GF7_HOOKS.md` §3 — logical time only, a wall-clock
//! event field is a production-fingerprint hazard) stays intact. This
//! module *is* the harness-timestamp form for the pre-live grade; the
//! sealing form is receipt-side timestamping by the sim-owned observer over
//! the live dispatch driver, named as the carrier in §19.1 and tracked in
//! `docs/FOLLOWUPS.md`. The grade below is therefore PROVISIONAL by
//! construction, exactly like every §7 synthesis conclusion.
//!
//! # A-priori bound (committed §19.2, before this code existed)
//!
//! Sibling identification: given one persona of a two-persona wallet among
//! `N` candidates (the rest on independent wallets), the observer names the
//! sibling. Chance is `1/(N−1)`; the committed bound is the §3.2 derivation
//! instantiated on this channel — `r = P(link)·(N−1) < 2`, additive
//! advantage below one excess de-anonymization, `r < 1` pre-rejected
//! (§13.4), no cross-subsidy from the steady-state margin (§13.5).
//!
//! # The §19.5 strength tripwire
//!
//! At `dispersal_bound = T` the arrival phase `(φ + d) mod T` is exactly
//! uniform, so the production posture is *expected* to pass by construction
//! of the draw. The informational content is the sub-`T` cliff — and a run
//! in which the half-dispersal row at the accumulation ceiling (`T/2`,
//! `m = 52`) also clears the bound means the modeled observer is weaker
//! than the channel: the run is graded **INVALID**, computed, never
//! narrated (criterion 9.9 shape).

use serde::Serialize;
use shekyl_standoff::bounded_uniform;

use crate::standoff::SplitMix64;

/// Wallet sweep-tick interval in milliseconds — the sim-side mirror of
/// `DEFAULT_PSCAN_CADENCE` (`shekyl-engine-core` `pscan/start.rs`,
/// `Duration::from_secs(60)`, verified at source 2026-07-11). The sim crate
/// deliberately does not depend on the engine crate (no-emit guard, hooks
/// §4), so the value is mirrored with this pointer rather than imported.
pub const TICK_MS: u64 = 60_000;

/// The committed a-priori advantage-ratio bound (measurement doc §19.2):
/// `r = P(link)·(N−1) < RATIO_BOUND`. Same §3.2 derivation and the same
/// non-tunability discipline as the main gate's bound: committed in the
/// reviewed doc before this module existed.
pub const RATIO_BOUND: f64 = 2.0;

/// Positive-control floor: naked phase-locking (`dispersal = 0`, `m ≥ 4`)
/// must link at least this well or the arm is blind (§19.3 control 1).
const POSITIVE_CONTROL_MIN: f64 = 0.80;

/// Negative-control tolerance around chance for the decoupled-generator
/// tripwire (§19.3 control 2; M6.2 shape).
const NEGATIVE_CONTROL_TOL: f64 = 0.05;

/// One graded scenario point.
struct Scenario {
    /// Candidate personas (probe + `n − 1` candidates; sibling among them).
    n: usize,
    /// Personas sharing the probe's wallet, probe included (`K` of §19.4).
    wallet_size: usize,
    /// Observed posts per persona (`m` of §19.4).
    posts: usize,
    /// Dispersal-draw bound in ms (`0` disables, matching the live driver's
    /// `Duration::ZERO` arm).
    dispersal_ms: u64,
    /// Negative control: sever the wallet — every persona gets an
    /// independent phase, so the ground-truth sibling carries no
    /// fingerprint (§19.3 control 2).
    decoupled: bool,
}

/// Draw one persona's observed arrival phases. All personas of one wallet
/// share `phase`; each post adds a fresh dispersal draw, matching the live
/// driver's inclusive integer-ms `bounded_uniform(bound − 1)` shape
/// (`pscan/dispatch.rs` phase 3; §7 distributional parity). Tick indices
/// (`k·T`) drop out of the statistic (`mod T`), so they are not modeled.
fn persona_phases(rng: &mut SplitMix64, phase: u64, posts: usize, dispersal_ms: u64) -> Vec<u64> {
    (0..posts)
        .map(|_| {
            let d = if dispersal_ms > 0 {
                bounded_uniform(rng, dispersal_ms - 1)
            } else {
                0
            };
            (phase + d) % TICK_MS
        })
        .collect()
}

/// Circular mean angle of a persona's phases, in radians. `m ≥ 1` by
/// construction of the sweep surface.
fn circular_mean(phases: &[u64]) -> f64 {
    let (mut s, mut c) = (0.0f64, 0.0f64);
    for &p in phases {
        let theta = (p as f64) * std::f64::consts::TAU / (TICK_MS as f64);
        s += theta.sin();
        c += theta.cos();
    }
    s.atan2(c)
}

/// Wrapped circular distance between two mean angles, in `[0, π]`.
fn circular_distance(a: f64, b: f64) -> f64 {
    let d = (a - b).rem_euclid(std::f64::consts::TAU);
    d.min(std::f64::consts::TAU - d)
}

/// One trial: synthesize the wall-clock layer, run the phase observer,
/// return whether it named the true sibling.
///
/// Persona 0 is the probe; persona 1 is the true sibling (personas
/// `1..wallet_size` share the probe's wallet); personas `wallet_size..n`
/// sit on independent wallets. The observer estimates each persona's
/// cadence phase by circular mean and names the candidate closest to the
/// probe — the strongest zero-noise network-position observer of the
/// modeled channel (§19.2; the §4.3.1 in-model ceiling pin applies).
fn trial(rng: &mut SplitMix64, sc: &Scenario) -> bool {
    let probe_wallet_phase = rng.next_u64() % TICK_MS;
    let mut phases: Vec<Vec<u64>> = Vec::with_capacity(sc.n);
    for i in 0..sc.n {
        let wallet_phase = if i < sc.wallet_size && !sc.decoupled {
            probe_wallet_phase
        } else {
            rng.next_u64() % TICK_MS
        };
        phases.push(persona_phases(rng, wallet_phase, sc.posts, sc.dispersal_ms));
    }
    let probe = circular_mean(&phases[0]);
    let mut best = 1usize;
    let mut best_d = f64::INFINITY;
    for (i, p) in phases.iter().enumerate().skip(1) {
        let d = circular_distance(probe, circular_mean(p));
        if d < best_d {
            best_d = d;
            best = i;
        }
    }
    best == 1
}

/// Monte-Carlo `P(link)` over `trials` independent syntheses.
fn p_link(rng: &mut SplitMix64, sc: &Scenario, trials: u32) -> f64 {
    let hits = (0..trials).filter(|_| trial(rng, sc)).count();
    hits as f64 / trials as f64
}

/// One graded row of the §19.4 sweep surface.
#[derive(Serialize)]
pub struct WallclockRow {
    pub group: &'static str,
    pub dispersal_ms: u64,
    pub posts_per_persona: usize,
    pub n: usize,
    pub wallet_size: usize,
    /// Chance floor `1/(n−1)` (sibling identification, §19.2).
    pub baseline: f64,
    pub p_link: f64,
    /// `p_link · (n−1)` against [`RATIO_BOUND`].
    pub ratio: f64,
    pub clears_bound: bool,
    /// Production-posture row (`dispersal = T`, `K = 2`): participates in
    /// the criterion-9.9 conjunction at every swept `N`.
    pub gate_relevant: bool,
}

/// A §19.3 control result.
#[derive(Serialize)]
pub struct WallclockControl {
    pub name: &'static str,
    pub p_link: f64,
    pub baseline: f64,
    pub expectation: &'static str,
    pub passed: bool,
}

/// The leg-(b) wall-clock section of the measurement report.
#[derive(Serialize)]
pub struct WallclockLegReport {
    /// Always true here: this is the harness-timestamp synthesis grade;
    /// leg (b) closes only at the §19.1 sealing form (receipt-timestamped
    /// live-driver re-run), tracked in `docs/FOLLOWUPS.md`.
    pub provisional: bool,
    pub tick_ms: u64,
    pub ratio_bound: f64,
    pub trials: u32,
    pub controls_valid: bool,
    /// §19.5 tripwire: the `T/2` row at the accumulation ceiling must FAIL
    /// the bound, or the modeled observer is weaker than the channel and
    /// the run is INVALID.
    pub observer_strength_ok: bool,
    pub status: String,
    pub controls: Vec<WallclockControl>,
    pub rows: Vec<WallclockRow>,
    /// Computed conjunction input for the criterion-9.9 gate verdict:
    /// controls valid ∧ strength tripwire armed ∧ every gate-relevant row
    /// clears the bound.
    pub pass: bool,
}

/// Run config (trials per row; §19.4 pins 1 000 with the SE derivation).
const TRIALS: u32 = 1_000;
const SEED: u64 = 0x1E9B_0B57_2026_0711;

/// The §19.4 sweep surface, pre-committed. Gate rows are the production
/// posture (`dispersal = T`, `K = 2`) at every swept `N` and every `m`;
/// everything else is the pre-committed context bracket.
fn sweep() -> Vec<Scenario> {
    let mut rows = Vec::new();
    // Dispersal × accumulation grid at N = 10, K = 2.
    for &dispersal_ms in &[0, TICK_MS / 4, TICK_MS / 2, TICK_MS, 2 * TICK_MS] {
        for &posts in &[1usize, 4, 12, 52] {
            rows.push(Scenario {
                n: 10,
                wallet_size: 2,
                posts,
                dispersal_ms,
                decoupled: false,
            });
        }
    }
    // N-sweep rider shape (§16.7): production posture at N ∈ {20, 50}.
    for &n in &[20usize, 50] {
        for &posts in &[1usize, 4, 12, 52] {
            rows.push(Scenario {
                n,
                wallet_size: 2,
                posts,
                dispersal_ms: TICK_MS,
                decoupled: false,
            });
        }
    }
    // K = 5 context row (per-principal promotion stays GF-4's conditional).
    rows.push(Scenario {
        n: 10,
        wallet_size: 5,
        posts: 52,
        dispersal_ms: TICK_MS,
        decoupled: false,
    });
    rows
}

fn grade_row(rng: &mut SplitMix64, sc: &Scenario, trials: u32) -> WallclockRow {
    let baseline = 1.0 / (sc.n - 1) as f64;
    let p = p_link(rng, sc, trials);
    let ratio = p * (sc.n - 1) as f64;
    let gate_relevant = sc.dispersal_ms == TICK_MS && sc.wallet_size == 2 && !sc.decoupled;
    WallclockRow {
        group: if sc.wallet_size != 2 {
            "context-k"
        } else if sc.n != 10 {
            "n-sweep"
        } else {
            "dispersal-sweep"
        },
        dispersal_ms: sc.dispersal_ms,
        posts_per_persona: sc.posts,
        n: sc.n,
        wallet_size: sc.wallet_size,
        baseline,
        p_link: p,
        ratio,
        clears_bound: ratio < RATIO_BOUND,
        gate_relevant,
    }
}

fn run_controls(rng: &mut SplitMix64, trials: u32) -> (Vec<WallclockControl>, bool) {
    let n = 10usize;
    let baseline = 1.0 / (n - 1) as f64;

    // §19.3 control 1: naked phase-locking must be caught.
    let pos = Scenario {
        n,
        wallet_size: 2,
        posts: 4,
        dispersal_ms: 0,
        decoupled: false,
    };
    let pos_p = p_link(rng, &pos, trials);
    let pos_ok = pos_p >= POSITIVE_CONTROL_MIN;

    // §19.3 control 2: severed wallet must come back at chance.
    let neg = Scenario {
        n,
        wallet_size: 2,
        posts: 52,
        dispersal_ms: TICK_MS,
        decoupled: true,
    };
    let neg_p = p_link(rng, &neg, trials);
    let neg_ok = (neg_p - baseline).abs() < NEGATIVE_CONTROL_TOL;

    let controls = vec![
        WallclockControl {
            name: "phase-lock caught (positive)",
            p_link: pos_p,
            baseline,
            expectation: "P(link) >= 0.80 at dispersal=0, m=4 (the tripwire must bite)",
            passed: pos_ok,
        },
        WallclockControl {
            name: "severed wallet (negative)",
            p_link: neg_p,
            baseline,
            expectation: "P(link) within 0.05 of 1/(N-1) (generator-coupling tripwire)",
            passed: neg_ok,
        },
    ];
    (controls, pos_ok && neg_ok)
}

/// Run the leg-(b) arm and compute its verdict (measurement doc §19.6).
pub fn run_wallclock_leg() -> WallclockLegReport {
    run_with(TRIALS, SEED)
}

fn run_with(trials: u32, seed: u64) -> WallclockLegReport {
    let mut rng = SplitMix64(seed);
    let (controls, controls_valid) = run_controls(&mut rng, trials);

    let rows: Vec<WallclockRow> = sweep()
        .iter()
        .map(|sc| grade_row(&mut rng, sc, trials))
        .collect();

    // §19.5 strength tripwire: the half-dispersal row at the accumulation
    // ceiling must FAIL the bound. If the observer cannot break half
    // dispersal with 52 posts, it is weaker than the channel and this
    // run's production pass counts for nothing.
    let observer_strength_ok = rows
        .iter()
        .filter(|r| r.dispersal_ms == TICK_MS / 2 && r.posts_per_persona == 52 && r.n == 10)
        .all(|r| !r.clears_bound);

    let gate_rows_pass = rows
        .iter()
        .filter(|r| r.gate_relevant)
        .all(|r| r.clears_bound);
    let pass = controls_valid && observer_strength_ok && gate_rows_pass;

    let status = if !controls_valid {
        "INVALID (leg-b controls failed — the run counts for nothing)".to_string()
    } else if !observer_strength_ok {
        "INVALID (modeled observer weaker than the channel — §19.5 tripwire)".to_string()
    } else if gate_rows_pass {
        "PROVISIONAL-PASS (harness-timestamp synthesis; sealing form §19.1 open)".to_string()
    } else {
        "PROVISIONAL-FAIL (dispersal-redesign signal; pre-live)".to_string()
    };

    WallclockLegReport {
        provisional: true,
        tick_ms: TICK_MS,
        ratio_bound: RATIO_BOUND,
        trials,
        controls_valid,
        observer_strength_ok,
        status,
        controls,
        rows,
        pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast, deterministic config for the structural tests; the binary runs
    /// the full §19.4 surface.
    fn small() -> WallclockLegReport {
        run_with(200, 0x1E9B_7E57)
    }

    /// §19.3: both controls must bite on the committed surface.
    #[test]
    fn controls_bite() {
        let r = small();
        assert!(
            r.controls_valid,
            "leg-b controls failed: {:?}",
            r.controls
                .iter()
                .map(|c| (c.name, c.p_link))
                .collect::<Vec<_>>()
        );
    }

    /// §19.5: production posture passes by construction of the draw AND the
    /// sub-T cliff exists (half dispersal at the accumulation ceiling is
    /// broken by the observer). Both directions pinned so a synthesis or
    /// observer regression is caught structurally, not by eyeballing.
    #[test]
    fn production_passes_and_sub_tick_cliff_exists() {
        let r = small();
        assert!(r.observer_strength_ok, "§19.5 tripwire: observer too weak");
        assert!(
            r.rows.iter().filter(|row| row.gate_relevant).count() > 0,
            "no gate-relevant rows"
        );
        assert!(
            r.rows
                .iter()
                .filter(|row| row.gate_relevant)
                .all(|row| row.clears_bound),
            "production posture unexpectedly fails in-model"
        );
        assert!(r.pass, "leg-b verdict expected to pass: {}", r.status);
    }

    /// The zero-dispersal anchor must be catastrophic at any accumulation —
    /// the negative anchor is never the graded conclusion (§7), but it must
    /// stay catastrophic or the model lost the channel.
    #[test]
    fn zero_dispersal_anchor_is_catastrophic() {
        let r = small();
        for row in r.rows.iter().filter(|row| row.dispersal_ms == 0) {
            assert!(
                row.p_link > 0.9,
                "dispersal=0 m={} expected near-certain linking, got {}",
                row.posts_per_persona,
                row.p_link
            );
        }
    }

    /// Full-period dispersal makes the phase exactly uniform: over-dispersal
    /// (`2T`) must buy nothing beyond `T` (§19.5's no-op pin).
    #[test]
    fn over_dispersal_is_a_noop() {
        let r = small();
        let at = |d: u64, m: usize| {
            r.rows
                .iter()
                .find(|row| row.dispersal_ms == d && row.posts_per_persona == m && row.n == 10)
                .map(|row| row.ratio)
                .expect("row present")
        };
        for &m in &[1usize, 4, 12, 52] {
            let (t, t2) = (at(TICK_MS, m), (at(2 * TICK_MS, m)));
            assert!(
                t < RATIO_BOUND && t2 < RATIO_BOUND,
                "both T and 2T rows must clear (m={m}): T→{t:.2}, 2T→{t2:.2}"
            );
        }
    }
}
