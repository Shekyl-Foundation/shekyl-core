//! §14.4-round riders (ARCHIVAL_BOND_WI4_MEASUREMENT.md).
//!
//! Four items ride the partition-adversary round on the same generator:
//!
//! 1. **N-sweep** (§16.7 item 4, added at review closure 2026-07-06 §17.1):
//!    the main gate re-graded at `N ∈ {10, 20, 50}` in-model, a-priori bound
//!    `r < 2` at **every** swept `N`. The ratio form is N-invariant by
//!    definition; whether the *measured* `r(N)` is flat is an empirical
//!    property of the score distribution's tail — a measured `r` growing with
//!    `N` means the `N = 10` pass was a small-candidate-set artifact, a
//!    redesign signal, never absorbed.
//! 2. **M6.2 indirect-channel coupling control** (§16.7 item 2, in the §5
//!    controls family): fails the run as INVALID if the synthetic generator
//!    ever produces session-independent chain-visible timing. A-priori form:
//!    the **blind** arm at `window = 0` must sit at least `2×` above the
//!    `1/N` chance floor (reference `0.237` vs chance `0.10` at `N = 10`); a
//!    future refactor that decouples the generator trips this control instead
//!    of silently producing the hollow pass §4.1.1 warns about.
//! 3. **Attribute-stratified grading** (§18.3, **narrowed by §18.8**): the
//!    cleartext bond attributes (`holdings` scaling `bond_floor`) are graded
//!    as candidate **bridge** axes — *does the attribute correlate with a
//!    user-side observable?* — never as crowds `P` hides in (`P` is public;
//!    the §18.3 intrinsic-stratification claim is retracted). Deployed
//!    attribute draws are independent of the user's session cadence, so the
//!    bridge statistic must sit at its permutation null; a coupled positive
//!    control (holdings driving session period) must bite, per the §5
//!    tripwire-must-bite shape.
//! 4. **Lifetime-accumulation sweep** (§18.4, re-anchored by §18.8): each `P`
//!    event is one more timing sample against the user's clock, so cumulative
//!    exposure is `1 − (1 − p)^events`, monotone in lifetime. Persona
//!    lifetime is a swept axis with the founder/long-lived end as the
//!    pessimistic anchor (the §6 pessimistic-distribution discipline extended
//!    to longevity). Reported per §18.4's own compounding form anchored at
//!    the measured per-post posture `p`; the doc commits no per-lifetime
//!    numeric bound — the row exists so the accumulation is *visible*, not
//!    averaged away.

use serde::Serialize;

use crate::gf7_timeline::{grade, ArmResult, SynthParams, RATIO_BOUND};
use crate::standoff::SplitMix64;

/// The swept anonymity-set sizes (§16.7 item 4).
pub const SWEPT_N: [usize; 3] = [10, 20, 50];

/// M6.2's a-priori floor multiplier: blind@window-0 must sit at least this
/// factor above the `1/N` chance floor.
const COUPLING_FLOOR_MULT: f64 = 2.0;

/// Swept persona lifetimes (observable `P` events). The last entry is the
/// founder/long-lived pessimistic anchor (§18.4: founders are long-lived by
/// construction, so they sit at the accumulation end of the axis).
const LIFETIME_EVENTS: [u32; 6] = [1, 2, 6, 12, 26, 52];

/// Bridge-control thresholds, following the §5 control-family precedent
/// (positive must bite decisively; negative within a small tolerance of
/// chance) — the §18.3 disposition names the conditional question, not
/// numeric bars, so the bars reuse the established control shape.
const BRIDGE_POSITIVE_MIN: f64 = 0.50;
const BRIDGE_NULL_TOL: f64 = 0.05;

/// One N-sweep row: the three arms re-graded at a swept `N`.
#[derive(Serialize)]
pub struct NSweepRow {
    pub n: usize,
    pub baseline: f64,
    pub blind: ArmResult,
    pub modeled_s3: ArmResult,
    pub lr_stress: ArmResult,
    /// `r < 2` for every graded arm at this `N`.
    pub pass: bool,
}

/// The M6.2 coupling-control verdict.
#[derive(Serialize)]
pub struct CouplingControl {
    pub n: usize,
    /// Blind-arm `P(link)` at `window = 0`.
    pub blind_p_link: f64,
    /// The committed floor: `2/N`.
    pub floor: f64,
    /// `blind_p_link ≥ floor` — the generator still couples chain-visible
    /// timing to the session clock.
    pub passed: bool,
}

/// The §18.3 (narrowed) bridge grade for one attribute-coupling scenario.
#[derive(Serialize)]
pub struct BridgeRow {
    pub scenario: &'static str,
    /// Mean `|Pearson corr(holdings, session period)|` over trials.
    pub bridge_stat: f64,
    /// Permutation-null mean of the same statistic.
    pub null_mean: f64,
    pub passed: bool,
    pub expectation: &'static str,
}

/// One lifetime-accumulation row (§18.4's own compounding form).
#[derive(Serialize)]
pub struct LifetimeRow {
    pub events: u32,
    /// `1 − (1 − p)^events` at the measured per-post posture `p`.
    pub cumulative: f64,
    /// This row is the founder/long-lived pessimistic anchor.
    pub founder_anchor: bool,
}

/// The riders report: every §14.4-round rider in one graded artifact.
#[derive(Serialize)]
pub struct RidersReport {
    pub trials: u32,
    pub ratio_bound: f64,
    pub n_sweep: Vec<NSweepRow>,
    pub coupling: CouplingControl,
    pub bridge: Vec<BridgeRow>,
    /// The per-post `p` the lifetime sweep compounds (the posture point's
    /// strongest graded arm — pessimistic per §6).
    pub lifetime_per_post_p: f64,
    pub lifetime: Vec<LifetimeRow>,
    /// Computed conjunction over the committed bounds (§9 criterion 9): the
    /// N-sweep `r < 2` at every swept `N`, the M6.2 floor, and the bridge
    /// validity pair. The lifetime sweep is a reported measurement (no
    /// committed numeric bound in the doc).
    pub status: String,
}

/// Pearson correlation magnitude between two equal-length samples.
fn abs_pearson(x: &[f64], y: &[f64]) -> f64 {
    let n = x.len() as f64;
    let mx = x.iter().sum::<f64>() / n;
    let my = y.iter().sum::<f64>() / n;
    let mut sxy = 0.0;
    let mut sxx = 0.0;
    let mut syy = 0.0;
    for (a, b) in x.iter().zip(y.iter()) {
        sxy += (a - mx) * (b - my);
        sxx += (a - mx) * (a - mx);
        syy += (b - my) * (b - my);
    }
    if sxx <= 0.0 || syy <= 0.0 {
        return 0.0;
    }
    (sxy / (sxx * syy).sqrt()).abs()
}

/// Draw one pair's `(holdings, session period)` under the deployed law:
/// holdings is an economic input (skewed toward small holders, per the §18.3
/// value↔rarity observation), drawn **independently** of the user's session
/// cadence — there is no code path from `CompleteTree` size to the wallet's
/// session clock.
fn draw_attrs_deployed(rng: &mut SplitMix64) -> (f64, f64) {
    // Skewed holdings: 1 + min of two uniforms squared — most personas small,
    // a thin large tail (the §18.3 "most-valuable personas are rarest" shape).
    let a = rng.next_u64() % 10;
    let b = rng.next_u64() % 10;
    let holdings = 1 + a.min(b) * a.min(b);
    // Session period drawn on the steady-state range, independent of holdings.
    let period = 40 + rng.next_u64() % 361;
    (holdings as f64, period as f64)
}

/// The coupled positive control: holdings *drives* the session period (a
/// hypothetical build where large holders run proportionally longer wallet
/// sessions). Marked non-production; exists so the bridge instrument's bite
/// is demonstrated, per the §5 tripwire-must-bite shape.
fn draw_attrs_coupled(rng: &mut SplitMix64) -> (f64, f64) {
    let (holdings, _) = draw_attrs_deployed(rng);
    // Period is a deterministic ramp in holdings plus small jitter.
    let period = 40.0 + holdings * 4.0 + (rng.next_u64() % 41) as f64;
    (holdings, period)
}

/// Grade one bridge scenario: mean `|corr|` over `trials` worlds of `n` pairs
/// each, against a permutation null (holdings column shuffled within-world).
fn grade_bridge(
    coupled: bool,
    n: usize,
    trials: u32,
    perms: u32,
    rng: &mut SplitMix64,
) -> (f64, f64) {
    let mut stat_sum = 0.0;
    let mut null_sum = 0.0;
    for _ in 0..trials {
        let pairs: Vec<(f64, f64)> = (0..n)
            .map(|_| {
                if coupled {
                    draw_attrs_coupled(rng)
                } else {
                    draw_attrs_deployed(rng)
                }
            })
            .collect();
        let holdings: Vec<f64> = pairs.iter().map(|p| p.0).collect();
        let periods: Vec<f64> = pairs.iter().map(|p| p.1).collect();
        stat_sum += abs_pearson(&holdings, &periods);

        let mut shuffled = holdings.clone();
        for _ in 0..perms {
            for i in (1..shuffled.len()).rev() {
                let j = (rng.next_u64() as usize) % (i + 1);
                shuffled.swap(i, j);
            }
            null_sum += abs_pearson(&shuffled, &periods);
        }
    }
    (
        stat_sum / trials as f64,
        null_sum / (trials as u64 * perms as u64) as f64,
    )
}

/// Run every rider and compute the conjunction verdict.
pub fn run_riders_report() -> RidersReport {
    let trials = 400u32;
    let mut rng = SplitMix64(0x9A7C_1667_2C2B_0004);
    let posture = SynthParams::posture();

    // Rider 4 (§16.7 item 4): the N-sweep. Same generator, one extra axis.
    let n_sweep: Vec<NSweepRow> = SWEPT_N
        .iter()
        .map(|&n| {
            let (blind, s3, lr) = grade(&posture, n, trials, &mut rng);
            let blind = ArmResult::new(blind, n);
            let modeled_s3 = ArmResult::new(s3, n);
            let lr_stress = ArmResult::new(lr, n);
            let pass = blind.clears_bound && modeled_s3.clears_bound && lr_stress.clears_bound;
            NSweepRow {
                n,
                baseline: 1.0 / n as f64,
                blind,
                modeled_s3,
                lr_stress,
                pass,
            }
        })
        .collect();

    // Rider 2 (§16.7 item 2): M6.2 coupling control — blind@window-0 vs 2/N.
    let coupling_n = 10usize;
    let zero_window = SynthParams {
        window: 0,
        ..posture
    };
    let (blind_p, _, _) = grade(&zero_window, coupling_n, trials, &mut rng);
    let floor = COUPLING_FLOOR_MULT / coupling_n as f64;
    let coupling = CouplingControl {
        n: coupling_n,
        blind_p_link: blind_p,
        floor,
        passed: blind_p >= floor,
    };

    // Rider 3 (§18.3 narrowed by §18.8): attribute-bridge grading.
    let (dep_stat, dep_null) = grade_bridge(false, 50, 200, 20, &mut rng);
    let (cpl_stat, cpl_null) = grade_bridge(true, 50, 200, 20, &mut rng);
    let bridge = vec![
        BridgeRow {
            scenario: "deployed (holdings ⊥ session clock)",
            bridge_stat: dep_stat,
            null_mean: dep_null,
            passed: (dep_stat - dep_null).abs() < BRIDGE_NULL_TOL,
            expectation: "|corr - null| < 0.05 (no attribute→user-side bridge)",
        },
        BridgeRow {
            scenario: "coupled control (holdings drives period)",
            bridge_stat: cpl_stat,
            null_mean: cpl_null,
            passed: cpl_stat >= BRIDGE_POSITIVE_MIN,
            expectation: "corr >= 0.50 (the bridge instrument must bite)",
        },
    ];

    // Rider 1 of §18.4: lifetime accumulation at the posture per-post p —
    // pessimistic arm choice: the strongest graded arm at the N = 10 posture
    // row (the stress panel upper-bounds the fielded correlators).
    let posture_row = &n_sweep[0];
    let per_post_p = posture_row
        .blind
        .p_link
        .max(posture_row.modeled_s3.p_link)
        .max(posture_row.lr_stress.p_link);
    let lifetime: Vec<LifetimeRow> = LIFETIME_EVENTS
        .iter()
        .map(|&events| LifetimeRow {
            events,
            cumulative: 1.0 - (1.0 - per_post_p).powi(events as i32),
            founder_anchor: events == *LIFETIME_EVENTS.last().unwrap(),
        })
        .collect();

    // §9 criterion 9: the verdict is a computed conjunction over the
    // committed bounds, never narrated.
    let n_sweep_ok = n_sweep.iter().all(|r| r.pass);
    let bridge_ok = bridge.iter().all(|b| b.passed);
    let status = if n_sweep_ok && coupling.passed && bridge_ok {
        "PASS (N-sweep r < 2 at every swept N; M6.2 coupling floor held; \
         bridge validity pair held)"
            .to_string()
    } else if !coupling.passed {
        "INVALID (M6.2: generator produced session-independent chain-visible \
         timing — the hollow-pass tripwire fired)"
            .to_string()
    } else if !bridge_ok {
        "INVALID (bridge validity pair failed — instrument cannot certify \
         the deployed no-bridge claim)"
            .to_string()
    } else {
        "FAIL (measured r grew past the bound at a swept N — the N = 10 pass \
         was a small-candidate-set artifact; redesign signal, never absorbed)"
            .to_string()
    };

    RidersReport {
        trials,
        ratio_bound: RATIO_BOUND,
        n_sweep,
        coupling,
        bridge,
        lifetime_per_post_p: per_post_p,
        lifetime,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full riders artifact holds its committed bounds at a test-scale
    /// run: `r < 2` at every swept `N` (the ratio bar is N-invariant and the
    /// measured `r(N)` must not grow), the M6.2 coupling floor bites, the
    /// bridge pair certifies (deployed at null, coupled control decisive),
    /// and the lifetime sweep is monotone with the founder anchor last.
    #[test]
    fn riders_hold_their_committed_bounds() {
        let r = run_riders_report();

        assert_eq!(r.n_sweep.len(), SWEPT_N.len());
        for row in &r.n_sweep {
            assert!(
                row.pass,
                "r < 2 must hold at swept N = {} (blind {:.3}, s3 {:.3}, lr {:.3})",
                row.n, row.blind.ratio, row.modeled_s3.ratio, row.lr_stress.ratio
            );
        }

        assert!(
            r.coupling.passed,
            "M6.2: blind@window-0 {:.3} must sit above the 2/N floor {:.3}",
            r.coupling.blind_p_link, r.coupling.floor
        );

        assert!(r.bridge[0].passed, "deployed bridge stat must sit at null");
        assert!(r.bridge[1].passed, "coupled bridge control must bite");

        let cums: Vec<f64> = r.lifetime.iter().map(|l| l.cumulative).collect();
        assert!(
            cums.windows(2).all(|w| w[1] >= w[0]),
            "cumulative exposure must be monotone in lifetime"
        );
        assert!(r.lifetime.last().unwrap().founder_anchor);
        assert!(r.status.starts_with("PASS"), "status: {}", r.status);
    }
}
