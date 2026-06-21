// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Funding-seam **cover-amount** anonymity model — the amount-axis sibling of
//! the entry-standoff timing model (`standoff.rs`). Where the standoff
//! decorrelates *when* `P` funds and enters, the cover decorrelates *how much*
//! the principal sent: the principal transfers `A = bond_floor + cover` to `P`,
//! and an observer who learns `A` out-of-band (`ARCHIVAL_COVER_DRAW.md` §1)
//! tries to match it to a public bond via `A − bond_floor(bond) ∈ [C_min,
//! C_max]?`.
//!
//! This harness is the **C1 first-cut sizing pass** (`ARCHIVAL_COVER_DRAW.md`
//! §7): it sweeps the **lattice dial** `k = (C_max − C_min) / floor` — the
//! number of shard-count rungs the cover blurs across — and reports the
//! effective anonymity set, its thin-cover tail, and the **regressive capital
//! tax** the bound imposes, so the err-large genesis bound (§2.5) can be picked
//! at the knee rather than the ceiling.
//!
//! ## The lattice geometry (§7.1)
//!
//! Rungs sit at `bond_floor = floor · s` where `s = Σ|holdings|` is the shard
//! count and `floor = ARCHIVAL_BOND_FLOOR_ATOMIC = 0.75 SKL`. For a *realized*
//! cover the attacker's candidate set is the **contiguous window of `k+1` rungs
//! straddling the true rung `s_P`**, with its split (rungs below vs above `s_P`)
//! sliding with the draw: a cover near `C_max` opens the window mostly *below*
//! `s_P`, near `C_min` mostly *above*. Uniform cover (DQ1) makes the
//! per-candidate likelihood flat, so the **effective** anonymity set equals the
//! raw count of stakers in the window (the §1.2 inverse-participation-ratio
//! collapses to a count) — which is *why* uniform is the answer, not merely a
//! preference: any non-uniform shape would hand the attacker posterior
//! concentration on the true rung.
//!
//! ## The load-bearing pre-testnet assumption is the per-rung *density*, swept
//!
//! The staking sim pins the per-staker *mean* shard count (thin `N_P = 17 → ≈9`,
//! lean `≈60`; `STAKER_ARCHIVAL_SIM.md:676,720`) but **not** the spread of
//! counts across stakers — and that spread is exactly what decides how many
//! stakers a `k`-rung window gathers. So we bracket it with two population
//! shapes (clustered vs dispersed), the cover analogue of the standoff sweeping
//! its background rate. The real seating archetype `min(⌊capital/bond⌋,
//! ⌊storage/shard⌋)` tends to *concentrate* (a min pushes mass toward a mode),
//! so the truth is likely nearer the clustered bracket — but err-large (§2.5)
//! sizes against the **dispersed** thin-`N_P` corner, never the optimistic one.
//!
//! ## What this is NOT (mirrors the standoff's conditionality)
//!
//! - **Amount-marginal — an upper bound on anonymity, so a *lower* bound on
//!   `k`.** The real candidate set is the *intersection* of amount-consistent
//!   **and** timing-consistent bonds (§1.1); the entry-gap standoff thins it
//!   further. With `timing_retain = 1.0` this harness reports the amount-only
//!   set, which **over**-counts cover — so a `k` sized off it alone is too
//!   small; the joint pass can only require **more**. The `timing_retain` knob
//!   models the §1.1 intersection (each amount-decoy is kept with that
//!   probability), so the joint set can be sized directly; the err-large
//!   recommendation uses it, not the marginal.
//! - **Uniform cover, honest population.** Like the standoff's Poisson decoys,
//!   the population here is honest background. An adversary that attributes some
//!   stakers elsewhere shrinks the set below these nominal figures.
//! - **No latency cost — the cost is capital.** The standoff's cost is entry
//!   latency (`window/epoch`); the cover's cost is the **permanent locked
//!   capital** `C_max`, reported as the regressive tax `k / s_P` (§7.3). That
//!   tax — heaviest on the smallest stakers, the very cold-start funders the
//!   cover protects — is what bounds err-large from running to the ceiling.
//!
//! The production draw is float-free and single-sourced in `shekyl-standoff`
//! (the `draw_cover_amount` sibling of `draw_entry_gap`, C4); this module is a
//! sim/analysis harness and uses `f64` freely, exactly like `standoff.rs`.

use serde::Serialize;

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;

/// Atomic units per SKL (`DISPLAY_DECIMAL_POINT = 9`). Local copy keeps this
/// harness free of a units-crate dependency, like the standoff's block-time.
const ATOMIC_PER_SKL: f64 = 1_000_000_000.0;

/// A candidate set this small or smaller is "thin cover" — the tail an averaged
/// anonymity-set mean hides (same threshold the standoff uses).
const THIN_COVER_THRESHOLD: f64 = 2.0;

/// Default "reasonable obfuscation" target mean candidate set (standoff parity).
const TARGET_ANON_SET: f64 = 10.0;

/// The thin-cover tail we *would like* closed (`P(set ≤ 2) ≤ 2%`) — reported as
/// the bar the residual tail is read against. It is **not** the recommendation
/// target: at the thin corner the bounded (`≤ N_P`) decoy pool leaves an
/// irreducible tail floor, so chasing this with `k` runs to the ceiling (§7).
const THIN_TAIL_TARGET: f64 = 0.02;

/// Per-staker shard-count spread — the swept pre-testnet assumption (§7.2). The
/// mean is pinned by the sim; the *shape* around it is not, and it is what sets
/// per-rung density, so we bracket it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Dispersion {
    /// `1 + Poisson(mean − 1)` — counts pile near the mean (`CV ≈ 1/√mean`). The
    /// optimistic, dense-rung bracket: a small `k` already gathers a crowd.
    Clustered,
    /// `1 + Geometric(mean − 1)` — counts spread thin with a heavy tail
    /// (`CV ≈ 1`). The pessimistic, sparse-rung bracket err-large sizes against.
    Dispersed,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverConfig {
    pub name: String,
    pub axis: &'static str,
    /// Live-staker count — the `N_P` envelope {thin 17 / lean 79 / thick 154}.
    pub n_p: u64,
    /// Per-staker mean shard count (which rung the staker sits on).
    pub mean_shards: f64,
    pub dispersion: Dispersion,
    /// The dial: rungs the cover blurs across, `k = (C_max − C_min) / floor`.
    pub rungs_blurred: u64,
    /// Fraction of amount-consistent decoys also inside the entry-gap timing
    /// window (§1.1 intersection). `1.0` = the amount-marginal upper bound.
    pub timing_retain: f64,
    pub trials: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverResult {
    pub name: String,
    pub axis: &'static str,
    pub n_p: u64,
    pub mean_shards: f64,
    pub dispersion: Dispersion,
    pub rungs_blurred: u64,
    pub timing_retain: f64,
    /// `C_max − C_min` in SKL — the working capital the dial costs.
    pub cover_span_skl: f64,
    /// Mean effective anonymity set (1 target + in-window, timing-retained decoys).
    pub anon_set_mean: f64,
    /// 5th-percentile candidate set — the thin-cover tail.
    pub anon_set_p05: f64,
    /// `P(set ≤ THIN_COVER_THRESHOLD)` — the fraction landing in thin cover.
    pub thin_cover_frac: f64,
    /// Mean adversary single-guess link probability (`1/set` under uniform cover).
    pub link_prob_mean: f64,
    /// Mean capital tax `k / s_P` — cover span as a multiple of the staker's bond.
    pub tax_mean: f64,
    /// Worst-case tax `k / min s_P` — the smallest staker, who pays the most (§7.3).
    pub tax_worst: f64,
}

/// SplitMix64 — small, seeded, reproducible; no `rand` dependency (the standoff's
/// posture — the harness must be deterministic for replay).
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 53-bit mantissa in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn gaussian(&mut self) -> f64 {
        // Box-Muller; one of the pair is enough here.
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Poisson draw — Knuth for small means, normal approximation for large.
    fn poisson(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        if mean > 30.0 {
            let v = mean + mean.sqrt() * self.gaussian();
            return v.round().max(0.0) as u64;
        }
        let l = (-mean).exp();
        let mut k = 0u64;
        let mut p = 1.0;
        loop {
            k += 1;
            p *= self.unit();
            if p <= l {
                return k - 1;
            }
        }
    }

    /// Geometric draw with the given **mean** (number of failures before the
    /// first success): `P(j) = (1−p)^j · p`, `mean = (1−p)/p`, so `p = 1/(mean+1)`.
    /// Inverse-CDF: `j = ⌊ln(U) / ln(1−p)⌋`. Heavy right tail ⇒ `CV ≈ 1`.
    fn geometric(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        let p = 1.0 / (mean + 1.0);
        let denom = (1.0 - p).ln();
        if denom == 0.0 {
            return 0;
        }
        let u = self.unit().max(1e-12);
        (u.ln() / denom).floor().max(0.0) as u64
    }
}

/// One staker's shard count `≥ 1` under the scenario's mean and spread.
fn draw_shard_count(rng: &mut SplitMix64, mean: f64, dispersion: Dispersion) -> u64 {
    let extra = (mean - 1.0).max(0.0);
    1 + match dispersion {
        Dispersion::Clustered => rng.poisson(extra),
        Dispersion::Dispersed => rng.geometric(extra),
    }
}

fn run(cfg: &CoverConfig) -> CoverResult {
    assert!(cfg.trials > 0, "cover::run requires trials > 0");
    assert!(cfg.n_p > 0, "cover::run requires n_p > 0");

    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL; // 0.75 SKL
    let cover_span_skl = cfg.rungs_blurred as f64 * floor_skl;
    let k = cfg.rungs_blurred as f64;

    let mut rng = SplitMix64::new(cfg.seed);
    let mut sets: Vec<f64> = Vec::with_capacity(cfg.trials as usize);
    let mut link_sum = 0.0;
    let mut thin = 0u64;
    let mut tax_sum = 0.0;
    let mut tax_worst = 0.0;

    for _ in 0..cfg.trials {
        // Fresh population each trial integrates over population realizations
        // (the standoff draws fresh Poisson decoys per trial for the same reason).
        let pop: Vec<i64> = (0..cfg.n_p)
            .map(|_| draw_shard_count(&mut rng, cfg.mean_shards, cfg.dispersion) as i64)
            .collect();

        let target = (rng.next_u64() % cfg.n_p) as usize;
        let s_p = pop[target];

        // Realized cover slides the k+1-rung window: a draw u∈[0,1) puts
        // ⌊(1−u)·k⌋ rungs below s_P and ⌊u·k⌋ above (sum k−1 or k; +1 with the
        // target's own rung ⇒ ≈ k+1 rungs total, §7.1).
        let u = rng.unit();
        let lo = s_p - ((1.0 - u) * k).floor() as i64;
        let hi = s_p + (u * k).floor() as i64;

        let mut decoys = 0u64;
        for (j, &s) in pop.iter().enumerate() {
            if j == target {
                continue;
            }
            if s >= lo && s <= hi {
                // §1.1 timing intersection: an amount-decoy is a *joint* decoy
                // only if it also posted inside the entry-gap window.
                if cfg.timing_retain >= 1.0 || rng.unit() < cfg.timing_retain {
                    decoys += 1;
                }
            }
        }

        let set = 1.0 + decoys as f64;
        sets.push(set);
        link_sum += 1.0 / set;
        if set <= THIN_COVER_THRESHOLD {
            thin += 1;
        }
        let tax = k / s_p as f64;
        tax_sum += tax;
        if tax > tax_worst {
            tax_worst = tax;
        }
    }

    sets.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sets.len();
    let mean = sets.iter().sum::<f64>() / n as f64;
    let p05 = sets[(0.05 * n as f64) as usize];

    CoverResult {
        name: cfg.name.clone(),
        axis: cfg.axis,
        n_p: cfg.n_p,
        mean_shards: cfg.mean_shards,
        dispersion: cfg.dispersion,
        rungs_blurred: cfg.rungs_blurred,
        timing_retain: cfg.timing_retain,
        cover_span_skl,
        anon_set_mean: mean,
        anon_set_p05: p05,
        thin_cover_frac: thin as f64 / n as f64,
        link_prob_mean: link_sum / n as f64,
        tax_mean: tax_sum / n as f64,
        tax_worst,
    }
}

/// The three `N_P` scenarios, `(name, n_p, mean_shards)`. Means are the sim's
/// cited per-staker portfolios: thin `17 → 9` (`:720`), lean `79 → 60` (`:676`).
/// Thick `154` reuses the lean mean as a conservative estimate (the thick-regime
/// mean is not separately pinned — flagged, not fabricated).
const SCENARIOS: [(&str, u64, f64); 3] =
    [("thin", 17, 9.0), ("lean", 79, 60.0), ("thick", 154, 60.0)];

pub fn build_configs() -> Vec<CoverConfig> {
    let mut cfgs = Vec::new();
    let trials = 200_000u64;
    let mut seed = 0xC0DE_0001u64;

    let (_, thin_np, thin_mean) = SCENARIOS[0];

    // Arm A — the dial sweep at the pessimistic corner (thin N_P, dispersed,
    // amount-marginal). This is where the knee in k is read off.
    for &k in &[0u64, 4, 8, 12, 16, 20, 24, 32] {
        cfgs.push(CoverConfig {
            name: format!("dial_k{k}_thin"),
            axis: "cover_dial",
            n_p: thin_np,
            mean_shards: thin_mean,
            dispersion: Dispersion::Dispersed,
            rungs_blurred: k,
            timing_retain: 1.0,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm B — N_P scenario sweep at a fixed mid dial, dispersed: anonymity grows
    // with population, but the thin end is what the genesis bound must clear.
    for &(name, n_p, mean) in &SCENARIOS {
        cfgs.push(CoverConfig {
            name: format!("scen_{name}_k16"),
            axis: "cover_scenario",
            n_p,
            mean_shards: mean,
            dispersion: Dispersion::Dispersed,
            rungs_blurred: 16,
            timing_retain: 1.0,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm C — the density assumption's leverage: clustered vs dispersed at the
    // thin corner, fixed dial. The gap is the cost of not knowing the spread.
    for &disp in &[Dispersion::Clustered, Dispersion::Dispersed] {
        cfgs.push(CoverConfig {
            name: format!(
                "dens_{}_thin_k16",
                match disp {
                    Dispersion::Clustered => "clustered",
                    Dispersion::Dispersed => "dispersed",
                }
            ),
            axis: "cover_density",
            n_p: thin_np,
            mean_shards: thin_mean,
            dispersion: disp,
            rungs_blurred: 16,
            timing_retain: 1.0,
            trials,
            seed,
        });
        seed += 1;
    }

    // Arm D — the §1.1 timing intersection: as the entry-gap standoff thins the
    // amount-set, the joint set shrinks and the required dial widens.
    for &retain in &[1.0_f64, 0.5, 0.2] {
        cfgs.push(CoverConfig {
            name: format!("timing_retain{retain}_thin_k16"),
            axis: "cover_timing",
            n_p: thin_np,
            mean_shards: thin_mean,
            dispersion: Dispersion::Dispersed,
            rungs_blurred: 16,
            timing_retain: retain,
            trials,
            seed,
        });
        seed += 1;
    }

    cfgs
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverRecommendation {
    /// The pessimistic corner the err-large bound is sized against.
    pub scenario: &'static str,
    pub n_p: u64,
    pub mean_shards: f64,
    pub dispersion: Dispersion,
    pub timing_retain: f64,
    /// Smallest dial whose **mean** set clears `TARGET_ANON_SET` (standoff parity).
    pub knee_rungs: u64,
    /// Whether the mean target was reachable within the scan — at the thin corner
    /// the bounded decoy pool (≤ `N_P`) can saturate below it (the §7 finding).
    pub mean_target_reached: bool,
    /// The err-large pin: the knee stepped up one notch (§2.5).
    pub err_large_rungs: u64,
    /// `C_max − C_min` at the err-large pin, in SKL.
    pub cover_span_skl: f64,
    /// Worst-case capital tax at the err-large pin (`k / 1` — the rung-1 staker).
    pub worst_tax_multiple: f64,
    /// Achieved mean set at the err-large pin.
    pub anon_set_mean: f64,
    /// Residual thin-cover tail at the pin — it does **not** vanish: the pool is
    /// bounded by `N_P`, so edge-of-lattice stakers keep a floor the dial can't
    /// close (firewall-composition, not a sizing knob — §7).
    pub thin_cover_frac: f64,
}

/// Find the smallest dial whose **mean** set clears `TARGET_ANON_SET` at the
/// pessimistic corner (thin `N_P`, dispersed, timing-intersected), then step up
/// one notch — the err-large rule (§2.5). Mean, not tail: unlike the standoff's
/// unbounded Poisson decoys, the cover pool saturates at `N_P`, so the thin-cover
/// **tail** has an irreducible floor no affordable `k` closes (the §7 structural
/// finding) — chasing it runs `k` to the ceiling. We size the dial to the mean
/// at viable capital and report the residual tail as the firewall's problem.
fn recommendation(timing_retain: f64) -> CoverRecommendation {
    let (scenario, n_p, mean_shards) = SCENARIOS[0];
    let dispersion = Dispersion::Dispersed;
    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL;
    let step = 4u64; // one notch ≈ 3 SKL of cover span.
    let scan_max = 48u64;

    let scan = |k: u64| {
        run(&CoverConfig {
            name: format!("reco_k{k}"),
            axis: "cover_reco",
            n_p,
            mean_shards,
            dispersion,
            rungs_blurred: k,
            timing_retain,
            trials: 50_000,
            seed: 0x5EED_0042 ^ k,
        })
    };

    let mut knee = None;
    for k in 0..=scan_max {
        if scan(k).anon_set_mean >= TARGET_ANON_SET {
            knee = Some(k);
            break;
        }
    }
    let mean_target_reached = knee.is_some();
    // If the mean target is unreachable (bounded pool saturates below it), pin at
    // the scan ceiling — widening further only taxes capital for no set gain.
    let knee = knee.unwrap_or(scan_max);
    let err_large = (knee + step).min(scan_max);
    let pin = scan(err_large);

    CoverRecommendation {
        scenario,
        n_p,
        mean_shards,
        dispersion,
        timing_retain,
        knee_rungs: knee,
        mean_target_reached,
        err_large_rungs: err_large,
        cover_span_skl: err_large as f64 * floor_skl,
        worst_tax_multiple: err_large as f64, // k / 1 for the rung-1 staker.
        anon_set_mean: pin.anon_set_mean,
        thin_cover_frac: pin.thin_cover_frac,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverReport {
    pub floor_atomic: u64,
    pub floor_skl: f64,
    pub target_anon_set: f64,
    pub thin_tail_target: f64,
    pub results: Vec<CoverResult>,
    pub recommendations: Vec<CoverRecommendation>,
}

pub fn run_full_report() -> CoverReport {
    let results: Vec<CoverResult> = build_configs().iter().map(run).collect();
    // Recommend across the timing-intersection brackets — the joint set, not the
    // amount marginal, is what the genesis bound is sized against.
    let recommendations = [1.0_f64, 0.5, 0.2]
        .iter()
        .map(|&t| recommendation(t))
        .collect();
    CoverReport {
        floor_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
        floor_skl: ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL,
        target_anon_set: TARGET_ANON_SET,
        thin_tail_target: THIN_TAIL_TARGET,
        results,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(k: u64) -> CoverConfig {
        CoverConfig {
            name: "t".into(),
            axis: "t",
            n_p: 17,
            mean_shards: 9.0,
            dispersion: Dispersion::Dispersed,
            rungs_blurred: k,
            timing_retain: 1.0,
            trials: 50_000,
            seed: 1,
        }
    }

    #[test]
    fn zero_dial_is_the_same_rung_floor() {
        // k = 0 ⇒ window is the single true rung — but other stakers on that rung
        // share the identical `bond_floor`, so the set is the rung's OWN occupancy
        // (the baseline before any cover; why the `cover == 0` opt-out, DQ6, still
        // gets same-rung cover). A strict floor below a widened dial.
        let z = run(&base(0));
        assert!(z.anon_set_mean >= 1.0);
        assert!(z.link_prob_mean <= 1.0);
        assert!(z.anon_set_mean < run(&base(16)).anon_set_mean);
    }

    #[test]
    fn wider_dial_grows_anon_set() {
        assert!(run(&base(24)).anon_set_mean > run(&base(8)).anon_set_mean);
    }

    #[test]
    fn dispersed_is_the_pessimistic_bracket() {
        // Clustered piles stakers near the mean ⇒ a fixed window gathers more of
        // them than the heavy-tailed dispersed shape ⇒ larger set.
        let clustered = CoverConfig {
            dispersion: Dispersion::Clustered,
            ..base(16)
        };
        let dispersed = CoverConfig {
            dispersion: Dispersion::Dispersed,
            ..base(16)
        };
        assert!(run(&clustered).anon_set_mean >= run(&dispersed).anon_set_mean);
    }

    #[test]
    fn timing_intersection_shrinks_the_joint_set() {
        let marginal = CoverConfig {
            timing_retain: 1.0,
            ..base(16)
        };
        let joint = CoverConfig {
            timing_retain: 0.2,
            ..base(16)
        };
        // Thinning the amount-set by timing can only shrink it (the §1.1 bound).
        assert!(run(&joint).anon_set_mean < run(&marginal).anon_set_mean);
    }

    #[test]
    fn tax_is_regressive_worst_at_rung_one() {
        // The worst-case tax is k / (smallest sampled rung); with a dispersed
        // population a rung-1 staker is sampled, so it approaches k exactly.
        let r = run(&base(16));
        assert!(r.tax_worst > r.tax_mean);
        assert!((r.tax_worst - 16.0).abs() < 1e-9);
    }

    #[test]
    fn larger_population_grows_anon_set() {
        let thin = base(16);
        let thick = CoverConfig {
            n_p: 154,
            mean_shards: 60.0,
            ..base(16)
        };
        assert!(run(&thick).anon_set_mean > run(&thin).anon_set_mean);
    }

    #[test]
    fn recommendation_steps_up_from_the_knee() {
        let rec = recommendation(1.0);
        assert_eq!(rec.err_large_rungs, rec.knee_rungs + 4);
        assert!((rec.worst_tax_multiple - rec.err_large_rungs as f64).abs() < 1e-9);
    }
}
