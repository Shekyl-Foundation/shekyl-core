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
//! cover the attacker's candidate set is the **contiguous window of `k` rungs
//! straddling the true rung `s_P`** — a length-`k` rung interval, which includes
//! `s_P`'s own rung and contains `k` integer rungs almost always (`k+1` only when
//! the cover lands exactly on a floor multiple, measure-zero for a continuous
//! cover). Its split (rungs below vs above `s_P`) slides with the draw: a cover
//! near `C_max` opens the window mostly *above* `s_P` (it must be matched by a
//! *higher* rung), near `C_min` mostly *below*. Uniform cover (DQ1) makes the
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

/// Marginal-return cutoff for the saturation knee: once a rung of cover buys
/// fewer than this many set members, the bounded pool is saturating and more
/// capital is wasted (and, via §7.5 opt-out, harmful). Sets where the dial pins.
const MARGINAL_CUTOFF: f64 = 0.15;

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
    /// Worst-case tax = the rung-1 staker's `k / 1 = k` — a deterministic bound on
    /// the smallest staker's burden (§7.3), not a sample-dependent max.
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
    assert!(
        cfg.timing_retain.is_finite() && (0.0..=1.0).contains(&cfg.timing_retain),
        "cover::run requires timing_retain in [0, 1], got {}",
        cfg.timing_retain
    );

    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL; // 0.75 SKL
    let cover_span_skl = cfg.rungs_blurred as f64 * floor_skl;
    let k = cfg.rungs_blurred as f64;

    let mut rng = SplitMix64::new(cfg.seed);
    let mut sets: Vec<f64> = Vec::with_capacity(cfg.trials as usize);
    let mut link_sum = 0.0;
    let mut thin = 0u64;
    let mut tax_sum = 0.0;
    // Reused across trials (clear + refill) — same draw order as a fresh Vec, so
    // bit-identical results, without 200k allocations.
    let mut pop: Vec<i64> = Vec::with_capacity(cfg.n_p as usize);

    for _ in 0..cfg.trials {
        // Fresh population each trial integrates over population realizations
        // (the standoff draws fresh Poisson decoys per trial for the same reason).
        pop.clear();
        pop.extend(
            (0..cfg.n_p)
                .map(|_| draw_shard_count(&mut rng, cfg.mean_shards, cfg.dispersion) as i64),
        );

        let target = (rng.next_u64() % cfg.n_p) as usize;
        let s_p = pop[target];

        // Realized cover slides the window: u∈[0,1) maps cover from C_min (u=0)
        // to C_max (u=1), placing ⌊(1−u)·k⌋ rungs below s_P and ⌊u·k⌋ above — so a
        // high cover (u→1) opens the window *above* s_P, a low cover *below*. The
        // window spans k rungs (⌊(1−u)k⌋ + ⌊uk⌋ + 1 = k for non-aligned u; k+1 only
        // when u·k is integral — measure-zero for a continuous cover), §7.1.
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
        tax_sum += k / s_p as f64;
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
        // The rung-1 staker's tax, `k / 1 = k` — the worst *possible* burden, a
        // deterministic bound (not the sample max, which is seed/trials-dependent
        // and under-reports when no rung-1 staker is sampled).
        tax_worst: cfg.rungs_blurred as f64,
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
    /// The pessimistic corner the bound is sized against.
    pub scenario: &'static str,
    pub n_p: u64,
    pub mean_shards: f64,
    pub dispersion: Dispersion,
    pub timing_retain: f64,
    /// The reachable set ceiling under this corner (set at the scan max) — the
    /// bounded (`≤ N_P`) pool saturates here, so the dial can buy no more.
    pub saturation_set: f64,
    /// The **saturation knee**: smallest `k` past which the marginal set gain per
    /// rung of cover falls below `MARGINAL_CUTOFF`. The pin, *not* `knee + step`:
    /// past the knee the bounded pool is saturating, so more cover capital buys
    /// ~nothing — and §7.3's regressive tax (and the §7.5 opt-out it triggers)
    /// makes over-shooting actively harmful, so err-large pins **at** the knee.
    pub knee_rungs: u64,
    /// Whether `TARGET_ANON_SET` is even reachable here (the joint corner often
    /// saturates below it — the §7 finding).
    pub mean_target_reached: bool,
    /// `C_max − C_min` at the knee, in SKL.
    pub cover_span_skl: f64,
    /// Worst-case capital tax at the knee (`k / 1` — the rung-1 staker).
    pub worst_tax_multiple: f64,
    /// Mean set at the knee.
    pub anon_set_mean: f64,
    /// Residual thin-cover tail at the knee — does **not** vanish (the bounded
    /// pool leaves an edge-of-lattice floor; firewall-composition, not a knob).
    pub thin_cover_frac: f64,
}

/// Size the dial at the **saturation knee** under the pessimistic corner (thin
/// `N_P`, dispersed, timing-intersected): the smallest `k` past which a rung of
/// cover buys less than `MARGINAL_CUTOFF` of set. Knee, not a mean target —
/// unlike the standoff's unbounded Poisson decoys the pool saturates at `N_P`,
/// so a mean target is often unreachable, and *past* the knee the regressive tax
/// (§7.3) drives the §7.5 opt-out, making over-shoot harmful. So err-large pins
/// **at** the knee, bounded above by participation rather than below by a tail
/// target. The joint (timing-intersected) corner is the genesis-pin input — the
/// amount-marginal `timing_retain = 1.0` is only a floor (§7.4).
fn recommendation(timing_retain: f64) -> CoverRecommendation {
    let (scenario, n_p, mean_shards) = SCENARIOS[0];
    let dispersion = Dispersion::Dispersed;
    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL;
    let step = 4u64; // marginal window, ≈ 3 SKL of cover span.
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
        .anon_set_mean
    };

    // Walk in `step`-rung increments; the knee is the first window whose marginal
    // set gain per rung drops below the cutoff (diminishing return on capital).
    let mut knee = scan_max;
    let mut prev = scan(0);
    let mut k = step;
    while k <= scan_max {
        let cur = scan(k);
        if (cur - prev) / (step as f64) < MARGINAL_CUTOFF {
            knee = k - step; // the last k before returns died.
            break;
        }
        prev = cur;
        k += step;
    }
    let knee = knee.max(step); // never pin below one marginal window.

    let pin = run(&CoverConfig {
        name: "reco_pin".into(),
        axis: "cover_reco",
        n_p,
        mean_shards,
        dispersion,
        rungs_blurred: knee,
        timing_retain,
        trials: 50_000,
        seed: 0x5EED_00FF,
    });
    let saturation_set = scan(scan_max);

    CoverRecommendation {
        scenario,
        n_p,
        mean_shards,
        dispersion,
        timing_retain,
        saturation_set,
        knee_rungs: knee,
        mean_target_reached: saturation_set >= TARGET_ANON_SET,
        cover_span_skl: knee as f64 * floor_skl,
        worst_tax_multiple: knee as f64, // k / 1 for the rung-1 staker.
        anon_set_mean: pin.anon_set_mean,
        thin_cover_frac: pin.thin_cover_frac,
    }
}

/// Economic-participation model (§7.5). Cover-stays-with-`P` means the principal
/// must fund `bond + cover` at the seam; a staker posts cover only if the dial's
/// max draw (`C_max = k · floor`) is at most `beta ×` their own bond — i.e. rung
/// `s ≥ k / beta`. Capital-constrained low-rung stakers fall below that and take
/// the `cover == 0` opt-out (the §7.3 regressive tax made *economic*). Because the
/// rung is **public** on the bond-post, the attacker raises the opt-out prior on
/// low rungs, so opted-out bonds are discounted as the source of a *covered* `A` —
/// the realized decoy pool for a paying target is other **payers** in the window,
/// not the honest population. This is what turns the honest-uniform tail into the
/// realized one.
#[derive(Debug, Clone, Serialize)]
pub struct ParticipationResult {
    pub rungs_blurred: u64,
    pub cover_span_skl: f64,
    /// Willingness-to-pay: max cover a staker locks, as a multiple of their bond.
    pub beta: f64,
    /// Lowest rung that can still afford the dial (`⌈k / beta⌉`).
    pub min_paying_rung: u64,
    /// Fraction of the population priced out into the `cover == 0` opt-out.
    pub opt_out_frac: f64,
    /// Realized mean set for a **paying** target (decoys = other payers in window).
    pub payer_set_mean: f64,
    /// Realized thin-cover tail among payers.
    pub payer_thin_frac: f64,
    /// Honest-uniform mean set (everyone pays) at the same `k`, for contrast.
    pub honest_set_mean: f64,
}

fn run_participation(
    n_p: u64,
    mean_shards: f64,
    dispersion: Dispersion,
    k: u64,
    beta: f64,
    trials: u64,
    seed: u64,
) -> ParticipationResult {
    assert!(trials > 0, "cover::run_participation requires trials > 0");
    assert!(n_p > 0, "cover::run_participation requires n_p > 0");
    assert!(
        beta.is_finite() && beta > 0.0,
        "cover::run_participation requires beta > 0, got {beta}"
    );

    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL;
    // s ≥ k/β to afford C_max = k·floor ≤ β·(s·floor).
    let min_paying_rung = (k as f64 / beta).ceil().max(1.0) as i64;
    let kf = k as f64;

    let mut rng = SplitMix64::new(seed);
    let mut opt_out = 0u64;
    let mut pop_seen = 0u64;
    let mut payer_sets: Vec<f64> = Vec::new();
    let mut honest_sum = 0.0;
    let mut honest_n = 0u64;
    // Reused across trials (clear + refill) — same draw order, bit-identical.
    let mut pop: Vec<i64> = Vec::with_capacity(n_p as usize);

    for _ in 0..trials {
        pop.clear();
        pop.extend((0..n_p).map(|_| draw_shard_count(&mut rng, mean_shards, dispersion) as i64));
        for &s in &pop {
            pop_seen += 1;
            if s < min_paying_rung {
                opt_out += 1;
            }
        }

        let target = (rng.next_u64() % n_p) as usize;
        let s_p = pop[target];
        let u = rng.unit();
        let lo = s_p - ((1.0 - u) * kf).floor() as i64;
        let hi = s_p + (u * kf).floor() as i64;

        // Honest set: all stakers in window count (everyone pays).
        let honest = 1 + pop
            .iter()
            .enumerate()
            .filter(|(j, &s)| *j != target && s >= lo && s <= hi)
            .count();
        honest_sum += honest as f64;
        honest_n += 1;

        // Realized set: only a PAYING target gets cover, and only PAYING decoys
        // (rung ≥ min_paying_rung) count — opted-out bonds are discounted.
        if s_p >= min_paying_rung {
            let decoys = pop
                .iter()
                .enumerate()
                .filter(|(j, &s)| *j != target && s >= min_paying_rung && s >= lo && s <= hi)
                .count();
            payer_sets.push(1.0 + decoys as f64);
        }
    }

    let payer_set_mean = if payer_sets.is_empty() {
        1.0
    } else {
        payer_sets.iter().sum::<f64>() / payer_sets.len() as f64
    };
    let payer_thin_frac = if payer_sets.is_empty() {
        1.0
    } else {
        payer_sets
            .iter()
            .filter(|&&s| s <= THIN_COVER_THRESHOLD)
            .count() as f64
            / payer_sets.len() as f64
    };

    ParticipationResult {
        rungs_blurred: k,
        cover_span_skl: k as f64 * floor_skl,
        beta,
        min_paying_rung: min_paying_rung as u64,
        opt_out_frac: opt_out as f64 / pop_seen as f64,
        payer_set_mean,
        payer_thin_frac,
        honest_set_mean: honest_sum / honest_n as f64,
    }
}

/// Participation sweep at the thin/dispersed corner over the dial, at a
/// pessimistic willingness-to-pay (`beta`). Shows the realized optimum is *lower*
/// than the amount-marginal `k`: widening the dial prices more low rungs out, so
/// the realized payer pool shrinks even as the window grows (§7.5).
pub fn participation_scan() -> Vec<ParticipationResult> {
    let (_, n_p, mean_shards) = SCENARIOS[0];
    let mut out = Vec::new();
    for &beta in &[1.0_f64, 2.0] {
        for &k in &[4u64, 8, 12, 16, 21, 32] {
            out.push(run_participation(
                n_p,
                mean_shards,
                Dispersion::Dispersed,
                k,
                beta,
                50_000,
                0x9A11_0000 ^ ((beta as u64) << 8) ^ k,
            ));
        }
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverReport {
    pub floor_atomic: u64,
    pub floor_skl: f64,
    pub target_anon_set: f64,
    pub thin_tail_target: f64,
    /// The saturation-knee marginal-return cutoff (single source: `MARGINAL_CUTOFF`).
    pub marginal_cutoff: f64,
    pub results: Vec<CoverResult>,
    pub recommendations: Vec<CoverRecommendation>,
    pub participation: Vec<ParticipationResult>,
}

pub fn run_full_report() -> CoverReport {
    let results: Vec<CoverResult> = build_configs().iter().map(run).collect();
    // Recommend across the timing-intersection brackets — the joint set, not the
    // amount marginal, is what the genesis bound is sized against (§7.4/§7.6).
    let recommendations = [1.0_f64, 0.5, 0.2]
        .iter()
        .map(|&t| recommendation(t))
        .collect();
    CoverReport {
        floor_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
        floor_skl: ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL,
        target_anon_set: TARGET_ANON_SET,
        thin_tail_target: THIN_TAIL_TARGET,
        marginal_cutoff: MARGINAL_CUTOFF,
        results,
        recommendations,
        participation: participation_scan(),
    }
}

// ===========================================================================
// §7.6 / §7.7 pass — is the scalar peak robust enough to freeze, or pin a
// function? Three analyses: (A) characterize the hump's shape and the
// sensitivity of k* across the pessimistic-input corners (density ×
// timing_retain × affordability); (B) compare an adaptive, population-
// conditioned dial against the best frozen scalar; (C) a bounding proxy for the
// one real net-leak concern — a height-aware attacker sub-localizing when the
// per-height distribution drifts across a timing window.
// ===========================================================================

/// One realized-set sample under the FULL model — timing intersection (§1.1) AND
/// participation opt-out (§7.5) together. A paying target (rung ≥ `min_paying_rung`)
/// counts only paying decoys that also survive the timing draw. `None` if the
/// target itself opted out (so the mean is over *payers*, the §7.5 metric).
fn realized_payer_sample(
    rng: &mut SplitMix64,
    pop: &[i64],
    target: usize,
    k: f64,
    timing_retain: f64,
    min_paying_rung: i64,
) -> Option<f64> {
    let s_p = pop[target];
    if s_p < min_paying_rung {
        return None;
    }
    let u = rng.unit();
    let lo = s_p - ((1.0 - u) * k).floor() as i64;
    let hi = s_p + (u * k).floor() as i64;
    let mut decoys = 0u64;
    for (j, &s) in pop.iter().enumerate() {
        if j == target || s < min_paying_rung || s < lo || s > hi {
            continue;
        }
        if timing_retain >= 1.0 || rng.unit() < timing_retain {
            decoys += 1;
        }
    }
    Some(1.0 + decoys as f64)
}

/// Mean realized payer set at one `(corner, k)` — the metric the genesis pin
/// maximizes (full timing × participation model).
#[allow(clippy::too_many_arguments)]
fn realized_payer_set_mean(
    n_p: u64,
    mean: f64,
    dispersion: Dispersion,
    k: u64,
    timing_retain: f64,
    beta: f64,
    trials: u64,
    seed: u64,
) -> f64 {
    let min_paying_rung = (k as f64 / beta).ceil().max(1.0) as i64;
    let kf = k as f64;
    let mut rng = SplitMix64::new(seed);
    let mut pop: Vec<i64> = Vec::with_capacity(n_p as usize);
    let mut sum = 0.0;
    let mut count = 0u64;
    for _ in 0..trials {
        pop.clear();
        pop.extend((0..n_p).map(|_| draw_shard_count(&mut rng, mean, dispersion) as i64));
        let target = (rng.next_u64() % n_p) as usize;
        if let Some(set) =
            realized_payer_sample(&mut rng, &pop, target, kf, timing_retain, min_paying_rung)
        {
            sum += set;
            count += 1;
        }
    }
    if count == 0 {
        1.0
    } else {
        sum / count as f64
    }
}

/// The dial values the robustness/adaptive sweeps walk.
fn dial_grid() -> Vec<u64> {
    (2..=32).step_by(2).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct CornerHump {
    pub density: Dispersion,
    pub timing_retain: f64,
    pub beta: f64,
    /// The realized-set-maximizing dial at this corner.
    pub k_star: u64,
    pub peak_set: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HumpRobustness {
    pub corners: Vec<CornerHump>,
    /// The single `k` maximizing the worst-corner fraction of peak.
    pub robust_k: u64,
    /// At `robust_k`, the worst corner's set as a fraction of its own peak.
    pub worst_corner_ratio: f64,
    /// Whether one frozen `k` holds ≥ 90% of peak across **every** corner.
    pub robust_band_90: bool,
    /// How far `k*` slides across the corners (`max − min`) — the fragility signal.
    pub k_star_spread: u64,
}

/// (A) Characterize the hump across the pessimistic corners (§7.6). At the thin
/// `N_P` corner, sweep the dial for every (density × timing_retain × β) and ask:
/// does a single frozen `k` stay within 90% of each corner's peak?
fn hump_robustness() -> HumpRobustness {
    let densities = [Dispersion::Clustered, Dispersion::Dispersed];
    let timings = [1.0_f64, 0.5, 0.2];
    let betas = [1.0_f64, 2.0, 4.0];
    let ks = dial_grid();
    let (_, n_p, mean) = SCENARIOS[0]; // thin N_P — the pessimistic population.
    let trials = 20_000u64;

    let mut corners = Vec::new();
    let mut curves: Vec<Vec<f64>> = Vec::new();
    let mut seed = 0xF00D_0001u64;
    for &density in &densities {
        for &timing_retain in &timings {
            for &beta in &betas {
                let curve: Vec<f64> = ks
                    .iter()
                    .map(|&k| {
                        seed += 1;
                        realized_payer_set_mean(
                            n_p,
                            mean,
                            density,
                            k,
                            timing_retain,
                            beta,
                            trials,
                            seed,
                        )
                    })
                    .collect();
                let (best_i, &peak) = curve
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                    .unwrap();
                corners.push(CornerHump {
                    density,
                    timing_retain,
                    beta,
                    k_star: ks[best_i],
                    peak_set: peak,
                });
                curves.push(curve);
            }
        }
    }

    // Robust k: the one maximizing the worst corner's fraction of its own peak.
    let mut robust_k = ks[0];
    let mut best_min_ratio = 0.0;
    for (ki, &k) in ks.iter().enumerate() {
        let min_ratio = corners
            .iter()
            .enumerate()
            .map(|(ci, c)| curves[ci][ki] / c.peak_set)
            .fold(f64::INFINITY, f64::min);
        if min_ratio > best_min_ratio {
            best_min_ratio = min_ratio;
            robust_k = k;
        }
    }
    let k_star_min = corners.iter().map(|c| c.k_star).min().unwrap();
    let k_star_max = corners.iter().map(|c| c.k_star).max().unwrap();

    HumpRobustness {
        corners,
        robust_k,
        worst_corner_ratio: best_min_ratio,
        robust_band_90: best_min_ratio >= 0.90,
        k_star_spread: k_star_max - k_star_min,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DensityResponse {
    pub label: &'static str,
    pub n_p: u64,
    pub mean_shards: f64,
    /// The adaptive (population-conditioned) dial = this density's own `k*`.
    pub adaptive_k: u64,
    pub adaptive_set: f64,
    pub adaptive_cover_skl: f64,
    /// The frozen scalar (the §7.6 robust-band centre), applied everywhere.
    pub frozen_k: u64,
    pub frozen_set: f64,
    pub frozen_cover_skl: f64,
}

/// (B) Adaptive vs frozen (§7.7). Across a sparse→dense sweep, the adaptive dial
/// is each density's own `k*` (what a public, population-conditioned `D` would
/// compute); the frozen dial is the single `robust_k`. The function should match
/// or beat the scalar on set while spending **less** cover capital where wide
/// cover buys nothing (sparse periods).
fn adaptive_vs_frozen(robust_k: u64) -> Vec<DensityResponse> {
    let levels: [(&str, u64, f64); 4] = [
        ("sparse-thin", 17, 9.0),
        ("mid", 40, 20.0),
        ("lean", 79, 60.0),
        ("dense-thick", 154, 60.0),
    ];
    let timing_retain = 0.5; // joint corner
    let beta = 2.0; // moderate affordability
    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL;
    let ks = dial_grid();
    let trials = 20_000u64;
    let mut seed = 0xADA9_0001u64;

    levels
        .iter()
        .map(|&(label, n_p, mean)| {
            let (adaptive_k, adaptive_set) = ks
                .iter()
                .map(|&k| {
                    seed += 1;
                    (
                        k,
                        realized_payer_set_mean(
                            n_p,
                            mean,
                            Dispersion::Dispersed,
                            k,
                            timing_retain,
                            beta,
                            trials,
                            seed,
                        ),
                    )
                })
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
                .unwrap();
            seed += 1;
            let frozen_set = realized_payer_set_mean(
                n_p,
                mean,
                Dispersion::Dispersed,
                robust_k,
                timing_retain,
                beta,
                trials,
                seed,
            );
            DensityResponse {
                label,
                n_p,
                mean_shards: mean,
                adaptive_k,
                adaptive_set,
                adaptive_cover_skl: adaptive_k as f64 * floor_skl,
                frozen_k: robust_k,
                frozen_set,
                frozen_cover_skl: robust_k as f64 * floor_skl,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct LeakPoint {
    /// Ratio of `D`-width across the timing window (1.0 = no drift = frozen `D`).
    pub drift: f64,
    pub frozen_set: f64,
    pub adaptive_set: f64,
    /// `(frozen − adaptive) / frozen` — the set a height-aware attacker strips off
    /// by exploiting the per-height width difference. The net-leak proxy.
    pub leak_frac: f64,
}

/// (C) Net-leak bounding proxy (§7.7). The one real concern: under an adaptive,
/// height-conditioned `D`, a height-aware attacker knows each candidate's window
/// width, so if `D` drifts across a timing window a candidate at the
/// narrower-`D` edge is excluded when its rung offset exceeds the narrowed width.
/// We model a window where a fraction of candidates sit in the other regime
/// (`D`-width narrowed by `drift`) and measure how much of the set the attacker
/// strips. NOT a full attacker model — a bound: leak is 0 at no drift and grows
/// with drift, and drift is structurally tiny (the timing window ≈ 600 blk is
/// ≪ the population-change epoch ≈ 10_000 blk, so per-window drift ≈ 6%).
fn leak_shock_check() -> Vec<LeakPoint> {
    let (n_p, mean) = (79u64, 60.0f64); // a dense corner so the set is non-trivial.
    let k = 16u64;
    let frac_other = 0.5; // half the window sits in the other density regime.
    let drifts = [1.0_f64, 1.06, 1.2, 1.5, 2.0, 3.0];
    let trials = 40_000u64;
    let kf = k as f64;

    drifts
        .iter()
        .map(|&drift| {
            let mut rng = SplitMix64::new(0x1EAC_0000 ^ (drift.to_bits()));
            let mut pop: Vec<i64> = Vec::with_capacity(n_p as usize);
            let mut frozen_sum = 0.0;
            let mut adaptive_sum = 0.0;
            for _ in 0..trials {
                pop.clear();
                pop.extend(
                    (0..n_p)
                        .map(|_| draw_shard_count(&mut rng, mean, Dispersion::Dispersed) as i64),
                );
                let target = (rng.next_u64() % n_p) as usize;
                let s_p = pop[target];
                let u = rng.unit();
                let lo = s_p - ((1.0 - u) * kf).floor() as i64;
                let hi = s_p + (u * kf).floor() as i64;
                let narrowed = kf / drift;
                let mut frozen = 1.0;
                let mut adaptive = 1.0;
                for (j, &s) in pop.iter().enumerate() {
                    if j == target || s < lo || s > hi {
                        continue;
                    }
                    frozen += 1.0;
                    // A candidate in the other (narrower-D) regime survives only if
                    // its rung offset fits the narrowed width.
                    let in_other = rng.unit() < frac_other;
                    if !in_other || ((s - s_p).unsigned_abs() as f64) <= narrowed {
                        adaptive += 1.0;
                    }
                }
                frozen_sum += frozen;
                adaptive_sum += adaptive;
            }
            let frozen_set = frozen_sum / trials as f64;
            let adaptive_set = adaptive_sum / trials as f64;
            LeakPoint {
                drift,
                frozen_set,
                adaptive_set,
                leak_frac: (frozen_set - adaptive_set) / frozen_set,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct FnReport {
    pub floor_skl: f64,
    /// Structural per-window `D`-drift: timing window / population-change epoch.
    pub realistic_drift: f64,
    pub hump: HumpRobustness,
    pub adaptive: Vec<DensityResponse>,
    pub leak: Vec<LeakPoint>,
}

pub fn run_cover_fn_report() -> FnReport {
    let hump = hump_robustness();
    let adaptive = adaptive_vs_frozen(hump.robust_k);
    // 600-block entry-gap window over the 10_000-block settlement epoch.
    let realistic_drift = 1.0 + 600.0 / 10_000.0;
    FnReport {
        floor_skl: ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL,
        realistic_drift,
        hump,
        adaptive,
        leak: leak_shock_check(),
    }
}

// ===========================================================================
// Statistic DQ (§7.8 / §7.9): count-uniform vs histogram-per-rung. The response
// `f` reads is genesis-frozen, so the choice of statistic is un-takebackable.
// The histogram lets `f` give a PER-RUNG response (narrow where your local rung
// is sparse, wide where dense — the saturation-aware shape arm B measured). That
// per-rung response IS a rung-local targeting surface: an attacker who withdraws
// their own bonds *at a victim's rung* makes `f` see "sparse here" and narrows
// THAT victim's cover toward `A == bond_floor` — a targeted, cheap attack. The
// count drives only a UNIFORM `D` (one width per epoch), so the same attacker can
// only move the global width — broad, epoch-long, visible. Richness and
// forgeability are the same property; this arm measures the gap so the decision
// is empirical (the saturation-finding discipline), not argued.
// ===========================================================================

/// Honest-baselined width response: a density signal → dial width, monotone
/// increasing (sparse → narrow/conceded, dense → wide), normalised so the honest
/// signal maps to `K_HONEST` and clamped to `[K_MIN, K_SAT]`. Same shape for both
/// modes — only the *signal* (global count vs local occupancy) differs, which is
/// exactly the manipulability difference under test.
fn targeting_width(signal: f64, honest_signal: f64) -> u64 {
    const K_HONEST: f64 = 16.0;
    const K_MIN: f64 = 4.0;
    const K_SAT: f64 = 24.0;
    if honest_signal <= 0.0 {
        return K_MIN as u64;
    }
    (K_HONEST * (signal.max(0.0) / honest_signal))
        .clamp(K_MIN, K_SAT)
        .round() as u64
}

/// Victim's realized anonymity set at a given cover width (honest decoys in the
/// window; the attacker's withdrawn bonds are not decoys either way).
fn victim_realized_set(rng: &mut SplitMix64, pop: &[i64], victim: usize, width: u64) -> f64 {
    let s_v = pop[victim];
    let u = rng.unit();
    let lo = s_v - ((1.0 - u) * width as f64).floor() as i64;
    let hi = s_v + (u * width as f64).floor() as i64;
    let decoys = pop
        .iter()
        .enumerate()
        .filter(|(j, &s)| *j != victim && s >= lo && s <= hi)
        .count();
    1.0 + decoys as f64
}

/// Honest local occupancy: bonds within `±W_REF` rungs of `rung` (excluding the
/// bond itself). The per-rung signal a histogram `f` would read.
fn local_occupancy(pop: &[i64], idx: usize, w_ref: i64) -> f64 {
    let r = pop[idx];
    pop.iter()
        .enumerate()
        .filter(|(j, &s)| *j != idx && (s - r).abs() <= w_ref)
        .count() as f64
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetingPoint {
    /// Bonds the attacker withdraws (their own), the cost axis.
    pub attacker_bonds: u64,
    /// Victim realized set when `f` reads the GLOBAL count (uniform `D`).
    pub count_uniform_set: f64,
    /// Victim realized set when `f` reads the victim's LOCAL occupancy (per-rung).
    pub histogram_set: f64,
    /// Same, restricted to victims on a MODERATE rung (local occupancy near the
    /// honest mean) — the *targetable* tier. Thin rungs the histogram already
    /// concedes (the three-tier framing); dense rungs swamp the attacker; the
    /// moderate middle is where a rung-local depopulation actually moves the dial.
    pub count_uniform_mod_set: f64,
    pub histogram_mod_set: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetingReport {
    pub n_p: u64,
    pub mean_shards: f64,
    pub w_ref: i64,
    pub honest_avg_local: f64,
    pub points: Vec<TargetingPoint>,
    /// Attacker bonds to halve a MODERATE victim's set: histogram vs count. The
    /// ratio is the targeting gain (how much cheaper the per-rung surface is).
    pub histogram_m_to_halve_mod: Option<u64>,
    pub count_m_to_halve_mod: Option<u64>,
}

/// Rung-local suppression adversary (§7.8 / §7.9). The attacker withdraws `m` of
/// their own bonds — concentrated at the victim's rung for the histogram mode,
/// spread globally for the count mode — across a full closed epoch, so the
/// epoch-close statistic sees the suppressed value. We measure how far each
/// response lets the attacker narrow the victim's realized cover. Default to
/// count-uniform; this is the measurement that may upgrade to a richer statistic
/// only if the per-rung targeting gain is negligible (honest occupancy swamps the
/// attacker's mass even at thin rungs).
fn targeting_attack() -> TargetingReport {
    let (_, n_p, mean) = SCENARIOS[0]; // thin N_P — the regime where attacker mass bites.
    let dispersion = Dispersion::Dispersed;
    let w_ref = 4i64;
    let trials = 60_000u64;
    let ms: Vec<u64> = (0..=8).collect();

    // Honest average local occupancy — the histogram normaliser and the
    // thin-rung threshold (bottom third ≈ 0.6× the mean here).
    let mut warm = SplitMix64::new(0x7A46_0001);
    let mut acc = 0.0;
    let mut cnt = 0u64;
    let mut pop: Vec<i64> = Vec::with_capacity(n_p as usize);
    for _ in 0..20_000 {
        pop.clear();
        pop.extend((0..n_p).map(|_| draw_shard_count(&mut warm, mean, dispersion) as i64));
        for i in 0..pop.len() {
            acc += local_occupancy(&pop, i, w_ref);
            cnt += 1;
        }
    }
    let honest_avg_local = acc / cnt as f64;
    // Moderate (targetable) band: local occupancy within ±25% of the honest mean.
    let mod_lo = honest_avg_local * 0.75;
    let mod_hi = honest_avg_local * 1.25;

    let mut points = Vec::new();
    for &m in &ms {
        let mut rng = SplitMix64::new(0x7A46_1000 ^ m);
        let (mut cu, mut hs) = (0.0, 0.0);
        let (mut cu_n, mut hs_n) = (0u64, 0u64);
        let (mut cum, mut hsm) = (0.0, 0.0);
        let (mut cum_n, mut hsm_n) = (0u64, 0u64);
        for _ in 0..trials {
            pop.clear();
            pop.extend((0..n_p).map(|_| draw_shard_count(&mut rng, mean, dispersion) as i64));
            let victim = (rng.next_u64() % n_p) as usize;
            let local = local_occupancy(&pop, victim, w_ref);

            // count-uniform: global signal N_P, suppressed by m globally.
            let w_count = targeting_width((n_p - m.min(n_p)) as f64, n_p as f64);
            // histogram: local signal, suppressed by m at the victim's rung.
            let w_hist = targeting_width(local - m as f64, honest_avg_local);

            let set_count = victim_realized_set(&mut rng, &pop, victim, w_count);
            let set_hist = victim_realized_set(&mut rng, &pop, victim, w_hist);
            cu += set_count;
            hs += set_hist;
            cu_n += 1;
            hs_n += 1;
            if local >= mod_lo && local <= mod_hi {
                cum += set_count;
                hsm += set_hist;
                cum_n += 1;
                hsm_n += 1;
            }
        }
        points.push(TargetingPoint {
            attacker_bonds: m,
            count_uniform_set: cu / cu_n as f64,
            histogram_set: hs / hs_n as f64,
            count_uniform_mod_set: if cum_n > 0 { cum / cum_n as f64 } else { 1.0 },
            histogram_mod_set: if hsm_n > 0 { hsm / hsm_n as f64 } else { 1.0 },
        });
    }

    // Attacker bonds to halve a moderate victim's set, per mode.
    let halve = |get: &dyn Fn(&TargetingPoint) -> f64| -> Option<u64> {
        let base = get(&points[0]);
        points
            .iter()
            .find(|p| get(p) <= base / 2.0)
            .map(|p| p.attacker_bonds)
    };
    let histogram_m_to_halve_mod = halve(&|p| p.histogram_mod_set);
    let count_m_to_halve_mod = halve(&|p| p.count_uniform_mod_set);

    TargetingReport {
        n_p,
        mean_shards: mean,
        w_ref,
        honest_avg_local,
        points,
        histogram_m_to_halve_mod,
        count_m_to_halve_mod,
    }
}

pub fn run_targeting_report() -> TargetingReport {
    targeting_attack()
}

// ===========================================================================
// Dispersion-value (§7.9): does count ALONE leave material anonymity on the
// table vs count + a coarse GLOBAL dispersion scalar? §7.4 showed clustered vs
// dispersed was load-bearing (2.1% vs 6.8% thin-tail) — but the count can't tell
// them apart (same N_P, different spread → same uniform D). A global dispersion
// scalar (effective-occupied-rungs) converts count into density without exposing
// a per-rung lever (the attacker must move a whole-population measure, §7.9). The
// arm measures the gap count-only leaves and whether count+dispersion closes it,
// so the enrichment is taken only if it earns its place.
// ===========================================================================

/// Effective occupied rungs via the occupancy **inverse-participation-ratio**:
/// `(Σ n_r)² / Σ n_r²` over per-rung occupancies `n_r` (`Σ n_r = N_P`). Ranges
/// from `1` (all bonds on one rung — fully clustered) to `N_P` (one per rung —
/// fully dispersed), so it is a far sharper spread discriminator than a raw
/// distinct-rung count. A whole-population measure (no per-rung handle), so it
/// keeps the §7.9 targeting-resistance.
fn effective_occupied_rungs(pop: &[i64]) -> f64 {
    let mut v: Vec<i64> = pop.to_vec();
    v.sort_unstable();
    let mut sum_sq = 0.0;
    let mut i = 0;
    while i < v.len() {
        let mut j = i + 1;
        while j < v.len() && v[j] == v[i] {
            j += 1;
        }
        let n = (j - i) as f64;
        sum_sq += n * n;
        i = j;
    }
    let total = pop.len() as f64;
    if sum_sq <= 0.0 {
        1.0
    } else {
        total * total / sum_sq
    }
}

/// Width to gather `target` neighbours at density `n_p / span`, clamped. The
/// count-only response uses a fixed reference span (blind to spread); the
/// count+dispersion response uses the realised occupied-rungs.
fn density_width(target: f64, span: f64, n_p: f64) -> u64 {
    const K_MIN: f64 = 2.0;
    const K_SAT: f64 = 32.0;
    if n_p <= 0.0 {
        return K_MIN as u64;
    }
    (target * span.max(1.0) / n_p).clamp(K_MIN, K_SAT).round() as u64
}

#[derive(Debug, Clone, Serialize)]
pub struct DispersionRow {
    pub shape: Dispersion,
    /// Mean distinct occupied rungs (the dispersion signal).
    pub occ_rungs: f64,
    /// count-only: one width from `N_P` and a fixed reference span (blind to spread).
    pub width_count_only: f64,
    pub set_count_only: f64,
    /// count + dispersion: width from `N_P` and the realised occupied-rungs.
    pub width_count_disp: f64,
    pub set_count_disp: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DispersionReport {
    pub n_p: u64,
    pub mean_shards: f64,
    pub target_set: f64,
    pub span_ref: f64,
    pub rows: Vec<DispersionRow>,
    /// Spread of realised set across the clustered↔dispersed bracket, count-only.
    pub gap_count_only: f64,
    /// …and with the dispersion scalar — does it close the gap?
    pub gap_count_disp: f64,
}

fn dispersion_value() -> DispersionReport {
    let (_, n_p, mean) = SCENARIOS[0]; // thin corner.
    let target = 8.0;
    let trials = 60_000u64;
    let shapes = [Dispersion::Clustered, Dispersion::Dispersed];

    // Reference span = mean occupied-rungs across both shapes — the best a
    // spread-blind count-only response can assume.
    let mut warm = SplitMix64::new(0x0D15_0001);
    let mut span_acc = 0.0;
    let mut span_n = 0u64;
    let mut pop: Vec<i64> = Vec::with_capacity(n_p as usize);
    for &shape in &shapes {
        for _ in 0..15_000 {
            pop.clear();
            pop.extend((0..n_p).map(|_| draw_shard_count(&mut warm, mean, shape) as i64));
            span_acc += effective_occupied_rungs(&pop);
            span_n += 1;
        }
    }
    let span_ref = span_acc / span_n as f64;

    let mut rows = Vec::new();
    let mut seed = 0x0D15_1000u64;
    for &shape in &shapes {
        let mut rng = SplitMix64::new(seed);
        seed += 1;
        let (mut occ, mut wc, mut sc, mut wd, mut sd) = (0.0, 0.0, 0.0, 0.0, 0.0);
        for _ in 0..trials {
            pop.clear();
            pop.extend((0..n_p).map(|_| draw_shard_count(&mut rng, mean, shape) as i64));
            let span = effective_occupied_rungs(&pop);
            let victim = (rng.next_u64() % n_p) as usize;

            let w_count = density_width(target, span_ref, n_p as f64); // blind to spread.
            let w_disp = density_width(target, span, n_p as f64); // spread-aware.

            occ += span;
            wc += w_count as f64;
            wd += w_disp as f64;
            sc += victim_realized_set(&mut rng, &pop, victim, w_count);
            sd += victim_realized_set(&mut rng, &pop, victim, w_disp);
        }
        let t = trials as f64;
        rows.push(DispersionRow {
            shape,
            occ_rungs: occ / t,
            width_count_only: wc / t,
            set_count_only: sc / t,
            width_count_disp: wd / t,
            set_count_disp: sd / t,
        });
    }

    let gap = |get: &dyn Fn(&DispersionRow) -> f64| (get(&rows[0]) - get(&rows[1])).abs();
    let gap_count_only = gap(&|r| r.set_count_only);
    let gap_count_disp = gap(&|r| r.set_count_disp);

    DispersionReport {
        n_p,
        mean_shards: mean,
        target_set: target,
        span_ref,
        rows,
        gap_count_only,
        gap_count_disp,
    }
}

pub fn run_dispersion_report() -> DispersionReport {
    dispersion_value()
}

// ===========================================================================
// Magnitude pass (§8): pin the D(count) curve's numbers under the JOINT corner
// (dispersed density × timing intersection × tight affordability) — the marginal
// set overstates, so size against the joint set, not it. For each count C:
// K_sat(C) (the saturation knee), the achievable set there, and the robust
// PLATEAU WIDTH (a sharp optimum ⇒ widen conservatism, don't pin the peak).
// C_boot is DERIVED, not guessed: the count below which even max-viable cover at
// the knee buys less than the floor's worth of set over the k=0 baseline — so the
// concession boundary falls out of the measured knee (§8.5).
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct MagnitudeRow {
    /// The count `f` reads (live active-bond count).
    pub count: u64,
    /// Saturation-knee dial at this count.
    pub k_sat: u64,
    /// `K_sat · floor` in SKL — the cover span the curve caps at here.
    pub cover_span_skl: f64,
    /// Realized joint set at the knee.
    pub set_at_knee: f64,
    /// Realized set at `k = 0` (the `C_min`-only / same-rung baseline).
    pub baseline_set: f64,
    /// What the blur buys over the baseline (`set_at_knee − baseline`).
    pub set_gain: f64,
    /// Robust plateau: dial values within 90% of the peak set (a wide band ⇒ safe
    /// to pin; a narrow band ⇒ the optimum is sharp, widen the conservatism).
    pub plateau_width_rungs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MagnitudeReport {
    pub mean_shards: f64,
    pub timing_retain: f64,
    pub beta: f64,
    pub floor_skl: f64,
    pub marginal_cutoff: f64,
    pub rows: Vec<MagnitudeRow>,
    /// **The continuity-clean `C_boot` (recommended):** the first count whose
    /// saturation knee is non-zero (`K_sat > 0`). At/below it `K_sat = 0`, so
    /// `k(C) = K_sat(C)` is **continuous through the boundary by construction** —
    /// the bootstrap clause is the `k = 0` tail of `K_sat`, not a glued step (§8.4).
    pub c_boot_continuity: Option<u64>,
    /// The cover span just above `c_boot_continuity` — small ⇒ no step (§8.4).
    pub c_boot_continuity_cover_span_skl: f64,
    /// The "cover becomes substantial" marker: the first count whose knee buys ≥
    /// the floor's worth (`set_gain ≥ baseline`). **NOT** the concession cutoff —
    /// conceding up to here would re-introduce the §8.4 step (here `K_sat` is
    /// already large). Reported as context only.
    pub c_substantial: Option<u64>,
}

fn magnitude_pin() -> MagnitudeReport {
    // Pessimistic JOINT corner: dispersed density, timing intersection on, tight
    // affordability, pessimistic per-staker portfolio (thin mean held fixed so the
    // x-axis is purely the count).
    let (_, _, mean) = SCENARIOS[0];
    let dispersion = Dispersion::Dispersed;
    let timing_retain = 0.5;
    let beta = 2.0;
    let floor_skl = ARCHIVAL_BOND_FLOOR_ATOMIC as f64 / ATOMIC_PER_SKL;
    let trials = 30_000u64;
    let step = 2u64;
    let ks: Vec<u64> = std::iter::once(0)
        .chain((step..=32).step_by(step as usize))
        .collect();
    let counts: [u64; 14] = [2, 3, 4, 5, 6, 8, 10, 12, 15, 17, 25, 40, 79, 154];

    let mut seed = 0x8A60_0001u64;
    let mut rows = Vec::new();
    for &count in &counts {
        let curve: Vec<f64> = ks
            .iter()
            .map(|&k| {
                seed += 1;
                realized_payer_set_mean(
                    count,
                    mean,
                    dispersion,
                    k,
                    timing_retain,
                    beta,
                    trials,
                    seed,
                )
            })
            .collect();
        let baseline_set = curve[0]; // k = 0
        let peak = curve.iter().cloned().fold(0.0_f64, f64::max);

        // Saturation knee: first k-step whose marginal gain per rung < cutoff.
        let mut k_sat = *ks.last().unwrap();
        for w in 1..ks.len() {
            let marginal = (curve[w] - curve[w - 1]) / step as f64;
            if marginal < MARGINAL_CUTOFF {
                k_sat = ks[w - 1];
                break;
            }
        }
        let set_at_knee = curve[ks.iter().position(|&k| k == k_sat).unwrap()];
        // Plateau width: dial values within 90% of the peak.
        let plateau_width_rungs = ks
            .iter()
            .zip(&curve)
            .filter(|(_, &s)| s >= 0.9 * peak)
            .count() as u64
            * step;

        rows.push(MagnitudeRow {
            count,
            k_sat,
            cover_span_skl: k_sat as f64 * floor_skl,
            set_at_knee,
            baseline_set,
            set_gain: set_at_knee - baseline_set,
            plateau_width_rungs,
        });
    }

    // Continuity-clean C_boot: the first count with a non-zero knee. Below it
    // K_sat = 0, so k(C) = K_sat(C) is continuous through the boundary (§8.4).
    let c_boot_continuity = rows.iter().find(|r| r.k_sat > 0).map(|r| r.count);
    let c_boot_continuity_cover_span_skl = c_boot_continuity
        .and_then(|c| rows.iter().find(|r| r.count == c))
        .map(|r| r.cover_span_skl)
        .unwrap_or(0.0);
    // The "cover becomes substantial" marker (floor's-worth) — context, not the cutoff.
    let c_substantial = rows
        .iter()
        .find(|r| r.set_gain >= r.baseline_set)
        .map(|r| r.count);

    MagnitudeReport {
        mean_shards: mean,
        timing_retain,
        beta,
        floor_skl,
        marginal_cutoff: MARGINAL_CUTOFF,
        rows,
        c_boot_continuity,
        c_boot_continuity_cover_span_skl,
        c_substantial,
    }
}

pub fn run_magnitude_report() -> MagnitudeReport {
    magnitude_pin()
}

// ===========================================================================
// The k(C) functional form (§8.8) — float-free reference C4 ports verbatim.
//
// Requirements (genesis-frozen): smooth, monotone, and DECAYING to zero in the
// low tail (k AND dk/dC → 0, so "bootstrap" is the limit of the ramp, not a
// clamp-kink, §8.4) — and EXACTLY evaluable in integer arithmetic, bit-identical
// across architectures, so two wallets compute the identical span from the same
// C (a float divergence would be a cross-wallet uniformity break, the very
// fingerprint the mechanism closes). A cubic smoothstep `s(t) = t²(3−2t)` has
// `s'(0) = s'(1) = 0` — zero slope at BOTH ends, so it decays into the tail and
// joins the cap with no kink — and as a cubic it is a finite integer expression.
// Output is the cover SPAN `C_max − C_min` in atomic units (the draw is then
// `bounded_uniform` over `[C_min, C_min + span]`, the standoff's integer draw).
// ===========================================================================

/// `K_sat → 0` tail boundary (§8.7): at/below this count the span is 0 — the
/// dissolved-`C_boot` bootstrap tail (§8.5).
const COVER_TAIL_COUNT: u64 = 13;
/// Count at which the ramp reaches the cap (the §8.7 knee plateau).
const COVER_RAMP_END_COUNT: u64 = 79;
/// Cover-span cap: `k = 10 rungs × 0.75 SKL = 7.5 SKL` (§8.7, joint-corner knee).
const COVER_SPAN_CAP_ATOMIC: u64 = 7_500_000_000;

/// `k(C)` as the cover span `C_max − C_min` in atomic units — the float-free
/// reference form (§8.8). Cubic-smoothstep ramp from `0` at `COVER_TAIL_COUNT`
/// (zero value *and* zero slope — the decay, not a clamp) to `COVER_SPAN_CAP_ATOMIC`
/// at `COVER_RAMP_END_COUNT` (joined with zero slope), flat thereafter. Pure u64
/// arithmetic ⇒ identical on every architecture; golden-vector-pinnable.
pub fn cover_dial_span_atomic(count: u64) -> u64 {
    if count <= COVER_TAIL_COUNT {
        return 0;
    }
    if count >= COVER_RAMP_END_COUNT {
        return COVER_SPAN_CAP_ATOMIC;
    }
    let num = count - COVER_TAIL_COUNT; // in (0, den)
    let den = COVER_RAMP_END_COUNT - COVER_TAIL_COUNT; // 66
                                                       // smoothstep s(t) = t²(3 − 2t) with t = num/den:
                                                       //   s = num²·(3·den − 2·num) / den³   (≤ den³, so span ≤ cap; monotone in num)
                                                       // span = cap · s. cap·s_num ≤ cap·den³ = 7.5e9·287_496 ≈ 2.16e15 < u64::MAX.
    let s_num = num * num * (3 * den - 2 * num);
    let s_den = den * den * den;
    COVER_SPAN_CAP_ATOMIC * s_num / s_den // floor division — deterministic
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
    fn cover_dial_span_golden_vector() {
        // Pinned (C, span) — C4 must reproduce these bit-for-bit (§8.8).
        assert_eq!(cover_dial_span_atomic(0), 0);
        assert_eq!(cover_dial_span_atomic(13), 0); // tail boundary
        assert_eq!(cover_dial_span_atomic(46), 3_750_000_000); // midpoint t=0.5 → cap/2
        assert_eq!(cover_dial_span_atomic(79), 7_500_000_000); // ramp end → cap
        assert_eq!(cover_dial_span_atomic(154), 7_500_000_000); // flat above
    }

    #[test]
    fn cover_dial_matches_standoff_reference() {
        // The sim's copy must equal the production form (`shekyl-standoff`, a
        // dev-dependency) at EVERY count — so drift between the two is
        // unrepresentable, not merely caught at the sampled golden points. If
        // either changes without the other, this fails.
        for c in 0..=200u64 {
            assert_eq!(
                cover_dial_span_atomic(c),
                shekyl_standoff::cover_dial_span_atomic(c),
                "sim k(C) diverged from shekyl-standoff at C={c}"
            );
        }
    }

    #[test]
    fn cover_dial_span_is_monotone_and_capped() {
        let mut prev = 0u64;
        for c in 0..=200u64 {
            let s = cover_dial_span_atomic(c);
            assert!(s >= prev, "monotone at C={c}");
            assert!(s <= 7_500_000_000, "capped at C={c}");
            prev = s;
        }
    }

    #[test]
    fn cover_dial_span_decays_into_the_tail_no_clamp_kink() {
        // Decay, not clamp: the second difference is POSITIVE just above the tail
        // (slope rising from 0 ⇒ convex ⇒ dk/dC → 0 into the tail), and NEGATIVE
        // near the cap (slope falling to 0 ⇒ concave ⇒ no kink at the join).
        let d = |c: u64| cover_dial_span_atomic(c + 1) as i128 - cover_dial_span_atomic(c) as i128;
        assert!(d(14) > d(13), "convex into the low tail (decay, not clamp)");
        assert!(d(76) < d(75), "concave into the cap (slope → 0, no kink)");
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
        // tax_worst is the deterministic rung-1 bound (k/1 = k), strictly above the
        // mean tax (k / mean_rung) — the regressive burden the smallest staker bears.
        let r = run(&base(16));
        assert!((r.tax_worst - 16.0).abs() < 1e-9);
        assert!(r.tax_worst > r.tax_mean);
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
    fn recommendation_pins_at_the_saturation_knee() {
        // The knee is a real interior point (not the scan ceiling), the worst tax
        // is k/1, and the saturation set never undershoots the pinned set.
        let rec = recommendation(1.0);
        assert!(rec.knee_rungs >= 4 && rec.knee_rungs < 48);
        assert!((rec.worst_tax_multiple - rec.knee_rungs as f64).abs() < 1e-9);
        assert!(rec.saturation_set >= rec.anon_set_mean - 1e-9);
    }

    #[test]
    fn participation_prices_out_low_rungs_and_shrinks_the_realized_set() {
        // At a wide dial and tight willingness-to-pay, low rungs opt out, so the
        // realized payer set is strictly below the honest-uniform set (§7.5).
        let p = run_participation(17, 9.0, Dispersion::Dispersed, 21, 2.0, 50_000, 7);
        assert!(p.min_paying_rung > 1);
        assert!(p.opt_out_frac > 0.0);
        assert!(p.payer_set_mean < p.honest_set_mean);
    }

    #[test]
    fn wider_dial_prices_out_more() {
        // More rungs of cover ⇒ a higher affordability floor ⇒ more opt-outs.
        let narrow = run_participation(17, 9.0, Dispersion::Dispersed, 8, 2.0, 50_000, 9);
        let wide = run_participation(17, 9.0, Dispersion::Dispersed, 32, 2.0, 50_000, 9);
        assert!(wide.opt_out_frac > narrow.opt_out_frac);
    }

    #[test]
    fn hump_robustness_reports_a_band_and_a_spread() {
        let h = hump_robustness();
        // robust_k is a real grid point; the worst-corner ratio is a fraction.
        assert!(h.robust_k >= 2 && h.robust_k <= 32);
        assert!(h.worst_corner_ratio > 0.0 && h.worst_corner_ratio <= 1.0 + 1e-9);
        assert_eq!(h.robust_band_90, h.worst_corner_ratio >= 0.90);
        // Every corner's peak is at least the same-rung baseline.
        assert!(h.corners.iter().all(|c| c.peak_set >= 1.0));
    }

    #[test]
    fn adaptive_never_underperforms_the_frozen_scalar() {
        // The adaptive dial is each density's own argmax over the grid, and the
        // frozen k is one grid point, so adaptive ≥ frozen on set at every level.
        let h = hump_robustness();
        for d in adaptive_vs_frozen(h.robust_k) {
            assert!(d.adaptive_set >= d.frozen_set - 1e-9, "level {}", d.label);
        }
    }

    #[test]
    fn leak_is_zero_at_no_drift_and_grows_with_drift() {
        let pts = leak_shock_check();
        let at_one = pts.iter().find(|p| (p.drift - 1.0).abs() < 1e-9).unwrap();
        assert!(at_one.leak_frac.abs() < 1e-9, "no drift ⇒ no leak");
        let at_three = pts.iter().find(|p| (p.drift - 3.0).abs() < 1e-9).unwrap();
        assert!(
            at_three.leak_frac > at_one.leak_frac,
            "leak grows with drift"
        );
        // And it stays bounded — even a 3× shock strips less than the whole set.
        assert!(at_three.leak_frac < 1.0);
    }

    #[test]
    fn targeting_no_attack_baseline_matches_across_modes() {
        // At m = 0 nothing is suppressed, so both modes sit at their honest width;
        // every per-point set is at least the same-rung baseline.
        let r = targeting_attack();
        let base = &r.points[0];
        assert_eq!(base.attacker_bonds, 0);
        assert!(base.count_uniform_set >= 1.0 && base.histogram_set >= 1.0);
        assert!(base.count_uniform_mod_set >= 1.0 && base.histogram_mod_set >= 1.0);
    }

    #[test]
    fn magnitude_pin_derives_c_boot_and_set_grows_with_count() {
        let r = magnitude_pin();
        // A bigger live-bond count buys a bigger achievable set at the knee.
        let first = &r.rows[0];
        let last = r.rows.last().unwrap();
        assert!(last.set_at_knee > first.set_at_knee);
        // Continuity-clean C_boot: the first non-zero knee. At/below it the knee is
        // 0, so k(C)=K_sat(C) is continuous through the boundary (no step).
        let c_boot = r.c_boot_continuity.expect("continuity C_boot derivable");
        if let Some(below) = r.rows.iter().rev().find(|x| x.count < c_boot) {
            assert_eq!(
                below.k_sat, 0,
                "knee must be 0 just below C_boot (continuity)"
            );
        }
        // The "substantial" marker sits at or above the continuity boundary (where
        // K_sat is already large) — conceding to it would re-introduce the step.
        if let Some(cs) = r.c_substantial {
            assert!(cs >= c_boot);
        }
    }

    #[test]
    fn dispersion_scalar_separates_shapes_and_narrows_the_gap() {
        // The dispersion signal distinguishes the shapes (dispersed occupies more
        // rungs), and feeding it into the width closes the realized-set gap that a
        // spread-blind count-only response leaves between clustered and dispersed.
        let r = dispersion_value();
        let clustered = &r.rows[0];
        let dispersed = &r.rows[1];
        assert_eq!(clustered.shape, Dispersion::Clustered);
        assert!(dispersed.occ_rungs > clustered.occ_rungs);
        assert!(r.gap_count_disp <= r.gap_count_only + 1e-9);
    }

    #[test]
    fn histogram_is_more_targetable_than_count_at_moderate_rungs() {
        // The decision measurement: at a wide attacker mass, the per-rung response
        // narrows a moderate (targetable) victim strictly more than the uniform
        // response — the local signal is a small number the attacker dominates,
        // while the global count dilutes the same mass across the whole network.
        let r = targeting_attack();
        let m8 = r.points.last().unwrap();
        assert_eq!(m8.attacker_bonds, 8);
        assert!(
            m8.histogram_mod_set < m8.count_uniform_mod_set,
            "histogram mod {} should be below count mod {}",
            m8.histogram_mod_set,
            m8.count_uniform_mod_set
        );
    }
}
