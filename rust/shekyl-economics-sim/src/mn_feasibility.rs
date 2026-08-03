// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `(m, n)` feasibility — the re-pin's decision surface, reported as a
//! **region** rather than an optimum.
//!
//! Constraint set (`FOLLOWUPS.md`, TJ entries):
//!
//! - **Floor** — false-slash probability over a bond life, from transport
//!   weather (`p^r` per read attempt-chain) and fabrication (bounded by the
//!   gap `e^−λ_eff`: a fabricated miss only survives in an epoch no diligent
//!   read covered).
//! - **Ceiling** — W16: every slash-free miss is a baseline a strategic
//!   degrader rides at crisis prices, so the window's slack has a deterrence
//!   cost.
//! - **Hard bound** — `n ≤ 25` from the prune-horizon assert.
//!
//! Wide-guardrails: the output is the feasible region and where the shipped
//! `(11, 13)` sits inside it. A genesis-adjacent constant moves only if the
//! region *excludes* it.
//!
//! # Observation unit
//!
//! Coverage `λ_eff` is **reads per pair per epoch**, but the failure window
//! counts **observations**. Three-valued settlement collapses an epoch's
//! reads to **one** observation (any authenticated pass settles the epoch
//! served). Observations therefore arrive at **≤ 1 per epoch** — slightly
//! under 1, because a gap epoch is a non-observation. A 13-observation window
//! spans **~13 epochs**, not `13/λ_eff`.
//!
//! What `λ_eff` buys sits in [`MissModel`]: pass-dominance **compounds** the
//! transport term across the epoch's reads — `(p^r)^j` for `j` reads, not
//! `p^r`. Coverage and retry depth are substitutes; coverage's version has
//! better independence (`j` miners / circuits vs `r` retries on one client).
//!
//! # Structure
//!
//! [`evaluate`] is the pure decision surface; [`mn_feasibility_report`] only
//! formats a [`FeasibilitySnapshot`]. Policy defaults live next to the model
//! ([`default_sources`], [`FeasibilityTargets::operative_defaults`]).

use core::fmt;

use shekyl_archival_retention::{
    FAILURE_WINDOW_M, FAILURE_WINDOW_N, MAX_HOLDINGS_SHARDS, SETTLEMENT_EPOCH_BLOCKS,
};

use crate::proxy::A5_REWARD_HORIZON_EPOCHS;

/// Hard ceiling on `n` (prune-horizon assert, `failure_window.rs`).
pub const N_HARD_BOUND: u32 = 25;

/// Bond life used by the report — A5's reward horizon (~5 y), not a second
/// lifetime constant.
pub const BOND_LIFE_EPOCHS: f64 = A5_REWARD_HORIZON_EPOCHS;

/// Sensitivity grid: retry depths under review (rig re-run still owns `r`).
const SENSITIVITY_RETRIES: [u32; 3] = [1, 2, 3];
/// Sensitivity grid: hashrate points (targeted φ saturates by ~1e-3).
const SENSITIVITY_F: [f64; 3] = [1.0, 0.10, 0.001];
/// Cap-delivered projection band; the operative projection is marked in-row.
const CAP_PAIR_BAND: [f64; 5] = [5_000.0, 10_000.0, 20_000.0, 40_000.0, 100_000.0];

// ── sources / model ─────────────────────────────────────────────────────────

/// Transport and fabrication inputs, with coverage **deliberately absent**.
///
/// [`evaluate`] derives delivered coverage from [`FeasibilityTargets`] and
/// builds every [`MissModel`] through [`MissSources::at_coverage`], so a call
/// site cannot hand the region a nominal `λ` where cap-delivered coverage
/// belongs.
#[derive(Debug, Clone, Copy)]
pub struct MissSources {
    /// Per-attempt transport failure. **Stand-in 0.30** (2026-07-30 cold-path
    /// onion, no PoW / no flood) — does not transfer to SP-T3; rig re-run gates
    /// the real value.
    pub p_attempt: f64,
    /// Attempts per read before a witness gives up (`r`).
    pub retries: u32,
    /// Probability a fabricator files a miss against this pair in an epoch.
    /// Under F-1 the operative value is [`targeted_fabrication_intensity`]
    /// (≈ 1 at any measurable hashrate). [`ambient_fabrication_intensity`] is
    /// the no-victim contrast only.
    pub fabrication_intensity: f64,
}

impl MissSources {
    /// Compose sources with **delivered** coverage into the per-epoch model.
    #[must_use]
    pub fn at_coverage(&self, lambda_eff: f64) -> MissModel {
        MissModel {
            lambda_eff,
            p_attempt: self.p_attempt,
            retries: self.retries,
            fabrication_intensity: self.fabrication_intensity,
        }
    }
}

/// Per-epoch miss model for one honest, live `(P, shard)` pair.
///
/// Built via [`MissSources::at_coverage`]. `lambda_eff` is **delivered**
/// coverage only — the policy target lives in
/// [`FeasibilityTargets::lambda_target`].
#[derive(Debug, Clone, Copy)]
pub struct MissModel {
    /// Delivered diligent reads per pair per epoch (never the policy target).
    pub lambda_eff: f64,
    pub p_attempt: f64,
    pub retries: u32,
    pub fabrication_intensity: f64,
}

impl MissModel {
    /// Probability one read's attempt-chain fails (`p^r`).
    #[must_use]
    pub fn read_failure(&self) -> f64 {
        self.p_attempt.clamp(0.0, 1.0).powi(self.retries as i32)
    }

    /// Gap probability `e^−λ_eff` — the only epoch class a fabricated miss
    /// can survive in (any pass dominates at settlement).
    #[must_use]
    pub fn gap(&self) -> f64 {
        (-self.lambda_eff.max(0.0)).exp()
    }

    /// Probability an epoch settles as an observation (served or missed).
    /// A gap is a non-observation unless a fabricator files into it.
    #[must_use]
    pub fn observation_rate(&self) -> f64 {
        1.0 - self.gap() * (1.0 - self.fabrication_intensity.clamp(0.0, 1.0))
    }

    /// Probability an epoch settles as a **missed** observation.
    ///
    /// Disjoint sources: fabrication `e^−λ · φ`, and transport
    /// `e^{−λ(1−p^r)} − e^{−λ}` (Poisson PGF, no truncation).
    #[must_use]
    pub fn missed_epoch_rate(&self) -> f64 {
        let fabricated = self.gap() * self.fabrication_intensity.clamp(0.0, 1.0);
        let x = self.read_failure();
        let transport = (-self.lambda_eff.max(0.0) * (1.0 - x)).exp() - self.gap();
        fabricated + transport.max(0.0)
    }

    /// Per-**observation** miss probability `q` — the failure window's input.
    /// Evaluate at cap-delivered `λ_eff`, not the nominal target.
    #[must_use]
    pub fn miss_given_observation(&self) -> f64 {
        let obs = self.observation_rate();
        if obs <= 0.0 {
            return 0.0;
        }
        (self.missed_epoch_rate() / obs).clamp(0.0, 1.0)
    }
}

// ── fabrication / coverage ──────────────────────────────────────────────────

/// Ambient (spraying, no-victim) fabrication intensity: `1 − e^(−f·λ)`.
/// Not the attack model — see [`targeted_fabrication_intensity`] (F-1).
#[must_use]
pub fn ambient_fabrication_intensity(f: f64, lambda_target: f64) -> f64 {
    let f = f.clamp(0.0, 1.0);
    1.0 - (-f * lambda_target.max(0.0)).exp()
}

/// Targeted fabrication intensity — operative threat.
///
/// Sets are miner-chosen, so an attacker places the victim in every won
/// block: `φ = 1 − (1−f)^SEB`. Saturates almost immediately (`f = 10⁻³` ≈ 1).
/// Floor evaluation must use this, not the ambient spray term.
#[must_use]
pub fn targeted_fabrication_intensity(f: f64, seb: f64) -> f64 {
    let f = f.clamp(0.0, 1.0);
    if f <= 0.0 || seb <= 0.0 {
        return 0.0;
    }
    // 1 − (1−f)^SEB via ln1p/expm1 for tiny-f accuracy.
    -((seb * (-f).ln_1p()).exp_m1())
}

/// Delivered coverage under `k_cap`: `λ_eff = min(k_cap, k)·SEB/pairs`.
#[must_use]
pub fn delivered_lambda(lambda_target: f64, pairs: f64, seb: f64, k_cap: f64) -> f64 {
    if pairs <= 0.0 || seb <= 0.0 {
        return 0.0;
    }
    let k_wanted = lambda_target * pairs / seb;
    k_wanted.min(k_cap.max(0.0)) * seb / pairs
}

// ── window / bound ──────────────────────────────────────────────────────────

/// Probability a window of `n` i.i.d. observations carries `≥ m` misses.
///
/// Two-sided binomial recurrence keyed on `min(q, 1−q)` so seeds stay away
/// from underflow when `q` is next to 1 (a one-sided `(1−q)^n` seed zeros the
/// whole tail for `n ≥ 22` and falsely reports infinite margin).
#[must_use]
pub fn window_exceedance(m: u32, n: u32, q: f64) -> f64 {
    if m == 0 {
        return 1.0;
    }
    if m > n {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    let tail = if q <= 0.5 {
        let ratio = q / (1.0 - q);
        let mut term = (1.0 - q).powi(n as i32);
        let mut sum = 0.0;
        for i in 0..=n {
            if i >= m {
                sum += term;
            }
            if i < n {
                term *= f64::from(n - i) / f64::from(i + 1) * ratio;
            }
        }
        sum
    } else {
        // P(X ≥ m) = Σ_{k=0}^{n−m} C(n,k)·(1−q)^k·q^(n−k).
        let ratio = (1.0 - q) / q;
        let mut term = q.powi(n as i32);
        let mut sum = 0.0;
        for k in 0..=(n - m) {
            sum += term;
            if k < n - m {
                term *= f64::from(n - k) / f64::from(k + 1) * ratio;
            }
        }
        sum
    };
    tail.clamp(0.0, 1.0)
}

/// Union-bound **upper** bound on false-slash over at most `max_observations`
/// draws.
///
/// `max_observations` must be a **deterministic ceiling**, never an
/// expectation: a realization above the mean would carry more sliding windows
/// than an expectation-priced bound covered. The miss fact supplies the
/// ceiling: ≤ 1 observation per epoch, so `bond_life_epochs` is the hard cap.
///
/// Tightness in the small-`q` regime is licensed by
/// [`crate::proxy::first_slash_probability`].
#[must_use]
pub fn false_slash_bound(m: u32, n: u32, q: f64, max_observations: f64) -> f64 {
    if max_observations <= 0.0 || n == 0 {
        return 0.0;
    }
    let windows = (max_observations - f64::from(n) + 1.0).max(0.0);
    (windows * window_exceedance(m, n, q)).clamp(0.0, 1.0)
}

/// W16 free-ride fraction `(m−1)/n`.
#[must_use]
pub fn free_ride_fraction(m: u32, n: u32) -> f64 {
    if n == 0 {
        return 0.0;
    }
    f64::from(m.saturating_sub(1)) / f64::from(n)
}

/// Operator-axis exposure at `MAX_HOLDINGS_SHARDS`: `1 − (1 − p)^MAX_HOLDINGS`
/// via `ln_1p`/`exp_m1`. Floor targets are set on this axis.
#[must_use]
pub fn max_holder_exposure(per_pair: f64) -> f64 {
    -((MAX_HOLDINGS_SHARDS as f64) * (-per_pair).ln_1p()).exp_m1()
}

// ── exposure helpers (single verdict pipeline) ──────────────────────────────

/// Shipped-window (or probe-window) exposure on both axes.
#[derive(Debug, Clone, Copy)]
pub struct PinExposure {
    pub m: u32,
    pub n: u32,
    pub false_slash_pair: f64,
    pub false_slash_max_holder: f64,
    pub free_ride: f64,
}

impl PinExposure {
    #[must_use]
    fn at(m: u32, n: u32, q: f64, max_observations: f64) -> Self {
        let false_slash_pair = false_slash_bound(m, n, q, max_observations);
        Self {
            m,
            n,
            false_slash_pair,
            false_slash_max_holder: max_holder_exposure(false_slash_pair),
            free_ride: free_ride_fraction(m, n),
        }
    }

    #[must_use]
    pub fn clears_floor(&self, false_slash_target: f64) -> bool {
        self.false_slash_max_holder <= false_slash_target
    }

    #[must_use]
    pub fn floor_margin(&self, false_slash_target: f64) -> f64 {
        if self.false_slash_max_holder > 0.0 {
            false_slash_target / self.false_slash_max_holder
        } else {
            f64::INFINITY
        }
    }

    #[must_use]
    pub fn floor_verdict(&self, false_slash_target: f64) -> &'static str {
        if self.clears_floor(false_slash_target) {
            "clears"
        } else {
            "EXCEEDS"
        }
    }
}

#[must_use]
fn floor_verdict_flag(clears: bool) -> &'static str {
    if clears {
        "clears"
    } else {
        "EXCEEDS"
    }
}

// ── policy inputs ───────────────────────────────────────────────────────────

/// Policy inputs — maintainer choices or pinned constants, none derived here.
///
/// `lambda_target` sizes `k`; delivered coverage is
/// [`delivered_lambda`] of it. Bundle keeps the target/delivered split in the
/// type rather than a comment.
#[derive(Debug, Clone, Copy)]
pub struct FeasibilityTargets {
    /// Coverage the pin asks for (`λ_target = 3`). Sizes `k`.
    pub lambda_target: f64,
    /// Floor budget: `P(any pair slashed)` over a bond life, per ARCHIVER.
    pub false_slash_target: f64,
    /// Ceiling: free-ride fraction bound (W16 crisis-price economics).
    pub free_ride_bound: f64,
    /// Step-2 cap on challenges per block.
    pub k_cap: f64,
    /// Settlement-epoch length in blocks.
    pub seb: f64,
    /// Pair-count projection the operative region is evaluated at.
    pub projected_pairs: f64,
}

impl FeasibilityTargets {
    /// Operative defaults for the stage-2 report — the single home for MN
    /// policy numbers (not scattered in the orchestrator).
    ///
    /// - `λ_target = 3` (step-2 pin)
    /// - false-slash budget `1e-3` per archiver over a bond life (**provisional**)
    /// - free-ride bound `0.80` (W16 input; shipped pin sits at `10/13 ≈ 0.77`)
    /// - `k_cap = 6` (mid-band of 4–9)
    /// - projection `40_000` pairs (twice the `k_cap` knee at 20 k, so the
    ///   cap bind is material: delivered = half the target)
    #[must_use]
    pub fn operative_defaults() -> Self {
        Self {
            lambda_target: 3.0,
            false_slash_target: 1e-3,
            free_ride_bound: 0.80,
            k_cap: 6.0,
            seb: SETTLEMENT_EPOCH_BLOCKS as f64,
            projected_pairs: 40_000.0,
        }
    }
}

/// Default sources minus coverage: stand-in `p`, single-retry witnesses,
/// targeted fabrication intensity `φ ≈ 1`. Coverage is derived by
/// [`evaluate`] from [`FeasibilityTargets`].
#[must_use]
pub fn default_sources() -> MissSources {
    MissSources {
        p_attempt: 0.30,
        retries: 1,
        fabrication_intensity: 1.0,
    }
}

// ── pure evaluation surface ─────────────────────────────────────────────────

/// One sensitivity-table row (retry × hashrate) at the shipped window.
#[derive(Debug, Clone, Copy)]
pub struct SensitivityRow {
    pub retries: u32,
    pub f: f64,
    pub phi_targeted: f64,
    pub phi_ambient: f64,
    pub q: f64,
    pub holder: f64,
    pub clears: bool,
}

/// One cap-delivered projection row at the shipped window.
#[derive(Debug, Clone, Copy)]
pub struct CapDeliveredRow {
    pub pairs: f64,
    pub k_wanted: f64,
    pub lambda_eff: f64,
    pub gap: f64,
    pub q: f64,
    pub holder: f64,
    pub clears: bool,
    pub is_operative: bool,
}

/// Feasible-region edge for one `n`: floor-set `m_min`, ceiling-set `m_max`.
#[derive(Debug, Clone, Copy)]
pub struct RegionRow {
    pub n: u32,
    pub m_min: Option<u32>,
    pub m_max: Option<u32>,
    /// Per-pair false-slash at `m_min` when the row is feasible.
    pub fs_at_m_min: Option<f64>,
    /// Free-ride at `m_max` when present.
    pub free_ride_at_m_max: Option<f64>,
}

impl RegionRow {
    #[must_use]
    pub fn is_feasible(&self) -> bool {
        matches!((self.m_min, self.m_max), (Some(lo), Some(hi)) if lo <= hi)
    }

    /// Whether `(m, n)` sits inside this row's feasible band.
    #[must_use]
    pub fn contains(&self, m: u32) -> bool {
        match (self.m_min, self.m_max) {
            (Some(lo), Some(hi)) => lo <= m && m <= hi,
            _ => false,
        }
    }
}

/// Pure decision surface: every number the report prints, with no formatting.
#[derive(Debug, Clone)]
pub struct FeasibilitySnapshot {
    pub targets: FeasibilityTargets,
    pub bond_life_epochs: f64,
    /// Union-bound ceiling (= bond life): ≤ 1 observation per epoch.
    pub observation_ceiling: f64,
    pub delivered_lambda: f64,
    pub knee_pairs: f64,
    pub model: MissModel,
    pub q: f64,
    pub observation_rate: f64,
    pub shipped: PinExposure,
    /// Whether the shipped `(m, n)` lies in the feasible band at the
    /// operative point (false when the row is infeasible or `m` is outside).
    pub shipped_in_region: bool,
    pub sensitivity: Vec<SensitivityRow>,
    pub cap_delivered: Vec<CapDeliveredRow>,
    pub region: Vec<RegionRow>,
}

/// Evaluate the `(m, n)` region at cap-delivered coverage for `targets`.
///
/// Coverage enters only through [`delivered_lambda`] — the caller supplies
/// [`MissSources`] (no λ field), so the nominal target cannot leak into
/// region numbers.
#[must_use]
pub fn evaluate(
    sources: &MissSources,
    bond_life_epochs: f64,
    targets: &FeasibilityTargets,
) -> FeasibilitySnapshot {
    let FeasibilityTargets {
        lambda_target,
        false_slash_target,
        free_ride_bound,
        k_cap,
        seb,
        projected_pairs,
    } = *targets;

    let delivered = delivered_lambda(lambda_target, projected_pairs, seb, k_cap);
    let model = sources.at_coverage(delivered);
    let q = model.miss_given_observation();
    // Deterministic ceiling (≤ 1 obs/epoch), not E[obs] = bond_life · rate.
    let observation_ceiling = bond_life_epochs;
    let knee_pairs = if lambda_target > 0.0 {
        k_cap * seb / lambda_target
    } else {
        0.0
    };

    let shipped = PinExposure::at(FAILURE_WINDOW_M, FAILURE_WINDOW_N, q, observation_ceiling);

    let mut sensitivity = Vec::with_capacity(SENSITIVITY_RETRIES.len() * SENSITIVITY_F.len());
    for &r in &SENSITIVITY_RETRIES {
        for &f in &SENSITIVITY_F {
            let phi = targeted_fabrication_intensity(f, seb);
            let probe = MissModel {
                retries: r,
                fabrication_intensity: phi,
                ..model
            };
            let q_probe = probe.miss_given_observation();
            let pin = PinExposure::at(
                FAILURE_WINDOW_M,
                FAILURE_WINDOW_N,
                q_probe,
                observation_ceiling,
            );
            sensitivity.push(SensitivityRow {
                retries: r,
                f,
                phi_targeted: phi,
                phi_ambient: ambient_fabrication_intensity(f, lambda_target),
                q: q_probe,
                holder: pin.false_slash_max_holder,
                clears: pin.clears_floor(false_slash_target),
            });
        }
    }

    let mut cap_delivered = Vec::with_capacity(CAP_PAIR_BAND.len());
    for &pairs in &CAP_PAIR_BAND {
        let lam = delivered_lambda(lambda_target, pairs, seb, k_cap);
        let probe = sources.at_coverage(lam);
        let q_probe = probe.miss_given_observation();
        let pin = PinExposure::at(
            FAILURE_WINDOW_M,
            FAILURE_WINDOW_N,
            q_probe,
            observation_ceiling,
        );
        cap_delivered.push(CapDeliveredRow {
            pairs,
            k_wanted: lambda_target * pairs / seb,
            lambda_eff: lam,
            gap: probe.gap(),
            q: q_probe,
            holder: pin.false_slash_max_holder,
            clears: pin.clears_floor(false_slash_target),
            is_operative: (pairs - projected_pairs).abs() < 0.5,
        });
    }

    let region = region_edges(
        &model,
        observation_ceiling,
        false_slash_target,
        free_ride_bound,
    );
    let shipped_in_region = region
        .iter()
        .find(|r| r.n == shipped.n)
        .is_some_and(|r| r.contains(shipped.m));

    FeasibilitySnapshot {
        targets: *targets,
        bond_life_epochs,
        observation_ceiling,
        delivered_lambda: delivered,
        knee_pairs,
        model,
        q,
        observation_rate: model.observation_rate(),
        shipped,
        shipped_in_region,
        sensitivity,
        cap_delivered,
        region,
    }
}

/// Floor/ceiling edges per `n`, computed in one pass (no re-filter of a flat
/// cell bag).
fn region_edges(
    model: &MissModel,
    observation_ceiling: f64,
    false_slash_target: f64,
    free_ride_bound: f64,
) -> Vec<RegionRow> {
    let q = model.miss_given_observation();
    let mut rows = Vec::with_capacity((N_HARD_BOUND - 1) as usize);
    for n in 2..=N_HARD_BOUND {
        let mut m_min = None;
        let mut m_max = None;
        let mut fs_at_m_min = None;
        let mut free_ride_at_m_max = None;
        for m in 2..=n {
            let pin = PinExposure::at(m, n, q, observation_ceiling);
            if m_min.is_none() && pin.clears_floor(false_slash_target) {
                m_min = Some(m);
                fs_at_m_min = Some(pin.false_slash_pair);
            }
            // free_ride rises with m; last m under the bound is m_max.
            if pin.free_ride <= free_ride_bound {
                m_max = Some(m);
                free_ride_at_m_max = Some(pin.free_ride);
            }
        }
        rows.push(RegionRow {
            n,
            m_min,
            m_max,
            fs_at_m_min,
            free_ride_at_m_max,
        });
    }
    rows
}

// ── report (format only) ────────────────────────────────────────────────────

/// Format a precomputed [`FeasibilitySnapshot`]. Prefer [`evaluate`] + this
/// when the numbers are needed without prose.
pub fn write_report(out: &mut impl fmt::Write, snap: &FeasibilitySnapshot) -> fmt::Result {
    let t = &snap.targets;
    let model = &snap.model;
    let floor = t.false_slash_target;
    let mh = MAX_HOLDINGS_SHARDS;

    writeln!(
        out,
        "\n(m,n) FEASIBILITY — region, not optimum (wide-guardrails: a shipped\n\
         constant moves only if the region EXCLUDES it).\n\
         Inputs: lambda_target={LT:.3} reads/pair/epoch; OPERATIVE evaluation at\n\
         DELIVERED lambda={DL:.3} (projection {PP:.0} pairs; k_cap binds past\n\
         {KNEE:.0} pairs, so target and delivered coincide only below that knee);\n\
         p_attempt={P:.3} (STAND-IN: measured 2026-07-30 with NO PoW and NO\n\
         flood -- does not transfer to the SP-T3 operating point; the rig re-run\n\
         gates the real value), r={R}, fabrication_intensity={FI:.2} (1.00 =\n\
         every gap epoch poisoned).",
        LT = t.lambda_target,
        DL = snap.delivered_lambda,
        PP = t.projected_pairs,
        KNEE = snap.knee_pairs,
        P = model.p_attempt,
        R = model.retries,
        FI = model.fabrication_intensity,
    )?;
    writeln!(
        out,
        "  OBSERVATION UNIT (correction the miss-fact ruling forces): an epoch's\n\
         reads collapse to ONE observation (any pass dominates), so observations\n\
         arrive at {OR:.4}/epoch -- NOT lambda_eff/epoch. A {N}-observation window\n\
         spans ~{SPAN:.1} epochs, so detection latency does NOT collapse and the\n\
         within-epoch independence worry does not arise (draws stay one per epoch,\n\
         weeks apart). What lambda_eff buys instead: pass-dominance COMPOUNDS the\n\
         transport term across an epoch's reads -- (p^r)^j for j reads, not p^r --\n\
         so coverage and retry depth are SUBSTITUTES on that term, and coverage's\n\
         version has better independence (j miners, j circuits vs r retries on one).",
        OR = snap.observation_rate,
        N = FAILURE_WINDOW_N,
        SPAN = f64::from(FAILURE_WINDOW_N) / snap.observation_rate,
    )?;
    writeln!(
        out,
        "  TERMS: gap (poisonable) = e^-lambda = {G:.4}; read-failure p^r = {RF:.4};\n\
         per-epoch missed = {ME:.6}; per-OBSERVATION miss q = {Q:.6}.\n\
         Bond life {BL:.0} epochs; union-bound ceiling = {CEIL:.0} observations\n\
         (<= 1 obs/epoch; E[obs] = bond_life * rate = {EOBS:.1}).",
        G = model.gap(),
        RF = model.read_failure(),
        ME = model.missed_epoch_rate(),
        Q = snap.q,
        BL = snap.bond_life_epochs,
        CEIL = snap.observation_ceiling,
        EOBS = snap.bond_life_epochs * snap.observation_rate,
    )?;

    let s = &snap.shipped;
    writeln!(
        out,
        "  SHIPPED PIN ({SM} of {SN}): false-slash/pair over bond life = {FS:.3e};\n\
         at MAX_HOLDINGS ({MH} pairs) = {FH:.3e} vs target {T:.1e} per ARCHIVER --\n\
         {VERDICT}, margin {MAR:.1e}x on the operator axis; free-ride fraction =\n\
         {FR:.3} (W16 bound {FRB:.3}); region membership = {IN}.",
        SM = s.m,
        SN = s.n,
        FS = s.false_slash_pair,
        MH = mh,
        FH = s.false_slash_max_holder,
        T = floor,
        VERDICT = s.floor_verdict(floor),
        MAR = s.floor_margin(floor),
        FR = s.free_ride,
        FRB = t.free_ride_bound,
        IN = if snap.shipped_in_region {
            "inside"
        } else {
            "OUTSIDE"
        },
    )?;

    // P(any) is the operative frame: a slash opens a record-scoped bad
    // interval (excludes the whole record from r_market, blocks HoldingsUpdate
    // until Rebond). Expected pairs lost prices only the burn.
    let bond_floor_skl = crate::proxy::bond_at_risk_skl();
    writeln!(
        out,
        "  EXPOSURE FRAMING — RULED: P(any pair slashed) is the operative frame,\n\
         and the reason is mechanical rather than a risk preference. A slash\n\
         opens a bad interval on the RECORD (bad_intervals are record-scoped, not\n\
         per-shard), which excludes the whole record from r_market via\n\
         good_through and blocks HoldingsUpdate until Rebond. One pair slashed is\n\
         therefore a whole-portfolio disruption plus a burn -- the harm is\n\
         record-scoped, so the probability must be too. At the shipped pin,\n\
         P(any of {MH} pairs) = {FH:.3e}; EXPECTED pairs lost = {EP:.3e} (~{SKL:.4}\n\
         SKL of {TOT:.0} posted) is recorded only to show the ~{MH}x framing gap the\n\
         ruling closes -- it prices the burn while ignoring the exclusion, which\n\
         is the larger harm.",
        MH = mh,
        FH = s.false_slash_max_holder,
        EP = mh as f64 * s.false_slash_pair,
        SKL = mh as f64 * s.false_slash_pair * bond_floor_skl,
        TOT = mh as f64 * bond_floor_skl,
    )?;

    writeln!(
        out,
        "  SENSITIVITY — does the shipped ({SM},{SN}) clear the floor? Evaluated at\n\
         the TARGETED fabrication intensity (F-1): sets are miner-chosen, so an\n\
         adversary attacking one victim does NOT spray -- it puts the victim in\n\
         its k slots in every block it wins, and poisoning an epoch needs ONE won\n\
         block, so phi = 1-(1-f)^SEB saturates at ~1 by f = 1e-3. The ambient\n\
         (no-victim) column 1-e^-(f*lambda) is shown only as the contrast; the\n\
         floor must be read against the targeted one. Rows are evaluated at the\n\
         operative delivered coverage; r stays unpinned pending the PoW-enabled\n\
         rig re-run.",
        SM = FAILURE_WINDOW_M,
        SN = FAILURE_WINDOW_N,
    )?;
    writeln!(
        out,
        "{:<6} {:>9} {:>10} {:>10} {:>12} {:>14} {:>10}",
        "r",
        "f",
        "phi_tgt",
        "phi_amb",
        "q/obs",
        format!("P(any) @{mh}"),
        "verdict"
    )?;
    for row in &snap.sensitivity {
        writeln!(
            out,
            "{:<6} {:>9.3} {:>10.4} {:>10.4} {:>12.5} {:>14.2e} {:>10}",
            row.retries,
            row.f,
            row.phi_targeted,
            row.phi_ambient,
            row.q,
            row.holder,
            floor_verdict_flag(row.clears),
        )?;
    }

    writeln!(
        out,
        "  CAP-DELIVERED COVERAGE (k_cap = {KC:.0}, SEB = {SEB:.0}): the fabrication\n\
         term must be read at DELIVERED lambda at projected pair counts, since\n\
         k = lambda_target*pairs/SEB is capped. Each row carries the SHIPPED\n\
         pin's floor verdict at that delivery, so the projection choice reads\n\
         off this table:",
        KC = t.k_cap,
        SEB = t.seb,
    )?;
    writeln!(
        out,
        "{:<12} {:>10} {:>12} {:>14} {:>12} {:>14} {:>10}",
        "pairs",
        "k wanted",
        "lambda_eff",
        "gap (poison)",
        "q/obs",
        format!("P(any) @{mh}"),
        "verdict"
    )?;
    for row in &snap.cap_delivered {
        writeln!(
            out,
            "{:<12.0} {:>10.2} {:>12.3} {:>14.4} {:>12.5} {:>14.2e} {:>10}{OP}",
            row.pairs,
            row.k_wanted,
            row.lambda_eff,
            row.gap,
            row.q,
            row.holder,
            floor_verdict_flag(row.clears),
            OP = if row.is_operative {
                "  <- operative"
            } else {
                ""
            },
        )?;
    }

    writeln!(
        out,
        "  FEASIBLE REGION at the operative point (delivered lambda {DL:.3},\n\
         projection {PP:.0} pairs, r={R}, targeted phi={FI:.2}):",
        DL = snap.delivered_lambda,
        PP = t.projected_pairs,
        R = model.retries,
        FI = model.fabrication_intensity,
    )?;
    writeln!(
        out,
        "{:<5} {:>8} {:>8} {:>14} {:>14}",
        "n", "m_min", "m_max", "fs@m_min", "free-ride@m_max"
    )?;
    for row in &snap.region {
        if row.is_feasible() {
            if let (Some(lo), Some(hi), Some(fs), Some(fr)) = (
                row.m_min,
                row.m_max,
                row.fs_at_m_min,
                row.free_ride_at_m_max,
            ) {
                writeln!(
                    out,
                    "{n:<5} {lo:>8} {hi:>8} {fs:>14.2e} {fr:>14.3}",
                    n = row.n
                )?;
            }
        } else {
            writeln!(
                out,
                "{n:<5} {:>8} {:>8} {:>14} {:>14}",
                row.m_min.map_or_else(|| "-".to_string(), |v| v.to_string()),
                row.m_max.map_or_else(|| "-".to_string(), |v| v.to_string()),
                "infeasible",
                "-",
                n = row.n,
            )?;
        }
    }
    writeln!(
        out,
        "  -> m_min is floor-set (false-slash at MAX_HOLDINGS <= target -- the axis\n\
         an OPERATOR experiences, since every held pair is independently exposed;\n\
         per-pair alone understates it by up to {MH}x). m_max is ceiling-set (W16\n\
         free-ride). A cell is feasible iff m_min <= m <= m_max. The W16 bound is\n\
         an INPUT here: its value comes from the crisis-price degrade economics,\n\
         not from this arm. The operative verdicts are GATED on two labelled\n\
         inputs: the stand-in p (rig re-run) and the pair projection -- move\n\
         either and the same tables re-answer without re-deriving the arm.",
        MH = mh,
    )?;
    Ok(())
}

/// Evaluate then format — stage-2 entry point.
pub fn mn_feasibility_report(
    out: &mut impl fmt::Write,
    sources: &MissSources,
    bond_life_epochs: f64,
    targets: &FeasibilityTargets,
) -> fmt::Result {
    write_report(out, &evaluate(sources, bond_life_epochs, targets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::first_slash_probability;

    fn default_snapshot() -> FeasibilitySnapshot {
        evaluate(
            &default_sources(),
            BOND_LIFE_EPOCHS,
            &FeasibilityTargets::operative_defaults(),
        )
    }

    #[test]
    fn shipped_pin_clearance_is_a_snapshot_property() {
        let snap = default_snapshot();
        assert_eq!(snap.shipped.m, FAILURE_WINDOW_M);
        assert_eq!(snap.shipped.n, FAILURE_WINDOW_N);
        // Clearance and region membership are snapshot booleans — not report
        // string scraping.
        let clears = snap.shipped.clears_floor(snap.targets.false_slash_target);
        assert_eq!(
            snap.shipped_in_region,
            snap.region
                .iter()
                .find(|r| r.n == snap.shipped.n)
                .is_some_and(|r| r.contains(snap.shipped.m))
        );
        // Free-ride must also sit under the W16 bound for membership to hold.
        if snap.shipped_in_region {
            assert!(clears);
            assert!(snap.shipped.free_ride <= snap.targets.free_ride_bound);
        }
        assert!(snap.shipped.false_slash_max_holder.is_finite());
        assert!(snap.shipped.false_slash_pair >= 0.0);
        // Delivered λ at the operative projection is below target (cap binds
        // past 20 k pairs; projection is 40 k).
        assert!(snap.delivered_lambda < snap.targets.lambda_target);
        assert!((snap.observation_ceiling - BOND_LIFE_EPOCHS).abs() < 1e-12);
    }

    #[test]
    fn region_edges_cover_the_shipped_window_or_mark_it() {
        let snap = default_snapshot();
        let row = snap
            .region
            .iter()
            .find(|r| r.n == FAILURE_WINDOW_N)
            .expect("region includes shipped n");
        // Either the shipped m is inside the band, or the row is infeasible /
        // m is outside — both are legitimate snapshot outcomes; the contract
        // is that evaluate reports the edges consistently with PinExposure.
        if row.is_feasible() {
            let lo = row.m_min.unwrap();
            let hi = row.m_max.unwrap();
            assert!(lo <= hi);
            assert!(row.contains(lo));
            assert!(row.contains(hi));
            // Edges must match recomputation at the operative q.
            let at_lo = PinExposure::at(lo, row.n, snap.q, snap.observation_ceiling);
            assert!(at_lo.clears_floor(snap.targets.false_slash_target));
            if lo > 2 {
                let below = PinExposure::at(lo - 1, row.n, snap.q, snap.observation_ceiling);
                assert!(!below.clears_floor(snap.targets.false_slash_target));
                assert!(!row.contains(lo - 1));
            }
            let at_hi = PinExposure::at(hi, row.n, snap.q, snap.observation_ceiling);
            assert!(at_hi.free_ride <= snap.targets.free_ride_bound + 1e-15);
        }
    }

    #[test]
    fn sensitivity_holder_falls_as_retry_depth_rises() {
        let snap = default_snapshot();
        // Fix f = 1.0 (first column of each retry block) and require holder
        // to drop when r increases — retry depth is the remaining floor lever
        // under targeted fabrication.
        let at_f1: Vec<_> = snap
            .sensitivity
            .iter()
            .filter(|r| (r.f - 1.0).abs() < 1e-15)
            .collect();
        assert_eq!(at_f1.len(), SENSITIVITY_RETRIES.len());
        for w in at_f1.windows(2) {
            assert!(
                w[1].holder < w[0].holder,
                "r={} holder {} should beat r={} holder {}",
                w[1].retries,
                w[1].holder,
                w[0].retries,
                w[0].holder
            );
        }
    }

    #[test]
    fn operative_cap_row_is_marked() {
        let snap = default_snapshot();
        let marked: Vec<_> = snap
            .cap_delivered
            .iter()
            .filter(|r| r.is_operative)
            .collect();
        assert_eq!(marked.len(), 1);
        assert!((marked[0].pairs - snap.targets.projected_pairs).abs() < 0.5);
        assert!((marked[0].lambda_eff - snap.delivered_lambda).abs() < 1e-12);
    }

    #[test]
    fn union_bound_is_an_upper_bound_and_tight_where_it_matters() {
        let (m, n) = (FAILURE_WINDOW_M, FAILURE_WINDOW_N);
        let obs = 120u64;
        for &q in &[1e-4_f64, 1e-3, 1e-2] {
            let exact = first_slash_probability(q, obs);
            let bound = false_slash_bound(m, n, q, obs as f64);
            assert!(
                exact > 0.0,
                "kernel returned no mass at q={q} — a vacuous license"
            );
            assert!(
                bound + 1e-18 >= exact,
                "union bound {bound:.3e} below exact {exact:.3e} at q={q}"
            );
            assert!(
                bound / exact < 1.5,
                "bound {bound:.3e} not tight vs exact {exact:.3e} at q={q}"
            );
        }
    }

    #[test]
    fn pass_dominance_compounds_the_transport_term() {
        // Compounding is real but Poisson-dispersion-bounded: j=1 epochs
        // dominate, so the gain is ~4× not the mean-read (p^r)^λ myth.
        let m = MissModel {
            lambda_eff: 3.0,
            p_attempt: 0.30,
            retries: 1,
            fabrication_intensity: 0.0,
        };
        let transport = m.missed_epoch_rate();
        let single = m.read_failure();
        assert!(
            transport < 0.5 * single,
            "compounding must beat a single read's failure by >2x: {transport} vs {single}"
        );
        assert!(
            transport > single.powi(3),
            "must NOT reach the mean-read figure {}: dispersion forbids it",
            single.powi(3)
        );
        let thinner = MissModel {
            lambda_eff: 1.0,
            ..m
        };
        assert!(thinner.missed_epoch_rate() > transport);
        let deeper = MissModel { retries: 2, ..m };
        assert!(deeper.missed_epoch_rate() < transport);
    }

    #[test]
    fn observations_arrive_at_most_once_per_epoch() {
        for &lam in &[1.0_f64, 3.0, 6.0] {
            let m = MissModel {
                fabrication_intensity: 0.0,
                ..default_sources().at_coverage(lam)
            };
            let rate = m.observation_rate();
            assert!(rate < 1.0 && rate > 0.0);
            assert!(f64::from(FAILURE_WINDOW_N) / rate > f64::from(FAILURE_WINDOW_N));
        }
    }

    #[test]
    fn max_holdings_exposure_dominates_the_per_pair_number() {
        let per_pair = 1e-9_f64;
        let holder = max_holder_exposure(per_pair);
        assert!(holder > per_pair * 4000.0);
        assert!(holder < 1.0);
    }

    #[test]
    fn delivered_coverage_decays_once_k_cap_binds() {
        let (target, seb, k_cap) = (3.0, 10_000.0, 6.0);
        let below = delivered_lambda(target, 10_000.0, seb, k_cap);
        let above = delivered_lambda(target, 40_000.0, seb, k_cap);
        assert!((below - target).abs() < 1e-12, "cap slack below the knee");
        assert!(above < target, "cap must bind past the knee: {above}");
        assert!(above > 0.0);
    }

    #[test]
    fn the_bound_holds_against_the_worst_realized_observation_count() {
        // Ceiling = bond_life dominates every realizable count; expectation
        // pricing is strictly smaller and would void the upper-bound claim.
        let (m, n, q) = (FAILURE_WINDOW_M, FAILURE_WINDOW_N, 1e-2_f64);
        let bond_life = 131.0_f64;
        let bound = false_slash_bound(m, n, q, bond_life);
        for realized in [60u64, 100, 131] {
            let exact = first_slash_probability(q, realized);
            assert!(exact > 0.0, "kernel returned no mass at {realized} draws");
            assert!(
                bound + 1e-18 >= exact,
                "bound {bound:.3e} below exact {exact:.3e} at {realized} observations"
            );
        }
        let expectation_priced = false_slash_bound(m, n, q, bond_life * 0.95);
        assert!(expectation_priced < bound);
    }

    #[test]
    fn targeted_fabrication_saturates_where_ambient_does_not() {
        let (lam, seb) = (3.0, 10_000.0);
        assert!(targeted_fabrication_intensity(0.0, seb).abs() < 1e-12);
        assert!(targeted_fabrication_intensity(1e-3, seb) > 0.99);
        assert!(targeted_fabrication_intensity(1e-4, seb) > 0.60);
        for &f in &[1e-3_f64, 1e-2, 0.10, 0.30] {
            let tgt = targeted_fabrication_intensity(f, seb);
            let amb = ambient_fabrication_intensity(f, lam);
            assert!(
                tgt > amb,
                "targeted must exceed ambient at f={f}: {tgt} vs {amb}"
            );
        }
        assert!(ambient_fabrication_intensity(0.10, lam) < 0.30);
    }

    #[test]
    fn retry_depth_not_hashrate_is_what_carries_the_floor() {
        let seb = 10_000.0;
        let base = MissModel {
            fabrication_intensity: targeted_fabrication_intensity(1e-3, seb),
            ..default_sources().at_coverage(3.0)
        };
        let tiny_f = MissModel {
            fabrication_intensity: targeted_fabrication_intensity(1e-2, seb),
            ..base
        };
        assert!(
            (base.miss_given_observation() - tiny_f.miss_given_observation()).abs() < 1e-3,
            "targeted fabrication must not scale with hashrate"
        );
        let deeper = MissModel { retries: 2, ..base };
        assert!(deeper.miss_given_observation() < 0.6 * base.miss_given_observation());
    }

    #[test]
    fn window_exceedance_survives_q_next_to_one() {
        let q = 1.0 - 1e-16;
        assert!(q < 1.0);
        assert!(window_exceedance(N_HARD_BOUND, N_HARD_BOUND, q) > 0.999);
        // Complement identity across the q = 1/2 seam.
        for &qq in &[0.1_f64, 0.3, 0.5, 0.7, 0.9, 0.97] {
            let lhs = window_exceedance(11, 13, qq);
            let rhs = 1.0 - window_exceedance(3, 13, 1.0 - qq);
            assert!(
                (lhs - rhs).abs() < 1e-12,
                "branch seam at q={qq}: {lhs} vs {rhs}"
            );
        }
    }

    #[test]
    fn free_ride_rises_with_m_and_falls_with_n() {
        assert!(free_ride_fraction(11, 13) > free_ride_fraction(6, 13));
        assert!(free_ride_fraction(11, 25) < free_ride_fraction(11, 13));
    }

    #[test]
    fn write_report_emits_ceiling_wording_not_arrow_equality() {
        let snap = default_snapshot();
        let mut buf = String::new();
        write_report(&mut buf, &snap).unwrap();
        assert!(
            buf.contains("union-bound ceiling"),
            "report must name the ceiling, not imply bond_life = E[obs]"
        );
        assert!(
            !buf.contains("epochs =>"),
            "old 'epochs => observations' arrow conflated ceiling with count"
        );
        assert!(
            buf.contains(&format!("P(any) @{MAX_HOLDINGS_SHARDS}")),
            "table headers must track MAX_HOLDINGS_SHARDS, not a hard-coded 4096"
        );
    }
}
