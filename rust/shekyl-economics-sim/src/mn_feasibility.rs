// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `(m, n)` feasibility — the re-pin's decision surface, reported as a
//! **region** rather than an optimum.
//!
//! The round's closed constraint set (`FOLLOWUPS.md`, TJ entries):
//!
//! - **Floor** — false-slash probability over a bond life, from two
//!   independent sources: transport weather (`p^r` per read attempt-chain)
//!   and fabrication (bounded by the gap fraction `e^−λ_eff`, since a
//!   fabricated miss only survives in an epoch no diligent read covered).
//! - **Ceiling** — W16: every slash-free miss is a baseline a strategic
//!   degrader rides at crisis prices, so the window's slack has a deterrence
//!   cost.
//! - **Hard bound** — `n ≤ 25` from the prune-horizon assert.
//!
//! **Wide-guardrails discipline:** the output is the feasible region and where
//! the shipped `(11, 13)` sits inside it. Moving a genesis-adjacent constant
//! requires the region to *exclude* it; a confirmation with margins is the
//! more valuable result and the one this arm is built to produce.
//!
//! # The observation unit — a correction the miss-fact ruling forces
//!
//! Coverage `λ_eff` is **reads per pair per epoch**, but the failure window
//! counts **observations**, and the ratified three-valued settlement collapses
//! an epoch's reads to **one** observation: any authenticated pass settles the
//! epoch served, so `λ_eff` reads of a live pair produce one served
//! observation, not `λ_eff` of them. Observations therefore still arrive at
//! **≤ 1 per epoch** — slightly under 1, because a gap epoch (no read at all)
//! is a *non-observation* the window never sees. A 13-observation window
//! consequently spans **~13 epochs**, not `13/λ_eff` ≈ 4.3, so detection
//! latency does not collapse and the within-epoch independence worry does not
//! arise (the draws remain one-per-epoch and weeks apart).
//!
//! What `λ_eff` *does* buy is stronger and sits in [`MissModel`]: because any
//! one pass clears the epoch, the transport term **compounds** across the
//! epoch's reads — `(p^r)^j` for `j` reads, not `p^r`. Coverage and retry
//! depth are therefore **substitutes** for the transport term, and coverage's
//! version is the better one: `j` reads come from `j` different miners on
//! different circuits and guards, where `r` retries share one client's
//! vantage.

use core::fmt;

use shekyl_archival_retention::{FAILURE_WINDOW_M, FAILURE_WINDOW_N, MAX_HOLDINGS_SHARDS};

use crate::proxy::A5_REWARD_HORIZON_EPOCHS;

/// Hard ceiling on `n` (prune-horizon assert, `failure_window.rs`).
pub const N_HARD_BOUND: u32 = 25;

/// Per-epoch miss model for **one honest, live `(P, shard)` pair**.
///
/// Every field is an input the round pinned or measured elsewhere; this type
/// only composes them. Named so a reader can see which measurement each
/// number is waiting on.
#[derive(Debug, Clone, Copy)]
pub struct MissModel {
    /// **Delivered** diligent reads per pair per epoch — never the policy
    /// target.
    ///
    /// The two coincide only while `k_cap` is slack; past the knee delivered
    /// coverage decays as `k_cap·SEB/pairs` ([`delivered_lambda`]). Keeping
    /// this field single-meaning is deliberate: the target lives in
    /// [`FeasibilityTargets::lambda_target`], so a call site cannot quietly
    /// pass one where the other belongs and skew the region (review finding,
    /// 2026-08-02).
    pub lambda_eff: f64,
    /// Per-attempt transport failure probability. **Stand-in: 0.30**, the
    /// 2026-07-30 cold-path onion measurement taken with **no PoW and no
    /// flood** — it does not transfer to the SP-T3 operating point and is
    /// carried only so the shape is reviewable before the rig re-run gates it.
    pub p_attempt: f64,
    /// Attempts per read before a witness gives up (`r`). Retry depth costs
    /// `W`-blocks, not bandwidth.
    pub retries: u32,
    /// Probability a fabricator files a miss against this pair in a given
    /// epoch. Under F-1 the operative value is the **targeted** one
    /// ([`targeted_fabrication_intensity`]), which is ≈ 1 at any measurable
    /// hashrate — so `1.0` is the realistic setting for an attacked pair, not
    /// a far corner. [`ambient_fabrication_intensity`] is the no-victim term.
    pub fabrication_intensity: f64,
}

impl MissModel {
    /// Probability one read's attempt-chain fails outright (`p^r`).
    #[must_use]
    pub fn read_failure(&self) -> f64 {
        self.p_attempt.clamp(0.0, 1.0).powi(self.retries as i32)
    }

    /// Probability an epoch yields **no** diligent read — the gap, `e^−λ_eff`.
    /// This is the only epoch class a fabricated miss can survive in, because
    /// any pass dominates a miss at settlement.
    #[must_use]
    pub fn gap(&self) -> f64 {
        (-self.lambda_eff.max(0.0)).exp()
    }

    /// Probability an epoch settles as an **observation** (served or missed)
    /// rather than a non-observation.
    ///
    /// A gap epoch is a non-observation *unless* a fabricator files into it.
    #[must_use]
    pub fn observation_rate(&self) -> f64 {
        1.0 - self.gap() * (1.0 - self.fabrication_intensity.clamp(0.0, 1.0))
    }

    /// Probability an epoch settles as a **missed observation**.
    ///
    /// Two disjoint sources, matching the round's two false-slash terms:
    ///
    /// - **fabrication** — a gap epoch a fabricator files into: `e^−λ · φ`;
    /// - **transport** — an epoch with `j ≥ 1` reads where *all* `j` fail:
    ///   `Σ_{j≥1} Pois(j; λ)·(p^r)^j = e^{−λ(1−p^r)} − e^{−λ}` (the Poisson
    ///   PGF, so no truncation error).
    #[must_use]
    pub fn missed_epoch_rate(&self) -> f64 {
        let fabricated = self.gap() * self.fabrication_intensity.clamp(0.0, 1.0);
        let x = self.read_failure();
        let transport = (-self.lambda_eff.max(0.0) * (1.0 - x)).exp() - self.gap();
        fabricated + transport.max(0.0)
    }

    /// Per-**observation** miss probability `q` — the failure window's input.
    ///
    /// The window counts observations, so this conditions on the epoch being
    /// one. **Evaluate at cap-delivered `λ_eff`, not the nominal target:**
    /// `k = λ_target·pairs/SEB` is capped at `k_cap`, so past the pair count
    /// where the cap binds, delivered coverage falls below `λ_target` and the
    /// gap — hence the fabrication term — grows.
    #[must_use]
    pub fn miss_given_observation(&self) -> f64 {
        let obs = self.observation_rate();
        if obs <= 0.0 {
            return 0.0;
        }
        (self.missed_epoch_rate() / obs).clamp(0.0, 1.0)
    }
}

/// **Ambient** fabrication intensity — a *spraying* adversary with no victim.
///
/// At hashrate `f` a fabricator wins `f·SEB` blocks per epoch carrying `k`
/// records each; spread uniformly over `pairs` pairs that is `f·λ_target` per
/// pair per epoch, so a given pair draws at least one with probability
/// `1 − e^(−f·λ)`. This is the right model **only** for the no-victim case:
/// background noise across the whole population.
///
/// It is **not** the model for an attack, and using it as one was F-1 (see
/// [`targeted_fabrication_intensity`]).
#[must_use]
pub fn ambient_fabrication_intensity(f: f64, lambda_target: f64) -> f64 {
    let f = f.clamp(0.0, 1.0);
    1.0 - (-f * lambda_target.max(0.0)).exp()
}

/// **Targeted** fabrication intensity — the operative threat, and it does not
/// scale with hashrate the way the ambient term does.
///
/// **F-1 (2026-08-02):** the ambient model divides the attack by `pairs`, which
/// silently assumes the adversary does not concentrate. Sets are **miner-chosen**
/// — that is this round's own ruling — so a fabricator attacking one victim does
/// not spray: it places the victim's pair in its `k` slots in **every block it
/// wins**. Poisoning an epoch needs exactly **one** won block, so
///
/// ```text
/// φ_targeted = 1 − (1 − f)^SEB
/// ```
///
/// which saturates almost immediately: `f = 10⁻⁴` already gives ≈ 0.63 and
/// `f = 10⁻³` gives ≈ 1. **For a targeted adversary `φ ≈ 1` at any measurable
/// hashrate**, so the floor must be evaluated there and the fabrication term is
/// *not* an adversary courtesy the region may lean on.
///
/// This is the same defect shape the round has rejected before — bounding an
/// adversary by assuming it does not optimize — arriving through a uniformity
/// assumption rather than an explicit one.
#[must_use]
pub fn targeted_fabrication_intensity(f: f64, seb: f64) -> f64 {
    let f = f.clamp(0.0, 1.0);
    if f <= 0.0 || seb <= 0.0 {
        return 0.0;
    }
    // 1 − (1−f)^SEB via ln1p/expm1 so it stays exact at the tiny `f` where the
    // saturation point actually sits.
    -((seb * (-f).ln_1p()).exp_m1())
}

/// Delivered coverage under the `k_cap` bind: `λ_eff = min(k_cap, k)·SEB/pairs`
/// where `k` is what `λ_target` would ask for.
///
/// Below the knee the cap is slack and delivered coverage is the target; above
/// it, coverage decays as `k_cap·SEB/pairs` — which is why the standing
/// discipline evaluates the fabrication term at **projected** pair counts.
#[must_use]
pub fn delivered_lambda(lambda_target: f64, pairs: f64, seb: f64, k_cap: f64) -> f64 {
    if pairs <= 0.0 || seb <= 0.0 {
        return 0.0;
    }
    let k_wanted = lambda_target * pairs / seb;
    k_wanted.min(k_cap.max(0.0)) * seb / pairs
}

/// Probability a window of `n` i.i.d. observations carries `≥ m` misses.
#[must_use]
pub fn window_exceedance(m: u32, n: u32, q: f64) -> f64 {
    if m == 0 {
        return 1.0;
    }
    if m > n {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    // Binomial tail by direct term recurrence — n ≤ 25, so no special
    // machinery is warranted and the terms stay exactly representable.
    let mut term = (1.0 - q).powi(n as i32);
    let mut tail = 0.0;
    for i in 0..=n {
        if i >= m {
            tail += term;
        }
        if i < n {
            // term(i+1) = term(i) · (n−i)/(i+1) · q/(1−q), guarded at q → 1.
            if q >= 1.0 {
                term = if i + 1 == n { 1.0 } else { 0.0 };
            } else {
                term *= f64::from(n - i) / f64::from(i + 1) * (q / (1.0 - q));
            }
        }
    }
    tail.clamp(0.0, 1.0)
}

/// Union-bound **upper** bound on false-slash over at most `max_observations`
/// draws.
///
/// Rigorous (a union over the sliding windows) and tight exactly where the
/// answer matters — the small-probability regime a false-slash target lives
/// in. [`false_slash_exact`] measures the slack at the shipped pin.
///
/// **`max_observations` must be a DETERMINISTIC ceiling, never an
/// expectation.** The observation count over a bond life is random, and a
/// realization above its mean would carry more sliding windows than the bound
/// priced — which would silently void the "upper bound" claim in exactly the
/// tail the floor target cares about. The ratified miss fact supplies the
/// ceiling for free: an epoch settles to at most ONE observation, so
/// `bond_life_epochs` *is* the hard cap and no distribution over counts is
/// needed. (Found by review, 2026-08-02; the arm previously passed
/// `bond_life · observation_rate`.)
#[must_use]
pub fn false_slash_bound(m: u32, n: u32, q: f64, max_observations: f64) -> f64 {
    if max_observations <= 0.0 || n == 0 {
        return 0.0;
    }
    let windows = (max_observations - f64::from(n) + 1.0).max(0.0);
    (windows * window_exceedance(m, n, q)).clamp(0.0, 1.0)
}

/// The fraction of observations a *placing* degrader may miss indefinitely
/// without ever tripping the window — W16's free-ride term, `(m−1)/n`.
#[must_use]
pub fn free_ride_fraction(m: u32, n: u32) -> f64 {
    if n == 0 {
        return 0.0;
    }
    f64::from(m.saturating_sub(1)) / f64::from(n)
}

/// Absorption table for a **counterfactual** `(m, n)`: for each prior-window
/// state, does a miss at the head trigger a slash?
///
/// The sweep needs the rule evaluated at parameters production cannot express
/// (`failure_window_slashable` reads the shipped constants), so this is a
/// parameterized twin — and
/// [`tests::parameterized_twin_matches_production_at_the_shipped_pin`] pins it
/// against the production predicate over **every** state at `(11, 13)`. The
/// twin may only ever be wrong about counterfactuals if it is also wrong at
/// the pin, which fails the build.
#[cfg_attr(not(test), allow(dead_code))]
fn absorb_table_for(m: u32, n: u32) -> Vec<bool> {
    let width = n.saturating_sub(1) as usize;
    (0..(1usize << width))
        .map(|state| 1 + (state as u32).count_ones() >= m)
        .collect()
}

/// Exact false-slash probability over `observations` draws, by the same
/// absorbing-chain walk the A5/TJ arms use — kept for **validating the union
/// bound**, and bounded to `n ≤ 20` because the state space is `2^(n−1)`.
#[must_use]
// Binary package: unit tests are a separate crate, so a validation-only helper
// trips `-D dead-code` on the non-test bin (the `cartel.rs` precedent).
#[cfg_attr(not(test), allow(dead_code))]
pub fn false_slash_exact(m: u32, n: u32, q: f64, observations: u64) -> Option<f64> {
    if n == 0 || n > 20 || m > n {
        return None;
    }
    let absorb = absorb_table_for(m, n);
    let states = absorb.len();
    let mask = states - 1;
    let q = q.clamp(0.0, 1.0);
    let mut dist = vec![0.0_f64; states];
    dist[0] = 1.0;
    let mut next = vec![0.0_f64; states];
    let mut absorbed = 0.0_f64;
    for _ in 0..observations {
        next.iter_mut().for_each(|v| *v = 0.0);
        for (state, &mass) in dist.iter().enumerate() {
            if mass < 1e-300 {
                continue;
            }
            let miss = mass * q;
            if absorb[state] {
                absorbed += miss;
            } else {
                next[((state << 1) | 1) & mask] += miss;
            }
            next[(state << 1) & mask] += mass * (1.0 - q);
        }
        core::mem::swap(&mut dist, &mut next);
    }
    Some(absorbed)
}

/// One `(m, n)` cell of the feasibility sweep.
#[derive(Debug, Clone, Copy)]
pub struct Cell {
    pub m: u32,
    pub n: u32,
    /// False-slash probability for ONE pair over the bond life (union bound).
    pub false_slash_pair: f64,
    /// The same exposure for an archiver at `MAX_HOLDINGS_SHARDS` — what an
    /// operator actually experiences, since every held pair is independently
    /// exposed.
    pub false_slash_max_holder: f64,
    /// W16 free-ride fraction `(m−1)/n`.
    pub free_ride: f64,
}

/// Sweep the admissible box, returning the **raw** cell for every `(m, n)`.
///
/// No filtering happens here: the floor and ceiling targets are policy inputs
/// and are applied by [`mn_feasibility_report`], so a caller wanting a
/// different target reads the same cells against it rather than re-running the
/// sweep.
#[must_use]
pub fn sweep(model: &MissModel, bond_life_epochs: f64, n_max: u32) -> Vec<Cell> {
    let q = model.miss_given_observation();
    // Deterministic ceiling, not the expected count — see `false_slash_bound`.
    let observations = bond_life_epochs;
    let mut cells = Vec::new();
    for n in 2..=n_max.min(N_HARD_BOUND) {
        for m in 2..=n {
            let per_pair = false_slash_bound(m, n, q, observations);
            cells.push(Cell {
                m,
                n,
                false_slash_pair: per_pair,
                // Independent pairs: 1 − (1 − p)^shards, computed via expm1/ln1p
                // so it stays accurate at the small p the floor targets.
                false_slash_max_holder: -((MAX_HOLDINGS_SHARDS as f64) * (-per_pair).ln_1p())
                    .exp_m1(),
                free_ride: free_ride_fraction(m, n),
            });
        }
    }
    cells
}

/// Policy inputs to the feasibility report — every one a maintainer choice or
/// a pinned constant, none of them derived by this arm.
///
/// Bundled so the **target vs delivered** split is visible in the type rather
/// than in a comment: `lambda_target` is what `k` is sized from, while a
/// [`MissModel`]'s `lambda_eff` is what a pair actually receives.
#[derive(Debug, Clone, Copy)]
pub struct FeasibilityTargets {
    /// Coverage the pin asks for (`λ_target = 3`). Sizes `k`, and is the
    /// spread the *ambient* fabrication term divides across.
    pub lambda_target: f64,
    /// Floor budget: `P(any pair slashed)` over a bond life, per ARCHIVER.
    pub false_slash_target: f64,
    /// Ceiling: the fraction of observations a placing degrader may ride free.
    /// W16's crisis-price economics owns the real value.
    pub free_ride_bound: f64,
    /// Step-2 cap on challenges per block.
    pub k_cap: f64,
    /// Settlement-epoch length in blocks.
    pub seb: f64,
}

/// `(m, n)` feasibility report.
pub fn mn_feasibility_report(
    out: &mut impl fmt::Write,
    model: &MissModel,
    bond_life_epochs: f64,
    targets: &FeasibilityTargets,
) -> fmt::Result {
    let FeasibilityTargets {
        lambda_target,
        false_slash_target,
        free_ride_bound,
        k_cap,
        seb,
    } = *targets;
    let q = model.miss_given_observation();
    let obs_rate = model.observation_rate();
    // Deterministic ceiling (<= 1 observation per epoch), not the expected
    // count — the union bound's guarantee depends on it.
    let observations = bond_life_epochs;
    writeln!(
        out,
        "\n(m,n) FEASIBILITY — region, not optimum (wide-guardrails: a shipped\n\
         constant moves only if the region EXCLUDES it).\n\
         Inputs: lambda_eff={LE:.3} reads/pair/epoch, p_attempt={P:.3} (STAND-IN:\n\
         measured 2026-07-30 with NO PoW and NO flood -- does not transfer to the\n\
         SP-T3 operating point; the rig re-run gates the real value), r={R},\n\
         fabrication_intensity={FI:.2} (1.00 = every gap epoch poisoned).",
        LE = model.lambda_eff,
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
        OR = obs_rate,
        N = FAILURE_WINDOW_N,
        SPAN = f64::from(FAILURE_WINDOW_N) / obs_rate,
    )?;
    writeln!(
        out,
        "  TERMS: gap (poisonable) = e^-lambda = {G:.4}; read-failure p^r = {RF:.4};\n\
         per-epoch missed = {ME:.6}; per-OBSERVATION miss q = {Q:.6}.\n\
         Bond life {BL:.0} epochs => {OBS:.0} observations.",
        G = model.gap(),
        RF = model.read_failure(),
        ME = model.missed_epoch_rate(),
        Q = q,
        BL = bond_life_epochs,
        OBS = observations,
    )?;

    // The shipped pin, with its margins on both sides.
    let (sm, sn) = (FAILURE_WINDOW_M, FAILURE_WINDOW_N);
    let shipped_fs = false_slash_bound(sm, sn, q, observations);
    let shipped_holder = -((MAX_HOLDINGS_SHARDS as f64) * (-shipped_fs).ln_1p()).exp_m1();
    writeln!(
        out,
        "  SHIPPED PIN ({SM} of {SN}): false-slash/pair over bond life = {FS:.3e}\n\
         (target {T:.1e}, margin {MAR:.1e}x); at MAX_HOLDINGS ({MH} pairs) = {FH:.3e};\n\
         free-ride fraction = {FR:.3} (W16 bound {FRB:.3}).",
        SM = sm,
        SN = sn,
        FS = shipped_fs,
        T = false_slash_target,
        MAR = if shipped_fs > 0.0 {
            false_slash_target / shipped_fs
        } else {
            f64::INFINITY
        },
        MH = MAX_HOLDINGS_SHARDS,
        FH = shipped_holder,
        FR = free_ride_fraction(sm, sn),
        FRB = free_ride_bound,
    )?;

    // Which exposure the target applies to is a MATERIAL choice, so report
    // both rather than smuggling one in: P(any pair slashed) treats a single
    // shard's FLOOR as the event, while expected-pairs-lost prices it. At
    // MAX_HOLDINGS the two differ by ~4096x in framing but describe the same
    // arithmetic, and they support opposite readings of the same margin.
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
        MH = MAX_HOLDINGS_SHARDS,
        FH = shipped_holder,
        EP = MAX_HOLDINGS_SHARDS as f64 * shipped_fs,
        SKL = MAX_HOLDINGS_SHARDS as f64 * shipped_fs * 0.75,
        TOT = MAX_HOLDINGS_SHARDS as f64 * 0.75,
    )?;

    // Sensitivity: the region's POSITION is set by two inputs neither pinned
    // (`r`, and the fabrication intensity). A single-point verdict would read
    // as a property of (m, n) when it is mostly a property of those two.
    writeln!(
        out,
        "  SENSITIVITY — does the shipped ({SM},{SN}) clear the floor? Evaluated at\n\
         the TARGETED fabrication intensity (F-1): sets are miner-chosen, so an\n\
         adversary attacking one victim does NOT spray -- it puts the victim in\n\
         its k slots in every block it wins, and poisoning an epoch needs ONE won\n\
         block, so phi = 1-(1-f)^SEB saturates at ~1 by f = 1e-3. The ambient\n\
         (no-victim) column 1-e^-(f*lambda) is shown only as the contrast; the\n\
         floor must be read against the targeted one. r stays unpinned pending\n\
         the PoW-enabled rig re-run.",
        SM = FAILURE_WINDOW_M,
        SN = FAILURE_WINDOW_N,
    )?;
    writeln!(
        out,
        "{:<6} {:>9} {:>10} {:>10} {:>12} {:>14} {:>10}",
        "r", "f", "phi_tgt", "phi_amb", "q/obs", "P(any) @4096", "verdict"
    )?;
    for &r in &[1u32, 2, 3] {
        for &f in &[1.00_f64, 0.10, 0.001] {
            let phi = targeted_fabrication_intensity(f, seb);
            let phi_amb = ambient_fabrication_intensity(f, lambda_target);
            let probe = MissModel {
                retries: r,
                fabrication_intensity: phi,
                ..*model
            };
            let q_probe = probe.miss_given_observation();
            let obs_probe = bond_life_epochs * probe.observation_rate();
            let pair = false_slash_bound(FAILURE_WINDOW_M, FAILURE_WINDOW_N, q_probe, obs_probe);
            let holder = -((MAX_HOLDINGS_SHARDS as f64) * (-pair).ln_1p()).exp_m1();
            writeln!(
                out,
                "{:<6} {:>9.3} {:>10.4} {:>10.4} {:>12.5} {:>14.2e} {:>10}",
                r,
                f,
                phi,
                phi_amb,
                q_probe,
                holder,
                if holder <= false_slash_target {
                    "clears"
                } else {
                    "EXCEEDS"
                }
            )?;
        }
    }

    // The standing discipline, executed rather than restated: the fabrication
    // term evaluates at CAP-DELIVERED coverage at projected pair counts, not
    // at the nominal target — past the knee the cap binds and the poisonable
    // gap grows, which is the term the floor is most sensitive to.
    writeln!(
        out,
        "  CAP-DELIVERED COVERAGE (k_cap = {KC:.0}, SEB = {SEB:.0}): the fabrication\n\
         term must be read at DELIVERED lambda at projected pair counts, since\n\
         k = lambda_target*pairs/SEB is capped:",
        KC = k_cap,
        SEB = seb,
    )?;
    writeln!(
        out,
        "{:<12} {:>10} {:>12} {:>14}",
        "pairs", "k wanted", "lambda_eff", "gap (poison)"
    )?;
    for &pairs in &[5_000.0_f64, 10_000.0, 20_000.0, 40_000.0, 100_000.0] {
        let lam = delivered_lambda(lambda_target, pairs, seb, k_cap);
        let probe = MissModel {
            lambda_eff: lam,
            ..*model
        };
        writeln!(
            out,
            "{:<12.0} {:>10.2} {:>12.3} {:>14.4}",
            pairs,
            lambda_target * pairs / seb,
            lam,
            probe.gap()
        )?;
    }

    // Feasible region: the lowest admissible m per n is what the floor sets;
    // the ceiling caps how high m may go before free-riding is over-cheap.
    writeln!(
        out,
        "{:<5} {:>8} {:>8} {:>14} {:>14}",
        "n", "m_min", "m_max", "fs@m_min", "free-ride@m_max"
    )?;
    let cells = sweep(model, bond_life_epochs, N_HARD_BOUND);
    for n in 4..=N_HARD_BOUND {
        let row: Vec<&Cell> = cells.iter().filter(|c| c.n == n).collect();
        let m_min = row
            .iter()
            .find(|c| c.false_slash_max_holder <= false_slash_target)
            .map(|c| c.m);
        let m_max = row
            .iter()
            .filter(|c| c.free_ride <= free_ride_bound)
            .map(|c| c.m)
            .next_back();
        match (m_min, m_max) {
            (Some(lo), Some(hi)) if lo <= hi => {
                let fs = row
                    .iter()
                    .find(|c| c.m == lo)
                    .map_or(0.0, |c| c.false_slash_pair);
                let fr = free_ride_fraction(hi, n);
                writeln!(out, "{n:<5} {lo:>8} {hi:>8} {fs:>14.2e} {fr:>14.3}")?;
            }
            (lo, hi) => writeln!(
                out,
                "{n:<5} {:>8} {:>8} {:>14} {:>14}",
                lo.map_or("-".to_string(), |v| v.to_string()),
                hi.map_or("-".to_string(), |v| v.to_string()),
                "infeasible",
                "-"
            )?,
        }
    }
    writeln!(
        out,
        "  -> m_min is floor-set (false-slash at MAX_HOLDINGS <= target -- the axis\n\
         an OPERATOR experiences, since every held pair is independently exposed;\n\
         per-pair alone understates it by up to {MH}x). m_max is ceiling-set (W16\n\
         free-ride). A cell is feasible iff m_min <= m <= m_max. The W16 bound is\n\
         an INPUT here: its value comes from the crisis-price degrade economics,\n\
         not from this arm.",
        MH = MAX_HOLDINGS_SHARDS,
    )?;
    Ok(())
}

/// The arm's default operating point: pinned `λ_target`, the labelled
/// stand-in `p`, and the A5 reward horizon as a bond life.
#[must_use]
pub fn default_model() -> MissModel {
    MissModel {
        lambda_eff: 3.0,
        p_attempt: 0.30,
        retries: 1,
        fabrication_intensity: 1.0,
    }
}

/// Bond life used by the report — reuses A5's reward horizon (~5 y) rather
/// than inventing a second lifetime constant.
pub const BOND_LIFE_EPOCHS: f64 = A5_REWARD_HORIZON_EPOCHS;

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::{failure_window_slashable, BaselineObservation};

    #[test]
    fn parameterized_twin_matches_production_at_the_shipped_pin() {
        // dep-don't-mirror, in the only form a counterfactual sweep admits:
        // the twin is parameterized, but at the SHIPPED (m, n) it must agree
        // with `failure_window_slashable` on EVERY state. If production's rule
        // changes shape, this fails rather than the sweep silently answering
        // for a window the chain no longer runs.
        let (m, n) = (FAILURE_WINDOW_M, FAILURE_WINDOW_N);
        let twin = absorb_table_for(m, n);
        let base = u64::from(n) + 1;
        for (state, &twin_says) in twin.iter().enumerate() {
            let mut obs = vec![BaselineObservation::missed(base)];
            for i in 0..(n as usize - 1) {
                let epoch = base - 1 - i as u64;
                if (state >> i) & 1 == 1 {
                    obs.push(BaselineObservation::missed(epoch));
                } else {
                    obs.push(BaselineObservation::served(epoch));
                }
            }
            let production = failure_window_slashable(&obs).expect("well-formed window");
            assert_eq!(twin_says, production, "divergence at state {state:#x}");
        }
    }

    #[test]
    fn union_bound_is_an_upper_bound_and_tight_where_it_matters() {
        // The bound is the sweep's workhorse (O(n) per cell); the exact walk
        // is what licenses it. Check both directions: never below the exact
        // value, and within a small factor in the small-probability regime the
        // floor target lives in.
        let obs = 120u64;
        for &q in &[1e-4_f64, 1e-3, 1e-2] {
            let exact = false_slash_exact(11, 13, q, obs).expect("n <= 20");
            let bound = false_slash_bound(11, 13, q, obs as f64);
            assert!(
                bound + 1e-18 >= exact,
                "union bound {bound:.3e} below exact {exact:.3e} at q={q}"
            );
            if exact > 0.0 {
                assert!(
                    bound / exact < 1.5,
                    "bound {bound:.3e} not tight vs exact {exact:.3e} at q={q}"
                );
            }
        }
    }

    #[test]
    fn pass_dominance_compounds_the_transport_term() {
        // The finding this arm records: because any pass clears the epoch, the
        // transport term is (p^r)^j across an epoch's j reads, not p^r, so
        // coverage substitutes for retry depth on that term.
        //
        // The size of the effect is bounded by Poisson dispersion, and that is
        // the part worth pinning: the j = 1 epochs (λe^−λ ≈ 15 % of them at
        // λ = 3) carry a bare `p^r` and dominate the sum, so compounding buys
        // ~4×, NOT the (p^r)^λ ≈ 11× a mean-read reading would suggest. An
        // earlier draft of this arm asserted the mean-read figure and this
        // test is what refuted it — keep the bound tied to `p^r` so the claim
        // stays honest if `p` moves after the PoW-enabled rig re-run.
        let m = MissModel {
            lambda_eff: 3.0,
            p_attempt: 0.30,
            retries: 1,
            fabrication_intensity: 0.0, // isolate the transport term
        };
        let transport = m.missed_epoch_rate();
        let single = m.read_failure();
        assert!(
            transport < 0.5 * single,
            "compounding must beat a single read's failure by >2x: {transport} vs {single}"
        );
        assert!(
            transport > (single).powi(3),
            "and must NOT reach the mean-read figure {}: dispersion forbids it",
            single.powi(3)
        );
        // Coverage must move it monotonically, which is what makes the
        // substitution real rather than rhetorical.
        let thinner = MissModel {
            lambda_eff: 1.0,
            ..m
        };
        assert!(thinner.missed_epoch_rate() > transport);
        // And retry depth must move it too — the two are substitutes, so the
        // allocation between them is a real choice rather than a formality.
        let deeper = MissModel { retries: 2, ..m };
        assert!(deeper.missed_epoch_rate() < transport);
    }

    #[test]
    fn observations_arrive_at_most_once_per_epoch() {
        // The correction: coverage is reads/epoch, but settlement collapses an
        // epoch to ONE observation, so the observation rate is bounded by 1 and
        // approaches it as the gap closes. A 13-observation window therefore
        // spans MORE than 13 epochs, never 13/lambda.
        for &lam in &[1.0_f64, 3.0, 6.0] {
            let m = MissModel {
                lambda_eff: lam,
                fabrication_intensity: 0.0,
                ..default_model()
            };
            let rate = m.observation_rate();
            assert!(rate < 1.0 && rate > 0.0);
            assert!(f64::from(FAILURE_WINDOW_N) / rate > f64::from(FAILURE_WINDOW_N));
        }
    }

    #[test]
    fn max_holdings_exposure_dominates_the_per_pair_number() {
        // Assert on the axis the operator experiences: every held pair is
        // independently exposed, so a max-holdings archiver's false-slash
        // exposure is ~MAX_HOLDINGS_SHARDS x the per-pair figure. A target set
        // per-pair would understate an operator's risk by that factor.
        let per_pair = 1e-9_f64;
        let holder = -((MAX_HOLDINGS_SHARDS as f64) * (-per_pair).ln_1p()).exp_m1();
        assert!(holder > per_pair * 4000.0);
        assert!(holder < 1.0);
    }

    #[test]
    fn delivered_coverage_decays_once_k_cap_binds() {
        // The standing discipline: evaluate the fabrication term at
        // cap-delivered coverage. Below the knee the cap is slack; above it,
        // delivered lambda falls and the gap (hence fabrication) grows.
        let (target, seb, k_cap) = (3.0, 10_000.0, 6.0);
        let below = delivered_lambda(target, 10_000.0, seb, k_cap);
        let above = delivered_lambda(target, 40_000.0, seb, k_cap);
        assert!((below - target).abs() < 1e-12, "cap slack below the knee");
        assert!(above < target, "cap must bind past the knee: {above}");
        assert!(above > 0.0);
    }

    #[test]
    fn the_bound_holds_against_the_worst_realized_observation_count() {
        // Review finding, 2026-08-02: the arm passed `bond_life * obs_rate` --
        // an EXPECTATION -- where the union bound needs a deterministic
        // ceiling. A bond life that happens to yield more observations than
        // its mean carries more sliding windows than an expectation-priced
        // bound accounted for, which voids the "upper bound" claim in exactly
        // the tail the floor target cares about.
        //
        // The ratified miss fact supplies the ceiling: at most ONE observation
        // per epoch. So the bound taken at `bond_life` must dominate the exact
        // probability at EVERY realizable count, including the maximum.
        let (m, n, q) = (11u32, 13u32, 1e-2_f64);
        let bond_life = 131.0_f64;
        let bound = false_slash_bound(m, n, q, bond_life);
        for realized in [60u64, 100, 131] {
            let exact = false_slash_exact(m, n, q, realized).expect("n <= 20");
            assert!(
                bound + 1e-18 >= exact,
                "bound {bound:.3e} below exact {exact:.3e} at {realized} observations"
            );
        }
        // And the defect is reachable, not theoretical: pricing at the
        // expectation (obs_rate < 1) yields a strictly smaller bound, so the
        // old form really was claiming less than it covered.
        let expectation_priced = false_slash_bound(m, n, q, bond_life * 0.95);
        assert!(expectation_priced < bound);
    }

    #[test]
    fn targeted_fabrication_saturates_where_ambient_does_not() {
        // F-1, as a test. The ambient (spraying) model divides the attack by
        // `pairs` and so reads as hashrate-bounded; the targeted model does
        // not, because miner-chosen sets let an adversary concentrate for
        // free. An earlier draft of this arm shipped the ambient model as THE
        // model and drew a region that leaned on the difference.
        let (lam, seb) = (3.0, 10_000.0);
        assert!(targeted_fabrication_intensity(0.0, seb).abs() < 1e-12);

        // One block per epoch is all a targeted fabricator needs, so phi
        // saturates far below any hashrate a real miner would hold.
        assert!(targeted_fabrication_intensity(1e-3, seb) > 0.99);
        assert!(targeted_fabrication_intensity(1e-4, seb) > 0.60);

        // And it must DOMINATE the ambient term everywhere it matters -- that
        // gap is exactly what the earlier region was silently claiming as
        // deterrence.
        for &f in &[1e-3_f64, 1e-2, 0.10, 0.30] {
            let tgt = targeted_fabrication_intensity(f, seb);
            let amb = ambient_fabrication_intensity(f, lam);
            assert!(
                tgt > amb,
                "targeted must exceed ambient at f={f}: {tgt} vs {amb}"
            );
        }
        // Ambient stays the weaker, hashrate-scaled term it always was.
        assert!(ambient_fabrication_intensity(0.10, lam) < 0.30);
    }

    #[test]
    fn retry_depth_not_hashrate_is_what_carries_the_floor() {
        // The consequence of F-1 worth pinning: at the targeted intensity the
        // fabrication term is fixed at the gap regardless of `f`, so the only
        // lever left on the floor is `r`. If a future edit re-introduces a
        // hashrate-scaled fabrication term as the headline model, the second
        // assertion here is what should fail.
        let seb = 10_000.0;
        let base = MissModel {
            fabrication_intensity: targeted_fabrication_intensity(1e-3, seb),
            ..default_model()
        };
        let tiny_f = MissModel {
            fabrication_intensity: targeted_fabrication_intensity(1e-2, seb),
            ..base
        };
        // A 10x hashrate difference must buy the defender essentially nothing.
        assert!(
            (base.miss_given_observation() - tiny_f.miss_given_observation()).abs() < 1e-3,
            "targeted fabrication must not scale with hashrate"
        );
        // Retry depth, by contrast, must move it materially.
        let deeper = MissModel { retries: 2, ..base };
        assert!(deeper.miss_given_observation() < 0.6 * base.miss_given_observation());
    }

    #[test]
    fn free_ride_rises_with_m_and_falls_with_n() {
        // W16's axis: a wider window or a lower m gives a placing degrader
        // less free room.
        assert!(free_ride_fraction(11, 13) > free_ride_fraction(6, 13));
        assert!(free_ride_fraction(11, 25) < free_ride_fraction(11, 13));
    }
}
