// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FL instrument (`docs/design/FEE_LADDER_DERIVATION.md` §1.9).
//!
//! Measures, over the §1.8 registered state grid, everything the FL round's
//! pre-registered criteria consume: the correction-factor surface
//! `C = (1−σ)·M_r/(1−b)`, the expansion (`x`) characterization of the
//! inherited ArticMine ladder, corrected-vs-current rung tables with the
//! relay-floor check (FL-C6), rung-value dwell under Poisson traffic
//! (FL-C4a), the fee↔volume feedback map (FL-C7), and the §1.8 degenerate
//! pins (FL-C8).
//!
//! **Which reward the derivation prices against:** the *validation* path —
//! the modulated, emission-split, burn-netted quantities consensus actually
//! pays the miner (FL-V1). The 5-arg estimate path is reproduced only as
//! the "current" comparison column, so the estimate/validation gap is a
//! *measured output* of this instrument, never an input assumption.
//!
//! Every economics quantity comes from canonical `shekyl-economics`
//! functions (drift-pair ban, §1.9). Two deliberate exceptions, marked at
//! their definitions: the ArticMine ladder transliteration (the round's
//! *subject* — it exists nowhere in Rust, and porting it faithfully is the
//! point of the comparison column) and the two C++ block-policy constants
//! the ladder folds in (which cross the FFI as arguments precisely so Rust
//! does not own a copy — see `cryptonote_basic_impl.cpp:110-113`).
//!
//! Output convention matches the crate: JSON to stdout, human summary to
//! stderr.

use serde::Serialize;
use shekyl_economics::params::SCALE;
use shekyl_economics::{
    base_block_reward, calc_burn_pct, calc_effective_emission_share, calc_release_multiplier,
    cap_reward_to_remaining_supply, projected_already_generated, EconomicParams, BLOCKS_PER_YEAR,
    STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE,
};

/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5` (`src/cryptonote_config.h:58`).
/// A C++ block-policy constant that crosses the FFI as an argument by design;
/// instrument-local copy, pinned by this comment.
const FULL_REWARD_ZONE_V5: u64 = 300_000;

/// `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` (`src/cryptonote_config.h:70`).
/// Same status; `fee_policy.rs` carries the same pinned copy wallet-side.
const REF_TX_WEIGHT: u64 = 3_000;

/// Rolling `tx_volume_avg` window (`SHEKYL_TX_VOLUME_WINDOW`,
/// `config/economics_params.json`): 720 blocks = one day at 120 s.
const VOLUME_WINDOW: usize = 720;

// ---------------------------------------------------------------------------
// Correction factor
// ---------------------------------------------------------------------------

/// One evaluated grid point of the correction surface.
#[derive(Serialize, Clone, Copy)]
pub struct CorrectionPoint {
    pub age_years: u64,
    pub height: u64,
    pub supply_ratio_millionths: u64,
    pub reachable: bool,
    pub tx_volume_avg: u64,
    pub release_multiplier: u64,
    pub burn_pct: u64,
    pub emission_share_sigma: u64,
    /// `C = (1−σ)·M_r/(1−b)`, fixed-point `SCALE`.
    pub c_scaled: u64,
}

/// `C = (1−σ)·M_r/(1−b)` in fixed point, every input from the canonical
/// crate. `b < SCALE` structurally (burn cap 0.9).
fn correction_factor(
    v: u64,
    circulating: u64,
    height: u64,
    params: &EconomicParams,
) -> (u64, u64, u64, u64) {
    let m_r = calc_release_multiplier(
        v,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    let b = calc_burn_pct(
        v,
        params.tx_volume_baseline,
        circulating,
        params.money_supply,
        params.burn_base_rate,
        params.burn_cap,
    );
    let sigma = calc_effective_emission_share(
        height,
        0,
        STAKER_EMISSION_SHARE,
        STAKER_EMISSION_DECAY,
        BLOCKS_PER_YEAR,
    );
    let miner_share = SCALE - sigma;
    let c = u128::from(miner_share) * u128::from(m_r) / u128::from(SCALE);
    let c = c * u128::from(SCALE) / u128::from(SCALE - b);
    (m_r, b, sigma, u64::try_from(c).expect("C fits u64"))
}

// ---------------------------------------------------------------------------
// The inherited ladder (transliteration — the round's subject)
// ---------------------------------------------------------------------------

/// UNROUNDED four-rung ladder, an exact integer transliteration of
/// `Blockchain::get_dynamic_base_fee_estimate_2021_scaling`
/// (`blockchain.cpp:4475-4508`), including its folded-division order.
/// Instrument-local by design: this is the artifact under derivation, and
/// the comparison column must reproduce it bit-for-bit, not idealize it.
fn articmine_ladder_raw(base_reward: u64, mnw: u64, mlw: u64) -> [u64; 4] {
    let mfw = mnw.min(mlw);
    let fl = base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fn_ = 4 * base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fm = 16 * base_reward * REF_TX_WEIGHT / (FULL_REWARD_ZONE_V5 * mfw);
    let fh = (4 * fm).max(4 * fm * mfw / (32 * REF_TX_WEIGHT * mnw / FULL_REWARD_ZONE_V5));
    [fl, fn_, fm, fh]
}

/// `cryptonote::round_money_up(v, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES=2)`:
/// round UP to 2 significant decimal digits.
fn round_money_up_2(v: u64) -> u64 {
    if v < 100 {
        return v;
    }
    let mut unit = 1u64;
    let mut head = v;
    while head >= 100 {
        head /= 10;
        unit *= 10;
    }
    v.div_ceil(unit) * unit
}

fn rounded(raw: [u64; 4]) -> [u64; 4] {
    raw.map(round_money_up_2)
}

/// Corrected ladder: `C` applied to each unrounded rung, then daemon
/// rounding. (Equivalent to running the ArticMine formula on the
/// miner-effective reward `(1−σ)·M_r·R` and dividing by `(1−b)`, since the
/// formula is linear in the reward.)
fn corrected_ladder(raw: [u64; 4], c_scaled: u64) -> [u64; 4] {
    raw.map(|f| {
        let scaled = u128::from(f) * u128::from(c_scaled) / u128::from(SCALE);
        round_money_up_2(u64::try_from(scaled).expect("corrected rung fits u64"))
    })
}

/// The relay floor, transliterating `get_dynamic_base_fee`
/// (`blockchain.cpp:4422-4437`): `R·w_ref/M²` minus 5%, floor 1. The
/// `check_fee` acceptance bound is this minus its further 2% buffer
/// (`blockchain.cpp:4468`).
fn relay_floor(base_reward: u64, median: u64) -> u64 {
    let median = median.max(FULL_REWARD_ZONE_V5);
    let lo = u128::from(base_reward) * u128::from(REF_TX_WEIGHT)
        / (u128::from(median) * u128::from(median));
    let mut lo = u64::try_from(lo).expect("fee/byte fits u64");
    lo -= lo / 20;
    if lo == 0 {
        1
    } else {
        lo
    }
}

// ---------------------------------------------------------------------------
// x-characterization (average-cost expansion each rung funds)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct XLadderRow {
    pub median: u64,
    pub mnw: u64,
    /// `x_i = f_i·M/R` per rung, in millionths (expansion fraction of the
    /// median that rung `i` pays for on an average-cost basis). Invariant
    /// under the `C` correction — `C` rescales fees and miner terms alike.
    pub x_millionths: [u64; 4],
    /// Adjacent-rung ratios ×1000 (`[f1/f0, f2/f1, f3/f2]`).
    pub adjacent_ratio_milli: [u64; 3],
}

fn x_ladder_row(base_reward: u64, mnw: u64, mlw: u64) -> XLadderRow {
    let raw = articmine_ladder_raw(base_reward, mnw, mlw);
    let m = mnw.min(mlw).max(FULL_REWARD_ZONE_V5);
    let x = raw.map(|f| {
        u64::try_from(u128::from(f) * u128::from(m) * u128::from(SCALE) / u128::from(base_reward))
            .expect("x fits u64")
    });
    let ratio = |hi: u64, lo: u64| -> u64 {
        if lo == 0 {
            0
        } else {
            u64::try_from(u128::from(hi) * 1000 / u128::from(lo)).expect("ratio fits u64")
        }
    };
    XLadderRow {
        median: m,
        mnw,
        x_millionths: x,
        adjacent_ratio_milli: [
            ratio(raw[1], raw[0]),
            ratio(raw[2], raw[1]),
            ratio(raw[3], raw[2]),
        ],
    }
}

// ---------------------------------------------------------------------------
// Rung tables at representative states
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RungTable {
    pub label: &'static str,
    pub age_years: u64,
    pub supply_ratio_millionths: u64,
    pub tx_volume_avg: u64,
    pub median: u64,
    pub base_reward_unmodulated: u64,
    pub c_scaled: u64,
    /// What the daemon serves today (5-arg estimate semantics).
    pub current: [u64; 4],
    /// What the validation-path economics ask for.
    pub corrected: [u64; 4],
    /// `check_fee` acceptance bound at this state (floor − 2% buffer).
    pub relay_floor_accept: u64,
    /// FL-C6/FL-V5: does the corrected floor rung bounce off `check_fee`?
    pub corrected_floor_below_relay: bool,
}

fn rung_table(
    label: &'static str,
    age_years: u64,
    v: u64,
    median: u64,
    params: &EconomicParams,
) -> RungTable {
    let height = age_years * BLOCKS_PER_YEAR;
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base = base_block_reward(ag, params).expect("base reward");
    let (_, _, _, c) = correction_factor(v, ag, height, params);
    let raw = articmine_ladder_raw(base, median, median);
    let floor = relay_floor(base, median);
    let accept = floor - floor / 50;
    let corrected = corrected_ladder(raw, c);
    RungTable {
        label,
        age_years,
        supply_ratio_millionths: u64::try_from(
            u128::from(ag) * u128::from(SCALE) / u128::from(params.money_supply),
        )
        .expect("ratio fits"),
        tx_volume_avg: v,
        median,
        base_reward_unmodulated: base,
        c_scaled: c,
        current: rounded(raw),
        corrected,
        relay_floor_accept: accept,
        corrected_floor_below_relay: corrected[0] < accept,
    }
}

// ---------------------------------------------------------------------------
// Dwell (FL-C4a): how long a posted rung value persists
// ---------------------------------------------------------------------------

/// xorshift64* — deterministic instrument RNG (reproducible runs; the crate
/// deliberately has no `rand` dependency).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    #[allow(clippy::cast_precision_loss)]
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Knuth Poisson sampler; fine for the registered means (≤ 500).
    fn poisson(&mut self, mean: f64) -> u64 {
        if mean <= 0.0 {
            return 0;
        }
        let l = (-mean).exp();
        let mut k = 0u64;
        let mut p = 1.0;
        loop {
            p *= self.unit();
            if p <= l {
                return k;
            }
            k += 1;
        }
    }
}

/// Snap `C` UP to a power of two: `2^ceil(log2(C))`, in `SCALE` fixed
/// point. The FL-C4a *registered* remedy was round-to-nearest; ceiling is
/// the adopted refinement (doc §5.2): round-to-nearest under-funds the top
/// rung's marginal pricing by up to √2, while ceiling never under-funds
/// (FL-C2(b) preserved everywhere), overprices ≤ 2× (inside FL-C3), and is
/// the same monotone step function of the same slow input, so it faces the
/// same dwell gate — re-measured, not assumed.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn quantize_c_pow2(c_scaled: u64) -> u64 {
    let log = (c_scaled as f64 / SCALE as f64).log2();
    let k = log.ceil();
    (SCALE as f64 * k.exp2()) as u64
}

#[derive(Serialize)]
pub struct DwellResult {
    pub scenario: String,
    pub mode: &'static str,
    pub blocks_measured: u64,
    /// Median run length (blocks) of an unchanged posted value, per rung.
    pub median_dwell: [u64; 4],
    /// Number of distinct posted values seen, per rung.
    pub distinct_values: [u64; 4],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LadderMode {
    /// Today's daemon output (no correction) — the churn baseline.
    Current,
    /// `C` applied raw.
    CorrectedRaw,
    /// `C` snapped to powers of two first.
    CorrectedQuantized,
}

impl LadderMode {
    fn name(self) -> &'static str {
        match self {
            LadderMode::Current => "current",
            LadderMode::CorrectedRaw => "corrected-raw",
            LadderMode::CorrectedQuantized => "corrected-quantized-pow2",
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn dwell_scenario(
    label: &str,
    mean_start: f64,
    mean_end: f64,
    median: u64,
    age_years: u64,
    mode: LadderMode,
    params: &EconomicParams,
) -> DwellResult {
    // σ, supply ratio, and the median are quasi-static on the measured
    // horizon (≈28 days): σ moves < 0.1 pp and the ratio ≈1% — orders below
    // the volume axis this scenario exercises. Held fixed per §1.8.
    let height = age_years * BLOCKS_PER_YEAR;
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base = base_block_reward(ag, params).expect("base reward");
    let raw = articmine_ladder_raw(base, median, median);

    let blocks: u64 = 20_000;
    let mut rng = Rng(0x5EED_F1FE_ED1E_5EED);
    let mut window: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut sum: u64 = 0;
    for _ in 0..VOLUME_WINDOW {
        let n = rng.poisson(mean_start);
        sum += n;
        window.push_back(n);
    }

    let mut runs: [Vec<u64>; 4] = [vec![], vec![], vec![], vec![]];
    let mut current: [u64; 4] = [0; 4];
    let mut run_len: [u64; 4] = [0; 4];
    for t in 0..blocks {
        let frac = if mean_end == mean_start {
            0.0
        } else {
            (t as f64 / VOLUME_WINDOW as f64).min(1.0)
        };
        let mean = mean_start + (mean_end - mean_start) * frac;
        let n = rng.poisson(mean);
        sum += n;
        window.push_back(n);
        sum -= window.pop_front().expect("window warm");
        let v_avg = sum / VOLUME_WINDOW as u64;

        let fees = match mode {
            LadderMode::Current => rounded(raw),
            LadderMode::CorrectedRaw => {
                let (_, _, _, c) = correction_factor(v_avg, ag, height, params);
                corrected_ladder(raw, c)
            }
            LadderMode::CorrectedQuantized => {
                let (_, _, _, c) = correction_factor(v_avg, ag, height, params);
                corrected_ladder(raw, quantize_c_pow2(c))
            }
        };
        for i in 0..4 {
            if fees[i] == current[i] {
                run_len[i] += 1;
            } else {
                if run_len[i] > 0 {
                    runs[i].push(run_len[i]);
                }
                current[i] = fees[i];
                run_len[i] = 1;
            }
        }
    }
    for i in 0..4 {
        runs[i].push(run_len[i]);
    }
    let mut median_dwell = [0u64; 4];
    let mut distinct = [0u64; 4];
    for i in 0..4 {
        runs[i].sort_unstable();
        median_dwell[i] = runs[i][runs[i].len() / 2];
        distinct[i] = runs[i].len() as u64;
    }
    DwellResult {
        scenario: label.to_owned(),
        mode: mode.name(),
        blocks_measured: blocks,
        median_dwell,
        distinct_values: distinct,
    }
}

// ---------------------------------------------------------------------------
// Feedback map (FL-C7)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeedbackResult {
    pub elasticity_milli: u64,
    pub start_volume: u64,
    /// Distinct standard-rung fee values over the final 3 000 blocks:
    /// 1 = converged to a fixed point; > 1 = residual cycle amplitude in
    /// rounding steps.
    pub distinct_fees_tail: u64,
    pub v_avg_tail_min: u64,
    pub v_avg_tail_max: u64,
    pub fee_tail_min: u64,
    pub fee_tail_max: u64,
}

/// Deterministic iteration of the fee↔volume map: demand
/// `v = v0·(f/f_ref)^(−ε)` against the corrected standard rung, through the
/// real 720-block trailing window and the real fee rounding.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn feedback_scenario(
    eps_milli: u64,
    start_volume: u64,
    age_years: u64,
    median: u64,
    params: &EconomicParams,
) -> FeedbackResult {
    let height = age_years * BLOCKS_PER_YEAR;
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base = base_block_reward(ag, params).expect("base reward");
    let raw = articmine_ladder_raw(base, median, median);
    let v0 = params.tx_volume_baseline;
    let (_, _, _, c0) = correction_factor(v0, ag, height, params);
    let f_ref = corrected_ladder(raw, c0)[1].max(1);

    let eps = eps_milli as f64 / 1000.0;
    let blocks: u64 = 30_000;
    let tail: u64 = 3_000;
    let mut window: std::collections::VecDeque<f64> =
        std::collections::VecDeque::with_capacity(VOLUME_WINDOW);
    let mut sum = 0.0f64;
    for _ in 0..VOLUME_WINDOW {
        sum += start_volume as f64;
        window.push_back(start_volume as f64);
    }

    let mut fee_min = u64::MAX;
    let mut fee_max = 0u64;
    let mut v_min = u64::MAX;
    let mut v_max = 0u64;
    let mut tail_fees = std::collections::BTreeSet::new();
    for t in 0..blocks {
        let v_avg = (sum / VOLUME_WINDOW as f64).max(0.0) as u64;
        let (_, _, _, c) = correction_factor(v_avg, ag, height, params);
        let fee = corrected_ladder(raw, c)[1].max(1);
        let demand = (v0 as f64) * (fee as f64 / f_ref as f64).powf(-eps);
        let demand = demand.clamp(0.0, 10_000.0);
        sum += demand;
        window.push_back(demand);
        sum -= window.pop_front().expect("window warm");
        if t >= blocks - tail {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            v_min = v_min.min(v_avg);
            v_max = v_max.max(v_avg);
            tail_fees.insert(fee);
        }
    }
    FeedbackResult {
        elasticity_milli: eps_milli,
        start_volume,
        distinct_fees_tail: tail_fees.len() as u64,
        v_avg_tail_min: v_min,
        v_avg_tail_max: v_max,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
    }
}

// ---------------------------------------------------------------------------
// Degenerate pins (FL-C8)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DegeneratePins {
    /// `b` reaches its cap on-grid: `(v=500, ratio=0.9)` → `burn_cap`.
    pub burn_at_cap: u64,
    /// `M_r` rails: at `v=0` and at `v=100`.
    pub release_at_zero: u64,
    pub release_at_double_baseline: u64,
    /// Tail subsidy per block, and the supply headroom at tail entry
    /// (`tail << esf`). The tail era is `headroom / tail` blocks long, then
    /// the supply cap zeroes the validation reward permanently.
    pub tail_subsidy_per_block: u64,
    pub headroom_at_tail_entry: u64,
    pub tail_era_blocks: u64,
    /// At `already_generated == money_supply`: what the 5-arg estimate path
    /// still believes the reward is (it has no supply cap) vs what
    /// validation pays. FL-V1's divergence in its terminal form.
    pub estimate_reward_at_exhaustion: u64,
    pub validation_reward_at_exhaustion: u64,
    /// The ladder and relay floor computed from each at exhaustion.
    pub estimate_ladder_at_exhaustion: [u64; 4],
    pub validation_ladder_at_exhaustion: [u64; 4],
    pub relay_floor_at_zero_reward: u64,
}

fn degenerate_pins(params: &EconomicParams) -> DegeneratePins {
    let ratio_09 = params.money_supply / 10 * 9;
    let esf = params.emission_speed_factor_per_minute - (params.daa_target_seconds / 60 - 1);
    let tail = params.final_subsidy_per_minute * (params.daa_target_seconds / 60);
    let s = params.money_supply;
    let est_reward = base_block_reward(s, params).expect("base at exhaustion");
    let val_reward = cap_reward_to_remaining_supply(est_reward, s, params);
    DegeneratePins {
        burn_at_cap: calc_burn_pct(
            500,
            params.tx_volume_baseline,
            ratio_09,
            s,
            params.burn_base_rate,
            params.burn_cap,
        ),
        release_at_zero: calc_release_multiplier(
            0,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        ),
        release_at_double_baseline: calc_release_multiplier(
            100,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        ),
        tail_subsidy_per_block: tail,
        headroom_at_tail_entry: tail << esf,
        tail_era_blocks: (tail << esf) / tail,
        estimate_reward_at_exhaustion: est_reward,
        validation_reward_at_exhaustion: val_reward,
        estimate_ladder_at_exhaustion: rounded(articmine_ladder_raw(
            est_reward,
            FULL_REWARD_ZONE_V5,
            FULL_REWARD_ZONE_V5,
        )),
        validation_ladder_at_exhaustion: rounded(articmine_ladder_raw(
            val_reward,
            FULL_REWARD_ZONE_V5,
            FULL_REWARD_ZONE_V5,
        )),
        relay_floor_at_zero_reward: relay_floor(val_reward, FULL_REWARD_ZONE_V5),
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FeeLadderReport {
    c_surface: Vec<CorrectionPoint>,
    c_reachable_min: u64,
    c_reachable_max: u64,
    x_ladder: Vec<XLadderRow>,
    rung_tables: Vec<RungTable>,
    dwell: Vec<DwellResult>,
    feedback: Vec<FeedbackResult>,
    degenerate: DegeneratePins,
}

/// Run the FL instrument and print the report (JSON → stdout, summary →
/// stderr).
pub fn run() {
    let params = EconomicParams::default();
    let zone = FULL_REWARD_ZONE_V5;

    // §1.8 grid.
    let ages: [u64; 5] = [0, 1, 4, 12, 30];
    let ratios: [u64; 3] = [SCALE / 10, SCALE / 2, SCALE * 9 / 10];
    let volumes: [u64; 6] = [0, 5, 50, 100, 200, 500];

    let mut c_surface = Vec::new();
    let (mut c_min, mut c_max) = (u64::MAX, 0u64);
    for &age in &ages {
        let height = age * BLOCKS_PER_YEAR;
        let proj = projected_already_generated(height, &params).expect("projected ag");
        let proj_ratio = u128::from(proj) * u128::from(SCALE) / u128::from(params.money_supply);
        for &ratio in &ratios {
            // §1.8 reachability: the release multiplier bounds the real
            // trajectory within [0.8, 1.3]× of the neutral one.
            let lo = proj_ratio * 8 / 10;
            let hi = (proj_ratio * 13 / 10).min(u128::from(SCALE));
            let reachable = u128::from(ratio) >= lo && u128::from(ratio) <= hi;
            let circ = u64::try_from(
                u128::from(params.money_supply) * u128::from(ratio) / u128::from(SCALE),
            )
            .expect("circ fits");
            for &v in &volumes {
                let (m_r, b, sigma, c) = correction_factor(v, circ, height, &params);
                if reachable {
                    c_min = c_min.min(c);
                    c_max = c_max.max(c);
                }
                c_surface.push(CorrectionPoint {
                    age_years: age,
                    height,
                    supply_ratio_millionths: ratio,
                    reachable,
                    tx_volume_avg: v,
                    release_multiplier: m_r,
                    burn_pct: b,
                    emission_share_sigma: sigma,
                    c_scaled: c,
                });
            }
        }
    }

    // x-characterization at the §1.8 medians (genesis-era reward; x is
    // reward-independent, the reward only sets absolute fee levels).
    let genesis_base = base_block_reward(0, &params).expect("genesis base");
    let x_ladder = vec![
        x_ladder_row(genesis_base, zone, zone),
        x_ladder_row(genesis_base, 3 * zone, 3 * zone),
        x_ladder_row(genesis_base, 10 * zone, 10 * zone),
        x_ladder_row(genesis_base, 50 * zone, 50 * zone),
        // Registered spot-check: short-term surge decoupled from long-term.
        x_ladder_row(genesis_base, 50 * zone, zone),
    ];

    let rung_tables = vec![
        rung_table("genesis-quiet", 0, 0, zone, &params),
        rung_table("genesis-baseline", 0, 50, zone, &params),
        rung_table("young-congested", 1, 200, zone, &params),
        rung_table("mature-quiet", 12, 5, zone, &params),
        rung_table("mature-congested", 12, 200, 3 * zone, &params),
        rung_table("old-congested-wide", 30, 500, 10 * zone, &params),
    ];

    let mut dwell = Vec::new();
    for mode in [
        LadderMode::Current,
        LadderMode::CorrectedRaw,
        LadderMode::CorrectedQuantized,
    ] {
        dwell.push(dwell_scenario(
            "stationary-v5",
            5.0,
            5.0,
            zone,
            4,
            mode,
            &params,
        ));
        dwell.push(dwell_scenario(
            "stationary-v50",
            50.0,
            50.0,
            zone,
            4,
            mode,
            &params,
        ));
        dwell.push(dwell_scenario(
            "stationary-v200",
            200.0,
            200.0,
            zone,
            4,
            mode,
            &params,
        ));
        dwell.push(dwell_scenario(
            "stationary-v50-m10z",
            50.0,
            50.0,
            10 * zone,
            4,
            mode,
            &params,
        ));
        dwell.push(dwell_scenario(
            "ramp-v50-to-v200",
            50.0,
            200.0,
            zone,
            4,
            mode,
            &params,
        ));
    }

    let mut feedback = Vec::new();
    for eps in [0u64, 500, 1000, 2000, 3000] {
        feedback.push(feedback_scenario(eps, 50, 4, zone, &params));
        feedback.push(feedback_scenario(eps, 400, 4, zone, &params));
    }

    let degenerate = degenerate_pins(&params);

    let report = FeeLadderReport {
        c_surface,
        c_reachable_min: c_min,
        c_reachable_max: c_max,
        x_ladder,
        rung_tables,
        dwell,
        feedback,
        degenerate,
    };

    eprintln!(
        "fee-ladder: C over reachable grid = [{:.3}, {:.3}]",
        ratio_f(c_min),
        ratio_f(c_max)
    );
    for t in &report.rung_tables {
        eprintln!(
            "fee-ladder: {} C={:.3} current={:?} corrected={:?} floor_accept={} floor_bounce={}",
            t.label,
            ratio_f(t.c_scaled),
            t.current,
            t.corrected,
            t.relay_floor_accept,
            t.corrected_floor_below_relay
        );
    }
    for d in &report.dwell {
        eprintln!(
            "fee-ladder: dwell {} [{}] median={:?} distinct={:?}",
            d.scenario, d.mode, d.median_dwell, d.distinct_values
        );
    }
    for f in &report.feedback {
        eprintln!(
            "fee-ladder: feedback eps={} start_v={} distinct_tail={} v_tail=[{},{}] fee_tail=[{},{}]",
            f.elasticity_milli,
            f.start_volume,
            f.distinct_fees_tail,
            f.v_avg_tail_min,
            f.v_avg_tail_max,
            f.fee_tail_min,
            f.fee_tail_max
        );
    }
    eprintln!(
        "fee-ladder: degenerate tail_era_blocks={} est_reward_at_exhaustion={} val_reward_at_exhaustion={}",
        report.degenerate.tail_era_blocks,
        report.degenerate.estimate_reward_at_exhaustion,
        report.degenerate.validation_reward_at_exhaustion
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}

#[allow(clippy::cast_precision_loss)]
fn ratio_f(scaled: u64) -> f64 {
    scaled as f64 / SCALE as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the transliteration against `tests/unit_tests/scaling_2021.cpp`
    /// `wallet_fee_estimate` (10 SKL reward cases) — the instrument's
    /// "current" column must reproduce the C++ oracle exactly.
    #[test]
    fn transliteration_matches_cpp_kat() {
        let coin: u64 = 1_000_000_000;
        assert_eq!(
            rounded(articmine_ladder_raw(10 * coin, 300_000, 300_000)),
            [340, 1400, 5400, 67_000]
        );
        assert_eq!(
            rounded(articmine_ladder_raw(10 * coin, 15_000_000, 300_000)),
            [340, 1400, 5400, 22_000]
        );
        assert_eq!(
            rounded(articmine_ladder_raw(10 * coin, 1_500_000, 1_500_000)),
            [13, 53, 1100, 14_000]
        );
    }

    /// Pin the genesis-condition `Fh` the wallet cap is derived from
    /// (`fee_policy.rs`: daemon-rounded genesis `Fh` = 14,000,000).
    #[test]
    fn genesis_fh_matches_wallet_cap() {
        let params = EconomicParams::default();
        let base = base_block_reward(0, &params).expect("genesis base");
        let fees = rounded(articmine_ladder_raw(base, 300_000, 300_000));
        assert_eq!(fees[3], 14_000_000);
    }

    /// Pin the relay-floor transliteration against
    /// `tests/unit_tests/scaling_2021.cpp` `relay_fee`.
    #[test]
    fn relay_floor_matches_cpp_kat() {
        let coin: u64 = 1_000_000_000;
        assert_eq!(relay_floor(10 * coin, 300_000), 317);
        assert_eq!(relay_floor(10 * coin, 600_000), 79);
        assert_eq!(relay_floor(10 * coin, 3_000_000), 3);
        assert_eq!(relay_floor(10 * coin, 6_000_000), 1);
        assert_eq!(relay_floor(coin, 300_000), 32);
        assert_eq!(relay_floor(10 * coin, 1), 317);
        assert_eq!(relay_floor(10 * coin, 100_000), 317);
    }

    #[test]
    fn round_money_up_two_places() {
        assert_eq!(round_money_up_2(0), 0);
        assert_eq!(round_money_up_2(99), 99);
        assert_eq!(round_money_up_2(101), 110);
        assert_eq!(round_money_up_2(27_810), 28_000);
        assert_eq!(round_money_up_2(13_653_333), 14_000_000);
        assert_eq!(round_money_up_2(68_000), 68_000);
    }
}
