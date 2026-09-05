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
//! (FL-C4a) for **both** pow2 snap rules (the registered round-to-nearest
//! and the adopted ceiling), the fee↔volume feedback map (FL-C7) on the
//! **served** (quantized) ladder across demand scales that exercise the
//! pow2 boundary, and the §1.8 degenerate pins (FL-C8).
//!
//! **Which reward the derivation prices against:** the *validation* path —
//! the modulated, emission-split, burn-netted quantities consensus actually
//! pays the miner (FL-V1). The 5-arg estimate path is reproduced only as
//! the "current" comparison column, so the estimate/validation gap is a
//! *measured output* of this instrument, never an input assumption.
//!
//! Every economics quantity comes from canonical `shekyl-economics`
//! functions or build-generated params (drift-pair ban, §1.9): the reward
//! family, `emission_speed_factor` / `tail_subsidy_per_block`, and
//! `TX_VOLUME_WINDOW` are all imported; the block-policy zone constant is
//! read from its single Rust owner (`shekyl_wire::transaction::MIN_BLOCK_WEIGHT`).
//! Four deliberate exceptions, marked at their definitions: the ArticMine
//! ladder transliteration (the round's *subject* — porting it faithfully is
//! the point of the comparison column), `REF_TX_WEIGHT` (a C++ constant
//! with no single Rust owner yet; `fee_policy.rs` carries the same pinned
//! copy wallet-side), `GENESIS_NG_HEIGHT` (the hardfork table has no Rust
//! owner), and [`HysteresisCq`] (the §7 construction, whose canonical
//! owner lives on the implementing branch until it merges).
//!
//! I/O convention: this module renders; the binary target performs the
//! writes (`main.rs --fee-ladder`), per the crate's stage2 precedent.

use core::fmt::Write as _;
use std::collections::{BTreeSet, VecDeque};

use serde::Serialize;
use shekyl_economics::params::{SCALE, TX_VOLUME_WINDOW};
use shekyl_economics::{
    apply_release_multiplier, base_block_reward, block_reward_with_penalty, calc_burn_pct,
    calc_effective_emission_share, calc_release_multiplier, cap_reward_to_remaining_supply,
    emission_speed_factor, projected_already_generated, tail_subsidy_per_block, EconomicParams,
    BLOCKS_PER_YEAR, STAKER_EMISSION_DECAY, STAKER_EMISSION_SHARE,
};

/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`, read from its single
/// Rust owner (`shekyl-wire`; `fee_policy.rs` single-sources from the same
/// constant).
const FULL_REWARD_ZONE_V5: u64 = shekyl_wire::transaction::MIN_BLOCK_WEIGHT as u64;

/// `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` (`src/cryptonote_config.h:70`).
/// Declared exception: no single Rust owner exists;
/// `rust/shekyl-engine-core/src/engine/fee_policy.rs` carries the same
/// pinned copy wallet-side.
const REF_TX_WEIGHT: u64 = 3_000;

/// Rolling `tx_volume_avg` window (`SHEKYL_TX_VOLUME_WINDOW`): 720 blocks =
/// one day at 120 s. Build-generated from `config/economics_params.json` so
/// a pre-genesis window recalibration cannot leave this instrument silently
/// measuring a window the chain no longer uses.
const VOLUME_WINDOW: usize = TX_VOLUME_WINDOW as usize;
// The cast above truncates silently on a 16/32-bit `usize`; fail the BUILD
// there instead of measuring a silently shrunken window (PR #614 review).
const _: () = assert!(
    TX_VOLUME_WINDOW <= usize::MAX as u64,
    "TX_VOLUME_WINDOW does not fit this target's usize"
);

/// The NG-genesis height production feeds to `calc_effective_emission_share`:
/// `get_earliest_ideal_height_for_version(HF_VERSION_SHEKYL_NG)` resolves to
/// **1** on the mainnet hardfork table (`src/hardforks/hardforks.cpp`
/// `{ 1, 1, 0, … }`; consumed at the `blockchain.cpp` emission-split and
/// fee-estimate call sites). Declared exception like `REF_TX_WEIGHT`: no
/// Rust owner exists for the hardfork table, so this pinned copy names its
/// C++ authority — a retune of that table must update it. The instrument
/// previously hard-coded 0 here, which at exact year-boundary heights put
/// `σ` a whole decay step ahead of the validation path (PR #614 review):
/// `(k·BLOCKS_PER_YEAR − 0)/BPY = k` but `(k·BPY − 1)/BPY = k − 1`.
const GENESIS_NG_HEIGHT: u64 = 1;

// ---------------------------------------------------------------------------
// Correction factor
// ---------------------------------------------------------------------------

/// The correction factor and its components at one state.
#[derive(Serialize, Clone, Copy)]
pub struct Correction {
    pub release_multiplier: u64,
    pub burn_pct: u64,
    pub emission_share_sigma: u64,
    /// `C = (1−σ)·M_r/(1−b)`, fixed-point `SCALE`.
    pub c_scaled: u64,
}

/// One evaluated grid point of the correction surface.
#[derive(Serialize, Clone, Copy)]
pub struct CorrectionPoint {
    pub age_years: u64,
    pub height: u64,
    pub supply_ratio_millionths: u64,
    pub reachable: bool,
    pub tx_volume_avg: u64,
    #[serde(flatten)]
    pub correction: Correction,
}

/// `C = (1−σ)·M_r/(1−b)` in fixed point, every input from the canonical
/// crate. Single division (`(1−σ)·M_r / (1−b)`) so no intermediate
/// truncation is amplified; `b < SCALE` structurally (burn cap 0.9).
fn correction_factor(v: u64, circulating: u64, height: u64, params: &EconomicParams) -> Correction {
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
        GENESIS_NG_HEIGHT,
        STAKER_EMISSION_SHARE,
        STAKER_EMISSION_DECAY,
        BLOCKS_PER_YEAR,
    );
    let c = u128::from(SCALE - sigma) * u128::from(m_r) / u128::from(SCALE - b);
    Correction {
        release_multiplier: m_r,
        burn_pct: b,
        emission_share_sigma: sigma,
        c_scaled: u64::try_from(c).expect("C fits u64"),
    }
}

// ---------------------------------------------------------------------------
// The inherited ladder (transliteration — the round's subject)
// ---------------------------------------------------------------------------

/// UNROUNDED four-rung ladder, an exact integer transliteration of
/// `Blockchain::get_dynamic_base_fee_estimate_2021_scaling`
/// (`blockchain.cpp:4475-4508`), including its folded-division order.
/// Instrument-local by design: this is the artifact under derivation, and
/// the comparison column must reproduce it bit-for-bit, not idealize it.
///
/// The 5-arg C++ this transliterates does not clamp its medians — the
/// production wrapper (`blockchain.cpp:4527-4537`) guarantees
/// `Mlw ≥ zone` and `Mnw ≥ Mlw` before it is ever called. The
/// `debug_assert`s document that precondition so an instrument grid row
/// below the zone fails loudly instead of printing fees the daemon cannot
/// emit (and instead of a divide-by-zero in the `Fh` folded divisor).
fn articmine_ladder_raw(base_reward: u64, mnw: u64, mlw: u64) -> [u64; 4] {
    // Hard asserts, not debug_asserts: the instrument runs in --release,
    // and the doc above promises loud failure — a stripped check would
    // print fees the daemon cannot emit instead (Copilot PR #614).
    assert!(mlw >= FULL_REWARD_ZONE_V5, "wrapper guarantees Mlw >= zone");
    assert!(mnw >= mlw, "wrapper guarantees Mnw >= Mlw");
    let mfw = mnw.min(mlw);
    let fl = base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fn_ = 4 * base_reward * REF_TX_WEIGHT / (mfw * mfw);
    let fm = 16 * base_reward * REF_TX_WEIGHT / (FULL_REWARD_ZONE_V5 * mfw);
    let fh = (4 * fm).max(4 * fm * mfw / (32 * REF_TX_WEIGHT * mnw / FULL_REWARD_ZONE_V5));
    [fl, fn_, fm, fh]
}

/// `cryptonote::round_money_up(v, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES=2)`:
/// round UP to 2 significant decimal digits. The C++ throws on overflow in
/// the final multiply (`cryptonote_format_utils.cpp`, pinned by
/// `scaling_2021.cpp`'s overflow case); the `expect` here is the same
/// fail-loud semantics.
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
    v.div_ceil(unit)
        .checked_mul(unit)
        .expect("round_money_up overflow (C++ throws here)")
}

fn rounded(raw: [u64; 4]) -> [u64; 4] {
    raw.map(round_money_up_2)
}

/// Corrected ladder: `C` applied to each **already-truncated** rung, then
/// daemon rounding — the SERVED order (`shekyl-economics`
/// `corrected_fee_ladder` computes `scale(base·w_ref/(m·m))`: rung
/// truncated first, `C_q` applied to the truncated value, one rounding at
/// the end), which this instrument must mirror bit-for-bit (§1.9; F-3's
/// instrument-blindness lesson). It is NOT the algebraic
/// `⌊C·R·w/M²⌋`: truncating the rung first loses up to `C_q` atomic units
/// pre-rounding (the fractional loss is amplified by the scalar), which
/// the coarse 2-significant-digit rounding then may or may not absorb —
/// at (10 SKL, `Mfw = 1.5 MB`, `C_q = 16`) served rounds to 210 where the
/// algebraic form would round to 220 (PR #614 review; the pin below
/// keeps a "fix" toward the algebraic form from silently diverging the
/// instrument from the served path).
fn corrected_ladder(raw: [u64; 4], c_scaled: u64) -> [u64; 4] {
    raw.map(|f| {
        let scaled = u128::from(f) * u128::from(c_scaled) / u128::from(SCALE);
        round_money_up_2(u64::try_from(scaled).expect("corrected rung fits u64"))
    })
}

/// The relay floor, transliterating `get_dynamic_base_fee`
/// (`blockchain.cpp:4422-4437`): `R·w_ref/M²` minus 5%, floor 1. The
/// `check_fee` acceptance bound is this minus its further 2% buffer
/// (`blockchain.cpp:4466`).
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
// Quantization (FL-C4a remedy; §5.2 adopted form)
// ---------------------------------------------------------------------------

/// Which pow2 snap rule to apply to `C`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapRule {
    /// `2^round(log2 C)` — the §1.4a *registered* remedy, kept measurable
    /// so the register-vs-adopted deviation stays auditable from the
    /// branch.
    Nearest,
    /// `2^ceil(log2 C)` — the §5.2 *adopted* refinement: never under-funds
    /// marginal pricing, overprices ≤ 2×.
    Ceiling,
}

impl SnapRule {
    /// Report label. The rule travels as this enum end to end (PR #614
    /// review: a stringly selector let a typo silently pick the wrong
    /// rule); the string exists only at the render edge.
    fn label(self) -> &'static str {
        match self {
            SnapRule::Nearest => "nearest",
            SnapRule::Ceiling => "ceil",
        }
    }
}

/// `2^k ≤ c/s`, exactly, in integers.
fn pow2_le(c: u128, s: u128, k: i32) -> bool {
    if k >= 0 {
        (s << k) <= c
    } else {
        s <= (c << (-k))
    }
}

/// Snap `C` to a power of two under `rule`, in exact integer arithmetic
/// (no float log2/exp2 — this is the reference implementation of a
/// concept destined for a wallet-must-match-daemon derivation, so
/// cross-platform float behavior must not be load-bearing). Panics if the
/// snapped exponent is below −6, where `SCALE = 10^6` can no longer
/// represent `2^k` exactly (unreachable for the derivation's C range
/// [0.68, 12.92]; the assert makes a future range widening loud instead of
/// silently truncated).
fn quantize_c_pow2(c_scaled: u64, rule: SnapRule) -> u64 {
    assert!(c_scaled > 0, "C is structurally positive");
    let c = u128::from(c_scaled);
    let s = u128::from(SCALE);

    // kf = floor(log2(c/s)). Seeded from integer bit lengths —
    // ilog2(c) − ilog2(s) is within one of the true floor — then settled
    // by the same exact-integer comparison the KATs pin, so the O(1) seed
    // cannot change any output, only the iteration count (PR #614 review:
    // the previous scan from −40 walked ~40 comparisons per call).
    let mut kf: i32 = c.ilog2() as i32 - s.ilog2() as i32 - 2;
    while pow2_le(c, s, kf + 1) {
        kf += 1;
    }

    let exact = if kf >= 0 {
        (s << kf) == c
    } else {
        (c << (-kf)) == s
    };
    let k = match rule {
        SnapRule::Ceiling => {
            if exact {
                kf
            } else {
                kf + 1
            }
        }
        SnapRule::Nearest => {
            // Log-space midpoint between kf and kf+1 is √2·2^kf:
            // round up iff (c/s)² ≥ 2^(2kf+1), compared exactly.
            let e = 2 * kf + 1;
            let up = if e >= 0 {
                c * c >= (s * s) << e
            } else {
                (c * c) << (-e) >= s * s
            };
            if up {
                kf + 1
            } else {
                kf
            }
        }
    };

    assert!(
        k >= -6,
        "2^{k} not exactly representable in SCALE=10^6 units"
    );
    if k >= 0 {
        SCALE << k
    } else {
        SCALE >> (-k)
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
// Per-age chain state (hoisted once; `projected_already_generated` is
// O(height) and was previously recomputed 25× at age 4 alone)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct AgeState {
    height: u64,
    ag: u64,
    base_reward: u64,
}

/// The demand scale at which the ceiling-quantized `C_q` first steps above
/// its baseline (`v = tx_volume_baseline`) value at this state — the
/// pow2-boundary-straddling probe, computed per state rather than
/// hard-coded (PR #614 review: the fixed `D = 230` was read off the age-4
/// curve and sits off-boundary at every other state). Falls back to the
/// historical 230 when no step exists in the reachable `v ≤ 500` range
/// (then the state has no interior boundary to straddle and the probe
/// degenerates to a plain interior point, which is the honest reading).
fn boundary_demand(st: AgeState, params: &EconomicParams) -> u64 {
    let q_at = |v: u64| {
        quantize_c_pow2(
            correction_factor(v, st.ag, st.height, params).c_scaled,
            SnapRule::Ceiling,
        )
    };
    let base = q_at(params.tx_volume_baseline);
    (params.tx_volume_baseline..=500)
        .find(|&v| q_at(v) != base)
        .unwrap_or(230)
}

fn age_state(age_years: u64, params: &EconomicParams) -> AgeState {
    let height = age_years * BLOCKS_PER_YEAR;
    let ag = projected_already_generated(height, params).expect("projected ag");
    let base_reward = base_block_reward(ag, params).expect("base reward");
    AgeState {
        height,
        ag,
        base_reward,
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
    /// The validation-path economics with raw `C` — the *mispricing*
    /// measurement. The §5.2 proposal serves the quantized form below.
    pub corrected_raw_c: [u64; 4],
    /// What a §5.2 daemon would serve (`C_q`, ceiling rule).
    pub served_ceil_cq: [u64; 4],
    /// `check_fee` acceptance bound at this state. Modeled as
    /// `floor − floor/50` per byte: the real check takes 2% off the
    /// *total* and rounds up to the quantization mask
    /// (`blockchain.cpp:4462-4466`) — both divergences are bounded well
    /// below every measured state's margin, and the mask examination is
    /// CEN-M3's held row.
    pub relay_floor_accept: u64,
    /// FL-C6/FL-V5: does the raw-`C` corrected floor bounce off
    /// `check_fee`?
    pub corrected_floor_below_relay: bool,
}

fn rung_table(
    label: &'static str,
    age_years: u64,
    v: u64,
    median: u64,
    st: AgeState,
    params: &EconomicParams,
) -> RungTable {
    let corr = correction_factor(v, st.ag, st.height, params);
    let raw = articmine_ladder_raw(st.base_reward, median, median);
    let floor = relay_floor(st.base_reward, median);
    let accept = floor - floor / 50;
    let corrected = corrected_ladder(raw, corr.c_scaled);
    let served = corrected_ladder(raw, quantize_c_pow2(corr.c_scaled, SnapRule::Ceiling));
    RungTable {
        label,
        age_years,
        supply_ratio_millionths: u64::try_from(
            u128::from(st.ag) * u128::from(SCALE) / u128::from(params.money_supply),
        )
        .expect("ratio fits"),
        tx_volume_avg: v,
        median,
        base_reward_unmodulated: st.base_reward,
        c_scaled: corr.c_scaled,
        current: rounded(raw),
        corrected_raw_c: corrected,
        served_ceil_cq: served,
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

    /// Knuth Poisson sampler; exact for the registered means (≤ 500 —
    /// `e^-500 ≈ 7.9e-218` is a normal f64; the real breakdown is ≳ 745).
    fn poisson(&mut self, mean: f64) -> u64 {
        // Hard assert (release-mode instrument): past ~745 the Knuth
        // product underflows and silently CAPS samples — corrupted
        // measurements, not an error, if this were stripped.
        assert!(mean < 700.0, "Knuth sampler underflows near mean 745");
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

#[derive(Serialize)]
pub struct DwellResult {
    pub scenario: &'static str,
    /// Chain age of the swept state (§1.8 grid; PR #614 review — dwell was
    /// previously pinned to the single age-4 state, and age/supply shift
    /// `C` relative to every pow2 boundary).
    pub age_years: u64,
    pub mode: String,
    pub blocks_measured: u64,
    /// Median run length (blocks) of an unchanged posted value, per rung,
    /// over the whole trace.
    pub median_dwell: [u64; 4],
    /// TRUE distinct posted values per rung (set cardinality — the wire
    /// alphabet).
    pub distinct_posted_values: [u64; 4],
    /// Number of value CHANGES per rung (churn; a value revisited counts
    /// each time). The pre-review field misnamed this "distinct values".
    pub value_changes: [u64; 4],
    /// For ramp scenarios: the shortest completed run that STARTED inside
    /// the ramp window, per rung — the statistic the FL-C4a ramp criterion
    /// actually gates on (the whole-trace median is dominated by the
    /// stationary tail and structurally cannot fail for ≤ 2 posted
    /// values). `None` when no value change began inside the window (the
    /// value held through the whole ramp — vacuous pass, reported as
    /// such).
    pub min_dwell_started_in_ramp: [Option<u64>; 4],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LadderMode {
    /// Today's daemon output (no correction) — the churn baseline.
    Current,
    /// `C` applied raw.
    CorrectedRaw,
    /// `C` snapped to a power of two first.
    Quantized(SnapRule),
    /// The ceiling snap behind the §7 hysteresis construction — the map
    /// the daemon actually serves once the implementing branch lands.
    QuantizedHysteresis,
}

/// The §7 hysteresis construction, transliterated from the implementing
/// branch's `shekyl-economics::fee_correction_quantized`
/// (`feat/fee-ladder-impl-1`; 3% band, `HYSTERESIS_MARGIN_MILLI = 30`,
/// band around the PREVIOUS step, `prev = 0` ⇒ no history). Declared
/// exception #3 (with the transliteration and `REF_TX_WEIGHT`): the
/// canonical owner does not exist on this branch yet, and §1.7's
/// registered remedy requires measuring the CONSTRUCTED map — hysteresis
/// on `C`, then re-test. At the impl-1 merge this copy must be replaced by
/// the crate function or the §4.5 acceptance claim is about a different
/// mechanism than the one shipped.
struct HysteresisCq {
    prev: u64,
}

impl HysteresisCq {
    fn step(&mut self, c_raw: u64) -> u64 {
        let cq = quantize_c_pow2(c_raw, SnapRule::Ceiling);
        if self.prev == 0 || cq == self.prev {
            self.prev = cq;
            return cq;
        }
        const MARGIN_MILLI: u128 = 30;
        let prev = u128::from(self.prev);
        let c = u128::from(c_raw);
        let upper = prev * (1000 + MARGIN_MILLI) / 1000;
        let lower = (prev / 2) * (1000 - MARGIN_MILLI) / 1000;
        if c > upper || c < lower {
            self.prev = cq;
            cq
        } else {
            self.prev
        }
    }
}

impl LadderMode {
    fn name(self) -> String {
        match self {
            LadderMode::Current => "current".to_owned(),
            LadderMode::CorrectedRaw => "corrected-raw".to_owned(),
            LadderMode::Quantized(rule) => {
                format!("corrected-quantized-pow2-{}", rule.label())
            }
            LadderMode::QuantizedHysteresis => {
                "corrected-quantized-pow2-ceil-hysteresis".to_owned()
            }
        }
    }
}

/// Registered dwell scenarios: `(label, mean_start, mean_end, median)`.
/// Stationary rows cover the full §1.8 volume grid (v=0 exercises the
/// degenerate mean; v=100 the `M_r` rail; v=500 the largest burn
/// gradient); the ramp is the registered 50→200 over one window.
const DWELL_SCENARIOS: &[(&str, f64, f64, u64)] = &[
    ("stationary-v0", 0.0, 0.0, FULL_REWARD_ZONE_V5),
    ("stationary-v5", 5.0, 5.0, FULL_REWARD_ZONE_V5),
    ("stationary-v50", 50.0, 50.0, FULL_REWARD_ZONE_V5),
    ("stationary-v100", 100.0, 100.0, FULL_REWARD_ZONE_V5),
    ("stationary-v200", 200.0, 200.0, FULL_REWARD_ZONE_V5),
    ("stationary-v500", 500.0, 500.0, FULL_REWARD_ZONE_V5),
    ("stationary-v50-m10z", 50.0, 50.0, 10 * FULL_REWARD_ZONE_V5),
    ("ramp-v50-to-v200", 50.0, 200.0, FULL_REWARD_ZONE_V5),
];

/// Advance the traced chain state by one block: the SHIPPED paid emission
/// at the trace's windowed volume (multiplier on the floored base, then
/// the remaining-supply cap — the composition the measured tree pays; the
/// FL-R12′ implementation changes the payer in its own PR, with
/// first-order-identical drift). §1.8 requires the quasi-static claim to
/// be CONFIRMED, not assumed (PR #614 review): the traces now evolve
/// `already_generated` and height per block, so any rung or `C_q`
/// crossing that supply/σ drift can cause is measured rather than frozen
/// out.
fn advance_traced_state(ag: u64, v_avg: u64, params: &EconomicParams) -> u64 {
    let base = base_block_reward(ag, params).expect("base along trace");
    let m_r = calc_release_multiplier(
        v_avg,
        params.tx_volume_baseline,
        params.release_min,
        params.release_max,
    );
    ag + cap_reward_to_remaining_supply(apply_release_multiplier(base, m_r), ag, params)
}

#[allow(clippy::cast_precision_loss)]
fn dwell_scenario(
    scenario: &'static str,
    mean_start: f64,
    mean_end: f64,
    median: u64,
    st: AgeState,
    mode: LadderMode,
    params: &EconomicParams,
) -> DwellResult {
    // σ, supply ratio, and reward drift are EVOLVED along the trace, not
    // held (the register demands confirmation, not assumption): `ag` and
    // height advance per block via [`advance_traced_state`], and rungs +
    // `C` are recomputed from the moving state. The arithmetic bound that
    // says drift is quasi-static on this horizon — dR/R ≈ 2⁻²¹/block, one
    // 2-significant-digit rounding step per ≈21 000 blocks; σ < 0.15 pp
    // per trace — is now a measured property of the reported dwell, and a
    // reward-decay crossing shows up as the ≤ 1-per-trace value change it
    // is instead of being frozen out.
    let blocks: u64 = 20_000;
    let ramp_len = VOLUME_WINDOW as u64;
    let mut rng = Rng(0x5EED_F1FE_ED1E_5EED);
    let mut window: VecDeque<u64> = VecDeque::new();
    let mut sum: u64 = 0;
    for _ in 0..VOLUME_WINDOW {
        let n = rng.poisson(mean_start);
        sum += n;
        window.push_back(n);
    }

    let mut ag = st.ag;
    let mut hyst = HysteresisCq { prev: 0 };
    // Per rung: (value, run_length, run_start_block) plus accumulators.
    let mut runs: [Vec<(u64, u64)>; 4] = [vec![], vec![], vec![], vec![]]; // (start, len)
    let mut values: [BTreeSet<u64>; 4] = Default::default();
    let mut current: [u64; 4] = [0; 4];
    let mut run_len: [u64; 4] = [0; 4];
    let mut run_start: [u64; 4] = [0; 4];
    for t in 0..blocks {
        let frac = if (mean_end - mean_start).abs() < f64::EPSILON {
            0.0
        } else {
            (t as f64 / ramp_len as f64).min(1.0)
        };
        let mean = mean_start + (mean_end - mean_start) * frac;
        let n = rng.poisson(mean);
        sum += n;
        window.push_back(n);
        sum -= window.pop_front().expect("window warm");
        let v_avg = sum / VOLUME_WINDOW as u64;

        let height = st.height + t;
        let base = base_block_reward(ag, params).expect("base along trace");
        let raw = articmine_ladder_raw(base, median, median);
        let fees = match mode {
            LadderMode::Current => rounded(raw),
            LadderMode::CorrectedRaw => {
                corrected_ladder(raw, correction_factor(v_avg, ag, height, params).c_scaled)
            }
            LadderMode::Quantized(rule) => {
                let c = correction_factor(v_avg, ag, height, params).c_scaled;
                corrected_ladder(raw, quantize_c_pow2(c, rule))
            }
            LadderMode::QuantizedHysteresis => {
                let c = correction_factor(v_avg, ag, height, params).c_scaled;
                corrected_ladder(raw, hyst.step(c))
            }
        };
        ag = advance_traced_state(ag, v_avg, params);
        for i in 0..4 {
            values[i].insert(fees[i]);
            if fees[i] == current[i] {
                run_len[i] += 1;
            } else {
                if run_len[i] > 0 {
                    runs[i].push((run_start[i], run_len[i]));
                }
                current[i] = fees[i];
                run_len[i] = 1;
                run_start[i] = t;
            }
        }
    }
    for i in 0..4 {
        runs[i].push((run_start[i], run_len[i]));
    }

    let is_ramp = (mean_end - mean_start).abs() >= f64::EPSILON;
    let mut median_dwell = [0u64; 4];
    let mut distinct = [0u64; 4];
    let mut changes = [0u64; 4];
    let mut min_ramp: [Option<u64>; 4] = [None; 4];
    for i in 0..4 {
        let mut lens: Vec<u64> = runs[i].iter().map(|&(_, l)| l).collect();
        lens.sort_unstable();
        median_dwell[i] = lens[lens.len() / 2];
        distinct[i] = values[i].len() as u64;
        changes[i] = (runs[i].len() - 1) as u64;
        if is_ramp {
            min_ramp[i] = runs[i]
                .iter()
                .filter(|&&(start, _)| start > 0 && start < ramp_len)
                .map(|&(_, l)| l)
                .min();
        }
    }
    DwellResult {
        scenario,
        age_years: st.height / BLOCKS_PER_YEAR,
        mode: mode.name(),
        blocks_measured: blocks,
        median_dwell,
        distinct_posted_values: distinct,
        value_changes: changes,
        min_dwell_started_in_ramp: min_ramp,
    }
}

// ---------------------------------------------------------------------------
// Feedback map (FL-C7) — on the SERVED (quantized) ladder
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeedbackResult {
    /// Chain age and median of the swept state (§1.8 interior grid;
    /// PR #614 review — feedback was previously pinned to (age 4, zone)).
    pub age_years: u64,
    pub median: u64,
    pub elasticity_milli: u64,
    /// Demand scale `D`: the fixed point of the demand curve
    /// (`v = D·(f/f_D)^(−ε)`). Swept so the fixed-point `C` crosses a pow2
    /// boundary; the boundary scale is COMPUTED per state
    /// ([`boundary_demand`]) — a fixed `D = 230` straddles the boundary
    /// only at the age-4 state it was read from.
    pub demand_scale: u64,
    pub start_volume: u64,
    pub mode: String,
    /// Distinct standard-rung fee values over the final 3 000 blocks:
    /// 1 = converged to a fixed point; > 1 = residual cycle amplitude in
    /// quantization/rounding steps.
    pub distinct_fees_tail: u64,
    /// Value CHANGES over the same tail window — the discriminator the
    /// evolved traces need (PR #614 review): with state drift a
    /// distinct_tail of 2 is EITHER one secular boundary crossing
    /// (transitions = 1: the system tracking real state change, a pass)
    /// or an oscillation (transitions ≥ 2: the limit cycle FL-C7
    /// excludes).
    pub tail_transitions: u64,
    pub v_avg_tail_min: u64,
    pub v_avg_tail_max: u64,
    pub fee_tail_min: u64,
    pub fee_tail_max: u64,
}

/// Deterministic iteration of the fee↔volume map through the real
/// 720-block trailing window and the real fee rounding, under the ladder
/// the mode serves. The raw-`C` rows measure the smooth map; the
/// quantized rows measure the §5.2 served map, whose pow2 step is exactly
/// the limit-cycle mechanism FL-C7 exists to exclude.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn feedback_scenario(
    eps_milli: u64,
    demand_scale: u64,
    start_volume: u64,
    st: AgeState,
    median: u64,
    mode: LadderMode,
    params: &EconomicParams,
) -> FeedbackResult {
    let fee_at = |v_avg: u64, ag: u64, height: u64, hyst: &mut HysteresisCq| -> u64 {
        let base = base_block_reward(ag, params).expect("base along trace");
        let raw = articmine_ladder_raw(base, median, median);
        let c = correction_factor(v_avg, ag, height, params).c_scaled;
        let c = match mode {
            LadderMode::Quantized(rule) => quantize_c_pow2(c, rule),
            LadderMode::QuantizedHysteresis => hyst.step(c),
            _ => c,
        };
        corrected_ladder(raw, c)[1].max(1)
    };
    // The reference fee is history-free and anchored at the trace's START
    // state — it defines the demand curve, so it must not move with the
    // loop; the loop's fee below evolves with the traced state (§1.8:
    // confirmed, not assumed) and carries the band's memory.
    let f_ref = fee_at(
        demand_scale,
        st.ag,
        st.height,
        &mut HysteresisCq { prev: 0 },
    );

    let eps = eps_milli as f64 / 1000.0;
    let blocks: u64 = 30_000;
    let tail: u64 = 3_000;
    let mut window: VecDeque<f64> = VecDeque::with_capacity(VOLUME_WINDOW);
    let mut sum = 0.0f64;
    for _ in 0..VOLUME_WINDOW {
        sum += start_volume as f64;
        window.push_back(start_volume as f64);
    }

    let mut fee_min = u64::MAX;
    let mut fee_max = 0u64;
    let mut v_min = u64::MAX;
    let mut v_max = 0u64;
    let mut tail_fees = BTreeSet::new();
    let mut tail_transitions = 0u64;
    let mut last_tail_fee: Option<u64> = None;
    let mut hyst = HysteresisCq { prev: 0 };
    let mut ag = st.ag;
    for t in 0..blocks {
        let v_avg = (sum / VOLUME_WINDOW as f64).max(0.0) as u64;
        let fee = fee_at(v_avg, ag, st.height + t, &mut hyst);
        ag = advance_traced_state(ag, v_avg, params);
        let demand = (demand_scale as f64) * (fee as f64 / f_ref as f64).powf(-eps);
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
            if let Some(prev_fee) = last_tail_fee {
                if fee != prev_fee {
                    tail_transitions += 1;
                }
            }
            last_tail_fee = Some(fee);
        }
    }
    FeedbackResult {
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        mode: mode.name(),
        distinct_fees_tail: tail_fees.len() as u64,
        tail_transitions,
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
    /// (`tail << esf`). The tail era is `2^esf` blocks by IDENTITY
    /// (doc §FL-V7: `remaining/tail = 2^esf`), then the supply cap zeroes
    /// the validation reward permanently.
    pub tail_subsidy_per_block: u64,
    pub headroom_at_tail_entry: u64,
    pub tail_era_blocks: u64,
    /// At `already_generated == money_supply`: what the 5-arg estimate path
    /// still believes the reward is (it has no supply cap) vs what
    /// validation pays. FL-V1's divergence in its terminal form.
    pub estimate_reward_at_exhaustion: u64,
    pub validation_reward_at_exhaustion: u64,
    /// The KAT-pinned penalty through the crate's block-reward entry point
    /// (§1.9: the instrument calls it, reimplements nothing): tail-emission
    /// reward at `x = ½` (`weight = 1.5·zone`) → `TAIL·(1 − x²) = TAIL·¾`.
    /// The FL-C8 tail-reward degenerate, coupled to the same entry point
    /// the 81-vector KAT pins (PR #614 review: the register claimed the
    /// coupling; this pin makes it true).
    pub penalty_at_tail_x_half: u64,
    /// The ladder and relay floor computed from each at exhaustion.
    pub estimate_ladder_at_exhaustion: [u64; 4],
    pub validation_ladder_at_exhaustion: [u64; 4],
    pub relay_floor_at_zero_reward: u64,
}

fn degenerate_pins(params: &EconomicParams) -> DegeneratePins {
    let ratio_09 = params.money_supply / 10 * 9;
    let esf = emission_speed_factor(params);
    let tail = tail_subsidy_per_block(params).expect("tail subsidy");
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
        // Identity, not a measurement: (tail << esf) / tail == 1 << esf.
        tail_era_blocks: 1 << esf,
        estimate_reward_at_exhaustion: est_reward,
        validation_reward_at_exhaustion: val_reward,
        penalty_at_tail_x_half: block_reward_with_penalty(
            FULL_REWARD_ZONE_V5,
            FULL_REWARD_ZONE_V5 + FULL_REWARD_ZONE_V5 / 2,
            s,
            FULL_REWARD_ZONE_V5,
            params,
        )
        .expect("tail-reward penalty pin"),
        estimate_ladder_at_exhaustion: rounded(articmine_ladder_raw(
            est_reward,
            FULL_REWARD_ZONE_V5,
            FULL_REWARD_ZONE_V5,
        )),
        validation_ladder_at_exhaustion: rounded(articmine_ladder_raw(
            val_reward.max(1),
            FULL_REWARD_ZONE_V5,
            FULL_REWARD_ZONE_V5,
        )),
        relay_floor_at_zero_reward: relay_floor(val_reward, FULL_REWARD_ZONE_V5),
    }
}

// ---------------------------------------------------------------------------
// Fee signal bits (FL-C9 — minted post-registration at review round 5)
// ---------------------------------------------------------------------------

/// FL-C9, as re-labeled at review round 6: **anchored-attack
/// candidate-set reduction**, not "signal bits as if the chain leaked
/// identity". FCMP++ puts no linkage primitive on the wire — nothing
/// on-chain says two transactions share an author — so the attack is:
/// acquire an anchor OFF-chain (merchant, KYC withdrawal, timing,
/// submission path), take the height window around it, filter by every
/// public field. The fee rung's contribution is a multiplier of
/// ≈ `1/usage_share(rung)` on that one transaction's candidate set,
/// **applied once per anchored transaction**. Conditioned on the
/// registered §4.4 dwell measurements (ceiling-`C_q` values hold
/// ≥ 20 000 blocks, so the stale-quote term is ≈ 0).
///
/// The state-computed single rate contributes ×1 (no reduction — every
/// conforming transaction's set is the full window under the other
/// fields). Surprisal in bits is kept as the log view of the same
/// number: `surprisal = log2(reduction)`. The earlier `share^n`
/// set-measure compounding field was STRUCK at round 6: cross-transaction
/// linkage requires an adversary who already holds the user's
/// transactions from outside the chain, at which point tier habit is
/// weak confirmation on a stronger leak — and tier choice uncorrelated
/// with identity carries zero cross-transaction information even then.
/// The floor below ×1 is confidential fees (commit the fee, prove
/// `fee − floor ≥ 0`) — out of scope: an FCMP++ tx-format surface.
#[derive(Serialize)]
pub struct AnchoredReduction {
    pub traffic_model: &'static str,
    /// Tier shares ×1000 (economy / standard / priority).
    pub shares_milli: [u64; 3],
    /// Per-rung candidate-set reduction factor ×1000 (= 1/share): what
    /// an anchored observer divides the window's candidate set by, once,
    /// for a transaction in that rung.
    pub reduction_factor_milli: [u64; 3],
    /// The same number in log view: `log2(reduction)` ×1000.
    pub rung_surprisal_milli: [u64; 3],
    /// `H(rung)` ×1000 — expected bits/tx, kept as a summary statistic.
    /// Identical for the inherited 4-rung and proposed 3-rung ladders
    /// under measured usage (`Fm` carries 0%).
    pub ladder_bits_per_tx_milli: u64,
    /// The state-computed single rate's reduction factor ×1000: 1000
    /// (×1.0, no reduction) by construction.
    pub single_rate_reduction_milli: u64,
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn anchored_reduction(traffic_model: &'static str, shares_milli: [u64; 3]) -> AnchoredReduction {
    let mut h = 0.0f64;
    let mut surprisal = [0u64; 3];
    let mut reduction = [0u64; 3];
    for (i, &m) in shares_milli.iter().enumerate() {
        let p = m as f64 / 1000.0;
        if p > 0.0 {
            let s_bits = -p.log2();
            h += p * s_bits;
            surprisal[i] = (s_bits * 1000.0).round() as u64;
            reduction[i] = (1000.0 / p).round() as u64;
        }
    }
    AnchoredReduction {
        traffic_model,
        shares_milli,
        reduction_factor_milli: reduction,
        rung_surprisal_milli: surprisal,
        ladder_bits_per_tx_milli: (h * 1000.0).round() as u64,
        single_rate_reduction_milli: 1000,
    }
}

// ---------------------------------------------------------------------------
// Driver (renders; the binary performs the writes)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeeLadderReport {
    c_surface: Vec<CorrectionPoint>,
    c_reachable_min: u64,
    c_reachable_max: u64,
    x_ladder: Vec<XLadderRow>,
    rung_tables: Vec<RungTable>,
    dwell: Vec<DwellResult>,
    feedback: Vec<FeedbackResult>,
    degenerate: DegeneratePins,
    /// FL-C9 (§1 birth stamp: minted at maintainer direction, review
    /// round 5, after measurement began; re-labeled at round 6 to the
    /// anchored-attack candidate-set reduction).
    fee_signal_bits: Vec<AnchoredReduction>,
}

/// Run the FL instrument and build the report.
pub fn report() -> FeeLadderReport {
    let params = EconomicParams::default();
    let zone = FULL_REWARD_ZONE_V5;

    // §1.8 grid.
    let ages: [u64; 5] = [0, 1, 4, 12, 30];
    let ratios: [u64; 3] = [SCALE / 10, SCALE / 2, SCALE * 9 / 10];
    let volumes: [u64; 6] = [0, 5, 50, 100, 200, 500];

    let states: Vec<(u64, AgeState)> = ages.iter().map(|&a| (a, age_state(a, &params))).collect();
    let state_of = |age: u64| -> AgeState {
        states
            .iter()
            .find(|&&(a, _)| a == age)
            .expect("age in grid")
            .1
    };

    let mut c_surface = Vec::new();
    let (mut c_min, mut c_max) = (u64::MAX, 0u64);
    for &(age, st) in &states {
        let proj_ratio = u128::from(st.ag) * u128::from(SCALE) / u128::from(params.money_supply);
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
                let correction = correction_factor(v, circ, st.height, &params);
                if reachable {
                    c_min = c_min.min(correction.c_scaled);
                    c_max = c_max.max(correction.c_scaled);
                }
                c_surface.push(CorrectionPoint {
                    age_years: age,
                    height: st.height,
                    supply_ratio_millionths: ratio,
                    reachable,
                    tx_volume_avg: v,
                    correction,
                });
            }
        }
    }
    // The grid ratios exclude genesis (proj ratio ≈ 0 there); fold the
    // projected-trajectory states themselves in so the reachable extremes
    // include genesis-quiet (C = 0.680) rather than only the ratio grid.
    for &(_, st) in &states {
        for &v in &volumes {
            let c = correction_factor(v, st.ag, st.height, &params).c_scaled;
            c_min = c_min.min(c);
            c_max = c_max.max(c);
        }
    }

    let genesis = state_of(0);
    let x_ladder = vec![
        x_ladder_row(genesis.base_reward, zone, zone),
        x_ladder_row(genesis.base_reward, 3 * zone, 3 * zone),
        x_ladder_row(genesis.base_reward, 10 * zone, 10 * zone),
        x_ladder_row(genesis.base_reward, 50 * zone, 50 * zone),
        // Registered spot-check: short-term surge decoupled from long-term.
        x_ladder_row(genesis.base_reward, 50 * zone, zone),
    ];

    let rung_tables = vec![
        rung_table("genesis-quiet", 0, 0, zone, genesis, &params),
        rung_table("genesis-baseline", 0, 50, zone, genesis, &params),
        rung_table("young-congested", 1, 200, zone, state_of(1), &params),
        rung_table("mature-quiet", 12, 5, zone, state_of(12), &params),
        rung_table("mature-congested", 12, 200, 3 * zone, state_of(12), &params),
        rung_table(
            "old-congested-wide",
            30,
            500,
            10 * zone,
            state_of(30),
            &params,
        ),
    ];

    // Dwell and feedback sweep the REACHABLE §1.8 interior — the projected
    // trajectory state at every registered age (supply ratio is coupled to
    // age through the emission curve, so the projected state IS the
    // reachable one; the synthetic ratio grid feeds only the C surface
    // above, where reachability is marked per point). Previously both were
    // pinned to the single age-4 state and feedback to the zone median
    // (PR #614 review): age/supply move `C` relative to every pow2
    // boundary, and the median moves the rung values the rounding acts on.
    let mut dwell = Vec::new();
    for &(_age, st) in &states {
        for mode in [
            LadderMode::Current,
            LadderMode::CorrectedRaw,
            LadderMode::Quantized(SnapRule::Nearest),
            LadderMode::Quantized(SnapRule::Ceiling),
            LadderMode::QuantizedHysteresis,
        ] {
            for &(label, m0, m1, median) in DWELL_SCENARIOS {
                dwell.push(dwell_scenario(label, m0, m1, median, st, mode, &params));
            }
        }
    }

    let mut feedback = Vec::new();
    for &(_age, st) in &states {
        // The boundary-straddling demand scale, computed at THIS state.
        let d_boundary = boundary_demand(st, &params);
        for &median in &[zone, 3 * zone, 10 * zone, 50 * zone] {
            for mode in [
                LadderMode::CorrectedRaw,
                LadderMode::Quantized(SnapRule::Ceiling),
                LadderMode::QuantizedHysteresis,
            ] {
                for eps in [0u64, 500, 1000, 2000, 3000] {
                    for demand_scale in [50u64, 100, d_boundary, 400] {
                        feedback.push(feedback_scenario(
                            eps,
                            demand_scale,
                            demand_scale,
                            st,
                            median,
                            mode,
                            &params,
                        ));
                        // A displaced start probes convergence back to the
                        // fixed point, not just persistence at it.
                        feedback.push(feedback_scenario(
                            eps,
                            demand_scale,
                            8 * demand_scale.min(1_250),
                            st,
                            median,
                            mode,
                            &params,
                        ));
                    }
                }
            }
        }
    }

    let degenerate = degenerate_pins(&params);

    // FL-C9 under the registered traffic model and its §1.8 sensitivity
    // variants.
    let fee_signal = vec![
        anchored_reduction("registered 50/40/10", [500, 400, 100]),
        anchored_reduction("sensitivity 70/25/5", [700, 250, 50]),
        anchored_reduction("sensitivity 33/33/33", [334, 333, 333]),
        // The operative model once standard ships as the default
        // (FL-R17 signed (a), §5.5): defaulters concentrate in STANDARD —
        // shares are (economy / standard / priority), so the 80% majority
        // sits in slot 1 (Bugbot PR #614 caught the swapped invocation).
        anchored_reduction("defaulted 15/80/5", [150, 800, 50]),
    ];

    FeeLadderReport {
        c_surface,
        c_reachable_min: c_min,
        c_reachable_max: c_max,
        x_ladder,
        rung_tables,
        dwell,
        feedback,
        degenerate,
        fee_signal_bits: fee_signal,
    }
}

/// Render the human summary into `out` (the binary writes it to stderr).
#[allow(clippy::cast_precision_loss)]
pub fn render_summary(r: &FeeLadderReport, out: &mut String) {
    let f = |scaled: u64| scaled as f64 / SCALE as f64;
    let _ = writeln!(
        out,
        "fee-ladder: C over reachable states = [{:.3}, {:.3}]",
        f(r.c_reachable_min),
        f(r.c_reachable_max)
    );
    for t in &r.rung_tables {
        let _ = writeln!(
            out,
            "fee-ladder: {} C={:.3} current={:?} corrected_raw={:?} served_ceil={:?} floor_accept={} floor_bounce={}",
            t.label,
            f(t.c_scaled),
            t.current,
            t.corrected_raw_c,
            t.served_ceil_cq,
            t.relay_floor_accept,
            t.corrected_floor_below_relay
        );
    }
    // Dwell over the swept grid: aggregate per mode, then every run where
    // a QUANTIZED mode posted more than one value (the FL-C4a hazard —
    // "no exceptions listed" is the pass statement, so the exceptions ARE
    // the interesting rows; raw-C rows print their per-age summary since
    // raw C is the rejected baseline the table contrasts).
    let quantized_runs = r
        .dwell
        .iter()
        .filter(|d| d.mode.contains("quantized"))
        .count();
    // Under the evolved traces a value change is NORMAL (the ~1-per-
    // 10-20k-block reward-decay crossing), so the exception filter is the
    // GATE, not any change: a quantized run whose median dwell dips below
    // the 240-block FL-C4a bar.
    let quantized_gate_violations: Vec<_> = r
        .dwell
        .iter()
        .filter(|d| d.mode.contains("quantized") && d.median_dwell.iter().any(|&m| m < 240))
        .collect();
    let _ = writeln!(
        out,
        "fee-ladder: dwell grid = {} runs ({} quantized; {} quantized runs below the 240-block gate)",
        r.dwell.len(),
        quantized_runs,
        quantized_gate_violations.len()
    );
    for d in &r.dwell {
        let interesting = if d.mode.contains("quantized") {
            d.median_dwell.iter().any(|&m| m < 240)
        } else {
            d.mode == "corrected-raw" && d.scenario.starts_with("stationary-v50")
        };
        if interesting {
            let _ = writeln!(
                out,
                "fee-ladder: dwell {} age={} [{}] median={:?} distinct={:?} changes={:?} min_ramp={:?}",
                d.scenario,
                d.age_years,
                d.mode,
                d.median_dwell,
                d.distinct_posted_values,
                d.value_changes,
                d.min_dwell_started_in_ramp
            );
        }
    }
    // Feedback over the swept grid. With evolved traces, distinct_tail
    // > 1 with ONE transition is a secular boundary crossing (the system
    // tracking real drift — a pass); the FL-C7 exception is OSCILLATION:
    // >= 2 tail transitions at more than one rounding step of amplitude.
    let fb_total = r.feedback.len();
    let secular = r
        .feedback
        .iter()
        .filter(|fb| fb.distinct_fees_tail > 1 && fb.tail_transitions <= 1)
        .count();
    let fb_multi: Vec<_> = r
        .feedback
        .iter()
        .filter(|fb| {
            fb.tail_transitions >= 2 && fb.fee_tail_max >= fb.fee_tail_min.saturating_mul(19) / 10
        })
        .collect();
    let _ = writeln!(
        out,
        "fee-ladder: feedback grid = {} cells; {} secular single crossings; {} OSCILLATING at >= 1.9x (listed below)",
        fb_total,
        secular,
        fb_multi.len()
    );
    for fb in fb_multi {
        let _ = writeln!(
            out,
            "fee-ladder: feedback age={} M={} [{}] eps={} D={} start={} distinct_tail={} transitions={} v_tail=[{},{}] fee_tail=[{},{}]",
            fb.age_years,
            fb.median,
            fb.mode,
            fb.elasticity_milli,
            fb.demand_scale,
            fb.start_volume,
            fb.distinct_fees_tail,
            fb.tail_transitions,
            fb.v_avg_tail_min,
            fb.v_avg_tail_max,
            fb.fee_tail_min,
            fb.fee_tail_max
        );
    }
    for fs in &r.fee_signal_bits {
        let _ = writeln!(
            out,
            "fee-ladder: c9 [{}] reduction_x1000={:?} surprisal={:?} ladder_bits/tx={} single_rate_reduction=x1.0",
            fs.traffic_model,
            fs.reduction_factor_milli,
            fs.rung_surprisal_milli,
            fs.ladder_bits_per_tx_milli
        );
    }
    let _ = writeln!(
        out,
        "fee-ladder: degenerate tail_era_blocks={} est_reward_at_exhaustion={} val_reward_at_exhaustion={} penalty_at_tail_x_half={}",
        r.degenerate.tail_era_blocks,
        r.degenerate.estimate_reward_at_exhaustion,
        r.degenerate.validation_reward_at_exhaustion,
        r.degenerate.penalty_at_tail_x_half
    );
}

/// Render the machine-readable report (the binary writes it to stdout).
pub fn render_json(r: &FeeLadderReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
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

    /// The exact-integer snap rules against hand-computed anchors,
    /// including exact powers of two (must not round up) and the log-space
    /// midpoint (nearest rounds up at ≥ √2·2^k).
    #[test]
    fn quantize_snap_rules() {
        // Exact powers stay put under both rules.
        for c in [500_000u64, 1_000_000, 2_000_000, 4_000_000] {
            assert_eq!(quantize_c_pow2(c, SnapRule::Ceiling), c);
            assert_eq!(quantize_c_pow2(c, SnapRule::Nearest), c);
        }
        // Ceiling always rounds up off-power.
        assert_eq!(quantize_c_pow2(680_000, SnapRule::Ceiling), 1_000_000);
        assert_eq!(quantize_c_pow2(1_130_000, SnapRule::Ceiling), 2_000_000);
        assert_eq!(quantize_c_pow2(5_600_000, SnapRule::Ceiling), 8_000_000);
        assert_eq!(quantize_c_pow2(12_917_390, SnapRule::Ceiling), 16_000_000);
        // Nearest: √2 ≈ 1.41421356 is the up/down midpoint.
        assert_eq!(quantize_c_pow2(680_000, SnapRule::Nearest), 500_000);
        assert_eq!(quantize_c_pow2(1_130_000, SnapRule::Nearest), 1_000_000);
        assert_eq!(quantize_c_pow2(1_414_213, SnapRule::Nearest), 1_000_000);
        assert_eq!(quantize_c_pow2(1_414_214, SnapRule::Nearest), 2_000_000);
        assert_eq!(quantize_c_pow2(5_600_000, SnapRule::Nearest), 4_000_000);
    }

    /// The correction scales the ALREADY-TRUNCATED rung — the served order
    /// (`shekyl-economics` `corrected_fee_ladder`), which the instrument
    /// mirrors. Discriminating pin: at (10 SKL, `Mfw = 1.5 MB`) the raw
    /// economy rung truncates to 13; with `C_q = 16` the served value is
    /// `round2(13·16) = round2(208) = 210`. The REJECTED alternative —
    /// `C_q` in the numerator, `⌊16·R·w/M²⌋ = 213 → 220` — would make the
    /// instrument diverge from the path the daemon serves (PR #614
    /// review): a change toward it must fail here, loudly, not retune the
    /// measurements. (The `C_q = 2` heritage case does not discriminate:
    /// 670 both ways.)
    #[test]
    fn correction_scales_the_truncated_rung_like_the_served_path() {
        let coin: u64 = 1_000_000_000;
        let raw = articmine_ladder_raw(10 * coin, 1_500_000, 1_500_000);
        assert_eq!(raw[0], 13);
        assert_eq!(corrected_ladder(raw, 16 * SCALE)[0], 210);
    }

    /// [`HysteresisCq`] is LOAD-BEARING (§4.5: the un-hysteretic map fails
    /// FL-C7 at 18 reachable boundary cells; the 800-cell convergence
    /// result rests on this band), so its boundaries are pinned directly —
    /// a threshold or inequality drift must fail HERE, not silently
    /// invalidate the §4.5 measurement (PR #614 review). Semantics mirror
    /// impl-1's `fee_correction_quantized`: 3% margin, band around the
    /// PREVIOUS step, escape is strictly-outside (`>` / `<`), `prev = 0`
    /// means no history.
    #[test]
    fn hysteresis_band_boundaries_are_exact() {
        // Initialization: no history ⇒ the plain ceiling snap, stored.
        let mut h = HysteresisCq { prev: 0 };
        assert_eq!(h.step(1_300_000), 2 * SCALE);
        assert_eq!(h.prev, 2 * SCALE, "first snap must become the history");

        // Retention at the upper band EDGE: prev = 2^0, raw C exactly
        // prev·1.03 — strictly-outside escape means the edge itself holds.
        let mut h = HysteresisCq { prev: SCALE };
        assert_eq!(h.step(1_030_000), SCALE);
        assert_eq!(h.prev, SCALE, "a held step must not rewrite history");
        // Transition immediately outside the upper margin: steps up.
        let mut h = HysteresisCq { prev: SCALE };
        assert_eq!(h.step(1_030_001), 2 * SCALE);

        // Retention at the lower band EDGE: prev = 2^1, lower bound is
        // (prev/2)·0.97 = 970 000; the edge holds.
        let mut h = HysteresisCq { prev: 2 * SCALE };
        assert_eq!(h.step(970_000), 2 * SCALE);
        // Immediately below: steps down to the fresh snap.
        let mut h = HysteresisCq { prev: 2 * SCALE };
        assert_eq!(h.step(969_999), SCALE);

        // Same-step short-circuit: a raw C whose ceiling snap equals the
        // held step returns it without consulting the band.
        let mut h = HysteresisCq { prev: 2 * SCALE };
        assert_eq!(h.step(1_500_000), 2 * SCALE);
    }
}
