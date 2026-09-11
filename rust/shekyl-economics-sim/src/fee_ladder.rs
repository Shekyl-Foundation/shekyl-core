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
//! copy wallet-side) and `GENESIS_NG_HEIGHT` (the hardfork table has no
//! Rust owner). [`HysteresisCq`] was the third; it now calls
//! `shekyl-economics::hysteresis_step` and that exception is discharged.
//!
//! I/O convention: this module renders; the binary target performs the
//! writes (`main.rs --fee-ladder`), per the crate's stage2 precedent.

use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use shekyl_economics::params::{SCALE, TX_VOLUME_WINDOW};
use shekyl_economics::{
    advance_already_generated, base_block_reward, block_reward_with_penalty, calc_burn_pct,
    calc_effective_emission_share, calc_release_multiplier, corrected_fee_ladder,
    effective_emission, emission_speed_factor, hysteresis_fold, hysteresis_settled,
    hysteresis_step, paid_block_reward, projected_already_generated, tail_subsidy_per_block,
    EconomicParams, FeeLadder, TxVolume, BLOCKS_PER_YEAR, STAKER_EMISSION_DECAY,
    STAKER_EMISSION_SHARE,
};

/// `CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`, read from its single
/// Rust owner (`shekyl-wire`; `fee_policy.rs` single-sources from the same
/// constant).
pub(crate) const FULL_REWARD_ZONE_V5: u64 = shekyl_wire::transaction::MIN_BLOCK_WEIGHT as u64;

/// `DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT` (`src/cryptonote_config.h:70`).
/// Declared exception: no single Rust owner exists;
/// `rust/shekyl-engine-core/src/engine/fee_policy.rs` carries the same
/// pinned copy wallet-side.
pub(crate) const REF_TX_WEIGHT: u64 = 3_000;

/// Rolling transaction-volume window (`SHEKYL_TX_VOLUME_WINDOW`): 720 blocks =
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

/// The minimum-dwell floor examined for FL-R18 (c) and **NOT ADOPTED**
/// (round 14): the anonymity harm it was to prevent was refuted (§4.5b)
/// and the floor was measured to destabilise the loop it was meant to
/// calm (§4.5a). Kept as an instrument mode ONLY so that result stays
/// reproducible from the branch — the same reason both pow2 snap rules
/// are still modes. 240 blocks = the FL-C4a stationary gate, i.e. the
/// best candidate the sweep found; nothing ships it.
const FL_R18_MIN_DWELL_BLOCKS: u64 = 240;

/// Quote-to-broadcast lags for the FL-R18 rejection-race measurement
/// (§4.5b), in blocks at the 120 s target. STATED, not assumed:
/// * **1** — the floor case: estimate fetched, transaction built and
///   broadcast inside one block.
/// * **3** (≈ 6 min) — the realistic case: FCMP++ proving at the rule-76
///   device floor, a human confirmation step, and the Dandelion++ stem
///   embargo before the transaction reaches a miner's pool.
/// * **25** (≈ 50 min) — a signing session left open, or a wallet that
///   quotes, waits on a second signer, then broadcasts.
/// * **100** — the PROTOCOL's own ceiling, not a guess:
///   `FCMP_REFERENCE_BLOCK_MAX_AGE` (100) is the oldest reference a
///   proof may carry at admission, so no conforming transaction can be
///   quoted more than 100 blocks before it is submitted.
const RACE_LAGS: [u64; 4] = [1, 3, 25, 100];

/// Blocks per day at the 120 s target — the unit §10.14.4's C10-6/7/8
/// report in, beside blocks. `BLOCKS_PER_YEAR / 365` would silently
/// inherit any leap-day convention the year constant carries; a day is
/// stated directly.
const BLOCKS_PER_DAY: u64 = 720;

/// C10-7's construction-to-broadcast window, in blocks: ten minutes at the
/// 120 s target — the window FL-R18's "≈ 4 %" was quoted on. **A
/// PLACEHOLDER for FL-R19's gap distribution, which the wallet lane owes**;
/// named as one in §10.14.4, so the figure it produces is comparable to
/// R18's, not a claim about real wallets.
const R19_GAP_BLOCKS_PLACEHOLDER: u64 = 5;

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
    correction_factor_ratio(TxVolume::per_block(v), circulating, height, params)
}

/// [`correction_factor`] with the volume operand given as the exact
/// window [`TxVolume`] the owners take since FL-R24 (PR A): `window(sum,
/// 720)` is the 720-block SMA at rational resolution and `per_block(sum /
/// 720)` the integer-truncated operand the daemon used to ship — §11
/// (FL-E2) measures the two against each other through this one function.
pub(crate) fn correction_factor_ratio(
    volume: TxVolume,
    circulating: u64,
    height: u64,
    params: &EconomicParams,
) -> Correction {
    let baseline = params.tx_volume_baseline;
    let m_r = calc_release_multiplier(volume, baseline, params.release_min, params.release_max);
    let b = calc_burn_pct(
        volume,
        baseline,
        circulating,
        params.emission_curve_asymptote,
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

/// Served-ladder arity, derived from the production owner so a slot-count
/// change cannot leave this instrument half-converted.
const SERVED_SLOTS: usize = FeeLadder::SATURATED.as_slots().len();

/// The legacy ladder projected onto the three priced rungs, for comparison
/// against the corrected one.
///
/// `articmine_ladder_raw` still returns four — that transliteration is the
/// round's subject and porting it faithfully is the point — but its `Fm`
/// slot (index 2) has no served counterpart. Dropping it here keeps the
/// comparison rung-for-rung instead of pairing `Fm` against `priority` by
/// position.
fn rounded(raw: [u64; 4]) -> [u64; SERVED_SLOTS] {
    [
        round_money_up_2(raw[0]),
        round_money_up_2(raw[1]),
        round_money_up_2(raw[3]),
    ]
}

/// The SERVED ladder, from **the production owner itself** — no local
/// re-derivation. `shekyl-economics::corrected_fee_ladder` computes
/// `base·w_ref·C / (Mfw²·SCALE)`: `C` in the NUMERATOR and a single
/// division, so no intermediate truncation compounds. Since FL-R21 there
/// is no `round_money_up_2` on it either, and `standard` is `4F` exactly.
///
/// This replaced a local mirror that scaled already-truncated ArticMine
/// rungs (PR #640 review). The mirror had been documented as bit-exact
/// with the served path and was pinned at 210 for
/// (10 SKL, `Mfw = 1.5 MB`, `C_q = 16`); the owner returned 220 there at
/// the time, because it divides once. (It returns 213 now — same single
/// division, one less rounding step.) The mirror was measuring a
/// composition the daemon does not serve, which is precisely the
/// drift-pair §1.9 forbids: call the canonical function, reimplement
/// none of it.
///
/// The legacy transliteration survives ONLY as the `Current` comparison
/// column — the PRE-FL-R20 daemon, which is what that column exists to
/// compare against. It stopped being "today's daemon" when FL-R20 landed;
/// it is a historical baseline now, and `transliteration_matches_cpp_kat`
/// pins it as one.
fn served_ladder(base_reward: u64, median: u64, c_q: u64) -> [u64; SERVED_SLOTS] {
    corrected_fee_ladder(
        base_reward,
        median,
        median,
        FULL_REWARD_ZONE_V5,
        REF_TX_WEIGHT,
        c_q,
    )
    .as_slots()
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
/// FL-D8's pre-registered predicate (§10.9): is raw `C` inside the band's
/// own flicker zone?
///
/// **Why the band's own margin and not a chosen one.** `C` always lies in
/// some pow2 interval `[B_lo, B_hi]`. The hysteresis band exists to damp
/// movement across the ends of that interval, and it does so with a
/// margin of `HYSTERESIS_MARGIN_MILLI` (3%). Defining "near a boundary"
/// as *within that same margin of either end* makes D8 measure the zone
/// the mechanism actually acts on, rather than a zone picked to produce a
/// number. It also keeps the definition tied to one constant: if the
/// margin is ever retuned, this predicate follows it instead of drifting.
///
/// The 3% is re-derived here rather than imported because
/// `HYSTERESIS_MARGIN_MILLI` is private to the owner. That is a knowing
/// duplication of a CONSTANT, not of the band's arithmetic — the step
/// itself is still the owner's — and it is pinned by
/// `boundary_zone_margin_matches_the_owner` below, which fails if the two
/// ever disagree.
const D8_MARGIN_MILLI: u128 = 30;

fn in_boundary_zone(c_scaled: u64) -> bool {
    if c_scaled == 0 {
        return false;
    }
    let hi = u128::from(quantize_c_pow2(c_scaled, SnapRule::Ceiling));
    let lo = hi / 2;
    let c = u128::from(c_scaled);
    // Within the margin of the upper end, or of the lower end.
    c * 1000 >= hi * (1000 - D8_MARGIN_MILLI) || c * 1000 <= lo * (1000 + D8_MARGIN_MILLI)
}

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
pub(crate) struct AgeState {
    pub(crate) height: u64,
    pub(crate) ag: u64,
    pub(crate) base_reward: u64,
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

pub(crate) fn age_state(age_years: u64, params: &EconomicParams) -> AgeState {
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
    pub current: [u64; SERVED_SLOTS],
    /// The validation-path economics with raw `C` — the *mispricing*
    /// measurement. The §5.2 proposal serves the quantized form below.
    pub corrected_raw_c: [u64; SERVED_SLOTS],
    /// What a §5.2 daemon would serve (`C_q`, ceiling rule).
    pub served_ceil_cq: [u64; SERVED_SLOTS],
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
    let corrected = served_ladder(st.base_reward, median, corr.c_scaled);
    let served = served_ladder(
        st.base_reward,
        median,
        quantize_c_pow2(corr.c_scaled, SnapRule::Ceiling),
    );
    RungTable {
        label,
        age_years,
        supply_ratio_millionths: u64::try_from(
            u128::from(st.ag) * u128::from(SCALE) / u128::from(params.emission_curve_asymptote),
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
pub(crate) struct Rng(pub(crate) u64);

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
    pub(crate) fn poisson(&mut self, mean: f64) -> u64 {
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
    /// Ramp vs stationary, from the SCENARIO DEFINITION (`mean_end !=
    /// mean_start`) — never inferred from observed data: a ramp whose
    /// value held through the window (the documented vacuous pass) has
    /// every `min_dwell_started_in_ramp` slot `None`, and inferring kind
    /// from that scored it against the stationary bar (PR #614 review).
    pub is_ramp: bool,
    /// Chain age of the swept state (§1.8 grid; PR #614 review — dwell was
    /// previously pinned to the single age-4 state, and age/supply shift
    /// `C` relative to every pow2 boundary).
    pub age_years: u64,
    pub mode: String,
    pub blocks_measured: u64,
    /// Median run length (blocks) of an unchanged posted value, per rung,
    /// over the whole trace.
    pub median_dwell: [u64; SERVED_SLOTS],
    /// TRUE distinct posted values per rung (set cardinality — the wire
    /// alphabet).
    pub distinct_posted_values: [u64; SERVED_SLOTS],
    /// Number of value CHANGES per rung (churn; a value revisited counts
    /// each time). The pre-review field misnamed this "distinct values".
    pub value_changes: [u64; SERVED_SLOTS],
    /// FL-D8 (§10.9), statistic 1 — **occupancy**: blocks whose raw `C`
    /// sits in the band's flicker zone, per thousand blocks measured.
    /// The "how much chain TIME" half of the question the round needs to
    /// pick `P`; mode-independent, since raw `C` does not depend on how a
    /// mode serves it.
    pub d8_boundary_occupancy_permille: u64,
    /// FL-D8, statistic 2 — **expected residence per visit**: the mean
    /// length in blocks of a run inside the zone. C10-4's reading: `P`
    /// must EXCEED this, or the grid re-samples inside a single visit and
    /// the boundary behaviour survives the grid.
    pub d8_mean_residence_blocks: u64,
    /// Longest single visit observed — the tail `P` would have to span to
    /// cover the worst case, not just the mean.
    pub d8_max_residence_blocks: u64,
    /// Whether this arm serves a pow2-snapped map, from
    /// [`LadderMode::serves_quantized_map`] — carried as data so the gate
    /// stops inferring its own subject from the mode's display name.
    pub is_quantized_map: bool,
    /// Deepest fold evaluated by a grid arm on this trace (0 for
    /// non-grid arms). C10-3's cost evidence, measured rather than
    /// derived from `P`: the fold depth is `h mod P`, so the observed
    /// maximum says what the COLD path actually pays.
    pub grid_max_fold_depth: u64,
    /// The arm's grid period (0 for non-grid arms), from
    /// [`LadderMode::grid_period`]. The C10-3 cost summary selects and
    /// labels its rows by this, not by a list of names it expects to find
    /// (§10.12.1's defect).
    pub grid_period: u64,
    /// C10-8 (§10.14.4): offset in blocks of the standard rung's first
    /// served change from the trace start; on the ramp scenario, this
    /// arm's minus the un-banded ceiling's is the lag on a secular
    /// crossing. `None` if the rung never changed.
    pub first_change_offset: Option<u64>,
    /// §10.14.3 over-quote share: blocks per thousand where the served
    /// `C_q` exceeds the un-banded ceiling of the same raw `C` —
    /// peak-hold's conservative bias, priced. 0 for non-snapped arms.
    pub over_ceiling_permille: u64,
    /// The mirror: blocks per thousand served BELOW the ceiling (a band
    /// holding the lower state through a rise).
    pub under_ceiling_permille: u64,
    /// For ramp scenarios: the shortest completed run that STARTED inside
    /// the ramp window, per rung — the statistic the FL-C4a ramp criterion
    /// actually gates on (the whole-trace median is dominated by the
    /// stationary tail and structurally cannot fail for ≤ 2 posted
    /// values). `None` when no value change began inside the window (the
    /// value held through the whole ramp — vacuous pass, reported as
    /// such).
    pub min_dwell_started_in_ramp: [Option<u64>; SERVED_SLOTS],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LadderMode {
    /// Today's daemon output (no correction) — the churn baseline.
    Current,
    /// `C` applied raw.
    CorrectedRaw,
    /// `C` snapped to a power of two first.
    Quantized(SnapRule),
    /// The ceiling snap behind the §7 hysteresis construction — the
    /// RULED served map (FL-R3, round 17).
    ///
    /// The shipped daemon does not reach it yet: #640 review cycle 5
    /// found the band unreachable on the served path, and restoring it
    /// needs a grid-anchored previous value, which is its own round. So
    /// this mode is the design's map and [`Self::Quantized`] with
    /// [`SnapRule::Ceiling`] is what is served in the interim — measure
    /// against this one when the question is what the ladder IS, and
    /// against that one when it is what the daemon does today.
    QuantizedHysteresis,
    /// The band plus a minimum-dwell floor of `n` blocks on the served
    /// value — examined for FL-R18 (c) and NOT ADOPTED; swept over
    /// candidate `n` to produce the evidence at §4.5a.
    RateLimited(u64),
    /// §10.3(B) — the grid-anchored fold, the FL-R3 restoration's
    /// candidate shape: at height `h` the band is folded from the grid
    /// anchor `h₀ = h − (h mod P)` with no seed, so the served value is a
    /// pure function of `(chain state, h)` and costs `h mod P` steps.
    GridFold(u64),
    /// §10.3(C) — grid-only, **INSTRUMENTATION, NOT A PROPOSAL**: the
    /// anchor's plain snap held for the whole cell, so a grid alone
    /// yields dwell ≥ `P` with no band at all. Built because the question
    /// "does the grid already do the band's boundary job" is going to be
    /// asked, and C10-5 pre-registers how each outcome reads. The band
    /// staying is RULED; this arm may not be read as reopening it.
    GridOnly(u64),
    /// §10.12.3(b) — the **warm-anchor** fold, round 2's mechanism test:
    /// `GridFold(p)` with the anchor moved `w` whole cells back, so the
    /// fold depth is `w·P + (h mod P) + 1 ∈ [w·P, (w+1)·P)`. INSTRUMENT,
    /// not a proposal — it costs more than the budget by construction.
    /// It exists to falsify one claim: that C10-1's extra cells are
    /// anchor-flip cells, which a deeper fold cannot recover because it
    /// moves the anchor rather than removing it (R2-E3).
    GridFoldWarm(u64, u64),
    /// §10.14.2 — shape (D), the **settled-anchor grid band**: the §7 band
    /// run over the sequence of grid SAMPLES `C(k·P)`, anchored at the
    /// most recent sample that is settled (`hysteresis_settled`), where
    /// the band's state is fixed with no history. `(P, K)`: look back at
    /// most `K` samples for a settled one, else fall back to the unseeded
    /// snap at `k − K`; `None` is the unbounded exact recurrence, the
    /// reference the bounded arms are measured against.
    GridBand(u64, Option<u64>),
    /// §10.14.3 — median of the last `W` sample snaps, **INSTRUMENTATION,
    /// NOT A PROPOSAL**: not the band (a time release in place of the
    /// amplitude margin), so a result here routes to R18-M4, never to
    /// closure. `(P, W)`.
    GridMedian(u64, u64),
    /// §10.14.3 — peak-hold: the maximum of the last `W` sample snaps.
    /// Same instrumentation status as [`Self::GridMedian`]. `(P, W)`.
    GridPeak(u64, u64),
}

/// The §7 hysteresis construction — the history, held so the sweep can
/// walk a trace; the step itself is
/// `shekyl-economics::hysteresis_step`.
///
/// **Declared exception #3 is DISCHARGED here.** This carried a
/// transliterated copy of the band while the canonical owner lived only
/// on the implementing branch, under a standing obligation to replace it
/// at that merge "or the §4.5 acceptance claim is about a different
/// mechanism than the one shipped". That obligation was live: the copy
/// had already drifted, never picking up the owner's
/// `MIN_REPRESENTABLE_C` floor. It now calls the owner, so the
/// acceptance claim is about the shipped mechanism by construction
/// rather than by inspection.
struct HysteresisCq {
    prev: u64,
}

impl HysteresisCq {
    fn step(&mut self, c_raw: u64) -> u64 {
        self.prev = hysteresis_step(c_raw, self.prev);
        self.prev
    }
}

/// The mechanism examined for FL-R18 (c), **withdrawn at round 14**: a
/// minimum-dwell floor on the served `C_q`, composed ON TOP of the band. The band damps boundary noise;
/// it cannot suppress a limit cycle driven by gain-≥2 demand feedback,
/// because a deadband only helps once it exceeds the loop's excursion
/// (the ruling's ground for rejecting a wider band). The floor makes the
/// FL-C4a dwell property structural: a served value that has changed
/// cannot change again for `n` blocks.
///
/// `blocks_since_change` counts blocks since the last CHANGE. The implementing branch
/// carries `(value, since_height)` instead — equivalent, and the reason
/// FL-R18 condition 1 names restart survival: this counter is state that
/// a restart can lose.
struct RateLimitedCq {
    band: HysteresisCq,
    served: u64,
    blocks_since_change: u64,
    n: u64,
}

impl RateLimitedCq {
    fn new(n: u64) -> Self {
        Self {
            band: HysteresisCq { prev: 0 },
            served: 0,
            blocks_since_change: 0,
            n,
        }
    }

    fn step(&mut self, c_raw: u64) -> u64 {
        let want = self.band.step(c_raw);
        if self.served == 0 {
            self.served = want;
            self.blocks_since_change = 0;
            return self.served;
        }
        self.blocks_since_change += 1;
        if want != self.served && self.blocks_since_change >= self.n {
            self.served = want;
            self.blocks_since_change = 0;
        }
        self.served
    }
}

/// §10 grid stepper — both grid arms, one implementation.
///
/// **What it holds is the CELL'S RAW INPUTS, never a fold result.** That
/// distinction is the round's whole subject: the daemon would re-read
/// `C`'s inputs from chain state at each height in the cell, so this
/// vector stands in for CHAIN STATE, not for the per-node remembered
/// value round 17 rejected (`m_fee_correction_cq`, archived at
/// `archive/fee-ladder-r12-impl-rejected-2026-09-08`).
///
/// It re-folds from the anchor on **every** step rather than carrying
/// `prev` forward. That is deliberate and is what makes the measurement
/// honest: §10.6 rules that C10-3's budget is met on the COLD path with
/// no memo counted, so the arm must cost what the cold path costs. The
/// re-fold is also what makes the served value a pure function of
/// `(trace, h)` — the property FL-R18 closed on.
///
/// The fold itself is `shekyl-economics::hysteresis_fold` — the owner
/// §10.12.4 pins for the daemon, so the arm measures the mechanism that
/// will ship. This holds no band arithmetic, per FL-R3 constraint (2) and
/// the drifted-copy lesson that discharged declared exception #3; round
/// 1's private fold loop here was the last such copy and is gone.
struct GridCq {
    period: u64,
    /// Grid-only (§10.3 C) when true: the anchor's snap, held for the cell.
    only: bool,
    /// Whole cells the anchor is moved back (§10.12.3(b)); 0 is §10.3 B.
    warm_cells: u64,
    /// Raw `C` at each height from the anchor to the current height,
    /// oldest first. Bounded at `(warm_cells + 1)·P`.
    span: VecDeque<u64>,
    /// Last height stepped, so a non-contiguous walk is detected rather
    /// than folded over.
    last_height: Option<u64>,
    /// Deepest fold actually evaluated — C10-3's evidence.
    max_depth: u64,
}

impl GridCq {
    /// The stepper an arm needs; an inert `P = 1` stepper for non-grid
    /// arms so the drivers can hold one unconditionally.
    fn for_mode(mode: LadderMode) -> Self {
        match mode {
            LadderMode::GridFold(p) => Self::new(p, false, 0),
            LadderMode::GridOnly(p) => Self::new(p, true, 0),
            LadderMode::GridFoldWarm(p, w) => Self::new(p, false, w),
            _ => Self::new(1, false, 0),
        }
    }

    fn new(period: u64, only: bool, warm_cells: u64) -> Self {
        Self {
            period: period.max(1),
            only,
            warm_cells,
            span: VecDeque::new(),
            last_height: None,
            max_depth: 0,
        }
    }

    fn step(&mut self, height: u64, c_raw: u64) -> u64 {
        let off = height % self.period;
        // The anchor is `h₀ − warm·P`; the span the daemon would re-read
        // from chain state runs from there to `h`. Its length at this
        // height is fixed by `h` alone — so if the driver skipped a height
        // the span cannot be rebuilt from what is held, and it restarts
        // (total, never folding over stale heights).
        let want = self.warm_cells * self.period + off + 1;
        if self.last_height != height.checked_sub(1) {
            self.span.clear();
        }
        self.last_height = Some(height);
        self.span.push_back(c_raw);
        while self.span.len() as u64 > want {
            self.span.pop_front();
        }
        // During the first `warm` cells of a trace the true anchor lies
        // before the trace began; the fold then starts at the trace's
        // first height instead — depth `< want`, which the depth record
        // shows honestly.
        let cells = self.span.make_contiguous();
        let depth = cells.len() as u64;
        if self.only {
            // The anchor's plain snap (`prev = 0` is "no history"), held
            // for the whole cell.
            self.max_depth = self.max_depth.max(1);
            return hysteresis_step(cells[0], 0);
        }
        self.max_depth = self.max_depth.max(depth);
        hysteresis_fold(cells).expect("span holds the height just pushed")
    }
}

/// How a §10.14 arm turns the grid-sample sequence into a served value.
#[derive(Clone, Copy)]
enum SeqRule {
    /// §10.14.2: band over the sequence from the last settled sample,
    /// scanning back at most `K` samples (`None` = unbounded).
    Band(Option<u64>),
    /// §10.14.3: median of the last `W` snaps.
    Median(u64),
    /// §10.14.3: maximum of the last `W` snaps.
    Peak(u64),
}

/// §10.14 grid-SEQUENCE stepper — the arms whose unit of time is the
/// period, not the block.
///
/// Holds the raw `C` at each grid sample `g_k = k·P`, oldest first — again
/// the cell's RAW INPUTS standing in for chain state, never a fold result
/// (see [`GridCq`]). The trace's first height is taken as a pseudo-sample
/// so the arm has something to serve before its first anchor; that is the
/// trace edge, and the depth record shows it.
///
/// Every step re-derives the served value from the samples (the cold
/// path, per §10.6); the band rule folds with the owner's
/// `hysteresis_fold` from the anchor `hysteresis_settled` selects. The
/// filters snap each sample with `hysteresis_step(c, 0)` — the owner's
/// unseeded snap — and hold no band arithmetic of their own.
struct GridSeq {
    period: u64,
    rule: SeqRule,
    samples: Vec<u64>,
    last_height: Option<u64>,
    /// Deepest evaluation (samples read) — the cold column's worst case.
    max_depth: u64,
    /// Sum of depths over steps, for the cold column's mean.
    depth_sum: u64,
    steps: u64,
    /// Steps whose scan hit the `K` bound without a settled sample and
    /// anchored on the unseeded snap instead — where the §10.2 defect
    /// lives for this shape, and the only way the monotonicity invariant
    /// can break.
    fallbacks: u64,
}

impl GridSeq {
    fn new(period: u64, rule: SeqRule) -> Self {
        Self {
            period: period.max(1),
            rule,
            samples: Vec::new(),
            last_height: None,
            max_depth: 0,
            depth_sum: 0,
            steps: 0,
            fallbacks: 0,
        }
    }

    /// Samples the rule can ever read, so the vector stays bounded.
    fn retain(&self) -> usize {
        match self.rule {
            SeqRule::Band(Some(k)) => k as usize + 1,
            SeqRule::Band(None) => usize::MAX,
            SeqRule::Median(w) | SeqRule::Peak(w) => w as usize,
        }
    }

    fn step(&mut self, height: u64, c_raw: u64) -> u64 {
        if self.last_height != height.checked_sub(1) {
            self.samples.clear();
        }
        self.last_height = Some(height);
        if self.samples.is_empty() || height.is_multiple_of(self.period) {
            self.samples.push(c_raw);
            let keep = self.retain();
            if self.samples.len() > keep {
                let drop = self.samples.len() - keep;
                self.samples.drain(..drop);
            }
        }
        let n = self.samples.len();
        let (served, depth) = match self.rule {
            SeqRule::Band(bound) => {
                let floor = bound.map_or(0, |k| n.saturating_sub(k as usize + 1));
                let anchor = (floor..n)
                    .rev()
                    .find(|&i| hysteresis_settled(self.samples[i]));
                let j = anchor.unwrap_or(floor);
                if anchor.is_none() && floor > 0 {
                    self.fallbacks += 1;
                }
                (
                    hysteresis_fold(&self.samples[j..]).expect("at least the sample just pushed"),
                    (n - j) as u64,
                )
            }
            SeqRule::Median(w) => {
                let from = n.saturating_sub(w as usize);
                let mut snaps: Vec<u64> = self.samples[from..]
                    .iter()
                    .map(|&c| hysteresis_step(c, 0))
                    .collect();
                snaps.sort_unstable();
                (snaps[snaps.len() / 2], (n - from) as u64)
            }
            SeqRule::Peak(w) => {
                let from = n.saturating_sub(w as usize);
                let peak = self.samples[from..]
                    .iter()
                    .map(|&c| hysteresis_step(c, 0))
                    .max()
                    .expect("at least the sample just pushed");
                (peak, (n - from) as u64)
            }
        };
        self.max_depth = self.max_depth.max(depth);
        self.depth_sum += depth;
        self.steps += 1;
        served
    }
}

/// The one grid stepper a driver holds — asks the mode which kind it
/// needs, so neither driver carries a per-variant match that a new arm
/// can be left out of.
enum GridArm {
    Block(GridCq),
    Seq(GridSeq),
}

impl GridArm {
    fn for_mode(mode: LadderMode) -> Self {
        match mode {
            LadderMode::GridBand(p, k) => Self::Seq(GridSeq::new(p, SeqRule::Band(k))),
            LadderMode::GridMedian(p, w) => Self::Seq(GridSeq::new(p, SeqRule::Median(w))),
            LadderMode::GridPeak(p, w) => Self::Seq(GridSeq::new(p, SeqRule::Peak(w))),
            _ => Self::Block(GridCq::for_mode(mode)),
        }
    }

    /// An inert stepper for the history-free reference evaluation.
    fn inert() -> Self {
        Self::Block(GridCq::new(1, false, 0))
    }

    fn step(&mut self, height: u64, c_raw: u64) -> u64 {
        match self {
            Self::Block(g) => g.step(height, c_raw),
            Self::Seq(g) => g.step(height, c_raw),
        }
    }

    /// `(max depth, mean depth, fallback steps)` — the cold column's
    /// evidence. For block arms the mean is not tracked (their depth is
    /// fixed by `h mod P`, §10.4) and reads 0.
    fn depth_stats(&self) -> (u64, u64, u64) {
        match self {
            Self::Block(g) => (g.max_depth, 0, 0),
            Self::Seq(g) => (g.max_depth, g.depth_sum / g.steps.max(1), g.fallbacks),
        }
    }
}

impl LadderMode {
    /// Cold parses of the 720-block volume window a quote at the arm's
    /// deepest observed evaluation costs, with NO memo (§10.6, C10-3 as
    /// registered). Block-fold arms read one window per height from the
    /// anchor to `h` and those windows overlap, so a single scan covers
    /// them: `720 + depth` (§10.12.1). Sequence arms read one DISJOINT
    /// window per sample: `depth × 720`. Non-grid arms read one window.
    fn cold_parses(self, depth: u64) -> u64 {
        match self {
            LadderMode::GridBand(..) | LadderMode::GridMedian(..) | LadderMode::GridPeak(..) => {
                depth.max(1) * TX_VOLUME_WINDOW
            }
            LadderMode::GridFold(_) | LadderMode::GridOnly(_) | LadderMode::GridFoldWarm(..) => {
                TX_VOLUME_WINDOW + depth
            }
            _ => TX_VOLUME_WINDOW,
        }
    }

    /// Steady-state parses **per day (720 blocks)** under a
    /// chain-state-keyed memo (§10.6's legitimate kind — a column the
    /// register has NOT adopted; reported beside the cold one, never
    /// instead of it). Sequence arms compute one new sample per period;
    /// every per-block arm computes one new window per block.
    fn memo_parses_per_day(self) -> u64 {
        match self {
            LadderMode::GridBand(p, _)
            | LadderMode::GridMedian(p, _)
            | LadderMode::GridPeak(p, _) => TX_VOLUME_WINDOW * (BLOCKS_PER_DAY / p.max(1)).max(1),
            _ => TX_VOLUME_WINDOW * BLOCKS_PER_DAY,
        }
    }

    /// Does this arm serve a **pow2-snapped** `C_q`, and therefore fall
    /// under the registered dwell gate?
    ///
    /// **This replaces a name-substring test, which was a silent
    /// under-gate.** The dwell gate previously selected rows with
    /// `mode.contains("quantized")`. Two arms serve a snapped map without
    /// the word in their label — `served-rate-limited-n*` (added to the
    /// dwell sweep at round 13) and §10's `grid-*` arms — so both were
    /// counted as non-quantized and skipped by the gate entirely. A gate
    /// that decides its own subject from a display string is a gate that
    /// stops covering each new arm without saying so; this asks the mode
    /// what it serves.
    fn serves_quantized_map(self) -> bool {
        match self {
            LadderMode::Current | LadderMode::CorrectedRaw => false,
            LadderMode::Quantized(_)
            | LadderMode::QuantizedHysteresis
            | LadderMode::RateLimited(_)
            | LadderMode::GridFold(_)
            | LadderMode::GridOnly(_)
            | LadderMode::GridFoldWarm(..)
            | LadderMode::GridBand(..)
            | LadderMode::GridMedian(..)
            | LadderMode::GridPeak(..) => true,
        }
    }

    /// The grid period, for the arms that have one.
    ///
    /// Everything downstream that is *about the grid* — which rows the
    /// C10-3 cost summary reads, which arms get a per-cell diff against
    /// the reference, whether a transition sits on an anchor — asks this,
    /// never a label. Round 1 read C10-3's depth off a hard-coded label
    /// list and reported the wrong arm's number (§10.12.1); that is the
    /// third figure in one round derived from a label or mode list rather
    /// than from the arm, and this is where the class is closed.
    fn grid_period(self) -> Option<u64> {
        match self {
            LadderMode::GridFold(p)
            | LadderMode::GridOnly(p)
            | LadderMode::GridFoldWarm(p, _)
            | LadderMode::GridBand(p, _)
            | LadderMode::GridMedian(p, _)
            | LadderMode::GridPeak(p, _) => Some(p),
            LadderMode::Current
            | LadderMode::CorrectedRaw
            | LadderMode::Quantized(_)
            | LadderMode::QuantizedHysteresis
            | LadderMode::RateLimited(_) => None,
        }
    }

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
            LadderMode::RateLimited(n) => format!("served-rate-limited-n{n}"),
            LadderMode::GridFold(p) => format!("grid-fold-p{p}"),
            LadderMode::GridOnly(p) => format!("grid-only-p{p}"),
            LadderMode::GridFoldWarm(p, w) => format!("grid-fold-p{p}-w{w}"),
            LadderMode::GridBand(p, Some(k)) => format!("grid-band-p{p}-k{k}"),
            LadderMode::GridBand(p, None) => format!("grid-band-p{p}-kfull"),
            LadderMode::GridMedian(p, w) => format!("grid-median-p{p}-w{w}"),
            LadderMode::GridPeak(p, w) => format!("grid-peak-p{p}-w{w}"),
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
    // §10.14.6: the same crossing downward. Peak-hold's lag is P up and
    // W·P down by construction; a grid with one ramp direction measures
    // C10-8 on the side that flatters it.
    ("ramp-v200-to-v50", 200.0, 50.0, FULL_REWARD_ZONE_V5),
];

/// Advance the traced chain state by one block: the SHIPPED paid emission
/// at the trace's windowed volume — FL-R12′'s composition, the multiplier
/// on the CURVE and no remaining-supply cap, so the accumulator runs
/// through the asymptote. §1.8 requires the quasi-static claim to
/// be CONFIRMED, not assumed (PR #614 review): the traces now evolve
/// `already_generated` and height per block, so any rung or `C_q`
/// crossing that supply/σ drift can cause is measured rather than frozen
/// out.
pub(crate) fn advance_traced_state(ag: u64, v_avg: u64, params: &EconomicParams) -> u64 {
    // Since the FL-R12′ implementation landed, this calls THE OWNERS rather
    // than modelling the composition: `effective_emission` is the paid
    // pre-penalty quantity `max(M_r·curve, TAIL)` and
    // `advance_already_generated` is the accumulator that runs THROUGH the
    // asymptote. Both replace the retired `cap_reward_to_remaining_supply`
    // this line used while the shipped tree still capped at remaining
    // supply — the substitution the round-12 comment anticipated, made at
    // the merge that introduced the owners (§1.9: call them, reimplement
    // none of them).
    let paid = effective_emission(ag, TxVolume::per_block(v_avg), params)
        .expect("paid emission along trace");
    advance_already_generated(ag, paid)
}

/// Per-rung run tracking over a dwell trace. Length is the served ladder's
/// arity — a fourth slot cannot exist here.
struct RungRuns<const N: usize> {
    runs: [Vec<(u64, u64)>; N],
    values: [BTreeSet<u64>; N],
    current: [u64; N],
    run_len: [u64; N],
    run_start: [u64; N],
}

struct RungStats<const N: usize> {
    median_dwell: [u64; N],
    distinct: [u64; N],
    changes: [u64; N],
    min_ramp: [Option<u64>; N],
    /// Start offset of the second run per rung (`None` if the value never
    /// changed). Index 1 is the standard rung.
    first_change: [Option<u64>; N],
}

impl<const N: usize> RungRuns<N> {
    fn new() -> Self {
        Self {
            runs: std::array::from_fn(|_| Vec::new()),
            values: std::array::from_fn(|_| BTreeSet::new()),
            current: [0; N],
            run_len: [0; N],
            run_start: [0; N],
        }
    }

    fn observe(&mut self, t: u64, fees: [u64; N]) {
        for (i, fee) in fees.into_iter().enumerate() {
            self.values[i].insert(fee);
            if fee == self.current[i] {
                self.run_len[i] += 1;
            } else {
                if self.run_len[i] > 0 {
                    self.runs[i].push((self.run_start[i], self.run_len[i]));
                }
                self.current[i] = fee;
                self.run_len[i] = 1;
                self.run_start[i] = t;
            }
        }
    }

    fn finish(mut self, is_ramp: bool, ramp_len: u64) -> RungStats<N> {
        for ((runs, start), len) in self.runs.iter_mut().zip(self.run_start).zip(self.run_len) {
            runs.push((start, len));
        }
        let mut stats = RungStats {
            median_dwell: [0; N],
            distinct: [0; N],
            changes: [0; N],
            min_ramp: [None; N],
            first_change: [None; N],
        };
        for (i, runs) in self.runs.iter().enumerate() {
            let mut lens: Vec<u64> = runs.iter().map(|&(_, l)| l).collect();
            lens.sort_unstable();
            stats.median_dwell[i] = lens[lens.len() / 2];
            stats.distinct[i] = self.values[i].len() as u64;
            stats.changes[i] = (runs.len() - 1) as u64;
            stats.first_change[i] = runs.get(1).map(|&(start, _)| start);
            if is_ramp {
                stats.min_ramp[i] = runs
                    .iter()
                    .filter(|&&(start, _)| start > 0 && start < ramp_len)
                    .map(|&(_, l)| l)
                    .min();
            }
        }
        stats
    }
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
    let mut rate_limited = match mode {
        LadderMode::RateLimited(n) => RateLimitedCq::new(n),
        _ => RateLimitedCq::new(1),
    };
    let mut grid = GridArm::for_mode(mode);
    // FL-D8 (§10.9): raw-`C` boundary occupancy and residence. Raw `C` is
    // MODE-INDEPENDENT, so these come out identical on every arm — which
    // is a free self-check that the modes differ only in how they serve a
    // shared trace, not in the trace itself.
    let mut near_blocks = 0u64;
    let mut near_runs: Vec<u64> = Vec::new();
    let mut near_run = 0u64;
    // §10.14.3: blocks where the served `C_q` sits above / below the
    // un-banded ceiling of the same raw `C` — peak-hold's conservative
    // bias, and every band's lag, in the units users pay.
    let mut over_ceiling = 0u64;
    let mut under_ceiling = 0u64;
    let mut rungs = RungRuns::<SERVED_SLOTS>::new();
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
        // Hoisted: every corrected arm needs it, and FL-D8 measures it.
        // Previously each arm recomputed it, which is the shape a new arm
        // silently forgets.
        let c_raw = correction_factor(v_avg, ag, height, params).c_scaled;
        if in_boundary_zone(c_raw) {
            near_blocks += 1;
            near_run += 1;
        } else if near_run > 0 {
            near_runs.push(near_run);
            near_run = 0;
        }
        // The served `C_q` first, so §10.14.3's over-quote share can be
        // read off it against the un-banded ceiling of the SAME raw `C`
        // (`None` for the arms that serve no snapped map).
        let served_cq: Option<u64> = match mode {
            LadderMode::Current | LadderMode::CorrectedRaw => None,
            LadderMode::Quantized(rule) => Some(quantize_c_pow2(c_raw, rule)),
            LadderMode::QuantizedHysteresis => Some(hyst.step(c_raw)),
            LadderMode::RateLimited(_) => Some(rate_limited.step(c_raw)),
            m if m.grid_period().is_some() => Some(grid.step(height, c_raw)),
            m => unreachable!(
                "mode {} serves a quantized map but has no stepper",
                m.name()
            ),
        };
        if let Some(cq) = served_cq {
            let ceiling = quantize_c_pow2(c_raw, SnapRule::Ceiling);
            over_ceiling += u64::from(cq > ceiling);
            under_ceiling += u64::from(cq < ceiling);
        }
        let fees = match (mode, served_cq) {
            (LadderMode::Current, _) => rounded(raw),
            (LadderMode::CorrectedRaw, _) => served_ladder(base, median, c_raw),
            (_, Some(cq)) => served_ladder(base, median, cq),
            (m, None) => unreachable!("mode {} produced no served C_q", m.name()),
        };
        ag = advance_traced_state(ag, v_avg, params);
        rungs.observe(t, fees);
    }

    let is_ramp = (mean_end - mean_start).abs() >= f64::EPSILON;
    let stats = rungs.finish(is_ramp, ramp_len);
    DwellResult {
        scenario,
        is_ramp,
        age_years: st.height / BLOCKS_PER_YEAR,
        mode: mode.name(),
        blocks_measured: blocks,
        median_dwell: stats.median_dwell,
        distinct_posted_values: stats.distinct,
        value_changes: stats.changes,
        min_dwell_started_in_ramp: stats.min_ramp,
        d8_boundary_occupancy_permille: if blocks == 0 {
            0
        } else {
            near_blocks * 1000 / blocks
        },
        d8_mean_residence_blocks: {
            // Close an open run so a trace ending inside the zone is not
            // silently dropped — the longest visits are exactly the ones
            // most likely to still be open at the end.
            if near_run > 0 {
                near_runs.push(near_run);
            }
            if near_runs.is_empty() {
                0
            } else {
                near_runs.iter().sum::<u64>() / near_runs.len() as u64
            }
        },
        d8_max_residence_blocks: near_runs.iter().copied().max().unwrap_or(0),
        is_quantized_map: mode.serves_quantized_map(),
        grid_max_fold_depth: grid.depth_stats().0,
        grid_period: mode.grid_period().unwrap_or(0),
        // Standard rung: first CHANGE after the opening value (that run
        // starts at 0 by construction).
        first_change_offset: stats.first_change[1],
        over_ceiling_permille: over_ceiling * 1000 / blocks.max(1),
        under_ceiling_permille: under_ceiling * 1000 / blocks.max(1),
    }
}

// ---------------------------------------------------------------------------
// Feedback map (FL-C7) — on the SERVED (quantized) ladder
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct FeedbackResult {
    /// FL-R18 rejection-race (§4.5b): quotes issued along the trace, and
    /// how many would be REFUSED at admission `RACE_LAGS[i]` blocks later
    /// because the relay floor rose above the quoted (already
    /// floor-clamped) economy rung. `check_fee`'s 2% buffer is applied,
    /// so this counts real refusals, not near-misses.
    pub race_quotes: u64,
    pub race_refused: [u64; 4],
    /// The race's REAL governing quantity (§4.5b). With the median held,
    /// the relay floor is monotonically non-increasing (reward decay only
    /// shrinks `R`), so `race_refused` is structurally zero and proves
    /// nothing on its own. What decides a refusal is the MARGIN a quote
    /// carries over the floor it was clamped against: `served/floor` in
    /// thousandths, minimised over the trace. A quote survives a median
    /// contraction of factor `f` iff `f² ≤ (served/floor)·(100/98)`, so
    /// this margin converts directly into the median move the quote can
    /// absorb — the exposure the fixed-median traces cannot show.
    pub race_margin_min_milli: u64,
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
    /// Of `tail_transitions`, those at a height `h ≡ 0 (mod P)` — the
    /// grid's anchors, where the fold forgets (§10.12.3). 0 for non-grid
    /// arms, which have no anchors. A grid arm whose extra transitions
    /// (over the banded reference) all sit here is losing cells to the
    /// anchor flip, which no fold depth removes; one with transitions
    /// elsewhere is losing them to something else.
    pub tail_transitions_at_anchor: u64,
    /// Standard-rung value changes over the WHOLE trace — the quantity
    /// §10.14.2's monotonicity invariant is stated on (band ≤ grid-only,
    /// same `P`, same cell). The tail alone cannot carry it: the tail is
    /// a 3 000-block window and a `P` = 720 grid cycle is ≈ 1 440 blocks.
    pub trace_transitions: u64,
    /// §10.14.4 C10-6, read on the LATE HALF of the trace (15 000 blocks)
    /// rather than the 3 000-block tail: a peak-hold-9 cycle at `P` = 720
    /// is ≈ 7 200 blocks and would not fit in the tail at all, so a
    /// tail-only reading would flatter exactly the arms with the longest
    /// cycles. Value changes in the late half; the min and mean gap in
    /// blocks between consecutive ones (0 when fewer than two); and the
    /// late-half fee range, so "sustained" can require the FL-C7
    /// amplitude bar over the same window.
    pub late_transitions: u64,
    pub late_gap_min: u64,
    pub late_gap_mean: u64,
    pub late_fee_min: u64,
    pub late_fee_max: u64,
    /// §10.14.4 C10-7: blocks per thousand (whole trace) from which a
    /// served-value change occurs within the next
    /// [`R19_GAP_BLOCKS_PLACEHOLDER`] blocks — the probability a quote
    /// taken at a uniformly random block is stale by broadcast.
    pub change_within_gap_permille: u64,
    /// §10.14's cold-cost evidence for the arm: deepest evaluation, mean
    /// evaluation, and (`grid-band-*` only) steps that hit the `K` bound
    /// without a settled sample. 0 / 0 / 0 for non-grid arms.
    pub grid_max_depth: u64,
    pub grid_mean_depth: u64,
    pub grid_fallbacks: u64,
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
    // ONE per-block evaluation, returning everything the trace needs from
    // it: the standard rung that drives the demand loop, and the SERVED
    // economy rung (clamped up to the relay floor, §5.2) with the floor
    // it was clamped against. The rejection race previously recomputed
    // the economy rung from RAW `C`, which is not what any stateful mode
    // serves — and it could not simply re-apply the band, because
    // `HysteresisCq::step` and `RateLimitedCq::step` ADVANCE state and a
    // second call per block would double-step them. Returning the served
    // values from the single stepping site fixes both (PR #634 review,
    // Bugbot + Copilot, same defect).
    let step_at = |v_avg: u64,
                   ag: u64,
                   height: u64,
                   hyst: &mut HysteresisCq,
                   rl: &mut RateLimitedCq,
                   grid: &mut GridArm|
     -> (u64, u64, u64) {
        let base = base_block_reward(ag, params).expect("base along trace");
        let c = correction_factor(v_avg, ag, height, params).c_scaled;
        let c = match mode {
            LadderMode::Quantized(rule) => quantize_c_pow2(c, rule),
            LadderMode::QuantizedHysteresis => hyst.step(c),
            LadderMode::RateLimited(_) => rl.step(c),
            m if m.grid_period().is_some() => grid.step(height, c),
            _ => c,
        };
        let ladder = served_ladder(base, median, c);
        let floor_now = relay_floor(base, median);
        (ladder[1].max(1), ladder[0].max(floor_now), floor_now)
    };
    // The reference fee is history-free and anchored at the trace's START
    // state — it defines the demand curve, so it must not move with the
    // loop; the loop's fee below evolves with the traced state (§1.8:
    // confirmed, not assumed) and carries the band's memory.
    let f_ref = step_at(
        demand_scale,
        st.ag,
        st.height,
        &mut HysteresisCq { prev: 0 },
        &mut RateLimitedCq::new(1),
        &mut GridArm::inert(),
    )
    .0;

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
    let mut served_economy: Vec<u64> = Vec::with_capacity(blocks as usize);
    let mut floors: Vec<u64> = Vec::with_capacity(blocks as usize);
    let mut tail_fees = BTreeSet::new();
    let mut tail_transitions = 0u64;
    let mut tail_transitions_at_anchor = 0u64;
    let mut last_tail_fee: Option<u64> = None;
    // Whole-trace and late-half records (§10.14.2 invariant; C10-6/7).
    let late_from = blocks / 2;
    let mut last_fee: Option<u64> = None;
    let mut transition_blocks: Vec<u64> = Vec::new();
    let mut late_fee_min = u64::MAX;
    let mut late_fee_max = 0u64;
    let mut hyst = HysteresisCq { prev: 0 };
    let mut rl = match mode {
        LadderMode::RateLimited(n) => RateLimitedCq::new(n),
        _ => RateLimitedCq::new(1),
    };
    let mut grid = GridArm::for_mode(mode);
    let grid_period = mode.grid_period();
    let mut ag = st.ag;
    for t in 0..blocks {
        let v_avg = (sum / VOLUME_WINDOW as f64).max(0.0) as u64;
        // FL-R18 rejection race: the served economy rung and its
        // quote-time floor come from the SAME stepping call as the fee,
        // so the margin is measured on the map the mode actually serves.
        let (fee, economy, floor_now) =
            step_at(v_avg, ag, st.height + t, &mut hyst, &mut rl, &mut grid);
        served_economy.push(economy);
        floors.push(floor_now);
        ag = advance_traced_state(ag, v_avg, params);
        // The registered §1.7 model has NO saturation (PR #614 review: a
        // hidden 10 000 clamp is a capacity bound the register never
        // derived). Unclamped: the rails bound the SYSTEM — `M_r`
        // saturates at 1.3 and `C_q` with it — so an extreme
        // high-elasticity excursion produces a large volume, a railed
        // correction, and a finite fee, not a divergence; the u64 cast
        // below saturates rather than wraps.
        let demand = (demand_scale as f64) * (fee as f64 / f_ref as f64).powf(-eps);
        let demand = demand.max(0.0);
        sum += demand;
        window.push_back(demand);
        sum -= window.pop_front().expect("window warm");
        if last_fee.is_some_and(|prev| prev != fee) {
            transition_blocks.push(t);
        }
        last_fee = Some(fee);
        if t >= late_from {
            late_fee_min = late_fee_min.min(fee);
            late_fee_max = late_fee_max.max(fee);
        }
        if t >= blocks - tail {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            v_min = v_min.min(v_avg);
            v_max = v_max.max(v_avg);
            tail_fees.insert(fee);
            if let Some(prev_fee) = last_tail_fee {
                if fee != prev_fee {
                    tail_transitions += 1;
                    if grid_period.is_some_and(|p| (st.height + t).is_multiple_of(p)) {
                        tail_transitions_at_anchor += 1;
                    }
                }
            }
            last_tail_fee = Some(fee);
        }
    }
    // Refused iff the quote misses `check_fee`'s acceptance bound at
    // admission: accept requires `fee >= needed - needed/50`, i.e.
    // `served * 100 >= floor_at_admission * 98`.
    let mut race_refused = [0u64; 4];
    for (i, &lag) in RACE_LAGS.iter().enumerate() {
        let lag = lag as usize;
        for h in 0..served_economy.len().saturating_sub(lag) {
            if u128::from(served_economy[h]) * 100 < u128::from(floors[h + lag]) * 98 {
                race_refused[i] += 1;
            }
        }
    }

    let race_margin_min_milli = served_economy
        .iter()
        .zip(floors.iter())
        .map(|(&sv, &fl)| {
            u64::try_from(u128::from(sv) * 1000 / u128::from(fl.max(1))).unwrap_or(u64::MAX)
        })
        .min()
        .unwrap_or(0);

    // Late-half inter-transition gaps.
    let late: Vec<u64> = transition_blocks
        .iter()
        .copied()
        .filter(|&t| t >= late_from)
        .collect();
    let late_gaps: Vec<u64> = late.windows(2).map(|w| w[1] - w[0]).collect();
    let late_gap_min = late_gaps.iter().copied().min().unwrap_or(0);
    let late_gap_mean = if late_gaps.is_empty() {
        0
    } else {
        late_gaps.iter().sum::<u64>() / late_gaps.len() as u64
    };
    // C10-7: the union over transitions at `t` of the blocks
    // `[t − g, t − 1]` from which that change lies within the next `g`
    // blocks; transitions are in ascending order so the union is a single
    // forward pass.
    let g = R19_GAP_BLOCKS_PLACEHOLDER;
    let mut covered = 0u64;
    let mut covered_until = 0u64;
    for &t in &transition_blocks {
        let lo = t.saturating_sub(g).max(covered_until);
        covered += t.saturating_sub(lo);
        covered_until = t;
    }
    let (grid_max_depth, grid_mean_depth, grid_fallbacks) = grid.depth_stats();

    FeedbackResult {
        race_quotes: served_economy.len() as u64,
        race_refused,
        race_margin_min_milli,
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        mode: mode.name(),
        distinct_fees_tail: tail_fees.len() as u64,
        tail_transitions,
        tail_transitions_at_anchor,
        trace_transitions: transition_blocks.len() as u64,
        late_transitions: late.len() as u64,
        late_gap_min,
        late_gap_mean,
        late_fee_min: if late_fee_min == u64::MAX {
            0
        } else {
            late_fee_min
        },
        late_fee_max,
        change_within_gap_permille: covered * 1000 / blocks.max(1),
        grid_max_depth,
        grid_mean_depth,
        grid_fallbacks,
        v_avg_tail_min: v_min,
        v_avg_tail_max: v_max,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
    }
}

// ---------------------------------------------------------------------------
// Degenerate pins (FL-C8)
// ---------------------------------------------------------------------------

/// One candidate `N` for FL-R18's minimum-dwell floor, with what it
/// leaves oscillating on the swept interior.
#[derive(Serialize)]
pub struct NSweepPoint {
    pub n: u64,
    pub oscillating_cells: u64,
    pub worst_tail_transitions: u64,
    /// Cells whose served economy rung sits within 2% of the relay floor
    /// (§4.5b's thin-margin measure) under this `N` — so the claim that a
    /// dwell floor worsens the rejection race is MEASURED rather than
    /// asserted (PR #634 review).
    pub thin_margin_cells: u64,
}

/// §10 — one grid period `P`, for one grid arm, over the SAME feedback
/// grid FL-C7 and FL-R18 were measured on, so the figures compose with
/// the ratified ones instead of describing a different sweep.
#[derive(Serialize)]
pub struct GridSweepPoint {
    /// Arm name (`grid-fold-p*` = §10.3 B, the candidate;
    /// `grid-only-p*` = §10.3 C, INSTRUMENTATION only — C10-5 governs
    /// how its result reads, and the band staying is RULED).
    pub mode: String,
    pub period: u64,
    /// C10-1's numerator: cells still oscillating beyond one rounding
    /// step. The ratified banded map leaves 14 boundary-parked cells at
    /// worst 24 transitions; the served un-banded map leaves 1 161.
    pub oscillating_cells: u64,
    pub worst_tail_transitions: u64,
    /// §4.5b's thin-margin measure, carried so a grid's effect on the
    /// rejection race is measured on the same axis FL-R18 used.
    pub thin_margin_cells: u64,
    /// §10.12.3(a) per-cell diff against the RULED banded reference
    /// (`corrected-quantized-pow2-ceil-hysteresis`, same sweep): cells
    /// this arm leaves oscillating that the reference does not. C10-1's
    /// "20 vs 14" made concrete — round 1 counted, round 2 names.
    pub extra_cells: u64,
    /// Worst `tail_transitions` among the extra cells.
    pub extra_cells_worst_transitions: u64,
    /// Across the extra cells, tail transitions NOT at a grid anchor.
    /// §10.12.3's claim is that the extra cells are anchor-flip cells,
    /// which predicts exactly 0 here (R2-E2); any other value is a
    /// transition the anchor story does not account for.
    pub extra_cells_off_anchor_transitions: u64,
    /// The reverse set: cells the reference leaves oscillating that this
    /// arm does not. Predicted empty for the fold arms — the grid adds
    /// forgetting, it does not add damping.
    pub recovered_cells: u64,
    /// §10.14.2's monotonicity invariant, MEASURED: cells where this arm's
    /// whole-trace transitions exceed `grid-only` at the same `P` on the
    /// same cell. `None` where there is no comparator (non-grid arms, and
    /// grid-only itself). Expected 0 for every sequence arm with an
    /// unbounded scan; a non-zero count on a bounded band arm is its
    /// fallback anchor at work, and on `kfull` it voids the run.
    pub invariant_violations: Option<u64>,
    /// C10-6 (§10.14.4): over cells with a SUSTAINED late-half oscillation
    /// ([`is_sustained_late`]), the minimum cycle period
    /// `2 × late_gap_mean` and the minimum single inter-transition gap —
    /// in blocks; the summary converts to days. 0 when no cell sustains.
    pub sustained_cells: u64,
    pub min_cycle_blocks: u64,
    pub min_gap_blocks: u64,
    /// C10-7 (§10.14.4): worst cell and cell-mean of the change-within-gap
    /// share, per thousand blocks.
    pub change_within_gap_worst_permille: u64,
    pub change_within_gap_mean_permille: u64,
    /// Cold-cost evidence (§10.14.2's first column): deepest evaluation
    /// over the sweep, the worst cell-mean depth, cells that hit the `K`
    /// bound, and the parses those imply under [`LadderMode::cold_parses`].
    pub max_depth: u64,
    pub mean_depth_worst: u64,
    pub fallback_cells: u64,
    pub cold_parses_worst: u64,
    pub cold_parses_mean: u64,
    /// The memo column, structural (§10.14.2's second column; not a
    /// register-adopted budget): parses per day at steady state.
    pub memo_parses_per_day: u64,
}

/// A feedback cell's identity on the shared sweep grid:
/// `(state height, median, ε‰, demand scale, start volume)`.
type CellKey = (u64, u64, u64, u64, u64);

/// FL-C7's oscillation criterion, ONE owner for every sweep that scores
/// it: at least two value changes in the tail, with an amplitude beyond a
/// single rounding step.
fn is_oscillating(fb: &FeedbackResult) -> bool {
    fb.tail_transitions >= 2 && fb.fee_tail_max > round_money_up_2(fb.fee_tail_min + 1)
}

/// C10-6's "sustained" (§10.14.4): FL-C7's bar — two changes and an
/// amplitude beyond one rounding step — applied over the LATE HALF of the
/// trace instead of the 3 000-block tail, so cycles longer than the tail
/// (peak-hold at `W` = 9 is ≈ 7 200 blocks) are counted rather than
/// vanished. `is_oscillating` stays the C10-1 owner so round 1's figures
/// remain comparable; this one exists for the criterion that asks about
/// PERIOD, which the tail cannot resolve.
fn is_sustained_late(fb: &FeedbackResult) -> bool {
    fb.late_transitions >= 2 && fb.late_fee_max > round_money_up_2(fb.late_fee_min + 1)
}

#[derive(Serialize)]
pub struct DegeneratePins {
    /// `b` reaches its cap on-grid: `(v=500, ratio=0.9)` → `burn_cap`.
    pub burn_at_cap: u64,
    /// `M_r` rails: at `v=0` and at `v=100`.
    pub release_at_zero: u64,
    pub release_at_double_baseline: u64,
    /// Tail subsidy per block, and the supply headroom at tail entry
    /// (`tail << esf`). `tail_era_blocks` is `2^esf` by IDENTITY (doc
    /// §FL-V7: `remaining/tail = 2^esf`) — but since FL-R12′ retired the
    /// supply cap it is no longer an ERA BOUNDARY: the tail is perpetual
    /// and the accumulator runs through the asymptote. It is now the
    /// number of tail-rate blocks the headroom to the asymptote covers,
    /// which is what makes the asymptote a landmark rather than an end.
    pub tail_subsidy_per_block: u64,
    pub headroom_at_tail_entry: u64,
    pub tail_era_blocks: u64,
    /// At `already_generated == emission_curve_asymptote`: the 5-arg estimate path's
    /// pre-penalty curve value vs the paid quantity validation settles on.
    /// FL-V1's divergence in its terminal form — since FL-R12′ that is a
    /// gap between two nonzero rewards, not the estimate-vs-ZERO it was
    /// while the supply cap stood.
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
    pub estimate_ladder_at_exhaustion: [u64; SERVED_SLOTS],
    pub validation_ladder_at_exhaustion: [u64; SERVED_SLOTS],
    pub relay_floor_at_exhaustion: u64,
}

fn degenerate_pins(params: &EconomicParams) -> DegeneratePins {
    let ratio_09 = params.emission_curve_asymptote / 10 * 9;
    let esf = emission_speed_factor(params);
    let tail = tail_subsidy_per_block(params).expect("tail subsidy");
    let s = params.emission_curve_asymptote;
    let est_reward = base_block_reward(s, params).expect("base at exhaustion");
    // FL-R12′ retired the supply cap, so validation no longer pays ZERO at
    // the asymptote — it pays the perpetual tail through the one owner.
    // §4.6's `[0,0,0,0]` ladder is the pre-implementation defect record.
    let val_reward = paid_block_reward(
        FULL_REWARD_ZONE_V5,
        FULL_REWARD_ZONE_V5,
        s,
        FULL_REWARD_ZONE_V5,
        TxVolume::per_block(params.tx_volume_baseline),
        params,
    )
    .expect("paid reward at the asymptote is total");
    DegeneratePins {
        burn_at_cap: calc_burn_pct(
            TxVolume::per_block(500),
            params.tx_volume_baseline,
            ratio_09,
            s,
            params.burn_base_rate,
            params.burn_cap,
        ),
        release_at_zero: calc_release_multiplier(
            TxVolume::ZERO,
            params.tx_volume_baseline,
            params.release_min,
            params.release_max,
        ),
        release_at_double_baseline: calc_release_multiplier(
            TxVolume::per_block(100),
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
        relay_floor_at_exhaustion: relay_floor(val_reward, FULL_REWARD_ZONE_V5),
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
    /// FL-R18's `N` measurement: oscillating cells remaining at each
    /// candidate minimum-dwell floor (§4.5a).
    n_sweep: Vec<NSweepPoint>,
    /// §10 FL-R3 time-grid round: both arms across the candidate periods.
    grid_sweep: Vec<GridSweepPoint>,
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
        let proj_ratio =
            u128::from(st.ag) * u128::from(SCALE) / u128::from(params.emission_curve_asymptote);
        for &ratio in &ratios {
            // §1.8 reachability: the release multiplier bounds the real
            // trajectory within [0.8, 1.3]× of the neutral one.
            let lo = proj_ratio * 8 / 10;
            let hi = (proj_ratio * 13 / 10).min(u128::from(SCALE));
            let reachable = u128::from(ratio) >= lo && u128::from(ratio) <= hi;
            let circ = u64::try_from(
                u128::from(params.emission_curve_asymptote) * u128::from(ratio) / u128::from(SCALE),
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
            LadderMode::RateLimited(FL_R18_MIN_DWELL_BLOCKS),
            // §10: the FL-R3 candidate shapes must appear on the DWELL
            // grid too, not only the feedback grid — C10-2 scores dwell
            // and C10-3 reads the observed fold depth, and both are
            // measured here. Omitting them left `grid_max_fold_depth` at
            // 0 on every row, which reads exactly like "the fold is
            // free" rather than "the fold was never run".
            //
            // Round 2 (§10.12.1): round 1 ran ONLY the P = 240 pair here
            // and read C10-3's depth off it, then attributed the figure
            // to the P = 720 that C10-4 selected. The selected P must be
            // measured where the depth is measured; the 240 arms stay so
            // the round-1 number stays reproducible next to the corrected
            // one, and the warm arm carries §10.12.3(b)'s depth ∈ [P, 2P).
            LadderMode::GridFold(240),
            LadderMode::GridOnly(240),
            LadderMode::GridFold(720),
            LadderMode::GridOnly(720),
            LadderMode::GridFoldWarm(720, 1),
            // Round 2b (§10.14.5): the settled-anchor band at the selected
            // P and K, and the window filters — on the dwell grid for
            // C10-8's lag, the flip rate FL-D8 owed, and the over-quote
            // share.
            LadderMode::GridBand(720, Some(32)),
            LadderMode::GridMedian(720, 3),
            LadderMode::GridPeak(720, 3),
            LadderMode::GridPeak(720, 4),
            LadderMode::GridPeak(720, 8),
            LadderMode::GridPeak(720, 9),
            LadderMode::GridPeak(720, 16),
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

    // FL-R18 (c): MEASURE `N`. Candidates are the figures the register
    // already contains — the ramp bar (60), the stationary dwell gate
    // (240), and the volume window (720) — plus their midpoint; the
    // ratified `N` is the smallest that closes every oscillating cell,
    // with the next-smaller candidate's residual recorded so the margin
    // is visible rather than asserted.
    let mut n_sweep = Vec::new();
    for n in [60u64, 120, 240, 480, 720] {
        let mut oscillating = 0u64;
        let mut worst_transitions = 0u64;
        let mut thin_margin_cells = 0u64;
        for &(_age, st) in &states {
            let d_boundary = boundary_demand(st, &params);
            for &median in &[zone, 3 * zone, 10 * zone, 50 * zone] {
                for eps in [0u64, 500, 1000, 2000, 3000] {
                    for demand_scale in [50u64, 100, d_boundary, 400] {
                        for start in [demand_scale, 8 * demand_scale.min(1_250)] {
                            let fb = feedback_scenario(
                                eps,
                                demand_scale,
                                start,
                                st,
                                median,
                                LadderMode::RateLimited(n),
                                &params,
                            );
                            if is_oscillating(&fb) {
                                oscillating += 1;
                                worst_transitions = worst_transitions.max(fb.tail_transitions);
                            }
                            if fb.race_margin_min_milli < 1020 {
                                thin_margin_cells += 1;
                            }
                        }
                    }
                }
            }
        }
        n_sweep.push(NSweepPoint {
            n,
            oscillating_cells: oscillating,
            worst_tail_transitions: worst_transitions,
            thin_margin_cells,
        });
    }

    // §10 FL-R3 time-grid round. Same grid as FL-R18's `n` sweep above,
    // deliberately: C10-1 scores against FL-C7's ratified banded figures,
    // and a figure measured on a different sweep cannot be compared to
    // them. Periods are the §10.5 candidates — 60 (≈ the measured worst
    // inter-flip dwell), 240 (the FL-C4a stationary bar) and 720 (the
    // volume window, `P`'s natural ceiling since the fold cannot outrun
    // the average feeding it). `settlement_epoch_blocks` (10 000) is
    // NOT swept: §10.5 rejects it on the record rather than measuring a
    // fee quote frozen for a fortnight.
    //
    // The two REFERENCE arms are swept here too, at `period = 0` meaning
    // "not a grid". Without them C10-1 would score new figures against
    // numbers taken from a different sweep, which is the comparison the
    // round is least entitled to make: `corrected-quantized-pow2-ceil` is
    // what the daemon serves TODAY (the floor to beat) and
    // `...-hysteresis` is the RULED banded map (the target to reach).
    // Measuring all three on one grid is what makes "restored" a
    // comparison rather than an assertion.
    //
    // Round 2 (§10.12.3(a)) adds the PER-CELL diff against the banded
    // reference. Round 1 compared totals (20 vs 14) and then EXPLAINED the
    // difference from the mechanism's construction; the explanation was
    // never itself measured. Each arm's cells are now matched to the
    // reference's by state, so "which six" and "where do their
    // transitions sit" are read off the run. The warm arm
    // (§10.12.3(b)) is the mechanism's own falsifier: if the six were a
    // depth artefact a fold of depth ∈ [P, 2P) would recover some of them.
    let arms: Vec<LadderMode> = vec![
        LadderMode::Quantized(SnapRule::Ceiling),
        LadderMode::QuantizedHysteresis,
        LadderMode::GridFold(60),
        LadderMode::GridOnly(60),
        LadderMode::GridFold(240),
        LadderMode::GridOnly(240),
        LadderMode::GridFold(720),
        LadderMode::GridOnly(720),
        LadderMode::GridFoldWarm(720, 1),
        // Round 2b (§10.14.5).
        LadderMode::GridBand(60, Some(8)),
        LadderMode::GridBand(60, Some(16)),
        LadderMode::GridBand(60, Some(32)),
        LadderMode::GridBand(60, None),
        LadderMode::GridBand(240, Some(8)),
        LadderMode::GridBand(240, Some(16)),
        LadderMode::GridBand(240, Some(32)),
        LadderMode::GridBand(240, None),
        LadderMode::GridBand(720, Some(8)),
        LadderMode::GridBand(720, Some(16)),
        LadderMode::GridBand(720, Some(32)),
        LadderMode::GridBand(720, None),
        LadderMode::GridMedian(720, 3),
        LadderMode::GridMedian(720, 5),
        LadderMode::GridMedian(720, 9),
        LadderMode::GridPeak(720, 3),
        LadderMode::GridPeak(720, 4),
        LadderMode::GridPeak(720, 5),
        LadderMode::GridPeak(720, 8),
        LadderMode::GridPeak(720, 9),
        LadderMode::GridPeak(720, 16),
    ];
    let sweep_arm = |mode: LadderMode| -> Vec<(CellKey, FeedbackResult)> {
        let mut cells = Vec::new();
        for &(_age, st) in &states {
            let d_boundary = boundary_demand(st, &params);
            for &median in &[zone, 3 * zone, 10 * zone, 50 * zone] {
                for eps in [0u64, 500, 1000, 2000, 3000] {
                    for demand_scale in [50u64, 100, d_boundary, 400] {
                        for start in [demand_scale, 8 * demand_scale.min(1_250)] {
                            let fb = feedback_scenario(
                                eps,
                                demand_scale,
                                start,
                                st,
                                median,
                                mode,
                                &params,
                            );
                            cells.push(((st.height, median, eps, demand_scale, start), fb));
                        }
                    }
                }
            }
        }
        cells
    };
    let reference: BTreeSet<CellKey> = sweep_arm(LadderMode::QuantizedHysteresis)
        .into_iter()
        .filter(|(_, fb)| is_oscillating(fb))
        .map(|(key, _)| key)
        .collect();
    // Every arm is swept once and held, because §10.14.2's invariant
    // compares each grid arm's cells against grid-only's AT THE SAME P —
    // a per-cell comparator, like the banded reference above.
    let swept: Vec<(LadderMode, Vec<(CellKey, FeedbackResult)>)> =
        arms.iter().map(|&mode| (mode, sweep_arm(mode))).collect();
    let grid_only_transitions: BTreeMap<(u64, CellKey), u64> = swept
        .iter()
        .filter_map(|(mode, cells)| match mode {
            LadderMode::GridOnly(p) => Some((*p, cells)),
            _ => None,
        })
        .flat_map(|(p, cells)| {
            cells
                .iter()
                .map(move |(key, fb)| ((p, *key), fb.trace_transitions))
        })
        .collect();
    let mut grid_sweep = Vec::new();
    for (mode, cells) in swept {
        let mut oscillating = 0u64;
        let mut worst_transitions = 0u64;
        let mut thin_margin_cells = 0u64;
        let mut extra_cells = 0u64;
        let mut extra_cells_worst_transitions = 0u64;
        let mut extra_cells_off_anchor_transitions = 0u64;
        let mut recovered_cells = 0u64;
        let has_comparator =
            mode.grid_period().is_some() && !matches!(mode, LadderMode::GridOnly(_));
        let mut invariant_violations = 0u64;
        let mut sustained_cells = 0u64;
        let mut min_cycle_blocks = u64::MAX;
        let mut min_gap_blocks = u64::MAX;
        let mut gap_worst = 0u64;
        let mut gap_sum = 0u64;
        let mut max_depth = 0u64;
        let mut mean_depth_worst = 0u64;
        let mut fallback_cells = 0u64;
        let n_cells = cells.len() as u64;
        for (key, fb) in cells {
            if has_comparator {
                let p = mode.grid_period().expect("has_comparator implies a period");
                let only = grid_only_transitions
                    .get(&(p, key))
                    .expect("grid-only swept at every period a grid arm uses");
                invariant_violations += u64::from(fb.trace_transitions > *only);
            }
            if is_sustained_late(&fb) {
                sustained_cells += 1;
                min_cycle_blocks = min_cycle_blocks.min(2 * fb.late_gap_mean);
                min_gap_blocks = min_gap_blocks.min(fb.late_gap_min);
            }
            gap_worst = gap_worst.max(fb.change_within_gap_permille);
            gap_sum += fb.change_within_gap_permille;
            max_depth = max_depth.max(fb.grid_max_depth);
            mean_depth_worst = mean_depth_worst.max(fb.grid_mean_depth);
            fallback_cells += u64::from(fb.grid_fallbacks > 0);
            let osc = is_oscillating(&fb);
            if osc {
                oscillating += 1;
                worst_transitions = worst_transitions.max(fb.tail_transitions);
                if !reference.contains(&key) {
                    extra_cells += 1;
                    extra_cells_worst_transitions =
                        extra_cells_worst_transitions.max(fb.tail_transitions);
                    extra_cells_off_anchor_transitions +=
                        fb.tail_transitions - fb.tail_transitions_at_anchor;
                }
            } else if reference.contains(&key) {
                recovered_cells += 1;
            }
            if fb.race_margin_min_milli < 1020 {
                thin_margin_cells += 1;
            }
        }
        grid_sweep.push(GridSweepPoint {
            mode: mode.name(),
            period: mode.grid_period().unwrap_or(0),
            oscillating_cells: oscillating,
            worst_tail_transitions: worst_transitions,
            thin_margin_cells,
            extra_cells,
            extra_cells_worst_transitions,
            extra_cells_off_anchor_transitions,
            recovered_cells,
            invariant_violations: has_comparator.then_some(invariant_violations),
            sustained_cells,
            min_cycle_blocks: if sustained_cells == 0 {
                0
            } else {
                min_cycle_blocks
            },
            min_gap_blocks: if sustained_cells == 0 {
                0
            } else {
                min_gap_blocks
            },
            change_within_gap_worst_permille: gap_worst,
            change_within_gap_mean_permille: gap_sum / n_cells.max(1),
            max_depth,
            mean_depth_worst,
            fallback_cells,
            cold_parses_worst: mode.cold_parses(max_depth),
            cold_parses_mean: mode.cold_parses(mean_depth_worst),
            memo_parses_per_day: mode.memo_parses_per_day(),
        });
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
        n_sweep,
        grid_sweep,
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
    let quantized_runs = r.dwell.iter().filter(|d| d.is_quantized_map).count();
    // Under the evolved traces a value change is NORMAL (the ~1-per-
    // 10-20k-block reward-decay crossing), so the exception filter is the
    // registered gate, not any change.
    // Per-scenario-kind REGISTERED gates (§1.4a; PR #614 review — a
    // single median-vs-240 filter tested the wrong statistic for ramps):
    // stationary gates median dwell ≥ 240; the ramp gates its min
    // in-ramp run ≥ 60 (the whole-trace median is tail-dominated there
    // and is not the ramp's registered bar).
    let fails_registered_gate = |d: &DwellResult| -> bool {
        if d.is_ramp {
            d.min_dwell_started_in_ramp
                .iter()
                .any(|r| matches!(r, Some(l) if *l < 60))
        } else {
            d.median_dwell.iter().any(|&m| m < 240)
        }
    };
    let quantized_gate_violations = r
        .dwell
        .iter()
        .filter(|d| d.is_quantized_map && fails_registered_gate(d))
        .count();
    let _ = writeln!(
        out,
        "fee-ladder: dwell grid = {} runs ({} quantized; {} quantized runs FAIL their registered gate)",
        r.dwell.len(),
        quantized_runs,
        quantized_gate_violations
    );
    for d in &r.dwell {
        let interesting = if d.is_quantized_map {
            fails_registered_gate(d)
        } else {
            d.mode == "corrected-raw" && d.scenario.starts_with("stationary-v50")
        };
        if interesting {
            let _ = writeln!(
                out,
                "fee-ladder: dwell {} age={} [{}] median={:?} distinct={:?} changes={:?} min_ramp={:?} d8_occupancy_permille={} d8_residence_mean={} d8_residence_max={} grid_max_fold_depth={}",
                d.scenario,
                d.age_years,
                d.mode,
                d.median_dwell,
                d.distinct_posted_values,
                d.value_changes,
                d.min_dwell_started_in_ramp,
                d.d8_boundary_occupancy_permille,
                d.d8_mean_residence_blocks,
                d.d8_max_residence_blocks,
                d.grid_max_fold_depth
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
    // The FL-C7 amplitude bar is the REGISTERED one — more than one
    // fee-rounding step (PR #614 review: a 1.9× ratio tested `C_q`
    // flips, not the bar; a smaller multi-step cycle must fail too).
    // "One rounding step" is exact: the next distinct
    // `round_money_up_2` value above the tail minimum.
    let fb_multi: Vec<_> = r.feedback.iter().filter(|fb| is_oscillating(fb)).collect();
    let _ = writeln!(
        out,
        "fee-ladder: feedback grid = {} cells; {} secular single crossings; {} OSCILLATING beyond one rounding step (listed below)",
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
    for p in &r.n_sweep {
        let _ = writeln!(
            out,
            "fee-ladder: FL-R18 n={} oscillating_cells={} worst_transitions={} thin_margin_cells={}",
            p.n, p.oscillating_cells, p.worst_tail_transitions, p.thin_margin_cells
        );
    }
    // §10 C10-3 (cost) and FL-D8, aggregated over the dwell grid. Both
    // live per-row in the JSON; these lines exist because a criterion
    // whose evidence is only machine-readable gets scored from memory.
    //
    // One line per grid arm THAT RAN, selected by the row's own period.
    // Round 1 iterated a hard-coded pair of labels here; the dwell grid
    // happened to run exactly that pair, so nothing was missing from the
    // output — the selected P = 720 simply never appeared, and its depth
    // was inferred from P = 240's line (§10.12.1). A summary that names
    // the rows it expects cannot report the row it did not get.
    let grid_arms: BTreeSet<(u64, &str)> = r
        .dwell
        .iter()
        .filter(|d| d.grid_period > 0)
        .map(|d| (d.grid_period, d.mode.as_str()))
        .collect();
    for (period, mode) in grid_arms {
        let depth = r
            .dwell
            .iter()
            .filter(|d| d.mode == mode)
            .map(|d| d.grid_max_fold_depth)
            .max()
            .unwrap_or(0);
        // The dwell rows carry the mode's NAME, not the mode; the parses
        // formula differs by arm kind (§10.14.5), so the dwell line reports
        // depth only and the per-arm cost triple is printed from the
        // feedback sweep below, where the mode is known.
        let _ = writeln!(
            out,
            "fee-ladder: FL-R3 cost {mode} period={period} max_fold_depth={depth} (dwell grid; parses on the C10-6/7 line)"
        );
    }
    // Round 2b (§10.14.4/5): per quantized-map arm on the DWELL grid — the
    // occupancy-weighted flip rate FL-D8 owed (standard-rung changes per
    // 10 000 blocks over the whole ensemble), C10-8's lag on the ramp
    // against the un-banded ceiling (max over ramp traces, blocks and
    // milli-days), and the over-/under-ceiling shares.
    {
        let modes: BTreeSet<&str> = r
            .dwell
            .iter()
            .filter(|d| d.is_quantized_map)
            .map(|d| d.mode.as_str())
            .collect();
        let ceiling_first: BTreeMap<(&str, u64), u64> = r
            .dwell
            .iter()
            .filter(|d| d.mode == LadderMode::Quantized(SnapRule::Ceiling).name() && d.is_ramp)
            .filter_map(|d| {
                d.first_change_offset
                    .map(|f| ((d.scenario, d.age_years), f))
            })
            .collect();
        for mode in modes {
            let rows: Vec<&DwellResult> = r.dwell.iter().filter(|d| d.mode == mode).collect();
            let blocks: u64 = rows.iter().map(|d| d.blocks_measured).sum();
            let changes: u64 = rows.iter().map(|d| d.value_changes[1]).sum();
            let mut lag_max: Option<u64> = None;
            // Per-direction worst lag (§10.14.6): the ramp scenarios now run
            // both ways and peak-hold's lag is asymmetric by construction, so
            // the selection rule's "worst-direction lag" needs each side
            // visible, not only their max.
            let mut lag_by_ramp: BTreeMap<&str, u64> = BTreeMap::new();
            let mut lag_unresolved = 0u64;
            for d in rows.iter().filter(|d| d.is_ramp) {
                match (
                    d.first_change_offset,
                    ceiling_first.get(&(d.scenario, d.age_years)),
                ) {
                    (Some(mine), Some(&ceil)) => {
                        let lag = mine.saturating_sub(ceil);
                        lag_max = Some(lag_max.unwrap_or(0).max(lag));
                        let slot = lag_by_ramp.entry(d.scenario).or_insert(0);
                        *slot = (*slot).max(lag);
                    }
                    _ => lag_unresolved += 1,
                }
            }
            let lag_by_ramp: Vec<String> = lag_by_ramp
                .iter()
                .map(|(s, l)| format!("{s}={l}"))
                .collect();
            let over = rows
                .iter()
                .map(|d| d.over_ceiling_permille)
                .max()
                .unwrap_or(0);
            let under = rows
                .iter()
                .map(|d| d.under_ceiling_permille)
                .max()
                .unwrap_or(0);
            let _ = writeln!(
                out,
                "fee-ladder: C10-8 {mode} flips_per_10k_blocks={} ramp_lag_max_blocks={} ramp_lag_max_millidays={} ramp_lag_by_ramp=[{}] ramp_lag_unresolved={lag_unresolved} over_ceiling_permille_max={over} under_ceiling_permille_max={under}",
                changes * 10_000 / blocks.max(1),
                lag_max.map_or("none".to_owned(), |l| l.to_string()),
                lag_max.map_or("none".to_owned(), |l| (l * 1000 / BLOCKS_PER_DAY).to_string()),
                lag_by_ramp.join(","),
            );
        }
    }
    {
        let occ = r
            .dwell
            .iter()
            .map(|d| d.d8_boundary_occupancy_permille)
            .max()
            .unwrap_or(0);
        let res_mean = r
            .dwell
            .iter()
            .map(|d| d.d8_mean_residence_blocks)
            .max()
            .unwrap_or(0);
        let res_max = r
            .dwell
            .iter()
            .map(|d| d.d8_max_residence_blocks)
            .max()
            .unwrap_or(0);
        let _ = writeln!(
            out,
            "fee-ladder: FL-D8 occupancy_permille_max={occ} residence_mean_max={res_mean} residence_max={res_max}"
        );
    }
    for p in &r.grid_sweep {
        let _ = writeln!(
            out,
            "fee-ladder: FL-R3 {} period={} oscillating_cells={} worst_transitions={} thin_margin_cells={} extra_vs_banded={} extra_worst_transitions={} extra_off_anchor_transitions={} recovered_vs_banded={}",
            p.mode,
            p.period,
            p.oscillating_cells,
            p.worst_tail_transitions,
            p.thin_margin_cells,
            p.extra_cells,
            p.extra_cells_worst_transitions,
            p.extra_cells_off_anchor_transitions,
            p.recovered_cells
        );
        let _ = writeln!(
            out,
            "fee-ladder: C10-6/7 {} sustained_cells={} min_cycle_blocks={} min_cycle_millidays={} min_gap_blocks={} change_in_gap_worst_permille={} change_in_gap_mean_permille={} invariant_violations={} max_depth={} mean_depth_worst={} fallback_cells={} cold_parses_worst={} cold_parses_mean={} memo_parses_per_day={}",
            p.mode,
            p.sustained_cells,
            p.min_cycle_blocks,
            p.min_cycle_blocks * 1000 / BLOCKS_PER_DAY,
            p.min_gap_blocks,
            p.change_within_gap_worst_permille,
            p.change_within_gap_mean_permille,
            p.invariant_violations.map_or("n/a".to_owned(), |v| v.to_string()),
            p.max_depth,
            p.mean_depth_worst,
            p.fallback_cells,
            p.cold_parses_worst,
            p.cold_parses_mean,
            p.memo_parses_per_day
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

    /// The guard [`in_boundary_zone`]'s docstring promises: `D8_MARGIN_MILLI`
    /// is a re-derivation of the owner's private `HYSTERESIS_MARGIN_MILLI`,
    /// and a duplicated constant that nothing checks is one that drifts.
    ///
    /// The owner's margin is private, so this asserts the BEHAVIOUR the two
    /// must share rather than the literal: a `C` just inside the band's
    /// margin above a boundary is one the band holds (`hysteresis_step`
    /// keeps `prev`), and D8 must call that same `C` "near". Take a pow2
    /// `C_q`, place `C` a hair under `prev * (1 + margin)`, and require both
    /// to agree. If either constant moves alone, the two disagree and this
    /// fails.
    #[test]
    fn boundary_zone_margin_matches_the_owner() {
        // A pow2 step in SCALE units, and a `C` just inside the upper edge
        // of the band around it: within +3%.
        let prev = SCALE;
        let inside = prev + prev * 29 / 1000;
        assert_eq!(
            hysteresis_step(inside, prev),
            prev,
            "owner must HOLD a C inside its margin — if not, the band's \
             margin moved and D8_MARGIN_MILLI must move with it"
        );
        assert!(
            in_boundary_zone(inside),
            "D8 must call the same C 'near a boundary' as the band acts on"
        );
        // Well outside the zone: the geometric middle of a pow2 interval
        // is the farthest a C can be from both ends.
        let middle = prev * 3 / 2;
        assert!(
            !in_boundary_zone(middle),
            "mid-interval C is not near either boundary; a predicate that \
             says otherwise would report occupancy ~1 and mean nothing"
        );
    }

    #[test]
    fn rung_runs_tracks_one_change_per_slot() {
        let mut rungs = RungRuns::<SERVED_SLOTS>::new();
        rungs.observe(0, [10, 20, 40]);
        rungs.observe(1, [10, 20, 40]);
        rungs.observe(2, [10, 20, 80]);
        let stats = rungs.finish(false, 0);
        assert_eq!(SERVED_SLOTS, 3);
        assert_eq!(stats.distinct, [1, 1, 2]);
        assert_eq!(stats.changes, [0, 0, 1]);
        assert_eq!(stats.min_ramp, [None, None, None]);
        assert_eq!(stats.first_change, [None, None, Some(2)]);
    }

    /// Pin the transliteration against `tests/unit_tests/scaling_2021.cpp`
    /// `wallet_fee_estimate` (10 SKL reward cases) — the instrument's
    /// "current" column must reproduce the PRE-FL-R20 C++ oracle exactly —
    /// the four-rung, `round_money_up_2`-ed, 0.95-ed shape that was the
    /// daemon's until FL-R20/FL-R21. It is a historical baseline the sim
    /// compares AGAINST, not a claim about what the daemon serves today.
    ///
    /// Deliberately NOT routed through [`rounded`], which projects onto the
    /// three priced rungs. This pin's subject is the legacy FOUR-value
    /// transliteration, and letting the projection eat `Fm` would quietly
    /// drop a pinned oracle value — the heritage KAT would still pass while
    /// covering one rung less than it claims.
    #[test]
    fn transliteration_matches_cpp_kat() {
        let coin: u64 = 1_000_000_000;
        let legacy =
            |r: u64, mnw: u64, mlw: u64| articmine_ladder_raw(r, mnw, mlw).map(round_money_up_2);
        assert_eq!(
            legacy(10 * coin, 300_000, 300_000),
            [340, 1400, 5400, 67_000]
        );
        assert_eq!(
            legacy(10 * coin, 15_000_000, 300_000),
            [340, 1400, 5400, 22_000]
        );
        assert_eq!(
            legacy(10 * coin, 1_500_000, 1_500_000),
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
        // `fees[2]` is priority.
        assert_eq!(fees[2], 14_000_000);
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

    /// The served ladder is the OWNER's arithmetic, and this pins the
    /// value the owner actually returns — which is not what this test
    /// asserted before (PR #640 review).
    ///
    /// Round 14 pinned 210 here on the belief that production scaled an
    /// already-truncated rung, and warned against "fixing" it toward the
    /// numerator form. The shipped `corrected_fee_ladder` divides ONCE —
    /// `round2(base·w_ref·C_q / (Mfw²·SCALE))` — so at
    /// (10 SKL, `Mfw = 1.5 MB`, `C_q = 16`) it returns **220**. The old
    /// pin was guarding the instrument against agreeing with the daemon.
    /// The local mirror is gone; this asserts the owner directly, so the
    /// two cannot diverge again.
    #[test]
    fn served_ladder_is_the_owners_arithmetic() {
        let coin: u64 = 1_000_000_000;
        // The legacy transliteration still truncates its rung first —
        // that is what today's daemon does, and it is why the Current
        // column keeps it.
        let raw = articmine_ladder_raw(10 * coin, 1_500_000, 1_500_000);
        assert_eq!(raw[0], 13);

        // The SERVED value at the same state: one division, no compounded
        // truncation, and since FL-R21 no `round_money_up_2` either. It was
        // 220 while the owner rounded each rung up to two significant
        // digits; the arithmetic's own answer is 213.
        assert_eq!(served_ladder(10 * coin, 1_500_000, 16 * SCALE)[0], 213);

        // And it is the owner's output verbatim, not a reproduction.
        assert_eq!(
            served_ladder(10 * coin, 1_500_000, 16 * SCALE),
            corrected_fee_ladder(
                10 * coin,
                1_500_000,
                1_500_000,
                FULL_REWARD_ZONE_V5,
                REF_TX_WEIGHT,
                16 * SCALE
            )
            .as_slots()
        );
    }

    /// [`HysteresisCq`] is LOAD-BEARING (§4.5: the un-hysteretic map fails
    /// FL-C7 at 18 reachable boundary cells; the 800-cell convergence
    /// result rests on this band), so its boundaries are pinned directly —
    /// a threshold or inequality drift must fail HERE, not silently
    /// invalidate the §4.5 measurement (PR #614 review). Since #640 the
    /// semantics are not mirrored but CALLED —
    /// `shekyl-economics::hysteresis_step` — so this pins the owner's
    /// boundaries: 3% margin, band around the PREVIOUS step, escape
    /// strictly-outside (`>` / `<`), `prev = 0` means no history.
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
