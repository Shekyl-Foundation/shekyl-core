//! §11 of `docs/design/FEE_LADDER_DERIVATION.md` — the relay floor follows
//! `C`. The confirmation set for FL-E1…FL-E3, pre-registered in §11.5
//! before this file was first run.
//!
//! What is measured. Under FL-R20 the relay floor is the raw economy rate
//! `F(h) = R·C(h)·w_ref/M²` — unquantized, unrounded — and the wallet pays
//! exactly the served rung (FL-R22: no pad, no draw). Under FL-R23 a
//! transaction is admitted at height `h′` iff
//!
//! ```text
//! fee/byte ≥ min{ F(h′−k) : 0 ≤ k ≤ G }        (lookback-min, G = LOOKBACK_G)
//! ```
//!
//! with `h′` the RECEIVING node's tip, so a quote taken at `h` is admitted
//! by IDENTITY at every node whose tip is in `[h, h+G]` — the
//! construction-to-broadcast gap is one hot session (0–2 blocks), peers
//! may be up to two blocks ahead at relay time, and `G` is those plus one
//! block of slack (review A-1). FL-E4 sweeps `G` ∈ [`LOOKBACK_SWEEP`]. Nothing in the inequality
//! depends on tiers, snaps, pads, or stored state beyond `G+1` floor
//! values every node derives from the chain. What the lookback COSTS is
//! the grace it extends: admission may sit below the current floor by
//! `F(h′)/min_k F(h′−k) − 1`, which is exactly the floor's worst rise over
//! `G` blocks. So the whole question is the per-block slew of `C`, and this
//! module measures it two ways:
//!
//! - **`slew`** — `C` along Poisson-driven volume traces (stationary,
//!   720-block ramps, and INSTANTANEOUS steps, the worst case a linear ramp
//!   cannot show), with the shipped integer-truncated SMA
//!   (`tx_count_sum / 720`, `blockchain.cpp:2115`) and the exact rational
//!   SMA (`tx_count_sum` against `baseline·720`) side by side. The integer
//!   operand is a hidden quantizer: one tick is `1/V` of `M_r`, 2 % at the
//!   baseline, 2.5 % at the low rail — in one block. Under the lookback a
//!   tick is a grace cost, not a bounce; under any pad it is a bounce
//!   unless the pad exceeds it. Both readings are reported: the lookback's
//!   grace (`grace_bp_max`, `grace_bp_mean`) and, as the road not taken,
//!   the bounce count a fixed pad of each candidate size would have
//!   suffered against `check_fee`'s inherited 2 % buffer.
//! - **`feedback`** — FL-C7's fee↔volume loop iterated through the new
//!   served map (paid standard fee `4·F`), both SMA resolutions, so the
//!   round can say whether putting the floor in the loop changes the
//!   convergence §4.5 recorded on raw `C`. The paid fee is unrounded here on
//!   purpose: `round_money_up_2` is a fee-uniformity quantizer of the same
//!   refuted class as the snap and §11.2 removes it from the served path.
//!
//! §1.9 discipline: `C` comes from the owners through
//! [`fee_ladder::correction_factor_ratio`]; the floor formula is written
//! here ONLY because its owner does not exist yet — §11.6 names the
//! production function that replaces [`floor_rate`] when it lands, and
//! this pin is what that function is tested against.

use core::fmt::Write as _;
use std::collections::VecDeque;

use serde::Serialize;
use shekyl_economics::params::TX_VOLUME_WINDOW;
use shekyl_economics::{base_block_reward, EconomicParams, TxVolume, BLOCKS_PER_YEAR};

use crate::fee_ladder::{
    advance_traced_state, age_state, correction_factor_ratio, AgeState, Rng, FULL_REWARD_ZONE_V5,
    REF_TX_WEIGHT,
};

const VOLUME_WINDOW: usize = TX_VOLUME_WINDOW as usize;

/// FL-R23's lookback depth as re-derived at review A-1: the hot-session gap
/// (0–2 blocks) + the network height spread at relay (2) + one block of
/// slack. The identity the predicate delivers is per receiving node — a
/// quote at `h` is admitted by identity at every node whose tip is in
/// `[h, h+G]`.
pub const LOOKBACK_G: usize = 5;
/// FL-E4's sweep: the first draft's `G` = 3, the re-derived 5, and the
/// point between, so the grace curve — not the derivation alone — is on
/// record.
pub const LOOKBACK_SWEEP: [usize; 3] = [3, 4, 5];

/// Gaps at which the road-not-taken pad race is scored, in blocks — the
/// same span the lookback covers.
pub const GAPS: [usize; 3] = [1, 2, 3];

/// The road not taken (§11.3): fixed additive pads that were considered
/// before FL-R23. Reported so the record shows what each would have cost
/// in bounces against the inherited buffer; not a design input.
pub const PAD_CANDIDATES_BP: [u64; 4] = [50, 100, 200, 300];
/// `check_fee`'s inherited buffer, `fee ≥ needed − needed/50`, which the
/// pad race is scored against and which FL-R23 deletes.
pub const Q_BUFFER_BP: u64 = 200;

/// The largest rise of `F` between quote and admission a fixed pad `p`
/// still admits under the inherited buffer: `(1+p)/(1−q) − 1`, basis
/// points, floored. `p = 50 → 255`, `100 → 306`, `200 → 408`, `300 → 510`.
pub const fn pad_admission_margin_bp(pad_bp: u64) -> u64 {
    (10_000 + pad_bp) * 10_000 / (10_000 - Q_BUFFER_BP) - 10_000
}

/// FL-E1's convergence bar: tail amplitude of the paid fee, basis points.
/// One tick of the integer SMA at the baseline is 200 bp; a loop whose
/// tail wobbles by less than a quarter of that is at its fixed point for
/// every purpose a user can observe.
pub const CONVERGED_AMPLITUDE_BP: u64 = 50;

/// Lookback grace over each `G` in [`LOOKBACK_SWEEP`]: `(max, mean)` of
/// `F(t)/min_{k≤G} F(t−k) − 1` in basis points, ceiling ratio.
fn grace_sweep(floors: &[u128]) -> ([u64; 3], [u64; 3]) {
    let mut maxes = [0u64; 3];
    let mut means = [0u64; 3];
    for (i, &g) in LOOKBACK_SWEEP.iter().enumerate() {
        let (mut mx, mut sum, mut n) = (0u64, 0u128, 0u64);
        for t in g..floors.len() {
            let lo = floors[t - g..=t]
                .iter()
                .copied()
                .min()
                .expect("non-empty lookback");
            let bp = ((floors[t] * 10_000).div_ceil(lo.max(1)) - 10_000) as u64;
            mx = mx.max(bp);
            sum += u128::from(bp);
            n += 1;
        }
        maxes[i] = mx;
        means[i] = (sum / u128::from(n.max(1))) as u64;
    }
    (maxes, means)
}

/// `F = R·C·w_ref/M²` × `SCALE`, with `M` floored at the penalty-free zone
/// as the shipped floor does. Single division. The `SCALE` factor is kept
/// in the numerator so per-block RATIOS are measured on a quantity whose
/// resolution is far below one basis point — the daemon's integer
/// atomic/byte (single digits at large `M`) would otherwise masquerade as
/// slew.
fn floor_rate(base_reward: u64, median: u64, c_scaled: u64) -> u128 {
    let m = u128::from(median.max(FULL_REWARD_ZONE_V5));
    u128::from(base_reward) * u128::from(REF_TX_WEIGHT) * u128::from(c_scaled) / (m * m)
}

/// Which SMA the arm feeds `C` with.
#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
pub enum Sma {
    /// `tx_count_sum / 720`, truncated — what `get_tx_volume_avg` returned
    /// before FL-R24 (PR A).
    Integer,
    /// `tx_count_sum : baseline·720` — the same quotient, unrounded.
    Exact,
}

impl Sma {
    fn label(self) -> &'static str {
        match self {
            Sma::Integer => "integer",
            Sma::Exact => "exact",
        }
    }
}

/// `C` for a window sum under the arm's SMA. `sum` is in units of
/// `1/unit` transactions (the slew set passes whole transactions,
/// `unit = 1`; the feedback loop carries milli-transactions, `unit =
/// 1000`, so the exact arm keeps the fraction the integer arm truncates).
fn c_for(sum: u64, unit: u64, sma: Sma, ag: u64, height: u64, params: &EconomicParams) -> u64 {
    let window = VOLUME_WINDOW as u64;
    match sma {
        Sma::Integer => correction_factor_ratio(
            TxVolume::per_block(sum / (unit * window)),
            ag,
            height,
            params,
        ),
        Sma::Exact => {
            correction_factor_ratio(TxVolume::window(sum, unit * window), ag, height, params)
        }
    }
    .c_scaled
}

/// Volume traces for the slew set: `(label, mean_start, mean_end, step)`.
/// `step = true` switches the mean instantaneously at [`STEP_AT`]; `false`
/// ramps it linearly over one window (the dwell set's shape). `v = 40` is
/// the low rail's edge, where one integer tick is largest (2.5 %) and
/// `M_r` first unclamps; `v = 500` is the sweep's top.
pub const SLEW_SCENARIOS: &[(&str, f64, f64, bool)] = &[
    ("stationary-v40", 40.0, 40.0, false),
    ("stationary-v50", 50.0, 50.0, false),
    ("stationary-v500", 500.0, 500.0, false),
    ("ramp-v50-to-v500", 50.0, 500.0, false),
    ("ramp-v500-to-v50", 500.0, 50.0, false),
    ("step-v40-to-v500", 40.0, 500.0, true),
    ("step-v50-to-v500", 50.0, 500.0, true),
    ("step-v500-to-v50", 500.0, 50.0, true),
];
const STEP_AT: u64 = 2_000;
const SLEW_BLOCKS: u64 = 20_000;

#[derive(Serialize, Clone)]
pub struct SlewResult {
    pub scenario: &'static str,
    pub age_years: u64,
    pub sma: Sma,
    /// `max_t F(t+k)/F(t) − 1` for `k ∈ GAPS`, basis points (rise), ceiling
    /// ratio so a rise is never understated.
    pub rise_bp_max: [i64; 3],
    /// `min_t F(t+k)/F(t) − 1` for `k ∈ GAPS`, basis points (fall).
    pub fall_bp_max: [i64; 3],
    /// FL-R23's grace, `F(t)/min_{k≤G} F(t−k) − 1` in basis points — the
    /// most an admitted transaction may sit below the current floor, and
    /// the mean over the trace — for each `G` in [`LOOKBACK_SWEEP`]
    /// (FL-E4).
    pub grace_bp_max: [u64; 3],
    pub grace_bp_mean: [u64; 3],
    /// Road not taken, per [`PAD_CANDIDATES_BP`]: blocks `t` from which
    /// some `k ∈ GAPS` rise exceeds that pad's margin under the inherited
    /// buffer — a quote at `t` that would have bounced at `t+k`.
    pub bounce_blocks_by_pad: [u64; 4],
    pub blocks_measured: u64,
    /// Blocks on which `C` changed at all (the integer arm's tick count;
    /// the exact arm moves nearly every block by construction).
    pub c_changes: u64,
    pub c_min: u64,
    pub c_max: u64,
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
fn slew_scenario(
    scenario: &'static str,
    mean_start: f64,
    mean_end: f64,
    step: bool,
    st: AgeState,
    sma: Sma,
    params: &EconomicParams,
) -> SlewResult {
    // Same seed as the dwell set so the traces are comparable across
    // instruments; both SMA arms of one scenario see the IDENTICAL block
    // sequence, which is the point of running them side by side.
    let mut rng = Rng(0x5EED_F1FE_ED1E_5EED);
    let mut window: VecDeque<u64> = VecDeque::with_capacity(VOLUME_WINDOW);
    let mut sum: u64 = 0;
    for _ in 0..VOLUME_WINDOW {
        let n = rng.poisson(mean_start);
        sum += n;
        window.push_back(n);
    }
    let mut ag = st.ag;
    let mut floors: Vec<u128> = Vec::with_capacity(SLEW_BLOCKS as usize);
    let (mut c_min, mut c_max, mut c_changes) = (u64::MAX, 0u64, 0u64);
    let mut last_c: Option<u64> = None;
    for t in 0..SLEW_BLOCKS {
        let mean = if step {
            if t < STEP_AT {
                mean_start
            } else {
                mean_end
            }
        } else if (mean_end - mean_start).abs() < f64::EPSILON {
            mean_start
        } else {
            mean_start + (mean_end - mean_start) * (t as f64 / VOLUME_WINDOW as f64).min(1.0)
        };
        let n = rng.poisson(mean);
        sum += n;
        window.push_back(n);
        sum -= window.pop_front().expect("window warm");

        let height = st.height + t;
        let base = base_block_reward(ag, params).expect("base along trace");
        let c = c_for(sum, 1, sma, ag, height, params);
        floors.push(floor_rate(base, FULL_REWARD_ZONE_V5, c));
        c_min = c_min.min(c);
        c_max = c_max.max(c);
        if last_c.is_some_and(|p| p != c) {
            c_changes += 1;
        }
        last_c = Some(c);
        // Emission advances on the SHIPPED consensus operand in both arms:
        // the SMA resolution under test is the FLOOR's, and whether the
        // reward's operand follows is §11.4's separate question.
        ag = advance_traced_state(ag, sum / VOLUME_WINDOW as u64, params);
    }

    let mut rise = [i64::MIN; 3];
    let mut fall = [i64::MAX; 3];
    let mut bounce = [0u64; 4];
    let n = floors.len() - GAPS[GAPS.len() - 1];
    for t in 0..n {
        let mut worst = i64::MIN;
        for (i, &k) in GAPS.iter().enumerate() {
            let bp = (floors[t + k] * 10_000).div_ceil(floors[t].max(1)) as i64 - 10_000;
            rise[i] = rise[i].max(bp);
            fall[i] = fall[i].min(bp);
            worst = worst.max(bp);
        }
        for (i, &pad) in PAD_CANDIDATES_BP.iter().enumerate() {
            if worst > pad_admission_margin_bp(pad) as i64 {
                bounce[i] += 1;
            }
        }
    }
    let (grace_max, grace_mean) = grace_sweep(&floors);
    SlewResult {
        scenario,
        age_years: st.height / BLOCKS_PER_YEAR,
        sma,
        rise_bp_max: rise,
        fall_bp_max: fall,
        grace_bp_max: grace_max,
        grace_bp_mean: grace_mean,
        bounce_blocks_by_pad: bounce,
        blocks_measured: n as u64,
        c_changes,
        c_min,
        c_max,
    }
}

#[derive(Serialize, Clone)]
pub struct FloorFeedbackResult {
    pub age_years: u64,
    pub median: u64,
    pub elasticity_milli: u64,
    pub demand_scale: u64,
    pub start_volume: u64,
    pub sma: Sma,
    /// Paid-fee range over the 3 000-block tail and its amplitude.
    pub fee_tail_min: u128,
    pub fee_tail_max: u128,
    pub tail_amplitude_bp: u64,
    pub tail_transitions: u64,
    pub converged: bool,
    /// FL-R23 along the deterministic trace: the lookback grace, max and
    /// mean in basis points, per `G` in [`LOOKBACK_SWEEP`].
    pub grace_bp_max: [u64; 3],
    pub grace_bp_mean: [u64; 3],
}

/// FL-C7's loop under the FL-R20 served map. Deterministic demand
/// `D·(fee/f_ref)^−ε` through the real 720-block window; `f_ref` is the
/// paid fee at the trace's start state.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn floor_feedback_scenario(
    eps_milli: u64,
    demand_scale: u64,
    start_volume: u64,
    st: AgeState,
    median: u64,
    sma: Sma,
    params: &EconomicParams,
) -> FloorFeedbackResult {
    const MILLI: u64 = 1_000;
    let paid_at = |sum_milli: u64, ag: u64, height: u64| -> (u128, u128) {
        let base = base_block_reward(ag, params).expect("base along trace");
        let c = c_for(sum_milli, MILLI, sma, ag, height, params);
        let f = floor_rate(base, median, c);
        // Standard rung = 4·F, paid exactly (FL-R22).
        (4 * f, f)
    };
    let f_ref = paid_at(
        start_volume * MILLI * VOLUME_WINDOW as u64,
        st.ag,
        st.height,
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
    let mut floors: Vec<u128> = Vec::with_capacity(blocks as usize);
    let (mut fee_min, mut fee_max) = (u128::MAX, 0u128);
    let mut tail_transitions = 0u64;
    let mut last_tail_fee: Option<u128> = None;
    let mut ag = st.ag;
    for t in 0..blocks {
        let sum_milli = (sum.max(0.0) * MILLI as f64) as u64;
        let (fee, f) = paid_at(sum_milli, ag, st.height + t);
        floors.push(f);
        ag = advance_traced_state(ag, sum_milli / (MILLI * VOLUME_WINDOW as u64), params);
        let demand = (demand_scale as f64) * (fee as f64 / f_ref.max(1) as f64).powf(-eps);
        let demand = demand.max(0.0);
        sum += demand;
        window.push_back(demand);
        sum -= window.pop_front().expect("window warm");
        if t >= blocks - tail {
            fee_min = fee_min.min(fee);
            fee_max = fee_max.max(fee);
            if last_tail_fee.is_some_and(|p| p != fee) {
                tail_transitions += 1;
            }
            last_tail_fee = Some(fee);
        }
    }
    let (grace_max, grace_mean) = grace_sweep(&floors);
    let amplitude_bp = (fee_max * 10_000 / fee_min.max(1) - 10_000) as u64;
    FloorFeedbackResult {
        age_years: st.height / BLOCKS_PER_YEAR,
        median,
        elasticity_milli: eps_milli,
        demand_scale,
        start_volume,
        sma,
        fee_tail_min: fee_min,
        fee_tail_max: fee_max,
        tail_amplitude_bp: amplitude_bp,
        tail_transitions,
        converged: amplitude_bp <= CONVERGED_AMPLITUDE_BP,
        grace_bp_max: grace_max,
        grace_bp_mean: grace_mean,
    }
}

#[derive(Serialize)]
pub struct FeeFloorReport {
    pub lookback_g: usize,
    pub lookback_sweep: [usize; 3],
    pub pad_candidates_bp: [u64; 4],
    pub q_buffer_bp: u64,
    pub pad_admission_margin_bp: [u64; 4],
    pub converged_amplitude_bp: u64,
    pub slew: Vec<SlewResult>,
    pub feedback: Vec<FloorFeedbackResult>,
}

/// Run the §11 set: the §1.8 age grid × [`SLEW_SCENARIOS`] × both SMAs,
/// and FL-C7's grid (medians, ε, demand scales, displaced starts) × both
/// SMAs.
pub fn report() -> FeeFloorReport {
    let params = EconomicParams::default();
    let zone = FULL_REWARD_ZONE_V5;
    let ages: [u64; 5] = [0, 1, 4, 12, 30];
    let states: Vec<AgeState> = ages.iter().map(|&a| age_state(a, &params)).collect();

    let mut slew = Vec::new();
    for &st in &states {
        for &sma in &[Sma::Integer, Sma::Exact] {
            for &(label, m0, m1, step) in SLEW_SCENARIOS {
                slew.push(slew_scenario(label, m0, m1, step, st, sma, &params));
            }
        }
    }

    let mut feedback = Vec::new();
    for &st in &states {
        for &median in &[zone, 3 * zone, 10 * zone, 50 * zone] {
            for &sma in &[Sma::Integer, Sma::Exact] {
                for eps in [0u64, 500, 1000, 2000, 3000] {
                    for demand_scale in [50u64, 100, 400] {
                        feedback.push(floor_feedback_scenario(
                            eps,
                            demand_scale,
                            demand_scale,
                            st,
                            median,
                            sma,
                            &params,
                        ));
                        // A displaced start probes convergence back to the
                        // fixed point, not just persistence at it.
                        feedback.push(floor_feedback_scenario(
                            eps,
                            demand_scale,
                            8 * demand_scale.min(1_250),
                            st,
                            median,
                            sma,
                            &params,
                        ));
                    }
                }
            }
        }
    }
    FeeFloorReport {
        lookback_g: LOOKBACK_G,
        lookback_sweep: LOOKBACK_SWEEP,
        pad_candidates_bp: PAD_CANDIDATES_BP,
        q_buffer_bp: Q_BUFFER_BP,
        pad_admission_margin_bp: PAD_CANDIDATES_BP.map(pad_admission_margin_bp),
        converged_amplitude_bp: CONVERGED_AMPLITUDE_BP,
        slew,
        feedback,
    }
}

pub fn render_summary(r: &FeeFloorReport, out: &mut String) {
    let _ = writeln!(
        out,
        "fee-floor: lookback_g={} lookback_sweep={:?} gaps={:?} pad_candidates_bp={:?} q_bp={} pad_admission_margin_bp={:?} converged_amplitude_bp={}",
        r.lookback_g,
        r.lookback_sweep,
        GAPS,
        r.pad_candidates_bp,
        r.q_buffer_bp,
        r.pad_admission_margin_bp,
        r.converged_amplitude_bp
    );
    for s in &r.slew {
        let _ = writeln!(
            out,
            "fee-floor: slew {} age={} sma={} rise_bp_max={:?} fall_bp_max={:?} grace_bp_max[G=3,4,5]={:?} grace_bp_mean[G=3,4,5]={:?} bounce_blocks_by_pad={:?}/{} c_changes={} c_range=[{},{}]",
            s.scenario,
            s.age_years,
            s.sma.label(),
            s.rise_bp_max,
            s.fall_bp_max,
            s.grace_bp_max,
            s.grace_bp_mean,
            s.bounce_blocks_by_pad,
            s.blocks_measured,
            s.c_changes,
            s.c_min,
            s.c_max
        );
    }
    // FL-E2 / FL-E3 roll-up per arm.
    for &sma in &[Sma::Integer, Sma::Exact] {
        let cells: Vec<&SlewResult> = r.slew.iter().filter(|s| s.sma == sma).collect();
        let worst_rise1 = cells.iter().map(|s| s.rise_bp_max[0]).max().unwrap_or(0);
        let worst_grace: [u64; 3] =
            core::array::from_fn(|i| cells.iter().map(|s| s.grace_bp_max[i]).max().unwrap_or(0));
        let mean_grace: [u64; 3] = core::array::from_fn(|i| {
            if cells.is_empty() {
                0
            } else {
                cells.iter().map(|s| s.grace_bp_mean[i]).sum::<u64>() / cells.len() as u64
            }
        });
        let stationary_mean: [u64; 3] = core::array::from_fn(|i| {
            cells
                .iter()
                .filter(|s| s.scenario.starts_with("stationary"))
                .map(|s| s.grace_bp_mean[i])
                .max()
                .unwrap_or(0)
        });
        let bounce: [u64; 4] = PAD_CANDIDATES_BP
            .iter()
            .enumerate()
            .map(|(i, _)| cells.iter().map(|s| s.bounce_blocks_by_pad[i]).sum::<u64>())
            .collect::<Vec<_>>()
            .try_into()
            .expect("four candidates");
        let _ = writeln!(
            out,
            "fee-floor: FL-E2/E3/E4 sma={} cells={} worst_1block_rise_bp={} grace_bp_max[G=3,4,5]={:?} grace_bp_mean_of_means[G=3,4,5]={:?} stationary_grace_bp_mean_max[G=3,4,5]={:?} pad_bounce_blocks_by_pad={:?}",
            sma.label(),
            cells.len(),
            worst_rise1,
            worst_grace,
            mean_grace,
            stationary_mean,
            bounce
        );
    }
    // FL-E1: the feedback grid, both arms.
    for &sma in &[Sma::Integer, Sma::Exact] {
        let cells: Vec<&FloorFeedbackResult> = r.feedback.iter().filter(|f| f.sma == sma).collect();
        let not_converged = cells.iter().filter(|f| !f.converged).count();
        let worst_amp = cells.iter().map(|f| f.tail_amplitude_bp).max().unwrap_or(0);
        let worst_grace: [u64; 3] =
            core::array::from_fn(|i| cells.iter().map(|f| f.grace_bp_max[i]).max().unwrap_or(0));
        let _ = writeln!(
            out,
            "fee-floor: FL-E1 sma={} cells={} not_converged={} worst_tail_amplitude_bp={} grace_bp_max[G=3,4,5]={:?}",
            sma.label(),
            cells.len(),
            not_converged,
            worst_amp,
            worst_grace
        );
        for f in cells.iter().filter(|f| !f.converged) {
            let _ = writeln!(
                out,
                "fee-floor: FL-E1 NOT-CONVERGED age={} M={} sma={} eps={} D={} start={} tail_amplitude_bp={} tail_transitions={} fee_tail=[{},{}]",
                f.age_years,
                f.median,
                f.sma.label(),
                f.elasticity_milli,
                f.demand_scale,
                f.start_volume,
                f.tail_amplitude_bp,
                f.tail_transitions,
                f.fee_tail_min,
                f.fee_tail_max
            );
        }
    }
}

pub fn render_json(r: &FeeFloorReport) -> String {
    serde_json::to_string_pretty(r).expect("report serializes")
}
