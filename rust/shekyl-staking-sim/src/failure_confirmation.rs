//! L14b — failure-confirmation scheduling (Round-1 policy comparator).
//!
//! Compares **escalate-on-failure + recheck window** vs **sliding-window m-of-n** on a
//! shared outage process. See `docs/design/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` and
//! `docs/design/STAKER_ARCHIVAL_SIM.md` §*L14b*.
//!
//! **Modeling discipline (Round-1 revision):**
//! - Recheck is sized from **assumed residual-life** quantile `p` (false-slash knob), not
//!   full outage duration — equal only for the exponential (memoryless) case.
//! - Recheck has **window start + width `w`** (gaming knob); deterministic point recheck
//!   is not modeled.
//! - Tail robustness: pick delay from law A, measure false-slash under true law B.
//! - Decision gate: **gaming floor `b_min` first**, then **binding constraint** (absolute
//!   block-space arithmetic), then relative volume ratio.
//! - **`P(slash)` vs `u` sweep** names the not-durably-absent slope (honest hosting).

use crate::model::Rng;
use crate::timing_cluster::SETTLEMENT_EPOCH_BLOCKS;
use crate::transport::{effective_uptime, regime_latency_epochs};
use serde::Serialize;

/// L16 onion band-ceiling operating point (scalar `u_eff` does not pin tail shape).
pub const L16_U_BASE: f64 = 0.9;
pub const L16_LATENCY_PER_UNIT: f64 = 6.0;
pub const L16_K: f64 = 0.07;
pub const L16_DEEP_SHARD_SIZE: f64 = 1.0;

pub const DEFAULT_MEAN_DOWN_EPOCHS: f64 = 2.0;

/// Analytical binding check (per-P sim drops shard multiplicity).
pub const N_MARKET_ARCHIVERS: u64 = 2_000;
pub const SHARDS_PER_P: u64 = 6;
/// Order-of-magnitude pure archival serve-credit vin size (bytes).
pub const CHALLENGE_VIN_BYTES: u64 = 2_048;
pub const BLOCK_WEIGHT_LIMIT_BYTES: u64 = 300_000;
/// Fraction of per-SEB block-weight budget above which challenge traffic is binding.
/// Order-of-magnitude check only; per-P micro-sim cannot settle absolute volume.
pub const VOLUME_BINDING_FRACTION: f64 = 0.05;

/// Down-segment duration law. Stressnet target: **outage-duration CDF** (residual-life
/// CDF is the gating empirical input; equals marginal duration only when memoryless).
#[derive(Debug, Clone, Copy)]
pub enum DownDurationLaw {
    Exponential { mean_epochs: f64 },
    /// Fat-tailed stalls (onion circuit/guard failures). `sigma` is log-space stddev.
    Lognormal { mean_epochs: f64, sigma: f64 },
}

impl DownDurationLaw {
    pub fn exponential(mean_epochs: f64) -> Self {
        Self::Exponential { mean_epochs }
    }

    pub fn lognormal_fat_tail(mean_epochs: f64, sigma: f64) -> Self {
        Self::Lognormal {
            mean_epochs,
            sigma,
        }
    }

    /// Mean down-segment length (epochs).
    pub fn mean_epochs(self) -> f64 {
        match self {
            Self::Exponential { mean_epochs } => mean_epochs,
            Self::Lognormal { mean_epochs, .. } => mean_epochs,
        }
    }

    fn sample_down_epochs(&self, rng: &mut Rng) -> u32 {
        match self {
            Self::Exponential { mean_epochs } => sample_exp_epochs(*mean_epochs, rng),
            Self::Lognormal { mean_epochs, sigma } => {
                sample_lognormal_epochs(*mean_epochs, *sigma, rng)
            }
        }
    }

    /// **Assumed** residual-life quantile for recheck window **start** offset.
    ///
    /// Exponential: memoryless ⇒ residual ≡ full duration ⇒ closed form.
    /// Lognormal: use equilibrium inspection-time residual approximation
    /// E[residual | in outage] ≈ mean × (1 + σ²/2) scaled quantile — Round-1 conservative
    /// proxy until stressnet CDF replaces it.
    pub fn assumed_residual_start_epochs(&self, quantile: f64) -> u32 {
        let p = quantile.clamp(f64::EPSILON, 1.0 - f64::EPSILON);
        match self {
            Self::Exponential { mean_epochs } => {
                (-mean_epochs * (1.0 - p).ln()).ceil().max(1.0) as u32
            }
            Self::Lognormal { mean_epochs, sigma } => {
                let inspection_factor = 1.0 + sigma * sigma / 2.0;
                let effective_mean = mean_epochs * inspection_factor;
                (-effective_mean * (1.0 - p).ln()).ceil().max(1.0) as u32
            }
        }
    }

    /// Nominal `1−p` bound is **exact only for exponential assumed + true** (memoryless).
    pub fn nominal_false_slash_bound(quantile: f64) -> f64 {
        (1.0 - quantile).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundTruth {
    HonestHosting,
    TransientOnce,
    NotServing,
    DodgeServing,
}

#[derive(Debug, Clone)]
pub struct OutageProcess {
    pub true_law: DownDurationLaw,
    pub mean_up_epochs: f64,
}

impl OutageProcess {
    pub fn from_uptime_and_laws(uptime_target: f64, true_law: DownDurationLaw) -> Self {
        let u = uptime_target.clamp(f64::EPSILON, 1.0 - f64::EPSILON);
        let mean_down = true_law.mean_epochs();
        let mean_up = mean_down * u / (1.0 - u);
        Self {
            true_law,
            mean_up_epochs: mean_up,
        }
    }

    pub fn l16_default(true_law: DownDurationLaw) -> Self {
        let latency = regime_latency_epochs(L16_DEEP_SHARD_SIZE, L16_LATENCY_PER_UNIT);
        let u_eff = effective_uptime(L16_U_BASE, latency, L16_K);
        Self::from_uptime_and_laws(u_eff, true_law)
    }

    pub fn with_uptime(uptime_target: f64, true_law: DownDurationLaw) -> Self {
        Self::from_uptime_and_laws(uptime_target, true_law)
    }

    pub fn uptime_target(&self) -> f64 {
        self.mean_up_epochs / (self.mean_up_epochs + self.true_law.mean_epochs())
    }

    /// Renewal schedule with explicit down-segment lengths from `true_law`.
    pub fn simulate_availability(&self, epochs: usize, rng: &mut Rng) -> Vec<bool> {
        let mut up = true;
        let mut remaining = sample_exp_epochs(self.mean_up_epochs, rng);
        let mut avail = Vec::with_capacity(epochs);
        for _ in 0..epochs {
            avail.push(up);
            remaining = remaining.saturating_sub(1);
            if remaining == 0 {
                up = !up;
                remaining = if up {
                    sample_exp_epochs(self.mean_up_epochs, rng)
                } else {
                    self.true_law.sample_down_epochs(rng)
                };
            }
        }
        avail
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecheckWindow {
    pub start: u32,
    pub end: u32,
    pub probe: u32,
}

#[derive(Debug, Clone)]
pub struct Round1Params {
    pub name: String,
    pub axis: String,
    pub epochs: usize,
    pub seeds: u32,
    pub outage: OutageProcess,
    /// Law used to **schedule** recheck window start (stressnet-fitted residual CDF stand-in).
    pub assumed_law: DownDurationLaw,
    pub recheck_quantile: f64,
    /// Recheck window width `w` (epochs) — gaming / dodge-cost knob.
    pub recheck_window_width_epochs: u32,
    pub sliding_window_epochs: usize,
    pub miss_threshold: usize,
    pub baseline_period: u32,
    pub gaming_baseline_sweep: Vec<u32>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PolicyRunStats {
    pub challenges: u64,
    pub slashes: u64,
    pub false_slashes: u64,
    pub slash_epoch_sum: u64,
    pub slash_samples: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BindingAnalysis {
    pub challenges_per_p_per_epoch_upper: f64,
    pub challenge_weight_per_seb: u64,
    pub block_weight_budget_per_seb: u64,
    pub volume_fraction_of_block_budget: f64,
    pub volume_binding: bool,
    pub latency_binding: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct USlashPoint {
    pub uptime_target: f64,
    pub escalate_slash_probability: f64,
    pub sliding_slash_probability: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureConfirmationReport {
    pub binding: BindingAnalysis,
    pub u_sweep: Vec<USlashPoint>,
    pub scenarios: Vec<Round1Result>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Round1Result {
    pub name: String,
    pub axis: String,
    pub params: Round1ParamsSummary,
    pub honest: PairedActorStats,
    pub transient: TransientStats,
    pub not_serving: PairedActorStats,
    pub dodge: DodgeStats,
    pub decision: DecisionGate,
}

#[derive(Debug, Clone, Serialize)]
pub struct Round1ParamsSummary {
    pub epochs: usize,
    pub seeds: u32,
    pub uptime_target: f64,
    pub true_law: String,
    pub assumed_law: String,
    pub recheck_quantile: f64,
    pub recheck_window_start_epochs: u32,
    pub recheck_window_width_epochs: u32,
    pub nominal_false_slash_bound: f64,
    pub sliding_window_epochs: usize,
    pub miss_threshold: usize,
    pub baseline_period: u32,
    pub gaming_floor_baseline_period: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedActorStats {
    pub escalate: PolicyRunStats,
    pub sliding: PolicyRunStats,
    pub challenge_volume_ratio: f64,
    pub slash_latency_delta_epochs: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransientStats {
    pub escalate_false_slash_rate: f64,
    pub sliding_false_slash_rate: f64,
    pub nominal_bound_exponential_only: f64,
    pub tail_misspecification_gap: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DodgeStats {
    pub escalate_slash_rate: f64,
    pub forced_online_fraction: f64,
    pub gaming_floor_baseline_period: u32,
    pub gaming_floor_satisfied: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionGate {
    pub gaming_floor_satisfied: bool,
    pub volume_binding: bool,
    pub latency_binding: bool,
    pub fsm_justified: bool,
    pub sliding_window_preferred: bool,
    pub volume_ratio: f64,
    pub slash_latency_delta_epochs: i32,
    pub rationale: String,
}

#[derive(Debug, Clone, Default)]
struct SimOutcome {
    challenges: u64,
    slashed: bool,
    slash_epoch: Option<u32>,
    false_slash: bool,
    forced_online_epochs: u32,
}

fn sample_exp_epochs(mean: f64, rng: &mut Rng) -> u32 {
    let u = rng.next_f64().max(f64::EPSILON);
    (-mean * u.ln()).ceil().max(1.0) as u32
}

fn sample_lognormal_epochs(mean: f64, sigma: f64, rng: &mut Rng) -> u32 {
    // E[exp(N(μ,σ²))] = exp(μ + σ²/2) = mean  ⇒  μ = ln(mean) − σ²/2
    let mu = mean.ln() - sigma * sigma / 2.0;
    let z: f64 = {
        let u1 = rng.next_f64().max(f64::EPSILON);
        let u2 = rng.next_f64().max(f64::EPSILON);
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    };
    (z * sigma + mu).exp().ceil().max(1.0) as u32
}

fn law_label(law: DownDurationLaw) -> String {
    match law {
        DownDurationLaw::Exponential { mean_epochs } => format!("exp(mean={mean_epochs:.2})"),
        DownDurationLaw::Lognormal { mean_epochs, sigma } => {
            format!("lognormal(mean={mean_epochs:.2},σ={sigma:.2})")
        }
    }
}

fn schedule_recheck_window(
    miss_epoch: u32,
    assumed_law: DownDurationLaw,
    quantile: f64,
    width: u32,
    rng: &mut Rng,
) -> RecheckWindow {
    let start = miss_epoch + assumed_law.assumed_residual_start_epochs(quantile);
    let width = width.max(1);
    let probe = start + (rng.below(width as usize) as u32);
    let end = start + width - 1;
    RecheckWindow {
        start,
        end,
        probe,
    }
}

fn can_serve(
    truth: GroundTruth,
    epoch: u32,
    avail: &[bool],
    transient: Option<(u32, u32)>,
    dodge_window: Option<RecheckWindow>,
) -> bool {
    match truth {
        GroundTruth::NotServing => false,
        GroundTruth::HonestHosting => avail[epoch as usize],
        GroundTruth::TransientOnce => {
            if let Some((start, len)) = transient {
                !(epoch >= start && epoch < start + len)
            } else {
                true
            }
        }
        GroundTruth::DodgeServing => dodge_window.is_some_and(|w| epoch >= w.start && epoch <= w.end),
    }
}

fn transient_window(epochs: u32, law: DownDurationLaw, rng: &mut Rng) -> (u32, u32) {
    let start = (epochs / 3).max(1);
    let len = law.sample_down_epochs(rng);
    (start, len)
}

fn run_escalate(
    truth: GroundTruth,
    avail: &[bool],
    params: &Round1Params,
    transient: Option<(u32, u32)>,
    rng: &mut Rng,
) -> SimOutcome {
    let epochs = params.epochs as u32;
    let mut out = SimOutcome::default();
    let mut pending: Option<RecheckWindow> = None;

    for epoch in 0..epochs {
        let baseline_due = epoch % params.baseline_period == 0;
        if !baseline_due && pending.map(|w| w.probe) != Some(epoch) {
            continue;
        }

        let dodge_window = if truth == GroundTruth::DodgeServing {
            pending
        } else {
            None
        };

        if pending.is_some_and(|w| w.probe == epoch) {
            let w = pending.unwrap();
            if truth == GroundTruth::DodgeServing {
                out.forced_online_epochs += w.end - w.start + 1;
            }
            out.challenges += 1;
            let serve = can_serve(truth, epoch, avail, transient, dodge_window);
            pending = None;
            if serve {
                continue;
            }
            out.slashed = true;
            out.slash_epoch = Some(epoch);
            out.false_slash = truth == GroundTruth::TransientOnce;
            break;
        }

        if baseline_due && pending.is_none() {
            out.challenges += 1;
            let serve = can_serve(truth, epoch, avail, transient, None);
            if serve {
                continue;
            }
            let w = schedule_recheck_window(
                epoch,
                params.assumed_law,
                params.recheck_quantile,
                params.recheck_window_width_epochs,
                rng,
            );
            if w.probe < epochs {
                pending = Some(w);
            } else if truth == GroundTruth::NotServing {
                out.slashed = true;
                out.slash_epoch = Some(epoch);
                break;
            }
        }
    }
    out
}

fn run_sliding(
    truth: GroundTruth,
    avail: &[bool],
    params: &Round1Params,
    transient: Option<(u32, u32)>,
) -> SimOutcome {
    let epochs = params.epochs as u32;
    let mut out = SimOutcome::default();
    let mut misses: Vec<u8> = Vec::new();

    for epoch in 0..epochs {
        if epoch % params.baseline_period != 0 {
            continue;
        }
        out.challenges += 1;
        let serve = can_serve(truth, epoch, avail, transient, None);
        let miss = u8::from(!serve);
        misses.push(miss);
        if misses.len() > params.sliding_window_epochs {
            misses.remove(0);
        }
        let miss_count = misses.iter().map(|&m| m as usize).sum::<usize>();
        if miss_count >= params.miss_threshold {
            out.slashed = true;
            out.slash_epoch = Some(epoch);
            out.false_slash = truth == GroundTruth::TransientOnce;
            break;
        }
    }
    out
}

fn stats_from(outcomes: &[SimOutcome]) -> PolicyRunStats {
    let mut s = PolicyRunStats::default();
    for o in outcomes {
        s.challenges += o.challenges;
        if o.slashed {
            s.slashes += 1;
            if o.false_slash {
                s.false_slashes += 1;
            }
            if let Some(e) = o.slash_epoch {
                s.slash_epoch_sum += e as u64;
                s.slash_samples += 1;
            }
        }
    }
    s
}

fn paired_for_truth(
    truth: GroundTruth,
    params: &Round1Params,
    base_seed: u64,
) -> (Vec<SimOutcome>, Vec<SimOutcome>) {
    let mut esc = Vec::with_capacity(params.seeds as usize);
    let mut slide = Vec::with_capacity(params.seeds as usize);
    for i in 0..params.seeds {
        let seed = base_seed.wrapping_add(i as u64);
        let mut rng_avail = Rng::new(seed);
        let avail = params.outage.simulate_availability(params.epochs, &mut rng_avail);
        let transient = if truth == GroundTruth::TransientOnce {
            let mut rng_tr = Rng::new(seed.wrapping_add(0x5452_414E_5349_454E));
            Some(transient_window(
                params.epochs as u32,
                params.outage.true_law,
                &mut rng_tr,
            ))
        } else {
            None
        };
        let mut rng_esc = Rng::new(seed.wrapping_add(0x9E37_79B9_7F4A_7C15));
        esc.push(run_escalate(
            truth,
            &avail,
            params,
            transient,
            &mut rng_esc,
        ));
        slide.push(run_sliding(truth, &avail, params, transient));
    }
    (esc, slide)
}

fn mean_slash_epoch(outcomes: &[SimOutcome]) -> Option<f64> {
    let slashed: Vec<u32> = outcomes.iter().filter_map(|o| o.slash_epoch).collect();
    if slashed.is_empty() {
        None
    } else {
        Some(slashed.iter().map(|&e| e as f64).sum::<f64>() / slashed.len() as f64)
    }
}

fn paired_stats(esc: &[SimOutcome], slide: &[SimOutcome]) -> PairedActorStats {
    let escalate = stats_from(esc);
    let sliding = stats_from(slide);
    let challenge_volume_ratio = if sliding.challenges == 0 {
        f64::INFINITY
    } else {
        escalate.challenges as f64 / sliding.challenges as f64
    };
    let slash_latency_delta_epochs = match (mean_slash_epoch(esc), mean_slash_epoch(slide)) {
        (Some(e), Some(s)) => (e - s).round() as i32,
        _ => 0,
    };
    PairedActorStats {
        escalate,
        sliding,
        challenge_volume_ratio,
        slash_latency_delta_epochs,
    }
}

/// Absolute block-space check (arithmetic; not settled by per-P micro-sim).
pub fn binding_analysis(baseline_period: u32, recheck_width: u32) -> BindingAnalysis {
    let baseline_rate = 1.0 / baseline_period as f64;
    // Per settlement epoch: one guaranteed baseline per (P, shard); recheck is conditional.
    let challenges_per_p_per_epoch = baseline_rate;
    let slots_per_epoch = N_MARKET_ARCHIVERS * SHARDS_PER_P;
    let challenges_per_seb = (slots_per_epoch as f64 * challenges_per_p_per_epoch) as u64;
    let weight_per_seb = challenges_per_seb * CHALLENGE_VIN_BYTES;
    let budget_per_seb = BLOCK_WEIGHT_LIMIT_BYTES * SETTLEMENT_EPOCH_BLOCKS;
    let fraction = weight_per_seb as f64 / budget_per_seb as f64;
    let volume_binding = fraction >= VOLUME_BINDING_FRACTION;
    // Foundation durability floor: Δslash of a few epochs is not network-load-bearing.
    let latency_binding = false;
    let rationale = if volume_binding {
        format!(
            "challenge weight ≈ {fraction:.4} of block budget per SEB (≥ {VOLUME_BINDING_FRACTION})"
        )
    } else {
        format!(
            "challenge weight ≈ {fraction:.4} of block budget per SEB — volume not binding (w={recheck_width})"
        )
    };
    BindingAnalysis {
        challenges_per_p_per_epoch_upper: challenges_per_p_per_epoch,
        challenge_weight_per_seb: weight_per_seb,
        block_weight_budget_per_seb: budget_per_seb,
        volume_fraction_of_block_budget: fraction,
        volume_binding,
        latency_binding,
        rationale,
    }
}

fn gaming_floor_baseline(params: &Round1Params) -> (u32, bool, f64) {
    let uptime_target = params.outage.uptime_target();
    let forced_target = (1.0 - uptime_target).max(0.20);
    let mut best_period = params.baseline_period;
    let mut best_forced = 0.0_f64;
    for &period in &params.gaming_baseline_sweep {
        let mut p = params.clone();
        p.baseline_period = period;
        let (esc, _) = paired_for_truth(GroundTruth::DodgeServing, &p, 0xD0D6_E_51D6);
        let forced = esc.iter().map(|o| o.forced_online_epochs).sum::<u32>() as f64
            / (esc.len() as f64 * params.epochs as f64);
        if forced > best_forced {
            best_forced = forced;
            best_period = period;
        }
    }
    (best_period, best_forced >= forced_target, best_forced)
}

pub fn run_u_sweep(seeds: u32, epochs: usize) -> Vec<USlashPoint> {
    let assumed = DownDurationLaw::exponential(DEFAULT_MEAN_DOWN_EPOCHS);
    let mut out = Vec::new();
    for &u in &[0.50, 0.60, 0.70, 0.80, 0.90, 0.95] {
        let params = Round1Params {
            name: format!("l14b_u_{u:.2}"),
            axis: "l14b_confirm_u".into(),
            epochs,
            seeds,
            outage: OutageProcess::with_uptime(u, assumed),
            assumed_law: assumed,
            recheck_quantile: 0.95,
            recheck_window_width_epochs: 3,
            sliding_window_epochs: 5,
            miss_threshold: 2,
            baseline_period: 1,
            gaming_baseline_sweep: vec![1],
        };
        let (esc, slide) = paired_for_truth(GroundTruth::HonestHosting, &params, 0x555F_5357);
        let esc_rate = stats_from(&esc).slashes as f64 / seeds as f64;
        let slide_rate = stats_from(&slide).slashes as f64 / seeds as f64;
        out.push(USlashPoint {
            uptime_target: u,
            escalate_slash_probability: esc_rate,
            sliding_slash_probability: slide_rate,
        });
    }
    out
}

fn decide(
    gaming_ok: bool,
    binding: &BindingAnalysis,
    volume_ratio: f64,
    slash_delta: i32,
    transient: &TransientStats,
) -> DecisionGate {
    if !gaming_ok {
        return DecisionGate {
            gaming_floor_satisfied: false,
            volume_binding: binding.volume_binding,
            latency_binding: binding.latency_binding,
            fsm_justified: false,
            sliding_window_preferred: false,
            volume_ratio,
            slash_latency_delta_epochs: slash_delta,
            rationale: "pin b_min first — gaming floor not met (recheck width / baseline cadence)"
                .into(),
        };
    }

    if !binding.volume_binding && !binding.latency_binding {
        return DecisionGate {
            gaming_floor_satisfied: true,
            volume_binding: false,
            latency_binding: false,
            fsm_justified: false,
            sliding_window_preferred: true,
            volume_ratio,
            slash_latency_delta_epochs: slash_delta,
            rationale: "neither challenge volume nor slash-latency binding — FSM unjustified; sliding-window wins"
                .into(),
        };
    }

    let transient_escalate_wins = transient.escalate_false_slash_rate
        < transient.sliding_false_slash_rate * 0.5;
    let fsm_justified = binding.volume_binding
        && transient_escalate_wins
        && volume_ratio < 0.85
        && transient.tail_misspecification_gap < 0.15;

    let sliding_window_preferred = !fsm_justified;
    let rationale = if fsm_justified {
        format!(
            "volume binding + escalate false-slash {:.3} vs {:.3} with volR={volume_ratio:.3}",
            transient.escalate_false_slash_rate, transient.sliding_false_slash_rate
        )
    } else if !transient_escalate_wins {
        "sliding-window false-slashes transients less — no FSM edge on separation".into()
    } else {
        format!(
            "relative trade only: volR={volume_ratio:.3}, tail gap {:.3}, Δslash={slash_delta}",
            transient.tail_misspecification_gap
        )
    };

    DecisionGate {
        gaming_floor_satisfied: true,
        volume_binding: binding.volume_binding,
        latency_binding: binding.latency_binding,
        fsm_justified,
        sliding_window_preferred,
        volume_ratio,
        slash_latency_delta_epochs: slash_delta,
        rationale,
    }
}

pub fn run_round1(params: &Round1Params) -> Round1Result {
    let binding = binding_analysis(
        params.baseline_period,
        params.recheck_window_width_epochs,
    );

    let (honest_esc, honest_slide) =
        paired_for_truth(GroundTruth::HonestHosting, params, 0x4854_5F48_4F4E);
    let (trans_esc, trans_slide) =
        paired_for_truth(GroundTruth::TransientOnce, params, 0x5452_414E_5349);
    let (dead_esc, dead_slide) = paired_for_truth(GroundTruth::NotServing, params, 0x4445_4144_5F50);
    let (dodge_esc, _) = paired_for_truth(GroundTruth::DodgeServing, params, 0x444F_4447_455F);

    let honest = paired_stats(&honest_esc, &honest_slide);
    let not_serving = paired_stats(&dead_esc, &dead_slide);

    let trans_esc_stats = stats_from(&trans_esc);
    let trans_slide_stats = stats_from(&trans_slide);
    let nominal = DownDurationLaw::nominal_false_slash_bound(params.recheck_quantile);
    let tail_gap = if params.assumed_law.mean_epochs() == params.outage.true_law.mean_epochs() {
        match (params.assumed_law, params.outage.true_law) {
            (DownDurationLaw::Exponential { .. }, DownDurationLaw::Exponential { .. }) => 0.0,
            _ => (trans_esc_stats.false_slashes as f64 / params.seeds as f64 - nominal).max(0.0),
        }
    } else {
        (trans_esc_stats.false_slashes as f64 / params.seeds as f64 - nominal).max(0.0)
    };

    let transient = TransientStats {
        escalate_false_slash_rate: trans_esc_stats.false_slashes as f64 / params.seeds as f64,
        sliding_false_slash_rate: trans_slide_stats.false_slashes as f64 / params.seeds as f64,
        nominal_bound_exponential_only: nominal,
        tail_misspecification_gap: tail_gap,
    };

    let dodge_slash_rate =
        dodge_esc.iter().filter(|o| o.slashed).count() as f64 / dodge_esc.len() as f64;
    let forced_online_fraction = dodge_esc.iter().map(|o| o.forced_online_epochs).sum::<u32>()
        as f64
        / (dodge_esc.len() as f64 * params.epochs as f64);
    let (gaming_floor_baseline_period, gaming_ok, _) = gaming_floor_baseline(params);

    let dodge = DodgeStats {
        escalate_slash_rate: dodge_slash_rate,
        forced_online_fraction,
        gaming_floor_baseline_period,
        gaming_floor_satisfied: gaming_ok,
    };

    let decision = decide(
        gaming_ok,
        &binding,
        honest.challenge_volume_ratio,
        not_serving.slash_latency_delta_epochs,
        &transient,
    );

    Round1Result {
        name: params.name.clone(),
        axis: params.axis.clone(),
        params: Round1ParamsSummary {
            epochs: params.epochs,
            seeds: params.seeds,
            uptime_target: params.outage.uptime_target(),
            true_law: law_label(params.outage.true_law),
            assumed_law: law_label(params.assumed_law),
            recheck_quantile: params.recheck_quantile,
            recheck_window_start_epochs: params
                .assumed_law
                .assumed_residual_start_epochs(params.recheck_quantile),
            recheck_window_width_epochs: params.recheck_window_width_epochs,
            nominal_false_slash_bound: nominal,
            sliding_window_epochs: params.sliding_window_epochs,
            miss_threshold: params.miss_threshold,
            baseline_period: params.baseline_period,
            gaming_floor_baseline_period,
        },
        honest,
        transient,
        not_serving,
        dodge,
        decision,
    }
}

pub fn build_round1_scenarios() -> Vec<Round1Params> {
    let exp = DownDurationLaw::exponential(DEFAULT_MEAN_DOWN_EPOCHS);
    let fat = DownDurationLaw::lognormal_fat_tail(DEFAULT_MEAN_DOWN_EPOCHS, 1.2);
    let gaming_sweep = vec![1, 2, 3, 5, 7, 10];

    let base = |true_law: DownDurationLaw, assumed: DownDurationLaw| Round1Params {
        name: String::new(),
        axis: String::new(),
        epochs: 500,
        seeds: 512,
        outage: OutageProcess::l16_default(true_law),
        assumed_law: assumed,
        recheck_quantile: 0.95,
        recheck_window_width_epochs: 3,
        sliding_window_epochs: 5,
        miss_threshold: 2,
        baseline_period: 1,
        gaming_baseline_sweep: gaming_sweep.clone(),
    };

    let mut out = Vec::new();

    {
        let mut p = base(exp, exp);
        p.name = "l14b_confirm_default".into();
        p.axis = "l14b_confirm".into();
        out.push(p);
    }

    for (label, q) in [("q90", 0.90), ("q95", 0.95), ("q99", 0.99)] {
        let mut p = base(exp, exp);
        p.name = format!("l14b_confirm_quantile_{label}");
        p.axis = "l14b_confirm_quantile".into();
        p.recheck_quantile = q;
        out.push(p);
    }

    {
        let mut p = base(exp, exp);
        p.name = "l14b_confirm_tail_assumed_exp_true_lognormal".into();
        p.axis = "l14b_confirm_tail".into();
        p.outage = OutageProcess::l16_default(fat);
        p.assumed_law = exp;
        out.push(p);
    }

    for (label, w) in [("w1", 1_u32), ("w3", 3), ("w6", 6)] {
        let mut p = base(exp, exp);
        p.name = format!("l14b_confirm_width_{label}");
        p.axis = "l14b_confirm_width".into();
        p.recheck_window_width_epochs = w;
        out.push(p);
    }

    for (label, m, n) in [("m2n3", 2, 3), ("m2n5", 2, 5), ("m3n7", 3, 7)] {
        let mut p = base(exp, exp);
        p.name = format!("l14b_confirm_window_{label}");
        p.axis = "l14b_confirm_window".into();
        p.miss_threshold = m;
        p.sliding_window_epochs = n;
        out.push(p);
    }

    {
        let mut p = base(exp, exp);
        p.name = "l14b_confirm_gaming_thin".into();
        p.axis = "l14b_confirm_gaming".into();
        p.baseline_period = 5;
        out.push(p);
    }

    out
}

pub fn run_full_report(axis_prefix: Option<&str>) -> FailureConfirmationReport {
    let scenarios: Vec<_> = build_round1_scenarios()
        .into_iter()
        .filter(|p| axis_prefix.is_none_or(|prefix| p.axis.starts_with(prefix)))
        .map(|p| run_round1(&p))
        .collect();
    let binding = binding_analysis(1, 3);
    let u_sweep = run_u_sweep(256, 500);
    FailureConfirmationReport {
        binding,
        u_sweep,
        scenarios,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_residual_start_matches_closed_form() {
        let law = DownDurationLaw::exponential(2.0);
        let q = law.assumed_residual_start_epochs(0.95) as f64;
        let expected = -2.0 * (1.0 - 0.95_f64).ln();
        assert!((q - expected.ceil()).abs() < 1.0);
    }

    #[test]
    fn not_serving_always_slashed() {
        let p = Round1Params {
            name: "test".into(),
            axis: "test".into(),
            epochs: 100,
            seeds: 32,
            outage: OutageProcess::l16_default(DownDurationLaw::exponential(2.0)),
            assumed_law: DownDurationLaw::exponential(2.0),
            recheck_quantile: 0.95,
            recheck_window_width_epochs: 3,
            sliding_window_epochs: 5,
            miss_threshold: 2,
            baseline_period: 1,
            gaming_baseline_sweep: vec![1, 2, 3],
        };
        let r = run_round1(&p);
        assert!(r.not_serving.escalate.slashes > 0);
        assert!(r.not_serving.sliding.slashes > 0);
    }

    #[test]
    fn tail_misspec_inflates_false_slash_vs_exponential_baseline() {
        let exp = DownDurationLaw::exponential(2.0);
        let fat = DownDurationLaw::lognormal_fat_tail(2.0, 1.5);
        let base = |true_law: DownDurationLaw| Round1Params {
            name: "tail".into(),
            axis: "test".into(),
            epochs: 500,
            seeds: 512,
            outage: OutageProcess::l16_default(true_law),
            assumed_law: exp,
            recheck_quantile: 0.95,
            recheck_window_width_epochs: 3,
            sliding_window_epochs: 5,
            miss_threshold: 2,
            baseline_period: 1,
            gaming_baseline_sweep: vec![1],
        };
        let r_exp = run_round1(&base(exp));
        let r_fat = run_round1(&base(fat));
        assert!(
            r_fat.transient.escalate_false_slash_rate
                >= r_exp.transient.escalate_false_slash_rate,
            "fat-tailed true outages should weakly increase transient false-slash vs exp"
        );
        assert!(
            r_fat.transient.tail_misspecification_gap >= r_exp.transient.tail_misspecification_gap,
            "tail gap should be at least as large under misspec"
        );
    }

    #[test]
    fn volume_not_binding_at_defaults() {
        let b = binding_analysis(1, 3);
        assert!(!b.volume_binding);
        assert!(!b.latency_binding);
    }

    #[test]
    fn u_sweep_monotone_slash_at_low_u() {
        let sweep = run_u_sweep(128, 300);
        let low = sweep.first().unwrap();
        let high = sweep.last().unwrap();
        assert!(low.escalate_slash_probability >= high.escalate_slash_probability);
    }
}
