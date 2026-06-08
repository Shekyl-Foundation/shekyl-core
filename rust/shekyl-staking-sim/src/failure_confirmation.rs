//! L14b — failure-confirmation scheduling (Round-1 policy comparator).
//!
//! Compares **escalate-on-failure + randomized recheck** vs **sliding-window m-of-n**
//! on a shared L16 outage-duration process. See
//! `docs/design/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md` and
//! `docs/design/STAKER_ARCHIVAL_SIM.md` §*L14b*.
//!
//! Round-1 is a per-`P` epoch micro-sim (not the full coverage world): the decision
//! gate is challenge-volume efficiency, false-slash vs outage-CDF quantile `p`, and a
//! gaming-resistance floor on baseline cadence.

use crate::model::Rng;
use crate::transport::{effective_uptime, regime_latency_epochs};
use serde::Serialize;

/// L16 operating point for outage calibration (matches `l16_regime_L6` substrate).
pub const L16_U_BASE: f64 = 0.9;
pub const L16_LATENCY_PER_UNIT: f64 = 6.0;
pub const L16_K: f64 = 0.07;
pub const L16_DEEP_SHARD_SIZE: f64 = 1.0;

/// Default transient-outage mean duration (epochs). Recheck quantile is read off this.
pub const DEFAULT_MEAN_DOWN_EPOCHS: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroundTruth {
    /// Has bytes; serves when the outage process is up.
    HonestHosting,
    /// Has bytes; one forced outage segment (length ~ mean down) mid-run.
    TransientOnce,
    /// No bytes — durable absence.
    NotServing,
    /// Has bytes but surfaces only in the recheck window after a baseline miss (escalate path).
    DodgeServing,
}

#[derive(Debug, Clone)]
pub struct OutageProcess {
    pub mean_down_epochs: f64,
    pub mean_up_epochs: f64,
}

impl OutageProcess {
    /// Calibrate renewal rates so stationary availability ≈ `uptime_target`.
    ///
    /// `u = μ_up / (μ_up + μ_down)` for exponential up/down segments.
    pub fn from_uptime_target(uptime_target: f64, mean_down_epochs: f64) -> Self {
        let u = uptime_target.clamp(f64::EPSILON, 1.0 - f64::EPSILON);
        let mean_up = mean_down_epochs * u / (1.0 - u);
        Self {
            mean_down_epochs,
            mean_up_epochs: mean_up,
        }
    }

    /// L16-default outage process at the onion band ceiling (`L=6`).
    pub fn l16_default(mean_down_epochs: f64) -> Self {
        let latency = regime_latency_epochs(L16_DEEP_SHARD_SIZE, L16_LATENCY_PER_UNIT);
        let u_eff = effective_uptime(L16_U_BASE, latency, L16_K);
        Self::from_uptime_target(u_eff, mean_down_epochs)
    }

    /// `p`-quantile of exponential down-duration (blocks/epochs).
    pub fn quantile_down_epochs(&self, p: f64) -> u32 {
        let p = p.clamp(f64::EPSILON, 1.0 - f64::EPSILON);
        let q = -self.mean_down_epochs * (1.0 - p).ln();
        q.ceil().max(1.0) as u32
    }

    /// Analytic bound `false_slash_on_genuine_transient ≈ 1 − p` (pin §4).
    pub fn analytic_transient_false_slash_bound(p: f64) -> f64 {
        (1.0 - p).clamp(0.0, 1.0)
    }

    fn sample_exp(&self, mean: f64, rng: &mut Rng) -> u32 {
        let u = rng.next_f64().max(f64::EPSILON);
        (-mean * u.ln()).ceil().max(1.0) as u32
    }

    /// Renewal up/down schedule: `true` = network-up (can serve if holding bytes).
    pub fn simulate_availability(&self, epochs: usize, rng: &mut Rng) -> Vec<bool> {
        let mut up = true;
        let mut remaining = self.sample_exp(self.mean_up_epochs, rng);
        let mut avail = Vec::with_capacity(epochs);
        for _ in 0..epochs {
            avail.push(up);
            remaining = remaining.saturating_sub(1);
            if remaining == 0 {
                up = !up;
                remaining = if up {
                    self.sample_exp(self.mean_up_epochs, rng)
                } else {
                    self.sample_exp(self.mean_down_epochs, rng)
                };
            }
        }
        avail
    }
}

#[derive(Debug, Clone)]
pub struct Round1Params {
    pub name: String,
    pub axis: String,
    pub epochs: usize,
    pub seeds: u32,
    pub outage: OutageProcess,
    pub recheck_quantile: f64,
    pub window_epochs: usize,
    pub miss_threshold: usize,
    pub baseline_period: u32,
    /// Baseline periods swept for the gaming-resistance floor (escalate path).
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
    pub mean_down_epochs: f64,
    pub mean_up_epochs: f64,
    pub uptime_target: f64,
    pub recheck_quantile: f64,
    pub recheck_delay_epochs: u32,
    pub analytic_false_slash_bound: f64,
    pub window_epochs: usize,
    pub miss_threshold: usize,
    pub baseline_period: u32,
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
    pub analytic_bound: f64,
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
    pub sliding_window_preferred: bool,
    pub volume_ratio: f64,
    pub slash_latency_delta_epochs: i32,
    pub gaming_floor_satisfied: bool,
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

fn can_serve(
    truth: GroundTruth,
    epoch: u32,
    avail: &[bool],
    transient: Option<(u32, u32)>,
    dodge_recheck: Option<u32>,
) -> bool {
    match truth {
        GroundTruth::NotServing => false,
        GroundTruth::HonestHosting => avail[epoch as usize],
        GroundTruth::TransientOnce => {
            // Single injected outage; otherwise always serving (isolates transient-vs-durable).
            if let Some((start, len)) = transient {
                !(epoch >= start && epoch < start + len)
            } else {
                true
            }
        }
        GroundTruth::DodgeServing => {
            if let Some(r) = dodge_recheck {
                // Surface one epoch before recheck through recheck (monitor → serve).
                epoch + 1 >= r.saturating_sub(1) && epoch <= r + 1
            } else {
                false
            }
        }
    }
}

fn transient_window(epochs: u32, outage: &OutageProcess, rng: &mut Rng) -> (u32, u32) {
    let start = (epochs / 3).max(1);
    let len = outage.sample_exp(outage.mean_down_epochs, rng);
    (start, len)
}

fn run_escalate(
    truth: GroundTruth,
    avail: &[bool],
    params: &Round1Params,
    transient: Option<(u32, u32)>,
) -> SimOutcome {
    let epochs = params.epochs as u32;
    let mut out = SimOutcome::default();
    let mut pending_recheck: Option<u32> = None;
    let recheck_delay = params.outage.quantile_down_epochs(params.recheck_quantile);

    for epoch in 0..epochs {
        let baseline_due = epoch % params.baseline_period == 0;
        if !baseline_due && pending_recheck != Some(epoch) {
            continue;
        }

        let dodge_recheck = if truth == GroundTruth::DodgeServing {
            pending_recheck
        } else {
            None
        };

        if pending_recheck == Some(epoch) {
            out.challenges += 1;
            let serve = can_serve(truth, epoch, avail, transient, dodge_recheck);
            if truth == GroundTruth::DodgeServing && serve {
                out.forced_online_epochs += 1;
            }
            pending_recheck = None;
            if serve {
                continue;
            }
            out.slashed = true;
            out.slash_epoch = Some(epoch);
            out.false_slash = truth == GroundTruth::TransientOnce;
            break;
        }

        if baseline_due && pending_recheck.is_none() {
            out.challenges += 1;
            let serve = can_serve(truth, epoch, avail, transient, None);
            if serve {
                continue;
            }
            let fire = epoch + recheck_delay;
            if fire < epochs {
                pending_recheck = Some(fire);
            } else if truth == GroundTruth::NotServing {
                // Durable absence: no recheck window left still counts as slash.
                out.slashed = true;
                out.slash_epoch = Some(epoch);
                break;
            }
            // Honest / transient: recheck falls past horizon — censored, not slashed.
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
        if misses.len() > params.window_epochs {
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
            Some(transient_window(params.epochs as u32, &params.outage, &mut rng_tr))
        } else {
            None
        };
        esc.push(run_escalate(truth, &avail, params, transient));
        slide.push(run_sliding(truth, &avail, params, transient));
    }
    (esc, slide)
}

fn mean_slash_epoch(outcomes: &[SimOutcome]) -> Option<f64> {
    let slashed: Vec<u32> = outcomes
        .iter()
        .filter_map(|o| o.slash_epoch)
        .collect();
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
    let esc_lat = mean_slash_epoch(esc);
    let slide_lat = mean_slash_epoch(slide);
    let slash_latency_delta_epochs = match (esc_lat, slide_lat) {
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

fn gaming_floor_baseline(params: &Round1Params) -> (u32, bool) {
    let uptime_target = params.outage.mean_up_epochs
        / (params.outage.mean_up_epochs + params.outage.mean_down_epochs);
    // Pin §5: gaming costly when dodge-forced online share approaches honest availability.
    let forced_target = (1.0 - uptime_target).max(0.25);

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
    (best_period, best_forced >= forced_target)
}

pub fn run_round1(params: &Round1Params) -> Round1Result {
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
    let transient = TransientStats {
        escalate_false_slash_rate: trans_esc_stats.false_slashes as f64 / params.seeds as f64,
        sliding_false_slash_rate: trans_slide_stats.false_slashes as f64 / params.seeds as f64,
        analytic_bound: OutageProcess::analytic_transient_false_slash_bound(params.recheck_quantile),
    };

    let dodge_slash_rate = dodge_esc.iter().filter(|o| o.slashed).count() as f64
        / dodge_esc.len() as f64;
    let forced_online_fraction = dodge_esc.iter().map(|o| o.forced_online_epochs).sum::<u32>()
        as f64
        / (dodge_esc.len() as f64 * params.epochs as f64);
    let (gaming_floor_baseline_period, gaming_floor_from_sweep) =
        gaming_floor_baseline(params);
    let gaming_floor_satisfied = gaming_floor_from_sweep;

    let dodge = DodgeStats {
        escalate_slash_rate: dodge_slash_rate,
        forced_online_fraction,
        gaming_floor_baseline_period,
        gaming_floor_satisfied,
    };

    let volume_ratio = honest.challenge_volume_ratio;
    let slash_delta = not_serving.slash_latency_delta_epochs;
    let transient_escalate_wins = transient.escalate_false_slash_rate
        < transient.sliding_false_slash_rate * 0.5;
    let sliding_window_preferred = volume_ratio <= 1.2
        && slash_delta.abs() <= 1
        && transient_escalate_wins;
    let rationale = if sliding_window_preferred {
        "challenge volume, slash latency, and transient false-slash favor sliding-window — defer per-P FSM"
            .into()
    } else if transient_escalate_wins && !gaming_floor_satisfied {
        format!(
            "escalate false-slash {:.3} vs sliding {:.3}, but gaming floor fails — tighten baseline cadence before FSM",
            transient.escalate_false_slash_rate,
            transient.sliding_false_slash_rate,
        )
    } else if transient_escalate_wins && volume_ratio > 1.2 {
        format!(
            "escalate false-slash wins ({:.3} vs {:.3}) but volume_ratio={volume_ratio:.3}>1.2 on L16 u_eff — FSM trade is transient precision vs honest-P volume",
            transient.escalate_false_slash_rate,
            transient.sliding_false_slash_rate,
        )
    } else if !gaming_floor_satisfied {
        "gaming-resistance floor not met at swept baseline cadences".into()
    } else {
        format!(
            "volume_ratio={volume_ratio:.3}, fsEsc={:.3}, fsSlide={:.3}, Δslash={slash_delta}",
            transient.escalate_false_slash_rate,
            transient.sliding_false_slash_rate,
        )
    };

    let uptime_target =
        params.outage.mean_up_epochs
            / (params.outage.mean_up_epochs + params.outage.mean_down_epochs);

    Round1Result {
        name: params.name.clone(),
        axis: params.axis.clone(),
        params: Round1ParamsSummary {
            epochs: params.epochs,
            seeds: params.seeds,
            mean_down_epochs: params.outage.mean_down_epochs,
            mean_up_epochs: params.outage.mean_up_epochs,
            uptime_target,
            recheck_quantile: params.recheck_quantile,
            recheck_delay_epochs: params.outage.quantile_down_epochs(params.recheck_quantile),
            analytic_false_slash_bound: transient.analytic_bound,
            window_epochs: params.window_epochs,
            miss_threshold: params.miss_threshold,
            baseline_period: params.baseline_period,
        },
        honest,
        transient,
        not_serving,
        dodge,
        decision: DecisionGate {
            sliding_window_preferred,
            volume_ratio,
            slash_latency_delta_epochs: slash_delta,
            gaming_floor_satisfied,
            rationale,
        },
    }
}

pub fn build_round1_scenarios() -> Vec<Round1Params> {
    let outage = OutageProcess::l16_default(DEFAULT_MEAN_DOWN_EPOCHS);
    let gaming_sweep = vec![1, 2, 3, 5, 7, 10];
    let base = || Round1Params {
        name: String::new(),
        axis: String::new(),
        epochs: 500,
        seeds: 512,
        outage: outage.clone(),
        recheck_quantile: 0.95,
        window_epochs: 5,
        miss_threshold: 2,
        baseline_period: 1,
        gaming_baseline_sweep: gaming_sweep.clone(),
    };

    let mut out = Vec::new();

    {
        let mut p = base();
        p.name = "l14b_confirm_default".into();
        p.axis = "l14b_confirm".into();
        out.push(p);
    }

    for (label, q) in [("q90", 0.90), ("q95", 0.95), ("q99", 0.99)] {
        let mut p = base();
        p.name = format!("l14b_confirm_quantile_{label}");
        p.axis = "l14b_confirm_quantile".into();
        p.recheck_quantile = q;
        out.push(p);
    }

    for (label, m, n) in [("m2n3", 2, 3), ("m2n5", 2, 5), ("m3n7", 3, 7)] {
        let mut p = base();
        p.name = format!("l14b_confirm_window_{label}");
        p.axis = "l14b_confirm_window".into();
        p.miss_threshold = m;
        p.window_epochs = n;
        out.push(p);
    }

    {
        let mut p = base();
        p.name = "l14b_confirm_gaming_thin".into();
        p.axis = "l14b_confirm_gaming".into();
        p.baseline_period = 5;
        out.push(p);
    }

    out
}

pub fn run_all_round1(axis_prefix: Option<&str>) -> Vec<Round1Result> {
    build_round1_scenarios()
        .into_iter()
        .filter(|p| axis_prefix.is_none_or(|prefix| p.axis.starts_with(prefix)))
        .map(|p| run_round1(&p))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_matches_exponential_closed_form() {
        let o = OutageProcess::from_uptime_target(0.9, 2.0);
        let q = o.quantile_down_epochs(0.95) as f64;
        let expected = -2.0 * (1.0 - 0.95_f64).ln();
        assert!((q - expected.ceil()).abs() < 1.0);
    }

    #[test]
    fn not_serving_always_slashed_under_both_policies() {
        let p = Round1Params {
            name: "test".into(),
            axis: "test".into(),
            epochs: 100,
            seeds: 32,
            outage: OutageProcess::l16_default(2.0),
            recheck_quantile: 0.95,
            window_epochs: 5,
            miss_threshold: 2,
            baseline_period: 1,
            gaming_baseline_sweep: vec![1, 2, 3],
        };
        let r = run_round1(&p);
        assert!(r.not_serving.escalate.slashes > 0);
        assert!(r.not_serving.sliding.slashes > 0);
    }

    #[test]
    fn transient_false_slash_tracks_quantile_bound() {
        let p = Round1Params {
            name: "test".into(),
            axis: "test".into(),
            epochs: 500,
            seeds: 512,
            outage: OutageProcess::l16_default(2.0),
            recheck_quantile: 0.95,
            window_epochs: 5,
            miss_threshold: 2,
            baseline_period: 1,
            gaming_baseline_sweep: vec![1, 2, 3],
        };
        let r = run_round1(&p);
        // Outage length exponential ⇒ ≈5% exceed the p=0.95 quantile (pin §4).
        assert!(
            r.transient.escalate_false_slash_rate <= r.transient.analytic_bound + 0.08,
            "escalate false slash {} vs bound {}",
            r.transient.escalate_false_slash_rate,
            r.transient.analytic_bound
        );
        // Sliding-window often false-slashes a single long baseline miss (m-of-n); escalate
        // defers to recheck — the Round-1 comparison surface.
        assert!(
            r.transient.sliding_false_slash_rate >= r.transient.escalate_false_slash_rate,
            "escalate should false-slash no more than sliding on single transient"
        );
    }

    #[test]
    fn round1_scenarios_non_empty() {
        assert!(!build_round1_scenarios().is_empty());
    }
}
