//! Reward computation: two arms.
//!
//! **`RewardArm::Production`** (the default) pays as production does
//! (`ECONOMICS_SIM_PRODUCTION_REBASE.md` Appendix B, R1–R5): each held seated
//! shard contributes `shard_work_micro(r, age, g)`, the sum floors to milli
//! once (`work_milli_from_micro`), market membership gates it
//! (`credited_work_milli`), and `reward_share_floor` pays
//! `⌊budget · credited / Σwork⌋` in atomic units, the dust unminted. Credit is
//! linear in work: production deleted the plateau from the reward path (D3/R2).
//! `r` is the shard's seated holders, `r_market_count`'s served count under the
//! population model's all-pass draw abstraction (N1). The purse crosses from
//! model units to atomic units once, at one model unit per SKL, and so do the
//! shard age (to milli) and the age weight (to milli).
//!
//! **`RewardArm::RegisteredPlateau`** is the arm the L11/L13 pins were taken on,
//! described below. It is on the retirement list (D1) and is the falsifier's
//! control: `l11_l13_five_seed_pins` runs it.
//!
//! `work_P = Σ_{shards held} (1/R(shard)) · g(age(shard))` (age-weighted scarcity),
//! then a per-pseudonym **banded plateau-cap** `Curve(work_P)` on work, then the
//! competitive-share servo (REWARD_EMISSION_LEG.md §4.0 form C):
//! `reward_P = budget · Curve(work_P) / Σ Curve(work_{P'})` — cap in numerator;
//! Σ reward = budget; not `Curve(budget·work/Σwork)` (strands budget when cap binds).
//!
//! Three dilution channels, all present (the agent's marginal-reward calculation in
//! `agent.rs` must see all three, per the spec's competitive-share correction):
//! 1. `1/R` self-dilution — holding a shard raises its `R`, lowering its `1/R`.
//! 2. concave plateau-cap — marginal capped-work falls to 0 above the cap.
//! 3. servo share — adding work raises `Σwork`, diluting everyone (incl. self).
//!
//! **Cap and splitting.** The plateau-cap is *per pseudonym*. An actor can evade it
//! by spreading work across pseudonyms — but each pseudonym carries an operational
//! cost `pseudonym_cost` (the firewall hygiene: separate circuits/timing/output).
//! So the cap binds an honest single-pseudonym staker, and a splitter trades
//! cap-evasion against `pseudonym_cost`. This is exactly the spec's point that the
//! per-staker cap alone is toothless against Sybil (freely evadable) and the bond is
//! what carries the limit; the sim embodies it rather than assuming it.

use crate::curve::curve_banded;
use crate::model::{g_age, World};
use shekyl_archival_retention::{
    credited_work_milli, curve_milli, reward_share_floor, scarcity_micro, shard_work_micro,
    sigma_work_milli, work_milli_from_micro, BandedCurveParams, WORK_MICRO_SCALE, WORK_MILLI_SCALE,
};

/// Atomic units per model unit: one model unit is one SKL (Appendix B, Units).
const ATOMIC_PER_UNIT: f64 = shekyl_units::ATOMIC_UNITS_PER_SKL as f64;

/// Which mechanism pays a run's reward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewardArm {
    /// Linear credited work on production's integer operands.
    #[default]
    Production,
    /// Float work, the banded plateau at `cap`, the pseudonym split and a float
    /// price: the arm the L11/L13 pins were taken on. Retired in production
    /// (D3/R2); kept as the falsifier's control until its deletion is ruled.
    RegisteredPlateau,
}

/// The plateau's evaluation backend on [`RewardArm::RegisteredPlateau`].
///
/// `Integer` evaluates the banded curve with `curve_milli`; `Float` with the
/// sim's `curve_banded`, which over-reads worst-shard redundancy by up to one
/// replica (PR 1.5, `ARCHIVAL_SIM_ECONOMICS_VERDICT.md`). Production applies
/// neither: its credit is linear (`credited_work_milli`), so this selects a
/// backend of the registered arm only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CurveImpl {
    #[default]
    Integer,
    Float,
}

#[derive(Debug, Clone)]
pub struct RewardParams {
    /// Total per-epoch reward budget distributed across all stakers (the servo's
    /// fixed pool — supply-safety under population growth is gate 1, not exercised
    /// here; only the share *incentive* is).
    pub budget: f64,
    /// Per-pseudonym work cap (the plateau). Work above this earns nothing for that
    /// pseudonym unless the actor opens another pseudonym.
    pub cap: f64,
    /// Operational cost per pseudonym (firewall hygiene). Makes cap-evasion via
    /// splitting non-free, so both the cap height and the bond are meaningful.
    pub pseudonym_cost: f64,
    /// Age-weight in `g(age) = 1 + age_weight · age`. `0` = pure `1/R` baseline.
    pub age_weight: f64,
    /// The registered arm's plateau backend.
    pub curve_impl: CurveImpl,
    /// Which mechanism pays.
    pub arm: RewardArm,
}

/// A shard age in `[0, 1]` as production's relative depth in milli. The one
/// crossing from the model's float age into the reward's integers.
#[must_use]
pub fn age_milli(age: f64) -> u64 {
    (age.clamp(0.0, 1.0) * WORK_MILLI_SCALE as f64).round() as u64
}

/// The age weight as production's milli weight (`2.0` → `2000`).
#[must_use]
pub fn age_weight_milli(age_weight: f64) -> u64 {
    (age_weight.max(0.0) * WORK_MILLI_SCALE as f64).round() as u64
}

/// The purse in atomic units, crossing once at one model unit per SKL.
#[must_use]
pub fn purse_atomic(budget: f64) -> u64 {
    let atomic = (budget.max(0.0) * ATOMIC_PER_UNIT).round();
    if atomic >= u64::MAX as f64 {
        u64::MAX
    } else {
        atomic as u64
    }
}

/// What one more held shard is worth to an agent at `price` (model units per
/// unit of work) with `r_eff` holders counting itself: the work term the arm
/// pays on, times the price. Production's term is `scarcity_micro`; the
/// registered arm's is the float `g/r`.
#[must_use]
pub fn shard_value(arm: RewardArm, price: f64, r_eff: usize, age: f64, age_weight: f64) -> f64 {
    match arm {
        RewardArm::Production => {
            let micro = scarcity_micro(r_eff as u64, age_milli(age), age_weight_milli(age_weight));
            price * micro as f64 / WORK_MICRO_SCALE as f64
        }
        RewardArm::RegisteredPlateau => price * (1.0 / r_eff as f64) * g_age(age, age_weight),
    }
}

/// Raw (uncapped) work for one actor, given current replication counts. The economic
/// game is on **committed** holdings (an actor is paid to *store* — verified by
/// challenge, L14 — not for instantaneous retrievability), so this counts every held
/// shard. The L10 backfill lag is a *retrieval-coverage* property tracked separately
/// (`serving_replication`), decoupled from the game so the lag does not death-spiral
/// the incentive (a fresh deep acquisition still earns; only its *serving* coverage
/// lags). Unchanged from iteration 2.
pub fn raw_work(world: &World, actor: usize, r: &[usize], age_weight: f64) -> f64 {
    let mut w = 0.0;
    for (s, &held) in world.holdings[actor].iter().enumerate() {
        if held {
            let rs = r[s].max(1) as f64;
            w += (1.0 / rs) * g_age(world.shards[s].age, age_weight);
        }
    }
    w
}

/// Number of pseudonyms an actor optimally splits into, and the operational cost,
/// given its raw work and the current work→reward price. An actor splits to
/// `ceil(raw_work / cap)` pseudonyms only while the recovered capped-work is worth
/// more than `pseudonym_cost`; otherwise it runs a single (capped) pseudonym.
///
/// Convert sim `work` to milli-units; non-finite and negative inputs map to `0`.
fn work_f64_to_milli(work: f64) -> u64 {
    if !work.is_finite() || work <= 0.0 {
        return 0;
    }
    let scaled = work * WORK_MILLI_SCALE as f64;
    if !scaled.is_finite() || scaled <= 0.0 {
        return 0;
    }
    if scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.round() as u64
    }
}

/// Convert sim `cap` to plateau-value milli; invalid caps map to `0`.
fn cap_f64_to_milli(cap: f64) -> u64 {
    if !cap.is_finite() || cap <= 0.0 {
        return 0;
    }
    let scaled = cap * WORK_MILLI_SCALE as f64;
    if !scaled.is_finite() || scaled <= 0.0 {
        return 0;
    }
    if scaled >= u64::MAX as f64 {
        u64::MAX
    } else {
        scaled.round() as u64
    }
}

/// Credited work via banded PL `Curve` (REWARD_EMISSION_LEG.md §4.0 form C).
///
/// Zero/invalid `cap` credits zero on both backends, matching the canonical
/// `curve_milli` (a zero plateau is a degenerate curve, not an uncapped
/// pass-through) and the float `curve_banded`.
#[must_use]
pub fn curve(work: f64, p: &RewardParams) -> f64 {
    match p.curve_impl {
        CurveImpl::Float => curve_banded(work, p.cap),
        CurveImpl::Integer => {
            // cap_f64_to_milli maps non-finite/non-positive caps to 0, and
            // curve_milli credits 0 for a zero plateau — no special-casing.
            let params = BandedCurveParams::from_plateau_value(cap_f64_to_milli(p.cap));
            let work_milli = work_f64_to_milli(work);
            curve_milli(work_milli, &params) as f64 / WORK_MILLI_SCALE as f64
        }
    }
}

/// Returns `(effective_capped_work, pseudonym_count, split_cost)`.
fn split_decision(raw_work: f64, price: f64, p: &RewardParams) -> (f64, usize, f64) {
    if p.cap <= 0.0 || raw_work <= 0.0 {
        return (curve(raw_work, p), 1, 0.0);
    }
    let single = curve(raw_work, p);
    // Upper bound on pseudonyms: concave `Curve` can make splitting profitable below
    // plateau work (2·cap raw), so size chunks by `cap` not plateau work.
    let m_full = (raw_work / p.cap).ceil().max(1.0) as usize;
    let per = raw_work / m_full as f64;
    // Each of the m_full pseudonyms credits the identical curve(per); multiply
    // rather than summing m_full equal terms (faster, no accumulated rounding).
    let multi = m_full as f64 * curve(per, p);
    let gain = (multi - single) * price;
    let split_cost = (m_full.saturating_sub(1)) as f64 * p.pseudonym_cost;
    if gain > split_cost {
        (multi, m_full, split_cost)
    } else {
        (single, 1, 0.0)
    }
}

/// Result of a full reward evaluation for one epoch. (Iteration 1 consumes `r` for
/// coverage, `pseudonyms` for the secondary pseudonym-level spread read, and `price`
/// to drive next epoch's marginal-value/split decisions. The realized per-actor
/// reward distribution is an iteration-3 servo-supply-safety concern, not a coverage
/// input, so it is not surfaced here.)
pub struct RewardEval {
    pub r: Vec<usize>,
    pub pseudonyms: Vec<usize>,
    pub price: f64,
    /// Realized per-actor token reward this epoch = `price · capped_work_a` (the servo
    /// share `budget · capped_a / Σ capped`). Drives the L11 participation yield
    /// (`net reward ÷ committed bond capital` vs. reservation). Zero for inactive or
    /// zero-work actors.
    pub rewards: Vec<f64>,
    /// Atomic units of the purse `reward_share_floor` left unminted this epoch
    /// (production arm; `0` on the registered arm).
    pub dust_atomic: u64,
}

/// Evaluate rewards for the whole world. `price_hint` seeds the split decision
/// (price = budget / Σ capped_work is itself a function of splitting, so we use the
/// previous epoch's price as the hint and recompute the realized price here; across
/// epochs this converges — no inner fixed point).
pub fn evaluate(world: &World, p: &RewardParams, price_hint: f64) -> RewardEval {
    match p.arm {
        RewardArm::Production => evaluate_production(world, p),
        RewardArm::RegisteredPlateau => evaluate_registered(world, p, price_hint),
    }
}

/// Production's reward for one epoch (module docs). `r` in the result is the
/// committed count, which the coverage metrics read on both arms; the reward
/// itself counts seated holders.
fn evaluate_production(world: &World, p: &RewardParams) -> RewardEval {
    let r = world.replication();
    let seated = world.serving_replication();
    let weight_milli = age_weight_milli(p.age_weight);
    let n = world.actors.len();

    let work_milli: Vec<u64> = (0..n)
        .map(|a| {
            let micro = world.holdings[a]
                .iter()
                .enumerate()
                .filter(|&(s, &held)| held && world.inflight[a][s] == 0)
                .map(|(s, _)| {
                    shard_work_micro(
                        seated[s] as u64,
                        age_milli(world.shards[s].age),
                        weight_milli,
                        true,
                    )
                })
                .fold(0u64, u64::saturating_add);
            work_milli_from_micro(micro)
        })
        .collect();
    let member = &world.active;
    let sigma = sigma_work_milli(&work_milli, member);
    let budget = purse_atomic(p.budget);

    let mut paid = 0u64;
    let rewards = (0..n)
        .map(|a| {
            let credited = credited_work_milli(work_milli[a], member[a]);
            let atomic = reward_share_floor(budget, credited, sigma);
            paid = paid.saturating_add(atomic);
            atomic as f64 / ATOMIC_PER_UNIT
        })
        .collect();
    let price = if sigma > 0 {
        p.budget * WORK_MILLI_SCALE as f64 / sigma as f64
    } else {
        0.0
    };

    RewardEval {
        r,
        pseudonyms: vec![1; n],
        price,
        rewards,
        dust_atomic: budget.saturating_sub(paid),
    }
}

/// The registered arm's reward for one epoch (module docs).
fn evaluate_registered(world: &World, p: &RewardParams, price_hint: f64) -> RewardEval {
    let r = world.replication();
    let n = world.actors.len();

    let raw: Vec<f64> = (0..n)
        .map(|a| raw_work(world, a, &r, p.age_weight))
        .collect();

    let mut capped = vec![0.0; n];
    let mut pseudonyms = vec![1usize; n];
    for a in 0..n {
        let (eff, m, _cost) = split_decision(raw[a], price_hint, p);
        capped[a] = eff;
        pseudonyms[a] = m;
    }

    // Denominator is Σ Curve(work), not Σ raw work — form C (REWARD_EMISSION_LEG.md §4.0).
    // Coherence check: spread/windowing verdicts transfer to spec only via this sum.
    let sum_capped: f64 = capped.iter().sum();
    let price = if sum_capped > 0.0 {
        p.budget / sum_capped
    } else {
        0.0
    };

    // Realized token reward = price · capped_work (= budget·capped/Σcapped); Σ rewards = budget.
    let rewards: Vec<f64> = capped.iter().map(|&c| price * c).collect();

    RewardEval {
        r,
        pseudonyms,
        price,
        rewards,
        dust_atomic: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_raises_credited_work_below_plateau_work() {
        let p = RewardParams {
            budget: 100.0,
            cap: 8.0,
            pseudonym_cost: 0.0,
            age_weight: 0.0,
            curve_impl: CurveImpl::Float,
            arm: RewardArm::RegisteredPlateau,
        };
        let single = curve(12.0, &p);
        let (eff, m, _) = split_decision(12.0, 1.0, &p);
        assert!(
            m >= 2,
            "expected multi-pseudonym split at raw_work=12, cap=8"
        );
        assert!(
            eff > single,
            "split credited work {eff} should exceed single {single}"
        );
    }

    /// Zero/invalid cap credits zero on *both* backends (canonical `curve_milli`
    /// semantics: degenerate plateau, not uncapped pass-through).
    #[test]
    fn degenerate_cap_credits_zero_on_both_backends() {
        for cap in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            for curve_impl in [CurveImpl::Float, CurveImpl::Integer] {
                let p = RewardParams {
                    budget: 100.0,
                    cap,
                    pseudonym_cost: 0.0,
                    age_weight: 0.0,
                    curve_impl,
                    arm: RewardArm::RegisteredPlateau,
                };
                assert_eq!(
                    curve(12.0, &p),
                    0.0,
                    "cap={cap} backend={curve_impl:?} must credit zero"
                );
            }
        }
    }

    /// Float and Integer backends agree to milli precision across the banded
    /// curve (pre-plateau, mid-band, and plateau region).
    #[test]
    fn backends_agree_to_milli_precision() {
        for work in [0.5, 2.0, 4.0, 6.0, 12.0, 16.0, 50.0] {
            let float_p = RewardParams {
                budget: 100.0,
                cap: 8.0,
                pseudonym_cost: 0.0,
                age_weight: 0.0,
                curve_impl: CurveImpl::Float,
                arm: RewardArm::RegisteredPlateau,
            };
            let int_p = RewardParams {
                curve_impl: CurveImpl::Integer,
                ..float_p.clone()
            };
            let f = curve(work, &float_p);
            let i = curve(work, &int_p);
            assert!(
                (f - i).abs() < 2e-3,
                "work={work}: float {f} vs integer {i} diverge beyond milli rounding"
            );
        }
    }

    fn world(holdings: Vec<Vec<bool>>, ages: &[f64]) -> World {
        use crate::model::{Actor, Shard};
        let shards = ages
            .iter()
            .map(|&age| Shard {
                age,
                size_seed: 0.0,
                size: 1.0,
            })
            .collect();
        let actors = holdings
            .iter()
            .map(|_| Actor {
                storage_capacity: 64,
                capital: 100.0,
                is_whale: false,
                reservation: 0.0,
            })
            .collect();
        let mut w = World::new(shards, actors);
        w.holdings = holdings;
        w
    }

    fn production(budget: f64) -> RewardParams {
        RewardParams {
            budget,
            cap: 8.0,
            pseudonym_cost: 0.05,
            age_weight: crate::model::AGE_WEIGHT,
            curve_impl: CurveImpl::Integer,
            arm: RewardArm::Production,
        }
    }

    /// The production arm pays `reward_share_floor` per member and leaves the
    /// rest unminted: paid plus dust is the purse, and the dust is under one
    /// atomic unit per member.
    #[test]
    fn production_pays_the_floor_and_keeps_the_dust() {
        let w = world(
            vec![
                vec![true, true, false, true],
                vec![true, false, true, true],
                vec![false, true, true, false],
            ],
            &[0.1, 0.37, 0.62, 0.95],
        );
        let p = production(100.0);
        let eval = evaluate(&w, &p, 1.0);
        let paid: u64 = eval
            .rewards
            .iter()
            .map(|&r| (r * ATOMIC_PER_UNIT).round() as u64)
            .sum();
        assert_eq!(paid + eval.dust_atomic, purse_atomic(100.0));
        assert!(eval.dust_atomic < w.actors.len() as u64);
        assert!(eval.pseudonyms.iter().all(|&m| m == 1));
    }

    /// Credit is linear in work: an actor holding two copies' worth of the
    /// same shards earns twice the other's share, where the plateau arm would
    /// cap it.
    #[test]
    fn production_credit_is_linear_in_work() {
        // Every shard has two holders. Actor 0 holds all eight; actor 1 holds
        // shards 0..4 and actor 2 shards 4..8. Actor 0's work is twice actor
        // 1's, and so is its share.
        let h0 = vec![true; 8];
        let h1: Vec<bool> = (0..8).map(|s| s < 4).collect();
        let h2: Vec<bool> = (0..8).map(|s| s >= 4).collect();
        let w = world(vec![h0, h1, h2], &[0.75; 8]);
        let eval = evaluate(&w, &production(100.0), 1.0);
        let ratio = eval.rewards[0] / eval.rewards[1];
        assert!((ratio - 2.0).abs() < 1e-6, "ratio {ratio}");
    }

    /// The agent's value of a shard on the production arm is the price times
    /// `scarcity_micro`'s `g/r`, to a micro.
    #[test]
    fn production_shard_value_is_scarcity_times_price() {
        for (r, age) in [(1usize, 0.0), (3, 0.5), (6, 0.999), (11, 0.25)] {
            let v = shard_value(RewardArm::Production, 2.0, r, age, crate::model::AGE_WEIGHT);
            let float = 2.0 * g_age(age, crate::model::AGE_WEIGHT) / r as f64;
            assert!(
                (v - float).abs() < 2.0 * 2e-6,
                "r={r} age={age}: {v} vs {float}"
            );
        }
    }
}
