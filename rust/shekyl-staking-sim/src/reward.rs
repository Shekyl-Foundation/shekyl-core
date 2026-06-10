//! Reward computation: the model under test.
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
use shekyl_archival_retention::{curve_milli, BandedCurveParams, WORK_MILLI_SCALE};

/// Reward curve evaluation backend (PR 1.5: integer imports canonical crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CurveImpl {
    #[default]
    Float,
    Integer,
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
    /// Float sim path vs `shekyl-archival-retention::reward_arithmetic` (minting code).
    pub curve_impl: CurveImpl,
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
/// Work input at which `Curve` reaches its plateau credited value (`p.cap`).
fn plateau_work(p: &RewardParams) -> f64 {
    if p.cap <= 0.0 {
        return 0.0;
    }
    p.cap * 2.0
}

/// Credited work via banded PL `Curve` (REWARD_EMISSION_LEG.md §4.0 form C).
#[must_use]
pub fn curve(work: f64, p: &RewardParams) -> f64 {
    match p.curve_impl {
        CurveImpl::Float => curve_banded(work, p.cap),
        CurveImpl::Integer => {
            let cap_milli = (p.cap * WORK_MILLI_SCALE as f64).round() as u64;
            let params = BandedCurveParams::from_sim_cap_milli(cap_milli);
            let work_milli = (work * WORK_MILLI_SCALE as f64).round() as u64;
            curve_milli(work_milli, &params) as f64 / WORK_MILLI_SCALE as f64
        }
    }
}

/// Returns `(effective_capped_work, pseudonym_count, split_cost)`.
fn split_decision(raw_work: f64, price: f64, p: &RewardParams) -> (f64, usize, f64) {
    let single = curve(raw_work, p);
    let pw = plateau_work(p);
    if raw_work <= pw || p.cap <= 0.0 {
        return (single, 1, 0.0);
    }
    let m_full = (raw_work / pw).ceil().max(1.0) as usize;
    let per = raw_work / m_full as f64;
    let multi: f64 = (0..m_full).map(|_| curve(per, p)).sum();
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
}

/// Evaluate rewards for the whole world. `price_hint` seeds the split decision
/// (price = budget / Σ capped_work is itself a function of splitting, so we use the
/// previous epoch's price as the hint and recompute the realized price here; across
/// epochs this converges — no inner fixed point).
pub fn evaluate(world: &World, p: &RewardParams, price_hint: f64) -> RewardEval {
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
    }
}
