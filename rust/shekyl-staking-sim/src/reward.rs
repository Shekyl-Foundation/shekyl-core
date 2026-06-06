//! Reward computation: the model under test.
//!
//! `work_P = Σ_{shards held} (1/R(shard)) · g(age(shard))` (age-weighted scarcity),
//! then a per-pseudonym **banded plateau-cap** on work, then the competitive-share
//! **`Σwork` servo** `reward_P = budget · capped_work_P / Σ capped_work`.
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

use crate::model::{g_age, World};

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
}

/// Raw (uncapped) work for one actor, given current replication counts.
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
/// Returns `(effective_capped_work, pseudonym_count, split_cost)`.
fn split_decision(raw_work: f64, price: f64, p: &RewardParams) -> (f64, usize, f64) {
    if raw_work <= p.cap || p.cap <= 0.0 {
        return (raw_work.min(if p.cap > 0.0 { p.cap } else { raw_work }), 1, 0.0);
    }
    // Value of fully crediting the over-cap work vs. running one capped pseudonym.
    let recovered = raw_work - p.cap; // work beyond a single pseudonym's cap
    let gain = recovered * price;
    let m_full = (raw_work / p.cap).ceil().max(1.0);
    let split_cost = (m_full - 1.0) * p.pseudonym_cost;
    if gain > split_cost {
        (raw_work, m_full as usize, split_cost)
    } else {
        (p.cap, 1, 0.0)
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
}

/// Evaluate rewards for the whole world. `price_hint` seeds the split decision
/// (price = budget / Σ capped_work is itself a function of splitting, so we use the
/// previous epoch's price as the hint and recompute the realized price here; across
/// epochs this converges — no inner fixed point).
pub fn evaluate(world: &World, p: &RewardParams, price_hint: f64) -> RewardEval {
    let r = world.replication();
    let n = world.actors.len();

    let raw: Vec<f64> = (0..n).map(|a| raw_work(world, a, &r, p.age_weight)).collect();

    let mut capped = vec![0.0; n];
    let mut pseudonyms = vec![1usize; n];
    for a in 0..n {
        let (eff, m, _cost) = split_decision(raw[a], price_hint, p);
        capped[a] = eff;
        pseudonyms[a] = m;
    }

    let sum_capped: f64 = capped.iter().sum();
    let price = if sum_capped > 0.0 {
        p.budget / sum_capped
    } else {
        0.0
    };

    RewardEval {
        r,
        pseudonyms,
        price,
    }
}
