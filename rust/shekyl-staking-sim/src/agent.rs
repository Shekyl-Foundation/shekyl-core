//! Agent behavior: myopic, share-reward-maximizing best-response under storage and
//! capital budgets.
//!
//! Each epoch, actors are processed in shuffled order (asynchronous / Gauss–Seidel:
//! `R` updates after each actor moves, which damps the simultaneous-update
//! oscillation that is the canonical myopia artifact — see the spec's
//! churn-stability pre-commitment). Each actor re-chooses its shard portfolio by
//! ranking shards on net marginal value:
//!
//! `net(s) = price · (1/R_eff(s)) · g(age(s)) − storage_unit_cost − [deep] bond_carry`
//!
//! and greedily filling under two budgets: total shards ≤ `storage_capacity`, and
//! deep shards ≤ `floor(capital / bond_rate)` (the per-shard retention bond — the
//! keystone Sybil/deep-history lever). `price` is the previous epoch's work→reward
//! exchange rate, carrying the competitive-share servo's dilution into the marginal
//! decision.

use crate::model::{g_age, World};
use crate::model::Rng;

#[derive(Debug, Clone)]
pub struct AgentParams {
    /// Flow cost per held shard (storage/bandwidth). Stops agents from holding
    /// everything when marginal reward is ~0.
    pub storage_unit_cost: f64,
    /// Capital locked per deep-history shard (the swept bond rate: low/mid/high).
    /// `0` disables the bond (the toothless-cap baseline).
    pub bond_rate: f64,
    /// Flow opportunity cost of capital locked in one deep-shard bond.
    pub bond_carry: f64,
    /// `age ≥ deep_threshold` ⇒ deep history ⇒ requires a bond.
    pub deep_threshold: f64,
}

impl AgentParams {
    /// Max deep shards this actor can bond given its capital.
    fn max_deep(&self, capital: f64, storage_capacity: usize) -> usize {
        if self.bond_rate > 0.0 {
            (capital / self.bond_rate).floor().max(0.0) as usize
        } else {
            storage_capacity
        }
    }
}

/// One actor's myopic best-response. Mutates `world.holdings[actor]`.
fn best_response(
    world: &mut World,
    actor: usize,
    price: f64,
    ap: &AgentParams,
    age_weight: f64,
) {
    let n_shard = world.shards.len();
    let r = world.replication();
    let cap_storage = world.actors[actor].storage_capacity;
    let cap_deep = ap.max_deep(world.actors[actor].capital, cap_storage);

    // Net marginal value of holding each shard (using the R that would result).
    let mut ranked: Vec<(usize, f64, bool)> = Vec::with_capacity(n_shard);
    // Indexes three parallel collections (holdings, r, shards) by `s`; enumerate
    // over one is no cleaner than the range loop here.
    #[allow(clippy::needless_range_loop)]
    for s in 0..n_shard {
        let held = world.holdings[actor][s];
        // If already held, R already counts me; else adding me makes R+1.
        let r_eff = if held { r[s].max(1) } else { r[s] + 1 };
        let deep = world.shards[s].is_deep(ap.deep_threshold);
        let value = price * (1.0 / r_eff as f64) * g_age(world.shards[s].age, age_weight);
        let cost = ap.storage_unit_cost + if deep { ap.bond_carry } else { 0.0 };
        let net = value - cost;
        ranked.push((s, net, deep));
    }
    // Highest net first.
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Greedily fill under both budgets; only positive-net shards.
    let mut new_held = vec![false; n_shard];
    let mut used_storage = 0usize;
    let mut used_deep = 0usize;
    for (s, net, deep) in ranked {
        if net <= 0.0 {
            break;
        }
        if used_storage >= cap_storage {
            break;
        }
        if deep && used_deep >= cap_deep {
            continue;
        }
        new_held[s] = true;
        used_storage += 1;
        if deep {
            used_deep += 1;
        }
    }
    world.holdings[actor] = new_held;
}

/// Run one epoch of asynchronous best-response. Returns the per-actor holding-set
/// change count (for churn metrics).
pub fn run_epoch(
    world: &mut World,
    price: f64,
    ap: &AgentParams,
    age_weight: f64,
    rng: &mut Rng,
) -> usize {
    let before: Vec<Vec<bool>> = world.holdings.clone();

    let mut order: Vec<usize> = (0..world.actors.len()).collect();
    rng.shuffle(&mut order);
    for a in order {
        best_response(world, a, price, ap, age_weight);
    }

    // Total (actor, shard) holding flips this epoch.
    let mut changes = 0usize;
    for (a, held_before) in before.iter().enumerate() {
        for (s, &b) in held_before.iter().enumerate() {
            if b != world.holdings[a][s] {
                changes += 1;
            }
        }
    }
    changes
}
