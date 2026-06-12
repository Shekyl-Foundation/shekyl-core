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
//! posted deep-shard bonds `Σ bond(age) ≤ capital` (the per-shard retention bond —
//! the keystone Sybil/deep-history lever). The bond is flat (`bond_rate` per deep
//! shard) when `bond_age_scale = 0` and age-scaled otherwise (older shards cost
//! more capital to bond — L4). `price` is the previous epoch's work→reward exchange
//! rate, carrying the competitive-share servo's dilution into the marginal decision.

use crate::model::Rng;
use crate::model::{bond_age, bond_duration, fetch_latency, g_age, World};

#[derive(Debug, Clone)]
pub struct AgentParams {
    /// Flow cost per held shard (storage/bandwidth). Stops agents from holding
    /// everything when marginal reward is ~0.
    pub storage_unit_cost: f64,
    /// Capital locked per deep-history shard (the swept bond rate: low/mid/high).
    /// `0` disables the bond (the toothless-cap baseline).
    pub bond_rate: f64,
    /// Age-scaling of the bond *magnitude* (L4). Resolved to `0` (flat) — kept as a
    /// parameter only so the 1c counter-evidence sweeps remain reproducible.
    pub bond_age_scale: f64,
    /// Flow opportunity cost of capital locked in one deep-shard bond.
    pub bond_carry: f64,
    /// `age ≥ deep_threshold` ⇒ deep history ⇒ requires a bond.
    pub deep_threshold: f64,
    /// Storage units a deep shard occupies (L8 storage leg / gate-5 granularity lever).
    /// `1.0` = iteration-1 behavior (every shard costs one unit).
    pub deep_shard_size: f64,
    // --- L9 duration axis (iteration 2; inert when `bond_dur_base == 0`) ---
    /// Flat retention-commitment horizon in epochs.
    pub bond_dur_base: f64,
    /// Age-scaling of the commitment horizon: `> 0` ⇒ older shards lock longer.
    pub bond_dur_age_scale: f64,
    /// Anticipation of the lock's opportunity cost. `0` = myopic (acquires on
    /// present net value, ignoring the future commitment — so duration damps churn
    /// but never suppresses participation). `> 0` = forward-looking: a longer lock
    /// deters *acquisition* of long-duration (old) shards, surfacing the willingness
    /// ceiling the spec pre-committed to testing under anticipatory agents.
    pub lock_anticipation: f64,
    // --- L10 backfill-lag axis (iteration 3; inert when `fetch_latency_per_unit == 0`) ---
    /// Epochs of fetch per storage unit over the anonymizing transport (the
    /// post-testnet measurement). A deep shard takes `round(deep_shard_size · this)`
    /// epochs to seat after acquisition; during the fetch it is committed (storage +
    /// bond) but not serving. `0` ⇒ instant seating ⇒ capacity-bound iteration-1/2.
    pub fetch_latency_per_unit: f64,
    /// Max *fresh* deep-shard fetches an actor may start per epoch (bandwidth bound).
    /// `0` = unlimited (the default; fetch latency alone carries the lag).
    pub acq_rate: usize,
    /// **Foundation re-seed bandwidth** (swan-4): network-wide cap on fresh deep
    /// acquisitions per epoch of shards with **zero serving market holders** — those
    /// fetches must source from the foundation complete-tree seeds (the retention
    /// guarantee makes them the source of last resort; few seats ⇒ serialized
    /// seeding). `0` = unlimited (legacy sourceless-instant behavior, byte-identical).
    /// Market-sourced fetches (≥1 serving holder) are never throttled by this knob.
    pub reseed_rate: usize,
}

/// One actor's best-response. Mutates `world.holdings[actor]` (and `world.locks`).
// Several loops index parallel collections (holdings, locks, r, shards) by `s`;
// enumerate over one is no cleaner than the range loop.
// `sole_source`: epoch-start serving replication + the epoch's shared foundation
// re-seed budget (swan-4); `None` when `reseed_rate == 0` (unlimited, legacy).
#[allow(clippy::needless_range_loop)]
fn best_response(
    world: &mut World,
    actor: usize,
    price: f64,
    ap: &AgentParams,
    age_weight: f64,
    sole_source: Option<&[usize]>,
    reseed_budget: &mut usize,
) {
    let n_shard = world.shards.len();
    let r = world.replication();
    let cap_storage = world.actors[actor].storage_capacity;
    let capital = world.actors[actor].capital;
    let bonded = ap.bond_rate > 0.0;
    let was_held = world.holdings[actor].clone();

    let bond_cost = |age: f64| -> f64 {
        if bonded {
            bond_age(age, ap.bond_rate, ap.bond_age_scale, ap.deep_threshold)
        } else {
            0.0
        }
    };

    // Forced set: deep shards under an unexpired retention commitment cannot be
    // dropped (the L9 lock), so they are retained regardless of present net value.
    let cap_storage = cap_storage as f64;
    // Storage a shard occupies: deep shards cost `deep_shard_size` units (the L8 storage
    // leg / granularity lever); hot shards cost one unit.
    let stor_cost = |deep: bool| if deep { ap.deep_shard_size } else { 1.0 };

    let mut new_held = vec![false; n_shard];
    let mut used_storage = 0.0f64;
    let mut used_bond = 0.0f64;
    for s in 0..n_shard {
        if world.locks[actor][s] > 0 && world.holdings[actor][s] {
            new_held[s] = true;
            let deep = world.shards[s].is_deep(ap.deep_threshold);
            used_storage += stor_cost(deep);
            if deep {
                used_bond += bond_cost(world.shards[s].age);
            }
        }
    }

    // Net marginal value of the remaining (unlocked) shards.
    let mut ranked: Vec<(usize, f64, bool, f64)> = Vec::with_capacity(n_shard);
    for s in 0..n_shard {
        if new_held[s] {
            continue; // already forced in
        }
        let held = world.holdings[actor][s];
        // If already held, R already counts me; else adding me makes R+1.
        let r_eff = if held { r[s].max(1) } else { r[s] + 1 };
        let age = world.shards[s].age;
        let deep = world.shards[s].is_deep(ap.deep_threshold);
        let value = price * (1.0 / r_eff as f64) * g_age(age, age_weight);
        let mut cost = ap.storage_unit_cost + if deep { ap.bond_carry } else { 0.0 };
        // Anticipatory lock cost: acquiring a deep shard commits storage for its
        // (age-scaled) duration, foregone if value later drops. Charged only on a
        // *fresh* acquisition (not already held), proportional to the horizon — so
        // it deters long-duration (old) shards specifically (the willingness ceiling).
        if deep && !held && ap.lock_anticipation > 0.0 {
            let dur = bond_duration(age, ap.bond_dur_base, ap.bond_dur_age_scale) as f64;
            cost += ap.lock_anticipation * dur * ap.storage_unit_cost;
        }
        ranked.push((s, value - cost, deep, bond_cost(age)));
    }
    // Highest net first.
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Greedily fill remaining budget with positive-net shards. `fresh_fetches` counts
    // new deep acquisitions started this epoch, capped by `acq_rate` (bandwidth bound;
    // 0 = unlimited).
    let mut fresh_fetches = 0usize;
    for (s, net, deep, bond) in ranked {
        if net <= 0.0 {
            break;
        }
        // Storage budget: deep shards may cost >1 unit, so skip-and-continue (a smaller
        // hot shard may still fit) rather than break.
        if used_storage + stor_cost(deep) > cap_storage {
            continue;
        }
        // Capital budget on posted bonds. Skip shards whose bond would overrun
        // remaining capital; keep scanning (a cheaper deep shard may fit).
        if deep && bonded && used_bond + bond > capital {
            continue;
        }
        // Acquisition-rate bound (L10): a *fresh* deep fetch (not already held) consumes
        // one of the epoch's fetch slots. Held-through deep shards re-selected here are
        // free (no new fetch). Hot shards are unthrottled (seat instantly).
        let fresh_deep = deep && !was_held[s];
        if fresh_deep && ap.acq_rate > 0 && fresh_fetches >= ap.acq_rate {
            continue;
        }
        // Foundation re-seed bound (swan-4): a fresh deep fetch of a shard with zero
        // serving market holders at epoch start must source from the foundation seeds
        // and consumes one of the epoch's shared re-seed slots; budget exhausted ⇒ the
        // seat defers to a later epoch. (The epoch-start snapshot means same-epoch
        // concurrent fetches of one sole-source shard each consume a slot — they all
        // hit the foundation.) Market-sourced fetches are untouched.
        if fresh_deep {
            if let Some(serving0) = sole_source {
                if serving0[s] == 0 {
                    if *reseed_budget == 0 {
                        continue;
                    }
                    *reseed_budget -= 1;
                }
            }
        }
        new_held[s] = true;
        used_storage += stor_cost(deep);
        if deep && bonded {
            used_bond += bond;
        }
        if fresh_deep {
            fresh_fetches += 1;
        }
    }

    // Arm retention commitments on *fresh* deep acquisitions (false→true). Held-through
    // shards keep their counting-down lock; this is what makes duration damp churn.
    if ap.bond_dur_base > 0.0 {
        for s in 0..n_shard {
            if new_held[s] && !was_held[s] && world.shards[s].is_deep(ap.deep_threshold) {
                world.locks[actor][s] =
                    bond_duration(world.shards[s].age, ap.bond_dur_base, ap.bond_dur_age_scale);
            }
        }
    }

    // L10 backfill lag: start the fetch clock on *fresh* deep acquisitions (committed
    // but not serving until it seats); held-through shards keep their counting-down
    // fetch; dropped/unheld shards clear to 0. Inert when `fetch_latency_per_unit == 0`.
    for s in 0..n_shard {
        let deep = world.shards[s].is_deep(ap.deep_threshold);
        if new_held[s] && !was_held[s] {
            world.inflight[actor][s] =
                fetch_latency(deep, ap.deep_shard_size, ap.fetch_latency_per_unit);
        } else if !new_held[s] {
            world.inflight[actor][s] = 0;
        }
        // held-through (new_held && was_held): leave inflight as-is (decremented by
        // advance_epoch each epoch until seated).
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

    // Only *active* actors best-respond (L11 endogenous participation). Inactive actors
    // hold nothing and earn nothing — they are potential entrants the free-entry layer
    // may admit. With the default all-active world (every pre-L11 scenario), this is the
    // full population in shuffled order, byte-identical to before.
    let mut order: Vec<usize> = (0..world.actors.len())
        .filter(|&a| world.active[a])
        .collect();
    rng.shuffle(&mut order);
    // Foundation re-seed budget (swan-4): shared across the epoch's best-responses,
    // against the epoch-start serving view. Inert (`None`) when `reseed_rate == 0`.
    let serving0 = if ap.reseed_rate > 0 {
        Some(world.serving_replication())
    } else {
        None
    };
    let mut reseed_budget = ap.reseed_rate;
    for a in order {
        best_response(
            world,
            a,
            price,
            ap,
            age_weight,
            serving0.as_deref(),
            &mut reseed_budget,
        );
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
