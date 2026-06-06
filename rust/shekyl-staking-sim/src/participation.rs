//! Endogenous participation (L11): the economic layer that makes the *operating
//! point emerge* instead of being tuned via an exogenous `budget`.
//!
//! Every prior iteration fixed the archiver population (`n_actors`) and tuned `budget`
//! so coverage landed at `R_target` — the "lean equilibrium" was *asserted*. Here the
//! population is a *pool of potential entrants*; free entry/exit is governed by
//! **risk-adjusted yield vs. reservation**:
//!
//! `apr_a = (reward_a − flow_costs_a) / committed_bond_capital_a`
//!
//! where `reward_a` is the realized servo share (`reward.rs`), `flow_costs_a` is the
//! per-epoch storage + bond-carry + pseudonym-split cost, and the denominator is the
//! capital the actor has actually deployed into deep-shard bonds. An actor stays a
//! bonded archiver only while `apr_a ≥ reservation_a` (its opportunity cost); it also
//! exits if it deploys *no* bond capital (it came to stake and couldn't — idle capital
//! pursues its alternative). Exit is hysteretic (a `patience` window) to damp
//! thrashing, mirroring the async-update damping the shard game uses.
//!
//! The dynamic is **trickle-entry + realized-yield-exit**: each epoch a bounded number
//! of inactive actors are admitted (capital arrives at a finite rate); admitted actors
//! best-respond and earn; those that cannot clear their reservation leave after the
//! patience window. As the population grows, the `Σwork` servo dilutes the share-price,
//! realized `apr` falls, and exit balances entry — the population converges to the
//! marginal-archiver-breaks-even point **without expectations** (profitable entrants
//! stay, unprofitable ones leave). Coverage at that emergent point is then *read*, not
//! tuned: the L11 question is whether free entry self-provisions to `R_target`.

use crate::agent::AgentParams;
use crate::model::{bond_age, World};
use crate::reward::RewardEval;

#[derive(Debug, Clone)]
pub struct ParticipationParams {
    /// Inactive actors admitted per epoch (the rate capital arrives — a bandwidth on
    /// entry, not an instantaneous jump). `0` with an all-active start ⇒ the fixed
    /// population is never trimmed *or* grown, i.e. legacy behavior.
    pub entry_per_epoch: usize,
    /// Consecutive sub-reservation (or zero-bond) epochs before an active actor exits.
    /// Hysteresis: a single bad epoch does not evict a committed archiver.
    pub patience: u32,
    /// Operational cost per pseudonym (mirrors `RewardParams::pseudonym_cost`): the
    /// flow cost of running `pseudonyms − 1` extra firewalled identities, charged
    /// against the actor's net yield.
    pub pseudonym_cost: f64,
}

/// Committed bond capital actor `a` has deployed = Σ over its held **deep** shards of
/// the (age-dependent) per-shard bond. This is the denominator of the participation
/// yield: capital actually at stake, not the actor's whole endowment (undeployed
/// capital is free to pursue the alternative, so it is not "lost to staking").
fn committed_bond_capital(world: &World, a: usize, ap: &AgentParams) -> f64 {
    if ap.bond_rate <= 0.0 {
        return 0.0;
    }
    let mut cap = 0.0;
    for (s, &held) in world.holdings[a].iter().enumerate() {
        if held && world.shards[s].is_deep(ap.deep_threshold) {
            cap += bond_age(
                world.shards[s].age,
                ap.bond_rate,
                ap.bond_age_scale,
                ap.deep_threshold,
            );
        }
    }
    cap
}

/// Per-epoch flow cost for actor `a`: storage on every held shard, bond-carry on each
/// deep shard, and the split cost of any extra pseudonyms.
fn flow_cost(
    world: &World,
    a: usize,
    ap: &AgentParams,
    pseudonyms: usize,
    pp: &ParticipationParams,
) -> f64 {
    let mut shards = 0.0;
    let mut deep = 0.0;
    for (s, &held) in world.holdings[a].iter().enumerate() {
        if held {
            shards += 1.0;
            if world.shards[s].is_deep(ap.deep_threshold) {
                deep += 1.0;
            }
        }
    }
    shards * ap.storage_unit_cost
        + deep * ap.bond_carry
        + (pseudonyms.saturating_sub(1)) as f64 * pp.pseudonym_cost
}

/// Admit up to `entry_per_epoch` currently-inactive actors (lowest index first, so the
/// dynamic is deterministic/reproducible). Newly admitted actors start with empty
/// holdings and will best-respond this epoch. Call **before** `run_epoch`.
pub fn admit_entrants(world: &mut World, pp: &ParticipationParams) {
    let mut admitted = 0usize;
    for a in 0..world.actors.len() {
        if admitted >= pp.entry_per_epoch {
            break;
        }
        if !world.active[a] {
            world.active[a] = true;
            world.below_streak[a] = 0;
            admitted += 1;
        }
    }
}

/// Process exits after the epoch's reward is known. An active actor's realized yield
/// `apr = (reward − flow_cost) / committed_bond_capital` is compared to its
/// reservation; it accrues a strike if `apr < reservation` *or* it deployed no bond
/// capital. After `patience` consecutive strikes it exits (`World::deactivate`). Call
/// **after** `evaluate`.
pub fn process_exits(
    world: &mut World,
    eval: &RewardEval,
    ap: &AgentParams,
    pp: &ParticipationParams,
) {
    let n = world.actors.len();
    let mut to_exit: Vec<usize> = Vec::new();
    for a in 0..n {
        if !world.active[a] {
            continue;
        }
        let committed = committed_bond_capital(world, a, ap);
        let strike = if committed <= 0.0 {
            // Deployed no capital — came to stake, couldn't. Idle capital exits.
            true
        } else {
            let net = eval.rewards[a] - flow_cost(world, a, ap, eval.pseudonyms[a], pp);
            let apr = net / committed;
            apr < world.actors[a].reservation
        };
        if strike {
            world.below_streak[a] += 1;
            if world.below_streak[a] >= pp.patience {
                to_exit.push(a);
            }
        } else {
            world.below_streak[a] = 0;
        }
    }
    for a in to_exit {
        world.deactivate(a);
    }
}

/// Count of currently-active actors holding at least one deep shard with a posted bond
/// — the *bonded archiver* population, which is what sets deep coverage (the emergent
/// L11 headline, distinct from raw active count).
pub fn bonded_active_count(world: &World, ap: &AgentParams) -> usize {
    (0..world.actors.len())
        .filter(|&a| world.active[a] && committed_bond_capital(world, a, ap) > 0.0)
        .count()
}
