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

use crate::agent::{AgentParams, CarryShape};
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

/// Committed bond capital actor `a` has deployed = Σ over its held **bonded** shards
/// ([`AgentParams::bonds`]) of the (age-dependent) per-shard bond. This is the denominator of the participation
/// yield: capital actually at stake, not the actor's whole endowment (undeployed
/// capital is free to pursue the alternative, so it is not "lost to staking").
pub(crate) fn committed_bond_capital(world: &World, a: usize, ap: &AgentParams) -> f64 {
    if ap.bond_rate <= 0.0 {
        return 0.0;
    }
    let mut cap = 0.0;
    for (s, &held) in world.holdings[a].iter().enumerate() {
        if held && ap.bonds(&world.shards[s]) {
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

/// A slash exit (A18): production's slash burns the bond, so the actor's posted
/// bond capital leaves its endowment before it is deactivated. A bond still in
/// the release escrow from an earlier exit is slashable too (R10), and burns
/// with it. An actor that re-enters later bonds from what is left. Returns the
/// capital burned.
///
/// The sim's slash sites are the L17 shock exits: an operator that vanishes
/// stops serving, the failure window slashes every pair it held, and nobody
/// is left to post a `Release`. A voluntary exit is a `Release` and goes
/// through `World::deactivate` alone.
pub(crate) fn slash_exit(world: &mut World, a: usize, ap: &AgentParams) -> f64 {
    let burned = committed_bond_capital(world, a, ap) + world.released_capital(a);
    world.actors[a].capital = (world.actors[a].capital - burned).max(0.0);
    world.releasing[a].clear();
    world.deactivate(a);
    burned
}

/// Per-epoch flow cost for actor `a`: storage on every held shard, the carry
/// ([`CarryShape`]), and the split cost of any extra pseudonyms.
fn flow_cost(
    world: &World,
    a: usize,
    ap: &AgentParams,
    pseudonyms: usize,
    pp: &ParticipationParams,
) -> f64 {
    let mut shards = 0.0;
    let mut bonded = 0.0;
    for (s, &held) in world.holdings[a].iter().enumerate() {
        if held {
            shards += 1.0;
            if ap.bonds(&world.shards[s]) {
                bonded += 1.0;
            }
        }
    }
    let carry = match ap.carry {
        CarryShape::Split {
            capital_rate,
            operating_per_shard,
        } => capital_rate * committed_bond_capital(world, a, ap) + shards * operating_per_shard,
        CarryShape::FlatPerBond(per_bond) => bonded * per_bond,
    };
    shards * ap.storage_unit_cost
        + carry
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
/// capital. After `patience` consecutive strikes it exits with a `Release`
/// (`World::release_exit`): its bond waits `exit_cooldown_epochs` in the release
/// escrow. Call **after** `evaluate`.
///
/// `reservation_add` (L13) is a *uniform* additive bump to every active actor's
/// reservation — the **price-coupling / death-spiral channel**. The staking yield and
/// bond capital are both token-denominated, so a static token price cancels in the
/// `apr` ratio; what does *not* cancel is **expected depreciation**: if holders expect
/// the token to lose value against their outside numéraire, the opportunity cost of
/// keeping capital staked rises by that expected depreciation rate. The caller drives
/// `reservation_add` from a coverage-confidence signal (low coverage ⇒ loss of trust ⇒
/// expected depreciation ⇒ higher effective reservation ⇒ more exit ⇒ worse coverage),
/// closing the candidate loop. `0.0` ⇒ no coupling (legacy / non-fee-era).
///
/// `reservation_mult` (L17) is a *multiplicative* stress on every active actor's
/// reservation — the acute flight-to-liquidity channel (outside yields spike in a
/// crisis, so the opportunity cost of staked capital jumps as a factor, not a bump).
/// `1.0` ⇒ no stress (every pre-L17 scenario). It composes with `reservation_add`:
/// `apr < reservation · mult + add`.
///
/// `flow_cost_fiat`/`token_price` (L13 / P2) decide the **second death-spiral leg**.
/// `reward_a` and the bond are token-denominated, so they cancel in the ratio and only
/// *expected* depreciation (the `reservation_add` channel) bites — **if every term is
/// token-denominated**. But the operational flow cost (bandwidth, storage hardware) is
/// paid in fiat regardless of token price. When `flow_cost_fiat` is set, the flow cost
/// is divided by the token price before netting:
///
/// `apr = (reward_a − flow_cost_a / token_price) / committed_a = R/B − F/(B·p)`
///
/// so a *low static price* raises the real flow-cost drag and can force exit with **no
/// trust-loss trigger** (`reservation_add = 0`) — a level-driven ignition the
/// expectation channel does not model. `token_price = 1.0` ⇒ identical to the
/// token-denominated case; `flow_cost_fiat = false` ⇒ legacy (price never consulted).
// The exit rule composes one channel per crisis leg (trust bump, acute stress, fiat
// price); a parameter struct would only relocate the argument list.
#[allow(clippy::too_many_arguments)]
pub fn process_exits(
    world: &mut World,
    eval: &RewardEval,
    ap: &AgentParams,
    pp: &ParticipationParams,
    reservation_add: f64,
    reservation_mult: f64,
    flow_cost_fiat: bool,
    token_price: f64,
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
            let fcost = flow_cost(world, a, ap, eval.pseudonyms[a], pp);
            // Fiat flow cost (P2): the fiat burden in token terms rises as the price
            // falls. `token_price = 1.0` (and `!flow_cost_fiat`) reduce to the legacy net.
            let net = if flow_cost_fiat {
                eval.rewards[a] - fcost / token_price
            } else {
                eval.rewards[a] - fcost
            };
            let apr = net / committed;
            apr < world.actors[a].reservation * reservation_mult + reservation_add
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
        let bond = committed_bond_capital(world, a, ap);
        world.release_exit(a, bond, ap.exit_cooldown_epochs);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::BondScope;
    use crate::model::{Actor, Shard};
    use crate::scenarios::baseline;

    fn shard(age: f64) -> Shard {
        Shard { age }
    }

    /// A slash exit burns exactly the posted bond and deactivates; a
    /// voluntary exit (`deactivate` alone) leaves capital whole.
    #[test]
    fn a_slash_burns_the_posted_bond_and_a_release_does_not() {
        let ap = baseline().agent_params();
        let actor = Actor {
            storage_capacity: 4,
            capital: 20.0,
            is_whale: false,
            reservation: 0.0,
        };
        // Two deep shards and one hot shard held. Every held shard posts
        // `bond_rate` (the default scope), so the bond is three of them.
        let mut world = World::new(
            vec![shard(0.9), shard(0.6), shard(0.1)],
            vec![actor.clone(), actor],
        );
        for w in [0, 1] {
            world.holdings[w] = vec![true, true, true];
        }
        let burned = slash_exit(&mut world, 0, &ap);
        assert_eq!(burned, 3.0 * ap.bond_rate);
        assert_eq!(world.actors[0].capital, 20.0 - 3.0 * ap.bond_rate);
        assert!(!world.active[0]);
        world.deactivate(1);
        assert_eq!(world.actors[1].capital, 20.0);
    }

    /// A7: the default scope bonds the hot shard too; deep only does not.
    #[test]
    fn every_held_shard_scope_bonds_the_hot_shard() {
        let mut ap = baseline().agent_params();
        assert_eq!(ap.bond_scope, BondScope::EveryHeld);
        let actor = Actor {
            storage_capacity: 4,
            capital: 20.0,
            is_whale: false,
            reservation: 0.0,
        };
        let mut world = World::new(vec![shard(0.9), shard(0.6), shard(0.1)], vec![actor]);
        world.holdings[0] = vec![true, true, true];
        assert_eq!(committed_bond_capital(&world, 0, &ap), 3.0 * ap.bond_rate);
        ap.bond_scope = BondScope::DeepOnly;
        assert_eq!(committed_bond_capital(&world, 0, &ap), 2.0 * ap.bond_rate);
    }

    /// R10: a voluntary exit's bond waits the cooldown in the release escrow,
    /// is not spendable there, and burns if the actor is slashed before it
    /// clears. A cooldown of 0 refunds at once.
    #[test]
    fn a_release_escrows_the_bond_for_the_cooldown_and_stays_slashable() {
        let ap = baseline().agent_params();
        assert_eq!(
            ap.exit_cooldown_epochs,
            crate::model::RELEASE_COOLDOWN_EPOCHS
        );
        let actor = Actor {
            storage_capacity: 4,
            capital: 20.0,
            is_whale: false,
            reservation: 0.0,
        };
        let mut world = World::new(vec![shard(0.9), shard(0.1)], vec![actor.clone(), actor]);
        world.holdings[0] = vec![true, true];
        let bond = committed_bond_capital(&world, 0, &ap);
        world.release_exit(0, bond, 2);
        assert!(!world.active[0]);
        assert_eq!(world.released_capital(0), bond);
        assert_eq!(world.actors[0].capital, 20.0);
        // The start of the next epoch: still held. The one after: back.
        world.tick_releases();
        assert_eq!(world.released_capital(0), bond);
        world.tick_releases();
        assert_eq!(world.released_capital(0), 0.0);

        // Re-entered inside the cooldown and slashed: the escrow burns too.
        world.release_exit(0, bond, 2);
        world.active[0] = true;
        world.holdings[0] = vec![true, false];
        let posted = committed_bond_capital(&world, 0, &ap);
        let burned = slash_exit(&mut world, 0, &ap);
        assert_eq!(burned, posted + bond);
        assert_eq!(world.actors[0].capital, 20.0 - posted - bond);
        assert_eq!(world.released_capital(0), 0.0);

        // A cooldown of 0 (the registered arm) refunds at once.
        world.holdings[1] = vec![true, true];
        world.release_exit(1, 2.0 * ap.bond_rate, 0);
        assert_eq!(world.released_capital(1), 0.0);
    }

    /// A6: the split carry charges capital carry on the posted bond and the
    /// operating cost on every held shard; the registered flat carry charges
    /// one amount per bonded shard. At the baseline's 2.0 the split's capital
    /// carry is exactly the registered 0.03, in `f64`.
    #[test]
    fn the_split_carry_scales_with_the_bond() {
        let split = CarryShape::Split {
            capital_rate: 0.015,
            operating_per_shard: 0.002,
        };
        assert_eq!(split.per_shard(true, 2.0), 0.015 * 2.0 + 0.002);
        assert_eq!(split.per_shard(true, 0.75), 0.015 * 0.75 + 0.002);
        assert_eq!(split.per_shard(false, 2.0), 0.002);
        let flat = CarryShape::FlatPerBond(0.03);
        assert_eq!(flat.per_shard(true, 0.75), 0.03);
        assert_eq!(flat.per_shard(false, 2.0), 0.0);
        assert_eq!(
            crate::scenarios::BASELINE_CAPITAL_CARRY_RATE * crate::scenarios::BASELINE_BOND_RATE,
            crate::scenarios::BASELINE_BOND_CARRY
        );
    }
}
