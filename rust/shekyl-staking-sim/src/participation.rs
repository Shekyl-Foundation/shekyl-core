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

/// **Foundation floor** (L12): the number of deep-shard replicas the foundation runs
/// as a *bootstrap* coverage guarantee, decaying as the staker population thickens.
///
/// L5/L6 framed the floor as a thin-period backstop; bootstrapping reframes it as the
/// **genesis coverage guarantee that backs off on a population-indexed schedule** —
/// foundation holds the line until the market can, then withdraws (per
/// `75-system-autonomy.mdc`: population-adaptive, no manual reset). The schedule is a
/// linear decay in the bonded-archiver population `pop`:
///
/// `floor(pop) = round( floor0 · max(0, 1 − pop / decay_pop) )`
///
/// so `pop = 0 ⇒ floor0` (full genesis backstop) and `pop ≥ decay_pop ⇒ 0` (the market
/// is deemed thick enough; foundation withdraws). `decay_pop` is the population at which
/// the floor reaches zero — set near the emergent steady-state bonded-archiver count so
/// the floor is ≈0 in steady state and re-engages adaptively only if the population dips
/// (the backstop property). `floor0 = 0` or `decay_pop ≤ 0` ⇒ no floor (legacy / the
/// pure-market read).
///
/// **The floor is invisible to the reward servo by construction.** Foundation replicas
/// are separately funded (not paid from `budget`) and are *not* counted in the staker
/// reward `R`/`Σwork` — they add retrieval coverage only. So the floor backstops
/// availability **without** raising on-shard `R` (which would lower the `1/R` staker
/// reward and crowd out the very entry the bootstrap needs). The market keeps its full
/// reason to come; the floor only guarantees the chain is retrievable while it does.
pub fn foundation_floor(pop: usize, floor0: usize, decay_pop: f64) -> usize {
    if floor0 == 0 || decay_pop <= 0.0 {
        return 0;
    }
    let frac = (1.0 - pop as f64 / decay_pop).max(0.0);
    (floor0 as f64 * frac).round() as usize
}

/// **Age-stratified floor (P3).** The uniform `foundation_floor` adds the same backstop to
/// every deep shard; P3 (and L13 finding 2 / L15) show the **oldest band fails first** — it
/// is the most irreplaceable *and* the thinnest in replicas and domain diversity. This tilts
/// the floor **oldest-ward, mean-preserving**: a deep shard at normalized age `age` (with
/// `deep_threshold ≤ age ≤ 1`) gets `floor_uniform · (1 + tilt·(2x − 1))` replicas, where
/// `x = (age − deep_threshold)/(1 − deep_threshold) ∈ [0,1]`. So the just-deep shoulder
/// (`x=0`) gets `floor_uniform·(1−tilt)` and the oldest tail (`x=1`) gets
/// `floor_uniform·(1+tilt)`; the mean over a uniform deep-age distribution is unchanged —
/// the **same total foundation cost, reallocated to the irreplaceable tail** (the same
/// mean-preserving shape the L4 bond-age tilt used, applied to the backstop instead of the
/// bond). `tilt = 0` ⇒ uniform (byte-identical to `foundation_floor`). Mirrors `R_target(age)`
/// tilting redundancy toward the deep, one level deeper into the irreplaceable tail.
pub fn foundation_floor_aged(
    pop: usize,
    floor0: usize,
    decay_pop: f64,
    tilt: f64,
    age: f64,
    deep_threshold: f64,
) -> usize {
    let base = foundation_floor(pop, floor0, decay_pop);
    if base == 0 || tilt == 0.0 {
        return base;
    }
    let span = (1.0 - deep_threshold).max(f64::EPSILON);
    let x = ((age - deep_threshold) / span).clamp(0.0, 1.0);
    let factor = 1.0 + tilt * (2.0 * x - 1.0);
    (base as f64 * factor).round().max(0.0) as usize
}
