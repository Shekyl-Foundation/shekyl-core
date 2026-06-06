//! Scenario construction, the epoch loop, and the iteration-1 sweep set.
//!
//! Sweeps (per the spec): coarse bond rate (low/mid/high), age-weight `g(age)`
//! including the `g=1` baseline, population thickness, endowment mix + whale, curve
//! shape (cap height), and shard-age distribution. The set below is curated
//! one-axis sweeps off a baseline plus the whale×bond cross — not the full Cartesian
//! product — to keep runtime bounded while exercising each axis.

use crate::agent::{run_epoch, AgentParams};
use crate::audit::{challenge_needed, deterrence_threshold, read_prob};
use crate::metrics::{
    churn_rate, coverage, coverage_with_r, CoverageMetrics, TargetParams, N_BANDS,
};
use crate::model::{r_target, Actor, Rng, Shard, World};
use crate::participation::{
    admit_entrants, bonded_active_count, foundation_floor_aged, process_exits, ParticipationParams,
};
use crate::retrieval::{r_target_for_availability, serving_availability};
use crate::reward::{evaluate, RewardParams};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct SimConfig {
    pub name: String,
    pub axis: String,

    // world
    pub n_shard: usize,
    pub n_actors: usize,
    /// `age = u^age_skew`, u~U(0,1): >1 hot-heavy, <1 deep-heavy, =1 uniform.
    pub age_skew: f64,

    /// Multiplies every actor's storage capacity (the provisioning axis). 1.0 =
    /// baseline; >1 = more aggregate storage (tests whether margin findings are
    /// structural or thin-baseline artifacts).
    pub storage_scale: f64,

    // endowment mix
    pub frac_storage_rich: f64,
    pub storage_rich_storage: usize,
    pub storage_rich_capital: f64,
    pub capital_rich_storage: usize,
    pub capital_rich_capital: f64,
    pub whale: bool,
    pub whale_storage: usize,
    pub whale_capital: f64,

    // reward / agent params
    pub budget: f64,
    pub cap: f64,
    pub pseudonym_cost: f64,
    pub age_weight: f64,
    pub storage_unit_cost: f64,
    pub bond_rate: f64,
    /// Age-scaling of the bond (L4): 0 = flat, >0 = older shards bond higher.
    pub bond_age_scale: f64,
    pub bond_carry: f64,
    pub deep_threshold: f64,
    /// Storage units a deep shard occupies (L8 storage leg / gate-5 granularity lever).
    /// `1.0` = iteration-1 behavior; the (bond × shard-size) pair sweep varies it.
    pub deep_shard_size: f64,

    // L9 duration axis + dynamic world (iteration 2; inert when `!dynamic`).
    /// Dynamic frontier-window: shards age each epoch and recycle at age 1.
    pub dynamic: bool,
    /// Age advance per epoch (only used when `dynamic`).
    pub epoch_aging: f64,
    /// Flat retention-commitment horizon (epochs). `0` disables duration locks.
    pub bond_dur_base: f64,
    /// Age-scaling of the commitment horizon (older ⇒ longer).
    pub bond_dur_age_scale: f64,
    /// Anticipation of the lock cost (0 = myopic; >0 = willingness ceiling).
    pub lock_anticipation: f64,

    // L10 backfill-lag axis (iteration 3; inert when `fetch_latency_per_unit == 0`).
    /// Epochs of deep-shard fetch per storage unit over the anonymizing transport.
    pub fetch_latency_per_unit: f64,
    /// Max fresh deep fetches per actor per epoch (0 = unlimited bandwidth).
    pub acq_rate: usize,

    // L11 endogenous-participation axis (iteration 3; inert when `!endogenous`).
    /// Free entry/exit on. When off, the population is fixed at `n_actors` all-active —
    /// every pre-L11 scenario, byte-identical.
    pub endogenous: bool,
    /// Fraction of the `n_actors` pool active at `t=0`. Run `0.0` (fill-up, bootstrap-
    /// like) and `1.0` (trim-down) to show the operating point is an *attractor*
    /// independent of initialization.
    pub init_active_frac: f64,
    /// Inactive actors admitted per epoch (rate capital arrives).
    pub entry_per_epoch: usize,
    /// Consecutive sub-reservation (or zero-bond) epochs before an active actor exits.
    pub participation_patience: u32,
    /// Reservation yield (opportunity cost of staking capital, per epoch) drawn uniform
    /// in `[reservation_lo, reservation_hi]` per actor (heterogeneous alternatives;
    /// `lo == hi` ⇒ homogeneous). Compared to realized `apr = net reward / committed bond`.
    pub reservation_lo: f64,
    pub reservation_hi: f64,

    // L12 bootstrap / cold-start axis (iteration 3; inert when `!bootstrap`).
    /// Growing frontier window: start from a small genesis core and append shards as the
    /// chain produces blocks, so deep history accrues *from zero* (vs. the steady-state
    /// `dynamic` window that recycles a full set in place). Requires `dynamic` (shards
    /// must age for deep history to form) and is meant to run `endogenous` (entry tracks
    /// the growing deep incentive). Off ⇒ the window is full at `t=0` (every prior
    /// scenario), byte-identical.
    pub bootstrap: bool,
    /// Genesis shard count — the chain at `t=0` (a handful of hot blocks). The window
    /// grows from here toward `n_shard`.
    pub n_shard_genesis: usize,
    /// Shards appended per epoch (the block-production / chain-growth rate) until the
    /// window reaches `n_shard`, after which the steady-state recycle holds it.
    pub shard_growth_per_epoch: usize,
    /// **Foundation floor** (L12): deep-shard replicas the foundation runs at genesis as
    /// the bootstrap coverage guarantee, decaying linearly to zero as the bonded-archiver
    /// population reaches `floor_decay_pop`. `0` ⇒ no floor (the pure-market read showing
    /// the unbacked transient gap). Counts toward retrieval coverage only, never the
    /// reward servo (see `participation::foundation_floor`).
    pub floor_replicas: usize,
    /// Bonded-archiver population at which the foundation floor reaches zero (it withdraws
    /// once the market is this thick). Set near the emergent steady-state archiver count.
    pub floor_decay_pop: f64,

    // L13 fee-era / sustainability axis (mission timeframe 2; inert when `!fee_era`).
    /// As block subsidy → 0 the archival purse comes from fees / a bounded terminal
    /// subsidy. When on, the (base) `budget` decays geometrically toward `budget_floor`
    /// each epoch — the shrinking-subsidy stress. Off ⇒ `budget` is constant (every prior
    /// scenario), byte-identical.
    pub fee_era: bool,
    /// Per-epoch geometric decay of the base budget toward `budget_floor` (the subsidy
    /// halving / emission taper). `0.0` ⇒ no decay (budget at `budget_floor` forever if
    /// already there).
    pub budget_decay: f64,
    /// **Bounded terminal subsidy** (`00-mission.mdc` timeframe 2): the floor the base
    /// budget decays to. Coverage at this floor is the pure-terminal-subsidy read; if it
    /// is below the sustainable purse the market thins and the oldest tail goes under
    /// (the fee market / adaptive share / floor must close the gap).
    pub budget_floor: f64,
    /// **Adaptive archival reward-share servo** (`75-system-autonomy.mdc`, `burn.rs`
    /// template): when on, the effective purse is raised above the decayed base toward
    /// `budget_ceiling` in proportion to the observed deep retrieval shortfall — fees
    /// flow to archival automatically when coverage slips, no manual reset. Off ⇒ the
    /// purse is just the decayed base (the unmanaged read).
    pub adaptive_share: bool,
    /// Proportional gain of the adaptive servo: `budget_eff = base · (1 + gain · shortfall)`
    /// clamped to `[base, budget_ceiling]`.
    pub share_gain: f64,
    /// Fee-market capacity ceiling on the adaptive purse — the most fees *can* fund. If
    /// the sustainable purse exceeds this, the servo pins at the ceiling and coverage
    /// stays short: a **graceful loud failure** (the fee market cannot fund the deep
    /// history; a higher terminal subsidy or the foundation floor is required).
    pub budget_ceiling: f64,
    /// **Price-coupling / death-spiral strength.** A deep retrieval shortfall lifts every
    /// actor's effective reservation by `price_coupling · shortfall` (lost trust ⇒
    /// expected token depreciation ⇒ higher opportunity cost ⇒ more exit ⇒ worse
    /// coverage). `0.0` ⇒ no coupling. The L13 question is whether the adaptive servo
    /// damps this loop (bounded) or it runs away (priority-1 durability failure).
    pub price_coupling: f64,
    /// **Fiat flow cost (P2 / second death-spiral leg).** When on, the per-actor flow
    /// cost is fiat-denominated and divided by `token_price` in the exit APR
    /// (`apr = R/B − F/(B·p)`), so a low/falling price raises the real flow-cost drag and
    /// can force exit with **no** trust-loss trigger. Off ⇒ token-denominated flow cost
    /// (the price cancels; every pre-P2 scenario), byte-identical.
    pub flow_cost_fiat: bool,
    /// Initial token price (fiat per token) used when `flow_cost_fiat`. `1.0` ⇒ the fiat
    /// flow cost equals the token-denominated one (the cancellation case).
    pub token_price: f64,
    /// Per-epoch geometric decay of the token price toward `price_floor` — a *static*
    /// price decline independent of coverage trust (isolates the level channel from the
    /// expectation channel). `0.0` ⇒ constant price.
    pub price_decay: f64,
    /// Terminal token price the decay approaches.
    pub price_floor: f64,

    /// **Retrieval availability (L15).** When on, the sim scores not just coverage
    /// (`R ≥ R_target`) but realized *retrieval availability* `1 − (1−u)^d` per shard,
    /// where `d` is the count of distinct failure domains among a shard's serving
    /// holders. Surfaces the coverage≠retrieval gap and lets correlated failure
    /// (`retr_n_domains` small) erode a fully-covered deep set. Off ⇒ inert,
    /// byte-identical.
    pub retrieval_model: bool,
    /// Per-holder uptime `u` (probability a holder is serving in an outage realization).
    pub retr_uptime: f64,
    /// Target retrieval availability `A*` the deep set must clear (e.g. `0.999`). Used
    /// both to derive `R_target` and to score `retr_under_deep` (deep shards below `A*`).
    pub retr_avail_target: f64,
    /// Failure-domain count for the correlated-failure bucketing (`a % n_domains`).
    /// `0` ⇒ each holder its own domain (independent / L4 best case); small values
    /// (1–6) model jurisdiction/ASN/implementation clustering.
    pub retr_n_domains: usize,

    /// **Proof-of-archival / free-rider audit (L14).** When on, the sim scores the
    /// non-productive (oversight-only) challenge traffic needed to keep free-riding
    /// unprofitable, *crediting real reads as proofs*. Surfaces that oversight collapses
    /// onto the cold/irreplaceable tail. Off ⇒ inert, byte-identical.
    pub audit_model: bool,
    /// Per-epoch real-read probability of the *hottest* shard (age 0). Reads decay with
    /// age at `read_decay` toward `read_cold`.
    pub read_hot: f64,
    /// Read-rate decay with normalized age (`read_hot · exp(−read_decay · age)`).
    pub read_decay: f64,
    /// Long-tail read floor — the per-epoch read probability the oldest shards approach
    /// (even ancient data is occasionally fetched).
    pub read_cold: f64,
    /// Free-rider per-epoch benefit (saved flow cost), normalized to the slash unit.
    pub freeride_benefit: f64,
    /// Free-rider penalty if caught (slashed bond), in the same unit as `freeride_benefit`.
    /// Deterrence threshold `a* = freeride_benefit / freeride_penalty`.
    pub freeride_penalty: f64,

    /// **Age-stratified floor tilt (P3).** Mean-preserving oldest-ward tilt of the
    /// foundation floor (and, in the fee-era, the terminal-subsidy backstop): the oldest
    /// deep shards get `floor·(1+tilt)`, the just-deep shoulder `floor·(1−tilt)`, same total
    /// cost. `0.0` ⇒ uniform floor (byte-identical). Protects the irreplaceable tail that
    /// fails first at both temporal ends (L12 hand-off, L13 thinning).
    pub floor_age_tilt: f64,

    // targets
    pub r_target_hot: f64,
    pub r_target_deep: f64,

    // run
    pub epochs: usize,
    pub churn_window: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubClaims {
    pub covered: bool,
    pub spread: bool,
    pub deep_history: bool,
    pub churn_stable: bool,
    pub all_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub name: String,
    pub axis: String,
    pub bond_rate: f64,
    pub age_weight: f64,
    pub cap: f64,
    pub n_actors: usize,
    pub whale: bool,
    pub final_metrics: CoverageMetrics,
    pub churn: f64,
    /// Churn rate restricted to the deepest age band (L9: the duration knob's target).
    /// This is the **abandonment-rate** (flips ÷ held), *not* a coverage-stability
    /// metric — high `oldest_churn` with zero coverage gap is benign rotation when the
    /// frontier backfills.
    pub oldest_churn: f64,
    /// **Oldest-band coverage oscillation** (L9 necessity): max oldest-band `frac_under`
    /// over the churn window — the coverage-instability diagnostic the churn sub-claim
    /// actually names. `> 0` under flat duration means abandonment is producing real
    /// coverage gaps (a holder drops with no replacement standing by); `→ 0` under
    /// age-scaled duration is direct necessity. At surplus this is ≈0 by construction
    /// (slack backfills), so it only discriminates at the lean equilibrium.
    pub oldest_under_max: f64,
    /// Variance of oldest-band `frac_under` over the churn window (oscillation amplitude).
    pub oldest_under_var: f64,
    /// **Serving** (retrieval-coverage) deep under-target fraction, windowed mean — the
    /// L10 *cost* axis. Counts only seated replicas (`serving_replication`), so the
    /// backfill lag depresses it below the committed `deep_frac_under_target`. Equals
    /// the committed value when `fetch_latency == 0`. The lock-in reallocation cost
    /// (confirmed in `bind_*`) shows here as a higher value under age-scaled duration.
    pub serving_deep_under: f64,
    /// **Committed** deep under-target fraction, windowed mean over the churn window —
    /// the steady-state read of the pure (lag-free) reallocation cost. This is the
    /// honest counterpart to `final_metrics.deep_frac_under_target` (a single final-epoch
    /// snapshot): the L10 reconciliation showed the `bind_*` "demonstrated cost" was a
    /// final-epoch artifact that this windowed mean dissolves, so the windowed mean is
    /// banked as a first-class number to keep the steady-state read the default one.
    pub committed_deep_under: f64,
    /// **Serving** oldest-band coverage oscillation — the L10 *benefit* axis: max seated
    /// oldest-band `frac_under` over the churn window. `> 0` is the timing-bound gap a
    /// drop-without-seated-replacement opens; age-scaled duration should *damp* it
    /// (fewer oldest drops ⇒ fewer in-flight gaps). The net L9 verdict weighs this
    /// reduction against the `serving_deep_under` increase.
    pub serving_oldest_under_max: f64,
    /// **Emergent active fraction** (L11): windowed-mean share of the `n_actors` pool
    /// that is active in steady state. With free entry/exit this is the equilibrium
    /// participation level the reservation-yield mechanism settles on, *not* an asserted
    /// constant. Flat at `1.0` for non-endogenous scenarios (fixed population).
    pub active_frac: f64,
    /// **Emergent bonded-archiver count** (L11): windowed-mean number of active actors
    /// actually holding bonded deep shards in steady state — the emergent size of the
    /// archiver set. The attractor check requires this converge to the same value from
    /// fill-up (`init_active_frac=0`) and trim-down (`init_active_frac=1`) starts.
    pub bonded_active: f64,
    /// **Bootstrap worst deep gap, unfloored** (L12): peak serving deep under-target over
    /// the whole run — the bare-market cold-start transient (deep history accrues before
    /// the archiver population that covers it does). `0` outside bootstrap.
    pub boot_deep_under_peak: f64,
    /// **Bootstrap worst deep gap, floored** (L12): the same peak with the
    /// population-decaying foundation floor added. The floor is load-bearing iff this is
    /// ≈0 while `boot_deep_under_peak` is large — the floor covering the transient the
    /// market cannot yet. `0` outside bootstrap.
    pub boot_deep_under_floored_peak: f64,
    /// **Peak bonded-archiver count** (L12): max over the run. `bonded_active_peak −
    /// bonded_active` (steady) is the overshoot the APR-inversion warning predicts;
    /// ≈0 means entry tracked demand monotonically (no overshoot-and-shed). Equals
    /// `bonded_active` outside endogenous runs.
    pub bonded_active_peak: f64,
    /// **Oldest-band floored gap peak** (P3): the worst floored deep gap restricted to the
    /// oldest band. `> boot_deep_under_floored_peak` ⇒ the residual concentrates in the
    /// irreplaceable tail (uniform floor); an age-stratified floor pulls it down at equal
    /// total foundation cost. `0` outside bootstrap/fee-era.
    pub boot_oldest_floored_peak: f64,
    /// **Fee-era realized purse at end** (L13): the budget in the final epoch. Below the
    /// initial `budget` it shows the subsidy decay; at `budget_ceiling` it shows the
    /// adaptive servo saturated (fee market maxed). Equals `budget` outside fee-era.
    pub fee_budget_end: f64,
    /// **Fee-era worst serving deep gap** (L13): peak serving deep under-target over the
    /// run's second half — the thinned-tail / death-spiral read. A sustained high value
    /// is a priority-1 durability failure (the deep tail is unfunded and going dark);
    /// ≈0 means the decayed purse, adaptive servo, or foundation floor held the tail.
    pub fee_deep_under_peak: f64,
    /// **Retrieval under-SLA deep fraction** (L15): windowed-mean fraction of deep shards
    /// whose realized retrieval availability `1 − (1−u)^d` falls below `retr_avail_target`.
    /// Nonzero with a covered deep set (`deep_und ≈ 0`) is the coverage≠retrieval gap —
    /// correlated failure (few distinct domains), not replica shortfall, is binding.
    pub retr_under_deep: f64,
    /// **Deep-set mean retrieval availability** (L15): windowed-mean `1 − (1−u)^d` over
    /// deep shards. Equals `1.0` outside the retrieval model.
    pub retr_avail_deep: f64,
    /// **Derived deep redundancy** (L15): the `R_target` the SLA `(u, A*)` requires under
    /// independence — `r_target_deep` read off the availability target rather than
    /// stipulated. `0` outside the retrieval model.
    pub r_target_avail: f64,
    /// **Naive audit cadence** (L14): the per-shard challenge probability `a*` deterrence
    /// requires when *every* shard is challenged uniformly (no read credit). `0` outside
    /// the audit model.
    pub audit_oversight_naive: f64,
    /// **Credited audit cadence** (L14): mean per-shard challenge rate when real reads are
    /// credited as proofs — hot shards self-prove, so this is `≪ audit_oversight_naive`.
    pub audit_oversight_credited: f64,
    /// **Deep share of oversight** (L14): fraction of the credited challenge traffic that
    /// lands on deep shards — ≈1 means the non-productive traffic is confined to the cold
    /// tail (hot shards are proven by their reads).
    pub audit_deep_share: f64,
    /// **Oldest-band audit cadence** (L14): the challenge rate the single oldest (coldest,
    /// most-irreplaceable) shard needs — the worst oversight point (P3 tail).
    pub audit_oldest_cadence: f64,
    pub claims: SubClaims,
    /// Compact time series for the four headline quantities (per epoch).
    pub series_frac_under: Vec<f64>,
    pub series_deep_frac_under: Vec<f64>,
    pub series_gini_actor: Vec<f64>,
    pub series_changes: Vec<usize>,
}

fn build_world(cfg: &SimConfig, rng: &mut Rng) -> World {
    // L12 bootstrap: the chain starts as a small genesis core of *hot* (age 0) shards —
    // there is no deep history at t=0; it accrues as these age and `run_sim` appends new
    // shards. The full-window draw below is the steady-state (every prior scenario).
    let shards: Vec<Shard> = if cfg.bootstrap {
        (0..cfg.n_shard_genesis)
            .map(|_| Shard { age: 0.0 })
            .collect()
    } else {
        (0..cfg.n_shard)
            .map(|_| {
                let u = rng.next_f64();
                let age = u.powf(cfg.age_skew);
                Shard { age }
            })
            .collect()
    };

    let scale = |s: usize| ((s as f64 * cfg.storage_scale).round() as usize).max(1);

    // Reservation yield (L11): drawn only when endogenous, so non-endogenous scenarios
    // consume zero extra RNG and stay byte-identical.
    let draw_reservation = |rng: &mut Rng| -> f64 {
        if cfg.endogenous {
            cfg.reservation_lo + rng.next_f64() * (cfg.reservation_hi - cfg.reservation_lo)
        } else {
            0.0
        }
    };

    let mut actors: Vec<Actor> = Vec::with_capacity(cfg.n_actors);
    for _ in 0..cfg.n_actors {
        let storage_rich = rng.next_f64() < cfg.frac_storage_rich;
        let (storage_capacity, capital) = if storage_rich {
            (scale(cfg.storage_rich_storage), cfg.storage_rich_capital)
        } else {
            (scale(cfg.capital_rich_storage), cfg.capital_rich_capital)
        };
        let reservation = draw_reservation(rng);
        actors.push(Actor {
            storage_capacity,
            capital,
            is_whale: false,
            reservation,
        });
    }
    if cfg.whale {
        let reservation = draw_reservation(rng);
        actors.push(Actor {
            storage_capacity: scale(cfg.whale_storage),
            capital: cfg.whale_capital,
            is_whale: true,
            reservation,
        });
    }

    let mut world = World::new(shards, actors);
    // L11 initial participation: when endogenous, only the first `init_active_frac`
    // share of the pool starts active (the rest are potential entrants). Off ⇒ all
    // active (legacy).
    if cfg.endogenous {
        let n = world.actors.len();
        let n_active = (cfg.init_active_frac * n as f64).round() as usize;
        for a in 0..n {
            world.active[a] = a < n_active;
        }
    }
    world
}

pub fn run_sim(cfg: &SimConfig) -> ScenarioResult {
    let mut rng = Rng::new(cfg.seed);
    let mut world = build_world(cfg, &mut rng);

    let mut rp = RewardParams {
        budget: cfg.budget,
        cap: cfg.cap,
        pseudonym_cost: cfg.pseudonym_cost,
        age_weight: cfg.age_weight,
    };
    let ap = AgentParams {
        storage_unit_cost: cfg.storage_unit_cost,
        bond_rate: cfg.bond_rate,
        bond_age_scale: cfg.bond_age_scale,
        bond_carry: cfg.bond_carry,
        deep_threshold: cfg.deep_threshold,
        deep_shard_size: cfg.deep_shard_size,
        bond_dur_base: cfg.bond_dur_base,
        bond_dur_age_scale: cfg.bond_dur_age_scale,
        lock_anticipation: cfg.lock_anticipation,
        fetch_latency_per_unit: cfg.fetch_latency_per_unit,
        acq_rate: cfg.acq_rate,
    };
    let pp = ParticipationParams {
        entry_per_epoch: cfg.entry_per_epoch,
        patience: cfg.participation_patience,
        pseudonym_cost: cfg.pseudonym_cost,
    };
    let tp = TargetParams {
        r_target_hot: cfg.r_target_hot,
        r_target_deep: cfg.r_target_deep,
        deep_threshold: cfg.deep_threshold,
        bond_rate: cfg.bond_rate,
        bond_age_scale: cfg.bond_age_scale,
        deep_shard_size: cfg.deep_shard_size,
    };

    // Seed price so the first epoch's marginal-value calc is non-degenerate.
    let mut price = 1.0;
    let mut series_frac_under = Vec::with_capacity(cfg.epochs);
    let mut series_deep_frac_under = Vec::with_capacity(cfg.epochs);
    let mut series_gini_actor = Vec::with_capacity(cfg.epochs);
    let mut series_changes = Vec::with_capacity(cfg.epochs);

    let mut last_eval = evaluate(&world, &rp, price);
    let mut last_metrics = coverage(&world, &last_eval, &tp);

    // Oldest-band churn (L9): flips and holdings in the deepest age band per epoch.
    // The duration knob is meant to damp *this* specifically.
    let old_lo = (N_BANDS - 1) as f64 / N_BANDS as f64;
    let mut series_old_changes = Vec::with_capacity(cfg.epochs);
    let mut series_old_held = Vec::with_capacity(cfg.epochs);
    // Oldest-band coverage oscillation (L9 necessity): the per-epoch under-target fraction
    // of the deepest band. Abandonment (above) is benign if this stays at 0.
    let mut series_old_under = Vec::with_capacity(cfg.epochs);
    // L10 serving (retrieval-coverage) view: deep under-target and oldest-band under per
    // epoch, computed against seated replicas only (`serving_replication`). Identical to
    // the committed series when `fetch_latency == 0`.
    let mut series_serving_deep_under = Vec::with_capacity(cfg.epochs);
    let mut series_serving_old_under = Vec::with_capacity(cfg.epochs);
    // L15 retrieval availability: per-epoch fraction of *deep* shards whose realized
    // retrieval availability `1 − (1−u)^d` falls below the SLA `retr_avail_target`, and
    // the deep-set mean availability. Inert (empty/zero) when `!retrieval_model`.
    let mut series_retr_under_deep = Vec::with_capacity(cfg.epochs);
    let mut series_retr_avail_deep = Vec::with_capacity(cfg.epochs);
    // L11 emergent participation: active count and bonded-active count per epoch. When
    // `!endogenous` these stay flat at the full population (legacy population is fixed).
    let mut series_active = Vec::with_capacity(cfg.epochs);
    let mut series_bonded_active = Vec::with_capacity(cfg.epochs);
    // L12 bootstrap: the deep retrieval-coverage transient. `boot_deep_under` is the
    // *unfloored* serving deep under-target per epoch (the bare-market cold-start gap);
    // `boot_deep_under_floored` adds the population-decaying foundation floor (the backed
    // transient). Peaks are taken over the WHOLE run (the transient is early, not in the
    // steady-state window). Both equal the serving deep under-target outside bootstrap.
    let mut series_boot_deep_under = Vec::with_capacity(cfg.epochs);
    let mut series_boot_deep_floored = Vec::with_capacity(cfg.epochs);
    // P3 band-resolve: the floored deep gap restricted to the OLDEST band (the most
    // irreplaceable tail), to test whether the aggregate floored residual concentrates there.
    let mut series_boot_oldest_floored = Vec::with_capacity(cfg.epochs);
    // L13 fee-era: the base subsidy decays toward `budget_floor`; the adaptive servo may
    // top it up toward `budget_ceiling`; the realized purse per epoch is tracked here.
    // `signal` is the previous epoch's *serving* deep retrieval shortfall (the trust
    // proxy) — it drives both the servo (top-up) and the price-coupling reservation bump,
    // a one-epoch-delayed feedback controller. Inert when `!fee_era`.
    let mut base_budget = cfg.budget;
    let mut signal = 0.0_f64;
    let mut series_fee_budget = Vec::with_capacity(cfg.epochs);
    // P2: the (exogenous) token price. Decays toward `price_floor` when `price_decay > 0`
    // (a static price decline, independent of the coverage-trust signal — so the fiat
    // flow-cost level channel is isolated from the expectation channel). Constant at
    // `token_price` otherwise; consulted only when `flow_cost_fiat`.
    let mut tok_price = cfg.token_price;

    for ep in 0..cfg.epochs {
        // Dynamic frontier-window: time passes (age + retire + lock-decrement) before
        // agents react. Skip on the first epoch so the initial distribution settles.
        if cfg.dynamic && ep > 0 {
            world.advance_epoch(cfg.epoch_aging);
        }

        // L12 chain growth: append fresh hot shards until the window reaches its
        // steady-state size. From `ep > 0` (the genesis core is what agents act on at
        // ep 0), so deep history accrues as these age. Inert when `!bootstrap`.
        if cfg.bootstrap && ep > 0 && world.shards.len() < cfg.n_shard {
            let room = cfg.n_shard - world.shards.len();
            for _ in 0..cfg.shard_growth_per_epoch.min(room) {
                world.append_shard(0.0);
            }
        }

        // L13 fee-era: shrink the base subsidy toward the terminal floor, then (if the
        // adaptive servo is on) raise the effective purse toward the fee-market ceiling in
        // proportion to last epoch's deep retrieval shortfall. The realized `rp.budget`
        // drives this epoch's reward share. `res_add` is the price-coupling reservation
        // bump applied at exit. Inert when `!fee_era` (purse stays `cfg.budget`).
        let res_add = if cfg.fee_era {
            base_budget =
                cfg.budget_floor + (base_budget - cfg.budget_floor) * (1.0 - cfg.budget_decay);
            let budget_eff = if cfg.adaptive_share {
                // Servo raises the purse with the shortfall, bounded by the fee-market
                // ceiling. The cap is `max(base, ceiling)`: in the thinned end-state the
                // base has decayed below the ceiling and the ceiling binds the top-up; if
                // the base subsidy still exceeds the ceiling (early transition), the
                // subsidy flows unimpeded (the ceiling caps fees, not the subsidy).
                let cap_hi = base_budget.max(cfg.budget_ceiling);
                (base_budget * (1.0 + cfg.share_gain * signal)).min(cap_hi)
            } else {
                base_budget
            };
            rp.budget = budget_eff;
            cfg.price_coupling * signal
        } else {
            0.0
        };

        // L11 entry: trickle inactive actors into the active set (inert when
        // `entry_per_epoch == 0`, i.e. every non-endogenous scenario).
        if cfg.endogenous {
            admit_entrants(&mut world, &pp);
        }

        let before = world.holdings.clone();
        let changes = run_epoch(&mut world, price, &ap, cfg.age_weight, &mut rng);

        // Oldest-band churn attribution (at the ages agents acted on this epoch).
        let mut old_changes = 0usize;
        let mut old_held = 0usize;
        for (a, hb) in before.iter().enumerate() {
            for (s, &b) in hb.iter().enumerate() {
                if world.shards[s].age >= old_lo {
                    if b != world.holdings[a][s] {
                        old_changes += 1;
                    }
                    if world.holdings[a][s] {
                        old_held += 1;
                    }
                }
            }
        }
        series_old_changes.push(old_changes);
        series_old_held.push(old_held);

        last_eval = evaluate(&world, &rp, price);
        price = if last_eval.price > 0.0 {
            last_eval.price
        } else {
            price
        };
        last_metrics = coverage(&world, &last_eval, &tp);

        series_frac_under.push(last_metrics.frac_under_target);
        series_deep_frac_under.push(last_metrics.deep_frac_under_target);
        series_gini_actor.push(last_metrics.gini_actor);
        series_changes.push(changes);
        series_old_under.push(
            last_metrics
                .bands
                .last()
                .map(|b| b.frac_under)
                .unwrap_or(0.0),
        );

        // L10 serving view: recompute coverage against seated replicas only. Free of
        // extra simulation cost (just a second pass over holdings/inflight).
        let serving_r = world.serving_replication();
        let serving_metrics = coverage_with_r(&world, &serving_r, &last_eval.pseudonyms, &tp);
        series_serving_deep_under.push(serving_metrics.deep_frac_under_target);
        series_serving_old_under.push(
            serving_metrics
                .bands
                .last()
                .map(|b| b.frac_under)
                .unwrap_or(0.0),
        );

        // L15 retrieval availability: realized `1 − (1−u)^d` per shard (d = distinct
        // failure domains among seated holders), scored over the deep set against the
        // SLA `retr_avail_target`. This is the coverage≠retrieval read — a shard can be
        // *covered* (serving_r ≥ R_target) yet fail the SLA if its holders cluster into
        // too few domains. Inert when `!retrieval_model`.
        if cfg.retrieval_model {
            let avail = serving_availability(&world, cfg.retr_uptime, cfg.retr_n_domains);
            let mut dn = 0usize;
            let mut under = 0usize;
            let mut sum = 0.0_f64;
            #[allow(clippy::needless_range_loop)]
            for s in 0..world.shards.len() {
                if world.shards[s].age >= cfg.deep_threshold {
                    dn += 1;
                    sum += avail[s];
                    if avail[s] < cfg.retr_avail_target {
                        under += 1;
                    }
                }
            }
            series_retr_under_deep.push(if dn > 0 {
                under as f64 / dn as f64
            } else {
                0.0
            });
            series_retr_avail_deep.push(if dn > 0 { sum / dn as f64 } else { 1.0 });
        } else {
            series_retr_under_deep.push(0.0);
            series_retr_avail_deep.push(1.0);
        }

        // L12 bootstrap deep coverage: serving deep under-target with and without the
        // foundation floor. The floor decays with the current bonded-archiver population
        // and adds replicas to *deep* shards only (retrieval coverage, not the reward
        // servo — see `participation::foundation_floor`). Computed inline over deep shards
        // to avoid a third full coverage pass. Outside bootstrap (`floor_replicas == 0`)
        // both equal the serving deep under-target.
        let pop_now = bonded_active_count(&world, &ap);
        // P3: the floor is age-stratified (oldest-ward, mean-preserving) when `floor_age_tilt
        // > 0`; `foundation_floor_aged` reduces to the uniform `foundation_floor` at tilt 0.
        // The oldest band (top 1/N_BANDS of the age range) is resolved separately to test
        // whether the floored residual concentrates in the irreplaceable tail (P3 / L13#2).
        let oldest_lo = (N_BANDS - 1) as f64 / N_BANDS as f64;
        let mut deep_n = 0usize;
        let mut deep_under_bare = 0usize;
        let mut deep_under_floored = 0usize;
        let mut old_n = 0usize;
        let mut old_under_floored = 0usize;
        #[allow(clippy::needless_range_loop)]
        for s in 0..world.shards.len() {
            let age = world.shards[s].age;
            if age >= cfg.deep_threshold {
                deep_n += 1;
                let tgt = r_target(age, cfg.r_target_hot, cfg.r_target_deep);
                let floor_eff = foundation_floor_aged(
                    pop_now,
                    cfg.floor_replicas,
                    cfg.floor_decay_pop,
                    cfg.floor_age_tilt,
                    age,
                    cfg.deep_threshold,
                );
                if serving_r[s] < tgt {
                    deep_under_bare += 1;
                }
                let floored_under = serving_r[s] + floor_eff < tgt;
                if floored_under {
                    deep_under_floored += 1;
                }
                if age >= oldest_lo {
                    old_n += 1;
                    if floored_under {
                        old_under_floored += 1;
                    }
                }
            }
        }
        series_boot_deep_under.push(if deep_n > 0 {
            deep_under_bare as f64 / deep_n as f64
        } else {
            0.0
        });
        series_boot_deep_floored.push(if deep_n > 0 {
            deep_under_floored as f64 / deep_n as f64
        } else {
            0.0
        });
        series_boot_oldest_floored.push(if old_n > 0 {
            old_under_floored as f64 / old_n as f64
        } else {
            0.0
        });

        // L11 exit: active actors whose realized APR sits below their reservation (or
        // who hold no bond) for `patience` consecutive epochs leave and drop their
        // holdings. Realized rewards come from the just-computed `last_eval`. Inert when
        // `!endogenous`.
        if cfg.price_decay > 0.0 {
            tok_price = cfg.price_floor + (tok_price - cfg.price_floor) * (1.0 - cfg.price_decay);
        }
        if cfg.endogenous {
            process_exits(
                &mut world,
                &last_eval,
                &ap,
                &pp,
                res_add,
                cfg.flow_cost_fiat,
                tok_price,
            );
        }
        series_active.push(world.active.iter().filter(|&&x| x).count());
        series_bonded_active.push(bonded_active_count(&world, &ap));

        // L13: record the realized purse and refresh the feedback signal. The signal is an
        // EMA of the *serving* deep shortfall, not its instantaneous value — trust/price is
        // STICKY (it does not snap to "fine" after one good epoch, nor crater after one bad
        // one). The smoothing is load-bearing: a servo (or depreciation premium) keyed to
        // the raw shortfall relaxes the instant coverage is briefly met, which — with
        // rate-limited entry and hysteretic exit — lets the population bleed back down and
        // oscillate; the EMA holds the response across the few epochs entry needs to
        // rebuild. λ=0.25 ⇒ ~4-epoch trust horizon. Drives next epoch's servo + coupling.
        signal = 0.75 * signal + 0.25 * serving_metrics.deep_frac_under_target;
        series_fee_budget.push(rp.budget);
    }

    let total_held: usize = (0..world.actors.len())
        .map(|a| world.actor_shard_count(a))
        .sum();
    let churn = churn_rate(&series_changes, total_held, cfg.churn_window);
    // Oldest-band churn rate: flips per held-shard-epoch in the deepest band over the
    // window (mean held as the denominator, since the band's holdings vary).
    let w = cfg.churn_window.min(series_old_changes.len());
    let oc_start = series_old_changes.len() - w;
    let old_changes_sum: usize = series_old_changes[oc_start..].iter().sum();
    let old_held_mean: f64 = if w > 0 {
        series_old_held[oc_start..].iter().sum::<usize>() as f64 / w as f64
    } else {
        0.0
    };
    let oldest_churn = if old_held_mean > 0.0 {
        (old_changes_sum as f64 / w as f64) / old_held_mean
    } else {
        0.0
    };
    // Oldest-band coverage oscillation over the same window: max and variance of the
    // under-target fraction. This is the L9 *necessity* metric (abandonment turning into
    // coverage gaps), distinct from the abandonment rate above.
    let ou_window = &series_old_under[series_old_under.len() - w..];
    let oldest_under_max = ou_window.iter().copied().fold(0.0_f64, f64::max);
    let oldest_under_var = if w > 0 {
        let mean = ou_window.iter().sum::<f64>() / w as f64;
        ou_window.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / w as f64
    } else {
        0.0
    };
    // L10 serving (retrieval-coverage) aggregates over the same window: the cost axis
    // (windowed mean deep under-target) and the benefit axis (peak oldest-band under).
    let sdu_window = &series_serving_deep_under[series_serving_deep_under.len() - w..];
    let serving_deep_under = if w > 0 {
        sdu_window.iter().sum::<f64>() / w as f64
    } else {
        0.0
    };
    let sou_window = &series_serving_old_under[series_serving_old_under.len() - w..];
    let serving_oldest_under_max = sou_window.iter().copied().fold(0.0_f64, f64::max);
    // Committed deep under-target, windowed mean — the steady-state reallocation-cost
    // read (vs. the final-epoch snapshot in `final_metrics`). Same window as everything
    // above so the cost and benefit axes are read on one consistent steady-state window.
    let cdu_window = &series_deep_frac_under[series_deep_frac_under.len() - w..];
    let committed_deep_under = if w > 0 {
        cdu_window.iter().sum::<f64>() / w as f64
    } else {
        0.0
    };
    // L11 emergent participation, windowed means over the same steady-state window:
    // the active fraction (of the full pool) and the bonded-active count (the emergent
    // archiver-set size). For non-endogenous scenarios these are the fixed population.
    let pool = world.actors.len().max(1) as f64;
    let active_window = &series_active[series_active.len() - w..];
    let active_frac = if w > 0 {
        active_window.iter().sum::<usize>() as f64 / w as f64 / pool
    } else {
        0.0
    };
    let ba_window = &series_bonded_active[series_bonded_active.len() - w..];
    let bonded_active = if w > 0 {
        ba_window.iter().sum::<usize>() as f64 / w as f64
    } else {
        0.0
    };
    // L15 retrieval availability, windowed means over the same steady-state window:
    // `retr_under_deep` is the fraction of deep shards below the SLA `A*` (the
    // coverage≠retrieval gap — nonzero here with covered shards means correlated failure
    // is the binding constraint), and `retr_avail_deep` is the deep-set mean availability.
    // `r_target_avail` is the *derived* deep redundancy the SLA requires under
    // independence — what `r_target_deep` should be, read off `(u, A*)` rather than
    // stipulated.
    let rud_window = &series_retr_under_deep[series_retr_under_deep.len() - w..];
    let retr_under_deep = if w > 0 {
        rud_window.iter().sum::<f64>() / w as f64
    } else {
        0.0
    };
    let rad_window = &series_retr_avail_deep[series_retr_avail_deep.len() - w..];
    let retr_avail_deep = if w > 0 {
        rad_window.iter().sum::<f64>() / w as f64
    } else {
        1.0
    };
    let r_target_avail = if cfg.retrieval_model {
        r_target_for_availability(cfg.retr_uptime, cfg.retr_avail_target) as f64
    } else {
        0.0
    };
    // L14 proof-of-archival audit: the non-productive (oversight-only) challenge traffic
    // needed to keep free-riding unprofitable, computed over the final age distribution
    // (steady in steady state). `a*` is the per-shard audit probability deterrence
    // requires; the NAIVE policy challenges every shard at `a*` (ignoring reads); the
    // CREDITED policy credits each shard's real-read probability and only tops up the
    // shortfall — so hot, frequently-read shards need ~0 challenge and the oversight lands
    // on the cold tail. `audit_deep_share` is the fraction of credited oversight on deep
    // shards; `audit_oldest_cadence` is the worst (oldest-band) challenge rate (P3 — the
    // most-irreplaceable, least-read shards carry the highest oversight cadence).
    let (audit_oversight_naive, audit_oversight_credited, audit_deep_share, audit_oldest_cadence) =
        if cfg.audit_model {
            let a_star = deterrence_threshold(cfg.freeride_benefit, cfg.freeride_penalty);
            let n = world.shards.len().max(1);
            let max_age = world.shards.iter().map(|s| s.age).fold(0.0_f64, f64::max);
            let mut credited_sum = 0.0_f64;
            let mut deep_credited = 0.0_f64;
            for sh in &world.shards {
                let p = read_prob(sh.age, cfg.read_hot, cfg.read_decay, cfg.read_cold);
                let c = challenge_needed(p, a_star);
                credited_sum += c;
                if sh.age >= cfg.deep_threshold {
                    deep_credited += c;
                }
            }
            let credited_mean = credited_sum / n as f64;
            let deep_share = if credited_sum > 0.0 {
                deep_credited / credited_sum
            } else {
                0.0
            };
            // Oldest-band cadence: the challenge rate the single oldest shard needs — the
            // worst oversight point (least-read, most-irreplaceable; the P3 tail).
            let oldest = challenge_needed(
                read_prob(max_age, cfg.read_hot, cfg.read_decay, cfg.read_cold),
                a_star,
            );
            (a_star, credited_mean, deep_share, oldest)
        } else {
            (0.0, 0.0, 0.0, 0.0)
        };
    // L12 bootstrap aggregates, taken over the WHOLE run (the cold-start transient is at
    // the *start*, not in the steady-state window): the worst deep retrieval gap with and
    // without the foundation floor, and the peak bonded-archiver count. `bonded_active_peak`
    // above the steady `bonded_active` is the **overshoot** — entrants the high early APR
    // pulled in beyond the steady-state set, which then shed (the early-churn risk).
    let boot_deep_under_peak = series_boot_deep_under
        .iter()
        .copied()
        .fold(0.0_f64, f64::max);
    let boot_deep_under_floored_peak = series_boot_deep_floored
        .iter()
        .copied()
        .fold(0.0_f64, f64::max);
    // P3: peak floored gap on the OLDEST band over the run. `boot_oldest_floored_peak >
    // boot_deep_under_floored_peak` confirms the residual concentrates in the irreplaceable
    // tail (uniform floor); an age-stratified floor (`floor_age_tilt > 0`) should pull this
    // down toward the aggregate at equal total foundation cost.
    let boot_oldest_floored_peak = series_boot_oldest_floored
        .iter()
        .copied()
        .fold(0.0_f64, f64::max);
    let bonded_active_peak = series_bonded_active.iter().copied().max().unwrap_or(0) as f64;
    // L13 fee-era aggregates. `fee_budget_end` is the realized purse averaged over the
    // steady read window — how far the subsidy decayed and how much the adaptive servo
    // topped it up (≈`budget_ceiling` ⇒ the fee market is saturated). A windowed mean, not
    // the final epoch, since the proportional servo can ripple epoch-to-epoch.
    // `fee_deep_under_peak` is the worst *serving* deep retrieval gap over the run's
    // **second half** (the thinned end-state, excluding any warm-up): a sustained high
    // value is the death-spiral / unsustainable read; ≈0 means the purse (decayed base, or
    // servo, or floor) held the deep tail.
    let fb_window = &series_fee_budget[series_fee_budget.len() - w..];
    let fee_budget_end = if w > 0 {
        fb_window.iter().sum::<f64>() / w as f64
    } else {
        cfg.budget
    };
    let half = series_serving_deep_under.len() / 2;
    let fee_deep_under_peak = series_serving_deep_under[half..]
        .iter()
        .copied()
        .fold(0.0_f64, f64::max);

    // Verdict thresholds (stated, not hidden). These are review-tunable judgment
    // calls; the raw metrics are reported alongside so a reviewer can re-judge.
    let covered = last_metrics.frac_under_target < 0.05 && last_metrics.min_r >= 1;
    let spread = last_metrics.gini_actor < 0.6 && last_metrics.max_actor_share < 0.20;
    let deep_history = last_metrics.deep_frac_under_target < 0.10;
    let churn_stable = churn < 0.05;
    let all_pass = covered && spread && deep_history && churn_stable;

    ScenarioResult {
        name: cfg.name.clone(),
        axis: cfg.axis.clone(),
        bond_rate: cfg.bond_rate,
        age_weight: cfg.age_weight,
        cap: cfg.cap,
        n_actors: cfg.n_actors,
        whale: cfg.whale,
        final_metrics: last_metrics,
        churn,
        oldest_churn,
        oldest_under_max,
        oldest_under_var,
        serving_deep_under,
        serving_oldest_under_max,
        committed_deep_under,
        active_frac,
        bonded_active,
        boot_deep_under_peak,
        boot_deep_under_floored_peak,
        bonded_active_peak,
        boot_oldest_floored_peak,
        fee_budget_end,
        fee_deep_under_peak,
        retr_under_deep,
        retr_avail_deep,
        r_target_avail,
        audit_oversight_naive,
        audit_oversight_credited,
        audit_deep_share,
        audit_oldest_cadence,
        claims: SubClaims {
            covered,
            spread,
            deep_history,
            churn_stable,
            all_pass,
        },
        series_frac_under,
        series_deep_frac_under,
        series_gini_actor,
        series_changes,
    }
}

/// The iteration-1 baseline. Mid bond, mid age-weight, mixed endowments, no whale.
///
/// Calibrated to sit *at the coverage margin*: aggregate storage (~1280 shard-slots)
/// is moderately above the full-coverage requirement (Σ R_target(age) ≈ 240·4.5 ≈
/// 1080, ~18% slack), so storage binds — agents must trade hot vs. deep rather than
/// holding everything — but coverage is *achievable* if agents prioritize correctly.
/// This is the regime where the `g(age)` premium is load-bearing: at `g=1` the bond
/// asymmetry makes deep strictly less attractive than equal-`R` hot, so agents fill
/// hot and starve deep (the predicted failure); `g>1` raises deep's value enough to
/// win the scarce storage back.
///
/// Capital is deliberately **ample** at baseline (Σ deep-slots ≈ 2400 ≫ deep need ≈
/// 650), so the bond does *not* bind here and `g(age)` is free to reallocate storage.
/// The high-bond sweep is where capital binds and the empty-window threat (bond high
/// enough to deter the whale but high enough to price out storage-rich archivers)
/// surfaces.
fn baseline() -> SimConfig {
    SimConfig {
        name: "baseline".into(),
        axis: "baseline".into(),
        n_shard: 240,
        n_actors: 80,
        age_skew: 1.0, // uniform age distribution
        storage_scale: 1.0,
        frac_storage_rich: 0.5,
        storage_rich_storage: 22,
        storage_rich_capital: 20.0,
        capital_rich_storage: 10,
        capital_rich_capital: 100.0,
        whale: false,
        whale_storage: 150,
        whale_capital: 600.0,
        budget: 100.0,
        cap: 8.0,
        pseudonym_cost: 0.05,
        age_weight: 2.0,
        storage_unit_cost: 0.03,
        bond_rate: 2.0,      // mid
        bond_age_scale: 0.0, // flat bond is the iteration-1 baseline (L4 sweep varies it)
        bond_carry: 0.03,
        deep_threshold: 0.5,
        deep_shard_size: 1.0, // one unit per shard = iteration-1 behavior
        // Static iteration-1 world by default; the L9 dynamic/duration scenarios opt in.
        dynamic: false,
        epoch_aging: 0.0,
        bond_dur_base: 0.0,
        bond_dur_age_scale: 0.0,
        lock_anticipation: 0.0,
        // L10: no fetch latency by default ⇒ instant seating ⇒ capacity-bound
        // iteration-1/2 model unchanged. The L10 scenarios opt in.
        fetch_latency_per_unit: 0.0,
        acq_rate: 0,
        // L11: fixed all-active population by default (every pre-L11 scenario). The
        // participation scenarios opt in.
        endogenous: false,
        init_active_frac: 1.0,
        entry_per_epoch: 0,
        participation_patience: 1,
        reservation_lo: 0.0,
        reservation_hi: 0.0,
        // L12: full window at t=0 by default (every pre-L12 scenario). The bootstrap
        // scenarios opt in.
        bootstrap: false,
        n_shard_genesis: 0,
        shard_growth_per_epoch: 0,
        floor_replicas: 0,
        floor_decay_pop: 0.0,
        // L13: constant budget by default (every pre-L13 scenario). The fee-era
        // scenarios opt in.
        fee_era: false,
        budget_decay: 0.0,
        budget_floor: 0.0,
        adaptive_share: false,
        share_gain: 0.0,
        budget_ceiling: 0.0,
        price_coupling: 0.0,
        // P2: token-denominated flow cost by default (price cancels; every pre-P2
        // scenario). The fiat-flow-cost scenarios opt in. `token_price = 1.0` keeps the
        // fiat path identical to the token path even when a scenario flips the flag.
        flow_cost_fiat: false,
        token_price: 1.0,
        price_decay: 0.0,
        price_floor: 1.0,
        // L15 retrieval model: off by default (inert, byte-identical). The retrieval
        // scenarios opt in. Defaults describe a three-nines SLA at 90% holder uptime
        // with independent domains; scenarios override `retr_n_domains` to add
        // correlation.
        retrieval_model: false,
        retr_uptime: 0.9,
        retr_avail_target: 0.999,
        retr_n_domains: 0,
        // L14 proof-of-archival audit: off by default (inert, byte-identical). The audit
        // scenarios opt in. Defaults: hot shards read often (0.6/epoch) decaying to a 1%
        // cold floor; free-rider saves 10% of the slash per epoch, slashed in full if
        // caught ⇒ deterrence threshold a* = 0.1.
        audit_model: false,
        read_hot: 0.6,
        read_decay: 4.0,
        read_cold: 0.01,
        freeride_benefit: 0.1,
        freeride_penalty: 1.0,
        // P3 age-stratified floor: uniform by default (tilt 0 ⇒ byte-identical to the
        // L12/L13 floor). The P3 scenarios opt in.
        floor_age_tilt: 0.0,
        r_target_hot: 3.0,
        r_target_deep: 6.0,
        // Myopic Gauss–Seidel converges in ~2 epochs; 40 is ample headroom and
        // keeps the churn window meaningful.
        epochs: 40,
        churn_window: 20,
        seed: 0x5EED_1234,
    }
}

/// Build the curated iteration-1 sweep set.
pub fn build_scenarios() -> Vec<SimConfig> {
    let mut out = Vec::new();

    // Baseline.
    out.push(baseline());

    // --- Coarse bond sweep (low / mid / high), no whale and with whale. ---
    for (label, rate) in [("low", 0.5), ("mid", 2.0), ("high", 8.0)] {
        let mut c = baseline();
        c.name = format!("bond_{label}");
        c.axis = "bond".into();
        c.bond_rate = rate;
        out.push(c);

        let mut cw = baseline();
        cw.name = format!("bond_{label}_whale");
        cw.axis = "bond_x_whale".into();
        cw.bond_rate = rate;
        cw.whale = true;
        out.push(cw);
    }

    // --- Age-weight g(age): g=1 baseline (expected deep failure) through g>1.
    // Finer points to locate the premium that clears deep coverage without
    // over-rewarding it (the spec's central designed experiment). ---
    for (label, w) in [
        ("g1", 0.0),
        ("g_2", 2.0),
        ("g_3", 3.0),
        ("g_4", 4.0),
        ("g_high", 5.0),
    ] {
        let mut c = baseline();
        c.name = format!("age_{label}");
        c.axis = "age_weight".into();
        c.age_weight = w;
        out.push(c);
    }

    // --- Population thickness. ---
    for (label, n) in [("thin", 25), ("mid", 80), ("thick", 200)] {
        let mut c = baseline();
        c.name = format!("pop_{label}");
        c.axis = "population".into();
        c.n_actors = n;
        out.push(c);
    }

    // --- Endowment mix. ---
    for (label, frac) in [
        ("capital_heavy", 0.2),
        ("balanced", 0.5),
        ("storage_heavy", 0.8),
    ] {
        let mut c = baseline();
        c.name = format!("mix_{label}");
        c.axis = "endowment_mix".into();
        c.frac_storage_rich = frac;
        out.push(c);
    }

    // --- Curve shape (cap height / plateau position). ---
    for (label, cap) in [("cap_low", 4.0), ("cap_mid", 8.0), ("cap_high", 16.0)] {
        let mut c = baseline();
        c.name = format!("curve_{label}");
        c.axis = "curve_shape".into();
        c.cap = cap;
        out.push(c);
    }

    // --- Shard-age distribution. ---
    for (label, skew) in [("hot_heavy", 2.5), ("uniform", 1.0), ("deep_heavy", 0.4)] {
        let mut c = baseline();
        c.name = format!("age_dist_{label}");
        c.axis = "age_distribution".into();
        c.age_skew = skew;
        out.push(c);
    }

    // --- Provisioning robustness (storage scale). A finding that survives this is
    // structural; one that only appears at the calibrated margin is an artifact. ---
    for (label, scale) in [
        ("p07", 0.7),
        ("p10", 1.0),
        ("p13", 1.3),
        ("p16", 1.6),
        ("p20", 2.0),
    ] {
        let mut c = baseline();
        c.name = format!("prov_{label}");
        c.axis = "provisioning".into();
        c.storage_scale = scale;
        out.push(c);
    }

    // --- g=1 × provisioning cross. Tests whether the deep_und=1.000 corner is
    // structural or a thin-baseline artifact: the prediction is that as provisioning
    // rises, hot saturates (its marginal 1/R falls) and deep becomes partially held
    // even at g=1, so deep_und(g=1) should fall below 1.000. ---
    for (label, scale) in [("p10", 1.0), ("p13", 1.3), ("p16", 1.6), ("p20", 2.0)] {
        let mut c = baseline();
        c.name = format!("g1_{label}");
        c.axis = "g1_x_provisioning".into();
        c.age_weight = 0.0;
        c.storage_scale = scale;
        out.push(c);
    }

    // --- Bond age-scaling (L4), in a capital-poor-archiver regime. The mean-preserving
    // tilt redistributes the *same* aggregate bond demand toward older shards while
    // holding the average deep bond fixed, so flat (s0) vs. tilted (s1,s3) are
    // comparable at equal `dS/dN`. The mechanism only bites when a genuinely
    // capital-poor archiver class exists (the baseline's storage-rich actors carry
    // capital 20, far above any per-shard bond, so the aggregate always binds first):
    // here the storage-rich are the capital-poor archivers the design worries about
    // (capital 3), in an ample-storage / capital-bound regime. The L4 evidence is the
    // per-band `affording` + `gini_actor` + `whale_share`: does tilting price the poor
    // out of the *oldest* shards specifically, concentrating the tail onto the
    // capital-rich (and onto a whale, if present)? ---
    for (label, scale) in [("s0", 0.0), ("s1", 1.0), ("s3", 3.0)] {
        let mut c = baseline();
        c.name = format!("bscale_{label}");
        c.axis = "bond_age_scale".into();
        c.frac_storage_rich = 0.6; // majority capital-poor archivers
        c.storage_rich_capital = 8.0; // poor enough that the tilt prices them out of
                                      // the oldest (mean bond 2 → ~4 deep; oldest bond
                                      // at s3 = 3.5 → only ~2 oldest), rich enough that
                                      // deep is coverable at the flat baseline
        c.bond_age_scale = scale;
        out.push(c);

        let mut cw = baseline();
        cw.name = format!("bscale_{label}_whale");
        cw.axis = "bond_age_scale".into();
        cw.frac_storage_rich = 0.6;
        cw.storage_rich_capital = 8.0;
        cw.bond_age_scale = scale;
        cw.whale = true;
        out.push(cw);
    }

    // --- L9: age-scaled bond DURATION in the dynamic frontier-window (iteration 2).
    // Flat magnitude (L4-resolved); the swept knob is the commitment horizon. The
    // dynamic world (shards age, transit hot→deep, recycle) is the churn source the
    // duration is meant to damp. `dur_s0` = flat horizon (control); `dur_s2/s4` =
    // age-scaled (older shards lock longer). Run myopic (lock_anticipation=0: duration
    // can only damp churn) and anticipatory (>0: a long horizon also deters acquisition
    // → the willingness ceiling). Read `oldest_churn` (should fall with age-scaling) vs
    // oldest-band coverage/affording (should NOT fall under myopia; may fall under
    // anticipation — the ceiling). ---
    let dyn_base = || {
        let mut c = baseline();
        c.dynamic = true;
        c.epoch_aging = 0.05; // ~20 epochs hot→retire
        c.epochs = 80; // enough transit for a steady churn frontier
        c.bond_dur_base = 4.0; // flat horizon floor
        c
    };
    for (label, dscale) in [("s0", 0.0), ("s2", 2.0), ("s4", 4.0)] {
        let mut c = dyn_base();
        c.name = format!("dur_{label}");
        c.axis = "bond_duration".into();
        c.bond_dur_age_scale = dscale;
        out.push(c);

        // Anticipation tuned to 0.25 so the willingness ceiling shows as *graded*
        // (acquisition of the longest-duration oldest shards is deterred first) rather
        // than the saturated cliff a high value produces.
        let mut ca = dyn_base();
        ca.name = format!("dur_{label}_antic");
        ca.axis = "bond_duration".into();
        ca.bond_dur_age_scale = dscale;
        ca.lock_anticipation = 0.25;
        out.push(ca);
    }

    // --- L9 resolver: the duration NECESSITY-AND-COST sweep in a thick/surplus regime.
    // The thin `dur_` sweep above confounds both halves of the duration question: at
    // near-zero deep margin, holders flip easily (the churn duration would fix) AND any
    // anticipated lock flips them negative (the steep ceiling) — so "duration unnecessary"
    // and "duration merely unaffordable" look identical. The surplus regime changes the
    // holder *distribution*: a generous budget + strong deep premium (high g) + ample
    // storage seat many *inframarginal* deep holders carrying a buffer. There we can
    // finally separate (a) NECESSITY — does oldest-band churn persist when holders aren't
    // on the knife-edge? — from (b) COST — anticipation should now cost a *gentle*
    // participation trim (marginal entrants drop, inframarginal holders tolerate the lock)
    // rather than a cliff. Three decision-useful outcomes: churn dissolves → duration
    // retires (L4 closes flat-no-duration, reversion discharged); churn persists + gentle
    // cost → adopt duration as the tail-churn tool with a known price; churn persists +
    // steep cost even at surplus → a real bind pointing at a foundation permafloor on the
    // oldest tail rather than a market mechanism. Flat magnitude throughout (L4). ---
    let surplus_base = || {
        let mut c = dyn_base();
        c.age_weight = 4.0; // strong deep premium → deep pays well above cost
        c.budget = 300.0; // ample reward pool → holders sit inframarginal, not knife-edge
        c.storage_scale = 1.6; // ample storage → coverage is not the binding constraint
        c
    };
    for (label, dscale) in [("s0", 0.0), ("s2", 2.0), ("s4", 4.0)] {
        let mut c = surplus_base();
        c.name = format!("surp_{label}");
        c.axis = "bond_duration_surplus".into();
        c.bond_dur_age_scale = dscale;
        out.push(c);

        let mut ca = surplus_base();
        ca.name = format!("surp_{label}_antic");
        ca.axis = "bond_duration_surplus".into();
        ca.bond_dur_age_scale = dscale;
        ca.lock_anticipation = 0.25;
        out.push(ca);
    }

    // --- L9 lean-equilibrium PROBE: find the just-covering operating point (R ≈ R_target,
    // buffer removed) where coverage oscillation — not benign rotation — is the diagnostic.
    // Surplus over-provisions (slack backfills, masking duration); thin under-covers. The
    // chain's real operating point is the zero-profit entry equilibrium in between. Sweep
    // storage provisioning at the deep-priority g, flat duration, and read `oUmx` (oldest-
    // band coverage oscillation): the lean point is the lowest provisioning where mean
    // deep coverage is ~complete but `oUmx > 0`. ---
    for (label, ss) in [
        ("p090", 0.90),
        ("p100", 1.00),
        ("p115", 1.15),
        ("p130", 1.30),
    ] {
        let mut c = dyn_base();
        c.name = format!("lean_probe_{label}");
        c.axis = "lean_probe".into();
        c.age_weight = 4.0;
        c.budget = 150.0;
        c.storage_scale = ss;
        out.push(c);
    }

    // --- L9 lean-equilibrium OSCILLATION test: the decision-relevant necessity check.
    // The surplus resolver established cost (gentle) but cannot answer necessity: its slack
    // is itself a coverage-stability mechanism, so it tests duration in the one regime where
    // it isn't needed. The probe above locates the lean operating point — the oldest band at
    // R ≈ R_target (mean_r ≈ 6 = target, buffer removed), the zero-profit entry equilibrium
    // the chain actually runs at. Here the failure mode the churn sub-claim *names* —
    // coverage oscillation (oldest-band frac_under dipping > 0, a holder dropping with no
    // replacement standing by) rather than abandonment (benign turnover) — can finally
    // manifest if it exists. Stress backfill with faster aging (more retire/recycle per
    // epoch) at lean capacity, flat (s0) vs age-scaled (s4) duration, and read `oUmx`
    // (oldest-band coverage oscillation, the necessity metric) — NOT `oChrn` (abandonment).
    // Prediction (rule-21 honesty): if `oUmx > 0` under flat and → 0 under age-scaled,
    // necessity is DIRECT (duration buys lean-and-stable operation). If `oUmx ≈ 0` under
    // both, the abandonment is benign rotation, duration prevents a non-problem at the
    // operating point, and L9 necessity stays INFERRED with the reversion axis open. ---
    let lean_base = || {
        let mut c = baseline();
        c.dynamic = true;
        c.epochs = 80;
        c.bond_dur_base = 4.0;
        c.age_weight = 3.0; // deep premium present but not over-defending the oldest band
        c.budget = 120.0; // tuned so the oldest band sits at R ≈ R_target (lean, no buffer)
        c.storage_scale = 1.0; // no storage slack — capacity is the bind, not abundance
        c
    };
    for (alabel, aging) in [("a05", 0.05), ("a10", 0.10), ("a20", 0.20)] {
        for (dlabel, dscale) in [("s0", 0.0), ("s4", 4.0)] {
            let mut c = lean_base();
            c.name = format!("lean_osc_{alabel}_{dlabel}");
            c.axis = "lean_oscillation".into();
            c.epoch_aging = aging;
            c.bond_dur_age_scale = dscale;
            out.push(c);
        }
    }

    // --- L9 cost confirmation: the lock-in REALLOCATION cost across capacity binds. The
    // lean-oscillation `a10` row exposed a redistribution signature, not noise: age-scaled
    // duration *lifts* the oldest band (mean_r 6.41→6.45, frac_under 0.041→0.020) while the
    // adjacent mid-deep band [0.6–0.8] *starves* (frac_under 0.346→0.410) and aggregate
    // deep_und worsens (0.351→0.377). Mechanism: at a capacity bind, locking holders onto
    // the oldest shards (the duration knob working as designed) denies those actors to
    // mid-deep, which has no slack to backfill — a lock-in opportunity cost that bites
    // exactly at the operating regime (surplus "gentle cost" was the slack absorbing it).
    // This is the SAME shape as finding #3: g reallocates hot→deep, age-scaled duration
    // reallocates within-deep oldest-ward; both redistribute without manufacturing coverage
    // (only capacity / L8 does), so stacked they double-count an oldest-ward pull. Confirm
    // the *direction* (not the magnitude) across several genuine binds — sweep aging through
    // the bind window and a storage-tightened bind, graded duration s0→s2→s4 — and read the
    // per-band split (oldest frac_under DOWN, mid-deep [0.6–0.8] frac_under UP under
    // age-scaling). If the signature replicates, the lean-margin reallocation cost is banked
    // as demonstrated; the surplus "gentle" reading is regime-specific. Flat magnitude
    // throughout (L4). ---
    // Widened aging grid (hardening): a06..a14 brackets the bind window denser, so the
    // Finding-3 cost-dissolution (committed deep_und windowed mean within noise under
    // age-scaling) is read across the envelope, not at three points. Read `cDeepU`
    // (committed windowed mean) — NOT the final-epoch `deep_und`, which is the snapshot
    // that produced the original (retracted) "7×" artifact.
    for (alabel, aging) in [
        ("a06", 0.06),
        ("a08", 0.08),
        ("a10", 0.10),
        ("a12", 0.12),
        ("a14", 0.14),
    ] {
        for (dlabel, dscale) in [("s0", 0.0), ("s2", 2.0), ("s4", 4.0)] {
            let mut c = lean_base();
            c.name = format!("bind_{alabel}_{dlabel}");
            c.axis = "duration_realloc_cost".into();
            c.epoch_aging = aging;
            c.bond_dur_age_scale = dscale;
            out.push(c);
        }
    }
    // A storage-tightened bind (independent lever): capacity bound via storage scarcity
    // rather than recycle speed, to show the cost is bind-generic, not aging-specific.
    for (dlabel, dscale) in [("s0", 0.0), ("s2", 2.0), ("s4", 4.0)] {
        let mut c = lean_base();
        c.name = format!("bind_stor_{dlabel}");
        c.axis = "duration_realloc_cost".into();
        c.epoch_aging = 0.10;
        c.storage_scale = 0.85;
        c.bond_dur_age_scale = dscale;
        out.push(c);
    }

    // --- L10: the BACKFILL-LAG test — the one model change that can price the L9
    // benefit. Iteration-2's model is capacity-bound (same-epoch full re-optimization),
    // so it *structurally* cannot show drop-without-standing-replacement oscillation —
    // the failure mode age-scaled duration would damp. L10 adds deep-shard fetch latency
    // (a fresh deep acquisition is committed but NOT serving for `round(deep_shard_size ·
    // fetch_latency_per_unit)` epochs; drops are instant), making coverage timing-bound.
    //
    // The clean experiment: start from the lean point that was *covered with oUmx = 0*
    // in the capacity-bound model (`lean_osc_a05`: slow churn, oldest at R ≈ R_target),
    // so any oscillation that appears is purely from the lag, not from a capacity gap.
    // Crank latency `L ∈ {0,1,2,4}` epochs, flat (s0) vs age-scaled (s4) duration, and
    // read BOTH halves of the sharpened reversion clause:
    //   - benefit: does flat-duration `oUmx` rise > 0 with latency (timing oscillation),
    //     and does age-scaled duration *damp* it?
    //   - cost: does mean `deep_und` (the lock-in reallocation cost, confirmed in `bind_*`)
    //     still bite under age-scaling?
    // Net verdict = does age-scaling's oUmx reduction beat its deep_und increase on the
    // aggregate. Longer run (120 ep / 40-window) for stable oscillation statistics.
    // `acq_rate` variants add the bandwidth bound (slower backfill ⇒ more lag). ---
    let lag_base = || {
        let mut c = lean_base();
        c.epochs = 120;
        c.churn_window = 40;
        c.epoch_aging = 0.05; // the covered lean point (capacity-bound oUmx = 0)
        c
    };
    // Denser latency grid (hardening): {0,1,2,3,4,6} epochs maps the benefit *curve*
    // (s0 deep_und − s4 deep_und), not two endpoints — so the sign's robustness and the
    // rise/saturate shape are visible, not asserted. The smallest non-trivial lag (L1)
    // is the floor-of-plausible read; L6 is the deep-saturation tail.
    for (llabel, lpu) in [
        ("L0", 0.0),
        ("L1", 1.0),
        ("L2", 2.0),
        ("L3", 3.0),
        ("L4", 4.0),
        ("L6", 6.0),
    ] {
        for (dlabel, dscale) in [("s0", 0.0), ("s4", 4.0)] {
            let mut c = lag_base();
            c.name = format!("lag_{llabel}_{dlabel}");
            c.axis = "backfill_lag".into();
            c.fetch_latency_per_unit = lpu;
            c.bond_dur_age_scale = dscale;
            out.push(c);
        }
    }
    // Duration-LEVEL sensitivity (hardening — the constant-vs-servo input). The lag_*
    // block compares only flat (s0) vs one age-scaled level (s4); it shows the benefit
    // EXISTS but not how sensitive it is to getting the LEVEL right. At a fixed mid
    // latency (L2), sweep `bond_dur_age_scale ∈ {0,1,2,4,8}` and read whether serving
    // coverage / oscillation improves MONOTONICALLY and SATURATES (⇒ any reasonable
    // genesis constant captures most of the benefit, so "age-scaled-constant" is robust
    // and the servo's governance surface is unjustified) or is SHARP/non-monotone (⇒ the
    // level matters, favoring the post-testnet-tunable servo). This is the magnitude
    // residue's decision-relevant slice: sign is known; this maps how much the level costs.
    for (slabel, dscale) in [
        ("d0", 0.0),
        ("d1", 1.0),
        ("d2", 2.0),
        ("d4", 4.0),
        ("d8", 8.0),
    ] {
        let mut c = lag_base();
        c.name = format!("lagscale_{slabel}");
        c.axis = "duration_level_sens".into();
        c.fetch_latency_per_unit = 2.0;
        c.bond_dur_age_scale = dscale;
        out.push(c);
    }
    // Bandwidth-bound variant: at a fixed latency, throttle fresh fetches to 1/epoch so
    // backfill cannot keep pace with churn — the regime most likely to surface a real
    // timing benefit for duration. Flat vs age-scaled.
    for (dlabel, dscale) in [("s0", 0.0), ("s4", 4.0)] {
        let mut c = lag_base();
        c.name = format!("lag_rate1_{dlabel}");
        c.axis = "backfill_lag".into();
        c.fetch_latency_per_unit = 2.0;
        c.acq_rate = 1;
        c.bond_dur_age_scale = dscale;
        out.push(c);
    }

    // --- L10 NET test: the backfill benefit AGAINST the lock-in cost, at a genuine
    // capacity bind. The `lag_*` block sits at the covered lean point (no bind), so
    // age-scaling there only helps — it shows the benefit *exists* but not whether it
    // *beats the cost*, because there is no reallocation cost to pay when the committed
    // game has slack. The sharpened L9 reversion clause asks for the NET: re-run at the
    // `bind_*` capacity binds (fast churn `a10`; storage-tightened `0.85`) WITH latency
    // `L2`, flat (s0) vs age-scaled (s4). Read serving `deep_und` (the net retrieval
    // coverage) against committed `deep_und` (the pure reallocation cost banked in
    // `bind_*`) and `servOUmx` (the benefit). The verdict: if age-scaling's serving
    // deep_und is *lower* at the bind, the timing benefit beats the reallocation cost
    // (reopen); if *higher*, the cost dominates (defer holds). ---
    for (blabel, aging, stor) in [("churn", 0.10, 1.0), ("stor", 0.10, 0.85)] {
        for (dlabel, dscale) in [("s0", 0.0), ("s4", 4.0)] {
            let mut c = lag_base();
            c.name = format!("lagbind_{blabel}_{dlabel}");
            c.axis = "backfill_lag_bind".into();
            c.epoch_aging = aging;
            c.storage_scale = stor;
            c.fetch_latency_per_unit = 2.0;
            c.bond_dur_age_scale = dscale;
            out.push(c);
        }
    }

    // --- L8: the (bond-level × deep-shard-size) PAIR sweep. L8 says neither leg moves
    // the co-located pool alone — lowering the bond recruits the storage-rich, shrinking
    // the deep shard recruits the capital-rich, and deep durability needs the *joint*
    // count. Run the stark split-endowment regime (where co-location is scarce and the
    // whale is the only co-located actor) and read `colocated_coverage` (the min-form
    // dS/dN) + non-whale deep coverage as the pair varies. Flat magnitude throughout
    // (L4). ---
    for &bond in &[2.0f64, 1.0, 0.5] {
        for &size in &[1.0f64, 0.5, 0.25] {
            let mut c = baseline();
            c.name = format!("pair_b{bond}_z{size}");
            c.axis = "bond_x_shardsize".into();
            // Stark split: storage-rich are capital-poor, capital-rich are storage-poor,
            // so co-location is scarce (the L8 stress regime).
            c.frac_storage_rich = 0.6;
            c.storage_rich_storage = 22;
            c.storage_rich_capital = 6.0; // capital-poor
            c.capital_rich_storage = 3; // storage-poor
            c.capital_rich_capital = 100.0;
            c.bond_rate = bond;
            c.deep_shard_size = size;
            out.push(c);
        }
    }

    // --- L11: endogenous participation. The operating point is no longer asserted via
    // `budget`; entry/exit is governed by realized APR vs. a per-actor reservation. The
    // pool (`n_actors`) is the set of *potential* archivers; how many actually bond in
    // steady state is emergent. Base config: a large pool (so the active set can be an
    // interior fraction), trickle entry, hysteretic exit. The static baseline world is
    // kept (no frontier churn) so the first L11 read isolates the participation servo
    // from the L9/L10 timing dynamics. ---
    let l11_base = || {
        let mut c = baseline();
        c.endogenous = true;
        // Pool MUST exceed the coverage floor with slack so the participation servo can
        // settle at an interior point that is ALSO coverage-feasible. The coverage floor
        // is ~90 co-located archivers (Σ slot-demand ≈ 1080 at ~16 storage/actor); a pool
        // of 240 gives the servo ~150 actors of headroom to find breakeven above the
        // floor. With pool ≈ floor (the first cut used 120), any pruning breaks coverage
        // and the equilibrium is interior-but-infeasible (a cliff, not a margin).
        c.n_actors = 240;
        c.entry_per_epoch = 6; // capital arrives at a finite rate
        c.participation_patience = 3; // a few bad epochs, not one, before exit
        c.epochs = 160; // pool=240 at 6/epoch fills in ~40; give exit room to settle
        c.churn_window = 50; // steady-state read window
        c
    };

    // (1) ATTRACTOR check: the emergent operating point must be independent of where the
    // population starts. `fill` boots from near-empty (init_active_frac=0 ⇒ bootstrap-
    // like, entrants trickle in) and `trim` boots from full (init_active_frac=1 ⇒ an
    // over-subscribed start the exit channel must prune). If both converge to the same
    // `bondA`/`deep_und` over the window, the operating point is a genuine attractor of
    // the entry/exit dynamic, not an artifact of initialization. Homogeneous mid
    // reservation so the two runs differ ONLY in initialization.
    for (label, init) in [("fill", 0.0_f64), ("trim", 1.0_f64)] {
        let mut c = l11_base();
        c.name = format!("l11_{label}");
        c.axis = "participation_attractor".into();
        c.init_active_frac = init;
        c.reservation_lo = 0.02;
        c.reservation_hi = 0.02;
        out.push(c);
    }

    // (2) RESERVATION sensitivity / calibration: sweep the (homogeneous) reservation
    // yield. As ρ rises, the marginal archiver's breakeven tightens, fewer actors clear
    // it, the emergent `bondA` falls, and `deep_und` rises — the participation servo
    // trading the opportunity-cost floor against coverage. This sweep also CALIBRATES
    // the interior point (the ρ where active_frac sits strictly inside (0,1)), which the
    // attractor/transfer scenarios reuse. Boot from fill so the level is the entry-
    // limited equilibrium, not a trim residue.
    for (label, rho) in [
        ("r000", 0.0_f64),
        ("r01", 0.01),
        ("r02", 0.02),
        ("r03", 0.03),
        ("r05", 0.05),
        ("r10", 0.10),
        ("r20", 0.20),
    ] {
        let mut c = l11_base();
        c.name = format!("l11_rho_{label}");
        c.axis = "participation_reservation".into();
        c.init_active_frac = 0.0;
        c.reservation_lo = rho;
        c.reservation_hi = rho;
        out.push(c);
    }

    // (3) BUDGET → COVERAGE transfer: with participation endogenous, raising `budget`
    // raises realized APR, clears more marginal archivers, and should self-provision MORE
    // coverage WITHOUT retuning the population — the emergent transfer function from the
    // reward purse to deep coverage. Read `bondA`/`deep_und` against `budget` at a fixed
    // interior reservation (mid). This is the L11 headline: budget buys coverage through
    // participation, not through an asserted population.
    for (label, budget) in [("b50", 50.0_f64), ("b100", 100.0), ("b200", 200.0)] {
        let mut c = l11_base();
        c.name = format!("l11_bud_{label}");
        c.axis = "participation_transfer".into();
        c.init_active_frac = 0.0;
        c.budget = budget;
        c.reservation_lo = 0.02;
        c.reservation_hi = 0.02;
        out.push(c);
    }

    // (4) HETEROGENEOUS reservation: a realistic alternative-yield spread. Entrants with
    // low ρ stay; high-ρ entrants probe and leave. The emergent active set should be the
    // low-ρ tail of the pool — a sorting result that the homogeneous sweep can't show.
    {
        let mut c = l11_base();
        c.name = "l11_hetero".into();
        c.axis = "participation_reservation".into();
        c.init_active_frac = 0.0;
        c.reservation_lo = 0.0;
        c.reservation_hi = 0.05;
        out.push(c);
    }

    // --- L12: bootstrapping / cold-start. The L11 layer settled the *steady-state*
    // attractor; L12 asks how the system gets there from genesis, where deep history is
    // ~empty and accrues over time while the archiver population grows into it. Three
    // mechanisms compose: the L11 endogenous entry (init_active_frac=0 ⇒ the empty
    // start), the L9/L10 dynamic aging (deep history forms as hot shards age), and the
    // new growing-window (the chain produces blocks from a small genesis core). The
    // questions: (a) does endogenous entry track the growing deep demand or OVERSHOOT
    // (high early APR pulls in entrants who shed at normalization, churning the youngest/
    // thinnest deep history)? (b) does the population-decaying foundation floor cover the
    // transient the market cannot yet? Reuses the L11 interior-feasible economics
    // (ρ=0.02, budget=100, pool 240, entry 6/epoch). ---
    let l12_base = || {
        let mut c = l11_base();
        c.dynamic = true;
        c.epoch_aging = 0.05; // hot→retire ~20 epochs; deep (age≥0.5) forms ~10 in
        c.bootstrap = true;
        c.n_shard_genesis = 6; // a handful of genesis blocks — all hot, no deep history
        c.shard_growth_per_epoch = 6; // chain grows to n_shard=240 in ~40 epochs
        c.init_active_frac = 0.0; // the literal cold start: zero archivers at genesis
        c.reservation_lo = 0.02;
        c.reservation_hi = 0.02;
        c.epochs = 200; // clear transient (~0–50) then long steady state
        c.churn_window = 60; // steady-state read window (epochs 140–200)
        c
    };

    // (1) COLD-START, no floor: the bare-market transient. `boot_deep_under_peak` is the
    // worst deep retrieval gap (deep history accrues before archivers do); the steady
    // `deep_und`/`bondA` show whether the market recovers to the L11 attractor; and
    // `bonded_active_peak` vs steady `bondA` is the OVERSHOOT read (the APR-inversion
    // early-churn risk). This is the honest unbacked picture.
    {
        let mut c = l12_base();
        c.name = "l12_boot_nofloor".into();
        c.axis = "bootstrap".into();
        c.floor_replicas = 0;
        out.push(c);
    }

    // (2) COLD-START + foundation floor: the same run with the foundation running
    // r_target_deep replicas at genesis, decaying to zero as the bonded-archiver
    // population reaches the emergent steady-state count (~80). `boot_deep_under_floored_peak`
    // ≈0 while the unfloored peak is large is the floor doing its bootstrap job —
    // covering the transient without crowding out entry (it is invisible to the reward
    // servo) and withdrawing once the market is thick.
    {
        let mut c = l12_base();
        c.name = "l12_boot_floor".into();
        c.axis = "bootstrap".into();
        c.floor_replicas = 6; // = r_target_deep: full deep coverage at genesis
        c.floor_decay_pop = 80.0; // withdraw as the archiver set reaches ~steady size
        out.push(c);
    }

    // (3) FLOOR-DECAY schedule: how fast the foundation withdraws. Aggressive (decay_pop
    // small ⇒ floor gone while the market is still half-built) should leave a residual
    // transient gap; gentle (decay_pop large ⇒ floor lingers) fully covers but keeps the
    // foundation working longer. The schedule is the lever trading bootstrap-risk against
    // foundation-burden; the floored peak as a function of decay_pop locates the safe
    // withdrawal speed.
    for (label, decay) in [("fast", 40.0_f64), ("mid", 80.0), ("slow", 160.0)] {
        let mut c = l12_base();
        c.name = format!("l12_decay_{label}");
        c.axis = "bootstrap_floor_decay".into();
        c.floor_replicas = 6;
        c.floor_decay_pop = decay;
        out.push(c);
    }

    // (4) GROWTH-RATE: the chain-growth vs. entry-rate race. Faster block production
    // (more shards/epoch) accrues deep demand faster while entry stays bandwidth-limited
    // (6/epoch), so the bare transient gap should widen with growth — the bootstrap
    // stress is the growth/entry mismatch, not the economics. No floor, so the bare gap
    // is visible. (Steady state is the same L11 attractor regardless of growth rate.)
    for (label, growth) in [("slow", 3usize), ("mid", 6), ("fast", 12)] {
        let mut c = l12_base();
        c.name = format!("l12_growth_{label}");
        c.axis = "bootstrap_growth".into();
        c.shard_growth_per_epoch = growth;
        c.floor_replicas = 0;
        out.push(c);
    }

    // --- L13: fee-era end-state / sustainability (mission timeframe 2, ~30 yr). L11/L12
    // settled the steady-state attractor and the cold-start approach to it *at a fixed
    // purse*. L13 asks the other end: as block subsidy → 0 the archival purse comes from
    // fees / a bounded terminal subsidy, so the purse SHRINKS. Mature chain (dynamic full
    // window, deep history present and aging), start at a healthy population, then decay
    // the subsidy toward `budget_floor` and read: (a) does the lean equilibrium thin and
    // the OLDEST tail go under first (the irreplaceable band)? (b) with price coupling on,
    // does coverage collapse run away (death spiral) or stay bounded? (c) does the
    // adaptive reward-share servo (burn.rs template) damp it, and where does the fee-market
    // ceiling turn damping into a graceful loud failure? (d) does the L12 foundation floor
    // RE-ENGAGE as the market thins (its decay schedule run in reverse)? Reuses the L11
    // interior economics (ρ=0.02, pool 240, entry 6/epoch), starting full and well-funded
    // (budget 200 ⇒ bondA well above the ~80 knee) so the decay sweeps DOWN through the
    // L11 transfer curve. ---
    let l13_base = || {
        let mut c = l11_base();
        c.dynamic = true; // mature aging frontier: deep history continuously produced
        c.epoch_aging = 0.05;
        c.init_active_frac = 1.0; // start full/healthy, let the shrinking purse thin it
        c.reservation_lo = 0.02;
        c.reservation_hi = 0.02;
        c.budget = 200.0; // well-funded at t=0 (above the L11 ~budget-100 coverage knee)
        c.fee_era = true;
        c.budget_decay = 0.02; // subsidy taper toward the terminal floor over the run
        c.epochs = 200;
        c.churn_window = 60; // steady-state (thinned end-state) read window
        c
    };

    // (1) DECAY / terminal-subsidy sweep: no servo, no coupling, no floor — the bare
    // shrinking-purse read. Vary the terminal `budget_floor` the subsidy decays to. As the
    // floor drops below the sustainable purse (~100 from the L11 transfer), the emergent
    // `bondA` thins and the deep tail goes under — `serving_oldest_under_max` should light
    // up FIRST (the oldest band is the most data / least fresh-fee-activity, the
    // irreplaceable band most exposed). Locates the minimum viable terminal subsidy.
    for (label, floor) in [
        ("hi", 100.0_f64),
        ("knee", 80.0),
        ("mid", 60.0),
        ("lo", 40.0),
        ("min", 20.0),
    ] {
        let mut c = l13_base();
        c.name = format!("l13_decay_{label}");
        c.axis = "fee_decay".into();
        c.budget_floor = floor;
        out.push(c);
    }

    // (2) DEATH-SPIRAL: price coupling on, unsustainable floor, NO servo. A deep retrieval
    // shortfall lifts every reservation (lost trust ⇒ expected depreciation), forcing more
    // exit, deepening the shortfall. If `fee_deep_under_peak` runs to ~1 and `bondA`
    // collapses, the loop is undamped — a priority-1 durability failure absent a damping
    // mechanism. This is the unmanaged fee-era at the bad end.
    {
        let mut c = l13_base();
        c.name = "l13_spiral".into();
        c.axis = "fee_spiral".into();
        c.budget_floor = 40.0;
        c.price_coupling = 0.10;
        out.push(c);
    }

    // (3) ADAPTIVE SERVO damps the spiral: same coupling + the burn.rs-style reward-share
    // servo with an adequate ceiling. When coverage slips, the servo raises the purse
    // toward `budget_ceiling`, clearing more archivers and closing the shortfall before the
    // coupling can run away. `fee_deep_under_peak` low + `fee_budget_end` elevated (servo
    // topped the purse up) is the damped result the autonomy rule requires.
    {
        let mut c = l13_base();
        c.name = "l13_servo".into();
        c.axis = "fee_servo".into();
        c.budget_floor = 40.0;
        c.price_coupling = 0.10;
        c.adaptive_share = true;
        c.share_gain = 8.0;
        c.budget_ceiling = 200.0; // adequate fee-market capacity
        out.push(c);
    }

    // (4) CEILING sweep: the servo can only draw what the fee market provides. Sweep the
    // ceiling across the sustainable purse (~100). Below it the servo pins at the ceiling
    // and coverage stays short — a GRACEFUL LOUD FAILURE (fees cannot fund the deep
    // history; a higher terminal subsidy or the foundation floor is required). Above it the
    // servo damps. `fee_budget_end` at the ceiling with a high `fee_deep_under_peak` is the
    // saturated-and-still-short signature.
    for (label, ceil) in [("lo", 70.0_f64), ("mid", 110.0), ("hi", 200.0)] {
        let mut c = l13_base();
        c.name = format!("l13_ceiling_{label}");
        c.axis = "fee_ceiling".into();
        c.budget_floor = 40.0;
        c.price_coupling = 0.10;
        c.adaptive_share = true;
        c.share_gain = 8.0;
        c.budget_ceiling = ceil;
        out.push(c);
    }

    // (5) FOUNDATION FLOOR re-engagement: the L12 floor decay schedule, run in REVERSE. The
    // floor is `floor0 · max(0, 1 − pop/decay_pop)` — in bootstrap `pop` rises and the floor
    // withdraws; in the fee-era `pop` THINS as the purse shrinks, so the floor automatically
    // re-engages. Decay (unsustainable floor) + foundation floor, no servo: the bare deep
    // gap (`boot_deep_under_peak`) is large as the market thins, but the FLOORED gap
    // (`boot_deep_under_floored_peak`) stays ≈0 — retrieval coverage held by the foundation
    // backstop without paying the staker servo. The one non-market capacity source is
    // load-bearing at BOTH ends (genesis and fee-era), as the unifying note predicts.
    {
        let mut c = l13_base();
        c.name = "l13_floor".into();
        c.axis = "fee_floor".into();
        c.budget_floor = 40.0;
        c.floor_replicas = 6; // = r_target_deep
        c.floor_decay_pop = 80.0; // re-engages as bonded archivers thin below ~80
        out.push(c);
    }

    // --- P1 (L8×L11 entanglement): does the L11 "smooth monotone lever" survive when the
    // pool's CO-LOCATION distribution puts the *seatable subset* near the deep floor? The
    // banked L11 gradient sat on an ALL-SEATABLE pool: baseline archetypes each seat ~10
    // deep shards (storage_rich `min(⌊20/2⌋,⌊22/1⌋)=10`, capital-limited; capital_rich
    // `min(⌊100/2⌋,⌊10/1⌋)=10`, storage-limited), so total seating ~2400 ≫ the ~720 deep
    // floor (120 deep shards × R_target_deep 6) — every one of the 240 was seatable, and
    // the breakeven population (~72) cleared the floor with 3× headroom. L8's lesson is
    // that headcount is not the binding constraint, co-located `min(⌊capital/bond⌋,
    // ⌊storage/shard⌋)` is. Here we POLARIZE the archetypes so each seats few deep
    // (storage_rich: ample storage, capital just 8 ⇒ `min(4,22)=4`; capital_rich: ample
    // capital, storage just 3 ⇒ `min(50,3)=3`), giving seating ~840 — still above the 720
    // floor, but now feasibility needs ~86% of the pool active (~206) vs ~30% loose. The
    // question: across the ρ band that gave a smooth loose gradient, does deep coverage
    // transition smoothly or JUMP (a knife-edge) — i.e. is the equilibrium self-correcting
    // or fragile when co-location, not headcount, sets the floor?
    let l11_coloc_base = || {
        let mut c = l11_base();
        c.frac_storage_rich = 0.5;
        c.storage_rich_storage = 22; // ample storage…
        c.storage_rich_capital = 8.0; // …capital-limited to ⌊8/2⌋=4 deep seats
        c.capital_rich_storage = 3; // storage-limited to 3 deep seats…
        c.capital_rich_capital = 100.0; // …capital ample
        c.init_active_frac = 0.0; // boot from fill (entry-limited equilibrium)
        c
    };
    // (P1a) co-location-binding ρ gradient — compare bondA/deep_und vs ρ against the loose
    // `l11_rho_*` sweep. A smooth fall ⇒ the lever survives co-location; a 0→1 jump ⇒ the
    // smooth gradient was a seatable-pool artifact and the realistic equilibrium is a
    // knife-edge.
    for (label, rho) in [
        ("r005", 0.005_f64),
        ("r01", 0.01),
        ("r015", 0.015),
        ("r02", 0.02),
        ("r03", 0.03),
    ] {
        let mut c = l11_coloc_base();
        c.name = format!("p1_coloc_{label}");
        c.axis = "p1_coloc_gradient".into();
        c.reservation_lo = rho;
        c.reservation_hi = rho;
        out.push(c);
    }
    // (P1b) budget → coverage transfer under binding co-location: if the gradient is a
    // knife-edge in ρ, can budget (raising APR) still buy coverage smoothly, or does the
    // co-location ceiling cap it regardless of purse? Fixed interior ρ, sweep budget.
    for (label, budget) in [("b100", 100.0_f64), ("b200", 200.0), ("b400", 400.0)] {
        let mut c = l11_coloc_base();
        c.name = format!("p1_coloc_{label}");
        c.axis = "p1_coloc_transfer".into();
        c.budget = budget;
        c.reservation_lo = 0.01;
        c.reservation_hi = 0.01;
        out.push(c);
    }

    // --- P2 (flow-cost denomination / second death-spiral leg): is the L13 disposition
    // complete? The price-coupling insight (token-denominated reward and bond cancel in
    // the APR ratio, so only *expected depreciation* bites) holds only if EVERY term is
    // token-denominated. The operational flow cost (bandwidth, storage hardware) is paid
    // in fiat. With `flow_cost_fiat`, the exit APR is `R/B − F/(B·p)`: a low/falling price
    // raises the real flow-cost drag — a LEVEL channel that can ignite exit with NO
    // trust-loss trigger (`price_coupling = 0`). These scenarios fund the token side
    // ADEQUATELY (`budget_floor = 100`, the L11 knee) and set `price_coupling = 0`, so any
    // collapse is the fiat leg alone, not subsidy starvation or expectation feedback.
    let l13_fiat_base = || {
        let mut c = l13_base();
        c.budget_floor = 100.0; // token side sustainable (above the L11 knee)
        c.price_coupling = 0.0; // NO expectation channel — isolate the level channel
        c.flow_cost_fiat = true; // flow cost paid in fiat
        c.token_price = 1.0; // start at parity (fiat cost == token cost)
        c
    };
    // (P2a) CONTROL: fiat flow cost, price stays at parity. `F/(B·1) = F/B`, so this must
    // reproduce the token-denominated behavior — coverage holds. Confirms the flag is
    // inert at `p = 1`.
    {
        let mut c = l13_fiat_base();
        c.name = "p2_fiat_stable".into();
        c.axis = "p2_fiat".into();
        out.push(c);
    }
    // (P2b) FALLING PRICE, no trust trigger: the token loses 75% of its value over the run
    // (`price_floor = 0.25`) while coverage funding stays adequate and `price_coupling = 0`.
    // If `fee_deep_under_peak` lights up and `bondA` thins, the fiat drag alone forced exit
    // — the level channel ignites WITHOUT trust loss, and the L13 disposition is incomplete
    // (the spiral has two legs, not one).
    {
        let mut c = l13_fiat_base();
        c.name = "p2_fiat_fall".into();
        c.axis = "p2_fiat".into();
        c.price_decay = 0.02;
        c.price_floor = 0.25;
        out.push(c);
    }
    // (P2c) SERVO vs the level channel: the burn.rs servo tops up the *token* purse. Higher
    // token reward R lifts `R/B` and can offset `F/(B·p)` — but only with enough ceiling
    // headroom to over-pay the fiat drag. Tests whether the SAME damping apparatus that
    // caught the expectation channel also catches the level channel, and at what ceiling.
    {
        let mut c = l13_fiat_base();
        c.name = "p2_fiat_fall_servo".into();
        c.axis = "p2_fiat".into();
        c.price_decay = 0.02;
        c.price_floor = 0.25;
        c.adaptive_share = true;
        c.share_gain = 8.0;
        c.budget_ceiling = 400.0; // more headroom than the expectation-channel servo needed
        out.push(c);
    }

    // --- L15 (retrieval availability / correlated failure): coverage ≠ retrieval. Every
    // prior layer scored a shard "covered" at `R ≥ R_target`. The property users need is
    // *retrieval* — ≥1 holder reachable at a target availability `A*`. Two facts the
    // coverage score ignores: (i) holders have per-holder uptime `u < 1`, so redundancy
    // is what converts `u` into `A*`; (ii) holders share **failure domains**
    // (jurisdiction / ASN / client), and a shard's effective redundancy is its count of
    // *distinct domains* `d`, not its raw replica count `R`. Availability `= 1 − (1−u)^d`.
    // These scenarios run on a HEALTHY, fully-covered deep set (the L11 attractor at a low
    // ρ) and ask: does the covered set actually meet its retrieval SLA, and what erodes it?
    let l15_base = || {
        let mut c = l11_base();
        c.init_active_frac = 0.0; // boot from fill → entry-limited covered equilibrium
        c.reservation_lo = 0.01; // low ρ → deep covered with headroom (R ≥ R_target_deep)
        c.reservation_hi = 0.01;
        c.retrieval_model = true;
        c.retr_uptime = 0.9; // 90% holder uptime (self-hosted node over the L16 onion path)
        c.retr_avail_target = 0.999; // three-nines retrieval SLA
        c.retr_n_domains = 0; // independent (each holder its own domain) — overridden below
        c
    };
    // (L15a) INDEPENDENT baseline: each holder its own domain (`d == R`). With R≈6 deep and
    // u=0.9, availability `1 − 0.1^6 ≈ 1` ≫ A* — retr_under_deep ≈ 0. This recovers the L4
    // arithmetic and confirms the covered set meets the SLA *when failure is independent*.
    {
        let mut c = l15_base();
        c.name = "l15_indep".into();
        c.axis = "l15_domains".into();
        out.push(c);
    }
    // (L15b) CORRELATED sweep: bucket holders into `n_domains` failure classes. As domains
    // fall, `d` caps below `R` and availability `1 − 0.1^d` drops: d=3 ⇒ 0.999 (at the
    // SLA), d=2 ⇒ 0.99 (under), d=1 ⇒ 0.9 (far under). The deep set stays fully *covered*
    // (R unchanged) yet `retr_under_deep` climbs — the headline coverage≠retrieval result:
    // **diversity (≥3 domains), not replica count, is the binding retrieval constraint.**
    for (label, nd) in [("d1", 1usize), ("d2", 2), ("d3", 3), ("d6", 6)] {
        let mut c = l15_base();
        c.name = format!("l15_corr_{label}");
        c.axis = "l15_domains".into();
        c.retr_n_domains = nd;
        out.push(c);
    }
    // (L15c) UPTIME sweep → derived R_target. Hold domains independent and vary `u`; the
    // reported `rTgtA` is the deep redundancy the SLA *requires* (`⌈ln(1−A*)/ln(1−u)⌉`),
    // read off `(u, A*)` rather than stipulated. u=0.9 ⇒ 3, u=0.8 ⇒ 5, u=0.5 ⇒ 10: the
    // stipulated `r_target_deep = 6` silently assumes `u ≳ 0.85`. Below that, the covered
    // set is under-redundant for the SLA even with independent failure.
    for (label, u) in [
        ("u95", 0.95_f64),
        ("u90", 0.90),
        ("u80", 0.80),
        ("u50", 0.50),
    ] {
        let mut c = l15_base();
        c.name = format!("l15_uptime_{label}");
        c.axis = "l15_uptime".into();
        c.retr_uptime = u;
        out.push(c);
    }

    // --- L14 (proof-of-archival / free-rider economics): minimize the non-productive
    // (oversight-only) traffic. Reward is for *provable* archival; the free-rider claims a
    // shard without storing it. What deters this is the per-epoch audit probability `a*`
    // (caught ⇒ slashed): abstain iff `a* · penalty ≥ benefit`, so `a* = benefit/penalty`.
    // The L14×L15 spec's lever: a successful content-bound **retrieval IS a proof**, so
    // every real read audits its shard for free. Explicit PoR challenges are then only the
    // top-up the cold (unread) tail needs to reach `a*`. These scenarios run on the same
    // healthy covered substrate and quantify how much oversight traffic the read-credit
    // saves and *where* the residual lands.
    let l14_base = || {
        let mut c = l15_base();
        c.retrieval_model = false; // L14 is the audit layer; retrieval columns off here
        c.audit_model = true;
        c
    };
    // (L14a) CREDITED vs NAIVE: the headline. `auN` is the naive cadence (challenge every
    // shard at `a*`); `auC` is the credited mean (reads self-prove the hot shards). The
    // result: `auC ≪ auN`, and `auDp ≈ 1` — the oversight traffic is confined to the cold
    // deep tail, hot shards proven for free by their reads.
    {
        let mut c = l14_base();
        c.name = "l14_credited".into();
        c.axis = "l14_audit".into();
        out.push(c);
    }
    // (L14b) PENALTY lever: a heavier slash lowers the deterrence threshold `a*`
    // (`benefit/penalty`), so *less* oversight is needed. Sweep penalty 0.5/1/2/4 ⇒ `a*`
    // 0.2/0.1/0.05/0.025. The cheapest oversight comes from a credible slash, not a high
    // challenge cadence — the bond/penalty is the primary deterrent, challenges the top-up.
    for (label, pen) in [("p05", 0.5_f64), ("p1", 1.0), ("p2", 2.0), ("p4", 4.0)] {
        let mut c = l14_base();
        c.name = format!("l14_penalty_{label}");
        c.axis = "l14_penalty".into();
        c.freeride_penalty = pen;
        out.push(c);
    }
    // (L14c) READ-RATE lever: the more the cold tail is actually read, the less explicit
    // challenge it needs. Sweep the cold read floor 0.001/0.01/0.05/0.1 ⇒ as it approaches
    // `a*=0.1` the oldest-band cadence `auOld` falls toward 0 (reads alone deter). Shows the
    // non-productive traffic is bounded by *demand* on the cold tail — popular history is
    // self-policing; only the truly-unread deep shards carry oversight (P3 again).
    for (label, cold) in [
        ("c0001", 0.001_f64),
        ("c001", 0.01),
        ("c005", 0.05),
        ("c01", 0.1),
    ] {
        let mut c = l14_base();
        c.name = format!("l14_read_{label}");
        c.axis = "l14_readrate".into();
        c.read_cold = cold;
        out.push(c);
    }

    // --- P3 (age-stratified floor / irreplaceable-tail protection): L13#2 found the OLDEST
    // band oscillates under (oUmx 0.163) while mid-deep holds (cDeepU 0.057), and the L12
    // hand-off residual (0.019) is an *aggregate* deep figure that may hide an oldest-band
    // concentration. The new `boOld` column band-resolves the floored gap: `boOld > bDUf`
    // on the uniform-floor scenarios (l12_*, l13_floor) is the band-resolve test — it
    // confirms the residual sits in the irreplaceable tail. P3's lever is an age-stratified
    // floor: `foundation_floor_aged` applies a MEAN-PRESERVING oldest-ward tilt (same total
    // foundation cost, redistributed toward the deepest band — the same way `R_target(age)`
    // already tilts). These scenarios run the REALISTIC re-engagement floor
    // (`floor_replicas = 6 = r_target_deep`, matching `l13_floor`), at which the fee-era
    // residual concentrates in the oldest band (`l13_floor`: boOld 0.612 > bDUf 0.425),
    // then sweep the tilt: `boOld` should fall toward 0 as the tilt steers replicas to the
    // oldest band, at the cost of a modest rise in the aggregate gap (younger, re-derivable
    // deep history under-floored). That trade — protect the irreplaceable, let the
    // replaceable ride the market — is the P3 disposition.
    //
    // (P3a) FEE-ERA re-engagement (= `l13_floor` at tilt 0). The market thins, the floor
    // re-engages, but the oldest band is abandoned by the market FIRST (age-weight churn),
    // so the floored residual lands on the irreplaceable tail. The tilt over-floors the
    // oldest band (round(6·(1+tilt))) at the expense of the freshly-deepened band
    // (round(6·(1−tilt))). `boOld` ↓ while `bDUf` holds/rises slightly is the trade.
    for (label, tilt) in [("t00", 0.0_f64), ("t03", 0.3), ("t06", 0.6), ("t09", 0.9)] {
        let mut c = l13_base();
        c.name = format!("p3_fee_tilt_{label}");
        c.axis = "p3_fee_tilt".into();
        c.budget_floor = 40.0;
        c.floor_replicas = 6; // = r_target_deep, the realistic re-engagement floor
        c.floor_decay_pop = 80.0; // re-engages as bonded archivers thin below ~80
        c.floor_age_tilt = tilt;
        out.push(c);
    }
    // (P3b) BOOTSTRAP (= `l12_boot_floor` at tilt 0). The asymmetry check: at genesis the
    // oldest shards are the genesis core (covered earliest/longest), so the bootstrap
    // residual is the freshly-deepened band, NOT the oldest (`boOld` ≈ 0). The tilt should
    // therefore leave `boOld` at ~0 — confirming the irreplaceable tail is exposed at the
    // FEE-ERA end, not the bootstrap end, so the age-stratification is a fee-era lever.
    for (label, tilt) in [("t00", 0.0_f64), ("t03", 0.3), ("t06", 0.6), ("t09", 0.9)] {
        let mut c = l12_base();
        c.name = format!("p3_boot_tilt_{label}");
        c.axis = "p3_boot_tilt".into();
        c.floor_replicas = 6; // = r_target_deep, matching l12_boot_floor
        c.floor_decay_pop = 80.0;
        c.floor_age_tilt = tilt;
        out.push(c);
    }

    out
}
