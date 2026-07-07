// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TM-1 / A0 — shard-portfolio linkage across **sequential persona rotation**.
//!
//! ## Grounding correction (what this harness is, after a retraction)
//!
//! The staking design rotates personas **sequentially**: "there is never a window
//! with two active personas" (`shekyl-engine-core` `stake_engine` — atomic
//! rotation). An operator runs **one** active persona at a time and rotates to a
//! fresh one for unlinkability; a bonded retired persona stays resident only so
//! unbonding/claiming remains reachable (the `W`-tail), never as a second active
//! persona. An earlier draft of this round modelled an operator **splitting
//! capacity across K *simultaneous* personas** to hide scale and built a
//! sibling-clustering matcher on it. That premise was a phantom extrapolated from
//! how other systems' anonymity sets work; the design does not do it, and the
//! economics make it self-defeating (the `1/R` scarcity reward means two personas
//! on the same shard split one reward and pay double work; on different shards they
//! are simply a bigger operator doing proportionally more work for proportional
//! pay — coverage, no exploit). So running simultaneous personas only correlates
//! *yourself* — a one-line wallet disclosure, not a mechanism, and not an open
//! problem. The matcher and the "split cardinality" hand-off are **retracted**.
//!
//! ## What this harness measures (real, design-relevant)
//!
//! The F1 "portfolio-bound" linkage across rotation: when an operator rotates from
//! retired persona A to fresh persona B, does B carry forward A's public
//! `shard_ids` (`bond_wire::HoldingsDescriptor::shard_ids`)? At the lean
//! equilibrium portfolios are ~unique, so re-taking the same set re-links the
//! succession on the portfolio alone. The **dispersive default** — B re-selects a
//! value-approximating set **disjoint** from A's prior set — decorrelates the
//! portfolio across the succession, at a haircut. This harness quantifies that
//! haircut, the network-size threshold where dispersion has room, and the value
//! structure it operates on. The residual after dispersion is the **temporal
//! intersection** channel (an adversary clustering the succession over a lifetime)
//! — that is T-A1 / TM-2, already instrumented in `fingerprint.rs`, not a new
//! problem.
//!
//! ## What the substrate forces (verified, not assumed — the CT-5 discipline)
//!
//! - The shard **set** (not just the count) is public on-wire, keyed to the persona
//!   (`bond_wire::HoldingsDescriptor::shard_ids`) — so re-using it across rotation
//!   is a linkable correlate.
//! - Consensus scarcity is `1/R · g(age)` with **no intrinsic per-shard difficulty
//!   term** (`reward_arithmetic::scarcity_milli`; `g_age` is the only weight —
//!   `model::g_age`). So a shard is "high-value" purely because few chose it
//!   (demand-driven), never because it is hard to serve. The `phi` sensitivity arm
//!   injects a per-shard cost the protocol lacks, to confirm the verdict is not an
//!   absence-artifact (a per-shard cost `phi ≳ 0.5` re-steepens the attractor — the
//!   rule-21 reopen number).
//!
//! ## The mechanism, made measurable
//!
//! The dispersive-default haircut **is the local steepness of the scarcity
//! value-curve**: the value an operator gives up when its fresh persona must pick a
//! set **disjoint** from the retired one rather than re-take the top-value block.
//! Endogenous in the dispersion-adoption fraction α: dispersers spread coverage
//! onto under-served deep shards → their `R` rises → `1/R` falls → the curve
//! flattens. The disperser must stay **in-tier** (the deep tier an independent
//! reward-maximizer occupies); spreading **cross-tier** into the hot tail charges
//! the **intrinsic `g(age)` premium** dispersion cannot flatten — kept as the
//! anti-virtuous baseline so the in-tier result is not read as free. The
//! within-tier-room (deep-tier redundancy = mean served-deep `R`) is the
//! honest-degradation predictor: as it falls toward 1 (the swan-2 trough / small
//! network) there is no slack to rotate onto a fresh deep set, and dispersion runs
//! out regardless of α.
//!
//! Focused harness (like `cover.rs` / `standoff.rs`), not `run_sim`. Its
//! load-bearing claim is only that it reproduces the known capacity-regime result
//! (the positive control: redundant deep coverage at the lean attractor, the
//! coverage edge at the trough). Every verdict is a ratio (haircut fraction), so
//! the arbitrary reward scale cancels.

use serde::Serialize;

use crate::model::g_age;

// ===========================================================================
// Deterministic RNG (local, like cover.rs — determinism is load-bearing so the
// sweep is reproducible and git-diffable across runs).
// ===========================================================================

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn shuffle<T>(&mut self, s: &mut [T]) {
        for i in (1..s.len()).rev() {
            let j = self.below(i + 1);
            s.swap(i, j);
        }
    }
}

// ===========================================================================
// Grounded constants — single-sourced shape from the baseline scenario
// (`scenarios.rs`) so the harness sits on the same economic substrate the rest of
// the sim is validated against. Per-shard `phi` is the one term NOT in the
// protocol — the injected sensitivity axis.
// ===========================================================================

/// `g_age = 1 + age_weight·age`; baseline `age_weight = 2` ⇒ the deepest shards
/// carry a 3× scarcity premium over the hot frontier — the value-curve steepness.
const AGE_WEIGHT: f64 = 2.0;
/// `age ≥ deep_threshold` ⇒ deep history ⇒ requires a retention bond.
const DEEP_THRESHOLD: f64 = 0.5;
/// Flat per-deep-shard bond (mid rung).
const BOND_RATE: f64 = 2.0;
/// Flow cost per held shard (storage/bandwidth) — uniform across shards (protocol).
const STORAGE_UNIT_COST: f64 = 0.03;
/// Flow opportunity cost of capital locked in one deep-shard bond.
const BOND_CARRY: f64 = 0.03;
/// Reward scale (arbitrary; cancels in every ratio). Sets `value = SCALE/R·g(age)`.
const REWARD_SCALE: f64 = 1.0;
/// Storage units a deep shard occupies (iteration-1 uniform value).
const DEEP_SHARD_SIZE: f64 = 1.0;

// ===========================================================================
// Population model — single-persona operators (one active persona each, the
// sequential-rotation design). The operator IS its current persona; rotation
// re-selects its shard set.
// ===========================================================================

/// One operator's capacity archetype (`scenarios.rs`): the heterogeneity that is
/// the only real supply-side floor source once serving cost is ruled out.
/// Storage-rich actors are capital-poor and vice-versa, so the binding constraint
/// is the `min(⌊capital/bond⌋, ⌊storage/shard_size⌋)` seat count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum Archetype {
    StorageRich,
    CapitalRich,
}

impl Archetype {
    /// `(storage_capacity, capital)` per the baseline scenario.
    fn endowment(self) -> (usize, f64) {
        match self {
            Archetype::StorageRich => (22, 20.0),
            Archetype::CapitalRich => (10, 100.0),
        }
    }
}

/// An operator's rotation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum Strategy {
    /// Reward-maximize; on rotation re-take the best set (may re-take its prior
    /// set → portfolio-bound re-link, the F1 failure the default prevents).
    Concentrate,
    /// Dispersive default: on rotation re-select a set **disjoint** from the
    /// retired persona's set, decorrelating the succession. Pays the haircut.
    Disperse,
}

/// One operator's active persona: a bond-post the chain sees. `holdings` is the
/// public shard set; `prior` is the retired persona's set (the disjoint-from
/// target on a dispersive rotation). `operator` equals the persona's own index
/// (1:1 — one active persona per operator).
#[derive(Debug, Clone)]
struct Persona {
    operator: usize,
    storage_capacity: usize,
    capital: f64,
    holdings: Vec<bool>,
    prior: Vec<bool>,
}

// ===========================================================================
// Scenario / regime configuration.
// ===========================================================================

/// Capacity regime — the load-bearing axis. Lean ≈ the `F1` attractor (~80 bonded),
/// trough ≈ the swan-2 post-shock floor (~20 bonded). Regimes differ only in
/// operator count against a fixed shard space (aggregate capacity vs. demand).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Regime {
    /// Capacity-rich attractor — dispersion has room.
    Lean,
    /// Capacity-starved swan trough — dispersion runs out of room.
    Trough,
}

impl Regime {
    /// Operator (= active-persona) count, matching `F1`'s ~79–100 / 9–25 bonded.
    fn operators(self) -> usize {
        match self {
            Regime::Lean => 80,
            Regime::Trough => 20,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ClusterConfig {
    regime: Regime,
    n_shard: usize,
    /// Dispersion adoption fraction.
    alpha: f64,
    /// Per-shard serving-cost magnitude (the sensitivity axis). `phi·age(s)` is
    /// added to a shard's serve cost — the realistic "deep is expensive" injection
    /// the protocol does NOT have. `0.0` = protocol reality.
    phi: f64,
    /// Epochs between rotations (each disperser re-selects disjoint-from-prior).
    rotation_period: usize,
    /// Disperser stratification window, as a multiple of the reward-max block size.
    /// `0` = CROSS-TIER (whole-list spread — charges the `g(age)` premium and
    /// abandons the deep top, the anti-virtuous baseline kept for comparison).
    /// `>0` = IN-TIER (stay where an independent deep-concentrated operator sits,
    /// spreading only *which* deep shards — isolates the flattenable `1/R`).
    spread_window_mult: usize,
    epochs: usize,
    seed: u64,
}

// ===========================================================================
// Equilibrium.
// ===========================================================================

struct Pop {
    /// Shard ages (dynamic; recycled at age ≥ 1).
    ages: Vec<f64>,
    personas: Vec<Persona>,
    n_operators: usize,
    /// The per-shard serve-cost magnitude this equilibrium settled under (so the
    /// haircut ranks candidates with the same φ the equilibrium used).
    phi: f64,
    /// The disperser stratification window this equilibrium ran under.
    spread_window_mult: usize,
}

/// Net marginal value of shard `s`, given current replication `r` and whether the
/// persona already holds it (so adding it makes `r+1`).
fn net_value(s: usize, ages: &[f64], r: &[usize], held: bool, phi: f64) -> f64 {
    let r_eff = if held { r[s].max(1) } else { r[s] + 1 };
    let age = ages[s];
    let deep = age >= DEEP_THRESHOLD;
    let value = REWARD_SCALE * (1.0 / r_eff as f64) * g_age(age, AGE_WEIGHT);
    let cost = STORAGE_UNIT_COST + if deep { BOND_CARRY } else { 0.0 } + phi * age;
    value - cost
}

/// Gross scarcity value of shard `s` at replication `r` (no cost) — the quantity
/// the value-curve and the haircut are measured in.
fn gross_value(s: usize, ages: &[f64], r: &[usize]) -> f64 {
    REWARD_SCALE * (1.0 / r[s].max(1) as f64) * g_age(ages[s], AGE_WEIGHT)
}

/// Replication per shard = number of distinct active personas holding it (= the
/// consensus `R`, since one active persona per operator).
fn replication(personas: &[Persona], n_shard: usize) -> Vec<usize> {
    let mut r = vec![0usize; n_shard];
    for p in personas {
        for (s, &h) in p.holdings.iter().enumerate() {
            if h {
                r[s] += 1;
            }
        }
    }
    r
}

fn stor_cost(deep: bool) -> f64 {
    if deep {
        DEEP_SHARD_SIZE
    } else {
        1.0
    }
}
fn bond_cost(deep: bool) -> f64 {
    if deep {
        BOND_RATE
    } else {
        0.0
    }
}

/// The candidate list: shards with **positive** net value (no rational operator
/// holds a money-losing shard), excluding `forbidden` (a rotating disperser's own
/// prior set), highest net value first. Ranked by the fresh-acquisition view
/// (adding makes `R+1`).
fn ranked_candidates(ages: &[f64], r: &[usize], phi: f64, forbidden: &[bool]) -> Vec<usize> {
    let mut v: Vec<(usize, f64)> = (0..ages.len())
        .filter(|&s| !forbidden[s])
        .map(|s| (s, net_value(s, ages, r, false, phi)))
        .filter(|&(_, net)| net > 0.0)
        .collect();
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v.into_iter().map(|(s, _)| s).collect()
}

/// Greedily take shards from `ranked` (value-desc) under a storage + capital
/// budget — the reward-max **block** a CONCENTRATE rotation re-takes.
fn feasible_block(
    ranked: &[usize],
    ages: &[f64],
    total_storage: f64,
    total_capital: f64,
) -> Vec<usize> {
    let mut out = Vec::new();
    let (mut us, mut ub) = (0.0f64, 0.0f64);
    for &s in ranked {
        let deep = ages[s] >= DEEP_THRESHOLD;
        if us + stor_cost(deep) > total_storage {
            continue;
        }
        if deep && ub + bond_cost(deep) > total_capital {
            continue;
        }
        out.push(s);
        us += stor_cost(deep);
        ub += bond_cost(deep);
    }
    out
}

/// A value-rank-**stratified** set of `m` shards — the DISPERSIVE default. With
/// `window_mult == 0` it spreads across the **whole** positive-net list
/// (CROSS-TIER: charges the intrinsic `g(age)` premium and abandons the deep top —
/// the anti-virtuous baseline). With `window_mult > 0` it restricts to the top
/// `m·window_mult` candidates (IN-TIER: stays where an independent deep-concentrated
/// operator sits, spreading only *which* high-value shards — the flattenable `1/R`).
fn stratified_set(
    ranked: &[usize],
    ages: &[f64],
    m: usize,
    total_storage: f64,
    total_capital: f64,
    window_mult: usize,
) -> Vec<usize> {
    if ranked.is_empty() || m == 0 {
        return Vec::new();
    }
    let l = if window_mult == 0 {
        ranked.len()
    } else {
        (m * window_mult).min(ranked.len())
    };
    let mut out = Vec::new();
    let mut taken = vec![false; l];
    let (mut us, mut ub) = (0.0f64, 0.0f64);
    for i in 0..m {
        let anchor = if m == 1 { 0 } else { i * (l - 1) / (m - 1) };
        for off in 0..l {
            let j = (anchor + off) % l;
            if taken[j] {
                continue;
            }
            let s = ranked[j];
            let deep = ages[s] >= DEEP_THRESHOLD;
            if us + stor_cost(deep) > total_storage {
                continue;
            }
            if deep && ub + bond_cost(deep) > total_capital {
                continue;
            }
            taken[j] = true;
            out.push(s);
            us += stor_cost(deep);
            ub += bond_cost(deep);
            break;
        }
    }
    out
}

/// The persona's selected shard set: the top block (concentrate), or — dispersing
/// — a stratified set of the **same size** within the tier window.
fn select_set(
    ranked: &[usize],
    ages: &[f64],
    total_storage: f64,
    total_capital: f64,
    spread: bool,
    window_mult: usize,
) -> Vec<usize> {
    let block = feasible_block(ranked, ages, total_storage, total_capital);
    if !spread {
        block
    } else {
        stratified_set(
            ranked,
            ages,
            block.len(),
            total_storage,
            total_capital,
            window_mult,
        )
    }
}

/// Run the endogenous coverage equilibrium to steady state. Each operator runs one
/// active persona, best-responding asynchronously (Gauss–Seidel: `R` updates after
/// each move — the myopia-damping discipline). Dispersers rotate every
/// `rotation_period` epochs onto a set disjoint from their prior (retired) one.
fn run_equilibrium(cfg: &ClusterConfig) -> Pop {
    let mut rng = SplitMix64::new(cfg.seed);
    let n_shard = cfg.n_shard;

    // Shards: uniform ages across [0,1), shuffled so the index does not encode age.
    let mut ages: Vec<f64> = (0..n_shard)
        .map(|i| (i as f64 + 0.5) / n_shard as f64)
        .collect();
    rng.shuffle(&mut ages);

    let n_op = cfg.regime.operators();
    let mut strategy = vec![Strategy::Concentrate; n_op];
    let mut personas: Vec<Persona> = Vec::with_capacity(n_op);
    for (op, strat) in strategy.iter_mut().enumerate() {
        // 50/50 storage-rich / capital-rich (baseline mix), archetype-interleaved.
        let arche = if op % 2 == 0 {
            Archetype::StorageRich
        } else {
            Archetype::CapitalRich
        };
        let (storage, capital) = arche.endowment();
        // First ⌊α·n_op⌋ operators adopt the dispersive rotation default.
        *strat = if (op as f64) < cfg.alpha * n_op as f64 {
            Strategy::Disperse
        } else {
            Strategy::Concentrate
        };
        personas.push(Persona {
            operator: op,
            storage_capacity: storage,
            capital,
            holdings: vec![false; n_shard],
            prior: vec![false; n_shard],
        });
    }

    for ep in 0..cfg.epochs {
        let mut order: Vec<usize> = (0..n_op).collect();
        rng.shuffle(&mut order);
        // Rotation tick: dispersers snapshot their set as `prior` (the retired
        // persona) and re-select disjoint from it this epoch.
        let rotating = ep > 0 && cfg.rotation_period > 0 && ep % cfg.rotation_period == 0;
        if rotating {
            for p in personas.iter_mut() {
                if strategy[p.operator] == Strategy::Disperse {
                    p.prior = p.holdings.clone();
                }
            }
        }

        for &op in &order {
            let r = replication(&personas, n_shard);
            let spread = strategy[op] == Strategy::Disperse;
            // A rotating disperser avoids its own prior (retired) set.
            let mut forbidden = vec![false; n_shard];
            if spread && rotating {
                for (s, &h) in personas[op].prior.iter().enumerate() {
                    if h {
                        forbidden[s] = true;
                    }
                }
            }
            let ranked = ranked_candidates(&ages, &r, cfg.phi, &forbidden);
            let storage = personas[op].storage_capacity as f64;
            let capital = personas[op].capital;
            let selected = select_set(
                &ranked,
                &ages,
                storage,
                capital,
                spread,
                cfg.spread_window_mult,
            );
            let mut h = vec![false; n_shard];
            for &s in &selected {
                h[s] = true;
            }
            personas[op].holdings = h;
        }

        // Age the window (dynamic frontier; recycle at age ≥ 1).
        let drift = 1.0 / cfg.epochs as f64 * 0.5; // gentle; ~half a window over the run
        for (s, age) in ages.iter_mut().enumerate() {
            *age += drift;
            if *age >= 1.0 {
                *age -= 1.0;
                for p in personas.iter_mut() {
                    p.holdings[s] = false;
                }
            }
        }
    }

    Pop {
        ages,
        personas,
        n_operators: n_op,
        phi: cfg.phi,
        spread_window_mult: cfg.spread_window_mult,
    }
}

// ===========================================================================
// Measurements.
// ===========================================================================

/// The dispersive-default **haircut** a disperser faces at this α-equilibrium: for
/// a representative operator (averaged over the two archetypes), the gross value of
/// the reward-max top **block** vs. the value-rank-stratified **disjoint** set of
/// the same size, both at the settled `R`-landscape — the local steepness of the
/// scarcity value-curve. A fraction in `[0,1]` that flattens (virtuous) or floors
/// (capacity-bound / φ) as α rises.
fn haircut(pop: &Pop) -> f64 {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    let forbidden = vec![false; n_shard];
    let ranked = ranked_candidates(&pop.ages, &r, pop.phi, &forbidden);
    let value = |set: &[usize]| -> f64 { set.iter().map(|&s| gross_value(s, &pop.ages, &r)).sum() };

    let archetypes = [
        Archetype::StorageRich.endowment(),
        Archetype::CapitalRich.endowment(),
    ];
    let mut acc = 0.0;
    let mut n = 0usize;
    for (storage, capital) in archetypes {
        let block = feasible_block(&ranked, &pop.ages, storage as f64, capital);
        if block.is_empty() {
            continue;
        }
        let spread = stratified_set(
            &ranked,
            &pop.ages,
            block.len(),
            storage as f64,
            capital,
            pop.spread_window_mult,
        );
        let (vb, vs) = (value(&block), value(&spread));
        if vb > 1e-12 {
            acc += ((vb - vs) / vb).max(0.0);
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        acc / n as f64
    }
}

/// Value-curve steepness: mean gross value of the top decile of shards over the
/// population mean. `1.0` = flat; `≫1` = steep. The mechanism behind the haircut.
fn curve_steepness(pop: &Pop) -> f64 {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    let mut vals: Vec<f64> = (0..n_shard)
        .map(|s| gross_value(s, &pop.ages, &r))
        .collect();
    vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let top = (vals.len() / 10).max(1);
    let top_mean = vals[..top].iter().sum::<f64>() / top as f64;
    if mean <= 1e-12 {
        1.0
    } else {
        top_mean / mean
    }
}

/// Deep-tier diagnostics — the mechanism instrument. The anti-virtuous (cross-tier)
/// diagnosis (dispersion pulls coverage off the scarce deep top, making it scarcer)
/// is falsifiable here: if real, `mean_r` falls and `mean_value` rises as α rises.
/// The **within-tier room** (`room_redundancy` = mean served-deep `R`) is the
/// honest-degradation predictor: as it falls toward 1 there is no slack to rotate
/// onto a fresh deep set, so in-tier dispersion runs out regardless of α.
struct DeepStats {
    served_frac: f64,
    mean_r: f64,
    max_r: usize,
    mean_value: f64,
    hold_frac: f64,
    /// `pool` = deep shards ÷ mean operator deep-holdings (how many disjoint
    /// operator-sized deep sets the pool holds); `redundancy` = mean served-deep `R`
    /// (the binding slack). They can diverge — `pool ≫ 1` while `redundancy → 1`.
    room_pool: f64,
    room_redundancy: f64,
}

fn deep_stats(pop: &Pop) -> DeepStats {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    let deep: Vec<usize> = (0..n_shard)
        .filter(|&s| pop.ages[s] >= DEEP_THRESHOLD)
        .collect();
    let n_deep = deep.len().max(1);
    let served: Vec<usize> = deep.iter().copied().filter(|&s| r[s] >= 1).collect();
    let served_frac = served.len() as f64 / n_deep as f64;
    let mean_r = if served.is_empty() {
        0.0
    } else {
        served.iter().map(|&s| r[s] as f64).sum::<f64>() / served.len() as f64
    };
    let max_r = deep.iter().map(|&s| r[s]).max().unwrap_or(0);
    let mean_value = deep
        .iter()
        .map(|&s| gross_value(s, &pop.ages, &r))
        .sum::<f64>()
        / n_deep as f64;

    let mut op_deep = vec![0usize; pop.n_operators];
    let mut op_total = vec![0usize; pop.n_operators];
    for p in &pop.personas {
        for (s, &h) in p.holdings.iter().enumerate() {
            if h {
                op_total[p.operator] += 1;
                if pop.ages[s] >= DEEP_THRESHOLD {
                    op_deep[p.operator] += 1;
                }
            }
        }
    }
    let (mut hf_acc, mut hf_n) = (0.0f64, 0usize);
    for (deep_c, total_c) in op_deep.iter().zip(op_total.iter()) {
        if *total_c > 0 {
            hf_acc += *deep_c as f64 / *total_c as f64;
            hf_n += 1;
        }
    }
    let hold_frac = if hf_n > 0 { hf_acc / hf_n as f64 } else { 0.0 };
    let mean_op_deep = {
        let active: Vec<usize> = op_deep
            .iter()
            .zip(op_total.iter())
            .filter(|(_, &t)| t > 0)
            .map(|(&d, _)| d)
            .collect();
        if active.is_empty() {
            0.0
        } else {
            active.iter().sum::<usize>() as f64 / active.len() as f64
        }
    };
    let room_pool = if mean_op_deep > 1e-9 {
        deep.len() as f64 / mean_op_deep
    } else {
        f64::INFINITY
    };
    DeepStats {
        served_frac,
        mean_r,
        max_r,
        mean_value,
        hold_frac,
        room_pool,
        room_redundancy: mean_r,
    }
}

// ===========================================================================
// Report.
// ===========================================================================

#[derive(Debug, Clone, Serialize)]
pub struct ClusterPoint {
    pub regime: Regime,
    pub alpha: f64,
    pub phi: f64,
    pub rotation_period: usize,
    /// `0` = cross-tier disperse (anti-virtuous baseline); `>0` = in-tier window.
    pub spread_window_mult: usize,
    /// Dispersive-rotation haircut (value fraction the fresh persona gives up to
    /// pick a set disjoint from the retired one).
    pub haircut: f64,
    pub curve_steepness: f64,
    pub deep_served_frac: f64,
    pub deep_mean_r: f64,
    pub deep_max_r: usize,
    pub deep_mean_value: f64,
    pub deep_hold_frac: f64,
    /// Within-tier room: pool size and the binding redundancy (mean deep R).
    pub room_pool: f64,
    pub room_redundancy: f64,
    pub n_operators: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterReport {
    pub points: Vec<ClusterPoint>,
    /// α=1, φ=0 haircut — CROSS-TIER (anti-virtuous baseline) vs IN-TIER (faithful),
    /// by regime: where does in-tier drive the rotation haircut toward 0?
    pub lean_haircut_a1_crosstier: f64,
    pub lean_haircut_a1_intier: f64,
    pub trough_haircut_a1_crosstier: f64,
    pub trough_haircut_a1_intier: f64,
    /// The φ at which the in-tier LEAN α=1 haircut first exceeds the floored
    /// threshold — the rule-21 reopen criterion with a number.
    pub lean_flip_phi: Option<f64>,
    pub phi_max_swept: f64,
    /// Within-tier room (deep redundancy) at α=1, by regime — the honest-degradation
    /// network-size predictor (→1 ⇒ dispersion unavailable).
    pub lean_room_redundancy: f64,
    pub trough_room_redundancy: f64,
}

fn measure(cfg: &ClusterConfig) -> ClusterPoint {
    let pop = run_equilibrium(cfg);
    let ds = deep_stats(&pop);
    ClusterPoint {
        regime: cfg.regime,
        alpha: cfg.alpha,
        phi: cfg.phi,
        rotation_period: cfg.rotation_period,
        spread_window_mult: cfg.spread_window_mult,
        haircut: haircut(&pop),
        curve_steepness: curve_steepness(&pop),
        deep_served_frac: ds.served_frac,
        deep_mean_r: ds.mean_r,
        deep_max_r: ds.max_r,
        deep_mean_value: ds.mean_value,
        deep_hold_frac: ds.hold_frac,
        room_pool: ds.room_pool,
        room_redundancy: ds.room_redundancy,
        n_operators: pop.n_operators,
    }
}

/// Haircut above which the attractor is judged "floored" (not virtuous).
const FLOOR_THRESHOLD: f64 = 0.10;

pub fn run_clustering_report() -> ClusterReport {
    const IN_TIER: usize = 3;
    let base = ClusterConfig {
        regime: Regime::Lean,
        n_shard: 240,
        alpha: 0.0,
        phi: 0.0,
        rotation_period: 8,
        spread_window_mult: 0,
        epochs: 120,
        seed: 0xC1_05_7E_11,
    };
    let alphas = [0.0, 0.25, 0.5, 0.75, 1.0];
    let mut points = Vec::new();

    // --- Arm 1: the COMPARISON — haircut vs α, by regime, CROSS-TIER vs IN-TIER
    //     side by side. Read for the haircut movement AND where in-tier dispersion
    //     succeeds (room) vs runs out (the honest-degradation threshold). ---
    for window in [0usize, IN_TIER] {
        for regime in [Regime::Lean, Regime::Trough] {
            for &alpha in &alphas {
                points.push(measure(&ClusterConfig {
                    regime,
                    alpha,
                    spread_window_mult: window,
                    seed: base.seed
                        ^ ((window as u64) << 16)
                        ^ ((regime as u64) << 8)
                        ^ ((alpha * 100.0) as u64),
                    ..base
                }));
            }
        }
    }

    // --- Arm 2: per-shard-cost sensitivity — find the in-tier lean α=1 flip φ. ---
    let phis = [0.0, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0];
    let phi_max = *phis.last().unwrap();
    let mut lean_flip_phi = None;
    for &phi in &phis {
        let pt = measure(&ClusterConfig {
            regime: Regime::Lean,
            alpha: 1.0,
            phi,
            spread_window_mult: IN_TIER,
            seed: base.seed ^ 0x9417 ^ ((phi * 100.0) as u64),
            ..base
        });
        if lean_flip_phi.is_none() && phi > 0.0 && pt.haircut > FLOOR_THRESHOLD {
            lean_flip_phi = Some(phi);
        }
        points.push(pt);
    }

    let find_haircut = |regime: Regime, window: usize| -> f64 {
        points
            .iter()
            .find(|p| {
                p.regime == regime
                    && p.alpha == 1.0
                    && p.phi == 0.0
                    && p.spread_window_mult == window
            })
            .map(|p| p.haircut)
            .unwrap_or(f64::NAN)
    };
    let find_room = |regime: Regime| -> f64 {
        points
            .iter()
            .find(|p| {
                p.regime == regime
                    && p.alpha == 1.0
                    && p.phi == 0.0
                    && p.spread_window_mult == IN_TIER
            })
            .map(|p| p.room_redundancy)
            .unwrap_or(f64::NAN)
    };

    ClusterReport {
        lean_haircut_a1_crosstier: find_haircut(Regime::Lean, 0),
        lean_haircut_a1_intier: find_haircut(Regime::Lean, IN_TIER),
        trough_haircut_a1_crosstier: find_haircut(Regime::Trough, 0),
        trough_haircut_a1_intier: find_haircut(Regime::Trough, IN_TIER),
        lean_room_redundancy: find_room(Regime::Lean),
        trough_room_redundancy: find_room(Regime::Trough),
        lean_flip_phi,
        phi_max_swept: phi_max,
        points,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(regime: Regime, alpha: f64, window: usize, seed: u64) -> ClusterConfig {
        ClusterConfig {
            regime,
            n_shard: 240,
            alpha,
            phi: 0.0,
            rotation_period: 8,
            spread_window_mult: window,
            epochs: 120,
            seed,
        }
    }

    /// **Positive control on the equilibrium** (the CT-5 discipline: validate the
    /// substrate reproduces the known result before trusting any downstream
    /// number). The capacity-regime signature of `F1` is *coverage*: the
    /// capacity-rich attractor covers the deep pool with **redundancy** (`R > 1`),
    /// the starved trough sits at the **coverage edge** (`R ≈ 1`, no slack — the
    /// within-tier-room predictor).
    #[test]
    fn equilibrium_reproduces_capacity_regime() {
        let lean = deep_stats(&run_equilibrium(&cfg(Regime::Lean, 1.0, 3, 1)));
        let trough = deep_stats(&run_equilibrium(&cfg(Regime::Trough, 1.0, 3, 1)));
        assert!(
            lean.mean_r > trough.mean_r,
            "capacity-rich attractor must have deeper coverage than the starved trough \
             (lean deep R {:.2} vs trough {:.2})",
            lean.mean_r,
            trough.mean_r
        );
        assert!(
            lean.mean_r > 1.5,
            "attractor must have coverage redundancy (slack to rearrange), got R {:.2}",
            lean.mean_r
        );
        assert!(
            trough.mean_r < 2.0,
            "starved trough must sit near the coverage edge, got R {:.2}",
            trough.mean_r
        );
    }

    /// In-tier dispersion preserves deep coverage (does not abandon the deep top),
    /// where cross-tier dispersion pulls it off — the mechanism behind the
    /// anti-virtuous cross-tier haircut. Assert lean in-tier deep R > cross-tier.
    #[test]
    fn in_tier_preserves_deep_coverage() {
        let cross = deep_stats(&run_equilibrium(&cfg(Regime::Lean, 1.0, 0, 5)));
        let in_tier = deep_stats(&run_equilibrium(&cfg(Regime::Lean, 1.0, 3, 5)));
        assert!(
            in_tier.mean_r > cross.mean_r,
            "in-tier dispersion must preserve deep coverage vs cross-tier abandonment \
             (in-tier R {:.2} vs cross-tier {:.2})",
            in_tier.mean_r,
            cross.mean_r
        );
    }

    /// The dispersive-rotation haircut is a fraction in `[0,1]` and the trough has
    /// less within-tier room (lower deep redundancy) than the attractor.
    #[test]
    fn haircut_bounded_and_room_runs_out_in_trough() {
        let lean = run_equilibrium(&cfg(Regime::Lean, 1.0, 3, 2));
        let trough = run_equilibrium(&cfg(Regime::Trough, 1.0, 3, 2));
        let hc = haircut(&lean);
        assert!(
            (0.0..=1.0).contains(&hc),
            "haircut must be a fraction, got {hc:.3}"
        );
        assert!(
            deep_stats(&trough).room_redundancy < deep_stats(&lean).room_redundancy,
            "the starved trough must have less within-tier room than the attractor"
        );
    }
}
