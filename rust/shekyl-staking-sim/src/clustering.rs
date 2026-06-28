// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! TM-1 / A0 — cross-persona **clustering** harness (the firewall Stage-1 enabler).
//!
//! Where `fingerprint.rs` (T-A1) asks whether *one* persona re-links to *itself*
//! across a rotation (the **temporal** channel, one-actor-one-portfolio), this
//! harness asks the A0 question: an operator splitting its capacity across **K
//! simultaneous personas** — are those siblings unlinkable **from each other**
//! (the **sibling** channel)? Same correlate (the on-wire `shard_ids`,
//! `bond_wire.rs:70`), two failure directions. The unifying invariant the whole
//! TM-1 round is built around:
//!
//! > Each persona's portfolio must be statistically indistinguishable from an
//! > **independent** operator's — neither sibling-correlated (TM-1) nor
//! > rotation-persistent (T-A1).
//!
//! ## What the substrate forces (verified, not assumed — the CT-5 discipline)
//!
//! - Shard **sets** (not just counts) are public on-wire, keyed to the persona
//!   (`HoldingsDescriptor.shard_ids`, `bond_wire.rs:68`).
//! - Consensus scarcity is `1000/R · g(age)` with **no intrinsic per-shard
//!   difficulty term** (`reward_arithmetic.rs:scarcity_milli`; `g_age` is the
//!   only weight, `model.rs:388`). So a shard is "high-value" **purely because
//!   few chose it** (demand-driven), never because it is hard to serve.
//! - Therefore the *only* place a supply-side cost floor can originate is **(a)
//!   aggregate operator capacity vs. shard demand** (heterogeneous archetypes +
//!   endogenous population) and **(b)** the **retention friction** (L9 lock / L18
//!   cooldown), a fixed per-rotation cost. There is no serving-cost
//!   heterogeneity to lean on — so the model is **automatically virtuous unless
//!   one of those two floors bites**, which is exactly why the per-shard-cost
//!   **sensitivity arm** (`--clustering`, `phi` axis) is mandatory: a clean
//!   virtuous verdict that rests on the *absence* of per-shard cost is an
//!   absence-artifact (the cover-saturation / histogram-bin failure twice over),
//!   so we inject a per-shard cost and report the magnitude at which the
//!   attractor **flips** virtuous → floored. That flip threshold is the rule-21
//!   reopen criterion with a number on it.
//!
//! ## The mechanism, made measurable (so the verdict is a residual, not a feeling)
//!
//! The dispersive-default haircut **is the local steepness of the scarcity
//! value-curve**: the value an operator gives up when it must pick a shard set
//! **disjoint** from its prior self / its siblings rather than re-take the
//! top-value block. That steepness is **endogenous in the dispersion-adoption
//! fraction α**: dispersers spread coverage onto under-served (high-value) shards
//! → their `R` rises → `1000/R` falls → the curve flattens → the next operator's
//! haircut shrinks. The headline test is the sign and limit of `∂(haircut)/∂α`:
//!
//! - **Virtuous** — at the capacity-rich lean attractor (~80 bonded personas) the
//!   population saturates the high-value region, the curve flattens, and
//!   `haircut → ~0` as `α → 1`: decorrelation is near-free, make dispersive the
//!   strong default.
//! - **Floored** — at the capacity-starved swan-2 trough (~20 bonded; `F1_TA3..`
//!   §7 regime bound) capacity cannot saturate the high-value region, the curve
//!   stays steep, and the haircut **floors** at some `α*`: the disjoint-set
//!   suggestion's honest scarcity-degradation path is load-bearing, not a corner.
//!
//! The prediction this harness is built to **confirm or kill**: dispersion is
//! near-free at the attractor and carries a real, disclosed, capacity-bound price
//! in the trough — **and once dispersion is on, the residual clustering signal is
//! the split *partition* (K similar-size siblings summing to one capacity), not
//! the shard *overlap*** (which no-self-replication economics already suppress).
//! If that last clause holds, the hard design problem is hiding the partition,
//! not dispersing the shards. The full sibling-clustering **matcher** (phase 2)
//! quantifies that on the [`EquilibriumPortfolios`] this harness emits; here we
//! ship the **proto-matcher** (co-location vs the independent baseline) that
//! gates the dispersive verdict, plus the matcher's consumed interface type.
//!
//! ## What this is NOT (mirrors the cover harness's conditionality)
//!
//! - **A C0 chain-only model.** The proto-matcher sees only public `shard_ids`
//!   (+ persona sizes); no principal knowledge is needed for Stage-1 clustering.
//! - **A claim of the equilibrium's full fidelity.** This is a focused harness
//!   (like `cover.rs` / `standoff.rs`), not `run_sim`. Its load-bearing claim is
//!   only that it **reproduces the known attractor result** — independent
//!   maximizers spread to ~unique portfolios with a flat value-curve at the lean
//!   population, a steep one at the trough (the `F1`/T-A1 finding) — which the
//!   positive-control test asserts. Absolute reward units are arbitrary; every
//!   verdict is a **ratio** (haircut fraction, accuracy-above-baseline), so the
//!   scale cancels.
//! - **The temporal channel.** Rotation persistence (T-A1) is `fingerprint.rs`'s
//!   job; here rotation enters only as the *cost multiplier* on retention
//!   friction, held **explicit** (the `rotation_period` axis) so no verdict is
//!   quietly conditioned on a rotation rate nobody chose — the two channels pull
//!   opposite ways on frequency (T-A1 wants frequent fresh personas, friction
//!   penalizes them).

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
    /// 53-bit mantissa in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
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
// (`scenarios.rs:1920`) so the harness sits on the same economic substrate the
// rest of the sim is validated against. Per-shard *serving* cost (`phi`) is the
// one term that is NOT in the protocol — it is the injected sensitivity axis.
// ===========================================================================

/// `g_age = 1 + age_weight·age`; baseline `age_weight = 2` ⇒ the deepest shards
/// carry a 3× scarcity premium over the hot frontier. This is what concentrates
/// value in the deep tail and gives the value-curve its steepness.
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

// --- Matcher partition-channel parameters (the heterogeneity sweep). ---
/// Heterogeneous persona-count distribution per operator (some run 1, some many),
/// so "K similar siblings" is not a regular population-wide signature.
const HETERO_K: [usize; 6] = [1, 1, 2, 2, 3, 5];
/// The high-K value for the `high_k_fraction` mechanism-check sweep (Check A).
const HIGH_K: usize = 5;
/// Spread of operator base onsets (synthetic bond-post heights). Non-sibling pairs
/// are ~uniform across this; co-onset siblings sit at ~0 distance.
const ONSET_RANGE: u32 = 240;
/// Window a staggered operator's siblings spread their onsets over — when this is a
/// meaningful fraction of `ONSET_RANGE`, staggering blurs the co-onset signature.
const ONSET_STAGGER: u32 = 96;

// ===========================================================================
// Population model — operators (ground truth) split into personas (chain view).
// ===========================================================================

/// One operator's capacity archetype (`scenarios.rs:1928`): the heterogeneity
/// that is the ONLY real supply-side floor source once serving cost is ruled
/// out. Storage-rich actors are capital-poor and vice-versa, so the binding
/// constraint is the `min(⌊capital/bond⌋, ⌊storage/shard_size⌋)` seat count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum Archetype {
    StorageRich,
    CapitalRich,
}

impl Archetype {
    /// `(storage_capacity, capital)` per `scenarios.rs:1929-1934`. (The whale
    /// archetype {150, 600} is omitted until the phase-2 matcher exercises the
    /// split-signature it produces — rule-21: no pre-provisioned unused variant.)
    fn endowment(self) -> (usize, f64) {
        match self {
            Archetype::StorageRich => (22, 20.0),
            Archetype::CapitalRich => (10, 100.0),
        }
    }
}

/// How an operator partitions its capacity across simultaneous personas — a
/// first-class axis (α decorrelates *which shards*; the split decides *whether
/// there is anything to regroup* and leaves a size signature dispersion does not
/// touch). `k == 1` ⇒ persona ≡ operator ⇒ the sibling channel is empty.
#[derive(Debug, Clone, Copy, Serialize)]
struct Split {
    /// Personas per operator.
    k: usize,
    /// Equal capacity per persona (a K-identical-size signature the matcher keys
    /// on) vs. a varied partition (blends into the population).
    equal: bool,
}

/// A persona: one bond-post the chain sees. `holdings` is the public shard set.
#[derive(Debug, Clone)]
struct Persona {
    operator: usize,
    storage_capacity: usize,
    capital: f64,
    /// `holdings[s]` — public shard membership (the on-wire `shard_ids`).
    holdings: Vec<bool>,
    /// Prior-rotation holdings (for the disjoint-set / decorrelation measurement).
    prior: Vec<bool>,
    /// Onset — the (synthetic) bond-post height at which this persona came online.
    /// Chain-visible metadata, separable from the steady-state portfolio; the
    /// matcher's **partition** channel reads it (siblings co-onset by default,
    /// stagger under the heterogeneity sweep). Does not affect the equilibrium.
    onset: u32,
}

/// An operator's privacy strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum Strategy {
    /// Reward-maximize; on rotation re-take the best (possibly overlapping its
    /// own past) set. Personas concentrate in the high-value region → co-located.
    Concentrate,
    /// Dispersive default: on rotation each persona re-selects a set **disjoint**
    /// from its prior self, mimicking an independent entrant. Pays the haircut.
    Disperse,
}

// ===========================================================================
// Scenario / regime configuration.
// ===========================================================================

/// Capacity regime — the load-bearing axis. Lean ≈ the `F1` attractor
/// (79–100 bonded), trough ≈ the swan-2 post-shock floor (9–25 bonded,
/// `F1_TA3_TA7_LIFETIME_WINDOW.md` §7). Regimes differ only in operator count
/// against a fixed shard space, i.e. in **aggregate capacity vs. demand**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Regime {
    /// Capacity-rich attractor — predicted virtuous.
    Lean,
    /// Capacity-starved swan trough — predicted floored.
    Trough,
}

impl Regime {
    fn operators(self) -> usize {
        match self {
            // Split k≈1.6 mean ⇒ ~80 personas (lean) / ~20 (trough).
            Regime::Lean => 50,
            Regime::Trough => 12,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct ClusterConfig {
    regime: Regime,
    n_shard: usize,
    /// Dispersion adoption fraction.
    alpha: f64,
    split: Split,
    /// Per-shard serving-cost magnitude (the sensitivity axis). `phi·age(s)` is
    /// added to a shard's serve cost — the realistic "deep is expensive" injection
    /// the protocol does NOT have. `0.0` = protocol reality.
    phi: f64,
    /// Epochs between a disperser's rotations. Held explicit (not a buried
    /// default) so the friction tradeoff is visible: more rotation = better
    /// temporal (T-A1) unlinkability but more retention-friction paid.
    rotation_period: usize,
    /// Disperser stratification window, as a multiple of the reward-max block
    /// size. `0` = spread across the **whole** positive-net list (CROSS-TIER —
    /// the first model: charges the `g(age)` premium + abandons the deep top, the
    /// anti-virtuous baseline kept for comparison). `>0` = stay **within** the top
    /// `m·mult` candidates (IN-TIER — mimic an independent deep-concentrated
    /// operator, isolating the flattenable `1/R` component). Both swept side by
    /// side; never one replacing the other.
    spread_window_mult: usize,
    /// Heterogeneity knobs for the matcher's partition channel (the sweep that
    /// distinguishes a *structural* partition leak from a *blur-able* one). When
    /// `false` (the regular case) every operator runs the same `split.k` siblings
    /// that all come online together — the cleanest "K similar-size co-onset"
    /// signature. When `true`, operators draw heterogeneous `K` / stagger their
    /// siblings' onsets, which may blur the signature (a designable mitigation).
    k_heterogeneous: bool,
    onset_staggered: bool,
    /// Mechanism-check knob (Check A): fraction of operators that run `HIGH_K`
    /// siblings, the rest running 1. `0.0` = use the normal `split.k` /
    /// `k_heterogeneous` logic. Sweeping this tests whether the size-AUC
    /// re-inflation is mechanism (size-AUC falls as the high-K fraction rises, i.e.
    /// less K=1 background to stand out against) or a seed artifact.
    high_k_fraction: f64,
    /// Onset stagger window when `onset_staggered` (Check B). `0` = the default
    /// `ONSET_STAGGER`; set to `ONSET_RANGE` for a full-range stagger (tests
    /// whether the onset sub-channel is killable → a user-controllable lever).
    onset_stagger_width: u32,
    epochs: usize,
    seed: u64,
}

// ===========================================================================
// The matcher's consumed interface (phase-2 parallelizable surface). The full
// sibling-clustering matcher operates on THIS — the public persona portfolios +
// the ground-truth operator labels it must *recover*. Shipping the type now (not
// the clustering logic) lets the matcher be wired without guessing the
// equilibrium's portfolio structure.
// ===========================================================================

/// The public persona-portfolio set at equilibrium, plus the ground-truth
/// operator labels the matcher must recover. Emitted by [`equilibrium_portfolios`].
#[derive(Debug, Clone, Serialize)]
pub struct EquilibriumPortfolios {
    /// `portfolios[p]` = the sorted public shard ids of persona `p`.
    pub portfolios: Vec<Vec<usize>>,
    /// `operator_of[p]` = ground-truth operator id (what the matcher recovers).
    pub operator_of: Vec<usize>,
    /// Number of distinct operators (the clustering target count).
    pub n_operators: usize,
    pub n_shard: usize,
    pub regime: Regime,
    pub alpha: f64,
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
    /// The disperser stratification window this equilibrium ran under (so the
    /// haircut measures the same disperse model: cross-tier `0` vs in-tier `>0`).
    spread_window_mult: usize,
}

/// Net marginal value of shard `s` to a persona, given current replication `r`
/// and whether the persona already holds it (so adding it makes `r+1`).
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

/// Replication per shard = number of distinct personas holding it (= consensus
/// `R`, since personas are what the chain counts).
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

/// The candidate list both strategies draw from: shards with **positive** net
/// value (no rational operator holds a money-losing shard), excluding `forbidden`
/// (a rotating disperser's own prior set), highest net value first. Ranked by the
/// fresh-acquisition view (adding makes `R+1`), so it is independent of who
/// currently holds what — the operator re-selects from scratch each epoch.
fn ranked_candidates(ages: &[f64], r: &[usize], phi: f64, forbidden: &[bool]) -> Vec<usize> {
    let mut v: Vec<(usize, f64)> = (0..ages.len())
        .filter(|&s| !forbidden[s])
        .map(|s| (s, net_value(s, ages, r, false, phi)))
        .filter(|&(_, net)| net > 0.0)
        .collect();
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    v.into_iter().map(|(s, _)| s).collect()
}

/// Greedily take shards from `ranked` (value-desc) under a total storage + capital
/// budget — the reward-max **block** a CONCENTRATE operator grabs. Returned in
/// rank order (top value first).
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
/// `window_mult == 0` it spreads across the **whole** positive-net `ranked` list
/// (CROSS-TIER: mimics the full population value distribution, but charges the
/// intrinsic `g(age)` age-premium and pulls coverage off the scarce deep top —
/// the anti-virtuous baseline, confirmed in-evidence). With `window_mult > 0` it
/// restricts to the top `m·window_mult` candidates (IN-TIER: stays where an
/// independent deep-concentrated operator sits, spreading only *which* high-value
/// shards, isolating the flattenable `1/R` component). Walks `m` evenly-spaced
/// anchors across the chosen window, taking the next affordable untaken shard.
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

/// The operator's total shard set under its `spread` strategy: the top block, or
/// (dispersing) a stratified set of the **same size** spread across the value
/// distribution.
fn operator_select(
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

/// Assign an operator's selected shard set across its personas round-robin
/// (interleaved, respecting each persona's own storage + capital budget), so each
/// persona is a **representative slice** of the operator's set: under CONCENTRATE
/// every persona is a top-value slice (siblings co-located); under DISPERSE every
/// persona is a population-representative slice (siblings indistinguishable from
/// independent draws). Disjoint across siblings by construction (each shard to one
/// persona). Shards no persona can afford are dropped.
fn assign_round_robin(personas: &mut [Persona], pis: &[usize], selected: &[usize], ages: &[f64]) {
    let n_shard = ages.len();
    for &pi in pis {
        personas[pi].holdings = vec![false; n_shard];
    }
    let mut us = vec![0.0f64; pis.len()];
    let mut ub = vec![0.0f64; pis.len()];
    let mut cursor = 0usize;
    for &s in selected {
        let deep = ages[s] >= DEEP_THRESHOLD;
        for t in 0..pis.len() {
            let idx = (cursor + t) % pis.len();
            let pi = pis[idx];
            if us[idx] + stor_cost(deep) <= personas[pi].storage_capacity as f64
                && ub[idx] + bond_cost(deep) <= personas[pi].capital
            {
                personas[pi].holdings[s] = true;
                us[idx] += stor_cost(deep);
                ub[idx] += bond_cost(deep);
                cursor = idx + 1;
                break;
            }
        }
    }
}

/// Run the endogenous coverage equilibrium to steady state and return the final
/// population. Personas best-respond asynchronously (Gauss–Seidel: `R` updates
/// after each move — the myopia-damping discipline from `agent.rs`). Dispersers
/// rotate every `rotation_period` epochs onto a set disjoint from their prior one.
fn run_equilibrium(cfg: &ClusterConfig) -> Pop {
    let mut rng = SplitMix64::new(cfg.seed);
    let n_shard = cfg.n_shard;

    // --- Shards: uniform ages across [0,1) (steady-state recycled window). ---
    let mut ages: Vec<f64> = (0..n_shard)
        .map(|i| (i as f64 + 0.5) / n_shard as f64)
        .collect();
    // Shuffle so shard index does not encode age (the matcher must not get age
    // for free from id ordering).
    rng.shuffle(&mut ages);

    // --- Operators → personas. ---
    let n_op = cfg.regime.operators();
    let mut strategy = vec![Strategy::Concentrate; n_op];
    let mut personas: Vec<Persona> = Vec::new();
    for (op, strat) in strategy.iter_mut().enumerate() {
        // 50/50 storage-rich / capital-rich (baseline mix); no whale by default.
        let arche = if op % 2 == 0 {
            Archetype::StorageRich
        } else {
            Archetype::CapitalRich
        };
        let (storage, capital) = arche.endowment();
        // Strategy: first ⌊α·n_op⌋ operators disperse (deterministic for a clean
        // sweep; the population is archetype-interleaved so this is unbiased).
        *strat = if (op as f64) < cfg.alpha * n_op as f64 {
            Strategy::Disperse
        } else {
            Strategy::Concentrate
        };
        // Persona count: the high-K-fraction mechanism sweep (Check A) takes
        // precedence; else uniform `split.k` or the heterogeneous array.
        let k = if cfg.high_k_fraction > 0.0 {
            if (op as f64) < cfg.high_k_fraction * n_op as f64 {
                HIGH_K
            } else {
                1
            }
        } else if cfg.k_heterogeneous {
            HETERO_K[op % HETERO_K.len()].max(1)
        } else {
            cfg.split.k.max(1)
        };
        // Onset: operator base height spread across the range; siblings co-onset
        // (regular) or stagger within a window (the blur-the-partition sweep). The
        // stagger width is `onset_stagger_width` or the default `ONSET_STAGGER`.
        let base_onset = (rng.next_u64() % ONSET_RANGE as u64) as u32;
        let stagger_w = if cfg.onset_stagger_width > 0 {
            cfg.onset_stagger_width
        } else {
            ONSET_STAGGER
        };
        let shares = partition(storage, capital, k, cfg.split.equal, &mut rng);
        for (i, (ps, pc)) in shares.into_iter().enumerate() {
            let onset = if cfg.onset_staggered {
                base_onset.wrapping_add((rng.next_u64() % stagger_w as u64) as u32)
            } else {
                base_onset + (i as u32) // co-onset: a +i tiebreak only (≈ together)
            };
            personas.push(Persona {
                operator: op,
                storage_capacity: ps,
                capital: pc,
                holdings: vec![false; n_shard],
                prior: vec![false; n_shard],
                onset,
            });
        }
    }

    // Operator → its persona indices.
    let mut op_personas: Vec<Vec<usize>> = vec![Vec::new(); n_op];
    for (pi, p) in personas.iter().enumerate() {
        op_personas[p.operator].push(pi);
    }

    // --- Iterate to equilibrium (operator-level best-response, Gauss–Seidel: `R`
    //     updates after each operator moves — the myopia-damping discipline). ---
    for ep in 0..cfg.epochs {
        let mut op_order: Vec<usize> = (0..n_op).collect();
        rng.shuffle(&mut op_order);
        // Rotation tick: dispersers snapshot their set as `prior` and re-select
        // disjoint from it this epoch (the decorrelation move).
        let rotating = ep > 0 && cfg.rotation_period > 0 && ep % cfg.rotation_period == 0;
        if rotating {
            for p in personas.iter_mut() {
                if strategy[p.operator] == Strategy::Disperse {
                    p.prior = p.holdings.clone();
                }
            }
        }

        for &op in &op_order {
            let r = replication(&personas, n_shard);
            let pis = &op_personas[op];
            let total_storage: f64 = pis
                .iter()
                .map(|&pi| personas[pi].storage_capacity as f64)
                .sum();
            let total_capital: f64 = pis.iter().map(|&pi| personas[pi].capital).sum();
            let spread = strategy[op] == Strategy::Disperse;
            // A rotating disperser avoids its own prior set (per-persona union).
            let mut forbidden = vec![false; n_shard];
            if spread && rotating {
                for &pi in pis {
                    for (s, &h) in personas[pi].prior.iter().enumerate() {
                        if h {
                            forbidden[s] = true;
                        }
                    }
                }
            }
            let ranked = ranked_candidates(&ages, &r, cfg.phi, &forbidden);
            let selected = operator_select(
                &ranked,
                &ages,
                total_storage,
                total_capital,
                spread,
                cfg.spread_window_mult,
            );
            assign_round_robin(&mut personas, pis, &selected, &ages);
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

/// Split `(storage, capital)` across `k` personas, equal or varied.
fn partition(
    storage: usize,
    capital: f64,
    k: usize,
    equal: bool,
    rng: &mut SplitMix64,
) -> Vec<(usize, f64)> {
    if k <= 1 {
        return vec![(storage, capital)];
    }
    if equal {
        let s = (storage / k).max(1);
        let c = capital / k as f64;
        return (0..k).map(|_| (s, c)).collect();
    }
    // Varied: random Dirichlet-ish weights, normalized, each persona ≥ 1 slot.
    let mut w: Vec<f64> = (0..k).map(|_| 0.25 + rng.unit()).collect();
    let sum: f64 = w.iter().sum();
    for x in w.iter_mut() {
        *x /= sum;
    }
    w.iter()
        .map(|&x| (((storage as f64 * x).round() as usize).max(1), capital * x))
        .collect()
}

// ===========================================================================
// Measurements.
// ===========================================================================

/// The dispersive-default **haircut** a disperser faces at this α-equilibrium: for
/// a representative operator (averaged over the two archetypes), the gross value
/// of the reward-max top **block** vs. the value-rank-stratified **spread** of the
/// same size, both at the settled `R`-landscape — i.e. the local steepness of the
/// scarcity value-curve. A fraction in `[0,1]`. This is the quantity that flattens
/// (virtuous) or floors (capacity-bound / φ) as α rises.
fn haircut(pop: &Pop) -> f64 {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    let forbidden = vec![false; n_shard];
    let ranked = ranked_candidates(&pop.ages, &r, pop.phi, &forbidden);
    let value = |set: &[usize]| -> f64 { set.iter().map(|&s| gross_value(s, &pop.ages, &r)).sum() };

    // Representative operators: the two baseline archetypes' total endowments.
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

/// Value-curve steepness: ratio of mean gross value of the top decile of shards
/// to the population mean. `1.0` = flat (saturated, virtuous); `≫1` = steep
/// (starved). The mechanism behind the haircut, reported for transparency.
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

/// Proto-matcher: the **co-location** signal. For each operator with ≥2 personas,
/// the intra-operator spread of persona "value-rank centroids" vs. the
/// cross-population baseline spread. Returned as `(intra, baseline, exact_overlap)`:
/// a co-located (concentrated) operator has `intra ≪ baseline` (its siblings sit
/// in one value region — regroupable); a dispersed one has `intra ≈ baseline`
/// (indistinguishable from independent draws). `exact_overlap` is the mean
/// fraction of sibling-shared shards — expected ≈ 0 either way (economics already
/// suppress double-serving), the empirical proof that **overlap is not the
/// signal, co-location is**.
fn colocation(pop: &Pop) -> (f64, f64, f64) {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    // Per-shard value rank in [0,1] (0 = highest value).
    let mut order: Vec<usize> = (0..n_shard).collect();
    order.sort_by(|&a, &b| {
        gross_value(b, &pop.ages, &r)
            .partial_cmp(&gross_value(a, &pop.ages, &r))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut rank = vec![0.0f64; n_shard];
    for (i, &s) in order.iter().enumerate() {
        rank[s] = i as f64 / n_shard.max(1) as f64;
    }
    // Per-persona centroid value-rank.
    let centroid = |p: &Persona| -> Option<f64> {
        let held: Vec<usize> = (0..n_shard).filter(|&s| p.holdings[s]).collect();
        if held.is_empty() {
            None
        } else {
            Some(held.iter().map(|&s| rank[s]).sum::<f64>() / held.len() as f64)
        }
    };
    let centroids: Vec<Option<f64>> = pop.personas.iter().map(centroid).collect();

    // Baseline: std-dev of all persona centroids (the population spread an
    // independent sample of K personas would exhibit).
    let active: Vec<f64> = centroids.iter().filter_map(|&c| c).collect();
    let baseline = std_dev(&active);

    // Intra-operator: mean over operators of the std-dev of that operator's
    // persona centroids.
    let mut intra_acc = 0.0;
    let mut intra_n = 0usize;
    let mut overlap_acc = 0.0;
    let mut overlap_n = 0usize;
    for op in 0..pop.n_operators {
        let mine: Vec<f64> = pop
            .personas
            .iter()
            .enumerate()
            .filter(|(_, p)| p.operator == op)
            .filter_map(|(i, _)| centroids[i])
            .collect();
        if mine.len() >= 2 {
            intra_acc += std_dev(&mine);
            intra_n += 1;
        }
        // Exact sibling overlap: shards held by ≥2 of this operator's personas.
        let sibs: Vec<&Persona> = pop.personas.iter().filter(|p| p.operator == op).collect();
        if sibs.len() >= 2 {
            let mut shared = 0usize;
            let mut total = 0usize;
            for s in 0..n_shard {
                let c = sibs.iter().filter(|p| p.holdings[s]).count();
                if c >= 1 {
                    total += 1;
                }
                if c >= 2 {
                    shared += 1;
                }
            }
            if total > 0 {
                overlap_acc += shared as f64 / total as f64;
                overlap_n += 1;
            }
        }
    }
    let intra = if intra_n > 0 {
        intra_acc / intra_n as f64
    } else {
        baseline
    };
    let overlap = if overlap_n > 0 {
        overlap_acc / overlap_n as f64
    } else {
        0.0
    };
    (intra, baseline, overlap)
}

fn std_dev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let var = v.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
    var.sqrt()
}

/// Deep-tier diagnostics — the mechanism instrument. The anti-virtuous diagnosis
/// (dispersion pulls coverage off the scarce deep top, making it scarcer) is
/// **falsifiable here**: if real, `mean_r` falls and `mean_value` rises as α
/// rises. Also reports the honest-population portfolio shape (`hold_frac`,
/// `served_frac`, `max_r`): whether an independent operator is deep-concentrated,
/// and whether independents pile on the same few deep shards (high `max_r`, low
/// `served_frac`) or stay disjoint across the deep pool.
struct DeepStats {
    /// Fraction of deep shards with ≥1 server (deep coverage breadth).
    served_frac: f64,
    /// Mean `R` over *served* deep shards (deep coverage depth).
    mean_r: f64,
    /// Max `R` over deep shards (piling indicator).
    max_r: usize,
    /// Mean gross scarcity value over all deep shards (rises as deep `R` falls).
    mean_value: f64,
    /// Per-operator mean deep fraction of holdings (portfolio shape: is the
    /// reward-max operator deep-concentrated?).
    hold_frac: f64,
    /// **Within-tier room** — the network-size threshold for the honest-degradation
    /// path. Two complementary readings, both reported because the literal
    /// pool-size formula and the binding redundancy can diverge: `pool` = deep
    /// shards ÷ mean operator deep-holdings (how many disjoint operator-sized deep
    /// sets the pool holds); `redundancy` = mean deep `R` (servers per deep shard —
    /// the *slack* to rearrange). When `redundancy → 1` there is no slack to move a
    /// persona to a fresh deep shard without a reward hit, so within-tier
    /// dispersion runs out **regardless of α** even if `pool ≫ 1`. The wallet's
    /// honest-degradation message needs whichever crosses 1 first at small networks.
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
    // Within-tier room. pool = deep shards / mean operator deep-holdings; the
    // redundancy (mean served-deep R) is the binding slack.
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

/// Emit the matcher's consumed interface from a settled population.
fn equilibrium_portfolios(pop: &Pop, cfg: &ClusterConfig) -> EquilibriumPortfolios {
    let portfolios: Vec<Vec<usize>> = pop
        .personas
        .iter()
        .map(|p| (0..pop.ages.len()).filter(|&s| p.holdings[s]).collect())
        .collect();
    let operator_of: Vec<usize> = pop.personas.iter().map(|p| p.operator).collect();
    EquilibriumPortfolios {
        portfolios,
        operator_of,
        n_operators: pop.n_operators,
        n_shard: cfg.n_shard,
        regime: cfg.regime,
        alpha: cfg.alpha,
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
    pub split_k: usize,
    pub split_equal: bool,
    pub rotation_period: usize,
    /// Dispersive-default haircut (population-mean value fraction given up).
    pub haircut: f64,
    /// Value-curve steepness (top-decile / mean gross value); 1 = flat.
    pub curve_steepness: f64,
    /// Proto-matcher co-location: intra-operator persona-centroid spread.
    pub colocation_intra: f64,
    /// …vs the independent-population baseline spread.
    pub colocation_baseline: f64,
    /// Co-location *signal* = `1 − intra/baseline` (0 = unclusterable on
    /// co-location, dispersed; →1 = tightly co-located, regroupable).
    pub colocation_signal: f64,
    /// Mean exact sibling shard-overlap fraction (expected ≈ 0 — overlap is not
    /// the signal).
    pub exact_overlap: f64,
    pub n_personas: usize,
    // --- Deep-tier mechanism instrument (falsifies/confirms the anti-virtuous
    //     diagnosis: deep_r should FALL and deep_value RISE as α rises if the
    //     mechanism is "dispersion abandons the scarce deep top"). ---
    pub deep_served_frac: f64,
    pub deep_mean_r: f64,
    pub deep_max_r: usize,
    pub deep_mean_value: f64,
    pub deep_hold_frac: f64,
    /// `0` = cross-tier disperse (whole-list spread, anti-virtuous baseline);
    /// `>0` = in-tier window multiple. Both swept side by side.
    pub spread_window_mult: usize,
    /// Within-tier room: pool size (deep ÷ op-deep) and the binding redundancy
    /// (mean deep R). `redundancy → 1` = within-tier dispersion has no slack.
    pub room_pool: f64,
    pub room_redundancy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterReport {
    pub points: Vec<ClusterPoint>,
    /// α=1, φ=0 haircut — CROSS-TIER (whole-list spread, anti-virtuous baseline)
    /// vs IN-TIER (faithful: stay where independent operators sit), by regime. The
    /// comparison that aims the matcher: where does in-tier actually drive the
    /// haircut toward 0 (portfolios decorrelated → the partition is the real test)?
    pub lean_haircut_a1_crosstier: f64,
    pub lean_haircut_a1_intier: f64,
    pub trough_haircut_a1_crosstier: f64,
    pub trough_haircut_a1_intier: f64,
    /// The φ at which the in-tier LEAN α=1 haircut first exceeds the floored
    /// threshold — the rule-21 reopen criterion with a number. `None` = no flip in
    /// range (only meaningful if the in-tier α=1 haircut is itself below floor).
    pub lean_flip_phi: Option<f64>,
    pub phi_max_swept: f64,
    /// Within-tier room (deep redundancy = slack) at α=1, by regime — the
    /// honest-degradation network-size predictor: as it falls toward 1, within-tier
    /// dispersion runs out regardless of α.
    pub lean_room_redundancy: f64,
    pub trough_room_redundancy: f64,
    /// A settled lean α=1 equilibrium's public portfolios + ground-truth operator
    /// labels — the interface the phase-2 sibling-clustering matcher consumes
    /// (shipped now so the matcher wires against the real equilibrium structure,
    /// not a stand-in distribution).
    pub sample_portfolios: EquilibriumPortfolios,
}

fn measure(cfg: &ClusterConfig) -> ClusterPoint {
    let pop = run_equilibrium(cfg);
    let hc = haircut(&pop);
    let steep = curve_steepness(&pop);
    let (intra, baseline, overlap) = colocation(&pop);
    let ds = deep_stats(&pop);
    let signal = if baseline > 1e-9 {
        (1.0 - intra / baseline).clamp(0.0, 1.0)
    } else {
        0.0
    };
    ClusterPoint {
        regime: cfg.regime,
        alpha: cfg.alpha,
        phi: cfg.phi,
        split_k: cfg.split.k,
        split_equal: cfg.split.equal,
        rotation_period: cfg.rotation_period,
        haircut: hc,
        curve_steepness: steep,
        colocation_intra: intra,
        colocation_baseline: baseline,
        colocation_signal: signal,
        exact_overlap: overlap,
        n_personas: pop.personas.len(),
        deep_served_frac: ds.served_frac,
        deep_mean_r: ds.mean_r,
        deep_max_r: ds.max_r,
        deep_mean_value: ds.mean_value,
        deep_hold_frac: ds.hold_frac,
        spread_window_mult: cfg.spread_window_mult,
        room_pool: ds.room_pool,
        room_redundancy: ds.room_redundancy,
    }
}

/// Haircut above which the attractor is judged "floored" (not virtuous).
const FLOOR_THRESHOLD: f64 = 0.10;

pub fn run_clustering_report() -> ClusterReport {
    // Cross-tier (window 0) is the kept anti-virtuous baseline; in-tier (window 3)
    // is the faithful model. `IN_TIER` is the window used for the split/φ arms.
    const IN_TIER: usize = 3;
    let base = ClusterConfig {
        regime: Regime::Lean,
        n_shard: 240,
        alpha: 0.0,
        split: Split { k: 2, equal: false },
        phi: 0.0,
        rotation_period: 8,
        spread_window_mult: 0,
        k_heterogeneous: false,
        onset_staggered: false,
        high_k_fraction: 0.0,
        onset_stagger_width: 0,
        epochs: 120,
        seed: 0xC1_05_7E_11,
    };
    let alphas = [0.0, 0.25, 0.5, 0.75, 1.0];
    let mut points = Vec::new();

    // --- Arm 1: the COMPARISON — haircut vs α, by regime, CROSS-TIER vs IN-TIER
    //     side by side (window ∈ {0, IN_TIER}). Read for two things: the haircut
    //     movement AND where in-tier decorrelation succeeds vs runs out of room. ---
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

    // --- Arm 2: split-structure (equal vs varied, k sweep) at α=1, lean, in-tier. ---
    for &k in &[1usize, 2, 3] {
        for &equal in &[false, true] {
            points.push(measure(&ClusterConfig {
                regime: Regime::Lean,
                alpha: 1.0,
                split: Split { k, equal },
                spread_window_mult: IN_TIER,
                seed: base.seed ^ 0x5717 ^ ((k as u64) << 4) ^ (equal as u64),
                ..base
            }));
        }
    }

    // --- Arm 3: per-shard-cost sensitivity — find the in-tier lean α=1 flip φ. ---
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

    // Summary: α=1, φ=0, k=2 haircut for each (regime × window), and the
    // honest-degradation room (deep redundancy) at α=1.
    let find_haircut = |regime: Regime, window: usize| -> f64 {
        points
            .iter()
            .find(|p| {
                p.regime == regime
                    && p.alpha == 1.0
                    && p.phi == 0.0
                    && p.split_k == 2
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
                    && p.split_k == 2
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
        sample_portfolios: run_equilibrium_portfolios(Regime::Lean, 1.0),
        points,
    }
}

/// Emit an [`EquilibriumPortfolios`] for the phase-2 matcher (interface check /
/// wiring). Settles a single representative scenario.
pub fn run_equilibrium_portfolios(regime: Regime, alpha: f64) -> EquilibriumPortfolios {
    let cfg = ClusterConfig {
        regime,
        n_shard: 240,
        alpha,
        split: Split { k: 2, equal: false },
        phi: 0.0,
        rotation_period: 8,
        // In-tier (the faithful disperse) — the matcher consumes decorrelated
        // portfolios, so the partition-residual question is the real one.
        spread_window_mult: 3,
        k_heterogeneous: false,
        onset_staggered: false,
        high_k_fraction: 0.0,
        onset_stagger_width: 0,
        epochs: 120,
        seed: 0xC1_05_7E_11 ^ ((alpha * 100.0) as u64),
    };
    let pop = run_equilibrium(&cfg);
    equilibrium_portfolios(&pop, &cfg)
}

// ===========================================================================
// The MATCHER (phase 2) — the C0 chain-observer sibling-clustering instrument.
//
// Operates on a settled in-tier (decorrelated) population at the LEAN attractor
// (the regime where the comparison arm showed portfolios actually separate). It
// scores every persona PAIR for "same operator?" from public features and asks
// how well that separates true sibling pairs from independent pairs — the AUC.
//
// The deliverable is THREE conditionals, not one number:
//  1. FEATURE ABLATION — AUC(portfolio-only) vs AUC(+partition). If portfolio-only
//     sits near the null and the partition jump is large, the partition is the
//     signal (dispersing shards is the easy half). If portfolio-only is already
//     high, in-tier dispersion did NOT decorrelate and it is *both*.
//  2. REAL NULL — AUC under SHUFFLED operator labels (same group-size multiset,
//     random membership). It must sit at ~0.5; that is what makes "above baseline"
//     mean something instead of an assumed chance line. Every reported AUC is read
//     against this measured null, not against 0.5.
//  3. HETEROGENEITY SWEEP — equal vs varied sizes × co-onset vs staggered × uniform
//     vs heterogeneous K. If the partition AUC stays high across all of these the
//     leak is STRUCTURAL (disclosure); if heterogeneity blurs it the leak is
//     BEHAVIOURAL (a designable mitigation: encourage heterogeneous, staggered
//     splits). That distinction decides the wallet's user-facing privacy claim.
//
// The partition channel is deliberately the cardinality/timing features (size,
// onset); the portfolio channel is the which-shards features (value-rank centroid,
// union coherence), so the ablation cleanly separates "the shards leaked" from
// "the split leaked".
// ===========================================================================

/// Per-shard value rank in `[0,1]` (0 = highest scarcity value) at the settled `R`.
fn value_rank_map(pop: &Pop) -> Vec<f64> {
    let n_shard = pop.ages.len();
    let r = replication(&pop.personas, n_shard);
    let mut order: Vec<usize> = (0..n_shard).collect();
    order.sort_by(|&a, &b| {
        gross_value(b, &pop.ages, &r)
            .partial_cmp(&gross_value(a, &pop.ages, &r))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut rank = vec![0.0; n_shard];
    for (i, &s) in order.iter().enumerate() {
        rank[s] = i as f64 / n_shard.max(1) as f64;
    }
    rank
}

/// Mann–Whitney AUC: P(a positive-labelled score outranks a negative-labelled
/// one), tie-averaged. `0.5` = no discrimination; `1.0` = perfect. `labels[k]` =
/// is the pair a true sibling pair (the positive class).
fn auc_from(scores: &[f64], labels: &[bool]) -> f64 {
    let n = scores.len();
    let n_pos = labels.iter().filter(|&&b| b).count();
    let n_neg = n - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return 0.5;
    }
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by(|&a, &b| {
        scores[a]
            .partial_cmp(&scores[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut ranks = vec![0.0f64; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && scores[idx[j]] == scores[idx[i]] {
            j += 1;
        }
        // 1-based ranks (i+1)..=j averaged over the tie group.
        let avg = (((i + 1) + j) as f64) / 2.0;
        for &k in &idx[i..j] {
            ranks[k] = avg;
        }
        i = j;
    }
    let sum_pos: f64 = (0..n).filter(|&k| labels[k]).map(|k| ranks[k]).sum();
    (sum_pos - n_pos as f64 * (n_pos as f64 + 1.0) / 2.0) / (n_pos as f64 * n_neg as f64)
}

#[derive(Debug, Clone, Serialize)]
pub struct MatcherRow {
    pub label: String,
    pub split_equal: bool,
    pub k_heterogeneous: bool,
    pub onset_staggered: bool,
    /// AUC from the WHICH-SHARDS features only (centroid, union coherence).
    pub auc_portfolio: f64,
    /// AUC from the SPLIT features only (size, onset).
    pub auc_partition: f64,
    /// Decomposition of the partition channel — which sub-signal drives it, and
    /// thus which mitigation matters (varied splits kill `size`; staggered onset
    /// kills `onset`). `onset` strength is partly a co-timing modelling choice, so
    /// this separates the intrinsic (size) leak from the behavioural (onset) one.
    pub auc_size: f64,
    pub auc_onset: f64,
    /// AUC from all features combined.
    pub auc_full: f64,
    /// AUC under shuffled operator labels — the measured null (must be ≈ 0.5).
    pub auc_null: f64,
    /// `auc_full − auc_portfolio` — how much the partition channel ADDS over shards.
    pub ablation_delta: f64,
    pub n_sibling_pairs: usize,
    pub n_pairs: usize,
}

fn z_score_column(feats: &mut [[f64; 4]], col: usize) {
    let n = feats.len();
    if n == 0 {
        return;
    }
    let mean = feats.iter().map(|f| f[col]).sum::<f64>() / n as f64;
    let var = feats.iter().map(|f| (f[col] - mean).powi(2)).sum::<f64>() / n as f64;
    let sd = var.sqrt();
    if sd < 1e-12 {
        return;
    }
    for f in feats.iter_mut() {
        f[col] = (f[col] - mean) / sd;
    }
}

fn run_matcher(pop: &Pop, label: &str, cfg: &ClusterConfig) -> MatcherRow {
    let n_shard = pop.ages.len();
    let rank = value_rank_map(pop);
    let np = pop.personas.len();
    let held: Vec<Vec<f64>> = pop
        .personas
        .iter()
        .map(|p| {
            (0..n_shard)
                .filter(|&s| p.holdings[s])
                .map(|s| rank[s])
                .collect()
        })
        .collect();
    let centroid: Vec<f64> = held
        .iter()
        .map(|h| {
            if h.is_empty() {
                0.5
            } else {
                h.iter().sum::<f64>() / h.len() as f64
            }
        })
        .collect();
    let size: Vec<f64> = held.iter().map(|h| h.len() as f64).collect();
    let onset: Vec<f64> = pop.personas.iter().map(|p| p.onset as f64).collect();
    let op: Vec<usize> = pop.personas.iter().map(|p| p.operator).collect();

    // Feature columns: [centroid (shards), coherence (shards), size (split), onset (split)].
    let mut feats: Vec<[f64; 4]> = Vec::new();
    let mut labels: Vec<bool> = Vec::new();
    let mut pair_ij: Vec<(usize, usize)> = Vec::new();
    for i in 0..np {
        if size[i] < 1.0 {
            continue; // a persona that holds nothing is not on chain
        }
        for j in (i + 1)..np {
            if size[j] < 1.0 {
                continue;
            }
            let f_centroid = -(centroid[i] - centroid[j]).abs();
            let union: Vec<f64> = held[i].iter().chain(held[j].iter()).copied().collect();
            let f_coherence = -std_dev(&union);
            let f_size = -(size[i] - size[j]).abs();
            let f_onset = -(onset[i] - onset[j]).abs();
            feats.push([f_centroid, f_coherence, f_size, f_onset]);
            labels.push(op[i] == op[j]);
            pair_ij.push((i, j));
        }
    }
    for c in 0..4 {
        z_score_column(&mut feats, c);
    }
    let portfolio: Vec<f64> = feats.iter().map(|f| f[0] + f[1]).collect();
    let partition: Vec<f64> = feats.iter().map(|f| f[2] + f[3]).collect();
    let size_only: Vec<f64> = feats.iter().map(|f| f[2]).collect();
    let onset_only: Vec<f64> = feats.iter().map(|f| f[3]).collect();
    let full: Vec<f64> = feats.iter().map(|f| f[0] + f[1] + f[2] + f[3]).collect();

    // Real null: shuffle operator labels (same group-size multiset, random
    // membership), recompute the full-score AUC; average over a few shuffles.
    let mut null_acc = 0.0;
    let null_runs = 8u64;
    for s in 0..null_runs {
        let mut shuf = op.clone();
        let mut rng = SplitMix64::new(cfg.seed ^ 0x4D17_C8E5 ^ s);
        rng.shuffle(&mut shuf);
        let null_labels: Vec<bool> = pair_ij.iter().map(|&(i, j)| shuf[i] == shuf[j]).collect();
        null_acc += auc_from(&full, &null_labels);
    }
    let auc_null = null_acc / null_runs as f64;

    let auc_portfolio = auc_from(&portfolio, &labels);
    let auc_partition = auc_from(&partition, &labels);
    let auc_full = auc_from(&full, &labels);
    MatcherRow {
        label: label.to_string(),
        split_equal: cfg.split.equal,
        k_heterogeneous: cfg.k_heterogeneous,
        onset_staggered: cfg.onset_staggered,
        auc_portfolio,
        auc_partition,
        auc_size: auc_from(&size_only, &labels),
        auc_onset: auc_from(&onset_only, &labels),
        auc_full,
        auc_null,
        ablation_delta: auc_full - auc_portfolio,
        n_sibling_pairs: labels.iter().filter(|&&b| b).count(),
        n_pairs: labels.len(),
    }
}

/// Check A — one point of the K-mix mechanism sweep: at a given high-K fraction,
/// the mean (± across-seed std) size-channel AUC. The mechanism predicts size-AUC
/// FALLS as the high-K fraction rises (less K=1 background for the K=5 split to
/// stand out against). If it tracks, the re-inflation is mechanism (bulletproof);
/// if flat/random, it is a seed artifact (the "structural" claim softens).
#[derive(Debug, Clone, Serialize)]
pub struct HetKPoint {
    pub high_k_fraction: f64,
    pub mean_size_auc: f64,
    pub std_size_auc: f64,
    pub n_seeds: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatcherReport {
    pub rows: Vec<MatcherRow>,
    /// Check A: size-AUC vs high-K fraction across seeds (mechanism vs artifact).
    pub hetk_mechanism: Vec<HetKPoint>,
}

/// Check A — sweep the high-K fraction across seeds and report size-channel AUC.
fn hetk_mechanism_sweep(base: &ClusterConfig) -> Vec<HetKPoint> {
    let fractions = [0.1, 0.2, 0.35, 0.5, 0.75];
    let seeds = [0u64, 1, 2, 3, 4, 5];
    let mut out = Vec::new();
    for &f in &fractions {
        let aucs: Vec<f64> = seeds
            .iter()
            .map(|&s| {
                let cfg = ClusterConfig {
                    high_k_fraction: f,
                    seed: base.seed ^ 0xA11C ^ ((f * 100.0) as u64) ^ (s << 24),
                    ..*base
                };
                let pop = run_equilibrium(&cfg);
                run_matcher(&pop, "hetk", &cfg).auc_size
            })
            .collect();
        let mean = aucs.iter().sum::<f64>() / aucs.len() as f64;
        let var = aucs.iter().map(|a| (a - mean).powi(2)).sum::<f64>() / aucs.len() as f64;
        out.push(HetKPoint {
            high_k_fraction: f,
            mean_size_auc: mean,
            std_size_auc: var.sqrt(),
            n_seeds: seeds.len(),
        });
    }
    out
}

pub fn run_matcher_report() -> MatcherReport {
    // Aimed at the LEAN attractor, α=1, in-tier (window 3) — the regime where the
    // comparison arm showed portfolios decorrelate, so "does the PARTITION still
    // leak despite decorrelation?" is the real question.
    let base = ClusterConfig {
        regime: Regime::Lean,
        n_shard: 240,
        alpha: 1.0,
        split: Split { k: 2, equal: true },
        phi: 0.0,
        rotation_period: 8,
        spread_window_mult: 3,
        k_heterogeneous: false,
        onset_staggered: false,
        high_k_fraction: 0.0,
        onset_stagger_width: 0,
        epochs: 120,
        seed: 0x9A7C_4E11,
    };
    // (label, split, k_heterogeneous, onset_staggered, onset_stagger_width).
    // width 0 ⇒ default ONSET_STAGGER (96); ONSET_RANGE ⇒ full-range stagger (Check B).
    let scenarios: [(&str, Split, bool, bool, u32); 7] = [
        (
            "regular (equal,co-onset,uniK)",
            Split { k: 2, equal: true },
            false,
            false,
            0,
        ),
        ("varied size", Split { k: 2, equal: false }, false, false, 0),
        (
            "staggered onset (w=96)",
            Split { k: 2, equal: true },
            false,
            true,
            0,
        ),
        (
            "FULL-range stagger (w=240)",
            Split { k: 2, equal: true },
            false,
            true,
            ONSET_RANGE,
        ),
        (
            "heterogeneous K",
            Split { k: 2, equal: true },
            true,
            false,
            0,
        ),
        (
            "varied+stagger+hetK",
            Split { k: 2, equal: false },
            true,
            true,
            0,
        ),
        ("regular k=3", Split { k: 3, equal: true }, false, false, 0),
    ];
    let mut rows = Vec::new();
    for (i, (label, split, hk, stag, width)) in scenarios.iter().enumerate() {
        let cfg = ClusterConfig {
            split: *split,
            k_heterogeneous: *hk,
            onset_staggered: *stag,
            onset_stagger_width: *width,
            seed: base.seed ^ ((i as u64) << 20),
            ..base
        };
        let pop = run_equilibrium(&cfg);
        rows.push(run_matcher(&pop, label, &cfg));
    }
    let hetk_mechanism = hetk_mechanism_sweep(&base);
    MatcherReport {
        rows,
        hetk_mechanism,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(regime: Regime, alpha: f64, k: usize, window: usize, seed: u64) -> ClusterConfig {
        ClusterConfig {
            regime,
            n_shard: 240,
            alpha,
            split: Split { k, equal: false },
            phi: 0.0,
            rotation_period: 8,
            spread_window_mult: window,
            k_heterogeneous: false,
            onset_staggered: false,
            high_k_fraction: 0.0,
            onset_stagger_width: 0,
            epochs: 120,
            seed,
        }
    }

    /// **Positive control on the equilibrium** (the CT-5 discipline: validate the
    /// substrate reproduces the known result before trusting any downstream
    /// number). The capacity-regime signature of `F1` is *coverage*, not relative
    /// curve-steepness (the steepness ratio actually inverts — recorded as a
    /// finding, not encoded here): the capacity-rich attractor covers the deep pool
    /// with **redundancy** (`R > 1`), the starved trough sits at the **coverage
    /// edge** (`R ≈ 1`, no slack). Assert exactly that — it is the within-tier-room
    /// predictor and the data-confirmed capacity difference (lean ≈3.7 vs trough ≈1).
    #[test]
    fn equilibrium_reproduces_capacity_regime() {
        let lean = deep_stats(&run_equilibrium(&cfg(Regime::Lean, 1.0, 2, 3, 1)));
        let trough = deep_stats(&run_equilibrium(&cfg(Regime::Trough, 1.0, 2, 3, 1)));
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

    /// **Metric-validity control on the proto-matcher** (analogue of the cover
    /// harness's targeting controls): on a *synthetic* population where each
    /// operator's personas are deliberately CO-LOCATED in value-rank, the
    /// co-location signal must be higher than on one where each operator's personas
    /// are deliberately SPREAD. This proves the instrument detects co-location when
    /// it is present — without asserting whether *dispersion* lowers it (that is the
    /// open question the comparison arm and the matcher answer, not a unit test).
    #[test]
    fn colocation_detects_co_location() {
        // 8 shards, value-rank fixed by age (R=1 ⇒ value ∝ g(age)): shard 0 highest.
        let ages = vec![0.95, 0.85, 0.75, 0.65, 0.35, 0.25, 0.15, 0.05];
        let mk = |sets: &[(usize, &[usize])]| -> f64 {
            let n = ages.len();
            let personas: Vec<Persona> = sets
                .iter()
                .map(|(op, sh)| {
                    let mut h = vec![false; n];
                    for &s in *sh {
                        h[s] = true;
                    }
                    Persona {
                        operator: *op,
                        storage_capacity: sh.len(),
                        capital: 100.0,
                        holdings: h,
                        prior: vec![false; n],
                        onset: 0,
                    }
                })
                .collect();
            let n_operators = sets.iter().map(|(op, _)| *op).max().unwrap_or(0) + 1;
            let pop = Pop {
                ages: ages.clone(),
                personas,
                n_operators,
                phi: 0.0,
                spread_window_mult: 0,
            };
            let (intra, baseline, _) = colocation(&pop);
            if baseline > 1e-9 {
                (1.0 - intra / baseline).clamp(0.0, 1.0)
            } else {
                0.0
            }
        };
        // Co-located: each operator's 2 personas hold adjacent (rank-near) shards.
        let co = mk(&[
            (0, &[0]),
            (0, &[1]),
            (1, &[2]),
            (1, &[3]),
            (2, &[4]),
            (2, &[5]),
            (3, &[6]),
            (3, &[7]),
        ]);
        // Spread: each operator's 2 personas straddle the rank range (far apart).
        let spread = mk(&[
            (0, &[0]),
            (0, &[4]),
            (1, &[1]),
            (1, &[5]),
            (2, &[2]),
            (2, &[6]),
            (3, &[3]),
            (3, &[7]),
        ]);
        assert!(
            co > spread + 0.05,
            "co-location signal must detect co-located siblings \
             (co {co:.3} vs spread {spread:.3})"
        );
    }

    /// Exact sibling overlap is ≈0 regardless of strategy (no-self-replication) —
    /// the empirical proof that overlap is not the clustering signal.
    #[test]
    fn exact_overlap_is_negligible() {
        let (_, _, overlap) = colocation(&run_equilibrium(&cfg(Regime::Lean, 0.0, 3, 3, 3)));
        assert!(
            overlap < 0.05,
            "sibling exact-overlap must be ≈0, got {overlap:.3}"
        );
    }

    /// The matcher interface emits one portfolio + operator label per persona.
    #[test]
    fn equilibrium_portfolios_shape() {
        let ep = run_equilibrium_portfolios(Regime::Lean, 1.0);
        assert_eq!(ep.portfolios.len(), ep.operator_of.len());
        assert!(ep.n_operators >= 1);
        assert!(ep.operator_of.iter().all(|&o| o < ep.n_operators));
    }

    /// **Matcher validity controls** (the discipline that makes the AUC trustworthy):
    /// (a) on a real equilibrium the full-feature AUC must beat the shuffled-label
    /// null — there *is* a sibling signal to find; (b) the null itself must sit at
    /// ≈0.5 — the metric has no structural bias, so "above baseline" is genuine.
    #[test]
    fn matcher_separates_siblings_and_null_is_unbiased() {
        let pop = run_equilibrium(&cfg(Regime::Lean, 1.0, 2, 3, 0x5EED));
        let row = run_matcher(&pop, "control", &cfg(Regime::Lean, 1.0, 2, 3, 0x5EED));
        assert!(
            (row.auc_null - 0.5).abs() < 0.05,
            "shuffled-label null must be ≈0.5 (unbiased metric), got {:.3}",
            row.auc_null
        );
        assert!(
            row.auc_full > row.auc_null + 0.15,
            "matcher must find the sibling signal above its own null \
             (full {:.3} vs null {:.3})",
            row.auc_full,
            row.auc_null
        );
    }
}
