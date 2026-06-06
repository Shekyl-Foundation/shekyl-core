//! Scenario construction, the epoch loop, and the iteration-1 sweep set.
//!
//! Sweeps (per the spec): coarse bond rate (low/mid/high), age-weight `g(age)`
//! including the `g=1` baseline, population thickness, endowment mix + whale, curve
//! shape (cap height), and shard-age distribution. The set below is curated
//! one-axis sweeps off a baseline plus the whale×bond cross — not the full Cartesian
//! product — to keep runtime bounded while exercising each axis.

use crate::agent::{run_epoch, AgentParams};
use crate::metrics::{churn_rate, coverage, CoverageMetrics, TargetParams};
use crate::model::{Actor, Rng, Shard, World};
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
    pub bond_carry: f64,
    pub deep_threshold: f64,

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
    pub claims: SubClaims,
    /// Compact time series for the four headline quantities (per epoch).
    pub series_frac_under: Vec<f64>,
    pub series_deep_frac_under: Vec<f64>,
    pub series_gini_actor: Vec<f64>,
    pub series_changes: Vec<usize>,
}

fn build_world(cfg: &SimConfig, rng: &mut Rng) -> World {
    let shards: Vec<Shard> = (0..cfg.n_shard)
        .map(|_| {
            let u = rng.next_f64();
            let age = u.powf(cfg.age_skew);
            Shard { age }
        })
        .collect();

    let scale = |s: usize| ((s as f64 * cfg.storage_scale).round() as usize).max(1);

    let mut actors: Vec<Actor> = Vec::with_capacity(cfg.n_actors);
    for _ in 0..cfg.n_actors {
        let storage_rich = rng.next_f64() < cfg.frac_storage_rich;
        let (storage_capacity, capital) = if storage_rich {
            (scale(cfg.storage_rich_storage), cfg.storage_rich_capital)
        } else {
            (scale(cfg.capital_rich_storage), cfg.capital_rich_capital)
        };
        actors.push(Actor {
            storage_capacity,
            capital,
            is_whale: false,
        });
    }
    if cfg.whale {
        actors.push(Actor {
            storage_capacity: scale(cfg.whale_storage),
            capital: cfg.whale_capital,
            is_whale: true,
        });
    }

    World::new(shards, actors)
}

pub fn run_sim(cfg: &SimConfig) -> ScenarioResult {
    let mut rng = Rng::new(cfg.seed);
    let mut world = build_world(cfg, &mut rng);

    let rp = RewardParams {
        budget: cfg.budget,
        cap: cfg.cap,
        pseudonym_cost: cfg.pseudonym_cost,
        age_weight: cfg.age_weight,
    };
    let ap = AgentParams {
        storage_unit_cost: cfg.storage_unit_cost,
        bond_rate: cfg.bond_rate,
        bond_carry: cfg.bond_carry,
        deep_threshold: cfg.deep_threshold,
    };
    let tp = TargetParams {
        r_target_hot: cfg.r_target_hot,
        r_target_deep: cfg.r_target_deep,
        deep_threshold: cfg.deep_threshold,
        bond_rate: cfg.bond_rate,
    };

    // Seed price so the first epoch's marginal-value calc is non-degenerate.
    let mut price = 1.0;
    let mut series_frac_under = Vec::with_capacity(cfg.epochs);
    let mut series_deep_frac_under = Vec::with_capacity(cfg.epochs);
    let mut series_gini_actor = Vec::with_capacity(cfg.epochs);
    let mut series_changes = Vec::with_capacity(cfg.epochs);

    let mut last_eval = evaluate(&world, &rp, price);
    let mut last_metrics = coverage(&world, &last_eval, &tp);

    for _ in 0..cfg.epochs {
        let changes = run_epoch(&mut world, price, &ap, cfg.age_weight, &mut rng);
        last_eval = evaluate(&world, &rp, price);
        price = if last_eval.price > 0.0 { last_eval.price } else { price };
        last_metrics = coverage(&world, &last_eval, &tp);

        series_frac_under.push(last_metrics.frac_under_target);
        series_deep_frac_under.push(last_metrics.deep_frac_under_target);
        series_gini_actor.push(last_metrics.gini_actor);
        series_changes.push(changes);
    }

    let total_held: usize = (0..world.actors.len())
        .map(|a| world.actor_shard_count(a))
        .sum();
    let churn = churn_rate(&series_changes, total_held, cfg.churn_window);

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
        bond_rate: 2.0, // mid
        bond_carry: 0.03,
        deep_threshold: 0.5,
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
    for (label, frac) in [("capital_heavy", 0.2), ("balanced", 0.5), ("storage_heavy", 0.8)] {
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

    out
}
