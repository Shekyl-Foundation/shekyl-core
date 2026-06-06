//! Coverage metrics and the four falsifiable sub-claims.
//!
//! The spread sub-claim is **actor-level** (primary): the firewall makes pseudonyms
//! unlinkable, so a Gini over pseudonyms reads a Sybil whale as a crowd of small
//! holders — egalitarian, passing, exactly wrong. The actor↔pseudonym map is a model
//! input held as ground truth; the live chain cannot observe it, so the sim is the
//! *only* place the bond's actor-level deterrence can be measured. A pseudonym-level
//! line is reported as the secondary "what an on-chain observer would (mis)conclude."

use crate::model::{r_target, World};
use crate::reward::RewardEval;
use serde::Serialize;

/// Gini coefficient of a non-negative distribution. 0 = perfectly equal, →1 =
/// maximally concentrated. Empty / all-zero ⇒ 0.
pub fn gini(values: &[f64]) -> f64 {
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    let sum: f64 = values.iter().sum();
    if sum <= 0.0 {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // G = (2·Σ i·x_i) / (n·Σ x_i) − (n+1)/n, with i 1-indexed.
    let mut weighted = 0.0;
    for (i, x) in v.iter().enumerate() {
        weighted += (i as f64 + 1.0) * x;
    }
    (2.0 * weighted) / (n as f64 * sum) - (n as f64 + 1.0) / n as f64
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageMetrics {
    /// Minimum replication over all shards.
    pub min_r: usize,
    /// Fraction of shards with `R < R_target(age)`.
    pub frac_under_target: f64,
    /// Mean replication over all shards.
    pub mean_r: f64,

    // --- spread ---
    /// Actor-level Gini of shards-held (PRIMARY pass/fail input).
    pub gini_actor: f64,
    /// Largest single-actor share of all (actor,shard) holdings.
    pub max_actor_share: f64,
    /// The Sybil whale's own share of all holdings, if a whale is present. The
    /// keystone claim is that the per-shard bond makes this *small* despite the
    /// whale's large endowment; on the live chain this is unobservable (the privacy
    /// guarantee), so the sim is the only place it can be measured.
    pub whale_shard_share: Option<f64>,
    /// Pseudonym-level Gini (SECONDARY — what an on-chain observer mis-sees).
    pub gini_pseudonym: f64,

    // --- deep history ---
    /// Mean replication restricted to deep-history shards.
    pub deep_mean_r: f64,
    /// Fraction of deep-history shards under their (higher) `R_target(age)`.
    pub deep_frac_under_target: f64,
    /// Mean replication restricted to hot shards (for the deep-vs-hot comparison
    /// that is the bond-asymmetry signature).
    pub hot_mean_r: f64,
}

pub struct TargetParams {
    pub r_target_hot: f64,
    pub r_target_deep: f64,
    pub deep_threshold: f64,
}

pub fn coverage(world: &World, eval: &RewardEval, tp: &TargetParams) -> CoverageMetrics {
    let r = &eval.r;
    let n_shard = world.shards.len();

    let min_r = r.iter().copied().min().unwrap_or(0);
    let mean_r = if n_shard > 0 {
        r.iter().sum::<usize>() as f64 / n_shard as f64
    } else {
        0.0
    };

    let mut under = 0usize;
    let mut deep_n = 0usize;
    let mut deep_r_sum = 0usize;
    let mut deep_under = 0usize;
    let mut hot_n = 0usize;
    let mut hot_r_sum = 0usize;
    // Indexes two parallel collections (r, shards) by `s`.
    #[allow(clippy::needless_range_loop)]
    for s in 0..n_shard {
        let age = world.shards[s].age;
        let tgt = r_target(age, tp.r_target_hot, tp.r_target_deep);
        if r[s] < tgt {
            under += 1;
        }
        if world.shards[s].is_deep(tp.deep_threshold) {
            deep_n += 1;
            deep_r_sum += r[s];
            if r[s] < tgt {
                deep_under += 1;
            }
        } else {
            hot_n += 1;
            hot_r_sum += r[s];
        }
    }
    let frac_under_target = if n_shard > 0 {
        under as f64 / n_shard as f64
    } else {
        0.0
    };
    let deep_mean_r = if deep_n > 0 {
        deep_r_sum as f64 / deep_n as f64
    } else {
        0.0
    };
    let deep_frac_under_target = if deep_n > 0 {
        deep_under as f64 / deep_n as f64
    } else {
        0.0
    };
    let hot_mean_r = if hot_n > 0 {
        hot_r_sum as f64 / hot_n as f64
    } else {
        0.0
    };

    // Spread: actor-level shards-held.
    let actor_counts: Vec<f64> = (0..world.actors.len())
        .map(|a| world.actor_shard_count(a) as f64)
        .collect();
    let total_held: f64 = actor_counts.iter().sum();
    let gini_actor = gini(&actor_counts);
    let max_actor_share = if total_held > 0.0 {
        actor_counts.iter().cloned().fold(0.0, f64::max) / total_held
    } else {
        0.0
    };
    let whale_shard_share = world
        .actors
        .iter()
        .position(|a| a.is_whale)
        .map(|w| {
            if total_held > 0.0 {
                actor_counts[w] / total_held
            } else {
                0.0
            }
        });

    // Spread: pseudonym-level. Each actor's shards split (≈evenly) across its
    // pseudonym count. This is what an on-chain observer sees — a splitting whale
    // disaggregates into many small pseudonyms.
    let mut pseudonym_counts: Vec<f64> = Vec::new();
    for a in 0..world.actors.len() {
        let held = world.actor_shard_count(a);
        let m = eval.pseudonyms[a].max(1);
        if held == 0 {
            continue;
        }
        let base = held / m;
        let rem = held % m;
        for k in 0..m {
            let c = base + usize::from(k < rem);
            pseudonym_counts.push(c as f64);
        }
    }
    let gini_pseudonym = gini(&pseudonym_counts);

    CoverageMetrics {
        min_r,
        frac_under_target,
        mean_r,
        gini_actor,
        max_actor_share,
        whale_shard_share,
        gini_pseudonym,
        deep_mean_r,
        deep_frac_under_target,
        hot_mean_r,
    }
}

/// Churn = mean per-epoch (actor,shard) holding flips over the last `window`
/// epochs, normalized by total holdings (a rate in `[0, ∞)`; ~0 = stable).
pub fn churn_rate(change_series: &[usize], total_held: usize, window: usize) -> f64 {
    if change_series.is_empty() || total_held == 0 {
        return 0.0;
    }
    let start = change_series.len().saturating_sub(window);
    let tail = &change_series[start..];
    let mean_changes = tail.iter().sum::<usize>() as f64 / tail.len() as f64;
    mean_changes / total_held as f64
}
