//! Coverage metrics and the four falsifiable sub-claims.
//!
//! The spread sub-claim is **actor-level** (primary): the firewall makes pseudonyms
//! unlinkable, so a Gini over pseudonyms reads a Sybil whale as a crowd of small
//! holders — egalitarian, passing, exactly wrong. The actor↔pseudonym map is a model
//! input held as ground truth; the live chain cannot observe it, so the sim is the
//! *only* place the bond's actor-level deterrence can be measured. A pseudonym-level
//! line is reported as the secondary "what an on-chain observer would (mis)conclude."

use crate::model::{bond_age, r_target, World};
use crate::reward::RewardEval;
use serde::Serialize;

/// Number of age bands for the per-band breakdowns. The top band is the
/// oldest-shard tail — the crux where `R_target`, bond, and scarcity all peak.
pub const N_BANDS: usize = 5;

/// Per-age-band breakdown. The aggregate spread metric masks durability-critical
/// concentration (a whale at 0.11 aggregate could be 0.4 in the deep band); age
/// resolution is what exposes it. `frac_under` per band is the residual-by-age
/// readout (the oldest-tail prediction is that the residual concentrates in the top
/// band, not random scatter).
#[derive(Debug, Clone, Serialize)]
pub struct AgeBandMetrics {
    pub band_lo: f64,
    pub band_hi: f64,
    pub n_shards: usize,
    pub mean_r: f64,
    pub frac_under: f64,
    /// Actor-level Gini of shards-held *within this band*.
    pub gini_actor: f64,
    /// Whale's share of all holdings *within this band* (durability-critical
    /// concentration), if a whale is present.
    pub whale_share: Option<f64>,
    /// Number of actors who could afford *one* bond at this band's bond level (the
    /// worst-case bond at `band_hi`). Under an age-scaled bond this declines with
    /// age; if it drops below `R_target` for the band, the band cannot be seated by
    /// enough distinct actors (the distinct-actor empty-window, concentrated at the
    /// oldest tail — L4). `usize::MAX` is reported as the actor count when the bond
    /// is disabled.
    pub affording: usize,
    /// Number of **co-located** actors for this band: those whose *smaller* leg can
    /// seat at least one deep shard, `min(⌊capital/bond⌋, ⌊storage/shard_size⌋) ≥ 1`
    /// (L8). A deep shard needs both legs on the *same* actor — capital sitting on a
    /// storage-poor actor (or storage on a capital-poor actor) cannot seat it. This is
    /// the binding count; `affording` (capital leg alone) overcounts it.
    pub colocated: usize,
    /// `R_target(age)` at this band's oldest edge (the seating bar for the band).
    pub r_target: usize,
}

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

    // --- per-age-band breakdown (residual-by-age + per-band concentration) ---
    pub bands: Vec<AgeBandMetrics>,

    // --- durability seating (gate-4 empty-window condition) ---
    /// Number of actors who can afford the *deepest* bond (`bond_age(1.0)`). If this
    /// drops below `r_target_deepest`, the deepest shards *cannot* be seated by enough
    /// distinct actors — a durability failure, not a fairness one (the distinct-actor
    /// empty-window). Slack under a flat bond in a populous network; an age-scaled bond
    /// is what can make it bind at the tail (L4).
    pub affording_actors: usize,
    /// `R_target` at the deepest age (the seating bar for the oldest tail).
    pub r_target_deepest: usize,
    /// `affording_actors ≥ r_target_deepest`: the distinct-actor seating condition.
    pub seating_feasible: bool,
    /// **Co-located coverage ratio** (the `dS/dN` column, L8): the *min-form* seating
    /// condition `Σ_actor min(⌊capital/bond⌋, ⌊storage/shard_size⌋) / Σ_{deep} R_target(age)`.
    /// A deep shard needs storage *and* bond-capital on the **same** actor, so each
    /// actor contributes only its *smaller* leg — capital on a storage-poor actor (or
    /// vice versa) cannot seat anything. `< 1` ⇒ the co-located population cannot seat
    /// the deep set even if every actor devoted everything to deep. This is the metric
    /// gate 4/5 own jointly; it predicts the starvation the aggregate ratio misses
    /// (`bscale_s0`: aggregate 3.24 but co-located ≈ 0.71, matching `deep_und` 0.75).
    pub colocated_coverage: f64,
    /// **Aggregate capital-coverage** = `Σ_actor capital / Σ_{deep} bond_age·R_target`
    /// — necessary-not-sufficient (treats capital as fungible across actors). Retained
    /// as the secondary line; `colocated_coverage` is the binding one.
    pub capital_coverage: f64,
    /// Total deep bond capital demanded `Σ_{deep} bond_age(age)·R_target(age)`.
    pub deep_bond_demand: f64,
    /// Total actor capital in the network.
    pub total_capital: f64,
    /// Aggregate deep replica need `Σ_{deep} R_target(age)` (context).
    pub deep_need_total: usize,
}

pub struct TargetParams {
    pub r_target_hot: f64,
    pub r_target_deep: f64,
    pub deep_threshold: f64,
    /// Bond rate in force, needed to compute durability seating.
    pub bond_rate: f64,
    /// Age-scaling of the bond (L4), needed to compute per-band affording counts.
    pub bond_age_scale: f64,
    /// Storage units a deep shard occupies (L8 storage leg / gate-5 granularity lever).
    /// Smaller shards clear more actors' storage leg, enlarging the co-located pool.
    pub deep_shard_size: f64,
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
    let whale_shard_share = world.actors.iter().position(|a| a.is_whale).map(|w| {
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

    // Per-age-band breakdown.
    let n_actors = world.actors.len();
    let whale_idx = world.actors.iter().position(|a| a.is_whale);
    let mut band_n = [0usize; N_BANDS];
    let mut band_r_sum = [0usize; N_BANDS];
    let mut band_under = [0usize; N_BANDS];
    let mut band_actor_counts: Vec<Vec<f64>> = vec![vec![0.0; n_actors]; N_BANDS];
    #[allow(clippy::needless_range_loop)]
    for s in 0..n_shard {
        let age = world.shards[s].age;
        let band = ((age * N_BANDS as f64) as usize).min(N_BANDS - 1);
        band_n[band] += 1;
        band_r_sum[band] += r[s];
        if r[s] < r_target(age, tp.r_target_hot, tp.r_target_deep) {
            band_under[band] += 1;
        }
        for a in 0..n_actors {
            if world.holdings[a][s] {
                band_actor_counts[band][a] += 1.0;
            }
        }
    }
    let bonded = tp.bond_rate > 0.0;
    let n_actors_total = world.actors.len();
    // Storage leg: how many deep shards (of size `deep_shard_size`) an actor can store.
    let storage_slots = |stor: usize| (stor as f64 / tp.deep_shard_size).floor() as usize;
    let bands: Vec<AgeBandMetrics> = (0..N_BANDS)
        .map(|b| {
            let lo = b as f64 / N_BANDS as f64;
            let hi = (b as f64 + 1.0) / N_BANDS as f64;
            let n = band_n[b];
            let counts = &band_actor_counts[b];
            let band_total: f64 = counts.iter().sum();
            // Affording at this band: worst-case bond at the band's oldest edge.
            let deep_band = hi > tp.deep_threshold;
            let r_tgt = r_target(hi, tp.r_target_hot, tp.r_target_deep);
            let (affording, colocated) = if bonded && deep_band {
                let bond_here = bond_age(hi, tp.bond_rate, tp.bond_age_scale, tp.deep_threshold);
                let aff = world
                    .actors
                    .iter()
                    .filter(|a| a.capital >= bond_here)
                    .count();
                // Co-located: BOTH legs seat ≥1 deep shard on the same actor (L8).
                let colo = world
                    .actors
                    .iter()
                    .filter(|a| {
                        let cap_slots = (a.capital / bond_here).floor() as usize;
                        let stor_slots = storage_slots(a.storage_capacity);
                        cap_slots.min(stor_slots) >= 1
                    })
                    .count();
                (aff, colo)
            } else {
                (n_actors_total, n_actors_total)
            };
            AgeBandMetrics {
                band_lo: lo,
                band_hi: hi,
                n_shards: n,
                mean_r: if n > 0 {
                    band_r_sum[b] as f64 / n as f64
                } else {
                    0.0
                },
                frac_under: if n > 0 {
                    band_under[b] as f64 / n as f64
                } else {
                    0.0
                },
                gini_actor: gini(counts),
                whale_share: whale_idx.map(|w| {
                    if band_total > 0.0 {
                        counts[w] / band_total
                    } else {
                        0.0
                    }
                }),
                affording,
                colocated,
                r_target: r_tgt,
            }
        })
        .collect();

    // Durability seating (gate-4 empty-window condition).
    let r_target_deepest = r_target(1.0, tp.r_target_hot, tp.r_target_deep);
    let bond_deepest = bond_age(1.0, tp.bond_rate, tp.bond_age_scale, tp.deep_threshold);
    let affording_actors = if bonded {
        world
            .actors
            .iter()
            .filter(|a| a.capital >= bond_deepest)
            .count()
    } else {
        n_actors_total
    };
    let seating_feasible = affording_actors >= r_target_deepest;
    let total_capital: f64 = world.actors.iter().map(|a| a.capital).sum();
    let deep_need_total: usize = world
        .shards
        .iter()
        .filter(|s| s.is_deep(tp.deep_threshold))
        .map(|s| r_target(s.age, tp.r_target_hot, tp.r_target_deep))
        .sum();
    // Capital the deep set demands: each deep shard needs R_target(age) copies, each
    // posting bond_age(age). The binding aggregate empty-window condition.
    let deep_bond_demand: f64 = if bonded {
        world
            .shards
            .iter()
            .filter(|s| s.is_deep(tp.deep_threshold))
            .map(|s| {
                bond_age(s.age, tp.bond_rate, tp.bond_age_scale, tp.deep_threshold)
                    * r_target(s.age, tp.r_target_hot, tp.r_target_deep) as f64
            })
            .sum()
    } else {
        0.0
    };
    let capital_coverage = if deep_bond_demand > 0.0 {
        total_capital / deep_bond_demand
    } else {
        f64::INFINITY
    };
    // Co-located coverage (L8 min-form): each actor contributes only its *smaller* leg
    // — capital-slots ⌊capital/bond⌋ vs storage-slots ⌊storage/shard_size⌋ — because a
    // deep shard needs both on the same actor. Representative bond = mean deep bond
    // (= bond_rate under flat magnitude). This is the binding seating condition.
    let colocated_coverage = if bonded && deep_n > 0 && deep_need_total > 0 {
        let mean_deep_bond: f64 = world
            .shards
            .iter()
            .filter(|s| s.is_deep(tp.deep_threshold))
            .map(|s| bond_age(s.age, tp.bond_rate, tp.bond_age_scale, tp.deep_threshold))
            .sum::<f64>()
            / deep_n as f64;
        let colocated_slots: usize = world
            .actors
            .iter()
            .map(|a| {
                let cap_slots = (a.capital / mean_deep_bond).floor() as usize;
                cap_slots.min(storage_slots(a.storage_capacity))
            })
            .sum();
        colocated_slots as f64 / deep_need_total as f64
    } else {
        f64::INFINITY
    };

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
        bands,
        affording_actors,
        r_target_deepest,
        seating_feasible,
        colocated_coverage,
        capital_coverage,
        deep_bond_demand,
        total_capital,
        deep_need_total,
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
