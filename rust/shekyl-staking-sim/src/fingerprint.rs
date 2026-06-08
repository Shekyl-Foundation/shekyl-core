//! T-A1 / T-A2 — F1 re-linkage instrument (PHASE_2B §7.7).
//!
//! **Timeline channel (diagnostic):** per-`(P, shard, settlement_epoch)` retention bits at
//! `SETTLEMENT_EPOCH_BLOCKS`. At the lean equilibrium, independent operators' timelines
//! converge on "serve every epoch" → high homogeneity is *protective* (non-fingerprint).
//! Re-linkage via timeline must be scored **relative to the independent-operator baseline**,
//! not against an absolute decorrelation ceiling.
//!
//! **Cohort channel (F1 gate):** re-linkage is **shard-set-intersection-cohort** driven.
//! `|{P' : portfolio(P') = portfolio(P)}|` is the anonymity floor; distinctive combinations
//! identify even when per-shard `R_target` is healthy.
//!
//! Spec: `docs/design/STAKER_ARCHIVAL_SIM.md` §*T-A1*; gate: `PHASE_2B_STAKE_LIFECYCLE.md` §7.7.

use crate::model::World;
use serde::Serialize;
use std::collections::HashMap;

/// Pinned genesis SEB per [`ARCHIVAL_TIMING_CONSTANTS.md`](../../docs/design/ARCHIVAL_TIMING_CONSTANTS.md).
pub const SEB_DEFAULT: u64 = 10_000;
/// Default block time for calendar reporting (seconds).
pub const BLOCK_TIME_SEC: u64 = 120;

/// Minimum completed settlement epochs for an adequate sample.
pub const MIN_SETTLEMENT_EPOCHS: usize = 20;
/// At lean equilibrium, independent `P` timelines should be highly similar (non-fingerprint).
pub const MIN_INDEPENDENT_SIMILARITY: f64 = 0.90;
/// Mean shard-set cohort size (operators sharing the exact deep portfolio).
pub const MIN_MEAN_COHORT_SIZE: f64 = 2.0;
/// Fraction of seated deep portfolios that are singleton cohorts (identifiable by set alone).
pub const MAX_SINGLETON_PORTFOLIO_FRACTION: f64 = 0.10;
/// Distinctive-portfolio negative control: singleton fraction should exceed this.
pub const MIN_DISTINCTIVE_SINGLETON_FRACTION: f64 = 0.50;
/// Cosmetic rotation (same pattern, new id) should re-link strongly — documents E-4 failure.
pub const MIN_COSMETIC_OVERLAP: f64 = 0.70;

#[derive(Debug, Clone, Serialize)]
pub struct Ta1Claims {
    pub sample_adequate: bool,
    /// Timeline channel: lean-equilibrium homogeneity (reassuring, not a fail).
    pub timeline_homogeneous: bool,
    /// Rotation `P₀→P₁` is not *more* timeline-similar than a random other archiver.
    pub rotation_no_timeline_advantage: bool,
    /// Cohort channel: shard-set anonymity floor adequate (primary F1 gate).
    pub cohort_adequate: bool,
    /// Negative control: distinctive portfolio is publicly identifiable by set.
    pub distinctive_identifiable: bool,
    pub cosmetic_relinks: bool,
    pub f1_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ta1Metrics {
    pub settlement_epochs: usize,
    pub settlement_epoch_days: f64,
    pub mean_bit_density: f64,
    /// Mean normalized Hamming distance between distinct `P` on the same shard (diagnostic).
    pub mean_pairwise_distance: f64,
    /// `1 − mean_pairwise_distance` — independent-operator timeline baseline similarity.
    pub mean_independent_similarity: f64,
    /// Pre-lapse `P₀` vs post-rotation `P₁` timeline similarity (`1 − Hamming`).
    pub lapse_relink_similarity: Option<f64>,
    /// `baseline_similarity − lapse_relink` (positive ⇒ rotation harder to link than chance).
    pub lapse_vs_baseline_advantage: Option<f64>,
    /// Stability: first vs second half timeline correlation (diagnostic).
    pub half_run_autocorrelation: f64,
    /// Mean `|{P' : portfolio(P') = portfolio(P)}|` over seated deep actor-epochs.
    pub mean_portfolio_cohort_size: f64,
    /// Fraction of seated deep actor-epochs in a singleton portfolio cohort.
    pub singleton_portfolio_fraction: f64,
    /// Post-lapse overlap when cosmetic relink is forced (E-4 failure mode).
    pub cosmetic_overlap: Option<f64>,
    pub claims: Ta1Claims,
}

/// Per-actor retention-bit timelines: `bits[actor][shard] = one bool per completed settlement epoch.
pub struct Ta1Recorder {
    settlement_epoch_blocks: u64,
    blocks_per_sim_epoch: u64,
    cumulative_blocks: u64,
    closed_settlements: usize,
    bits: Vec<Vec<Vec<bool>>>,
    /// Cohort size per actor per completed settlement epoch (`0` = no seated deep portfolio).
    cohort_sizes: Vec<Vec<usize>>,
    deep_threshold: f64,
    lapse_actor: Option<usize>,
    lapse_at_settlement: u32,
    lapse_span_settlement: u32,
    cosmetic_relink: bool,
    rotation_actor: Option<usize>,
    expect_distinctive_portfolio: bool,
    pre_lapse_bits: Option<Vec<Vec<bool>>>,
    lapse_started: bool,
    lapse_ended: bool,
    post_lapse_start_epoch: usize,
}

impl Ta1Recorder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        n_actors: usize,
        n_shards: usize,
        settlement_epoch_blocks: u64,
        blocks_per_sim_epoch: u64,
        deep_threshold: f64,
        lapse_actor: Option<usize>,
        lapse_at_settlement: u32,
        lapse_span_settlement: u32,
        cosmetic_relink: bool,
        rotation_actor: Option<usize>,
        expect_distinctive_portfolio: bool,
    ) -> Self {
        Self {
            settlement_epoch_blocks,
            blocks_per_sim_epoch,
            cumulative_blocks: 0,
            closed_settlements: 0,
            bits: vec![vec![Vec::new(); n_shards]; n_actors],
            cohort_sizes: vec![Vec::new(); n_actors],
            deep_threshold,
            lapse_actor,
            lapse_at_settlement,
            lapse_span_settlement,
            cosmetic_relink,
            rotation_actor,
            expect_distinctive_portfolio,
            pre_lapse_bits: None,
            lapse_started: false,
            lapse_ended: false,
            post_lapse_start_epoch: 0,
        }
    }

    pub fn tick_epoch(&mut self, world: &World) {
        self.cumulative_blocks = self
            .cumulative_blocks
            .saturating_add(self.blocks_per_sim_epoch);
        while self.cumulative_blocks
            >= (self.closed_settlements as u64 + 1) * self.settlement_epoch_blocks
        {
            self.close_settlement(world);
        }
    }

    fn retention_bit(world: &World, actor: usize, shard: usize, deep_threshold: f64) -> bool {
        world.shards[shard].is_deep(deep_threshold)
            && world.holdings[actor][shard]
            && world.inflight[actor][shard] == 0
    }

    fn close_settlement(&mut self, world: &World) {
        let se = self.closed_settlements;

        if let Some(actor) = self.lapse_actor {
            if se == self.lapse_at_settlement as usize && !self.lapse_started {
                self.pre_lapse_bits = Some(self.bits[actor].clone());
                self.lapse_started = true;
            }
            if self.lapse_started
                && !self.lapse_ended
                && se >= (self.lapse_at_settlement + self.lapse_span_settlement) as usize
            {
                self.lapse_ended = true;
                self.post_lapse_start_epoch = se + 1;
            }
        }

        for a in 0..world.actors.len() {
            for s in 0..world.shards.len() {
                let bit = Self::retention_bit(world, a, s, self.deep_threshold);
                self.bits[a][s].push(bit);
            }
        }

        let mut portfolios: Vec<Vec<usize>> = vec![Vec::new(); world.actors.len()];
        for (a, actor_bits) in self.bits.iter().enumerate().take(world.actors.len()) {
            for (s, shard_bits) in actor_bits.iter().enumerate().take(world.shards.len()) {
                if shard_bits.last() == Some(&true) {
                    portfolios[a].push(s);
                }
            }
        }
        let mut counts: HashMap<Vec<usize>, usize> = HashMap::new();
        for p in &portfolios {
            if !p.is_empty() {
                *counts.entry(p.clone()).or_insert(0) += 1;
            }
        }
        for (a, portfolio) in portfolios.iter().enumerate().take(world.actors.len()) {
            let size = if portfolio.is_empty() {
                0
            } else {
                counts.get(portfolio).copied().unwrap_or(1)
            };
            self.cohort_sizes[a].push(size);
        }

        self.closed_settlements += 1;
    }

    pub fn apply_lapse_drop(&self, world: &mut World, actor: usize) {
        if !self.lapse_started || self.lapse_ended {
            return;
        }
        let se = self.closed_settlements;
        if se < self.lapse_at_settlement as usize
            || se >= (self.lapse_at_settlement + self.lapse_span_settlement) as usize
        {
            return;
        }
        for s in 0..world.shards.len() {
            if world.shards[s].is_deep(self.deep_threshold) {
                world.holdings[actor][s] = false;
                world.locks[actor][s] = 0;
                world.inflight[actor][s] = 0;
            }
        }
    }

    pub fn apply_cosmetic_relink(&self, world: &mut World, actor: usize) {
        if !self.cosmetic_relink {
            return;
        }
        let Some(ref pre) = self.pre_lapse_bits else {
            return;
        };
        if self.closed_settlements < self.post_lapse_start_epoch {
            return;
        }
        for (s, timeline) in pre
            .iter()
            .enumerate()
            .take(world.shards.len().min(pre.len()))
        {
            if world.shards[s].is_deep(self.deep_threshold)
                && timeline.last().copied().unwrap_or(false)
            {
                world.holdings[actor][s] = true;
                world.inflight[actor][s] = 0;
                world.locks[actor][s] = world.locks[actor][s].max(1);
            }
        }
    }

    pub fn finalize(&self, cosmetic_overlap_hint: Option<f64>) -> Ta1Metrics {
        let n_ep = self.closed_settlements;
        let seb_days = (self.settlement_epoch_blocks as f64 * BLOCK_TIME_SEC as f64) / 86_400.0;

        let (mean_density, mean_dist, half_auto) = aggregate_timeline_stats(&self.bits);
        let baseline_sim = 1.0 - mean_dist;

        let lapse_relink = match (self.lapse_actor, self.rotation_actor) {
            (Some(pre), Some(post)) if !self.cosmetic_relink => rotation_lapse_relink(
                &self.bits[pre],
                &self.bits[post],
                self.lapse_at_settlement as usize,
                self.post_lapse_start_epoch,
            ),
            (Some(a), _) => lapse_relink_similarity(
                &self.bits[a],
                self.lapse_at_settlement as usize,
                self.post_lapse_start_epoch,
            ),
            _ => None,
        };
        let lapse_advantage = lapse_relink.map(|r| baseline_sim - r);

        let (mean_cohort, singleton_frac) = aggregate_cohort_stats(&self.cohort_sizes, &self.bits);

        let cosmetic_overlap = cosmetic_overlap_hint.or_else(|| {
            if self.cosmetic_relink {
                self.lapse_actor.and_then(|a| {
                    cosmetic_pattern_overlap(&self.bits[a], self.post_lapse_start_epoch)
                })
            } else {
                None
            }
        });

        let sample_adequate = n_ep >= MIN_SETTLEMENT_EPOCHS;
        let timeline_homogeneous = baseline_sim >= MIN_INDEPENDENT_SIMILARITY;
        let rotation_no_timeline_advantage = lapse_relink.is_none_or(|r| r <= baseline_sim + 1e-9);
        let cohort_adequate = mean_cohort >= MIN_MEAN_COHORT_SIZE
            && singleton_frac <= MAX_SINGLETON_PORTFOLIO_FRACTION;
        let distinctive_identifiable = singleton_frac >= MIN_DISTINCTIVE_SINGLETON_FRACTION;
        let cosmetic_relinks = cosmetic_overlap.is_none_or(|o| o >= MIN_COSMETIC_OVERLAP);

        let f1_pass = if self.expect_distinctive_portfolio {
            sample_adequate && distinctive_identifiable
        } else {
            sample_adequate && rotation_no_timeline_advantage && cohort_adequate
        };

        Ta1Metrics {
            settlement_epochs: n_ep,
            settlement_epoch_days: seb_days,
            mean_bit_density: mean_density,
            mean_pairwise_distance: mean_dist,
            mean_independent_similarity: baseline_sim,
            lapse_relink_similarity: lapse_relink,
            lapse_vs_baseline_advantage: lapse_advantage,
            half_run_autocorrelation: half_auto,
            mean_portfolio_cohort_size: mean_cohort,
            singleton_portfolio_fraction: singleton_frac,
            cosmetic_overlap,
            claims: Ta1Claims {
                sample_adequate,
                timeline_homogeneous,
                rotation_no_timeline_advantage,
                cohort_adequate,
                distinctive_identifiable,
                cosmetic_relinks,
                f1_pass,
            },
        }
    }
}

/// Force an actor's deep holdings to an exact shard set (portfolio-distinctiveness sweep).
pub fn force_deep_portfolio(
    world: &mut World,
    actor: usize,
    shards: &[usize],
    deep_threshold: f64,
) {
    for s in 0..world.shards.len() {
        if !world.shards[s].is_deep(deep_threshold) {
            continue;
        }
        let hold = shards.contains(&s);
        world.holdings[actor][s] = hold;
        if hold {
            world.inflight[actor][s] = 0;
            world.locks[actor][s] = world.locks[actor][s].max(1);
        } else {
            world.locks[actor][s] = 0;
            world.inflight[actor][s] = 0;
        }
    }
}

fn actor_flat(bits: &[Vec<bool>]) -> Vec<bool> {
    let mut out = Vec::new();
    for shard_bits in bits {
        out.extend_from_slice(shard_bits);
    }
    out
}

fn aggregate_cohort_stats(cohort_sizes: &[Vec<usize>], bits: &[Vec<Vec<bool>>]) -> (f64, f64) {
    let mut sum = 0.0;
    let mut n = 0usize;
    let mut singletons = 0usize;
    for (a, sizes) in cohort_sizes.iter().enumerate() {
        for (ep, &size) in sizes.iter().enumerate() {
            let seated = bits[a]
                .iter()
                .any(|shard| shard.get(ep).copied().unwrap_or(false));
            if !seated || size == 0 {
                continue;
            }
            sum += size as f64;
            n += 1;
            if size == 1 {
                singletons += 1;
            }
        }
    }
    if n == 0 {
        return (0.0, 0.0);
    }
    (sum / n as f64, singletons as f64 / n as f64)
}

fn aggregate_timeline_stats(bits: &[Vec<Vec<bool>>]) -> (f64, f64, f64) {
    if bits.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let n_shards = bits[0].len();
    let mut density_sum = 0.0;
    let mut density_n = 0usize;
    for actor in bits {
        for shard_bits in actor.iter() {
            if shard_bits.is_empty() {
                continue;
            }
            density_sum +=
                shard_bits.iter().filter(|&&b| b).count() as f64 / shard_bits.len() as f64;
            density_n += 1;
        }
    }
    let mean_density = if density_n > 0 {
        density_sum / density_n as f64
    } else {
        0.0
    };

    let mut dist_sum = 0.0;
    let mut dist_n = 0usize;
    for s in 0..n_shards {
        let active: Vec<&[bool]> = bits
            .iter()
            .map(|actor| actor[s].as_slice())
            .filter(|v| v.iter().any(|&b| b))
            .collect();
        for i in 0..active.len() {
            for j in (i + 1)..active.len() {
                dist_sum += normalized_hamming(active[i], active[j]);
                dist_n += 1;
            }
        }
    }
    let mean_dist = if dist_n > 0 {
        dist_sum / dist_n as f64
    } else {
        0.0
    };

    let active_flat: Vec<Vec<bool>> = bits
        .iter()
        .map(|actor| actor_flat(actor))
        .filter(|v| v.iter().any(|&b| b))
        .collect();
    let mut auto_sum = 0.0;
    let mut auto_n = 0usize;
    for v in &active_flat {
        if let Some(r) = half_correlation(v) {
            auto_sum += r;
            auto_n += 1;
        }
    }
    let half_auto = if auto_n > 0 {
        auto_sum / auto_n as f64
    } else {
        0.0
    };

    (mean_density, mean_dist, half_auto)
}

fn normalized_hamming(a: &[bool], b: &[bool]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    let mut diff = 0usize;
    for i in 0..n {
        if a[i] != b[i] {
            diff += 1;
        }
    }
    diff as f64 / n as f64
}

fn half_correlation(v: &[bool]) -> Option<f64> {
    if v.len() < 4 {
        return None;
    }
    let mid = v.len() / 2;
    bool_correlation(&v[..mid], &v[mid..])
}

fn bool_correlation(a: &[bool], b: &[bool]) -> Option<f64> {
    let n = a.len().min(b.len());
    if n < 2 {
        return None;
    }
    let mut a1 = 0usize;
    let mut b1 = 0usize;
    let mut both = 0usize;
    for i in 0..n {
        if a[i] {
            a1 += 1;
        }
        if b[i] {
            b1 += 1;
        }
        if a[i] && b[i] {
            both += 1;
        }
    }
    let p_a = a1 as f64 / n as f64;
    let p_b = b1 as f64 / n as f64;
    let p_ab = both as f64 / n as f64;
    let denom = (p_a * (1.0 - p_a) * p_b * (1.0 - p_b)).sqrt();
    if denom < 1e-12 {
        return None;
    }
    Some(((p_ab - p_a * p_b) / denom).clamp(-1.0, 1.0))
}

fn rotation_lapse_relink(
    pre_actor: &[Vec<bool>],
    post_actor: &[Vec<bool>],
    lapse_at: usize,
    post_start: usize,
) -> Option<f64> {
    let mut pre = Vec::new();
    let mut post = Vec::new();
    for (pre_shard, post_shard) in pre_actor.iter().zip(post_actor.iter()) {
        if pre_shard.len() <= lapse_at || post_shard.len() <= post_start {
            continue;
        }
        if !pre_shard[..lapse_at].iter().any(|&b| b) {
            continue;
        }
        pre.extend_from_slice(&pre_shard[..lapse_at]);
        post.extend_from_slice(&post_shard[post_start..]);
    }
    let n = pre.len().min(post.len());
    if n < 4 {
        return None;
    }
    Some(1.0 - normalized_hamming(&pre[..n], &post[..n]))
}

fn lapse_relink_similarity(
    actor_bits: &[Vec<bool>],
    lapse_at: usize,
    post_start: usize,
) -> Option<f64> {
    let mut pre = Vec::new();
    let mut post = Vec::new();
    for shard in actor_bits {
        if shard.len() <= lapse_at || post_start >= shard.len() {
            continue;
        }
        if !shard[..lapse_at].iter().any(|&b| b) {
            continue;
        }
        pre.extend_from_slice(&shard[..lapse_at]);
        post.extend_from_slice(&shard[post_start..]);
    }
    let n = pre.len().min(post.len());
    if n < 4 {
        return None;
    }
    Some(1.0 - normalized_hamming(&pre[..n], &post[..n]))
}

fn cosmetic_pattern_overlap(actor_bits: &[Vec<bool>], post_start: usize) -> Option<f64> {
    let flat = actor_flat(actor_bits);
    if post_start >= flat.len() || post_start < 2 {
        return None;
    }
    let pre = &flat[..post_start];
    let post = &flat[post_start..];
    let n = pre.len().min(post.len());
    if n == 0 {
        return None;
    }
    let mut same = 0usize;
    for i in 0..n {
        if pre[i] == post[i] {
            same += 1;
        }
    }
    Some(same as f64 / n as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_bounds() {
        assert!((normalized_hamming(&[true, false], &[false, true]) - 1.0).abs() < 1e-9);
        assert!((normalized_hamming(&[true, true], &[true, true]) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn rotation_harder_than_baseline_when_relink_below_baseline() {
        let baseline = 0.959;
        let lapse = 0.928;
        assert!(lapse <= baseline);
        assert!(baseline - lapse > 0.0);
    }

    #[test]
    fn cohort_singleton_detected() {
        let sizes = vec![vec![1, 3]];
        let bits = vec![vec![vec![true, true], vec![false, false]]];
        let (mean, frac) = aggregate_cohort_stats(&sizes, &bits);
        assert!((mean - 2.0).abs() < 1e-9);
        assert!((frac - 0.5).abs() < 1e-9);
    }
}
