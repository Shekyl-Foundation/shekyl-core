//! T-A1 — F1 retention-timeline fingerprint instrument (PHASE_2B §7.7).
//!
//! Models public per-`(P, shard, settlement_epoch)` retention bits at pinned
//! `SETTLEMENT_EPOCH_BLOCKS` (default 10_000). Quantifies within-shard epoch-timeline
//! distinguishability and hygiene buy-down (lapse / cosmetic-rotation failure mode).
//! Spec: `docs/design/STAKER_ARCHIVAL_SIM.md` §*T-A1*; gate: `PHASE_2B_STAKE_LIFECYCLE.md` §7.7.

use crate::model::World;
use serde::Serialize;

/// Pinned genesis SEB per [`ARCHIVAL_TIMING_CONSTANTS.md`](../../docs/design/ARCHIVAL_TIMING_CONSTANTS.md).
pub const SEB_DEFAULT: u64 = 10_000;
/// Default block time for calendar reporting (seconds).
pub const BLOCK_TIME_SEC: u64 = 120;

/// Minimum completed settlement epochs for an adequate T-A1 sample.
pub const MIN_SETTLEMENT_EPOCHS: usize = 20;
/// Independent `P` timelines should be distinguishable (normalized Hamming distance).
pub const MIN_PAIRWISE_DISTANCE: f64 = 0.10;
/// After lapse, re-entry timeline should not strongly match pre-lapse (hygiene residual).
pub const MAX_LAPSE_RELINK: f64 = 0.55;
/// Cosmetic rotation (same pattern, new id) should re-link strongly — documents E-4 failure.
pub const MIN_COSMETIC_OVERLAP: f64 = 0.70;

#[derive(Debug, Clone, Serialize)]
pub struct Ta1Claims {
    pub sample_adequate: bool,
    pub independent_distinguishable: bool,
    pub lapse_decorrelates: bool,
    pub cosmetic_relinks: bool,
    pub f1_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ta1Metrics {
    pub settlement_epochs: usize,
    pub settlement_epoch_days: f64,
    pub mean_bit_density: f64,
    /// Mean normalized Hamming distance between actor pair timelines (within-shard aggregate).
    pub mean_pairwise_distance: f64,
    /// Pearson correlation between pre-lapse and post-lapse timeline (same actor). `None` if no lapse.
    pub lapse_relink_correlation: Option<f64>,
    /// Correlation between first and second half of run (stability / fingerprint persistence).
    pub half_run_autocorrelation: f64,
    /// Post-lapse overlap with pre-lapse when cosmetic relink is simulated.
    pub cosmetic_overlap: Option<f64>,
    pub claims: Ta1Claims,
}

/// Per-actor retention-bit timelines: `bits[actor][shard] = one bool per completed settlement epoch`.
pub struct Ta1Recorder {
    settlement_epoch_blocks: u64,
    blocks_per_sim_epoch: u64,
    cumulative_blocks: u64,
    closed_settlements: usize,
    bits: Vec<Vec<Vec<bool>>>,
    deep_threshold: f64,
    lapse_actor: Option<usize>,
    lapse_at_settlement: u32,
    lapse_span_settlement: u32,
    cosmetic_relink: bool,
    rotation_actor: Option<usize>,
    pre_lapse_bits: Option<Vec<Vec<bool>>>,
    lapse_started: bool,
    lapse_ended: bool,
    post_lapse_start_epoch: usize,
}

impl Ta1Recorder {
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
    ) -> Self {
        Self {
            settlement_epoch_blocks,
            blocks_per_sim_epoch,
            cumulative_blocks: 0,
            closed_settlements: 0,
            bits: vec![vec![Vec::new(); n_shards]; n_actors],
            deep_threshold,
            lapse_actor,
            lapse_at_settlement,
            lapse_span_settlement,
            cosmetic_relink,
            rotation_actor,
            pre_lapse_bits: None,
            lapse_started: false,
            lapse_ended: false,
            post_lapse_start_epoch: 0,
        }
    }

    /// Advance simulated chain height; close settlement epoch(s) when boundaries cross.
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
        self.closed_settlements += 1;
    }

    /// Force-drop all deep holdings for lapse simulation (E-4 / `W` hygiene).
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

    /// Cosmetic rotation failure mode: restore pre-lapse deep holdings (same pattern, new session).
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
        for s in 0..world.shards.len().min(pre.len()) {
            if world.shards[s].is_deep(self.deep_threshold)
                && pre[s].last().copied().unwrap_or(false)
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
        let lapse_relink = match (self.lapse_actor, self.rotation_actor) {
            (Some(pre), Some(post)) if !self.cosmetic_relink => rotation_lapse_relink(
                &self.bits[pre],
                &self.bits[post],
                self.lapse_at_settlement as usize,
                self.post_lapse_start_epoch,
            ),
            (Some(a), _) => lapse_relink_correlation(
                &self.bits[a],
                self.lapse_at_settlement as usize,
                self.post_lapse_start_epoch,
            ),
            _ => None,
        };

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
        let independent_distinguishable = mean_dist >= MIN_PAIRWISE_DISTANCE;
        let lapse_decorrelates = lapse_relink.is_none_or(|r| r <= MAX_LAPSE_RELINK);
        let cosmetic_relinks = cosmetic_overlap.is_none_or(|o| o >= MIN_COSMETIC_OVERLAP);
        let f1_pass = sample_adequate && independent_distinguishable && lapse_decorrelates;

        Ta1Metrics {
            settlement_epochs: n_ep,
            settlement_epoch_days: seb_days,
            mean_bit_density: mean_density,
            mean_pairwise_distance: mean_dist,
            lapse_relink_correlation: lapse_relink,
            half_run_autocorrelation: half_auto,
            cosmetic_overlap,
            claims: Ta1Claims {
                sample_adequate,
                independent_distinguishable,
                lapse_decorrelates,
                cosmetic_relinks,
                f1_pass,
            },
        }
    }
}

/// Flatten per-shard timelines into one bit vector per actor (concatenate shards).
fn actor_flat(bits: &[Vec<bool>]) -> Vec<bool> {
    let mut out = Vec::new();
    for shard_bits in bits {
        out.extend_from_slice(shard_bits);
    }
    out
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

    // F1 axis is per-`(P, shard, E)`: compare independent `P` on the *same* shard only.
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

/// Pre-lapse `P` vs post-rotation `P'` on shards the pre-lapse actor served.
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

/// Pre-lapse vs post-reentry similarity (1 − Hamming) on shards the actor served pre-lapse.
fn lapse_relink_correlation(
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
    fn lapse_relink_detects_shift() {
        let pre = vec![true, true, false, false];
        let post = vec![false, false, true, true];
        let c = bool_correlation(&pre, &post).unwrap();
        assert!(c < 0.5);
    }
}
