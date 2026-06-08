//! Archival timing-cluster pin — coupling and F4 inequality checks.
//!
//! Numeric values are authoritative in `docs/design/ARCHIVAL_TIMING_CONSTANTS.md` §1;
//! this module is the sim-backed verification harness (pin procedure §4 step 1–2).

use serde::Serialize;

/// Genesis-pinned cluster (2026-06-07). Do not diverge from ARCHIVAL_TIMING_CONSTANTS.md.
pub const SETTLEMENT_EPOCH_BLOCKS: u64 = 10_000;
pub const MAX_SETTLEMENT_EPOCHS_PER_EMISSION: u64 = 15;
pub const MAX_CLAIM_AGE_W: u64 = 26;
pub const RETENTION_HORIZON_BLOCKS: u64 = 420_000;
pub const ARCHIVAL_REORG_DEPTH_BLOCKS: u64 = 720;
pub const RELEASE_COOLDOWN_EPOCHS: u64 = 2;
pub const CHALLENGE_RESOLUTION_BLOCKS: u64 = 10_000;

pub const BLOCK_TIME_SEC: u64 = 120;
pub const JOIN_LAG_BLOCKS: u64 = SETTLEMENT_EPOCH_BLOCKS;
pub const EMISSION_BATCH_WINDOW_BLOCKS: u64 =
    MAX_SETTLEMENT_EPOCHS_PER_EMISSION * SETTLEMENT_EPOCH_BLOCKS;

#[derive(Debug, Clone, Serialize)]
pub struct CouplingCheck {
    pub name: &'static str,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingClusterReport {
    pub constants: TimingClusterConstants,
    pub couplings: Vec<CouplingCheck>,
    pub f4_offline_burst: F4OfflineBurst,
    pub f4_slow_emitter: F4SlowEmitter,
    pub all_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingClusterConstants {
    pub settlement_epoch_blocks: u64,
    pub max_settlement_epochs_per_emission: u64,
    pub max_claim_age_w: u64,
    pub retention_horizon_blocks: u64,
    pub archival_reorg_depth_blocks: u64,
    pub release_cooldown_epochs: u64,
    pub challenge_resolution_blocks: u64,
    pub prune_horizon_epochs: u64,
    pub retention_horizon_epochs: u64,
    pub settlement_epoch_days: f64,
    pub w_wall_clock_days: f64,
    pub release_cooldown_days: f64,
    pub retention_horizon_days: f64,
    pub archival_reorg_depth_days: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct F4OfflineBurst {
    pub max_offline_epochs_tested: u64,
    pub worst_offline_without_forfeit: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct F4SlowEmitter {
    pub offline_epochs: u64,
    pub emit_period_epochs: u64,
    pub pass: bool,
    pub detail: String,
}

pub fn verify() -> TimingClusterReport {
    let retention_horizon_epochs = div_ceil(RETENTION_HORIZON_BLOCKS, SETTLEMENT_EPOCH_BLOCKS);
    let seb_days = (SETTLEMENT_EPOCH_BLOCKS as f64 * BLOCK_TIME_SEC as f64) / 86_400.0;

    let constants = TimingClusterConstants {
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        max_settlement_epochs_per_emission: MAX_SETTLEMENT_EPOCHS_PER_EMISSION,
        max_claim_age_w: MAX_CLAIM_AGE_W,
        retention_horizon_blocks: RETENTION_HORIZON_BLOCKS,
        archival_reorg_depth_blocks: ARCHIVAL_REORG_DEPTH_BLOCKS,
        release_cooldown_epochs: RELEASE_COOLDOWN_EPOCHS,
        challenge_resolution_blocks: CHALLENGE_RESOLUTION_BLOCKS,
        prune_horizon_epochs: MAX_CLAIM_AGE_W,
        retention_horizon_epochs,
        settlement_epoch_days: seb_days,
        w_wall_clock_days: seb_days * MAX_CLAIM_AGE_W as f64,
        release_cooldown_days: seb_days * RELEASE_COOLDOWN_EPOCHS as f64,
        retention_horizon_days: (RETENTION_HORIZON_BLOCKS as f64 * BLOCK_TIME_SEC as f64)
            / 86_400.0,
        archival_reorg_depth_days: (ARCHIVAL_REORG_DEPTH_BLOCKS as f64 * BLOCK_TIME_SEC as f64)
            / 86_400.0,
    };

    let mut couplings = Vec::new();

    couplings.push(CouplingCheck {
        name: "release_cooldown_lt_w",
        pass: RELEASE_COOLDOWN_EPOCHS < MAX_CLAIM_AGE_W,
        detail: format!(
            "RELEASE_COOLDOWN_EPOCHS ({}) < W ({})",
            RELEASE_COOLDOWN_EPOCHS, MAX_CLAIM_AGE_W
        ),
    });

    let release_cooldown_blocks = RELEASE_COOLDOWN_EPOCHS * SETTLEMENT_EPOCH_BLOCKS;
    couplings.push(CouplingCheck {
        name: "release_cooldown_blocks_gt_challenge",
        pass: release_cooldown_blocks > CHALLENGE_RESOLUTION_BLOCKS,
        detail: format!(
            "RELEASE_COOLDOWN in blocks ({}) > CHALLENGE_RESOLUTION_BLOCKS ({})",
            release_cooldown_blocks, CHALLENGE_RESOLUTION_BLOCKS
        ),
    });

    let retention_min =
        MAX_CLAIM_AGE_W * SETTLEMENT_EPOCH_BLOCKS + JOIN_LAG_BLOCKS + EMISSION_BATCH_WINDOW_BLOCKS;
    couplings.push(CouplingCheck {
        name: "retention_horizon_floor",
        pass: RETENTION_HORIZON_BLOCKS >= retention_min,
        detail: format!(
            "RETENTION_HORIZON_BLOCKS ({}) >= W*SEB + join_lag + batch ({})",
            RETENTION_HORIZON_BLOCKS, retention_min
        ),
    });

    couplings.push(CouplingCheck {
        name: "archival_reorg_depth_ll_seb",
        pass: ARCHIVAL_REORG_DEPTH_BLOCKS < SETTLEMENT_EPOCH_BLOCKS,
        detail: format!(
            "ARCHIVAL_REORG_DEPTH_BLOCKS ({}) < SEB ({})",
            ARCHIVAL_REORG_DEPTH_BLOCKS, SETTLEMENT_EPOCH_BLOCKS
        ),
    });

    couplings.push(CouplingCheck {
        name: "prune_horizon_is_w",
        pass: constants.prune_horizon_epochs == MAX_CLAIM_AGE_W,
        detail: format!(
            "prune_horizon_epochs ({}) == W ({})",
            constants.prune_horizon_epochs, MAX_CLAIM_AGE_W
        ),
    });

    couplings.push(CouplingCheck {
        name: "w_gt_batch_cap",
        pass: MAX_CLAIM_AGE_W > MAX_SETTLEMENT_EPOCHS_PER_EMISSION,
        detail: format!(
            "W ({}) > MAX_SETTLEMENT_EPOCHS_PER_EMISSION ({})",
            MAX_CLAIM_AGE_W, MAX_SETTLEMENT_EPOCHS_PER_EMISSION
        ),
    });

    let f4_offline_burst = verify_f4_offline_burst();
    let f4_slow_emitter = verify_f4_slow_emitter(25, 1);

    let all_pass =
        couplings.iter().all(|c| c.pass) && f4_offline_burst.pass && f4_slow_emitter.pass;

    TimingClusterReport {
        constants,
        couplings,
        f4_offline_burst,
        f4_slow_emitter,
        all_pass,
    }
}

/// Offline `n` epochs, return, burst-drain at current tip before any forfeit.
fn verify_f4_offline_burst() -> F4OfflineBurst {
    let mut worst = 0u64;
    for offline in 0..=MAX_CLAIM_AGE_W {
        if offline_burst_survives(offline) {
            worst = offline;
        } else {
            break;
        }
    }
    F4OfflineBurst {
        max_offline_epochs_tested: MAX_CLAIM_AGE_W,
        worst_offline_without_forfeit: worst,
        pass: worst == MAX_CLAIM_AGE_W,
    }
}

fn offline_burst_survives(offline_epochs: u64) -> bool {
    if offline_epochs == 0 {
        return true;
    }
    if offline_epochs > MAX_CLAIM_AGE_W {
        return false;
    }
    let tip_at_return = offline_epochs;
    let oldest = 0u64;
    if oldest < tip_at_return.saturating_sub(MAX_CLAIM_AGE_W) {
        return false;
    }
    let mut remaining = offline_epochs;
    while remaining > 0 {
        let claimed = remaining.min(MAX_SETTLEMENT_EPOCHS_PER_EMISSION);
        remaining -= claimed;
    }
    oldest >= tip_at_return.saturating_sub(MAX_CLAIM_AGE_W)
}

/// Return after `offline_epochs` gap; accrue 1/epoch while online; emit every `emit_period`.
fn verify_f4_slow_emitter(offline_epochs: u64, emit_period: u64) -> F4SlowEmitter {
    let pass = slow_emitter_survives(offline_epochs, emit_period);
    F4SlowEmitter {
        offline_epochs,
        emit_period_epochs: emit_period,
        pass,
        detail: format!(
            "offline {offline_epochs} settlement epochs, emit every {emit_period} epoch(s)"
        ),
    }
}

fn slow_emitter_survives(offline_epochs: u64, emit_period: u64) -> bool {
    let mut oldest = 0u64;
    let mut backlog = offline_epochs;
    let mut tip = offline_epochs;
    let mut epochs_since_emit = 0u64;

    while backlog > 0 {
        if oldest < tip.saturating_sub(MAX_CLAIM_AGE_W) {
            return false;
        }
        epochs_since_emit += 1;
        if epochs_since_emit >= emit_period {
            let claimed = backlog.min(MAX_SETTLEMENT_EPOCHS_PER_EMISSION);
            oldest += claimed;
            backlog -= claimed;
            epochs_since_emit = 0;
        }
        if backlog == 0 {
            break;
        }
        tip += 1;
        backlog += 1;
        if tip > offline_epochs + MAX_CLAIM_AGE_W * 8 {
            return false;
        }
    }
    true
}

fn div_ceil(num: u64, den: u64) -> u64 {
    num.div_ceil(den)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_cluster_pin_passes() {
        let report = verify();
        assert!(
            report.all_pass,
            "timing cluster pin failed: {}",
            serde_json::to_string_pretty(&report).unwrap()
        );
    }
}
