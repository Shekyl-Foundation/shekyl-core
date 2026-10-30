//! Archival timing-cluster pin — coupling and F4 inequality checks.
//!
//! Numeric values are authoritative in `docs/design/ARCHIVAL_TIMING_CONSTANTS.md` §1;
//! this module is the sim-backed verification harness (pin procedure §4 step 1–2).

use serde::Serialize;

// Genesis-pinned cluster (2026-06-07), read from the canonical crate rather
// than mirrored: a local copy under a "do not diverge" comment has no gate —
// a crate re-pin would leave this harness silently verifying stale values.
// Importing means the coupling checks below run against the LIVE cluster, so
// a re-pin that breaks an inequality fails this sim's test.
//
// Every timing value here is generated from `config/consensus_constants.json`:
// W, the settlement epoch, the release cooldown and the emission batch cap by
// `shekyl-archival-retention`'s build script, the reorg depth by
// `shekyl-types`' (re-exported by archival-retention). The slash grace is
// `SLASH_GRACE_EPOCHS`, a multiple of the epoch with no JSON key: it has no
// value of its own to source (DRS-E4 commit 5). The deepest retention is not a
// constant: the store retires each per-epoch table at its last reader's reach,
// and [`deepest_retention_epochs`] asks the validator's `EpochFloor` for it.
pub use shekyl_archival_retention::{
    ARCHIVAL_REORG_DEPTH_BLOCKS, MAX_CLAIM_AGE_W, RELEASE_COOLDOWN_EPOCHS, SETTLEMENT_EPOCH_BLOCKS,
    SLASH_GRACE_EPOCHS,
};

/// Epochs the store keeps below a settlement boundary for its deepest
/// family, the claimable tables: the claim window `W` plus the one epoch of
/// slack the boundary batch keeps (it retires below the floor of the
/// boundary's previous epoch). Read from chain-rules'
/// `EpochFloor::<Claimable>::at_boundary` on the genesis schedule, at a
/// boundary past the window, so the sim reports the reach the chain keeps
/// rather than a horizon of its own (`SO-D12h`; the retired
/// `retention_horizon_blocks`, ruled deleted 2026-10-30).
#[must_use]
pub fn deepest_retention_epochs() -> u64 {
    use shekyl_chain_rules::{Claimable, EpochFloor};
    let schedule = shekyl_archival_retention::SettlementSchedule::GENESIS;
    let boundary_epoch = MAX_CLAIM_AGE_W + 10;
    let boundary = shekyl_types::BlockHeight::from_raw(boundary_epoch * SETTLEMENT_EPOCH_BLOCKS);
    let kept_from = EpochFloor::<Claimable>::at_boundary(boundary, schedule)
        .kept_from()
        .expect("a boundary past the claim window retires something")
        .to_raw();
    boundary_epoch - kept_from
}

/// Canonical owner is `emission_wire`'s `usize` bound; this cluster does
/// block arithmetic in `u64` (usize → u64 is lossless on every supported
/// target).
pub const MAX_SETTLEMENT_EPOCHS_PER_EMISSION: u64 =
    shekyl_archival_retention::MAX_SETTLEMENT_EPOCHS_PER_EMISSION as u64;

pub const BLOCK_TIME_SEC: u64 = 120;

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
    pub deepest_retention_blocks: u64,
    pub archival_reorg_depth_blocks: u64,
    pub release_cooldown_epochs: u64,
    pub slash_grace_epochs: u64,
    pub prune_horizon_epochs: u64,
    pub deepest_retention_epochs: u64,
    pub settlement_epoch_days: f64,
    pub w_wall_clock_days: f64,
    pub release_cooldown_days: f64,
    pub deepest_retention_days: f64,
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
    let deepest_retention_epochs = deepest_retention_epochs();
    let deepest_retention_blocks = deepest_retention_epochs * SETTLEMENT_EPOCH_BLOCKS;
    let seb_days = (SETTLEMENT_EPOCH_BLOCKS as f64 * BLOCK_TIME_SEC as f64) / 86_400.0;

    let constants = TimingClusterConstants {
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        max_settlement_epochs_per_emission: MAX_SETTLEMENT_EPOCHS_PER_EMISSION,
        max_claim_age_w: MAX_CLAIM_AGE_W,
        deepest_retention_blocks,
        archival_reorg_depth_blocks: ARCHIVAL_REORG_DEPTH_BLOCKS,
        release_cooldown_epochs: RELEASE_COOLDOWN_EPOCHS,
        slash_grace_epochs: SLASH_GRACE_EPOCHS,
        prune_horizon_epochs: MAX_CLAIM_AGE_W,
        deepest_retention_epochs,
        settlement_epoch_days: seb_days,
        w_wall_clock_days: seb_days * MAX_CLAIM_AGE_W as f64,
        release_cooldown_days: seb_days * RELEASE_COOLDOWN_EPOCHS as f64,
        deepest_retention_days: (deepest_retention_blocks as f64 * BLOCK_TIME_SEC as f64)
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

    // L16: both sides in epochs since DRS-E4 commit 5, so the inequality is
    // the same on every schedule rather than one the regtest lever could
    // invert.
    couplings.push(CouplingCheck {
        name: "release_cooldown_epochs_gt_slash_grace",
        pass: RELEASE_COOLDOWN_EPOCHS > SLASH_GRACE_EPOCHS,
        detail: format!(
            "RELEASE_COOLDOWN_EPOCHS ({}) > SLASH_GRACE_EPOCHS ({})",
            RELEASE_COOLDOWN_EPOCHS, SLASH_GRACE_EPOCHS
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The store keeps the claim window and one epoch of slack below a
    /// boundary: 27 epochs, 270 000 blocks, at the shipped `W` of 26. A
    /// change to the claimable family's reach in chain-rules moves this.
    #[test]
    fn the_deepest_retention_is_the_claim_window_and_one_epoch() {
        assert_eq!(deepest_retention_epochs(), MAX_CLAIM_AGE_W + 1);
        assert_eq!(deepest_retention_epochs(), 27);
        let report = verify();
        assert_eq!(report.constants.deepest_retention_blocks, 270_000);
    }

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
