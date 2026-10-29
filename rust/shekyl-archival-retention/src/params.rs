// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival consensus parameters as one value (ESR-16 completion,
//! `ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.26, ruled 2026-10-29).
//!
//! [`ArchivalParams`] is generated from `config/consensus_constants.json`,
//! whose keys the consensus digest covers. Production reads only the
//! shipped set, through [`archival_params`]; a node on another set forks
//! itself off, so there is no CLI flag, configuration key or RPC for it
//! (rules 71 and 83). The economics sim builds other sets and calls the
//! same functions with them; [`ArchivalParams::validate`] is the door, so a
//! sweep cannot build a set the shipped build would refuse.
//!
//! The one sanctioned second door into the epoch length is the fakechain
//! schedule lever (`constants::arm_settlement_epoch_override`), whose
//! unarmed value is this set's.
//!
//! Kept out, with their class in §5.26: the reorg depth, the shard length
//! and the holdings cap are structural constants read below this crate;
//! the attestation anchor lag sizes the anchor window's tables and is tied
//! to the reorg depth at compile time; the retention horizon has no
//! production reader.

use crate::bond_floor::{
    ARCHIVAL_BOND_FLOOR_ATOMIC, ARCHIVAL_REORG_DEPTH_BLOCKS, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
    BOND_DURATION_AGE_SCALE, BOND_DURATION_BASE_EPOCHS, MAX_CLAIM_AGE_W, RELEASE_COOLDOWN_EPOCHS,
    SETTLEMENT_EPOCH_BLOCKS,
};
use crate::constants::{
    CHALLENGES_PER_PAIR_PER_EPOCH, SLASH_GRACE_EPOCHS, W2_EPOCH_DIVISOR, W2_MAX_DEFENSIBLE_BLOCKS,
    W2_MIN_DEFENSIBLE_BLOCKS,
};
use crate::failure_window::{
    ARCHIVAL_FAILURE_WINDOW_M, ARCHIVAL_FAILURE_WINDOW_N, SLASH_SETTLEMENT_TIP_LAG_EPOCHS,
    WINDOW_MIN_OBSERVATION_PER_MILLE,
};
use crate::reward_arithmetic::{WORK_MICRO_PER_MILLI, WORK_MILLI_SCALE};
use crate::SettlementSchedule;
use shekyl_types::archival::SettlementEpochBlocks;

/// The archival consensus parameters. Fields are public so a fold can
/// copy the shipped set and replace one; [`Self::validate`] is the door a
/// replaced set passes before it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArchivalParams {
    /// One bond rung, atomic units (gate-4 §3.2): the per-shard bond floor,
    /// the whole floor of a `CompleteTree` holding, and the cover draw's
    /// exclusive bound. `archival_bond_floor_atomic`.
    pub bond_floor_atomic: u64,
    /// Blocks per settlement epoch. `settlement_epoch_blocks`.
    pub settlement_epoch_blocks: u64,
    /// The claim window `W`, in settlement epochs: an emission may claim an
    /// epoch at most `W` behind the settled one, and the per-epoch tables a
    /// claim reads are kept that long. `max_claim_age_w`.
    pub max_claim_age_w: u64,
    /// The age weight `g` of credited work, thousandths
    /// (`ARCHIVAL_REWARD_ARITHMETIC.md`). `archival_reward_age_weight_milli`.
    pub reward_age_weight_milli: u64,
    /// Settlement epochs a released shard waits before it may be re-bonded.
    /// `release_cooldown_epochs`.
    pub release_cooldown_epochs: u64,
    /// The bond duration's base, in epochs. `bond_duration_base_epochs`.
    pub bond_duration_base_epochs: u64,
    /// The bond duration's age scale. `bond_duration_age_scale`.
    pub bond_duration_age_scale: u64,
    /// The failure window's `m`: misses that slash. `archival_failure_window_m`.
    pub failure_window_m: u32,
    /// The failure window's `n`: observations it counts over.
    /// `archival_failure_window_n`.
    pub failure_window_n: u32,
    /// Challenges per `(P, shard)` pair per settlement epoch.
    /// `archival_challenges_per_pair_per_epoch`.
    pub challenges_per_pair_per_epoch: u32,
}

/// A set of archival parameters the chain cannot run, naming the coupling
/// it breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArchivalParamsError {
    /// The epoch is no longer than the reorg depth: the retention prune's
    /// undo floor would cross the body horizon (`reorg.rs`, SPR-9).
    #[error("settlement epoch {epoch} blocks is not longer than the reorg depth {reorg}")]
    EpochNotPastReorg {
        /// The set's epoch length.
        epoch: u64,
        /// The reorg depth, a structural constant.
        reorg: u64,
    },
    /// The epoch does not divide into the W₂ fraction, so the response
    /// window would truncate.
    #[error("settlement epoch {0} blocks is not a multiple of the W2 divisor")]
    EpochOffW2Divisor(u64),
    /// W₂ falls outside the band the W₂ ruling was made over.
    #[error("the challenge-response window {0} blocks is outside the ruled W2 band")]
    W2OutsideBand(u64),
    /// The slash grace is shorter than W₂: the fold would run before the
    /// response window of the epoch's last challenge closes.
    #[error("the slash grace is shorter than the challenge-response window")]
    GraceShorterThanW2,
    /// The claim window is shorter than the slash grace: the pass would
    /// write rows the window has already retired.
    #[error("claim window {0} epochs is shorter than the slash grace")]
    ClaimWindowShorterThanGrace(u64),
    /// `m = 0` slashes a persona that never missed.
    #[error("failure window m is zero")]
    FailureWindowMZero,
    /// `n < m` makes the threshold unreachable: a silently disabled slash.
    #[error("failure window n {n} is below m {m}")]
    FailureWindowNBelowM {
        /// The set's `n`.
        n: u32,
        /// The set's `m`.
        m: u32,
    },
    /// The failure window reaches past what the C++ gather can read, or
    /// past what the retention leaves at the minimum observation rate.
    #[error("failure window n {0} reaches past the retained epochs")]
    FailureWindowPastRetention(u32),
    /// No challenge per pair: settlement would count nothing.
    #[error("challenges per pair is zero")]
    NoChallenges,
    /// The release cooldown does not outlast the slash grace, so a release
    /// could outrun its last epoch's slash (`ARCHIVAL_TIMING_CONSTANTS.md`
    /// §2.2, the L16 pin).
    #[error("release cooldown {0} epochs does not exceed the slash grace")]
    CooldownNotPastGrace(u64),
    /// The age weight lets a shard's scarcity exceed the `u32` wire field
    /// it is carried in (`WORK_MICRO_PER_MILLI · (WORK_MILLI_SCALE + g)`).
    #[error("reward age weight {0} lets scarcity exceed its u32 wire field")]
    AgeWeightPastWireField(u64),
    /// A bond floor below 2 has no cover strictly inside one rung.
    #[error("bond floor {0} is below 2 atomic units")]
    BondFloorBelowTwo(u64),
}

impl ArchivalParams {
    /// The shipped set, generated from `config/consensus_constants.json`.
    /// Production reads it through [`archival_params`].
    pub const SHIPPED: Self = Self {
        bond_floor_atomic: ARCHIVAL_BOND_FLOOR_ATOMIC,
        settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
        max_claim_age_w: MAX_CLAIM_AGE_W,
        reward_age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
        release_cooldown_epochs: RELEASE_COOLDOWN_EPOCHS,
        bond_duration_base_epochs: BOND_DURATION_BASE_EPOCHS,
        bond_duration_age_scale: BOND_DURATION_AGE_SCALE,
        failure_window_m: ARCHIVAL_FAILURE_WINDOW_M,
        failure_window_n: ARCHIVAL_FAILURE_WINDOW_N,
        challenges_per_pair_per_epoch: CHALLENGES_PER_PAIR_PER_EPOCH,
    };

    /// Refuse a set the chain cannot run. Every check is a coupling the
    /// shipped build asserts at compile time, so a sweep is held to what
    /// production is.
    ///
    /// The W₂ band confines the epoch length: at the divisor of 20 and the
    /// band `[200, 500]`, an epoch is 4 000 to 10 000 blocks. A sweep past
    /// that is a re-run of the W₂ ruling, not a parameter change.
    ///
    /// # Errors
    ///
    /// [`ArchivalParamsError`] naming the first coupling broken.
    pub const fn validate(&self) -> Result<(), ArchivalParamsError> {
        let seb = self.settlement_epoch_blocks;
        if seb <= ARCHIVAL_REORG_DEPTH_BLOCKS {
            return Err(ArchivalParamsError::EpochNotPastReorg {
                epoch: seb,
                reorg: ARCHIVAL_REORG_DEPTH_BLOCKS,
            });
        }
        if !seb.is_multiple_of(W2_EPOCH_DIVISOR) {
            return Err(ArchivalParamsError::EpochOffW2Divisor(seb));
        }
        let w2 = seb / W2_EPOCH_DIVISOR;
        if w2 < W2_MIN_DEFENSIBLE_BLOCKS || w2 > W2_MAX_DEFENSIBLE_BLOCKS {
            return Err(ArchivalParamsError::W2OutsideBand(w2));
        }
        if SLASH_GRACE_EPOCHS.saturating_mul(seb) < w2 {
            return Err(ArchivalParamsError::GraceShorterThanW2);
        }
        let w = self.max_claim_age_w;
        if w < SLASH_GRACE_EPOCHS {
            return Err(ArchivalParamsError::ClaimWindowShorterThanGrace(w));
        }
        let (m, n) = (self.failure_window_m, self.failure_window_n);
        if m == 0 {
            return Err(ArchivalParamsError::FailureWindowMZero);
        }
        if n < m {
            return Err(ArchivalParamsError::FailureWindowNBelowM { n, m });
        }
        // The C++ gather reads `W + 1 − LAG` epochs below an on-time slash;
        // the Rust walk reads `W + 2 − LAG`, and at the minimum observation
        // rate that span must still hold `n` observations.
        let n_wide = n as u64;
        let gather = match (w + 1).checked_sub(SLASH_SETTLEMENT_TIP_LAG_EPOCHS) {
            Some(bound) => bound,
            None => 0,
        };
        let readable = (w + 2).saturating_sub(SLASH_SETTLEMENT_TIP_LAG_EPOCHS);
        if n_wide > gather
            || WINDOW_MIN_OBSERVATION_PER_MILLE.saturating_mul(readable)
                < 1000u64.saturating_mul(n_wide)
        {
            return Err(ArchivalParamsError::FailureWindowPastRetention(n));
        }
        if self.challenges_per_pair_per_epoch == 0 {
            return Err(ArchivalParamsError::NoChallenges);
        }
        if self.release_cooldown_epochs <= SLASH_GRACE_EPOCHS {
            return Err(ArchivalParamsError::CooldownNotPastGrace(
                self.release_cooldown_epochs,
            ));
        }
        // Evaluated in `u128`: the product of two `u64` operands cannot
        // overflow it, so the refusal names the weight for any value.
        let g = self.reward_age_weight_milli;
        if (WORK_MICRO_PER_MILLI as u128) * ((WORK_MILLI_SCALE as u128) + (g as u128))
            > u32::MAX as u128
        {
            return Err(ArchivalParamsError::AgeWeightPastWireField(g));
        }
        if self.bond_floor_atomic < 2 {
            return Err(ArchivalParamsError::BondFloorBelowTwo(
                self.bond_floor_atomic,
            ));
        }
        Ok(())
    }

    /// The settlement calendar this set's epoch length names. The
    /// validator reads the rule set's schedule instead, which a fakechain
    /// lever may shorten.
    ///
    /// # Panics
    ///
    /// On a zero epoch, which [`Self::validate`] refuses.
    #[must_use]
    pub const fn schedule(&self) -> SettlementSchedule {
        match SettlementEpochBlocks::new(self.settlement_epoch_blocks) {
            Some(blocks) => SettlementSchedule::new(blocks),
            None => panic!("a settlement epoch of zero blocks; validate refuses it"),
        }
    }

    /// Challenge-response budget the failure window leaves a pair: `n − m`
    /// epochs it may miss without being slashed.
    #[must_use]
    pub const fn failure_window_serve_budget(&self) -> u32 {
        self.failure_window_n.saturating_sub(self.failure_window_m)
    }
}

impl Default for ArchivalParams {
    fn default() -> Self {
        Self::SHIPPED
    }
}

/// The shipped [`ArchivalParams`]: the one production read.
#[must_use]
pub const fn archival_params() -> &'static ArchivalParams {
    &ArchivalParams::SHIPPED
}

const _: () = assert!(
    ArchivalParams::SHIPPED.validate().is_ok(),
    "config/consensus_constants.json's archival set fails ArchivalParams::validate"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_set_is_valid_and_is_the_accessor() {
        assert_eq!(ArchivalParams::SHIPPED.validate(), Ok(()));
        assert_eq!(archival_params(), &ArchivalParams::SHIPPED);
        assert_eq!(ArchivalParams::default(), ArchivalParams::SHIPPED);
    }

    /// The gate-4 pin (G4-7), a test on the generated default where a
    /// `const` assert stood.
    #[test]
    fn the_shipped_bond_floor_is_the_gate4_pin() {
        assert_eq!(ArchivalParams::SHIPPED.bond_floor_atomic, 750_000_000);
    }

    /// The Round-1 provisional failure window (ARCHIVAL_FAILURE_CONFIRMATION_PIN.md
    /// §1). A re-pin is the Round-2 stressnet's decision.
    #[test]
    fn the_shipped_failure_window_is_the_round1_pin() {
        let p = ArchivalParams::SHIPPED;
        assert_eq!((p.failure_window_m, p.failure_window_n), (11, 13));
        assert_eq!(p.failure_window_serve_budget(), 2);
    }

    /// The challenge count and the draws settlement counts are one
    /// decision: the settlement row is `COUNTED_DRAWS` wide.
    #[test]
    fn the_shipped_challenge_count_is_the_counted_draws() {
        assert_eq!(
            ArchivalParams::SHIPPED.challenges_per_pair_per_epoch as usize,
            shekyl_types::archival::COUNTED_DRAWS
        );
    }

    /// `shekyl-types` holds the claim window and its at-rest bound as
    /// decode bounds on stored bytes; the shipped window is theirs.
    #[test]
    fn the_shipped_claim_window_is_the_decode_bound() {
        let w = ArchivalParams::SHIPPED.max_claim_age_w;
        assert_eq!(w, shekyl_types::archival::MAX_CLAIM_AGE_W_EPOCHS);
        assert_eq!(
            w + 6,
            shekyl_types::archival::MAX_CLAIMED_EPOCH_ENTRIES as u64
        );
    }

    /// E16-13: every coupling the shipped build asserts refuses a set that
    /// breaks it.
    #[test]
    fn validate_refuses_each_broken_coupling() {
        let with = |f: fn(&mut ArchivalParams)| {
            let mut p = ArchivalParams::SHIPPED;
            f(&mut p);
            p.validate()
        };
        assert!(matches!(
            with(|p| p.settlement_epoch_blocks = ARCHIVAL_REORG_DEPTH_BLOCKS),
            Err(ArchivalParamsError::EpochNotPastReorg { .. })
        ));
        assert_eq!(
            with(|p| p.settlement_epoch_blocks = 9_990),
            Err(ArchivalParamsError::EpochOffW2Divisor(9_990))
        );
        assert_eq!(
            with(|p| p.settlement_epoch_blocks = 20_000),
            Err(ArchivalParamsError::W2OutsideBand(1_000))
        );
        assert_eq!(
            with(|p| p.max_claim_age_w = 0),
            Err(ArchivalParamsError::ClaimWindowShorterThanGrace(0))
        );
        assert_eq!(
            with(|p| p.failure_window_m = 0),
            Err(ArchivalParamsError::FailureWindowMZero)
        );
        assert_eq!(
            with(|p| p.failure_window_n = 10),
            Err(ArchivalParamsError::FailureWindowNBelowM { n: 10, m: 11 })
        );
        assert_eq!(
            with(|p| p.failure_window_n = 26),
            Err(ArchivalParamsError::FailureWindowPastRetention(26))
        );
        assert_eq!(
            with(|p| p.challenges_per_pair_per_epoch = 0),
            Err(ArchivalParamsError::NoChallenges)
        );
        assert_eq!(
            with(|p| p.release_cooldown_epochs = SLASH_GRACE_EPOCHS),
            Err(ArchivalParamsError::CooldownNotPastGrace(
                SLASH_GRACE_EPOCHS
            ))
        );
        const PAST_WIRE: u64 = u32::MAX as u64 / WORK_MICRO_PER_MILLI - WORK_MILLI_SCALE + 1;
        assert_eq!(
            with(|p| p.reward_age_weight_milli = PAST_WIRE),
            Err(ArchivalParamsError::AgeWeightPastWireField(PAST_WIRE))
        );
        assert_eq!(
            with(|p| p.bond_floor_atomic = 1),
            Err(ArchivalParamsError::BondFloorBelowTwo(1))
        );
        // The band's edges are inside it.
        assert_eq!(with(|p| p.settlement_epoch_blocks = 4_000), Ok(()));
        assert_eq!(with(|p| p.settlement_epoch_blocks = 10_000), Ok(()));
    }

    /// E16-7: the schedule reads the set's epoch length.
    #[test]
    fn the_schedule_reads_the_sets_epoch() {
        let p = ArchivalParams {
            settlement_epoch_blocks: 8_000,
            ..ArchivalParams::SHIPPED
        };
        assert_eq!(p.schedule().blocks().get(), 8_000);
        assert_eq!(p.schedule().epoch_at_height(16_000), 2);
        assert_eq!(
            ArchivalParams::SHIPPED.schedule(),
            SettlementSchedule::GENESIS
        );
    }

    /// E16-7: each promoted field is read by the function that uses it. A
    /// reader that still took the constant would not move here.
    #[test]
    fn each_field_moves_its_reader() {
        use crate::bond_floor::bond_floor_of;
        use crate::bond_wire::HoldingsKind;
        use crate::{
            bond_duration, claim_window_floor, failure_window_slashable, join_scarcity_micro,
            release_cooldown_elapsed, BaselineObservation, ShardAgeAtAdd,
        };
        let shipped = ArchivalParams::SHIPPED;

        let floor = ArchivalParams {
            bond_floor_atomic: 1_000_000_000,
            ..shipped
        };
        assert_eq!(
            bond_floor_of(HoldingsKind::ShardSetCompact, 3, &shipped),
            2_250_000_000
        );
        assert_eq!(
            bond_floor_of(HoldingsKind::ShardSetCompact, 3, &floor),
            3_000_000_000
        );

        let window = ArchivalParams {
            max_claim_age_w: 30,
            ..shipped
        };
        assert_eq!(claim_window_floor(100, &shipped), 74);
        assert_eq!(claim_window_floor(100, &window), 70);

        let cooldown = ArchivalParams {
            release_cooldown_epochs: 3,
            ..shipped
        };
        assert!(release_cooldown_elapsed(Some(10), 12, &shipped));
        assert!(!release_cooldown_elapsed(Some(10), 12, &cooldown));

        // The oldest age: a freeze at or past the add epoch's close.
        let oldest = ShardAgeAtAdd::from_add(0, u64::MAX);
        let base = ArchivalParams {
            bond_duration_base_epochs: 5,
            ..shipped
        };
        let scale = ArchivalParams {
            bond_duration_age_scale: 6,
            ..shipped
        };
        assert_eq!(bond_duration(oldest, &shipped), 20);
        assert_eq!(bond_duration(oldest, &base), 25);
        assert_eq!(bond_duration(oldest, &scale), 28);

        let weight = ArchivalParams {
            reward_age_weight_milli: 3_000,
            ..shipped
        };
        assert!(join_scarcity_micro(4, 1_000, &weight) > join_scarcity_micro(4, 1_000, &shipped));

        // Eleven misses in thirteen: a slash at m = 11, not at m = 12.
        let mut obs: Vec<BaselineObservation> = (0..11)
            .rev()
            .map(|e| BaselineObservation::missed(e + 2))
            .collect();
        obs.push(BaselineObservation::served(1));
        obs.push(BaselineObservation::served(0));
        let strict = ArchivalParams {
            failure_window_m: 12,
            ..shipped
        };
        assert_eq!(failure_window_slashable(&obs, &shipped), Ok(true));
        assert_eq!(failure_window_slashable(&obs, &strict), Ok(false));
        let narrow = ArchivalParams {
            failure_window_n: 12,
            ..shipped
        };
        assert!(failure_window_slashable(&obs, &narrow).is_err());
    }
}
