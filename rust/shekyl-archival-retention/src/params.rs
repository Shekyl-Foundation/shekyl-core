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
    SLASH_GRACE_EPOCHS, W2_EPOCH_DIVISOR, W2_MAX_DEFENSIBLE_BLOCKS, W2_MIN_DEFENSIBLE_BLOCKS,
};

include!(concat!(
    env!("OUT_DIR"),
    "/archival_count_rule_generated.rs"
));
use crate::failure_window::{
    ARCHIVAL_FAILURE_WINDOW_M, ARCHIVAL_FAILURE_WINDOW_N, SLASH_SETTLEMENT_TIP_LAG_EPOCHS,
    WINDOW_MIN_OBSERVATION_PER_MILLE,
};
use crate::reward_arithmetic::{WORK_MICRO_PER_MILLI, WORK_MILLI_SCALE};
use crate::SettlementSchedule;
use shekyl_types::archival::SettlementEpochBlocks;

/// The archival consensus parameters. Fields are public so a fold can
/// copy the shipped set and replace one; [`Self::validate`] is the door a
/// replaced set passes before it is used. Deserializing is that door too:
/// a wire form with the same fields converts through it, as
/// `shekyl_economics::EconomicParams` does, so no deserialized set is
/// unchecked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ArchivalParamsWire")]
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
    /// The draw count rule's catch-up point: the share of the epoch, in
    /// thousandths, by which the top-up aims to finish (§4.3; 700 is the
    /// spec's 70 %). `archival_draw_catch_up_permille`.
    pub draw_catch_up_permille: u64,
    /// The floor on the count rule's horizon `H`, in blocks.
    /// `archival_draw_horizon_floor_blocks`.
    pub draw_horizon_floor_blocks: u64,
    /// The count cap as a multiple of `COUNTED_DRAWS · D/SEB`
    /// ([`Self::count_cap_base_multiple`] is the product).
    /// `archival_count_cap_multiple`.
    pub count_cap_multiple: u64,
    /// A bundle section's draw budget as a multiple of the count cap, `c`
    /// (§13.2 V6). `archival_bundle_section_budget_multiple`.
    pub bundle_section_budget_multiple: u64,
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
    /// The catch-up point is outside `(0, 1000]` thousandths of the epoch.
    #[error("draw catch-up {0} permille is outside 1..=1000")]
    CatchUpOutsideEpoch(u64),
    /// The horizon floor is zero, which the count rule refuses, or past the
    /// epoch, which takes `H ≤ SEB` from the target's overflow bound.
    #[error("draw horizon floor {0} blocks is zero or past the epoch")]
    HorizonFloorOutsideEpoch(u64),
    /// The cap multiple is outside `1..=1000`: zero leaves no room above the
    /// base, and past 1000 the cap's product can leave the target's domain.
    #[error("count cap multiple {0} is outside 1..=1000")]
    CapMultipleOutsideBand(u64),
    /// A section multiple of zero budgets no draw and refuses every section.
    #[error("bundle section budget multiple is zero")]
    SectionBudgetZero,
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

/// [`ArchivalParams`]' serde wire: the same fields, converted through
/// [`ArchivalParams::validate`]. The conversion names every field, so the
/// compiler holds the two lists equal.
#[derive(serde::Deserialize)]
#[serde(rename = "ArchivalParams", deny_unknown_fields)]
struct ArchivalParamsWire {
    bond_floor_atomic: u64,
    settlement_epoch_blocks: u64,
    max_claim_age_w: u64,
    reward_age_weight_milli: u64,
    release_cooldown_epochs: u64,
    bond_duration_base_epochs: u64,
    bond_duration_age_scale: u64,
    failure_window_m: u32,
    failure_window_n: u32,
    draw_catch_up_permille: u64,
    draw_horizon_floor_blocks: u64,
    count_cap_multiple: u64,
    bundle_section_budget_multiple: u64,
}

impl TryFrom<ArchivalParamsWire> for ArchivalParams {
    type Error = ArchivalParamsError;

    fn try_from(w: ArchivalParamsWire) -> Result<Self, Self::Error> {
        let params = Self {
            bond_floor_atomic: w.bond_floor_atomic,
            settlement_epoch_blocks: w.settlement_epoch_blocks,
            max_claim_age_w: w.max_claim_age_w,
            reward_age_weight_milli: w.reward_age_weight_milli,
            release_cooldown_epochs: w.release_cooldown_epochs,
            bond_duration_base_epochs: w.bond_duration_base_epochs,
            bond_duration_age_scale: w.bond_duration_age_scale,
            failure_window_m: w.failure_window_m,
            failure_window_n: w.failure_window_n,
            draw_catch_up_permille: w.draw_catch_up_permille,
            draw_horizon_floor_blocks: w.draw_horizon_floor_blocks,
            count_cap_multiple: w.count_cap_multiple,
            bundle_section_budget_multiple: w.bundle_section_budget_multiple,
        };
        match params.validate() {
            Ok(()) => Ok(params),
            Err(e) => Err(e),
        }
    }
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
        draw_catch_up_permille: GENERATED_DRAW_CATCH_UP_PERMILLE,
        draw_horizon_floor_blocks: GENERATED_DRAW_HORIZON_FLOOR_BLOCKS,
        count_cap_multiple: GENERATED_COUNT_CAP_MULTIPLE,
        bundle_section_budget_multiple: GENERATED_BUNDLE_SECTION_BUDGET_MULTIPLE,
    };

    /// The count cap as a multiple of the base rate `D/SEB`:
    /// [`Self::count_cap_multiple`] times
    /// [`COUNTED_DRAWS`](shekyl_types::archival::COUNTED_DRAWS) (9 at the
    /// shipped 3). The one place the product is formed: the target caps at
    /// it, the cap predicate asks whether the top-up passes it, and the
    /// section budget is bounded by it.
    #[must_use]
    // CLIPPY: cast_possible_truncation — `COUNTED_DRAWS` is 3.
    #[allow(clippy::cast_possible_truncation)]
    pub const fn count_cap_base_multiple(&self) -> u64 {
        self.count_cap_multiple
            .saturating_mul(shekyl_types::archival::COUNTED_DRAWS as u64)
    }

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
        if self.draw_catch_up_permille == 0 || self.draw_catch_up_permille > 1000 {
            return Err(ArchivalParamsError::CatchUpOutsideEpoch(
                self.draw_catch_up_permille,
            ));
        }
        if self.draw_horizon_floor_blocks == 0 || self.draw_horizon_floor_blocks > seb {
            return Err(ArchivalParamsError::HorizonFloorOutsideEpoch(
                self.draw_horizon_floor_blocks,
            ));
        }
        if self.count_cap_multiple == 0 || self.count_cap_multiple > 1000 {
            return Err(ArchivalParamsError::CapMultipleOutsideBand(
                self.count_cap_multiple,
            ));
        }
        if self.bundle_section_budget_multiple == 0 {
            return Err(ArchivalParamsError::SectionBudgetZero);
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

    /// The shipped count rule is the spec's §13.2: catch-up by 70 %, a
    /// 200-block floor, a cap of 3 × nominal (9 × base) and `c = 2`.
    #[test]
    fn the_shipped_count_rule_is_the_specs() {
        let p = ArchivalParams::SHIPPED;
        assert_eq!(p.draw_catch_up_permille, 700);
        assert_eq!(p.draw_horizon_floor_blocks, 200);
        assert_eq!(p.count_cap_multiple, 3);
        assert_eq!(p.count_cap_base_multiple(), 9);
        assert_eq!(p.bundle_section_budget_multiple, 2);
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
            with(|p| p.draw_catch_up_permille = 0),
            Err(ArchivalParamsError::CatchUpOutsideEpoch(0))
        );
        assert_eq!(
            with(|p| p.draw_catch_up_permille = 1_001),
            Err(ArchivalParamsError::CatchUpOutsideEpoch(1_001))
        );
        assert_eq!(with(|p| p.draw_catch_up_permille = 1_000), Ok(()));
        assert_eq!(
            with(|p| p.draw_horizon_floor_blocks = 0),
            Err(ArchivalParamsError::HorizonFloorOutsideEpoch(0))
        );
        assert_eq!(
            with(|p| p.draw_horizon_floor_blocks = 10_001),
            Err(ArchivalParamsError::HorizonFloorOutsideEpoch(10_001))
        );
        assert_eq!(
            with(|p| p.count_cap_multiple = 0),
            Err(ArchivalParamsError::CapMultipleOutsideBand(0))
        );
        assert_eq!(
            with(|p| p.count_cap_multiple = 1_001),
            Err(ArchivalParamsError::CapMultipleOutsideBand(1_001))
        );
        assert_eq!(
            with(|p| p.bundle_section_budget_multiple = 0),
            Err(ArchivalParamsError::SectionBudgetZero)
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
    fn the_serde_door_is_validate() {
        let shipped = ArchivalParams::SHIPPED;
        let wire = serde_json::to_value(shipped).expect("serializes");
        assert_eq!(
            serde_json::from_value::<ArchivalParams>(wire.clone()).expect("round-trips"),
            shipped
        );
        let refused = ArchivalParams {
            failure_window_m: 0,
            ..shipped
        };
        let err = serde_json::from_value::<ArchivalParams>(
            serde_json::to_value(refused).expect("serializes"),
        )
        .expect_err("the door refuses what validate refuses");
        assert_eq!(
            err.to_string(),
            ArchivalParamsError::FailureWindowMZero.to_string()
        );
        let mut unknown = wire;
        unknown
            .as_object_mut()
            .expect("an object")
            .insert("anchor_lag_blocks".into(), 4.into());
        assert!(serde_json::from_value::<ArchivalParams>(unknown).is_err());
    }

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

        // The count rule: horizon, cap and section budget read the set.
        use crate::{draw_horizon, draw_target, section_budget};
        let seb = 10_000;
        let w2 = 500;
        assert_eq!(draw_horizon(0, seb, w2, &shipped), 7_000);
        let catch_up = ArchivalParams {
            draw_catch_up_permille: 500,
            ..shipped
        };
        assert_eq!(draw_horizon(0, seb, w2, &catch_up), 5_000);
        assert_eq!(draw_horizon(6_950, seb, w2, &shipped), 200);
        let floor = ArchivalParams {
            draw_horizon_floor_blocks: 300,
            ..shipped
        };
        assert_eq!(draw_horizon(6_950, seb, w2, &floor), 300);
        // A shortfall far past the cap: the target is the cap, and it moves
        // with the multiple.
        let capped = draw_target(1_000, u64::MAX / 2, 1_000, seb, &shipped).expect("fits");
        let wider = ArchivalParams {
            count_cap_multiple: 4,
            ..shipped
        };
        let capped_wider = draw_target(1_000, u64::MAX / 2, 1_000, seb, &wider).expect("fits");
        assert!(capped.capped && capped_wider.capped);
        // `t = (min(·, k·D·H) << 32) / (SEB·H)`, floored, at k = 9 and 12.
        let at = |k: u128| ((k * 1_000 * 1_000) << 32) / (10_000 * 1_000);
        assert_eq!(capped.fixed, at(9));
        assert_eq!(capped_wider.fixed, at(12));
        let blocks = SettlementEpochBlocks::new(seb).expect("non-zero");
        let doubled = ArchivalParams {
            bundle_section_budget_multiple: 4,
            ..shipped
        };
        assert_eq!(
            section_budget(&doubled, 10_000, blocks).get(),
            2 * section_budget(&shipped, 10_000, blocks).get()
        );
    }
}
