// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-4 — [`PFundingInflow`]: the per-epoch `P` funding-inflow signal `C_min`
//! sizing consumes.
//!
//! The other half of the Design-B crash-recovery decision (paired with SP-2's
//! [`PScanCursor`](../../../../shekyl_engine_state); see
//! `docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6 SP-4). It is **idempotent**:
//! recomputed once from an epoch's *complete* confirmed-output set, a pure fold,
//! so a post-crash re-scan recomputes the **same** value rather than
//! double-counting — which is exactly what lets SP-2's cursor resume-and-rescan
//! without a second durable results frontier.
//!
//! ## Two enforcement points
//!
//! 1. **Confirmed-only, by the input type.** `recompute_for_epoch` consumes
//!    [`RecoveredWalletOutput`]s — and a `RecoveredWalletOutput` is materialized
//!    *only* by the scanner's full ownership-recovery path, **never** by an FA-6
//!    pre-filter hit (DQ7). So an inflow can never be summed from pre-filter
//!    hits: the type makes it unrepresentable, not a convention.
//! 2. **Output-only across the seam.** `PFundingInflow` is built here and flows
//!    *out* toward `C_min` sizing; it is never an inbound message field, so no
//!    caller can hand-build one and inject an unconfirmed inflow into sizing.
//!
//! ## Money and epoch are typed, not raw
//!
//! [`AtomicUnits`] (checked-only) for the amount, [`SettlementEpoch`] for the
//! epoch — so an epoch index or a bare `u64` can never be passed where the
//! `C_min`-feeding amount is expected.
//!
//! ## Staging
//!
//! `recompute_for_epoch` is `pub(crate)` for now; when the SP-3/SP-5 extractor
//! lands it tightens to `pub(in crate::engine::pscan::extractor)` (the module
//! that runs the confirmed-output extraction). Until its consumer exists it
//! carries a transient `#[allow(dead_code)]`, like SP-0/SP-1.

use shekyl_scanner::RecoveredWalletOutput;
use shekyl_types::SettlementEpoch;
use shekyl_units::AtomicUnits;

/// Why recomputing a [`PFundingInflow`] failed.
#[allow(dead_code)] // transient — SP-5 consumer (extractor / C_min sizing) not built yet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PFundingInflowError {
    /// The epoch's confirmed inflow summed past `u64::MAX` (an attacker-stuffed
    /// or impossible amount set). Fail closed rather than wrap a money total.
    Overflow,
}

impl std::fmt::Display for PFundingInflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Overflow => write!(f, "per-epoch funding inflow overflowed u64"),
        }
    }
}

impl std::error::Error for PFundingInflowError {}

/// Per-epoch `P` funding inflow — the amount that funded `P` in one settlement
/// epoch, the signal the cover's `C_min` (earnings ramp) consumes.
///
/// Constructible only via [`Self::recompute_for_epoch`] (private fields), from
/// ownership-confirmed outputs — see the module docs for the two enforcement
/// points.
#[allow(dead_code)] // transient — SP-5 consumer not built yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PFundingInflow {
    settlement_epoch: SettlementEpoch,
    atomic: AtomicUnits,
}

impl PFundingInflow {
    /// **Idempotent** recompute: `confirmed` is the epoch's *complete*
    /// ownership-confirmed output set; this folds their amounts once (it does
    /// not accumulate across passes), so a post-crash re-scan over the same set
    /// yields the same value. Fails closed on a `u64` overflow.
    ///
    /// `pub(crate)` for now (staging note); tightens to the extractor module
    /// when SP-3/SP-5 lands.
    #[allow(dead_code)] // transient — SP-5 consumer not built yet.
    pub(crate) fn recompute_for_epoch(
        epoch: SettlementEpoch,
        confirmed: &[RecoveredWalletOutput],
    ) -> Result<Self, PFundingInflowError> {
        let atomic = AtomicUnits::checked_sum(confirmed.iter().map(RecoveredWalletOutput::amount))
            .ok_or(PFundingInflowError::Overflow)?;
        Ok(Self {
            settlement_epoch: epoch,
            atomic,
        })
    }

    /// The settlement epoch this inflow accrued in.
    #[allow(dead_code)] // transient — SP-5 consumer not built yet.
    pub(crate) fn epoch(&self) -> SettlementEpoch {
        self.settlement_epoch
    }

    /// The confirmed inflow amount `C_min` sizing consumes.
    #[allow(dead_code)] // transient — SP-5 consumer not built yet.
    pub(crate) fn atomic(&self) -> AtomicUnits {
        self.atomic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
    use shekyl_curve_primitives::Commitment;
    use shekyl_scanner::WalletOutput;

    /// A confirmed output carrying `amount`, the way the scanner's recovery path
    /// produces them (mirrors `engine-core/src/tests.rs`).
    fn confirmed_output(global_index: u64, amount: u64) -> RecoveredWalletOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&global_index.to_le_bytes());
        let scalar = Scalar::from_bytes_mod_order(bytes);
        let key = &scalar * ED25519_BASEPOINT_TABLE;
        let base = WalletOutput::new_for_test(
            [0u8; 32],
            0,
            global_index,
            key,
            Scalar::ZERO,
            Commitment {
                mask: Scalar::ONE,
                amount,
            },
            None,
        );
        RecoveredWalletOutput::new_for_test(base, amount)
    }

    #[test]
    fn sums_the_epochs_confirmed_amounts() {
        let epoch = SettlementEpoch::from_raw(7);
        let outs = [
            confirmed_output(0, 100),
            confirmed_output(1, 250),
            confirmed_output(2, 50),
        ];
        let inflow = PFundingInflow::recompute_for_epoch(epoch, &outs).expect("recompute");
        assert_eq!(inflow.epoch(), epoch);
        assert_eq!(inflow.atomic(), AtomicUnits::from_raw(400));
    }

    #[test]
    fn empty_epoch_is_zero() {
        let inflow = PFundingInflow::recompute_for_epoch(SettlementEpoch::from_raw(3), &[])
            .expect("recompute empty");
        assert_eq!(inflow.atomic(), AtomicUnits::ZERO);
    }

    #[test]
    fn idempotent_recompute_over_the_same_set() {
        let epoch = SettlementEpoch::from_raw(9);
        let outs = [confirmed_output(0, 1_000), confirmed_output(1, 2_345)];
        let a = PFundingInflow::recompute_for_epoch(epoch, &outs).expect("a");
        let b = PFundingInflow::recompute_for_epoch(epoch, &outs).expect("b");
        assert_eq!(
            a, b,
            "recompute over the same complete set must be idempotent"
        );
    }

    #[test]
    fn fails_closed_on_overflow() {
        let outs = [
            confirmed_output(0, u64::MAX),
            confirmed_output(1, 1), // tips the sum past u64::MAX
        ];
        assert_eq!(
            PFundingInflow::recompute_for_epoch(SettlementEpoch::from_raw(1), &outs),
            Err(PFundingInflowError::Overflow),
        );
    }
}
