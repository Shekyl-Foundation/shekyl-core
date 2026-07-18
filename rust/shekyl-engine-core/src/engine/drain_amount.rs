// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D1 amount stage — the drain amount is chosen from `{user target,
//! cadence, RNG}` and an **aggregate scalar affordability check only**
//! (`ARCHIVAL_FIREWALL_GATE6.md` §12.3, the drain-amount taint-carve).
//!
//! This is a **guarded module** (F-D1 M1 arm). The forbidden read is the
//! reward-sequence decomposition: per-output amounts are the reward *values*,
//! so an amount stage that could see the per-output vector could compute a
//! drain amount equal to a reward subsum, off-chain-matchable against the
//! publicly-derivable `reward_P(E)` (§18.10). The carve is structural: the
//! only balance input this stage takes is a single [`AtomicUnits`] scalar —
//! the aggregate spendable total — consulted for `amount <= affordable`
//! **only**, never as a computation input. Core code therefore **cannot
//! derive** a reward-shaped amount from the decomposition — the per-output
//! vector never reaches this stage. Whether the returned value *coincides*
//! with some subsum depends on the `target` handed in; shaping `target` away
//! from reward values is the F-D2 round-number / random-split UI default
//! (`shekyl-gui-wallet`), not this stage.
//!
//! The amount-stage signature check ([`tests`]) pins that carve: the entry
//! point takes `affordable: AtomicUnits`, and this file never names the
//! per-output vector or the persisted funding record.

use shekyl_units::AtomicUnits;

/// A drain amount the amount stage has chosen and proven affordable against
/// the aggregate scalar. Opaque so no downstream stage can mistake it for a
/// reward-derived value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainAmount(AtomicUnits);

impl DrainAmount {
    /// The chosen atomic-unit amount.
    pub(crate) fn get(self) -> AtomicUnits {
        self.0
    }
}

impl std::fmt::Debug for DrainAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DrainAmount({})", self.0.to_raw())
    }
}

/// What the user asked the drain to move, plus the default shaping inputs.
///
/// Carries no balance vector — only a scalar `target` and the shaping policy.
/// The core-side half of F-D2 lives here: the request shape a UI hands in
/// **cannot** carry a reward-decomposed figure, only a single target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DrainRequest {
    /// The atomic-unit amount the user wants to move.
    pub(crate) target: AtomicUnits,
}

/// Why the amount stage could not honour the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainAmountError {
    /// `target` exceeds the aggregate spendable scalar.
    Unaffordable,
    /// `target` is zero — nothing to move.
    Empty,
}

/// Choose the drain amount from the request and the aggregate scalar.
///
/// `affordable` is the **aggregate spendable total** (one scalar); it is read
/// for the affordability check (`target <= affordable`) **only**, never as a
/// computation input. The per-output reward vector never reaches this stage,
/// so core code cannot *derive* a reward-shaped amount here; the returned
/// amount is the validated `target` verbatim (§12.3). The `{cadence, RNG}`
/// shaping the pin lists alongside the target — which steers `target` away
/// from any reward subsum — is the F-D2 round-number / random-split UI default
/// that *produces* it; it lives in `shekyl-gui-wallet`, not here.
pub(crate) fn choose_drain_amount(
    request: DrainRequest,
    affordable: AtomicUnits,
) -> Result<DrainAmount, DrainAmountError> {
    if request.target == AtomicUnits::from_raw(0) {
        return Err(DrainAmountError::Empty);
    }
    if request.target.to_raw() > affordable.to_raw() {
        return Err(DrainAmountError::Unaffordable);
    }
    Ok(DrainAmount(request.target))
}

#[cfg(test)]
mod tests {
    /// F-D1 M1 arm (amount-stage signature check). Two properties, both
    /// grepped against the production source text:
    ///
    /// 1. the amount entry point reads the aggregate scalar
    ///    (`affordable: AtomicUnits`); and
    /// 2. this stage names neither the per-output stripped vector
    ///    (`DrainCandidate`) nor the persisted funding record — so it
    ///    structurally cannot consult per-output reward values.
    ///
    /// Forbidden identifiers are assembled with `concat!` so the assertion
    /// never self-matches.
    #[test]
    fn fd1_arm_amount_stage_reads_scalar_not_vector() {
        let src = include_str!("drain_amount.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("drain_amount.rs has a production section");
        assert!(
            src.contains("affordable: AtomicUnits"),
            "F-D1 carve breached: amount stage must take the aggregate scalar \
             `affordable: AtomicUnits` (§12.3)"
        );
        let candidate = concat!("Drain", "Candidate");
        let record = concat!("PFundingOutput", "Record");
        let lineage = concat!("MintLineage", "Output");
        assert!(
            !src.contains(candidate),
            "F-D1 carve breached: amount stage names the per-output vector type \
             (it must read only the aggregate scalar; §12.3)"
        );
        assert!(
            !src.contains(record),
            "F-D1 carve breached: amount stage names the funding-output record \
             (§12.3)"
        );
        assert!(
            !src.contains(lineage),
            "F-D1 carve breached: amount stage names the mint-lineage rung tag \
             (a guarded module is blind to every stripped type; §12.3)"
        );
    }

    #[test]
    fn amount_stage_affordability_and_empty_guards() {
        let ten = shekyl_units::AtomicUnits::from_raw(10);
        let zero = shekyl_units::AtomicUnits::from_raw(0);
        assert_eq!(
            super::choose_drain_amount(super::DrainRequest { target: zero }, ten),
            Err(super::DrainAmountError::Empty)
        );
        assert_eq!(
            super::choose_drain_amount(
                super::DrainRequest {
                    target: shekyl_units::AtomicUnits::from_raw(11)
                },
                ten
            ),
            Err(super::DrainAmountError::Unaffordable)
        );
        assert!(super::choose_drain_amount(super::DrainRequest { target: ten }, ten).is_ok());
    }
}
