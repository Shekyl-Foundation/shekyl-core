// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! F-D1 select stage — lineage-blind coin selection for the `P` value-out
//! (drain) path (`ARCHIVAL_FIREWALL_GATE6.md` §12.3, the drain-amount
//! taint-carve).
//!
//! This is a **guarded module** (F-D1 M1 arm): it consumes only the
//! *stripped* per-output view ([`DrainCandidate`] — output id, amount,
//! spendable height) and never the persisted funding-output record or its
//! mint-lineage rung tag. The record carries `{lineage, epoch, height}`,
//! which a decomposition adversary matches against the publicly-derivable
//! reward sequence (§18.10); the drain never needs any of it. Selection is
//! **fungible and lineage-blind** — the codebase's own scan-side selection
//! principle already refuses a lineage preference as "a distinguishable …
//! signal" (`backing_set.rs`), and on-chain the outputs are FCMP++-hidden,
//! so there is nothing for lineage-aware selection to buy.
//!
//! The type names of the stripped-away fields are deliberately absent from
//! this file; the import-check arm ([`tests`]) greps for their reappearance.

use shekyl_types::{BlockHeight, GlobalOutputIndex};
use shekyl_units::AtomicUnits;

use super::drain_amount::DrainAmount;

/// One spendable `P` funding output, reduced to exactly the fields drain
/// selection needs: a stable identity, its value, and the maturity axis.
///
/// This is the **stripped view** the drain trust boundary
/// (`drain_orchestrator`) projects out of the persisted funding record. It
/// carries **no** mint-lineage rung, arrival epoch, or arrival height — the
/// three fields whose per-output presence lets `Σ amount` grouped by epoch
/// approximate `reward_P(E)` even after the tag is dropped (§12.3 part 1).
/// `spendable_height` is kept because it is a *different* axis
/// (maturity/provability), not a reward-sequence coordinate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainCandidate {
    /// The global (chain-wide) output index — the curve-tree leaf position
    /// the downstream assembly re-maps to a full record for spending.
    pub(crate) output_id: GlobalOutputIndex,
    /// The output's cleartext value.
    pub(crate) amount: AtomicUnits,
    /// The height at which the output's leaf is present in the curve tree
    /// and the output becomes spendable/provable.
    pub(crate) spendable_height: BlockHeight,
}

impl std::fmt::Debug for DrainCandidate {
    /// Redacted: an `(output_id, amount, spendable_height)` row is a slice of
    /// `P`'s funding history, same discipline as the record it was projected
    /// from.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DrainCandidate(<redacted funding-history>)")
    }
}

/// The outcome of the select stage: the output identities that fund the drain
/// and the exact input total they contribute (change is computed downstream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DrainSelection {
    /// The selected outputs' global indices, in selection order.
    pub(crate) chosen: Vec<GlobalOutputIndex>,
    /// The sum of the chosen outputs' amounts (`>= drain amount`).
    pub(crate) input_total: AtomicUnits,
}

/// Why the select stage could not assemble the requested drain amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainSelectError {
    /// The provable (mature) candidate set cannot cover the drain amount.
    Insufficient,
    /// Summing candidate amounts overflowed `u64` atomic units.
    Overflow,
}

/// Select a lineage-blind set of mature candidates whose amounts cover
/// `amount`.
///
/// Skeleton (F-D1 M1 arm lands first — real logic in the next commit).
pub(crate) fn select_for_drain(
    _candidates: &[DrainCandidate],
    _amount: DrainAmount,
    _reference_height: BlockHeight,
) -> Result<DrainSelection, DrainSelectError> {
    Err(DrainSelectError::Insufficient)
}

#[cfg(test)]
mod tests {
    /// F-D1 M1 arm (import-check). The guarded select stage must never name
    /// the persisted funding-output record or its mint-lineage rung tag: the
    /// stripped [`super::DrainCandidate`] is the only per-output view it may
    /// read. A reappearance of either type identifier reopens the
    /// decomposition surface §12.3 closes. The forbidden identifiers are
    /// assembled with `concat!` so this assertion never self-matches.
    #[test]
    fn fd1_arm_select_stage_names_no_lineage_type() {
        let src = include_str!("drain_select.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("drain_select.rs has a production section");
        let record = concat!("PFundingOutput", "Record");
        let lineage = concat!("MintLineage", "Output");
        assert!(
            !src.contains(record),
            "F-D1 carve breached: select stage names the funding-output record \
             (drain must read only the stripped DrainCandidate; §12.3)"
        );
        assert!(
            !src.contains(lineage),
            "F-D1 carve breached: select stage names the mint-lineage rung tag \
             (drain selection is lineage-blind; §12.3)"
        );
    }
}
