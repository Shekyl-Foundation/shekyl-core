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
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DrainSelection {
    /// The selected outputs' global indices, in selection order — largest-first
    /// with ties broken by output id ascending (see [`select_for_drain`]).
    /// Deterministic and *not* re-sorted; a downstream consumer that needs a
    /// different order sorts explicitly rather than depending on this one.
    pub(crate) chosen: Vec<GlobalOutputIndex>,
    /// The sum of the chosen outputs' amounts (`>= drain amount`).
    pub(crate) input_total: AtomicUnits,
}

impl std::fmt::Debug for DrainSelection {
    /// Redacted: `chosen` is the set of leaf positions `P` is about to drain
    /// together — a slice of `P`'s spend set, which the firewall keeps
    /// unenumerable, same discipline as [`DrainCandidate`]. The aggregate
    /// `input_total` is a public scalar and renders.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrainSelection")
            .field("chosen", &"<redacted spend-set>")
            .field("input_total", &self.input_total)
            .finish()
    }
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
/// Selection reads only `{amount, spendable_height, output_id}` off each
/// candidate: mature candidates (`spendable_height <= reference_height`) are
/// taken largest-first (ties broken by output id ascending) — a fully
/// deterministic, lineage-blind policy that minimises the input count — until
/// their running total reaches the drain amount. The maturity filter is
/// defensive: the projection already hands in the mature subset, but
/// re-checking keeps this stage correct for any candidate slice.
pub(crate) fn select_for_drain(
    candidates: &[DrainCandidate],
    amount: DrainAmount,
    reference_height: BlockHeight,
) -> Result<DrainSelection, DrainSelectError> {
    let target = amount.get();

    let mut mature: Vec<&DrainCandidate> = candidates
        .iter()
        .filter(|c| c.spendable_height <= reference_height)
        .collect();
    // Largest-first, ties broken by output id ascending — the engine's
    // established selection order (`output_selector.rs`). `sort_by` is stable,
    // so amount-only ties would preserve the caller's candidate order, making
    // the chosen set depend on how the record slice was built; the id tiebreak
    // makes selection independent of input order and fully deterministic.
    // Lineage-blind (never orders on lineage/epoch/height), and minimises the
    // number of inputs the drain consumes.
    mature.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.output_id.cmp(&b.output_id)));

    let mut chosen = Vec::new();
    let mut input_total = AtomicUnits::ZERO;
    for candidate in mature {
        if input_total >= target {
            break;
        }
        chosen.push(candidate.output_id);
        input_total = input_total
            .checked_add(candidate.amount)
            .ok_or(DrainSelectError::Overflow)?;
    }

    if input_total < target {
        return Err(DrainSelectError::Insufficient);
    }

    Ok(DrainSelection {
        chosen,
        input_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::drain_amount::{choose_drain_amount, DrainRequest};

    fn candidate(output_id: u64, amount: u64, spendable_height: u64) -> DrainCandidate {
        DrainCandidate {
            output_id: GlobalOutputIndex::from_raw(output_id),
            amount: AtomicUnits::from_raw(amount),
            spendable_height: BlockHeight::from_raw(spendable_height),
        }
    }

    /// F-D1 M1 arm (import-check). The guarded select stage must never name
    /// the persisted funding-output record or its mint-lineage rung tag: the
    /// stripped [`DrainCandidate`] is the only per-output view it may read. A
    /// reappearance of either type identifier reopens the decomposition
    /// surface §12.3 closes. The forbidden identifiers are assembled with
    /// `concat!` so this assertion never self-matches.
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

    fn amount(raw: u64, affordable: u64) -> DrainAmount {
        choose_drain_amount(
            DrainRequest {
                target: AtomicUnits::from_raw(raw),
            },
            AtomicUnits::from_raw(affordable),
        )
        .expect("affordable")
    }

    #[test]
    fn single_largest_output_covers() {
        let candidates = [
            candidate(1, 5, 10),
            candidate(2, 100, 10),
            candidate(3, 7, 10),
        ];
        let sel = select_for_drain(&candidates, amount(90, 112), BlockHeight::from_raw(10))
            .expect("covers");
        assert_eq!(sel.chosen, vec![GlobalOutputIndex::from_raw(2)]);
        assert_eq!(sel.input_total, AtomicUnits::from_raw(100));
    }

    #[test]
    fn accumulates_largest_first_until_covered() {
        let candidates = [
            candidate(1, 40, 10),
            candidate(2, 40, 10),
            candidate(3, 40, 10),
        ];
        let sel = select_for_drain(&candidates, amount(70, 120), BlockHeight::from_raw(10))
            .expect("covers");
        // Two 40s cover 70; the third is not consumed.
        assert_eq!(sel.chosen.len(), 2);
        assert_eq!(sel.input_total, AtomicUnits::from_raw(80));
    }

    #[test]
    fn immature_outputs_are_not_selected() {
        // Only the immature output could cover; selection must refuse.
        let candidates = [candidate(1, 10, 10), candidate(2, 1000, 999)];
        let err = select_for_drain(&candidates, amount(500, 1010), BlockHeight::from_raw(10))
            .expect_err("immature excluded");
        assert_eq!(err, DrainSelectError::Insufficient);
    }

    #[test]
    fn equal_amounts_break_ties_by_output_id_ascending() {
        // Three equal-amount candidates, presented out of id order. The drain
        // needs exactly one; the id tiebreak must pick the lowest id
        // deterministically, independent of input order or toolchain.
        let candidates = [
            candidate(9, 50, 10),
            candidate(2, 50, 10),
            candidate(5, 50, 10),
        ];
        let sel = select_for_drain(&candidates, amount(40, 150), BlockHeight::from_raw(10))
            .expect("covers");
        assert_eq!(sel.chosen, vec![GlobalOutputIndex::from_raw(2)]);
    }

    #[test]
    fn insufficient_mature_total_refuses() {
        let candidates = [candidate(1, 10, 10), candidate(2, 20, 10)];
        let err = select_for_drain(&candidates, amount(31, 31), BlockHeight::from_raw(10));
        // 31 > affordable 31? affordable is 31, target 31 ok at amount stage,
        // but mature total is 30 < 31 → select refuses.
        assert_eq!(err, Err(DrainSelectError::Insufficient));
    }
}
