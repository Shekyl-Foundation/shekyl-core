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
    /// The amount is coverable by the pool, but not within the
    /// [`shekyl_tx_builder::MAX_INPUTS`] inputs one FCMP++ transaction can
    /// spend. Exact, not heuristic: selection is largest-first, so the capped
    /// prefix is the maximum any legal input set can sum — if it cannot cover
    /// the amount, no legal selection can. Refused here as a user-actionable
    /// planner arm ("lower the amount") rather than assembling a selection
    /// the curve-tree actor's own `MAX_INPUTS` boundary check would reject as
    /// an internal fault after the proof work.
    InputCapExceeded,
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
        // One FCMP++ tx spends at most MAX_INPUTS inputs (the curve-tree
        // actor refuses more at the proof boundary). Largest-first makes the
        // capped prefix the maximum sum of any legal selection, so hitting
        // the cap short of the target is an exact "cannot cover within one
        // drain" refusal, not a selection-order artifact.
        if chosen.len() == shekyl_tx_builder::MAX_INPUTS {
            return Err(DrainSelectError::InputCapExceeded);
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

/// The outcome of the terminal-sweep select stage: the pass's inputs, the
/// payment they fund after the fee, and the pool residue this pass leaves.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SweepSelection {
    /// The selected outputs' global indices — the same largest-first,
    /// id-ascending order as [`select_for_drain`].
    pub(crate) chosen: Vec<GlobalOutputIndex>,
    /// The sum of the chosen outputs' amounts.
    pub(crate) input_total: AtomicUnits,
    /// The pass's principal payment: `input_total − fee`. Exact by
    /// construction, so the assembly's change is zero and its drain-all arm
    /// (the T-DS-6 two-output principal split) is the shape that fires.
    pub(crate) payment: AtomicUnits,
    /// What this pass leaves in the pool: every candidate **not** chosen —
    /// immature outputs plus any mature overflow past the input cap. An
    /// aggregate scalar (the same class `get_drain_balance` serves); `"0"`
    /// is the completion fact the caller cannot infer from a payment amount.
    pub(crate) remainder: AtomicUnits,
}

impl std::fmt::Debug for SweepSelection {
    /// Redacted like [`DrainSelection`]: `chosen` is a slice of `P`'s spend
    /// set; the aggregates are public scalars and render.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SweepSelection")
            .field("chosen", &"<redacted spend-set>")
            .field("input_total", &self.input_total)
            .field("payment", &self.payment)
            .field("remainder", &self.remainder)
            .finish()
    }
}

/// Why the terminal-sweep select stage refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SweepSelectError {
    /// No candidate is mature at the reference height — nothing is provable
    /// yet. Distinct from [`Self::DustPool`]: the remedy is "wait for
    /// maturity", not "the residue is uncollectable".
    NothingSpendable,
    /// The mature candidates cannot fund the pass's own fee
    /// (`input_total <= fee`) — the pool residue is smaller than the cost of
    /// moving it. The named dust residual: it stays in `P`, and the funded
    /// retirement gate stays held by it, until further value matures into
    /// the slot or the fee floor moves.
    DustPool,
    /// Summing candidate amounts overflowed `u64` atomic units.
    Overflow,
}

/// Select one terminal-sweep pass: **all** mature candidates, largest-first
/// (ties by output id ascending), capped at [`shekyl_tx_builder::MAX_INPUTS`];
/// the payment is what they fund after the fee.
///
/// This is the one selection arm whose payment is an **output of selection**
/// rather than a caller target — deliberately, and only here: the funded
/// retirement gate needs the slot at exactly zero, and an exact-zero payment
/// is not expressible through the user-target path (the fee is an internal
/// quote, never a parameter — `unstake_facade`'s finding). The F-D1 amount
/// stage (`drain_amount.rs`) is **not** consulted and its carve text is
/// untouched: this stage already legitimately holds the stripped per-output
/// amounts, still reads none of the lineage/epoch/arrival fields (the M1
/// grep below covers this arm too), and is reachable only through a
/// [`TerminalSweep`](super::drain_orchestrator::DrainIntent::TerminalSweep)
/// intent, whose witness certifies the persona's terminal exit is already
/// public on-chain — the §12.3 reward-subsum matching the carve defends
/// against adds nothing to a persona whose collateral return the record
/// delta has already published (the F-W10-era re-pricing; the amendment is
/// recorded in `PRINCIPAL_STAKE_LIFECYCLE.md`, not silently assumed).
///
/// Unlike [`select_for_drain`] there is no `Insufficient` / cap refusal: the
/// pass takes what it can and reports the rest as `remainder` — a capped or
/// immature residue is "call again once it matures/confirms", not an error.
pub(crate) fn select_for_sweep(
    candidates: &[DrainCandidate],
    fee: AtomicUnits,
    reference_height: BlockHeight,
) -> Result<SweepSelection, SweepSelectError> {
    let mut mature: Vec<&DrainCandidate> = candidates
        .iter()
        .filter(|c| c.spendable_height <= reference_height)
        .collect();
    if mature.is_empty() {
        return Err(SweepSelectError::NothingSpendable);
    }
    // The same ordering as `select_for_drain`, same rationale.
    mature.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.output_id.cmp(&b.output_id)));

    let mut chosen = Vec::new();
    let mut input_total = AtomicUnits::ZERO;
    for candidate in &mature {
        if chosen.len() == shekyl_tx_builder::MAX_INPUTS {
            break;
        }
        chosen.push(candidate.output_id);
        input_total = input_total
            .checked_add(candidate.amount)
            .ok_or(SweepSelectError::Overflow)?;
    }

    let payment = input_total
        .checked_sub(fee)
        .filter(|p| !p.is_zero())
        .ok_or(SweepSelectError::DustPool)?;

    // Everything not chosen — mature overflow past the cap plus every
    // immature candidate — is what the pool still holds after this pass.
    let all_total = AtomicUnits::checked_sum(candidates.iter().map(|c| c.amount))
        .ok_or(SweepSelectError::Overflow)?;
    let remainder = all_total
        .checked_sub(input_total)
        .ok_or(SweepSelectError::Overflow)?;

    Ok(SweepSelection {
        chosen,
        input_total,
        payment,
        remainder,
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
        // Split on the `#[cfg(test)]` boundary only — not the full
        // `mod tests {` line — so a reformat of the test-module declaration
        // (extra attributes, a `mod tests;` file split, whitespace) can't
        // silently fold the test section into the scanned text. `split_once` +
        // `expect` fails loudly if that boundary is ever absent, rather than
        // the old `.split(..).next()` defaulting to the whole file.
        let (src, _tests) = include_str!("drain_select.rs")
            .split_once("\n#[cfg(test)]")
            .expect("drain_select.rs has a #[cfg(test)] section to exclude from the scan");
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

    /// Selection stops at `MAX_INPUTS` with an exact refusal: largest-first
    /// makes the capped prefix the maximum sum of ANY legal input set, so an
    /// amount only coverable past the cap is `InputCapExceeded` — the
    /// user-actionable planner arm ("lower the amount") — never a selection
    /// handed to the curve-tree actor for its `MAX_INPUTS` boundary check to
    /// refuse as an internal fault after the proof work. The at-cap amount
    /// still selects (negative control: the cap refuses the ninth input, not
    /// the eighth).
    #[test]
    fn selection_caps_at_max_inputs_with_an_exact_refusal() {
        // Nine mature candidates of 10 each: the eight largest sum to 80.
        let candidates: Vec<_> = (1..=9).map(|i| candidate(i, 10, 10)).collect();

        let over = select_for_drain(&candidates, amount(90, 90), BlockHeight::from_raw(10));
        assert_eq!(over, Err(DrainSelectError::InputCapExceeded));

        let at_cap = select_for_drain(&candidates, amount(80, 90), BlockHeight::from_raw(10))
            .expect("eight inputs cover 80");
        assert_eq!(at_cap.chosen.len(), shekyl_tx_builder::MAX_INPUTS);
        assert_eq!(at_cap.input_total, AtomicUnits::from_raw(80));
    }

    /// This bites against the sweep payment drifting off `Σ selected − fee`
    /// (the exact-zero-change property the funded retirement gate needs) and
    /// against a remainder that forgets either residue class. It does NOT
    /// cover the witness gate (the intent's, at the seam) or the assembly's
    /// two-output split.
    #[test]
    fn sweep_takes_all_mature_and_pays_sum_minus_fee() {
        // Two mature, one immature: the pass takes exactly the mature pair.
        let candidates = [
            candidate(1, 300, 10),
            candidate(2, 200, 10),
            candidate(3, 400, 99),
        ];
        let sel = select_for_sweep(
            &candidates,
            AtomicUnits::from_raw(50),
            BlockHeight::from_raw(10),
        )
        .expect("two mature candidates fund a 50 fee");
        assert_eq!(
            sel.chosen,
            vec![
                GlobalOutputIndex::from_raw(1),
                GlobalOutputIndex::from_raw(2)
            ],
            "largest-first over the mature subset only"
        );
        assert_eq!(sel.input_total, AtomicUnits::from_raw(500));
        assert_eq!(
            sel.payment,
            AtomicUnits::from_raw(450),
            "the payment is exactly Σ selected − fee: zero change by construction"
        );
        assert_eq!(
            sel.remainder,
            AtomicUnits::from_raw(400),
            "the immature candidate is reported as residue, not dropped"
        );
    }

    /// This bites against the sweep refusing (or panicking) at the input cap
    /// instead of taking a full pass and reporting the mature overflow as
    /// remainder — the multi-pass contract `collect_unstaked` documents. It
    /// does NOT cover pass sequencing (the one-live-drain gate's).
    #[test]
    fn sweep_caps_at_max_inputs_and_reports_the_overflow_as_remainder() {
        // Nine mature candidates of 10 each: one pass spends the cap (80).
        let candidates: Vec<_> = (1..=9).map(|i| candidate(i, 10, 10)).collect();
        let sel = select_for_sweep(
            &candidates,
            AtomicUnits::from_raw(5),
            BlockHeight::from_raw(10),
        )
        .expect("a full pass fits the cap");
        assert_eq!(sel.chosen.len(), shekyl_tx_builder::MAX_INPUTS);
        assert_eq!(sel.input_total, AtomicUnits::from_raw(80));
        assert_eq!(sel.payment, AtomicUnits::from_raw(75));
        assert_eq!(
            sel.remainder,
            AtomicUnits::from_raw(10),
            "the ninth output stays in the pool and the reply must say so"
        );
    }

    /// This bites against the dust arm collapsing into an empty selection or
    /// a zero payment (the prover rejects zero-value outputs; the caller
    /// needs the named residual, not a downstream fault). Boundary exact:
    /// `Σ == fee` is dust, `Σ == fee + 1` pays 1.
    #[test]
    fn sweep_dust_and_nothing_spendable_refuse_distinctly() {
        let none = select_for_sweep(
            &[candidate(1, 100, 99)],
            AtomicUnits::from_raw(5),
            BlockHeight::from_raw(10),
        );
        assert_eq!(
            none,
            Err(SweepSelectError::NothingSpendable),
            "an all-immature pool is 'wait for maturity', not dust"
        );

        let dust = select_for_sweep(
            &[candidate(1, 50, 10)],
            AtomicUnits::from_raw(50),
            BlockHeight::from_raw(10),
        );
        assert_eq!(dust, Err(SweepSelectError::DustPool));

        let one_over = select_for_sweep(
            &[candidate(1, 51, 10)],
            AtomicUnits::from_raw(50),
            BlockHeight::from_raw(10),
        )
        .expect("one atomic unit over the fee is a payable sweep");
        assert_eq!(one_over.payment, AtomicUnits::from_raw(1));
    }
}
