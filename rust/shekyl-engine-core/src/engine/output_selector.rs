// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Output-selection trait surface for the C5 `PendingTxEngine`
//! impl.
//!
//! Phase 0i binding form per
//! `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §3.1 (R13 segment-2c
//! closure; substrate refined by segment-2g and segment-2h
//! finalizing the narrow-trait shape).
//!
//! # Surface
//!
//! - [`OutputSelector`] — the trait V3.x alternative
//!   selectors plug into ([`WalletGreedyOutputSelector`] is
//!   the V3.0 default; V3.x adds `RandomizedSelector`,
//!   `EntropyMaximizingSelector` per the
//!   `docs/FOLLOWUPS.md` R13 entry).
//! - [`OutputCandidate`] — the per-output (index, amount)
//!   record the caller passes after pre-filtering against
//!   `output_locks` (per §5.6.6 P6 / γ three-collection lean
//!   shape).
//! - [`SelectedOutputs`] — the (indices, total_covered)
//!   pair the selector returns.
//! - [`WalletGreedyOutputSelector`] — the V3.0 default impl
//!   (largest-first greedy; matches the pre-PR-5
//!   `build_pending_tx_in_state` selection loop byte-for-byte).
//!
//! # Trait-vs-implementation split (R13)
//!
//! The trait surface is **narrow** — single method, no
//! algorithm-internal knobs in the trait signature. Selection
//! algorithm details (sort order, coverage strategy,
//! randomization, entropy maximization, …) are the impl's
//! responsibility, not the trait surface's. R13's design pin
//! (per segment-2c): "Adding a new selector to V3.x is a new
//! [`OutputSelector`] impl; the trait surface does not
//! re-open."
//!
//! # F4 caller-side subset re-verification discipline
//!
//! Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F4 closure,
//! the caller (`LocalPendingTx::build`) MUST re-verify
//! that each index returned in [`SelectedOutputs::indices`] is
//! present in the [`OutputCandidate`] slice passed to
//! `select_outputs`. A faulty or malicious selector returning
//! indices outside the candidate set MUST be rejected at the
//! caller via
//! [`OutputSelectorError::ReturnedIndicesNotSubset`].
//!
//! The trait surface cannot syntactically enforce subset; the
//! verification is structurally in the caller's body. See the
//! [`OutputSelector::select_outputs`] doc-comment for the
//! caller-side discipline pin.

use super::error::OutputSelectorError;

/// Per-output candidate record consumed by
/// [`OutputSelector::select_outputs`].
///
/// The caller (`LocalPendingTx::build`) builds these
/// from the engine's snapshot of spendable outputs, filtered
/// against the engine's `output_locks` map (per §5.6.6 P6
/// / γ three-collection lean shape's per-output lock
/// discipline).
///
/// Carries only the structurally-minimal fields the selector
/// needs: the index into the engine's spendable-outputs vector
/// (so the selector can return references back to the caller)
/// and the output's atomic-unit amount (so the selector can
/// reason about coverage). The selector does not need access
/// to the output's commitment, output public key, or any
/// other per-output cryptographic material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCandidate {
    /// Index into the engine's spendable-outputs vector at
    /// the snapshot the caller built the candidate set from.
    /// The selector returns these indices unchanged in
    /// [`SelectedOutputs::indices`]; the caller's F4 subset
    /// re-verification ensures returned indices were actually
    /// in the candidate slice.
    pub index: usize,

    /// Output amount in atomic units. The selector reasons
    /// about coverage against this value; the caller's
    /// total-coverage check uses [`SelectedOutputs::total_covered`].
    pub amount: u64,
}

/// Successful selection result.
///
/// The caller (`LocalPendingTx::build`) consumes both
/// fields: `indices` to construct the
/// `Reservation::selected_transfer_indices` vector and
/// `total_covered` to validate the selector's own coverage
/// claim against the structurally-computed `needed` target.
#[derive(Debug, Clone)]
pub struct SelectedOutputs {
    /// Indices into the candidate slice the caller passed
    /// to [`OutputSelector::select_outputs`]. Per F4, the
    /// caller MUST verify each returned index is present in
    /// the candidate slice before using it.
    pub indices: Vec<usize>,

    /// Sum of the selected outputs' amounts. The caller
    /// validates this is `>= target`; a selector returning a
    /// `total_covered` value inconsistent with the actual
    /// sum of selected outputs is itself a caller-side
    /// invariant violation (the caller can re-sum from
    /// `indices` against the candidate slice to double-check
    /// in audit builds).
    pub total_covered: u64,
}

/// Trait isolating output-selection algorithm from the
/// `LocalPendingTx::build` pipeline.
///
/// Phase 0i binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §3.1 (R13 segment-2c
/// closure). [`WalletGreedyOutputSelector`] is the V3.0
/// default implementor; V3.x adds alternative impls
/// (`RandomizedSelector`, `EntropyMaximizingSelector`) per
/// the `docs/FOLLOWUPS.md` R13 entry.
///
/// # F3-transitive sensitive-material discipline pin
///
/// Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F3 closure,
/// **[`OutputSelector::Error`] and its `Debug` / `Display`
/// projections SHOULD NOT carry sensitive material**. The
/// `OutputSelector` doesn't normally hold spend secrets (the
/// candidate set is filtered against output indices and
/// amounts only — no key material), so this is the lighter-
/// touch transitive application of the F3 discipline pinned
/// on [`Signer::Error`](super::signer::Signer::Error). The
/// trait still names the discipline uniformly so the
/// secret-locality boundary is grep-able across all engine
/// trait surfaces.
///
/// # Trait bounds
///
/// - `Send + Sync + 'static`: matches the engine-trait
///   pattern so a selector can be held behind
///   `Arc<dyn OutputSelector<Error = E>>` if needed.
/// - `type Error: Into<OutputSelectorError>`: the
///   implementor's local error converts to the engine-wide
///   [`OutputSelectorError`] discriminant set (landed C2α).
pub trait OutputSelector: Send + Sync + 'static {
    /// Implementor-specific error type that converts into
    /// the engine-wide [`OutputSelectorError`].
    type Error: Into<OutputSelectorError>;

    /// Select a subset of `candidates` whose summed amount
    /// covers `target`.
    ///
    /// # Caller-side discipline (F4 caller-side subset
    /// re-verification)
    ///
    /// The trait surface cannot syntactically enforce that
    /// the indices returned in [`SelectedOutputs::indices`]
    /// are a subset of `candidates`. **The caller**
    /// (`LocalPendingTx::build`) MUST verify that each
    /// returned index is present in `candidates` and reject
    /// via
    /// [`OutputSelectorError::ReturnedIndicesNotSubset { offending_index }`]
    /// if a violation is detected. This is the F4 closure
    /// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 — a
    /// faulty or malicious selector returning out-of-set
    /// indices either fails at downstream transaction
    /// construction or silently corrupts; the caller-side
    /// check is the structural defense.
    ///
    /// # `target` semantics
    ///
    /// `target` is the total amount-plus-fee the selector
    /// must cover, in atomic units. The caller is responsible
    /// for computing target from the request's recipient
    /// amounts plus the fee estimate; the selector treats
    /// it as opaque coverage threshold.
    ///
    /// # Errors
    ///
    /// Returns the implementor's local `Error` type. The
    /// orchestrator converts via `.into()` to the engine-wide
    /// [`OutputSelectorError`]. The V3.0 default impl
    /// ([`WalletGreedyOutputSelector`]) returns
    /// [`OutputSelectorError::NoEligibleOutputs`] when
    /// `candidates` is empty and
    /// [`OutputSelectorError::InsufficientFunds`] when
    /// `sum(candidates) < target`.
    fn select_outputs(
        &self,
        candidates: &[OutputCandidate],
        target: u64,
    ) -> Result<SelectedOutputs, Self::Error>;
}

/// V3.0 default [`OutputSelector`] implementor.
///
/// Greedy largest-first selection: sort candidates by
/// amount descending (ties broken by ascending `index` for
/// determinism), accumulate until coverage reaches `target`,
/// return the selected indices.
///
/// **Byte-for-byte regression with the pre-PR-5
/// `build_pending_tx_in_state` body.** The selection loop in
/// `engine::pending::build_pending_tx_in_state` (the existing
/// free function) sorts `candidates: Vec<(usize, u64)>` by
/// `(b.amount, a.index)` and accumulates greedily; this
/// implementor extracts that body verbatim. The
/// `wallet_greedy_selects_largest_first` test pins the
/// regression — selection ordering matches the pre-PR-5
/// behavior across the C5β extraction.
///
/// # V3.x successors
///
/// `RandomizedSelector` and `EntropyMaximizingSelector` are
/// V3.x successor impls landing per the
/// `docs/FOLLOWUPS.md` R13 entry. They plug in as
/// alternative [`OutputSelector`] impls (the trait surface
/// does not re-open).
///
/// Zero-sized.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalletGreedyOutputSelector;

impl OutputSelector for WalletGreedyOutputSelector {
    type Error = OutputSelectorError;

    fn select_outputs(
        &self,
        candidates: &[OutputCandidate],
        target: u64,
    ) -> Result<SelectedOutputs, OutputSelectorError> {
        // Empty candidate set: distinct from "candidates sum
        // < target". Caller (`LocalPendingTx::build`) sees
        // this when the post-filter step against
        // `output_locks` left nothing; the engine-wide
        // `From<OutputSelectorError> for SendError` impl
        // collapses to `InsufficientFunds { needed,
        // available: 0 }` so the consumer-facing surface
        // matches the pre-PR-5 behavior.
        if candidates.is_empty() {
            return Err(OutputSelectorError::NoEligibleOutputs);
        }

        // Sort largest-first; ties broken by index ascending.
        // Matches `build_pending_tx_in_state` body at
        // `engine/pending.rs:574` byte-for-byte.
        //
        // The clone of references (not owned candidates) is
        // bounded by candidates.len() and dominated by the
        // surrounding selection-pipeline allocations.
        let mut sorted: Vec<&OutputCandidate> = candidates.iter().collect();
        sorted.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.index.cmp(&b.index)));

        let mut indices = Vec::new();
        let mut covered: u64 = 0;
        for c in &sorted {
            if covered >= target {
                break;
            }
            indices.push(c.index);
            covered = covered.saturating_add(c.amount);
        }

        if covered < target {
            // Per `OutputSelectorError::InsufficientFunds`'
            // C2α doc: the selector's `available` projection
            // is `sum(candidates)` (the selector's own view
            // of the candidate set); the engine-wide
            // `SendError::InsufficientFunds`'s `available`
            // matches this for the V3.0 default selector
            // (the engine doesn't re-aggregate).
            let available: u64 = candidates.iter().map(|c| c.amount).sum();
            return Err(OutputSelectorError::InsufficientFunds {
                needed: target,
                available,
            });
        }

        // Sort indices ascending for deterministic
        // downstream consumption (the caller's
        // `Reservation::selected_transfer_indices` carries
        // sorted indices per the pre-PR-5 body's
        // `selected.sort()` step).
        indices.sort();

        Ok(SelectedOutputs {
            indices,
            total_covered: covered,
        })
    }
}

#[cfg(test)]
mod tests {
    //! C4β `OutputSelector` / `WalletGreedyOutputSelector`
    //! regression tests.
    //!
    //! Coverage scope (per `STAGE_1_PR_5_PENDING_TX_ENGINE.md`
    //! §7.X C4β):
    //!
    //! - `wallet_greedy_selects_largest_first` — pins the
    //!   largest-first selection ordering; matches pre-PR-5
    //!   behavior byte-for-byte.
    //! - `wallet_greedy_insufficient_funds` — pins the
    //!   `InsufficientFunds { needed, available }` payload
    //!   shape for the non-empty-but-undercovering case.
    //! - `wallet_greedy_no_eligible_outputs` — pins the
    //!   empty-candidate-set case fires
    //!   `NoEligibleOutputs` (distinct from the under-
    //!   coverage case).
    //! - `wallet_greedy_ties_broken_by_index` — pins the
    //!   secondary sort key (ascending index on equal
    //!   amount); the pre-PR-5 body did
    //!   `b.1.cmp(&a.1).then(a.0.cmp(&b.0))` — same here.
    //! - `wallet_greedy_total_covered_matches_indices` —
    //!   audit-grade check that the selector's
    //!   `total_covered` projection is internally consistent
    //!   with the returned `indices`.
    use super::*;

    fn candidate(index: usize, amount: u64) -> OutputCandidate {
        OutputCandidate { index, amount }
    }

    #[test]
    fn wallet_greedy_selects_largest_first() {
        let candidates = vec![
            candidate(0, 1_000),
            candidate(1, 5_000),
            candidate(2, 3_000),
            candidate(3, 2_000),
        ];
        let target = 6_000;
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Largest-first: pick index 1 (5_000), then index 2
        // (3_000) → covered = 8_000 ≥ 6_000. `indices` is
        // sorted ascending for deterministic consumption.
        assert_eq!(selected.indices, vec![1, 2]);
        assert_eq!(selected.total_covered, 8_000);
    }

    #[test]
    fn wallet_greedy_insufficient_funds() {
        let candidates = vec![candidate(0, 1_000), candidate(1, 2_000)];
        let target = 10_000;
        let err = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect_err("under-coverage fires InsufficientFunds");
        match err {
            OutputSelectorError::InsufficientFunds { needed, available } => {
                assert_eq!(needed, 10_000);
                assert_eq!(available, 3_000);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn wallet_greedy_no_eligible_outputs() {
        let candidates: Vec<OutputCandidate> = Vec::new();
        let target = 1_000;
        let err = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect_err("empty candidate set fires NoEligibleOutputs");
        assert!(matches!(err, OutputSelectorError::NoEligibleOutputs));
    }

    #[test]
    fn wallet_greedy_ties_broken_by_index() {
        // Three candidates with equal amount. Secondary sort
        // is by ascending index, so the selector picks index
        // 0 (then 1, etc.) when target requires the
        // smallest-index candidate first.
        let candidates = vec![
            candidate(2, 1_000),
            candidate(0, 1_000),
            candidate(1, 1_000),
        ];
        let target = 1_000;
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Only one candidate needed; ties broken by
        // ascending index → index 0.
        assert_eq!(selected.indices, vec![0]);
        assert_eq!(selected.total_covered, 1_000);
    }

    #[test]
    fn wallet_greedy_total_covered_matches_indices() {
        let candidates = vec![
            candidate(5, 7_000),
            candidate(2, 4_000),
            candidate(9, 2_000),
        ];
        let target = 10_000;
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Verify total_covered is internally consistent with
        // the sum of selected indices' amounts in the
        // candidate set.
        let recomputed: u64 = selected
            .indices
            .iter()
            .map(|i| {
                candidates
                    .iter()
                    .find(|c| c.index == *i)
                    .expect(
                        "selected index appears in candidates (F4 caller-side check is structural)",
                    )
                    .amount
            })
            .sum();
        assert_eq!(selected.total_covered, recomputed);
    }
}
