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
//! - [`SelectedInputs`] — the indices of one spend, at most
//!   [`shekyl_tx_builder::MAX_INPUTS`].
//! - [`SelectedOutputs`] — the (indices, total_covered)
//!   pair the selector returns.
//! - `cover_largest_first` — the minimum-cardinality cover
//!   the default selector and the drain selector both call.
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

use shekyl_units::AtomicUnits;

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
    pub amount: AtomicUnits,
}

/// The inputs of one spend. The length is at most
/// [`shekyl_tx_builder::MAX_INPUTS`].
///
/// A cover that needs more inputs is
/// [`OutputSelectorError::TooManyInputs`], never a value of
/// this type. An empty set is representable: a zero target
/// selects nothing, and the signer refuses an empty spend
/// on its own path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedInputs {
    indices: Vec<usize>,
}

impl SelectedInputs {
    /// Accept `indices` when one transaction can spend them.
    ///
    /// `Err` is the length that did not fit.
    pub fn within_cap(indices: Vec<usize>) -> Result<Self, usize> {
        let count = indices.len();
        if count > shekyl_tx_builder::MAX_INPUTS {
            return Err(count);
        }
        Ok(Self { indices })
    }

    /// The indices, in the order the selector stored them.
    #[must_use]
    pub fn as_slice(&self) -> &[usize] {
        &self.indices
    }

    /// How many inputs this spend carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// No inputs. A zero target is the case that constructs one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// The indices, by reference.
    pub fn iter(&self) -> std::slice::Iter<'_, usize> {
        self.indices.iter()
    }
}

impl<'a> IntoIterator for &'a SelectedInputs {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// One largest-first cover of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LargestFirstCover<T> {
    /// The prefix of the ranking that covers the target, in
    /// the ranking's order.
    pub(crate) chosen: Vec<T>,
    /// The sum of [`Self::chosen`].
    pub(crate) total: AtomicUnits,
}

/// Why [`cover_largest_first`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LargestFirstFault {
    /// The whole ranking sums to less than the target.
    ///
    /// This wins over [`Self::TooManyInputs`]: a ranking that
    /// cannot cover at any length is short, including when it
    /// is longer than the cap.
    Short {
        /// The target the caller asked to cover.
        needed: AtomicUnits,
        /// The sum of the ranking.
        available: AtomicUnits,
    },
    /// A cover exists and its length is greater than the cap.
    ///
    /// `count` is that length. Largest-first is a minimum-
    /// cardinality cover: any other subset that covers the
    /// target is at least as long, because any `k` amounts
    /// sum to at most the `k` largest. A cover longer than
    /// the cap means no legal selection exists.
    TooManyInputs {
        /// How many inputs the shortest cover needs.
        count: usize,
    },
    /// Adding an amount overflowed `u64` atomic units.
    Overflow,
}

/// The shortest prefix of `ranked_largest_first` whose amounts
/// cover `target`.
///
/// `ranked_largest_first` is already ordered largest amount
/// first. The caller owns the tiebreak. `cap` is how many
/// inputs one transaction can spend; a cover longer than that
/// is [`LargestFirstFault::TooManyInputs`].
///
/// A zero `target` covers with an empty prefix. An empty
/// ranking covers only a zero target.
///
/// The walk counts to the covering length, since that length
/// is what a refusal names and what tells a short ranking from
/// an over-cap one, but keeps at most `cap` items: a cover past
/// the cap is refused, so nothing past it is ever returned.
pub(crate) fn cover_largest_first<T>(
    ranked_largest_first: impl IntoIterator<Item = T>,
    amount_of: impl Fn(&T) -> AtomicUnits,
    target: AtomicUnits,
    cap: usize,
) -> Result<LargestFirstCover<T>, LargestFirstFault> {
    let mut chosen = Vec::with_capacity(cap);
    let mut count = 0usize;
    let mut total = AtomicUnits::ZERO;
    for item in ranked_largest_first {
        if total >= target {
            break;
        }
        total = total
            .checked_add(amount_of(&item))
            .ok_or(LargestFirstFault::Overflow)?;
        count += 1;
        if count <= cap {
            chosen.push(item);
        }
    }
    if total < target {
        return Err(LargestFirstFault::Short {
            needed: target,
            available: total,
        });
    }
    if count > cap {
        return Err(LargestFirstFault::TooManyInputs { count });
    }
    Ok(LargestFirstCover { chosen, total })
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
    /// the candidate slice before using it. The length fits
    /// in one transaction; [`SelectedInputs`] is what makes
    /// a longer set unrepresentable.
    pub indices: SelectedInputs,

    /// Sum of the selected outputs' amounts. The caller
    /// validates this is `>= target`; a selector returning a
    /// `total_covered` value inconsistent with the actual
    /// sum of selected outputs is itself a caller-side
    /// invariant violation (the caller can re-sum from
    /// `indices` against the candidate slice to double-check
    /// in audit builds).
    pub total_covered: AtomicUnits,
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
    /// # Input bound
    ///
    /// A successful selection carries [`SelectedInputs`]: at
    /// most [`shekyl_tx_builder::MAX_INPUTS`] indices. An
    /// implementation returns
    /// [`OutputSelectorError::TooManyInputs`] only when it
    /// has established that the shortest cover exceeds that
    /// bound. [`WalletGreedyOutputSelector`] has: its
    /// largest-first cover is a minimum-cardinality cover.
    /// A strategy that spends more inputs than the shortest
    /// cover does not report that count as the number the
    /// send needs. It returns a set the type can carry, or
    /// a different error.
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
    /// `candidates` is empty,
    /// [`OutputSelectorError::InsufficientFunds`] when
    /// `sum(candidates) < target`, and
    /// [`OutputSelectorError::TooManyInputs`] when the
    /// shortest cover is longer than one transaction.
    fn select_outputs(
        &self,
        candidates: &[OutputCandidate],
        target: AtomicUnits,
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
        target: AtomicUnits,
    ) -> Result<SelectedOutputs, OutputSelectorError> {
        // Empty candidate set: distinct from "candidates sum
        // < target". The build routes both through
        // `CandidatePartition::refusal`, which names a rebuild
        // or incoming money when waiting would cover the send.
        if candidates.is_empty() {
            return Err(OutputSelectorError::NoEligibleOutputs);
        }

        // Largest-first; ties broken by index ascending.
        // `cover_largest_first` consumes that order and
        // refuses a cover one transaction cannot spend.
        let mut sorted: Vec<&OutputCandidate> = candidates.iter().collect();
        sorted.sort_by(|a, b| b.amount.cmp(&a.amount).then(a.index.cmp(&b.index)));

        let cover = cover_largest_first(
            sorted,
            |candidate| candidate.amount,
            target,
            shekyl_tx_builder::MAX_INPUTS,
        )
        .map_err(|fault| match fault {
            // The error payload carries raw `u64`. Convert
            // at the edge. `available` is the sum of the
            // candidate set: a short cover took all of it.
            LargestFirstFault::Short { needed, available } => {
                OutputSelectorError::InsufficientFunds {
                    needed: needed.to_raw(),
                    available: available.to_raw(),
                }
            }
            LargestFirstFault::TooManyInputs { count } => {
                OutputSelectorError::TooManyInputs { count }
            }
            // Owned-output amounts. The wallet's balance is
            // bounded by supply, so overflow is corrupted
            // state, not a request the user can repair.
            LargestFirstFault::Overflow => {
                panic!("selected-output sum overflowed total supply bound")
            }
        })?;

        // Ascending indices for deterministic downstream
        // consumption (the caller's reservation carries
        // sorted indices, as the pre-PR-5 body did).
        let mut indices: Vec<usize> = cover
            .chosen
            .into_iter()
            .map(|candidate| candidate.index)
            .collect();
        indices.sort();
        // The cover was bounded by the same cap. A miss here
        // means the two checks drifted.
        let indices = SelectedInputs::within_cap(indices)
            .expect("cover_largest_first returned a cover within the cap");

        Ok(SelectedOutputs {
            indices,
            total_covered: cover.total,
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
        OutputCandidate {
            index,
            amount: AtomicUnits::from_raw(amount),
        }
    }

    #[test]
    fn wallet_greedy_selects_largest_first() {
        let candidates = vec![
            candidate(0, 1_000),
            candidate(1, 5_000),
            candidate(2, 3_000),
            candidate(3, 2_000),
        ];
        let target = AtomicUnits::from_raw(6_000);
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Largest-first: pick index 1 (5_000), then index 2
        // (3_000) → covered = 8_000 ≥ 6_000. `indices` is
        // sorted ascending for deterministic consumption.
        assert_eq!(selected.indices.as_slice(), &[1, 2]);
        assert_eq!(selected.total_covered, AtomicUnits::from_raw(8_000));
    }

    #[test]
    fn wallet_greedy_insufficient_funds() {
        let candidates = vec![candidate(0, 1_000), candidate(1, 2_000)];
        let target = AtomicUnits::from_raw(10_000);
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
        let target = AtomicUnits::from_raw(1_000);
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
        let target = AtomicUnits::from_raw(1_000);
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Only one candidate needed; ties broken by
        // ascending index → index 0.
        assert_eq!(selected.indices.as_slice(), &[0]);
        assert_eq!(selected.total_covered, AtomicUnits::from_raw(1_000));
    }

    #[test]
    fn wallet_greedy_total_covered_matches_indices() {
        let candidates = vec![
            candidate(5, 7_000),
            candidate(2, 4_000),
            candidate(9, 2_000),
        ];
        let target = AtomicUnits::from_raw(10_000);
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, target)
            .expect("greedy selector covers target");
        // Verify total_covered is internally consistent with
        // the sum of selected indices' amounts in the
        // candidate set.
        let recomputed: u64 = selected
            .indices
            .as_slice()
            .iter()
            .map(|i| {
                candidates
                    .iter()
                    .find(|c| c.index == *i)
                    .expect(
                        "selected index appears in candidates (F4 caller-side check is structural)",
                    )
                    .amount
                    .to_raw()
            })
            .sum();
        assert_eq!(selected.total_covered, AtomicUnits::from_raw(recomputed));
    }

    /// The shortest cover past the cap is `TooManyInputs` with
    /// that cover's length, not the length of the whole set.
    /// Bites if the selector hands the build an over-cap `Ok`,
    /// or reports every candidate instead of the cover.
    #[test]
    fn wallet_greedy_names_the_shortest_cover_past_the_cap() {
        let cap = shekyl_tx_builder::MAX_INPUTS;
        let candidates: Vec<_> = (0..cap + 4).map(|index| candidate(index, 10)).collect();
        let need = cap + 1;
        let err = WalletGreedyOutputSelector
            .select_outputs(&candidates, AtomicUnits::from_raw(10 * need as u64))
            .expect_err("the cover is one past the cap");
        assert!(
            matches!(err, OutputSelectorError::TooManyInputs { count } if count == need),
            "{err:?}"
        );
    }

    /// A cover of exactly the cap is a selection. Bites on an
    /// off-by-one that refuses the cap itself.
    #[test]
    fn wallet_greedy_accepts_a_cover_of_exactly_the_cap() {
        let cap = shekyl_tx_builder::MAX_INPUTS;
        let candidates: Vec<_> = (0..cap + 2).map(|index| candidate(index, 10)).collect();
        let selected = WalletGreedyOutputSelector
            .select_outputs(&candidates, AtomicUnits::from_raw(10 * cap as u64))
            .expect("the cap's own count is a legal cover");
        assert_eq!(selected.indices.len(), cap);
        assert_eq!(
            selected.total_covered,
            AtomicUnits::from_raw(10 * cap as u64)
        );
    }

    /// The success type rejects a length the transaction cannot
    /// spend, and accepts the cap itself. Bites if the bound
    /// moves off [`shekyl_tx_builder::MAX_INPUTS`].
    #[test]
    fn selected_inputs_refuse_a_length_past_the_cap() {
        let cap = shekyl_tx_builder::MAX_INPUTS;
        assert_eq!(
            SelectedInputs::within_cap((0..cap).collect())
                .expect("the cap fits")
                .len(),
            cap
        );
        assert_eq!(
            SelectedInputs::within_cap((0..=cap).collect()),
            Err(cap + 1)
        );
        assert!(SelectedInputs::within_cap(Vec::new())
            .expect("empty fits")
            .is_empty());
    }

    /// A ranking that cannot cover at any length is short, even
    /// when it is longer than the cap. Bites if the cap check
    /// runs before the shortfall and tells the user to consolidate
    /// a balance that does not exist.
    #[test]
    fn a_short_ranking_is_not_an_input_cap_refusal() {
        let cap = shekyl_tx_builder::MAX_INPUTS;
        let ranked: Vec<u64> = vec![10; cap + 2];
        let err = cover_largest_first(
            ranked,
            |amount| AtomicUnits::from_raw(*amount),
            AtomicUnits::from_raw(10 * (cap as u64 + 3)),
            cap,
        )
        .expect_err("the ranking does not cover");
        assert!(matches!(err, LargestFirstFault::Short { .. }), "{err:?}");
    }
}
