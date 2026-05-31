// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `EconomicsEngine` trait surface (§2.7, new in Round 3).
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.7, `EconomicsEngine` is
//! the **canonical economic derivation** surface: base subsidy on the
//! neutral trajectory, the adaptive fee burn, the pool-weighted stake
//! denominator, and the parameter rulebook. It exists to kill the
//! scattered-canonical-derivation bug class (Bugs 2 / 7 / 13 per
//! `16-architectural-inheritance.mdc`) by giving every consumer one
//! place to ask "what does consensus compute here?".
//!
//! # Scope guard (§2.7)
//!
//! `EconomicsEngine` is canonical-derivation **only** — no wallet-side
//! consensus enforcement, no per-stake / per-shard state, no
//! orchestration. Phase 2b's `StakeEngine` and V3.x's `ArchivalEngine`
//! *consume* these four methods; they do **not** extend the trait.
//! Extending `EconomicsEngine` into any of those territories requires an
//! explicit revisit of this scope guard, not silent growth.
//!
//! # V3.0 sync leaf; Stage 4 actor (§2.7 implementing-type note)
//!
//! All four methods are reads, idempotent, and synchronous: there is no
//! actor mailbox at V3.0 and no async cascade. The Stage 1 implementor
//! [`LocalEconomics`](super::super::local_economics::LocalEconomics)
//! holds **no mutable state** — its methods are pure-function wrappers
//! around `shekyl-economics` constants and caller-provided inputs. At
//! V3.x Component 3 (adaptive burn) `LocalEconomics` gains a
//! `Mutex<AdaptiveBurnState>`; at Stage 4 `EconomicsActor` owns the
//! state and queries route through its mailbox. The trait surface is
//! preserved verbatim across all three (§7 invariants), which is why the
//! `Send + Sync + 'static` supertrait bound is carried now — it is the
//! actor-readiness contract, not a V3.0 convenience.
//!
//! # Visibility
//!
//! `pub(crate)` until the JSON-RPC server cutover (V3.2), per the
//! [`traits` module](super) visibility note.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md

use shekyl_economics::ActivityMetric;

use crate::engine::economics_snapshot::EconomicsParametersSnapshot;
use crate::engine::error::EconomicsError;

/// Canonical economic-derivation surface (§2.7). Four sync reads; see
/// the [module docs](self) for the scope guard and the Stage 1 → Stage 4
/// invariant.
pub(crate) trait EconomicsEngine: Send + Sync + 'static {
    /// Trait-error vocabulary; convertible into the orchestrator's
    /// [`EconomicsError`]. The V3.0 implementor uses
    /// `Error = EconomicsError` directly.
    type Error: Into<EconomicsError>;

    /// Base block subsidy at `height` on the **neutral trajectory**
    /// (`release_multiplier = 1` at every block) — not effective
    /// reward (no activity / release-multiplier input) and not
    /// realized emission (actual chain path uses realized multipliers
    /// and burn-adjusted `already_generated`). Legitimate consumers:
    /// supply-curve / schedule projections (e.g. ESF-22 milestones in
    /// [`DESIGN_CONCEPTS.md`](../../../../../../docs/DESIGN_CONCEPTS.md)). Realized emission at a
    /// height requires a future mirror + `realized_emission_at` if the
    /// gated (B) initiative lands.
    ///
    /// At V3.0 (interpretation **(A)**): pure function of `(height, params)`
    /// via `shekyl-economics` — does **not** read `ChainEconomicsSource`.
    /// `Err` is arithmetic overflow only (defensive; should not occur with
    /// checked math). When per-height chain mirror exists, `Err` may gain an
    /// unsynced-height arm without renaming this method.
    // R6: zero V3.0 consumer (§5.5); reopens with the supply-curve / schedule projection consumer.
    #[allow(dead_code)]
    fn base_emission_at(&self, height: u64) -> Result<u64, Self::Error>;

    /// Absolute atomic-unit amount to burn from `fee`, modulated by
    /// `activity` — not a ratio or basis-points field.
    ///
    /// **Staleness contract (PR 7 §6.3 G4).** Returns the burn
    /// consensus *would* compute at `activity.as_of_height`; the actual
    /// on-chain burn at block-connect may differ if the chain advanced
    /// past that height. The trait stays a point estimate — no
    /// tolerance/range, and no consensus-side wallet validation at
    /// V3.0. Any future consumer must consult `activity.as_of_height`
    /// and apply its own staleness policy rather than treating the
    /// return as the realized burn. Coherence of the four
    /// `ActivityMetric` fields as one chain view at `as_of_height` is
    /// the constructor-caller's obligation
    /// ([`ActivityMetric::new`](shekyl_economics::ActivityMetric::new)),
    /// not re-checked here.
    // R6: zero V3.0 consumer (§5.5); reopens with the fee-path / PendingTxEngine burn consumer.
    #[allow(dead_code)]
    fn burn_amount(&self, fee: u64, activity: ActivityMetric) -> Result<u64, Self::Error>;

    /// Canonical total weighted stake across the principal pool — the
    /// denominator intended for Phase 2b's `StakeEngine::projected_yield`
    /// (2026-05-08 disposition). Sourced from chain-mirror state via
    /// `ChainEconomicsSource::active_weighted_stake`, not from wallet-local
    /// `shekyl-staking::Registry` (Bug 2 class).
    ///
    /// **`u128` per Bug 7** — aggregation uses `u128` to prevent overflow at
    /// large pool sizes.
    ///
    /// **Zero is valid, not an error.** A return of `0` means no active stake
    /// at the mirrored height — consensus burns the block's pool contribution
    /// rather than carrying it ([`STAKER_REWARD_DISBURSEMENT.md`](../../../../../../docs/STAKER_REWARD_DISBURSEMENT.md)
    /// §"Empty-staker-set behavior"). Do not treat `0` as a failed read.
    ///
    /// **Callers using this as a denominator must guard division.** `0` is a
    /// live divide-by-zero for yield-style computations; check before dividing.
    ///
    /// **`0` is overloaded.** The same value can mean (a) no active stake at
    /// the relevant height (legitimate) or (b) wallet not synced to that height
    /// / stale mirror (must not be used as denominator). This method is
    /// infallible (`-> u128`) and cannot signal "unknown." Consumers that must
    /// distinguish the cases must verify sync state separately before
    /// interpreting `0`.
    // R6: zero V3.0 consumer (§5.5); reopens with Phase 2b `StakeEngine::projected_yield`.
    #[allow(dead_code)]
    fn pool_weighted_total(&self) -> u128;

    /// Parameter snapshot for governance / display.
    ///
    /// At V3.0 the snapshot is constants-derived and stable in
    /// practice. At V3.x Component 3 the snapshot reflects the
    /// current adaptive-burn state and may change between
    /// calls.
    ///
    /// **Callers must not cache the snapshot beyond the
    /// immediate use.** Even at V3.0 where the value is stable,
    /// the contract permits per-call variation; callers that
    /// cache the snapshot break at V3.x adoption. Treat each
    /// call as fresh; if you need stability across a logical
    /// operation, capture the snapshot at the start of the
    /// operation and use that captured value for its duration,
    /// then discard.
    ///
    /// This is the same forward-compatibility discipline as
    /// §3.4's drop-cancellation: write Stage-4-ready code at
    /// Stage 1 and V3.x-ready code at V3.0.
    ///
    /// **Staleness contract (PR 7 §6.3 G5).** A consumer that must hold
    /// a snapshot across a logical operation captures it once, then
    /// before relying on the captured copy re-fetches a stamp and
    /// compares `as_of.generation` and `as_of.params_digest`: a
    /// mismatch on either means the calibration advanced and the
    /// captured snapshot is stale. At V3.0 the value is display-only —
    /// a stale read has no theft or failed-send consequence — but
    /// writing the generation/digest comparison now keeps consumers
    /// V3.x-ready, where the snapshot tracks live adaptive-burn state.
    // R6: zero V3.0 consumer (§5.5); reopens with the governance / display snapshot consumer.
    #[allow(dead_code)]
    fn parameters_snapshot(&self) -> EconomicsParametersSnapshot;
}
