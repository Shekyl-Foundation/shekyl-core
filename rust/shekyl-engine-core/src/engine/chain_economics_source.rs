// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain-state seam for [`EconomicsEngine`](super::traits::economics::EconomicsEngine)
//! (PR 7 Shape 2′, §4.5.1 / §5.2 B.3 / B.8).
//!
//! [`LocalEconomics`](super::local_economics::LocalEconomics) needs **one**
//! V3.0 chain read — the pool-weighted total stake that backs
//! [`EconomicsEngine::pool_weighted_total`](super::traits::economics::EconomicsEngine::pool_weighted_total).
//! Every other trait method is either a pure projection
//! (`base_emission_at` — reads nothing from chain state) or a pure
//! constants read (`parameters_snapshot`). This module is that single
//! read seam, deliberately **narrow**:
//!
//! - **One method** ([`ChainEconomicsSource::active_weighted_stake`]).
//!   The earlier two-read shape (`already_generated_coins()` +
//!   `active_weighted_stake()`) shrank to one in Round 1 segment 2b
//!   (§5.2 B.3): `already_generated` is computed by projection at V3.0,
//!   not read, so the source carries only the stake total.
//! - **Not a `LedgerEngine` amendment** (Shape 2, rejected §4.5.1):
//!   coupling `EconomicsEngine` to the `LedgerEngine` *trait* would drag
//!   the ledger's full read surface into the economics contract. The
//!   abstract seam here names exactly the one quantity economics needs;
//!   only the concrete production adapter
//!   ([`LedgerChainEconomicsSource`]) knows about [`LocalLedger`].
//! - **Not an `Arc<dyn Fn>` injection** (Shape 1, rejected §4.5.1): a
//!   named trait, not a type-erased closure, so the read seam is
//!   greppable and the test substrate is an ordinary implementor
//!   (`RecordedChainFixture` at C4 — not a `MockEconomics`).
//!
//! # Zero-semantics (§5.2 B.8 / §2.7 `pool_weighted_total` rustdoc)
//!
//! The return is `u128` and **infallible**; `0` is overloaded. It means
//! either a legitimately empty staker set at the mirrored height
//! (consensus burns the pool contribution per
//! [`STAKER_REWARD_DISBURSEMENT.md`](../../../../../docs/STAKER_REWARD_DISBURSEMENT.md)
//! §"Empty-staker-set behavior") **or** an unsynced / stale mirror. An
//! infallible return cannot distinguish the two; a consumer that must
//! (e.g. `StakeEngine::projected_yield`'s divide-by-zero guard) checks
//! sync state separately. The value feeds `pool_weighted_total()`
//! verbatim — single aggregation path, no second reduction.

use std::sync::Arc;

use super::local_ledger::LocalLedger;

/// The single V3.0 chain read [`LocalEconomics`](super::local_economics::LocalEconomics)
/// depends on: the tier-weighted total active stake at the mirrored
/// ledger tip.
///
/// Implementors:
///
/// - [`LedgerChainEconomicsSource`] — production; reads the engine's
///   [`LocalLedger`] staker-pool mirror under one read guard.
/// - `RecordedChainFixture` / `ChainMirrorSource` (C4, `#[cfg(test)]`) —
///   replays sim-recorded `total_weighted_stake` rows so the differential
///   test exercises the **real** `LocalEconomics` code path against a
///   fixture rather than a mock.
///
/// # Read contract (§5.2 R3, normative)
///
/// `active_weighted_stake` reads through a **consistent, height-bound**
/// view — not a racy direct DB peek outside that view. The production
/// adapter takes a single [`RwLock`](std::sync::RwLock) read guard so the
/// staker-pool aggregate it reports cannot tear against a concurrent
/// `apply_scan_result` merge. Reorg atomicity is the mirror's
/// responsibility (`StakerPoolState::handle_reorg` truncates orphaned
/// accrual records), so the value is always bound to a canonical height.
///
/// # Supertrait bounds (Stage 4 readiness)
///
/// `Send + Sync + 'static` mirrors [`LedgerEngine`](super::traits::LedgerEngine)
/// and the other engine traits: a [`LocalEconomics`](super::local_economics::LocalEconomics)
/// generic over the source is itself [`EconomicsEngine`](super::traits::economics::EconomicsEngine),
/// whose `Send + Sync + 'static` actor-readiness bound transitively
/// requires the same of `S`. It is the same contract the production
/// `Arc<LocalLedger>` handle already satisfies.
pub(crate) trait ChainEconomicsSource: Send + Sync + 'static {
    /// Tier-weighted total active stake at the mirrored ledger tip, in
    /// the same `u128` units as `AccrualRecord::total_weighted_stake`
    /// (Bug 7: `u128` to avoid saturation at moderate adoption with
    /// tier multipliers > 1.0). `0` is valid-but-ambiguous — see the
    /// [module docs](self).
    // R6: zero V3.0 consumer (§5.5); reopens with `LocalEconomics::pool_weighted_total`'s consumer.
    #[allow(dead_code)]
    fn active_weighted_stake(&self) -> u128;
}

/// Production [`ChainEconomicsSource`]: reads the engine's
/// [`LocalLedger`] staker-pool mirror.
///
/// Holds the **same** `Arc<LocalLedger>` handle the [`Engine`](super::Engine)
/// shares with its ledger and pending-tx engines, so the economics read
/// sees exactly the state the rest of the engine sees. The adapter is
/// constructed at engine-assembly time (C5) from `Arc::clone(&ledger)`;
/// no separate ledger instance is created.
///
/// [`Engine`]: super::Engine
//
// `pub` (not `pub(crate)`) because it is the default `S` of the `pub`
// `LocalEconomics`, which is in turn the default `E` of the `pub`
// `Engine`; a more-private visibility trips `private_interfaces`. The
// `ChainEconomicsSource` trait stays `pub(crate)`, so the read seam is
// not externally implementable or callable.
pub struct LedgerChainEconomicsSource {
    // R6: read only via `active_weighted_stake`, which has zero V3.0 consumer (§5.5).
    #[allow(dead_code)]
    ledger: Arc<LocalLedger>,
}

impl LedgerChainEconomicsSource {
    /// Wrap a shared [`LocalLedger`] handle. The caller passes
    /// `Arc::clone(&ledger)` from the engine's ledger field so the
    /// economics read and the ledger read paths observe one state.
    pub(crate) fn new(ledger: Arc<LocalLedger>) -> Self {
        Self { ledger }
    }
}

impl ChainEconomicsSource for LedgerChainEconomicsSource {
    fn active_weighted_stake(&self) -> u128 {
        // One read guard: the staker-pool aggregate and the tip it is
        // read at are projected together so the value cannot tear
        // against a concurrent merge (read contract §5.2 R3).
        let guard = self.ledger.read();
        let pool = guard.indexes.staker_pool();
        // The mirror tip (`max_height`) is the most recent accrual
        // height; during normal operation it is <= the ledger's synced
        // height, and `handle_reorg` keeps it on the canonical chain.
        // An empty mirror (no record at the tip) reports `0` — the
        // valid-but-ambiguous empty/unsynced value (module docs).
        pool.get(pool.max_height())
            .map_or(0, |record| record.total_weighted_stake)
    }
}
