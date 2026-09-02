// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Product-surface door for staking: [`Engine::stake`] → [`StakeFacade`].
//!
//! This type is the **ownership cut** for new staking / drain / claim
//! behavior (`ENGINE_COMPOSITION_DECOMPOSITION.md`). Bodies of methods that
//! already existed on [`Engine`] stay in those workflow modules
//! (`principal_stake`, `bond_orchestrator`, `drain_*`, `pscan`, serving);
//! this façade **forwards** to them so GUI/CLI keep compiling against the
//! inherent names. New verbs land here first, not as a new inherent
//! `Engine::` method.
//!
//! [`Engine::stake`] is always a view — including for non-stakers.
//! Handle-gated verbs (`stake_in`) still fail closed inside the body
//! (`StakeInError::NotStaking`). [`Engine::has_stake_engine`] is the
//! predicate for a resident actor. `unstake` / Unbond dispatch is not a
//! product method yet.

use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_units::AtomicUnits;
use tokio::sync::RwLock;

use super::bond_orchestrator::{FirstStakeError, FirstStakeOutcome, StakePosture};
use super::drain_facade::{DrainOutcome, DrainToPrincipalError};
use super::drain_read::DrainBalanceReadError;
use super::pending::PendingTx;
use super::principal_stake::StakeInError;
use super::pscan::start::{PScanHandle, PScanStartError};
use super::stake_engine::serving::{ServingHandle, ServingStartError};
use super::staking_read::{StakingReadError, StakingReadView};
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::{Engine, EngineSignerKind, LocalLedger, LocalRefresh};

/// Borrow of an [`Engine`] for the staking product surface.
///
/// Always constructible ([`Engine::stake`]). Read methods that are valid
/// for non-stakers (`staking_read_view`) are callable here; handle-gated
/// verbs refuse with their existing error types when no
/// [`super::stake_engine::StakeEngineHandle`] is resident.
#[derive(Clone, Copy)]
#[allow(private_bounds)] // same Engine-trait privacy posture as `Engine` itself
pub struct StakeFacade<'a, S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    F: PersistenceEngine,
{
    engine: &'a Engine<S, D, L, E, R, P, F>,
}

#[allow(private_bounds)]
impl<'a, S, D, L, E, R, P, F> StakeFacade<'a, S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    F: PersistenceEngine,
{
    /// Fund the active persona (`Engine::stake_in`).
    pub async fn stake_in(&self, amount: AtomicUnits) -> Result<PendingTx, StakeInError> {
        self.engine.stake_in(amount).await
    }
}

#[allow(private_bounds)]
impl<'a, S, D, E, R, P> StakeFacade<'a, S, D, LocalLedger, E, R, P, WalletFile>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    /// Authoritative staking read (WI-RPC-1). Valid for non-stakers
    /// (honest zeros).
    pub fn staking_read_view(&self) -> Result<StakingReadView, StakingReadError> {
        self.engine.staking_read_view()
    }

    /// [`Self::staking_read_view`] with a caller-supplied ledger snapshot.
    pub fn staking_read_view_with_snapshot(
        &self,
        staking_enabled: bool,
        recovery_pending_reopen: bool,
    ) -> Result<StakingReadView, StakingReadError> {
        self.engine
            .staking_read_view_with_snapshot(staking_enabled, recovery_pending_reopen)
    }

    /// Whether bond-watch adopted a recovered staked slot this session.
    pub fn staking_recovery_pending_reopen(&self) -> bool {
        self.engine.staking_recovery_pending_reopen()
    }
}

#[allow(private_bounds, clippy::type_complexity)]
impl<S, D, L, E, R, P> StakeFacade<'_, S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync,
{
    /// Drain the live active persona's pool to principal.
    pub async fn drain_to_principal(
        engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
        payment: AtomicUnits,
    ) -> Result<DrainOutcome, DrainToPrincipalError> {
        Engine::drain_to_principal(engine, payment).await
    }

    /// Aggregate drainable `P` scalar (F-D2).
    pub async fn drain_balance_aggregate(
        engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
    ) -> Result<AtomicUnits, DrainBalanceReadError> {
        Engine::drain_balance_aggregate(engine).await
    }

    /// Start P-scan iff this wallet is a staker.
    pub async fn start_pscan_if_staker(
        engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
    ) -> Result<Option<PScanHandle>, PScanStartError> {
        Engine::start_pscan_if_staker(engine).await
    }

    /// Start the serving host iff this wallet is a staker with an active persona.
    pub async fn start_serving_if_staker(
        engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
        daemon_address: &str,
    ) -> Result<Option<ServingHandle>, ServingStartError> {
        Engine::start_serving_if_staker(engine, daemon_address).await
    }
}

#[allow(private_bounds, clippy::type_complexity)]
impl<S, D, E, P> StakeFacade<'_, S, D, LocalLedger, E, LocalRefresh, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    E: EconomicsEngine,
    P: PendingTxEngine,
    Engine<S, D, LocalLedger, E, LocalRefresh, P, WalletFile>: Send + Sync,
{
    /// First-stake bond assemble (W2 resume / first call).
    pub async fn first_stake(
        engine: Arc<RwLock<Engine<S, D, LocalLedger, E, LocalRefresh, P, WalletFile>>>,
        slot: u32,
        posture: StakePosture,
    ) -> Result<FirstStakeOutcome, FirstStakeError> {
        Engine::first_stake(engine, slot, posture).await
    }
}

#[allow(private_bounds)]
impl<S, D, L, E, R, P, F> Engine<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    F: PersistenceEngine,
{
    /// Product-surface door for staking. Always a view — including when no
    /// [`StakeEngine`](super::stake_engine::StakeEngine) is resident.
    /// [`Self::has_stake_engine`] is the handle predicate. New staking
    /// behavior lands on [`StakeFacade`], not as a new inherent `Engine`
    /// method.
    ///
    /// Homonym: the crate-private field `stake` is the
    /// [`super::stake_engine::StakeEngineHandle`]; this method is the façade.
    pub fn stake(&self) -> StakeFacade<'_, S, D, L, E, R, P, F> {
        StakeFacade { engine: self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::test_support::{non_staker_engine, staker_engine};
    use crate::engine::StakedBalance;
    use shekyl_units::AtomicUnits;

    const SEED: u8 = 11;

    /// This bites against gating `Engine::stake()` on a resident handle
    /// (so non-staker `staking_info` / `get_staked_balance` would fail
    /// closed). It does NOT cover a corrupt-seal fail-closed path.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_view_serves_honest_zeros_on_a_non_staker() {
        let (_tmp, engine) = non_staker_engine(SEED);
        assert!(
            !engine.has_stake_engine(),
            "the handle predicate is independent of the view"
        );
        let via_facade = engine
            .stake()
            .staking_read_view()
            .expect("a non-staker read is honest zeros, not NotStaking");
        let via_engine = engine
            .staking_read_view()
            .expect("inherent read remains the same answer");
        assert_eq!(via_facade, via_engine);
        assert!(!via_facade.staking_enabled);
        assert_eq!(via_facade.balance, StakedBalance::ZERO);
        assert!(via_facade.outputs.is_empty());
        assert!(via_facade.pscan_synced_height.is_none());
        assert!(!via_facade.recovery_pending_reopen);
    }

    /// This bites against a façade `stake_in` that skipped the handle check.
    /// It does NOT cover the active-persona funding path.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_via_facade_on_a_non_staker_is_not_staking() {
        let (_tmp, engine) = non_staker_engine(SEED);
        let err = engine
            .stake()
            .stake_in(AtomicUnits::from_raw(50_000))
            .await
            .expect_err("a non-staker cannot stake_in");
        assert!(matches!(err, StakeInError::NotStaking), "got {err:?}");
    }

    /// This bites against `has_stake_engine` drifting from the resident
    /// handle. It does NOT cover first-stake assembly.
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_view_and_handle_predicate_agree() {
        let (_tmp, engine) = staker_engine(3, SEED);
        assert!(engine.has_stake_engine());
        let view = engine
            .stake()
            .staking_read_view()
            .expect("a staker read is the same door");
        assert!(view.staking_enabled);
    }
}
