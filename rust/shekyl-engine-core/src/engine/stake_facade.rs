// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Product-surface door for staking: [`Engine::stake`] → [`StakeFacade`].
//!
//! Bodies stay in the existing workflow modules (`principal_stake`,
//! `bond_orchestrator`, `drain_*`, `pscan`, serving). This type is the
//! **ownership cut**: new staking / drain / claim behavior lands here, not
//! as a new inherent `Engine::` method (`ENGINE_COMPOSITION_DECOMPOSITION.md`).
//! `unstake` / Unbond dispatch is not a product method yet.

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

/// Borrow of an [`Engine`] that has a resident [`super::stake_engine::StakeEngineHandle`].
///
/// [`Engine::stake`] returns `None` when this wallet is not a staker. Read
/// methods that are valid for non-stakers (`staking_read_view`) stay callable
/// on `Engine` directly; prefer this type when the caller already knows it is
/// in the staking product surface.
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
    pub(crate) fn for_engine(engine: &'a Engine<S, D, L, E, R, P, F>) -> Option<Self> {
        engine.has_stake_engine().then_some(Self { engine })
    }

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
    /// Authoritative staking read (WI-RPC-1).
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
    /// Product-surface door for staking. `None` if no
    /// [`StakeEngine`](super::stake_engine::StakeEngine) is resident. New
    /// staking behavior lands on [`StakeFacade`], not as a new inherent
    /// `Engine` method.
    pub fn stake(&self) -> Option<StakeFacade<'_, S, D, L, E, R, P, F>> {
        StakeFacade::for_engine(self)
    }
}
