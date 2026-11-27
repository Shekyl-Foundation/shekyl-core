// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The owner's withdrawal of a stake that is still a plan
//! (`ARCHIVAL_BOND_POST_DELAY.md` §3.6, ruled 2026-11-26), reached through
//! `unstake` when the stake has not been signed. Carved beside the composed
//! exit in `unstake_facade.rs`, which resolves what `unstake` does.

use std::sync::Arc;

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::Withdrawal;
use shekyl_types::PCanonicalId;
use tokio::sync::RwLock;

use super::pscan::start::pending_post_store_for_engine;
use super::signer::EngineSignerKind;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine as _, PendingTxEngine, RefreshEngine,
};
use super::unstake_facade::{UnstakeError, UnstakeOutcome};
use super::{Engine, LocalLedger};

/// Withdraw `persona`'s planned stake (BD-Q3 as ruled 2026-11-26), in one
/// confirmed save: the plan ends as withdrawn and its persona's drain is
/// owed. A plan signed between the read and this write refuses: a signed
/// post is never withdrawn.
#[allow(private_bounds, clippy::type_complexity)]
pub(crate) async fn withdraw_plan<S, D, E, R, P>(
    engine: Arc<RwLock<Engine<S, D, LocalLedger, E, R, P, WalletFile>>>,
    gate: Arc<crate::engine::pending_post_gate::PendingPostGate>,
    persona: PCanonicalId,
) -> Result<UnstakeOutcome, UnstakeError>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, LocalLedger, E, R, P, WalletFile>: Send + Sync,
{
    let at_height = engine.read().await.ledger.synced_height();
    let store = pending_post_store_for_engine(engine.clone(), gate);
    let (withdrawal, durability) = store
        .mutate_reporting(|block| {
            let withdrawal = block.withdraw_plan(&persona, at_height);
            (matches!(withdrawal, Withdrawal::Withdrawn(_)), withdrawal)
        })
        .await
        .map_err(|e| UnstakeError::Engine {
            context: "withdraw the planned stake",
            detail: e.to_string(),
        })?;
    match withdrawal {
        Withdrawal::Withdrawn(ended) => {
            // The persona never receives a second funding: it stops being the
            // active one at once, before the save's durability is judged.
            let stake = { engine.read().await.stake_handle() };
            if let Some(stake) = stake {
                stake
                    .deactivate_ended_persona(ended.p_slot)
                    .await
                    .map_err(|e| UnstakeError::Engine {
                        context: "deactivate the withdrawn persona",
                        detail: e.to_string(),
                    })?;
            }
            crate::engine::dispatch_durability::require_confirmed(durability)
                .map_err(UnstakeError::SealNotSaved)?;
            Ok(UnstakeOutcome::Withdrawn)
        }
        Withdrawal::AlreadySigned => Err(UnstakeError::BondConfirming),
        Withdrawal::NoPlan => Err(UnstakeError::ExitInProgress),
    }
}
