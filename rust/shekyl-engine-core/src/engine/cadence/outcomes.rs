// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pending-outcomes leg: re-derives the pending-funds integrity alarm
//! on every fire from durable state: the `spent_elsewhere` outcomes, and the
//! stakes the end-date release holds because every reserved input is spent
//! with no confirmation seen (`WALLET_RPC_STAKING_OUTCOMES.md` WR-Q3).
//!
//! The outcome is written by the dispatch driver when a record reaches its
//! end date with part of its reservation spent by another transaction; a
//! stake with all of it spent is held instead, in the pending seal. Both are
//! the system of record; the board's alarm is `LatchedRederived`, so this leg
//! re-raises it after every restart until the outcome is acknowledged and no
//! held stake remains.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_engine_state::pending_post_block::OutcomeKind;
use shekyl_engine_state::PendingPostBlock;
use shekyl_operator_alarm::{AlarmCondition, OperatorAlarms};

use crate::engine::signer::EngineSignerKind;
use crate::engine::staking_outcomes::held_spent_stakes;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

use super::{CadenceLeg, WeakEngine};

/// How many records in `block` carry a `spent_elsewhere` outcome.
pub(super) fn spent_elsewhere_count(block: &PendingPostBlock) -> u64 {
    let n = block
        .outcomes()
        .iter()
        .filter(|o| o.outcome == OutcomeKind::SpentElsewhere)
        .count();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// One read of the two sealed staking files per chain advance, mapped onto the
/// board by `shekyl_operator_alarm::cadence::apply_pending_outcomes`.
///
/// A wallet with no pending seal (a non-staker) reports nothing: its board has
/// no row for this condition, which reads as "not watched" rather than "not
/// checking", the same as the claim leg's. A seal that will not open is
/// logged and reports nothing this fire; it is not read as "no outcomes".
pub(super) struct PendingOutcomeLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    pub(super) engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    pub(super) alarms: Arc<OperatorAlarms>,
}

impl<S, D, L, E, R, P> CadenceLeg for PendingOutcomeLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "pending-outcomes"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        Some(AlarmCondition::PendingFundsIntegrity)
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let alarms = Arc::clone(&self.alarms);
        Box::pin(async move {
            let Some(engine) = weak.upgrade() else {
                return;
            };
            let read = engine.read().await.sealed_staking_records();
            match read {
                Ok((pscan, Some(block))) => {
                    let held = held_spent_stakes(&block, pscan.as_ref());
                    shekyl_operator_alarm::cadence::apply_pending_outcomes(
                        &alarms,
                        spent_elsewhere_count(&block),
                        u64::try_from(held.len()).unwrap_or(u64::MAX),
                    );
                }
                Ok((_, None)) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "pending-outcomes leg: the pending seal did not open");
                }
            }
        })
    }
}
