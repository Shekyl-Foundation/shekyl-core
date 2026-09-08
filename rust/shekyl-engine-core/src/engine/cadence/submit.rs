// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Leg 1 (`ENGINE_CADENCE_DRIVER.md` §3): submit lifecycle.

use std::future::Future;
use std::pin::Pin;
use std::sync::Weak;

use shekyl_operator_alarm::AlarmCondition;

use super::super::signer::EngineSignerKind;
use super::super::submit_lifecycle::WatchdogHost;
use super::super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::super::Engine;
use super::{CadenceLeg, WeakEngine};

/// One [`Engine::run_submit_lifecycle_tick`] per chain advance. The tick
/// is the `DAEMON_SUBMIT_VERDICT.md` §5.3 driver step (F40 targeted
/// re-scan + escape ladder over every held tx); this leg is its
/// **production caller** — the scheduler §5.3 deferred to "the embedding
/// runtime" and no embedder ever built (design doc §0, the motivating
/// zero-caller month).
///
/// Holds the driver's `Weak`; a failed upgrade is a quiet no-op (the
/// wallet is closing and the loop is about to observe the same via
/// [`super::TipPoll::EngineGone`]). The engine **read** lock is held
/// across the tick's daemon round-trips — same discipline as every RPC
/// handler; the §5.3 constraint is only that no merge *write* lock is
/// held, and the driver's own overlay state has its own mutex precisely
/// so the tick never takes one (see `Engine::submit_driver`).
pub(super) struct SubmitLifecycleLeg<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    F: PersistenceEngine,
{
    pub(super) engine: WeakEngine<S, D, L, E, R, P, F>,
}

impl<S, D, L, E, R, P, F> CadenceLeg for SubmitLifecycleLeg<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine + WatchdogHost,
    F: PersistenceEngine,
    Engine<S, D, L, E, R, P, F>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "submit-lifecycle"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        // The tick raises its own per-tx alarms through the watchdog host's
        // diagnostic sink; the driver has no condition to park for it.
        None
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        Box::pin(async move {
            let Some(engine) = weak.upgrade() else {
                return;
            };
            engine.read().await.run_submit_lifecycle_tick().await;
        })
    }
}
