// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The body-store leg (`WSS-Q4`, `WSS-Q17`): each chain advance, pull what
//! the bond newly owes and, when due, reconcile what the store holds against
//! what it owes ([`Engine::reconcile_bodies`]).
//!
//! The pass runs on a task of its own, one at a time. A body sweep opens
//! every owed shard, which for a `CompleteTree` holder on the Pi 4 floor is
//! minutes of decryption, and the loop awaits each leg's fire in turn: a
//! sweep inline would hold the claim leg behind it. An advance that finds a
//! pass still running skips this leg's tick; the next advance tries again.
//! Opening the wallet never waits on a pass.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::AlarmCondition;
use tokio::sync::Mutex;

use super::{CadenceLeg, WeakEngine};
use crate::engine::body_reconcile::{ReconcileState, ShardAlarms};
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

/// The body-store leg's state: the session's alarms (shared with the
/// handle that reads them), the reconcile's memory, and the single-flight
/// flag.
pub(crate) struct BodyStoreLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    pub(crate) engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    pub(crate) daemon: shekyl_rpc_transport::DaemonTarget,
    pub(crate) alarms: ShardAlarms,
    pub(crate) state: Arc<Mutex<ReconcileState>>,
    pub(crate) running: Arc<AtomicBool>,
}

impl<S, D, L, E, R, P> CadenceLeg for BodyStoreLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "body-store"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        None
    }

    fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let daemon = self.daemon.clone();
        let alarms = self.alarms.clone();
        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        Box::pin(async move {
            if running.swap(true, Ordering::AcqRel) {
                return;
            }
            tokio::spawn(async move {
                if let Some(engine) = weak.upgrade() {
                    let epoch = shekyl_archival_retention::settlement_epoch_at_height(tip);
                    let mut state = state.lock().await;
                    if let Err(e) =
                        Engine::reconcile_bodies(engine, &daemon, epoch, &mut state, &alarms).await
                    {
                        tracing::warn!(
                            error = %e,
                            "persona body store: this pass could not run; the next chain \
                             advance retries"
                        );
                    }
                }
                running.store(false, Ordering::Release);
            });
        })
    }
}
