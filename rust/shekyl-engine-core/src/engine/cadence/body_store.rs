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
//!
//! Closing stops a pass in flight. The pass holds the engine while it reads
//! the scan state and the stake engine's store handles after that, so the
//! leg's teardown aborts it and waits until it has dropped them: the
//! embedder's `Arc::try_unwrap → close` never meets a pass, and no store
//! handle outlives the wallet. Aborting is safe at any await: a shard's
//! write is one store transaction, and the reconcile's memory and alarms
//! are this session's and end with it.
//!
//! A pass that panics is this crate's bug. The next advance re-raises its
//! panic from `fire`, so the driver parks the leg as it parks any leg whose
//! fire panics, rather than the leg going quiet.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::AlarmCondition;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::{CadenceLeg, WeakEngine};
use crate::engine::body_reconcile::{ReconcileState, ShardAlarms};
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

/// The body-store leg's state: the session's alarms (shared with the
/// handle that reads them), the reconcile's memory, and the pass in flight.
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
    pub(crate) pass: Arc<PassSlot>,
}

/// The one reconcile pass in flight: single flight for `fire`, and what the
/// leg's teardown stops.
///
/// A `std` mutex, as the driver's serving slot: every access is a brief
/// lock-inspect-release, and no `.await` runs under the guard.
#[derive(Default)]
pub(crate) struct PassSlot(std::sync::Mutex<Option<JoinHandle<()>>>);

impl PassSlot {
    /// Start `pass` unless one is still running, in which case `pass` is
    /// dropped unstarted and this returns `false`.
    ///
    /// # Panics
    ///
    /// Re-raises the panic of the previous pass, if it panicked: the caller
    /// is the leg's `fire`, and the driver parks a leg whose fire panics.
    pub(crate) async fn start<F>(&self, pass: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let previous = {
            let mut slot = self.0.lock().expect("body-store pass slot lock");
            if slot.as_ref().is_some_and(|running| !running.is_finished()) {
                return false;
            }
            slot.replace(tokio::spawn(pass))
        };
        // Finished, so this does not wait. The slot's only abort is
        // `stop`, which empties it, so a finished pass ended or panicked.
        if let Some(finished) = previous {
            if let Err(e) = finished.await {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
            }
        }
        true
    }

    /// Abort the pass in flight, if any, and wait until it has dropped what
    /// it holds.
    pub(crate) async fn stop(&self) {
        let pass = self.0.lock().expect("body-store pass slot lock").take();
        let Some(pass) = pass else {
            return;
        };
        pass.abort();
        match pass.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {}
            Err(_) => tracing::error!(
                "persona body store: the last reconcile pass panicked; the wallet is closing"
            ),
        }
    }
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
        let pass = Arc::clone(&self.pass);
        Box::pin(async move {
            pass.start(async move {
                let Some(engine) = weak.upgrade() else {
                    return;
                };
                let epoch = shekyl_archival_retention::settlement_epoch_at_height(tip);
                let mut state = state.lock().await;
                if let Err(e) =
                    Engine::reconcile_bodies(engine, &daemon, epoch, &mut state, &alarms).await
                {
                    tracing::warn!(
                        error = %e,
                        "persona body store: this pass could not run; the next chain advance \
                         retries"
                    );
                }
            })
            .await;
        })
    }

    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move { self.pass.stop().await })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn a_pass_in_flight_turns_the_next_away_unstarted() {
        let slot = PassSlot::default();
        let (release, held) = oneshot::channel::<()>();
        assert!(
            slot.start(async move {
                held.await.expect("the test releases the pass");
            })
            .await
        );

        let ran = Arc::new(AtomicBool::new(false));
        let second = Arc::clone(&ran);
        assert!(
            !slot
                .start(async move { second.store(true, Ordering::SeqCst) })
                .await,
            "a second pass starts only once the first has finished"
        );

        release.send(()).expect("the first pass is waiting");
        while slot
            .0
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|p| !p.is_finished())
        {
            tokio::task::yield_now().await;
        }
        let third = Arc::clone(&ran);
        assert!(
            slot.start(async move { third.store(true, Ordering::SeqCst) })
                .await
        );
        slot.stop().await;
        assert!(
            ran.load(Ordering::SeqCst),
            "the pass after the first ran; the turned-away one never did"
        );
    }

    #[tokio::test]
    async fn a_panicked_pass_is_raised_by_the_next_start() {
        let slot = Arc::new(PassSlot::default());
        assert!(slot.start(async { panic!("a reconcile bug") }).await);
        while slot
            .0
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|p| !p.is_finished())
        {
            tokio::task::yield_now().await;
        }

        // The driver runs `fire` on a task of its own and parks the leg when
        // that task panics; this is that task.
        let fire = Arc::clone(&slot);
        let joined = tokio::spawn(async move { fire.start(async {}).await }).await;
        let panic = joined.expect_err("the next start re-raises the pass's panic");
        assert!(panic.is_panic());
    }

    #[tokio::test]
    async fn stop_aborts_the_pass_and_waits_for_what_it_holds() {
        let slot = PassSlot::default();
        // Stands in for the engine the pass upgrades to and holds.
        let engine = Arc::new(());
        let held = Arc::clone(&engine);
        assert!(
            slot.start(async move {
                let _held = held;
                std::future::pending::<()>().await;
            })
            .await
        );

        slot.stop().await;
        assert!(
            Arc::try_unwrap(engine).is_ok(),
            "once stop returns, the pass no longer holds the engine"
        );
        assert!(slot.0.lock().unwrap().is_none());
        // Nothing in flight: a no-op.
        slot.stop().await;
    }
}
