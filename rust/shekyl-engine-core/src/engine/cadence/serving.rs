// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Leg 2 (`ENGINE_CADENCE_DRIVER.md` §3): serving liveness.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::AlarmCondition;

use super::super::signer::EngineSignerKind;
use super::super::stake_engine::serving::ServingStartError;
use super::super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use super::super::Engine;
use super::{CadenceLeg, ServingSlot, WeakEngine};

/// Predicate — **"a serving obligation exists AND the serving task is not
/// live"** — evaluated every fire; when it holds, one
/// [`Engine::start_serving_if_staker`] attempt. Self-arming: no unregister,
/// no session state, so one condition covers both the start that failed and
/// the serving that started and later died (a Tor drop, a task panic, a
/// lost descriptor). One attempt per chain-progress tick is the natural
/// backoff (≥ block cadence), so a broken Tor config gets no retry storm.
///
/// The *obligation* half of the predicate lives inside
/// `start_serving_if_staker` itself — a non-staker and an idle staker
/// return `Ok(None)` without claiming the serving slot — so the leg's own
/// check is only *liveness*: a parked handle whose task still runs
/// ([`super::super::stake_engine::serving::ServingHandle::is_live`]) is a
/// no-op fire.
///
/// [`ServingStartError::AlreadyRunning`] is a no-op, not a failure. The
/// engine's serving slot guard is the single-flight arbiter between this
/// leg and the embedder's own start (open, restore); the production
/// schedule's first tick is immediate, so the race is real: losing it means
/// the other starter won or is mid-start, and its handle reaches this
/// driver via [`super::CadenceHandle::adopt_serving`].
pub(super) struct ServingLivenessLeg<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    pub(super) engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
    /// The daemon address serving derives its shard set over — threaded from
    /// the embedder at driver start (`into_shared` / `start_cadence`), the
    /// same "the endpoint is the caller's" shape `start_serving_if_staker`
    /// itself documents.
    pub(super) daemon_address: String,
    pub(super) slot: ServingSlot,
}

impl<S, D, L, E, R, P> CadenceLeg for ServingLivenessLeg<S, D, L, E, R, P>
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
        "serving-liveness"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        // Each serving lifecycle carries its own alarm board on its handle
        // (`ServingHandle::alarms`); the driver has no condition to park.
        None
    }

    fn fire(&mut self, _tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let weak = Weak::clone(&self.engine);
        let address = self.daemon_address.clone();
        let slot = Arc::clone(&self.slot);
        Box::pin(async move {
            // Liveness under a brief lock: a live task is the no-op fire; a
            // dead one is taken out for reaping. The `.await`s below run
            // with the guard released.
            let dead = {
                let mut held = slot.lock().expect("serving slot lock");
                match held.as_ref() {
                    Some(handle) if handle.is_live() => return,
                    Some(_) => held.take(),
                    None => None,
                }
            };
            if let Some(dead) = dead {
                // The task has already exited; this observes the exit (and
                // with it the engine slot guard's release) deterministically
                // before the restart below re-claims it.
                dead.shutdown().await;
            }
            let Some(engine) = weak.upgrade() else {
                return;
            };
            match Engine::start_serving_if_staker(engine, &address).await {
                Ok(Some(handle)) => {
                    *slot.lock().expect("serving slot lock") = Some(handle);
                }
                // `Ok(None)`: no obligation — a non-staker, or a staker with
                // no active persona; the predicate simply does not hold this
                // tick. `AlreadyRunning`: the embedder's own start is in
                // flight or won; its handle arrives via `adopt_serving`.
                Ok(None) | Err(ServingStartError::AlreadyRunning) => {}
                Err(e) => {
                    // Named rather than silent (rule 82); the leg retries on
                    // the next chain advance, and repeated failure alarms
                    // through the serving lifecycle's own board once a task
                    // does start and then faults.
                    tracing::warn!(
                        error = %e,
                        "serving-liveness leg: start attempt failed; \
                         retrying on the next chain advance"
                    );
                }
            }
        })
    }

    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(async move {
            let handle = self.slot.lock().expect("serving slot lock").take();
            if let Some(handle) = handle {
                // Awaited: the host stops tor before its listener, and this
                // completing is what lets the embedder's shutdown sequence
                // stop the P-scan only after the advertisement is gone.
                handle.shutdown().await;
            }
        })
    }
}
