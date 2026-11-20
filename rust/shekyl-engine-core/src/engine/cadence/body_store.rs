// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The body-store leg (`WSS-Q4`, `WSS-Q17`): pull what the bond newly owes,
//! reconcile what the store holds against what it owes
//! ([`Engine::reconcile_bodies`]), and check at once a shard the serving
//! path reports.
//!
//! The passes run one at a time on a task of the leg's own, its runner. A
//! body sweep opens every owed shard, which for a `CompleteTree` holder on
//! the Pi 4 floor is minutes of decryption, and the driver awaits each
//! leg's fire in turn: a sweep inline would hold the claim leg behind it.
//! `fire` hands the runner the new tip and returns. Opening the wallet never
//! waits on a pass.
//!
//! The runner wakes for two things:
//!
//! * **A chain advance:** a pass at the new tip. Advances that arrive while
//!   a pass runs become one pass, at the latest of them.
//! * **A serve fault** (`HeldShardSource::report_fault`): a held body that
//!   did not read back as it was opened. A pass at once, at the last tip,
//!   which checks the reported shards the bond owes and refills what is
//!   lost, so a damaged shard is not drawn on until the next scheduled
//!   check. The serving path does not know what is owed; the pass decides.
//!   A report of a shard whose alarm this session is still unanswered
//!   (`failed`, `discarded`) wakes nothing: the pass at each advance
//!   retries a failed refill, and a requester drawing on the shard again
//!   must not make the wallet ask its node again. A report before the first
//!   advance waits for it, and that first pass checks every owed shard.
//!
//! A pass that cannot run (the node unreachable, the scan state unreadable)
//! keeps the shards reported to it for the next pass, and the runner waits
//! for the next advance or report rather than trying again at once.
//!
//! Closing stops the runner: the leg's teardown aborts it and waits until
//! it has dropped what it holds. Between passes that is a weak reference to
//! the engine and the fault queue, which holds neither the engine nor the
//! store. During a pass it holds the engine while it reads the scan state,
//! and the stake engine's store handles after that, so the embedder's
//! `Arc::try_unwrap → close` never meets a pass, and no store handle
//! outlives the wallet. Aborting is safe at any await: a shard's write is
//! one store transaction, and the reconcile's memory and alarms are this
//! session's and end with it.
//!
//! A runner that panics is this crate's bug. The next advance re-raises its
//! panic from `fire`, so the driver parks the leg as it parks any leg whose
//! fire panics, rather than the leg going quiet.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use shekyl_engine_file::WalletFile;
use shekyl_operator_alarm::AlarmCondition;
use shekyl_types::ShardId;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;

use super::{CadenceLeg, WeakEngine};
use crate::engine::body_reconcile::{ReconcileState, ShardAlarms};
use crate::engine::signer::EngineSignerKind;
use crate::engine::stake_engine::body_store_actor::ServeFaults;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

/// The body-store leg: the tip it hands its runner, and the runner.
pub(crate) struct BodyStoreLeg {
    tips: watch::Sender<Option<u64>>,
    /// `None` once a finished runner has been taken by `fire`.
    runner: Option<JoinHandle<()>>,
}

/// How one pass ended, as the runner needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassEnd {
    /// The pass ran.
    Ran,
    /// The pass could not run; the shards reported to it wait for the next.
    CouldNotRun,
    /// The wallet has closed: the runner stops.
    EngineGone,
}

impl BodyStoreLeg {
    /// The production leg over `engine`: its passes are
    /// [`Engine::reconcile_bodies`], and its faults the stake engine's
    /// body store's (none for a wallet without one).
    pub(crate) fn new<S, D, L, E, R, P>(
        engine: WeakEngine<S, D, L, E, R, P, WalletFile>,
        daemon: shekyl_rpc_transport::DaemonTarget,
        alarms: ShardAlarms,
    ) -> Self
    where
        S: EngineSignerKind + Send + Sync + 'static,
        D: DaemonEngine,
        L: LedgerEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        Engine<S, D, L, E, R, P, WalletFile>: Send + Sync + 'static,
    {
        let faults = {
            let engine = Weak::clone(&engine);
            async move {
                let engine = engine.upgrade()?;
                let stake = engine.read().await.stake_handle()?;
                Some(stake.bodies.serve_faults())
            }
        };
        let admits = {
            let alarms = alarms.clone();
            move |shard: ShardId| alarms.wakes_for(shard)
        };
        let state = Arc::new(Mutex::new(ReconcileState::default()));
        let pass = move |tip: u64, suspects: BTreeSet<ShardId>| {
            let engine = Weak::clone(&engine);
            let daemon = daemon.clone();
            let alarms = alarms.clone();
            let state = Arc::clone(&state);
            async move {
                let Some(engine) = engine.upgrade() else {
                    return PassEnd::EngineGone;
                };
                let mut state = state.lock().await;
                match Engine::reconcile_bodies(engine, &daemon, tip, &suspects, &mut state, &alarms)
                    .await
                {
                    Ok(()) => PassEnd::Ran,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "persona body store: this pass could not run; the next chain \
                             advance retries"
                        );
                        PassEnd::CouldNotRun
                    }
                }
            }
        };
        Self::spawn(faults, admits, pass)
    }

    /// Start the runner: `faults` resolves to the queue it wakes on, if any;
    /// `admits` says whether a reported shard wakes a pass; `pass` runs one.
    fn spawn<Faults, Admits, Pass, PassFut>(faults: Faults, admits: Admits, pass: Pass) -> Self
    where
        Faults: Future<Output = Option<ServeFaults>> + Send + 'static,
        Admits: Fn(ShardId) -> bool + Send + 'static,
        Pass: FnMut(u64, BTreeSet<ShardId>) -> PassFut + Send + 'static,
        PassFut: Future<Output = PassEnd> + Send,
    {
        let (tips, tip) = watch::channel(None);
        let runner = tokio::spawn(async move { run(tip, faults.await, admits, pass).await });
        Self {
            tips,
            runner: Some(runner),
        }
    }
}

/// The runner: one pass at a time, on a chain advance or a serve fault.
async fn run<Admits, Pass, PassFut>(
    mut tips: watch::Receiver<Option<u64>>,
    faults: Option<ServeFaults>,
    admits: Admits,
    mut pass: Pass,
) where
    Admits: Fn(ShardId) -> bool,
    Pass: FnMut(u64, BTreeSet<ShardId>) -> PassFut,
    PassFut: Future<Output = PassEnd>,
{
    loop {
        let tip_known = tips.borrow().is_some();
        let woke_by_advance = tokio::select! {
            changed = tips.changed() => {
                if changed.is_err() {
                    // The leg is gone.
                    return;
                }
                true
            }
            () = reported(faults.as_ref()), if tip_known => false,
        };
        // An advance that landed beside a report is still an advance.
        let advanced = woke_by_advance || tips.has_changed().unwrap_or(false);
        let Some(tip) = *tips.borrow_and_update() else {
            continue;
        };
        let taken = faults.as_ref().map(ServeFaults::take).unwrap_or_default();
        let fresh: BTreeSet<ShardId> = taken.fresh.into_iter().filter(|s| admits(*s)).collect();
        let kept: BTreeSet<ShardId> = taken.kept.into_iter().filter(|s| admits(*s)).collect();
        // A report's wake runs a pass only for a fresh report. The wake of
        // a report an advance's pass already took finds none, and shards a
        // pass could not check wait for the next advance or fresh report.
        if !advanced && fresh.is_empty() {
            if let Some(faults) = &faults {
                faults.keep(kept);
            }
            continue;
        }
        let mut suspects = fresh;
        suspects.extend(kept);
        match pass(tip, suspects.clone()).await {
            PassEnd::Ran => {}
            PassEnd::CouldNotRun => {
                if let Some(faults) = &faults {
                    faults.keep(suspects);
                }
            }
            PassEnd::EngineGone => return,
        }
    }
}

/// A report on `faults`; never, without a queue.
async fn reported(faults: Option<&ServeFaults>) {
    match faults {
        Some(faults) => faults.reported().await,
        None => std::future::pending().await,
    }
}

impl CadenceLeg for BodyStoreLeg {
    fn name(&self) -> &'static str {
        "body-store"
    }

    fn park_condition(&self) -> Option<AlarmCondition> {
        None
    }

    fn fire(&mut self, tip: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.tips.send_replace(Some(tip));
        let finished = self.runner.take_if(|runner| runner.is_finished());
        Box::pin(async move {
            // The runner ends on its own only when the wallet has gone, or
            // by a panic, which is raised here for the driver to park.
            if let Some(Err(e)) = match finished {
                Some(runner) => Some(runner.await),
                None => None,
            } {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic());
                }
            }
        })
    }

    fn teardown(self: Box<Self>) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let runner = self.runner;
        Box::pin(async move {
            let Some(runner) = runner else {
                return;
            };
            runner.abort();
            match runner.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {}
                Err(_) => tracing::error!(
                    "persona body store: the reconcile runner panicked; the wallet is closing"
                ),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::{mpsc, Semaphore};

    use super::*;

    fn shards(ids: &[u64]) -> BTreeSet<ShardId> {
        ids.iter().copied().map(ShardId::from_raw).collect()
    }

    /// A runner whose passes report `(tip, suspects)` and wait for a permit
    /// from `gate` before they end, as `outcome` says for the nth pass.
    struct Probe {
        leg: BodyStoreLeg,
        faults: ServeFaults,
        passes: mpsc::UnboundedReceiver<(u64, BTreeSet<ShardId>)>,
        gate: Arc<Semaphore>,
    }

    impl Probe {
        fn start(outcome: impl Fn(usize) -> PassEnd + Send + 'static) -> Self {
            let faults = ServeFaults::default();
            let (sent, passes) = mpsc::unbounded_channel();
            let gate = Arc::new(Semaphore::new(0));
            let count = AtomicUsize::new(0);
            let pass = {
                let gate = Arc::clone(&gate);
                move |tip, suspects| {
                    let nth = count.fetch_add(1, Ordering::SeqCst);
                    sent.send((tip, suspects)).expect("the test is listening");
                    let gate = Arc::clone(&gate);
                    let end = outcome(nth);
                    async move {
                        gate.acquire().await.expect("gate").forget();
                        end
                    }
                }
            };
            let queue = faults.clone();
            let leg = BodyStoreLeg::spawn(async move { Some(queue) }, |_| true, pass);
            Self {
                leg,
                faults,
                passes,
                gate,
            }
        }

        fn advance(&mut self, tip: u64) {
            self.leg.tips.send_replace(Some(tip));
        }

        async fn next_pass(&mut self) -> (u64, BTreeSet<ShardId>) {
            self.passes.recv().await.expect("a pass")
        }

        /// No pass starts while the runtime has nothing else to do.
        async fn no_pass(&mut self) {
            assert!(
                tokio::time::timeout(Duration::from_secs(60), self.passes.recv())
                    .await
                    .is_err(),
                "no pass runs"
            );
        }

        fn finish_passes(&self, n: usize) {
            self.gate.add_permits(n);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn advances_during_a_pass_become_one_pass_at_the_latest() {
        let mut probe = Probe::start(|_| PassEnd::Ran);
        probe.advance(10);
        assert_eq!(probe.next_pass().await, (10, shards(&[])));
        probe.advance(11);
        probe.advance(12);
        probe.finish_passes(1);
        assert_eq!(
            probe.next_pass().await,
            (12, shards(&[])),
            "one pass for the advances that arrived during the last"
        );
        probe.finish_passes(1);
        probe.no_pass().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_serve_fault_runs_a_pass_for_its_shard_without_an_advance() {
        let mut probe = Probe::start(|_| PassEnd::Ran);
        probe.finish_passes(Semaphore::MAX_PERMITS);
        probe.advance(10);
        assert_eq!(probe.next_pass().await, (10, shards(&[])));
        probe.faults.report(ShardId::from_raw(3));
        assert_eq!(
            probe.next_pass().await,
            (10, shards(&[3])),
            "a pass at once, at the last tip, for the reported shard"
        );
        probe.no_pass().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_serve_fault_before_the_first_advance_waits_for_it() {
        let mut probe = Probe::start(|_| PassEnd::Ran);
        probe.finish_passes(Semaphore::MAX_PERMITS);
        probe.faults.report(ShardId::from_raw(3));
        probe.no_pass().await;
        probe.advance(10);
        assert_eq!(probe.next_pass().await, (10, shards(&[3])));
        probe.no_pass().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_that_cannot_run_keeps_its_faults_and_is_not_retried_at_once() {
        let mut probe = Probe::start(|nth| {
            if nth == 0 {
                PassEnd::CouldNotRun
            } else {
                PassEnd::Ran
            }
        });
        probe.finish_passes(Semaphore::MAX_PERMITS);
        probe.faults.report(ShardId::from_raw(3));
        probe.advance(10);
        assert_eq!(probe.next_pass().await, (10, shards(&[3])));
        probe.no_pass().await;
        probe.advance(11);
        assert_eq!(
            probe.next_pass().await,
            (11, shards(&[3])),
            "the next pass checks the shard the last could not"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_report_taken_by_an_advance_does_not_retry_a_pass_that_could_not_run() {
        // The report and the advance land before the runner looks, so the
        // advance's pass takes the report, and the report's wake is still
        // pending when that pass ends.
        let mut probe = Probe::start(|nth| {
            if nth == 0 {
                PassEnd::CouldNotRun
            } else {
                PassEnd::Ran
            }
        });
        probe.finish_passes(Semaphore::MAX_PERMITS);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        probe.faults.report(ShardId::from_raw(3));
        probe.advance(10);
        assert_eq!(probe.next_pass().await, (10, shards(&[3])));
        probe.no_pass().await;
        probe.faults.report(ShardId::from_raw(5));
        assert_eq!(
            probe.next_pass().await,
            (10, shards(&[3, 5])),
            "a fresh report runs a pass, and it carries the kept shard"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_shard_the_alarm_already_names_wakes_no_pass() {
        let faults = ServeFaults::default();
        let (sent, mut passes) = mpsc::unbounded_channel();
        let queue = faults.clone();
        let leg = BodyStoreLeg::spawn(
            async move { Some(queue) },
            |shard: ShardId| shard.to_raw() != 4,
            move |tip, suspects| {
                sent.send((tip, suspects)).expect("listening");
                async { PassEnd::Ran }
            },
        );
        leg.tips.send_replace(Some(10));
        assert_eq!(passes.recv().await, Some((10, shards(&[]))));
        faults.report(ShardId::from_raw(4));
        assert!(
            tokio::time::timeout(Duration::from_secs(60), passes.recv())
                .await
                .is_err(),
            "an unanswered alarm's shard does not wake a pass"
        );
    }

    #[tokio::test]
    async fn teardown_aborts_the_runner_and_waits_for_what_it_holds() {
        // Stands in for the engine the pass upgrades to and holds.
        let engine = Arc::new(());
        let held = Arc::clone(&engine);
        let (started, mut running) = mpsc::unbounded_channel();
        let mut leg = BodyStoreLeg::spawn(
            async { None },
            |_| true,
            move |_, _| {
                let held = Arc::clone(&held);
                started.send(()).expect("listening");
                async move {
                    let _held = held;
                    std::future::pending::<PassEnd>().await
                }
            },
        );
        drop(leg.fire(10));
        running.recv().await.expect("the pass started");
        Box::new(leg).teardown().await;
        assert!(
            Arc::try_unwrap(engine).is_ok(),
            "once teardown returns, the runner no longer holds the engine"
        );
    }

    #[tokio::test]
    async fn a_panicked_runner_is_raised_by_the_next_fire() {
        let mut leg = BodyStoreLeg::spawn(
            async { None },
            |_| true,
            |_, _| async { panic!("a reconcile bug") },
        );
        leg.tips.send_replace(Some(10));
        while !leg.runner.as_ref().is_some_and(JoinHandle::is_finished) {
            tokio::task::yield_now().await;
        }
        // The driver runs `fire` on a task of its own and parks the leg when
        // that task panics; this is that task.
        let joined = tokio::spawn(leg.fire(11)).await;
        let panic = joined.expect_err("the next fire re-raises the runner's panic");
        assert!(panic.is_panic());
    }
}
