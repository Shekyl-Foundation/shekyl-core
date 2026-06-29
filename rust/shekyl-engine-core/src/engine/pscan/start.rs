// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-5 (PR-B) — `Engine::start_pscan`: wire the driving [`run_pscan_task`] to the
//! `Engine`'s real dependencies.
//!
//! Seam choice **(b)**: `start_pscan` is defined only for the file-backed engine
//! (`F = WalletFile`). The `.wallet.pscan` seal is a concrete `WalletFile` concern
//! — it shares the `.wallet.keys` `file_kek`, its swap-refusal is defined relative
//! to `.wallet`, it is `PayloadKind::PScanStatePostcard` in that one sealed-file
//! family — so the entire family stays owned by one type, and the seal stays
//! single-sourced in [`WalletFile::save_pscan_state`]. The general extensibility a
//! `PersistenceEngine` method would buy already exists one layer down: the task is
//! generic over [`PScanStore`], so a future non-file backend implements that trait
//! and wires its own start path (rule 21 reopen criterion: a real second backend
//! appears — not "this might be less abstract").
//!
//! Mirrors [`Engine::start_refresh`]'s self-arc spawn shape: the task outlives any
//! borrow taken at the call site, clones the daemon + stake handle under a brief
//! read lock, then runs unattended until the returned [`PScanHandle`] is cancelled
//! or dropped.

use std::sync::Arc;
use std::time::Duration;

use shekyl_engine_file::{WalletFile, WalletFileError};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_engine_state::WalletLedgerError;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::block_source::DaemonBlockSource;
use super::cadence::FixedRateSchedule;
use super::task::{run_pscan_task, PScanConfig, PScanStore};
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::Engine;

/// Why a P-scan task could not be started. Distinct from [`PScanTaskError`] (the
/// per-sweep, recoverable failures the running loop logs): this is the one-time
/// wiring precondition checked before the spawn.
///
/// [`PScanTaskError`]: super::task::PScanTaskError
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // transient — surfaced once the lifecycle layer calls start_pscan.
pub(crate) enum PScanStartError {
    /// No archival-bond [`StakeEngine`] is running, so there is no persona to scan
    /// as. The stake engine is the `view_sk` vault the scan-step offloads to; with
    /// no vault there is nothing for the P-scan to do.
    ///
    /// [`StakeEngine`]: crate::engine::stake_engine::StakeEngine
    #[error("no archival-bond stake engine is running; nothing to scan as P")]
    NoStakeEngine,
    /// A `P`-scan task is already running for this wallet — the single-flight slot
    /// ([`PScanSlot`](super::task::PScanSlot)) is held. Two tasks would race the
    /// read-modify-seal of the same `.wallet.pscan`.
    #[error("a P-scan task is already running for this wallet")]
    AlreadyRunning,
    /// The sealed `P`-scan state could not be loaded (corrupt / version mismatch).
    /// Surfaced here, before the spawn, rather than as a silent task death — the
    /// caller learns the firewall scan did not start.
    #[error("loading the sealed P-scan state failed: {0}")]
    LoadFailed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A running P-scan task: the cancel token plus the spawned task's join handle.
///
/// Unlike `RefreshHandle` there is no completion channel — the P-scan is a
/// perpetual catch-up loop with no terminal summary; it ends only on cancel. The
/// token fires on both [`cancel`](Self::cancel) and `Drop`, so a dropped handle
/// winds the task down rather than leaking it (the `CancellationToken` is `Arc`'d
/// internally, so the task observes the fire even after the handle's clone drops).
#[allow(dead_code)] // transient — held by the lifecycle layer once it calls start_pscan.
pub(crate) struct PScanHandle {
    cancel_token: CancellationToken,
    // `Option` so [`shutdown`](Self::shutdown) can take the join handle out for
    // `.await` without moving a field out of a `Drop` type.
    join: Option<JoinHandle<()>>,
}

#[allow(dead_code)] // transient — exercised by the lifecycle layer + the e2e tests.
impl PScanHandle {
    /// Fire the cancel token. Idempotent. The task observes it at the next cadence
    /// tick (or mid-`select!`) and exits after its in-flight sweep.
    pub(crate) fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Cancel and await the task's exit. Test/shutdown wind-down: deterministically
    /// observes that the loop has stopped (and released its borrows) before
    /// returning.
    pub(crate) async fn shutdown(mut self) {
        self.cancel_token.cancel();
        if let Some(join) = self.join.take() {
            // A `JoinError` here means the task panicked; on shutdown there is
            // nothing to recover, so we observe the result only to retire it.
            let _outcome = join.await;
        }
    }
}

impl Drop for PScanHandle {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
}

/// The production [`PScanStore`]: reaches the **live** `WalletFile` — held by value
/// inside the `Engine` (no `Arc`, not `Clone`) — through the `Arc<RwLock<Engine>>`
/// under a brief read lock, and delegates the seal to
/// [`WalletFile::save_pscan_state`] / [`WalletFile::open_pscan_state`] (one owner,
/// one definition). The read guard is never held across an `.await`: the seal /
/// open are synchronous, so they run, the guard drops, and only then does decoding
/// proceed.
// `type_complexity`: the `Arc<RwLock<Engine<…>>>` self-arc is the established engine
// background-task shape (cf. `start_refresh`); a type alias would need its own
// `type_alias_bounds` dance for no clarity gain.
#[allow(clippy::type_complexity)]
struct WalletFilePScanStore<S, D, L, E, R, P>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    engine: Arc<RwLock<Engine<S, D, L, E, R, P, WalletFile>>>,
}

/// Run a synchronous file-I/O closure off the async executor's critical path.
///
/// [`tokio::task::block_in_place`] yields the worker for the blocking call, but it
/// **panics** on a `current_thread` runtime — and this crate builds those (e.g.
/// [`drive_persistence`](crate::engine::lifecycle), via `Builder::new_current_thread`).
/// So gate on the flavor: yield the worker on a multi-threaded runtime, and call
/// directly on `current_thread` (where there is no sibling worker to free anyway).
/// The P-scan seal/open is small, infrequent file I/O, so the direct-call block on
/// a single-threaded runtime is acceptable; the point is to never *panic*.
fn run_blocking_io<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::current().runtime_flavor() {
        tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Failures of the file-backed store: either the `WalletFile` seal/open layer, or
/// postcard (de)serialization of the [`PScanState`] body.
#[derive(Debug, thiserror::Error)]
enum WalletFilePScanStoreError {
    /// The `.wallet.pscan` seal/open (envelope, atomic write, swap-refusal, I/O).
    #[error("P-scan file: {0}")]
    File(#[from] WalletFileError),
    /// (De)serializing the `PScanState` body across the seal boundary.
    #[error("P-scan state codec: {0}")]
    Codec(WalletLedgerError),
}

impl<S, D, L, E, R, P> PScanStore for WalletFilePScanStore<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync,
{
    type Error = WalletFilePScanStoreError;

    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PScanState>, Self::Error>> + Send {
        let engine = self.engine.clone();
        async move {
            // Read + open under the lock; the guard drops before we decode. The
            // seal stays single-sourced in `WalletFile` (seam b), which is held by
            // value behind the lock and so cannot move into `spawn_blocking`;
            // `run_blocking_io` instead frees the tokio worker for the synchronous
            // file I/O without relocating the `WalletFile` (no await spans it, so
            // the read guard is fine).
            let body = {
                let g = engine.read().await;
                run_blocking_io(|| {
                    g.persistence()
                        .open_pscan_state(g.state_wrap_key().as_bytes())
                })?
            };
            match body {
                Some(b) => Ok(Some(
                    PScanState::from_postcard_bytes(&b)
                        .map_err(WalletFilePScanStoreError::Codec)?,
                )),
                None => Ok(None),
            }
        }
    }

    fn save(
        &self,
        state: &PScanState,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let engine = self.engine.clone();
        // Encode before taking the lock — the postcard step needs no engine state,
        // so it stays off the critical section.
        let body = state.to_postcard_bytes();
        async move {
            let body = body.map_err(WalletFilePScanStoreError::Codec)?;
            let g = engine.read().await;
            // `run_blocking_io` for the synchronous seal + atomic write: frees the
            // tokio worker (on a multi-threaded runtime) without moving the
            // lock-held `WalletFile` (seam b keeps the seal single-sourced there).
            // No await spans the guard.
            run_blocking_io(|| {
                g.persistence()
                    .save_pscan_state(g.state_wrap_key().as_bytes(), &body)
            })?;
            Ok(())
        }
    }
}

// `private_bounds`: the engine traits are deliberately `pub(crate)` behind the
// `pub` `Engine` (see the `#[allow(private_bounds)]` on the struct itself); every
// engine impl that restates them carries the same allow.
#[allow(private_bounds)]
impl<S, D, L, E, R, P> Engine<S, D, L, E, R, P, WalletFile>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Self: Send + Sync,
{
    /// Spawn the driving P-scan task and return a [`PScanHandle`] to control it.
    ///
    /// Wires the verified layer to the live engine: a [`DaemonBlockSource`] over a
    /// clone of the engine's daemon, the
    /// [`StakeEngineHandle`](crate::engine::stake_engine::StakeEngineHandle)
    /// (`view_sk` vault) for the offloaded scan-step, a [`WalletFilePScanStore`]
    /// over the engine's
    /// `WalletFile` + region-2 wrap key, and a [`FixedRateSchedule`] at `cadence`.
    /// The fixed-rate cadence is deliberate (DQ8): a size-independent tick keeps
    /// retirement invisible on the timing axis.
    ///
    /// # Shape
    ///
    /// Takes `Arc<RwLock<Self>>` (a self-arc) rather than `&self`, mirroring
    /// [`start_refresh`](Self::start_refresh): the spawned task outlives any borrow
    /// at the call site and reaches the live `WalletFile` through the same arc for
    /// each seal.
    ///
    /// # No I/O in this method
    ///
    /// Only a brief read lock to clone the daemon + stake handle. The first network
    /// call (the tip fetch) happens inside the spawned task, so an unreachable
    /// daemon does not stall the caller's `start_pscan.await`.
    ///
    /// # Errors
    ///
    /// - [`PScanStartError::NoStakeEngine`] if no stake engine is running.
    /// - [`PScanStartError::AlreadyRunning`] if a P-scan task already holds the
    ///   single-flight slot for this wallet.
    /// - [`PScanStartError::LoadFailed`] if the sealed state cannot be loaded.
    ///
    /// All per-sweep failures are recoverable and logged by the loop, not here.
    #[allow(dead_code)] // transient — the lifecycle layer is the call site (next).
    pub(crate) async fn start_pscan(
        self_arc: Arc<RwLock<Self>>,
        config: PScanConfig,
        cadence: Duration,
    ) -> Result<PScanHandle, PScanStartError> {
        // Brief read borrow: clone the spawn inputs + claim the single-flight slot.
        // Stake is checked first so a non-staker never claims-then-releases; the
        // slot guard is RAII, so any error below releases it on the early return.
        let (daemon, stake, slot_guard) = {
            let g = self_arc.read().await;
            let stake = g.stake_handle().ok_or(PScanStartError::NoStakeEngine)?;
            let slot_guard = g
                .pscan_slot
                .try_claim()
                .ok_or(PScanStartError::AlreadyRunning)?;
            (g.daemon().clone(), stake, slot_guard)
        };

        let block_source = DaemonBlockSource::new(daemon);
        let store = WalletFilePScanStore {
            engine: self_arc.clone(),
        };

        // Load the sealed state up front (#4): a corrupt / version-mismatched seal
        // surfaces here, not as a silent task death. `slot_guard` drops on this
        // early return, releasing the slot.
        let initial = store
            .load()
            .await
            .map_err(|e| PScanStartError::LoadFailed(Box::new(e)))?;

        let schedule = FixedRateSchedule::new(cadence);
        let cancel_token = CancellationToken::new();

        let join = tokio::spawn(run_pscan_task(
            block_source,
            stake,
            store,
            schedule,
            config,
            initial,
            cancel_token.clone(),
            slot_guard,
        ));

        Ok(PScanHandle {
            cancel_token,
            join: Some(join),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_rpc_transport::SimpleRequestRpc;
    use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};
    use shekyl_units::AtomicUnits;
    use tempfile::TempDir;

    use crate::engine::signer::SoloSigner;
    use crate::engine::{Credentials, DaemonClient, EngineCreateParams};

    /// A `DaemonClient` that never connects — the wiring tests touch the
    /// `WalletFile` + the start precondition, never the network. (Same shape as the
    /// lifecycle suite's helper; replicated because that one is test-private.)
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct SimpleRequestRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    /// Build a real `WalletFile`-backed full engine on a fresh tempdir. Returns the
    /// `TempDir` guard so the wallet files outlive the test body.
    fn create_test_engine() -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"correct horse battery staple");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
        (tmp, engine)
    }

    fn accruals(pairs: &[(u64, u64)]) -> BTreeMap<SettlementEpoch, AtomicUnits> {
        pairs
            .iter()
            .map(|&(e, a)| (SettlementEpoch::from_raw(e), AtomicUnits::from_raw(a)))
            .collect()
    }

    fn pending(pairs: &[(u8, u64)]) -> BTreeMap<PCanonicalId, SettlementEpoch> {
        pairs
            .iter()
            .map(|&(id, e)| {
                (
                    PCanonicalId::from_bytes([id; 32]),
                    SettlementEpoch::from_raw(e),
                )
            })
            .collect()
    }

    /// The (b) seam end-to-end: the `WalletFile`-backed store seals a `PScanState`
    /// to the real `.wallet.pscan` and reopens it byte-faithfully — and a re-seal is
    /// the single durable resume point (crash-recovery: a restart reads exactly the
    /// last sealed state, never a torn or stale one).
    #[tokio::test(flavor = "multi_thread")]
    async fn wallet_file_store_round_trips_a_pscan_state_through_the_real_seal() {
        let (_tmp, engine) = create_test_engine();
        let pscan_path = engine.persistence().pscan_path().to_path_buf();
        let arc = Arc::new(RwLock::new(engine));
        let store = WalletFilePScanStore {
            engine: arc.clone(),
        };

        // Never-scanned-as-P wallet: no seal yet ⇒ load is None (start at genesis).
        assert!(
            store.load().await.expect("load empty").is_none(),
            "absent .wallet.pscan must read as None, not error"
        );
        assert!(!pscan_path.exists(), "no seal exists before the first save");

        // Seal an initial state; reopen it through the real file.
        let state_a = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(5_000)),
            accruals(&[(0, 100), (1, 250)]),
            pending(&[(0xAB, 1)]),
        );
        store.save(&state_a).await.expect("save A");
        assert!(pscan_path.exists(), ".wallet.pscan written by the seal");
        assert_eq!(
            store.load().await.expect("load A").expect("sealed A"),
            state_a,
            "the state round-trips through the real seal"
        );

        // Crash-recovery: the latest seal is the single durable resume point.
        let state_b = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(9_000)),
            accruals(&[(0, 100), (1, 250), (2, 75)]),
            pending(&[(0xAB, 1)]),
        );
        store.save(&state_b).await.expect("save B");
        assert_eq!(
            store.load().await.expect("load B").expect("sealed B"),
            state_b,
            "a restart resumes from the latest sealed state"
        );
    }

    /// The start precondition: with no stake engine running (a fresh, non-staking
    /// wallet) there is no persona to scan as, so `start_pscan` refuses up front
    /// rather than spawning a no-op loop.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_pscan_without_a_stake_engine_returns_no_stake_engine() {
        let (_tmp, engine) = create_test_engine();
        assert!(
            engine.stake_handle().is_none(),
            "a fresh non-staking wallet has no stake engine"
        );
        let arc = Arc::new(RwLock::new(engine));

        let result = Engine::<SoloSigner>::start_pscan(
            arc,
            PScanConfig::production(),
            Duration::from_secs(60),
        )
        .await;

        match result {
            Err(PScanStartError::NoStakeEngine) => {}
            Ok(_) => panic!("expected NoStakeEngine, got a running handle"),
            Err(other) => panic!("expected NoStakeEngine, got {other:?}"),
        }
    }

    /// Single-flight (#1): the slot admits exactly one claimant; a second
    /// `try_claim` fails until the first guard drops, then succeeds again. This is
    /// the primitive `start_pscan` rests on to stop two tasks racing the
    /// `.wallet.pscan` seal (the full path needs a staking engine, exercised by the
    /// lifecycle layer; here we pin the guarantee at the slot).
    #[test]
    fn pscan_slot_admits_one_claimant_at_a_time() {
        let slot = crate::engine::pscan::task::PScanSlot::new();
        assert!(!slot.is_claimed());

        let guard = slot.try_claim().expect("first claim succeeds");
        assert!(slot.is_claimed());
        assert!(slot.try_claim().is_none(), "second claim is refused");

        drop(guard);
        assert!(!slot.is_claimed(), "dropping the guard releases the slot");
        assert!(slot.try_claim().is_some(), "the slot can be reclaimed");
    }

    /// The store's blocking-I/O helper must not panic on a `current_thread` runtime
    /// — a bare `tokio::task::block_in_place` would. `drive_persistence` builds such
    /// runtimes, so the flavor gate is load-bearing, not theoretical.
    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_io_does_not_panic_on_a_current_thread_runtime() {
        let v = run_blocking_io(|| 42);
        assert_eq!(v, 42, "falls back to a direct call instead of panicking");
    }

    /// And it still runs (via `block_in_place`) on a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_blocking_io_runs_on_a_multi_thread_runtime() {
        assert_eq!(run_blocking_io(|| 7), 7);
    }
}
