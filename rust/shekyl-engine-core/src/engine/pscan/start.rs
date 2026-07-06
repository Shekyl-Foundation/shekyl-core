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
//!
//! # Lifecycle (WI-1)
//!
//! The embedder-facing surface is two `pub` entry points:
//!
//! - [`Engine::start_pscan_if_staker`] — the **auto-start** lifecycle call. The
//!   canonical post-open step: after wrapping the opened engine in its
//!   `Arc<RwLock<_>>`, an embedder calls this once; a staker wallet
//!   (`stake.is_some()`) gets its firewalled `P`-scan started, a non-staker gets
//!   `Ok(None)` and pays nothing. Auto-start is the recommended default
//!   (`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` SP-5): the `P`-scan is load-bearing for
//!   funding discovery and unbond/retire reconcile, so a staker wallet that never
//!   scans silently accrues nothing and never retires.
//! - [`Engine::start_pscan`] — the **on-demand** entry mirroring
//!   [`Engine::start_refresh`]'s shape, for embedders that manage the start
//!   moment themselves. Refuses with [`PScanStartError::NoStakeEngine`] for a
//!   non-staker.
//!
//! Both run [`PScanConfig::production`] at [`DEFAULT_PSCAN_CADENCE`] — no public
//! tuning knobs (per `81-no-protocol-knowledge.mdc`, an embedder should not need
//! to know what a finality horizon is). The config-injectable seam stays
//! `pub(crate)` as [`Engine::start_pscan_with`] for tests.
//!
//! # The handle is embedder-held, not engine-held
//!
//! The returned [`PScanHandle`] is owned by the caller (the `RefreshHandle`
//! discipline), **not** stored on the `Engine`. Storing it on the engine would
//! make the pair immortal: the running task's store holds a strong
//! `Arc<RwLock<Engine>>`, so an engine that owned the task's handle could never
//! be dropped (task keeps engine alive; only the engine's drop would cancel the
//! task). Embedder-held inverts that into the correct shutdown order
//! structurally: [`Engine::close`] consumes `self`, which the embedder can only
//! obtain via `Arc::try_unwrap` — impossible while the scan task still holds its
//! clone — so the handle **must** be cancelled/shut down before close can
//! proceed. "Close stops the task" is enforced by ownership, not by convention.
//! Reopen engine-held storage only if the store moves to a `Weak` upgrade-per-
//! sweep shape (a design round of its own, not a lifecycle patch).

use std::sync::Arc;
use std::time::Duration;

use shekyl_engine_file::{WalletFile, WalletFileError};
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_engine_state::WalletLedgerError;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use shekyl_engine_state::PendingPostBlock;
use shekyl_p_transport::TorSocksEndpoint;

use super::block_source::DaemonBlockSource;
use super::cadence::FixedRateSchedule;
use super::dispatch::{BondBroadcast, DispatchConfig, DispatchDriver, PendingSealStore};
use super::task::{run_pscan_task, PScanConfig, PScanStore};
use crate::engine::bond_assembly::PBoundBytes;
use crate::engine::posture::BroadcastPosture;
use crate::engine::signer::EngineSignerKind;
use crate::engine::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, RefreshEngine,
};
use crate::engine::transaction_submitter::{
    BroadcastSubmitError, BroadcastSubmitter, SubmitSuccess,
};
use crate::engine::Engine;

/// Default wall-clock interval between P-scan sweeps (rule 75: rationale + bounds).
///
/// **Rationale.** The P-scan is a catch-up loop over *final* blocks — its sweep
/// ceiling trails the tip by [`ARCHIVAL_REORG_DEPTH_BLOCKS`] (720 blocks ≈ 24 h at
/// the 120 s block target), so per-block reactivity buys nothing: a new block
/// becomes scannable only ~24 h after it is mined, and only ~0.5 blocks cross the
/// finality horizon per minute. Each sweep catches up to the horizon fully
/// (batched internally), so a 60 s tick keeps the steady-state frontier within one
/// block-target of the horizon while the idle-path cost stays negligible (one
/// `tip_height` RPC per tick). The cadence is **fixed-rate and size-independent**
/// (DQ8): ticks fire on schedule regardless of how much work the previous sweep
/// did, so retirement activity stays invisible on the timing axis.
///
/// **Bounds.** Anything in [10 s, 600 s] is safe: below that only wastes RPC on
/// no-op sweeps (nothing new finalizes that fast); above it the scan still keeps
/// up trivially (each sweep clears the whole backlog) but funding-output discovery
/// and unbond/retire reconcile latency degrade for no benefit. The value is not
/// embedder-tunable (per `81-no-protocol-knowledge.mdc`); tests inject their own
/// cadence through [`Engine::start_pscan_with`].
///
/// [`ARCHIVAL_REORG_DEPTH_BLOCKS`]: shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS
pub const DEFAULT_PSCAN_CADENCE: Duration = Duration::from_secs(60);

/// Why a P-scan task could not be started. Distinct from [`PScanTaskError`] (the
/// per-sweep, recoverable failures the running loop logs): this is the one-time
/// wiring precondition checked before the spawn.
///
/// [`PScanTaskError`]: super::task::PScanTaskError
#[derive(Debug, thiserror::Error)]
pub enum PScanStartError {
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
pub struct PScanHandle {
    cancel_token: CancellationToken,
    // `Option` so [`shutdown`](Self::shutdown) can take the join handle out for
    // `.await` without moving a field out of a `Drop` type.
    join: Option<JoinHandle<()>>,
}

impl PScanHandle {
    /// Fire the cancel token. Idempotent. The task observes it at the next cadence
    /// tick (or mid-`select!`) and exits after its in-flight sweep.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    /// Cancel and await the task's exit. Shutdown wind-down: deterministically
    /// observes that the loop has stopped (and released its clone of the engine
    /// arc) before returning — the step that makes a subsequent `Arc::try_unwrap`
    /// → [`Engine::close`](crate::engine::Engine) possible.
    pub async fn shutdown(mut self) {
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

/// The production [`PendingSealStore`] (WI-3 §3.3 / §5 gate 11): same live-file
/// reach as [`WalletFilePScanStore`] — through the engine arc under a brief read
/// lock — delegating the seal to [`WalletFile::save_pending_posts`] /
/// [`WalletFile::open_pending_posts`], the **sole** writer of `.wallet.pending`
/// and the sole `PayloadKind::PendingPostBlockPostcard` encode site. This type
/// adds no second write path; it only carries bytes to that one.
#[allow(clippy::type_complexity)] // same self-arc shape as `WalletFilePScanStore`.
struct WalletFilePendingSealStore<S, D, L, E, R, P>
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

/// Failures of the file-backed pending-post store: the `.wallet.pending`
/// seal/open layer, or postcard (de)serialization of the [`PendingPostBlock`]
/// body (including the fail-closed version refusal — a v1 seal under the v2
/// binary surfaces here, per the WI-3 schema-v2 discipline).
#[derive(Debug, thiserror::Error)]
enum WalletFilePendingStoreError {
    /// The `.wallet.pending` seal/open (envelope, atomic write, swap-refusal, I/O).
    #[error("pending-post file: {0}")]
    File(#[from] WalletFileError),
    /// (De)serializing the `PendingPostBlock` body across the seal boundary.
    #[error("pending-post block codec: {0}")]
    Codec(WalletLedgerError),
}

impl<S, D, L, E, R, P> PendingSealStore for WalletFilePendingSealStore<S, D, L, E, R, P>
where
    S: EngineSignerKind + Send + Sync + 'static,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    Engine<S, D, L, E, R, P, WalletFile>: Send + Sync,
{
    type Error = WalletFilePendingStoreError;

    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PendingPostBlock>, Self::Error>> + Send
    {
        let engine = self.engine.clone();
        async move {
            // Same guard discipline as `WalletFilePScanStore::load`: read + open
            // under the lock, decode after the guard drops; `run_blocking_io` frees
            // the tokio worker for the synchronous file I/O.
            let body = {
                let g = engine.read().await;
                run_blocking_io(|| {
                    g.persistence()
                        .open_pending_posts(g.state_wrap_key().as_bytes())
                })?
            };
            match body {
                Some(b) => Ok(Some(
                    PendingPostBlock::from_postcard_bytes(&b)
                        .map_err(WalletFilePendingStoreError::Codec)?,
                )),
                None => Ok(None),
            }
        }
    }

    fn save(
        &self,
        block: &PendingPostBlock,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let engine = self.engine.clone();
        // Encode before taking the lock — postcard needs no engine state.
        let body = block.to_postcard_bytes();
        async move {
            let body = body.map_err(WalletFilePendingStoreError::Codec)?;
            let g = engine.read().await;
            run_blocking_io(|| {
                g.persistence()
                    .save_pending_posts(g.state_wrap_key().as_bytes(), &body)
            })?;
            Ok(())
        }
    }
}

/// Tor's conventional local SOCKS port. A **placeholder** feeding
/// [`BroadcastSubmitter::for_posture`]'s signature: the hardwired ① `Local`
/// posture below never dials SOCKS (the ① arm ignores the endpoint entirely),
/// but construction must stay on the audited posture→submitter choke point
/// rather than reach around it to a bare submitter.
const TOR_SOCKS_PLACEHOLDER_PORT: u16 = 9050;

/// The production [`BondBroadcast`]: routes every dispatch through the
/// [`BroadcastSubmitter::for_posture`] choke point (posture→submitter binding)
/// and its [`submit_bound`](BroadcastSubmitter::submit_bound) pairing check.
///
/// **Posture is hardwired ① `Local`** — the privacy default (the loopback
/// broadcast originates on the operator's own box; exactly what
/// [`select_broadcast`](crate::engine::posture::select_broadcast) resolves for
/// no-choice + reachable-local). The operator's *explicit* posture choice (an
/// ② `OwnRemote` over `P`'s own circuit, with its per-persona circuit-bound
/// submitter) plugs in here when the 2c config-source slice lands; the seam —
/// per-dispatch construction from `(posture, persona)` — is already the ②
/// shape, so that slice swaps the hardwired value, not this type.
struct LocalBondBroadcast<D> {
    daemon: Arc<D>,
}

impl<D: DaemonEngine> BondBroadcast for LocalBondBroadcast<D> {
    fn submit_bound(
        &self,
        bound: PBoundBytes,
    ) -> impl std::future::Future<Output = Result<SubmitSuccess, BroadcastSubmitError>> + Send {
        let daemon = self.daemon.clone();
        async move {
            let submitter = BroadcastSubmitter::for_posture(
                BroadcastPosture::Local,
                *bound.persona(),
                daemon,
                &TorSocksEndpoint::loopback(TOR_SOCKS_PLACEHOLDER_PORT),
            )
            // The ① arm is infallible (`for_posture` docs): only the ② arm's
            // SOCKS proxy configuration can be rejected, and ① never builds one.
            .expect("the Local arm of for_posture is infallible");
            submitter.submit_bound(bound).await
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
    /// Start the firewalled P-scan **iff this wallet is a staker** — the lifecycle
    /// auto-start call (WI-1, closing 2d-1 SP-5).
    ///
    /// The canonical post-open step: an embedder wraps the opened engine in its
    /// `Arc<RwLock<_>>` and calls this once. A staker wallet (a running
    /// [`StakeEngine`](crate::engine::stake_engine::StakeEngine), i.e. the open
    /// path found `staking_enabled`) gets its P-scan spawned at production
    /// settings; a non-staker gets `Ok(None)` and pays nothing — the "if staker"
    /// gate is this method's job, so the embedder never branches on staking state
    /// itself (per `81-no-protocol-knowledge.mdc`).
    ///
    /// The returned [`PScanHandle`] is embedder-held (see the module docs): call
    /// [`PScanHandle::shutdown`] before `Arc::try_unwrap` →
    /// [`close`](Self::close).
    ///
    /// # Errors
    ///
    /// Everything except the non-staker case propagates from
    /// [`start_pscan`](Self::start_pscan): [`PScanStartError::AlreadyRunning`],
    /// [`PScanStartError::LoadFailed`]. A non-staker is `Ok(None)`, not an error —
    /// for this call the absent stake engine is the expected quiet path, not a
    /// wiring failure.
    pub async fn start_pscan_if_staker(
        self_arc: Arc<RwLock<Self>>,
    ) -> Result<Option<PScanHandle>, PScanStartError> {
        if self_arc.read().await.stake_handle().is_none() {
            return Ok(None);
        }
        // Benign TOCTOU: the stake engine is set at open and never unset during a
        // session, so a re-check inside `start_pscan` can only agree.
        Self::start_pscan(self_arc).await.map(Some)
    }

    /// Spawn the driving P-scan task at production settings and return a
    /// [`PScanHandle`] to control it — the on-demand entry, mirroring
    /// [`start_refresh`](Self::start_refresh)'s shape.
    ///
    /// Runs [`PScanConfig::production`] at [`DEFAULT_PSCAN_CADENCE`]; there are no
    /// public tuning knobs (the finality horizon is a consensus constant and the
    /// cadence has a documented default + bounds — nothing an embedder should
    /// choose). Unlike [`start_pscan_if_staker`](Self::start_pscan_if_staker),
    /// calling this on a non-staker is an error
    /// ([`PScanStartError::NoStakeEngine`]): the caller asked for a scan that
    /// cannot exist.
    ///
    /// # Errors
    ///
    /// - [`PScanStartError::NoStakeEngine`] if no stake engine is running.
    /// - [`PScanStartError::AlreadyRunning`] if a P-scan task already holds the
    ///   single-flight slot for this wallet.
    /// - [`PScanStartError::LoadFailed`] if the sealed state cannot be loaded.
    pub async fn start_pscan(self_arc: Arc<RwLock<Self>>) -> Result<PScanHandle, PScanStartError> {
        Self::start_pscan_with(self_arc, PScanConfig::production(), DEFAULT_PSCAN_CADENCE).await
    }

    /// Spawn the driving P-scan task with explicit `config` + `cadence` — the
    /// injectable seam behind [`start_pscan`](Self::start_pscan), crate-visible
    /// for tests that need a tight cadence or a shallow horizon.
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
    pub(crate) async fn start_pscan_with(
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

        // The WI-3 dispatch driver's broadcast seam shares the daemon (one more
        // clone before `daemon` moves into the block source).
        let broadcast = LocalBondBroadcast {
            daemon: Arc::new(daemon.clone()),
        };
        let block_source = DaemonBlockSource::new(daemon);
        let store = WalletFilePScanStore {
            engine: self_arc.clone(),
        };

        // WI-3: the block-timed bond-post dispatch driver, ticked at the end of
        // every sweep (`ARCHIVAL_BOND_WI3_DISPATCH.md` §3.1). The dispersal draw
        // spans the sweep cadence — the tick interval is exactly the phase window
        // the send-time decorrelation must cover.
        let dispatch = DispatchDriver::new(
            WalletFilePendingSealStore {
                engine: self_arc.clone(),
            },
            broadcast,
            DispatchConfig::production(cadence),
        );

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
            dispatch,
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

        // Seal an initial state; reopen it through the real file. Include bond-post
        // matches so the privacy-sensitive reconcile evidence is exercised through the
        // real `.wallet.pscan` AEAD seal + atomic write, not just postcard.
        let state_a = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(5_000), [0x1A; 32]),
            accruals(&[(0, 100), (1, 250)]),
            pending(&[(0xAB, 1)]),
            vec![
                shekyl_engine_state::pscan_state::BondPostRecord {
                    height: BlockHeight::from_raw(1_200),
                    p_canonical_id: PCanonicalId::from_bytes([0xAB; 32]),
                    post_kind: 0,
                },
                shekyl_engine_state::pscan_state::BondPostRecord {
                    height: BlockHeight::from_raw(4_900),
                    p_canonical_id: PCanonicalId::from_bytes([0xCD; 32]),
                    post_kind: 2,
                },
            ],
            Vec::new(),
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
            PScanCursor::at(BlockHeight::from_raw(9_000), [0x2B; 32]),
            accruals(&[(0, 100), (1, 250), (2, 75)]),
            pending(&[(0xAB, 1)]),
            Vec::new(),
            Vec::new(),
        );
        store.save(&state_b).await.expect("save B");
        assert_eq!(
            store.load().await.expect("load B").expect("sealed B"),
            state_b,
            "a restart resumes from the latest sealed state"
        );
    }

    /// The start precondition: with no stake engine running (a fresh, non-staking
    /// wallet) there is no persona to scan as, so the on-demand `start_pscan`
    /// refuses up front rather than spawning a no-op loop.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_pscan_without_a_stake_engine_returns_no_stake_engine() {
        let (_tmp, engine) = create_test_engine();
        assert!(
            engine.stake_handle().is_none(),
            "a fresh non-staking wallet has no stake engine"
        );
        let arc = Arc::new(RwLock::new(engine));

        let result = Engine::<SoloSigner>::start_pscan(arc).await;

        match result {
            Err(PScanStartError::NoStakeEngine) => {}
            Ok(_) => panic!("expected NoStakeEngine, got a running handle"),
            Err(other) => panic!("expected NoStakeEngine, got {other:?}"),
        }
    }

    /// The lifecycle auto-start on a **non-staker** is the quiet path: `Ok(None)`,
    /// no error, no task — the embedder calls it unconditionally after open and
    /// never branches on staking state itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn start_pscan_if_staker_is_none_for_a_non_staker() {
        let (_tmp, engine) = create_test_engine();
        let arc = Arc::new(RwLock::new(engine));

        let started = Engine::<SoloSigner>::start_pscan_if_staker(arc.clone())
            .await
            .expect("non-staker auto-start must not error");
        assert!(started.is_none(), "a non-staker gets no P-scan task");

        // Nothing claimed the single-flight slot: the quiet path really did nothing.
        assert!(
            !arc.read().await.pscan_slot.is_claimed(),
            "the quiet path must not claim the P-scan slot"
        );
    }

    /// The staker lifecycle end-to-end: `start_pscan_if_staker` on a staker wallet
    /// spawns the task (the single-flight slot is claimed), a second start is
    /// refused with [`PScanStartError::AlreadyRunning`], and `shutdown` releases
    /// both the slot and the task's engine-arc clone — after which
    /// `Arc::try_unwrap` succeeds and [`Engine::close`] can run. That last step is
    /// the "close stops the task" property, enforced by ownership (see the module
    /// docs): close is unreachable *until* the handle has been shut down.
    ///
    /// The daemon is a never-connecting stub, which is fine on purpose: a failed
    /// tip fetch is a recoverable per-sweep error the loop logs and retries, so
    /// the task stays alive for the lifecycle assertions without a chain.
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_auto_start_single_flight_and_shutdown_releases_the_engine() {
        use shekyl_engine_file::SafetyOverrides;

        use crate::engine::stake_engine::PSlot;
        use crate::engine::OpenedEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"correct horse battery staple");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network = params.network;

        // Become a staker: persist a bond record (sets `staking_enabled`), then
        // reopen — the open path spawns the StakeEngine for a staker.
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
        engine
            .persist_bond_record(PSlot(3))
            .expect("persist bond record");
        engine.close(&creds).expect("close created wallet");

        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen staker wallet");
        assert!(matches!(opened, OpenedEngine::Loaded(_)));
        let engine = opened.into_wallet();
        assert!(
            engine.stake_handle().is_some(),
            "a staker reopen spawns the StakeEngine"
        );
        let arc = Arc::new(RwLock::new(engine));

        // Auto-start: a staker gets a running P-scan task.
        let handle = Engine::<SoloSigner>::start_pscan_if_staker(arc.clone())
            .await
            .expect("staker auto-start succeeds")
            .expect("a staker gets a P-scan handle");
        assert!(
            arc.read().await.pscan_slot.is_claimed(),
            "the running task holds the single-flight slot"
        );

        // Double-start is refused while the first task runs.
        match Engine::<SoloSigner>::start_pscan(arc.clone()).await {
            Err(PScanStartError::AlreadyRunning) => {}
            Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
            Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
        }
        // ... and through the auto-start entry too.
        match Engine::<SoloSigner>::start_pscan_if_staker(arc.clone()).await {
            Err(PScanStartError::AlreadyRunning) => {}
            Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
            Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
        }

        // Shutdown: the task exits, releasing the slot and its engine-arc clone.
        handle.shutdown().await;
        assert!(
            !arc.read().await.pscan_slot.is_claimed(),
            "shutdown releases the single-flight slot"
        );

        // The embedder is now the sole owner, so close is reachable — the
        // ownership-enforced "close stops the task" order.
        let engine = Arc::try_unwrap(arc)
            .unwrap_or_else(|_| panic!("the shut-down task must not hold the engine arc"))
            .into_inner();
        engine.close(&creds).expect("close after shutdown");
    }

    /// A stopped scan can be started again: the slot is reusable across
    /// start → shutdown → start within one session (restart-after-stop is an
    /// ordinary lifecycle, not a wedged state).
    #[tokio::test(flavor = "multi_thread")]
    async fn pscan_can_be_restarted_after_shutdown() {
        use shekyl_engine_file::SafetyOverrides;

        use crate::engine::stake_engine::PSlot;

        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"correct horse battery staple");
        let seed = fixed_seed();
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network = params.network;

        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create wallet");
        engine
            .persist_bond_record(PSlot(0))
            .expect("persist bond record");
        engine.close(&creds).expect("close created wallet");
        let engine = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen staker wallet")
        .into_wallet();
        let arc = Arc::new(RwLock::new(engine));

        let first = Engine::<SoloSigner>::start_pscan(arc.clone())
            .await
            .expect("first start");
        first.shutdown().await;

        let second = Engine::<SoloSigner>::start_pscan(arc.clone())
            .await
            .expect("restart after shutdown succeeds");
        second.shutdown().await;
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
