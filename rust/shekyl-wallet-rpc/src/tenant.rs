// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tenant isolation type for wallet-dir multi-tenancy.
//!
//! Phase 4b: single-tenant process holds at most one open
//! [`Engine`](shekyl_engine_core::Engine). The Engine is stored behind
//! `Arc<RwLock<_>>` so long-running work (`refresh` via
//! [`Engine::start_refresh`]) does not hold the process-level tenant
//! mutex, and so concurrent read RPCs can share the Engine under a
//! read lock. The send lifecycle (`build_pending_tx` / `submit_pending_tx`
//! / `discard_pending_tx`) also runs under the read lock: slow work
//! (FCMP++ assembly, daemon submit RPC) is serialized by
//! `LocalPendingTx`'s interior mutability and its engine-owned build
//! permit, not by this lock, so reads proceed during build and submit.
//! Multi-tenant `--wallet-dir` exchanges extend this seam later
//! (`WALLET_REWRITE_PLAN.md`).

use shekyl_engine_core::{Engine, PScanHandle, SoloSigner};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::WalletRpcError;

/// Shared handle to the open Engine (read/write under the inner lock).
pub type SharedEngine = Arc<RwLock<Engine<SoloSigner>>>;

/// One wallet-bearing tenant inside the RPC process.
///
/// `Debug` is hand-written rather than derived because [`PScanHandle`] is not
/// `Debug` (a live task handle renders nothing useful); the manual impl reports
/// only whether a P-scan task is parked, not its internals.
#[derive(Default)]
pub struct Tenant {
    /// Wallet file stem currently open, if any.
    open_name: Option<String>,
    /// Open Engine handle (FULL capability, SoloSigner).
    engine: Option<SharedEngine>,
    /// Embedder-held P-scan task handle for the open wallet (WI-1).
    ///
    /// A **staker** open/create spawns the driving P-scan task via
    /// [`Engine::start_pscan_if_staker`] and parks its handle here for the
    /// wallet's whole open lifetime; a non-staker parks `None`. The task holds
    /// its own clone of the engine arc, so
    /// [`close_wallet`](crate::lifecycle::close_wallet)
    /// must [`PScanHandle::shutdown`] this handle (awaiting the task's exit and
    /// the release of that clone) **before** `Arc::try_unwrap` — a live handle
    /// otherwise blocks the unwrap and the close would fail-loud as "still in
    /// use." The handle is carried atomically with the engine through
    /// [`take_open`](Self::take_open) / [`restore_open`](Self::restore_open) so
    /// no lifecycle transition can strand one without the other.
    pscan: Option<PScanHandle>,
    /// True while `create_wallet` / `open_wallet` is doing slow work
    /// (daemon connect, Argon2) *outside* the tenant mutex. Prevents a
    /// concurrent create/open from racing past `is_open` while the first
    /// call has released the mutex. Cleared on success (`set_open`) or
    /// failure ([`Self::clear_opening`]).
    opening: bool,
    /// True while `close_wallet` has taken the engine out of the slot
    /// ([`Self::take_open`]) and is unwrapping / persisting *outside* the
    /// tenant mutex. Prevents a concurrent create/open from claiming the
    /// temporarily-empty slot mid-close — the close's failure path re-installs
    /// via [`Self::set_open`] / [`Self::restore_open`], whose empty-slot
    /// asserts would otherwise panic the server. Set by `take_open`; cleared
    /// by the re-install paths or [`Self::clear_closing`] on close success.
    closing: bool,
}

impl Tenant {
    /// Construct an empty (no wallet open) tenant.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a wallet is currently open on this tenant.
    pub fn is_open(&self) -> bool {
        self.engine.is_some()
    }

    /// Whether a lifecycle transition (create/open/close) is in flight or a
    /// wallet is already open.
    ///
    /// Lifecycle create/open refuse with `-29000` when this is true.
    pub fn is_busy(&self) -> bool {
        self.is_open() || self.opening || self.closing
    }

    /// Mark create/open in flight. Caller must hold the tenant mutex and
    /// have already checked [`Self::is_busy`].
    pub fn begin_opening(&mut self) {
        debug_assert!(!self.is_busy());
        self.opening = true;
    }

    /// Clear the in-flight create/open reservation (error path).
    pub fn clear_opening(&mut self) {
        self.opening = false;
    }

    /// Open wallet stem, if any.
    pub fn open_name(&self) -> Option<&str> {
        self.open_name.as_deref()
    }

    /// Clone the shared Engine handle, if a wallet is open.
    pub fn engine(&self) -> Option<SharedEngine> {
        self.engine.clone()
    }

    /// Install a freshly created / opened engine (already wrapped in its
    /// [`SharedEngine`] arc) and its P-scan handle as the open wallet.
    ///
    /// The caller wraps the engine and starts the P-scan task
    /// ([`Engine::start_pscan_if_staker`]) *before* this call, so the
    /// arc-and-handle land together and a staker's scan is live the moment the
    /// wallet is reachable. `pscan` is `None` for a non-staker.
    ///
    /// # Panics
    ///
    /// Panics if a wallet is already open — callers must check
    /// [`Self::is_open`] and return `-29000` first.
    pub fn set_open(
        &mut self,
        name: impl Into<String>,
        engine: SharedEngine,
        pscan: Option<PScanHandle>,
    ) {
        assert!(
            self.engine.is_none(),
            "set_open called while a wallet is already open"
        );
        self.opening = false;
        self.closing = false;
        self.open_name = Some(name.into());
        self.engine = Some(engine);
        self.pscan = pscan;
    }

    /// Take the open engine (for [`Engine::close`]), clearing the tenant slot.
    ///
    /// The name/engine pair is taken atomically: if either field is missing the
    /// other is restored and this returns `None`, so a broken pair cannot clear
    /// only the stem and leave an undiagnosable half-empty slot.
    ///
    /// On success the tenant is marked *closing* — [`Self::is_busy`] stays true
    /// so a concurrent create/open cannot claim the emptied slot while the
    /// close is unwrapping / persisting outside the tenant mutex. Every close
    /// outcome must clear the reservation: the failure paths re-install via
    /// [`set_open`](Self::set_open) / [`restore_open`](Self::restore_open)
    /// (which clear it), and the success path calls
    /// [`clear_closing`](Self::clear_closing).
    ///
    /// The caller should [`PScanHandle::shutdown`] the returned P-scan handle
    /// (if any) and then [`Arc::try_unwrap`](std::sync::Arc::try_unwrap) the
    /// engine handle before close. Shutting the task down first is what lets the
    /// unwrap succeed — the task holds its own clone of the engine arc. If other
    /// clones still exist afterward (e.g. an in-flight refresh), the caller must
    /// [`restore_open`](Self::restore_open) all three — name, engine, and P-scan
    /// handle — and fail loud rather than evicting the still-live wallet.
    pub fn take_open(&mut self) -> Option<(String, SharedEngine, Option<PScanHandle>)> {
        match (self.open_name.take(), self.engine.take()) {
            (Some(name), Some(engine)) => {
                self.closing = true;
                // The P-scan handle rides out with the engine so the two never
                // separate across a lifecycle transition.
                Some((name, engine, self.pscan.take()))
            }
            (None, None) => None,
            (name, engine) => {
                // Invariant: both are Some together, or both None. Restore both
                // so a bug / future refactor cannot lose the stem alone.
                debug_assert!(
                    false,
                    "tenant invariant violated: open_name/engine mismatch"
                );
                self.open_name = name;
                self.engine = engine;
                None
            }
        }
    }

    /// Re-install the (name, engine, P-scan handle) triple previously removed by
    /// [`take_open`](Self::take_open) when the close attempt could not proceed
    /// (another task still holds a clone, or reservations are outstanding).
    /// Inverse of `take_open`.
    ///
    /// The caller passes a **freshly restarted** P-scan handle (or `None` for a
    /// non-staker): the one `take_open` yielded was already shut down before the
    /// abandoned `Arc::try_unwrap`, so leaving a still-open staker wallet without
    /// re-arming its scan would silently go dark. Re-arming here keeps the
    /// wallet's post-restore state indistinguishable from never-closed.
    ///
    /// # Panics
    ///
    /// Panics if a wallet is already open — the slot must be empty, which it is
    /// on the close path that just called `take_open`.
    pub fn restore_open(&mut self, name: String, engine: SharedEngine, pscan: Option<PScanHandle>) {
        assert!(
            self.engine.is_none(),
            "restore_open called while a wallet is already open"
        );
        self.closing = false;
        self.open_name = Some(name);
        self.engine = Some(engine);
        self.pscan = pscan;
    }

    /// Clear the in-flight close reservation after the engine has been
    /// successfully persisted and dropped (close success path). The failure
    /// paths clear it implicitly by re-installing via
    /// [`set_open`](Self::set_open) / [`restore_open`](Self::restore_open).
    pub fn clear_closing(&mut self) {
        self.closing = false;
    }

    /// Whether a P-scan task is parked for the open wallet.
    ///
    /// Two consumers: the `stake` entry, which treats a resident StakeEngine
    /// with **no** parked scan as still needing the intent reopen (a dark
    /// scan is a guaranteed-stuck stake, so the reopen re-arms it rather
    /// than letting every retry spin on a scan that is not running), and the
    /// WI-1 lifecycle test asserting a staker open parks a handle (the
    /// behavioral check that survives `pub`).
    pub(crate) fn has_pscan(&self) -> bool {
        self.pscan.is_some()
    }
}

impl std::fmt::Debug for Tenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tenant")
            .field("open_name", &self.open_name)
            .field("engine", &self.engine.as_ref().map(|_| "<engine>"))
            .field("pscan", &self.pscan.as_ref().map(|_| "<pscan-task>"))
            .field("opening", &self.opening)
            .field("closing", &self.closing)
            .finish()
    }
}

/// Clone the open Engine handle under a short tenant-mutex hold, or map the
/// no-wallet-open case to [`WalletRpcError::WalletNotOpen`].
///
/// The tenant mutex is released before the caller awaits the Engine lock, so a
/// long-running RPC never holds the process-level mutex across its work.
pub(crate) async fn require_open_engine(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<SharedEngine, WalletRpcError> {
    let state = tenants.lock().await;
    state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)
}

/// The daemon endpoint every wallet on this server connects to. The address
/// and its proxy are only ever meaningful together — threading them as two
/// loose values is how a call site ends up proxying one connection and not
/// another — so they snapshot, clone, and travel as one value.
#[derive(Clone)]
pub struct DaemonEndpoint {
    /// Daemon JSON-RPC base URL (CLI `--daemon-address`).
    pub address: String,
    /// SOCKS5h proxy for the daemon transport (CLI `--proxy`); `None` =
    /// direct. Server-level constant, applied to every wallet's daemon
    /// connection.
    pub proxy: Option<String>,
}

/// Manual (not derived): the address may carry digest credentials in its
/// authority (`user:pass@host`), so every rendering goes through the
/// transport's [`redacted_endpoint`] — the same authority grammar the
/// credential split uses, so redaction and split cannot disagree. The proxy
/// gets the same treatment (userinfo there is refused at startup, but
/// refusal errors and logs run before that).
impl std::fmt::Debug for DaemonEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonEndpoint")
            .field(
                "address",
                &shekyl_rpc_transport::redacted_endpoint(&self.address),
            )
            .field(
                "proxy",
                &self
                    .proxy
                    .as_deref()
                    .map(shekyl_rpc_transport::redacted_endpoint),
            )
            .finish()
    }
}

/// Process-level wallet directory + tenant slot + daemon/network binding.
#[derive(Debug)]
pub struct TenantState {
    /// Directory that holds wallet files for this process.
    pub wallet_dir: PathBuf,
    /// Network every create/open binds to (CLI `--network`).
    pub network: shekyl_engine_core::Network,
    /// The daemon endpoint (address + proxy) every wallet connects to.
    pub daemon: DaemonEndpoint,
    /// The single tenant (Phase 4b).
    pub tenant: Tenant,
}

impl TenantState {
    /// Construct tenant state for `wallet_dir` on `network`.
    pub fn new(
        wallet_dir: PathBuf,
        network: shekyl_engine_core::Network,
        daemon: DaemonEndpoint,
    ) -> Self {
        Self {
            wallet_dir,
            network,
            daemon,
            tenant: Tenant::new(),
        }
    }
}
