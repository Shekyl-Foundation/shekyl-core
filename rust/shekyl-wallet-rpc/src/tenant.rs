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
//! read lock. Multi-tenant `--wallet-dir` exchanges extend this seam
//! later (`WALLET_REWRITE_PLAN.md`).

use shekyl_engine_core::{Engine, SoloSigner};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::WalletRpcError;

/// Shared handle to the open Engine (read/write under the inner lock).
pub type SharedEngine = Arc<RwLock<Engine<SoloSigner>>>;

/// One wallet-bearing tenant inside the RPC process.
#[derive(Debug, Default)]
pub struct Tenant {
    /// Wallet file stem currently open, if any.
    open_name: Option<String>,
    /// Open Engine handle (FULL capability, SoloSigner).
    engine: Option<SharedEngine>,
    /// True while `create_wallet` / `open_wallet` is doing slow work
    /// (daemon connect, Argon2) *outside* the tenant mutex. Prevents a
    /// concurrent create/open from racing past `is_open` while the first
    /// call has released the mutex. Cleared on success (`set_open`) or
    /// failure ([`Self::clear_opening`]).
    opening: bool,
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

    /// Whether create/open is in flight or a wallet is already open.
    ///
    /// Lifecycle create/open refuse with `-29000` when this is true.
    pub fn is_busy(&self) -> bool {
        self.is_open() || self.opening
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

    /// Install a freshly created / opened engine as the open wallet.
    ///
    /// # Panics
    ///
    /// Panics if a wallet is already open — callers must check
    /// [`Self::is_open`] and return `-29000` first.
    pub fn set_open(&mut self, name: impl Into<String>, engine: Engine<SoloSigner>) {
        assert!(
            self.engine.is_none(),
            "set_open called while a wallet is already open"
        );
        self.opening = false;
        self.open_name = Some(name.into());
        self.engine = Some(Arc::new(RwLock::new(engine)));
    }

    /// Take the open engine (for [`Engine::close`]), clearing the tenant slot.
    ///
    /// The name/engine pair is taken atomically: if either field is missing the
    /// other is restored and this returns `None`, so a broken pair cannot clear
    /// only the stem and leave an undiagnosable half-empty slot.
    ///
    /// The caller should [`Arc::try_unwrap`](std::sync::Arc::try_unwrap) the
    /// returned handle before close. If other clones still exist (e.g. an
    /// in-flight refresh), the caller must [`restore_open`](Self::restore_open)
    /// the handle and fail loud rather than evicting the still-live wallet.
    pub fn take_open(&mut self) -> Option<(String, SharedEngine)> {
        match (self.open_name.take(), self.engine.take()) {
            (Some(name), Some(engine)) => Some((name, engine)),
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

    /// Re-install a handle previously removed by [`take_open`](Self::take_open)
    /// when the close attempt could not proceed (another task still holds a
    /// clone, or reservations are outstanding). Inverse of `take_open`.
    ///
    /// # Panics
    ///
    /// Panics if a wallet is already open — the slot must be empty, which it is
    /// on the close path that just called `take_open`.
    pub fn restore_open(&mut self, name: String, engine: SharedEngine) {
        assert!(
            self.engine.is_none(),
            "restore_open called while a wallet is already open"
        );
        self.open_name = Some(name);
        self.engine = Some(engine);
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

/// Process-level wallet directory + tenant slot + daemon/network binding.
#[derive(Debug)]
pub struct TenantState {
    /// Directory that holds wallet files for this process.
    pub wallet_dir: PathBuf,
    /// Network every create/open binds to (CLI `--network`).
    pub network: shekyl_engine_core::Network,
    /// Daemon JSON-RPC base URL (CLI `--daemon-address`).
    pub daemon_address: String,
    /// The single tenant (Phase 4b).
    pub tenant: Tenant,
}

impl TenantState {
    /// Construct tenant state for `wallet_dir` on `network`.
    pub fn new(
        wallet_dir: PathBuf,
        network: shekyl_engine_core::Network,
        daemon_address: String,
    ) -> Self {
        Self {
            wallet_dir,
            network,
            daemon_address,
            tenant: Tenant::new(),
        }
    }
}
