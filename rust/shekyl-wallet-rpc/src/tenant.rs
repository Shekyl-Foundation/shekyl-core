// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tenant isolation type for wallet-dir multi-tenancy.
//!
//! Phase 4a ships a single-tenant process: at most one open wallet. The
//! `Tenant` type is the seam Phase 4b multi-tenant mode (`--wallet-dir`
//! exchanges) will extend — separate lock + key material per wallet, no
//! shared state (`WALLET_REWRITE_PLAN.md` §"Hard design questions for the
//! RPC").

use std::path::PathBuf;

/// One wallet-bearing tenant inside the RPC process.
///
/// Phase 4a: the process holds zero or one tenant with an open wallet.
/// The Engine handle lands in Phase 4b lifecycle; until then `open_name`
/// records whether a wallet *would* be open (always `None` in 4a — no
/// open/create methods yet).
#[derive(Debug, Default)]
pub struct Tenant {
    /// Wallet file stem currently open, if any.
    open_name: Option<String>,
}

impl Tenant {
    /// Construct an empty (no wallet open) tenant.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a wallet is currently open on this tenant.
    pub fn is_open(&self) -> bool {
        self.open_name.is_some()
    }

    /// Open wallet stem, if any.
    pub fn open_name(&self) -> Option<&str> {
        self.open_name.as_deref()
    }

    /// Record an open wallet (Phase 4b lifecycle will call this).
    pub fn set_open(&mut self, name: impl Into<String>) {
        self.open_name = Some(name.into());
    }

    /// Clear the open-wallet record (Phase 4b `close_wallet`).
    pub fn clear_open(&mut self) {
        self.open_name = None;
    }
}

/// Process-level wallet directory + tenant slot.
///
/// Future multi-tenant mode will replace the single `tenant` with a map
/// keyed by wallet name; Phase 4a keeps one slot so the type exists and
/// panic-on-cross-tenant-leak checks have a place to live.
#[derive(Debug)]
pub struct TenantState {
    /// Directory that holds wallet files for this process.
    pub wallet_dir: PathBuf,
    /// The single tenant (Phase 4a).
    pub tenant: Tenant,
}

impl TenantState {
    /// Construct tenant state for `wallet_dir`.
    pub fn new(wallet_dir: PathBuf) -> Self {
        Self {
            wallet_dir,
            tenant: Tenant::new(),
        }
    }
}
