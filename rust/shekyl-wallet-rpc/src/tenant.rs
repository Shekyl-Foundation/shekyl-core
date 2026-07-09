// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tenant isolation type for wallet-dir multi-tenancy.
//!
//! Phase 4b: single-tenant process holds at most one open
//! [`Engine`](shekyl_engine_core::Engine). Multi-tenant `--wallet-dir`
//! exchanges extend this seam later (`WALLET_REWRITE_PLAN.md`).

use shekyl_engine_core::{Engine, SoloSigner};
use std::path::PathBuf;

/// One wallet-bearing tenant inside the RPC process.
#[derive(Debug, Default)]
pub struct Tenant {
    /// Wallet file stem currently open, if any.
    open_name: Option<String>,
    /// Open Engine handle (FULL capability, SoloSigner).
    engine: Option<Engine<SoloSigner>>,
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

    /// Open wallet stem, if any.
    pub fn open_name(&self) -> Option<&str> {
        self.open_name.as_deref()
    }

    /// Borrow the open engine, if any.
    pub fn engine(&self) -> Option<&Engine<SoloSigner>> {
        self.engine.as_ref()
    }

    /// Mutably borrow the open engine, if any.
    pub fn engine_mut(&mut self) -> Option<&mut Engine<SoloSigner>> {
        self.engine.as_mut()
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
        self.open_name = Some(name.into());
        self.engine = Some(engine);
    }

    /// Take the open engine (for [`Engine::close`]), clearing the tenant slot.
    pub fn take_open(&mut self) -> Option<(String, Engine<SoloSigner>)> {
        let name = self.open_name.take()?;
        let engine = self.engine.take()?;
        Some((name, engine))
    }
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
