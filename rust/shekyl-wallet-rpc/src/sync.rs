// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sync JSON-RPC methods (Phase 4b).
//!
//! `refresh` is implemented via [`Engine::start_refresh`] so the
//! process-level tenant mutex is not held across the scan. The Engine
//! lives behind `Arc<RwLock<_>>` (see [`crate::tenant`]); single-flight
//! is Engine-owned (`RefreshError::AlreadyRunning` → `-29200`).
//!
//! `rescan_blockchain` stays `-32601` until Engine grows an explicit
//! rescan API (see `docs/FOLLOWUPS.md`).

use serde_json::Value;
use shekyl_engine_core::{Engine, RefreshOptions};

use crate::error::WalletRpcError;
use crate::params::require_empty_object;
use crate::project::refresh_result;
use crate::tenant::{require_open_engine, TenantState};

pub(crate) async fn refresh(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "refresh")?;

    // Clone the shared Engine handle under a short tenant-mutex hold;
    // do not keep the tenant mutex across the refresh await.
    let engine = require_open_engine(tenants).await?;

    let opts = RefreshOptions::default();
    let handle = Engine::start_refresh(engine.clone(), opts).await?;
    let summary = handle.join().await?;
    let synced_height = engine.read().await.ledger().ledger.height();
    let result = refresh_result(&summary, synced_height);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize refresh: {e}")))
}
