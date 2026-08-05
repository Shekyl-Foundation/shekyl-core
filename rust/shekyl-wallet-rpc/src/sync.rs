// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sync JSON-RPC methods (Phase 4b / Phase 4c).
//!
//! `refresh` and `rescan_blockchain` both use the Engine's async single-flight
//! slot (`RefreshError::AlreadyRunning` → `-29200`). The process-level tenant
//! mutex is not held across the scan: clone the shared Engine under a short
//! hold, then await the handle (see [`crate::tenant`]).

use serde_json::Value;
use shekyl_engine_core::{Engine, RefreshOptions};

use crate::error::WalletRpcError;
use crate::params::require_empty_object;
use crate::project::{refresh_result, rescan_result};
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

pub(crate) async fn rescan_blockchain(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "rescan_blockchain")?;

    let engine = require_open_engine(tenants).await?;

    let opts = RefreshOptions::default();
    let handle = Engine::start_rescan(engine.clone(), opts).await?;
    let summary = handle.join().await?;
    let synced_height = engine.read().await.ledger().ledger.height();
    // OpenAPI `RescanBlockchainResult` omits `reorg_fork_height`.
    let result = rescan_result(&summary, synced_height);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize rescan: {e}")))
}
