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
use crate::project::refresh_result;
use crate::tenant::TenantState;

/// Dispatch a sync method against `tenants`.
pub async fn dispatch(
    tenants: &tokio::sync::Mutex<TenantState>,
    method: &str,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    match method {
        "refresh" => refresh(tenants, params).await,
        "rescan_blockchain" => Err(WalletRpcError::MethodNotFound(method.to_owned())),
        _ => Err(WalletRpcError::MethodNotFound(method.to_owned())),
    }
}

async fn refresh(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "refresh")?;

    // Clone the shared Engine handle under a short tenant-mutex hold;
    // do not keep the tenant mutex across the refresh await.
    let engine = {
        let state = tenants.lock().await;
        state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?
    };

    let opts = RefreshOptions::default();
    let handle = Engine::start_refresh(engine.clone(), opts).await?;
    let summary = handle.join().await?;
    let synced_height = engine.read().await.ledger().ledger.height();
    let result = refresh_result(&summary, synced_height);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize refresh: {e}")))
}

fn require_empty_object(params: &Value, method: &str) -> Result<(), WalletRpcError> {
    match params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Object(_) => Err(WalletRpcError::InvalidParams(format!(
            "{method} takes no parameters"
        ))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object or omitted"
        ))),
    }
}
