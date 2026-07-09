// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-only wallet JSON-RPC methods (Phase 4b).
//!
//! `get_balance`, `get_primary_address`, `get_transfers`,
//! `get_transfer_by_id`, `get_height`.

use serde::Deserialize;
use serde_json::Value;
use shekyl_rpc_client::Rpc;
use shekyl_scanner::LedgerBlockExt;

use crate::error::WalletRpcError;
use crate::project::{transfer_id, transfer_view};
use crate::tenant::TenantState;
use crate::types::{
    GetBalanceResult, GetHeightResult, GetPrimaryAddressResult, GetTransferByIdResult,
    GetTransfersResult, TransferDirection, TransferState, TransferView,
};

/// Optional filters for `get_transfers`.
#[derive(Debug, Default, Deserialize)]
struct GetTransfersParams {
    direction: Option<TransferDirection>,
    state: Option<TransferState>,
    since_height: Option<i64>,
}

/// Params for `get_transfer_by_id`.
#[derive(Debug, Deserialize)]
struct GetTransferByIdParams {
    id: String,
}

/// Dispatch a read-query method against `tenants`.
pub async fn dispatch(
    tenants: &tokio::sync::Mutex<TenantState>,
    method: &str,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    match method {
        "get_balance" => get_balance(tenants, params).await,
        "get_primary_address" => get_primary_address(tenants, params).await,
        "get_transfers" => get_transfers(tenants, params).await,
        "get_transfer_by_id" => get_transfer_by_id(tenants, params).await,
        "get_height" => get_height(tenants, params).await,
        _ => Err(WalletRpcError::MethodNotFound(method.to_owned())),
    }
}

async fn get_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_balance")?;
    let state = tenants.lock().await;
    let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
    let ledger = engine.ledger();
    let height = ledger.ledger.height();
    let summary = ledger.ledger.balance(height);
    let result = GetBalanceResult::from(&summary);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_balance: {e}")))
}

async fn get_primary_address(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_primary_address")?;
    let state = tenants.lock().await;
    let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
    let address = engine
        .primary_address()
        .encode()
        .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?;
    let result = GetPrimaryAddressResult { address };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_primary_address: {e}")))
}

async fn get_transfers(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let filters: GetTransfersParams = parse_optional_object(params, "get_transfers")?;
    let since = filters.since_height.map(|h| u64::try_from(h).unwrap_or(0));

    let state = tenants.lock().await;
    let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
    let ledger = engine.ledger();

    let transfers: Vec<TransferView> = ledger
        .ledger
        .transfers()
        .iter()
        .map(transfer_view)
        .filter(|view| {
            if let Some(min_h) = since {
                if (view.block_height as u64) < min_h {
                    return false;
                }
            }
            if let Some(dir) = filters.direction {
                if view.direction != dir {
                    return false;
                }
            }
            if let Some(st) = filters.state {
                if view.state != st {
                    return false;
                }
            }
            true
        })
        .collect();

    let result = GetTransfersResult { transfers };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_transfers: {e}")))
}

async fn get_transfer_by_id(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetTransferByIdParams = parse_required_object(params, "get_transfer_by_id")?;
    if p.id.is_empty() {
        return Err(WalletRpcError::InvalidParams(
            "get_transfer_by_id requires non-empty id".into(),
        ));
    }

    let state = tenants.lock().await;
    let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
    let ledger = engine.ledger();

    let found = ledger
        .ledger
        .transfers()
        .iter()
        .find(|td| transfer_id(td) == p.id)
        .map(transfer_view);

    match found {
        Some(transfer) => {
            let result = GetTransferByIdResult { transfer };
            serde_json::to_value(result).map_err(|e| {
                WalletRpcError::InternalError(format!("serialize get_transfer_by_id: {e}"))
            })
        }
        None => Err(WalletRpcError::UnknownTransferId),
    }
}

async fn get_height(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_height")?;
    let (wallet_height, daemon) = {
        let state = tenants.lock().await;
        let engine = state.tenant.engine().ok_or(WalletRpcError::WalletNotOpen)?;
        let wallet_height = i64::try_from(engine.ledger().ledger.height()).unwrap_or(i64::MAX);
        (wallet_height, engine.daemon().clone())
    };

    let daemon_height = daemon
        .get_height()
        .await
        .map_err(|_e| WalletRpcError::DaemonUnreachable)?;
    let daemon_height = i64::try_from(daemon_height).unwrap_or(i64::MAX);

    let result = GetHeightResult {
        wallet_height,
        daemon_height,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_height: {e}")))
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

fn parse_optional_object<T: for<'de> Deserialize<'de> + Default>(
    params: &Value,
    method: &str,
) -> Result<T, WalletRpcError> {
    match params {
        Value::Null => Ok(T::default()),
        Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|e| WalletRpcError::InvalidParams(format!("{method} params: {e}"))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object or omitted"
        ))),
    }
}

fn parse_required_object<T: for<'de> Deserialize<'de>>(
    params: &Value,
    method: &str,
) -> Result<T, WalletRpcError> {
    match params {
        Value::Null => Err(WalletRpcError::InvalidParams(format!(
            "{method} requires a params object"
        ))),
        Value::Object(_) => serde_json::from_value(params.clone())
            .map_err(|e| WalletRpcError::InvalidParams(format!("{method} params: {e}"))),
        _ => Err(WalletRpcError::InvalidParams(format!(
            "{method} params must be an object"
        ))),
    }
}
