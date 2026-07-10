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
use crate::params::{parse_optional_object, parse_required_object, require_empty_object};
use crate::project::{parse_transfer_id, transfer_state, transfer_view};
use crate::tenant::{require_open_engine, TenantState};
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

pub(crate) async fn get_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_balance")?;
    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();
    let height = ledger.ledger.height();
    let summary = ledger.ledger.balance(height);
    let result = GetBalanceResult::from(&summary);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_balance: {e}")))
}

pub(crate) async fn get_primary_address(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_primary_address")?;
    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let address = engine
        .primary_address()
        .encode()
        .map_err(|e| WalletRpcError::InternalError(format!("encode address: {e}")))?;
    let result = GetPrimaryAddressResult { address };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_primary_address: {e}")))
}

pub(crate) async fn get_transfers(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let filters: GetTransfersParams = parse_optional_object(params, "get_transfers")?;
    let since = match filters.since_height {
        None => None,
        Some(h) => Some(u64::try_from(h).map_err(|_| {
            WalletRpcError::InvalidParams("since_height must be a non-negative integer".into())
        })?),
    };

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();

    // Filter on the domain rows first, then project only the survivors — this
    // avoids per-row string/hex allocation for filtered-out rows and compares
    // `since_height` against the true `u64` height (no lossy `i64` round-trip).
    let transfers: Vec<TransferView> = ledger
        .ledger
        .transfers()
        .iter()
        .filter(|&td| {
            if let Some(min_h) = since {
                if td.block_height < min_h {
                    return false;
                }
            }
            if let Some(dir) = filters.direction {
                // Ledger rows are receive-side outputs; every row projects as
                // INCOMING until a dedicated outgoing-history surface lands
                // (see `project::transfer_view`).
                if dir != TransferDirection::Incoming {
                    return false;
                }
            }
            if let Some(st) = filters.state {
                if transfer_state(td) != st {
                    return false;
                }
            }
            true
        })
        .map(transfer_view)
        .collect();

    let result = GetTransfersResult { transfers };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_transfers: {e}")))
}

pub(crate) async fn get_transfer_by_id(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetTransferByIdParams = parse_required_object(params, "get_transfer_by_id")?;
    if p.id.is_empty() {
        return Err(WalletRpcError::InvalidParams(
            "get_transfer_by_id requires non-empty id".into(),
        ));
    }

    // Parse the id into its (tx_hash, index) parts once and compare typed
    // fields, rather than formatting a fresh id string for every ledger row
    // scanned. A non-canonical id could never match any row's transfer_id
    // output, so it is the same UnknownTransferId the string compare gave.
    let Some((tx_hash, out_idx)) = parse_transfer_id(&p.id) else {
        return Err(WalletRpcError::UnknownTransferId);
    };

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();

    let found = ledger
        .ledger
        .transfers()
        .iter()
        .find(|td| td.tx_hash == tx_hash && td.internal_output_index == out_idx)
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

pub(crate) async fn get_height(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_height")?;
    let shared = require_open_engine(tenants).await?;
    let (wallet_height, daemon) = {
        let engine = shared.read().await;
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
