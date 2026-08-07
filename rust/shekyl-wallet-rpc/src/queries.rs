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
use crate::project::{
    outgoing_transfer_state, outgoing_transfer_view, parse_transfer_id, transfer_state,
    transfer_view,
};
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

    let want_incoming = filters
        .direction
        .is_none_or(|d| d == TransferDirection::Incoming);
    let want_outgoing = filters
        .direction
        .is_none_or(|d| d == TransferDirection::Outgoing);

    let mut transfers: Vec<TransferView> = Vec::new();

    if want_incoming {
        transfers.extend(
            ledger
                .ledger
                .transfers()
                .iter()
                .filter(|&td| {
                    if let Some(min_h) = since {
                        if td.block_height < min_h {
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
                .map(transfer_view),
        );
    }

    if want_outgoing {
        transfers.extend(ledger.send_journal.rows.iter().filter_map(|(txid, row)| {
            let height = match row.state {
                shekyl_engine_state::SendState::Confirmed { height } => height,
                _ => row.dispatched_at_height,
            };
            if let Some(min_h) = since {
                if height < min_h {
                    return None;
                }
            }
            if let Some(st) = filters.state {
                if outgoing_transfer_state(row) != st {
                    return None;
                }
            }
            Some(outgoing_transfer_view(
                &shekyl_types::TxHash::from_bytes(*txid),
                row,
            ))
        }));
    }

    // Stable interleave: height ascending, then INCOMING before OUTGOING,
    // then id — deterministic without inventing timestamps (SJ-DQ-7).
    transfers.sort_by(|a, b| {
        a.block_height
            .cmp(&b.block_height)
            .then_with(|| {
                (a.direction == TransferDirection::Outgoing)
                    .cmp(&(b.direction == TransferDirection::Outgoing))
            })
            .then_with(|| a.id.cmp(&b.id))
    });

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

    let engine = require_open_engine(tenants).await?;
    let engine = engine.read().await;
    let ledger = engine.ledger();

    // OUTGOING ids are bare txid hex (SJ-DQ-7); INCOMING keep `txid:index`.
    if let Some((tx_hash, out_idx)) = parse_transfer_id(&p.id) {
        let found = ledger
            .ledger
            .transfers()
            .iter()
            .find(|td| td.tx_hash == tx_hash && td.internal_output_index == out_idx)
            .map(transfer_view);
        if let Some(transfer) = found {
            let result = GetTransferByIdResult { transfer };
            return serde_json::to_value(result).map_err(|e| {
                WalletRpcError::InternalError(format!("serialize get_transfer_by_id: {e}"))
            });
        }
        return Err(WalletRpcError::UnknownTransferId);
    }

    if let Some(bytes) = crate::params::parse_hex32(&p.id) {
        if let Some(row) = ledger.send_journal.rows.get(&bytes) {
            let result = GetTransferByIdResult {
                transfer: outgoing_transfer_view(&shekyl_types::TxHash::from_bytes(bytes), row),
            };
            return serde_json::to_value(result).map_err(|e| {
                WalletRpcError::InternalError(format!("serialize get_transfer_by_id: {e}"))
            });
        }
    }

    Err(WalletRpcError::UnknownTransferId)
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

    // Do not fail the whole call when the daemon is unreachable: the wallet
    // height is local and always meaningful (a user whose own node is down or
    // still syncing must still be able to see their wallet's status). Report
    // daemon_height as null in that case rather than erroring out.
    let daemon_height = daemon
        .get_height()
        .await
        .ok()
        .map(|h| i64::try_from(h).unwrap_or(i64::MAX));

    let result = GetHeightResult {
        wallet_height,
        daemon_height,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_height: {e}")))
}
