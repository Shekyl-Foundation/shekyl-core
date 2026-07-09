// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Send-lifecycle JSON-RPC methods (Phase 4b).
//!
//! `build_pending_tx`, `submit_pending_tx`, `discard_pending_tx`.

use std::num::NonZeroU64;

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{FeePriority, ReservationId, TxRecipient, TxRequest};
use shekyl_units::AtomicUnits;

use crate::error::WalletRpcError;
use crate::project::pending_tx_result;
use crate::tenant::TenantState;
use crate::types::{DiscardPendingTxResult, SubmitPendingTxResult, SubmitVerdictView};

/// One recipient in `build_pending_tx` params.
#[derive(Debug, Deserialize)]
struct TxRecipientParams {
    address: String,
    amount: String,
}

/// Fee priority: named tier string or `{ "custom": "<feerate>" }`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FeePriorityParams {
    Named(String),
    Custom { custom: String },
}

/// Params for `build_pending_tx`.
#[derive(Debug, Deserialize)]
struct BuildPendingTxParams {
    recipients: Vec<TxRecipientParams>,
    priority: FeePriorityParams,
}

/// Params for `submit_pending_tx`.
#[derive(Debug, Deserialize)]
struct SubmitPendingTxParams {
    pending_tx_id: String,
    seen_gen: i64,
}

/// Params for `discard_pending_tx`.
#[derive(Debug, Deserialize)]
struct DiscardPendingTxParams {
    pending_tx_id: String,
}

/// Dispatch a send-lifecycle method against `tenants`.
pub async fn dispatch(
    tenants: &tokio::sync::Mutex<TenantState>,
    method: &str,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    match method {
        "build_pending_tx" => build_pending_tx(tenants, params).await,
        "submit_pending_tx" => submit_pending_tx(tenants, params).await,
        "discard_pending_tx" => discard_pending_tx(tenants, params).await,
        _ => Err(WalletRpcError::MethodNotFound(method.to_owned())),
    }
}

async fn build_pending_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: BuildPendingTxParams = parse_required_object(params, "build_pending_tx")?;
    if p.recipients.is_empty() {
        return Err(WalletRpcError::InvalidParams(
            "build_pending_tx requires at least one recipient".into(),
        ));
    }
    let request = TxRequest {
        recipients: p
            .recipients
            .into_iter()
            .map(|r| {
                Ok(TxRecipient {
                    address: r.address,
                    amount_atomic_units: parse_atomic_units(&r.amount)?,
                })
            })
            .collect::<Result<Vec<_>, WalletRpcError>>()?,
        priority: parse_fee_priority(p.priority)?,
    };

    let mut state = tenants.lock().await;
    let engine = state
        .tenant
        .engine_mut()
        .ok_or(WalletRpcError::WalletNotOpen)?;
    let pending = engine.build_pending_tx_async(&request).await?;
    let result = pending_tx_result(&pending);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize build_pending_tx: {e}")))
}

async fn submit_pending_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: SubmitPendingTxParams = parse_required_object(params, "submit_pending_tx")?;
    let id = parse_reservation_id(&p.pending_tx_id)?;
    let seen_gen = u64::try_from(p.seen_gen).map_err(|_| {
        WalletRpcError::InvalidParams("seen_gen must be a non-negative integer".into())
    })?;

    let mut state = tenants.lock().await;
    let engine = state
        .tenant
        .engine_mut()
        .ok_or(WalletRpcError::WalletNotOpen)?;
    let tx_hash = engine.submit_pending_tx_async(id, seen_gen).await?;
    let result = SubmitPendingTxResult {
        tx_hash: format!("{tx_hash}"),
        verdict: SubmitVerdictView::Accepted,
        confirmed_height: None,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize submit_pending_tx: {e}")))
}

async fn discard_pending_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: DiscardPendingTxParams = parse_required_object(params, "discard_pending_tx")?;
    let id = parse_reservation_id(&p.pending_tx_id)?;

    let mut state = tenants.lock().await;
    let engine = state
        .tenant
        .engine_mut()
        .ok_or(WalletRpcError::WalletNotOpen)?;
    // Engine maps unknown handles to Ok(()) (idempotent discard).
    engine.discard_pending_tx(id)?;
    let result = DiscardPendingTxResult {};
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize discard_pending_tx: {e}")))
}

fn parse_fee_priority(p: FeePriorityParams) -> Result<FeePriority, WalletRpcError> {
    match p {
        FeePriorityParams::Named(s) => match s.as_str() {
            "ECONOMY" => Ok(FeePriority::Economy),
            "STANDARD" => Ok(FeePriority::Standard),
            "PRIORITY" => Ok(FeePriority::Priority),
            _ => Err(WalletRpcError::InvalidParams(format!(
                "unknown fee priority tier: {s}"
            ))),
        },
        FeePriorityParams::Custom { custom } => {
            let rate: u64 = custom.parse().map_err(|_| {
                WalletRpcError::InvalidParams("custom feerate must be a decimal integer".into())
            })?;
            let nz = NonZeroU64::new(rate).ok_or_else(|| {
                WalletRpcError::InvalidParams("custom feerate must be non-zero".into())
            })?;
            Ok(FeePriority::Custom(nz))
        }
    }
}

fn parse_atomic_units(s: &str) -> Result<AtomicUnits, WalletRpcError> {
    let raw: u64 = s.parse().map_err(|_| {
        WalletRpcError::InvalidParams(format!("amount must be a decimal atomic-units string: {s}"))
    })?;
    Ok(AtomicUnits::from_raw(raw))
}

fn parse_reservation_id(s: &str) -> Result<ReservationId, WalletRpcError> {
    let raw: u64 = s.parse().map_err(|_| {
        WalletRpcError::InvalidParams("pending_tx_id must be a decimal reservation id".into())
    })?;
    Ok(ReservationId::from_raw(raw))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_and_custom_priority() {
        assert!(matches!(
            parse_fee_priority(FeePriorityParams::Named("STANDARD".into())).unwrap(),
            FeePriority::Standard
        ));
        let custom = parse_fee_priority(FeePriorityParams::Custom {
            custom: "42".into(),
        })
        .unwrap();
        assert!(matches!(custom, FeePriority::Custom(n) if n.get() == 42));
    }

    #[test]
    fn rejects_zero_custom_feerate() {
        let err = parse_fee_priority(FeePriorityParams::Custom { custom: "0".into() }).unwrap_err();
        assert!(matches!(err, WalletRpcError::InvalidParams(_)));
    }
}
