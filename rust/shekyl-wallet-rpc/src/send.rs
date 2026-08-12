// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Send-lifecycle JSON-RPC methods (Phase 4b; `abandon_tx` PR-SJ-3).
//!
//! `build_pending_tx`, `submit_pending_tx`, `discard_pending_tx`,
//! `abandon_tx`.

use std::num::NonZeroU64;

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{FeePriority, ReservationId, TxHash, TxRecipient, TxRequest};

use crate::error::WalletRpcError;
use crate::params::{parse_atomic_units, parse_hex32, parse_required_object};
use crate::project::{pending_tx_result, submit_pending_tx_result};
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{AbandonTxResult, DiscardPendingTxResult, TransferState};

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

/// Params for `abandon_tx`.
#[derive(Debug, Deserialize)]
struct AbandonTxParams {
    tx_hash: String,
}

pub(crate) async fn build_pending_tx(
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

    let shared = require_open_engine(tenants).await?;
    // W-B step 1: build runs under a *read* lock — the slow FCMP++
    // assembly lives inside `LocalPendingTx`'s interior mutability behind
    // an engine-owned permit of one (network observable unchanged:
    // serialized `AssembleTx`), so concurrent read RPCs (`get_balance`,
    // `get_height`, `get_transfers`) are no longer stalled behind a
    // build.
    //
    // This lock orders nothing against `refresh`: the refresh driver and
    // its ledger merge take *read* guards too (`Engine::start_refresh`),
    // so a merge could always land while a build ran, and can now land
    // mid-build. Build owns that: it re-validates its selected inputs
    // under the state lock at the commit boundary
    // (`revalidate_selected_inputs`) and refuses rather than hand back a
    // `PendingTx` the merge already invalidated.
    let engine = shared.read().await;
    let pending = engine.build_pending_tx_async(&request).await?;
    let result = pending_tx_result(&pending);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize build_pending_tx: {e}")))
}

pub(crate) async fn submit_pending_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: SubmitPendingTxParams = parse_required_object(params, "submit_pending_tx")?;
    let id = parse_reservation_id(&p.pending_tx_id)?;
    let seen_gen = u64::try_from(p.seen_gen).map_err(|_| {
        WalletRpcError::InvalidParams("seen_gen must be a non-negative integer".into())
    })?;

    let shared = require_open_engine(tenants).await?;
    // Same interior-mutability insight as build (W-B review): submit
    // mutates under `LocalPendingTx`'s own state lock and awaits the
    // daemon under that implementor — exclusive Engine borrow only
    // stalled concurrent read RPCs for the network round-trip. Submit's
    // own slow segment work (the stale-reference re-anchor) takes the
    // same build permit, so the serialized `AssembleTx` observable holds
    // across build and submit alike.
    let engine = shared.read().await;
    let outcome = engine.submit_pending_tx_async(id, seen_gen).await?;
    let result = submit_pending_tx_result(&outcome);
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize submit_pending_tx: {e}")))
}

pub(crate) async fn discard_pending_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: DiscardPendingTxParams = parse_required_object(params, "discard_pending_tx")?;
    let id = parse_reservation_id(&p.pending_tx_id)?;

    let shared = require_open_engine(tenants).await?;
    // Discard is a short pending-tx state mutation under interior
    // mutability; exclusive Engine borrow is not required.
    let engine = shared.read().await;
    // Engine maps unknown handles to Ok(()) (idempotent discard).
    engine.discard_pending_tx(id)?;
    let result = DiscardPendingTxResult {};
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize discard_pending_tx: {e}")))
}

/// `abandon_tx` (`WALLET_SEND_RECORD.md` P3-4 / SJ-DQ-8, PR-SJ-3): the
/// user-authored give-up on a dispatched send. The journal row moves to
/// `Abandoned` and its retention reference migrates off the pending set
/// (keys retained — the OUTBOUND proof still works). Idempotent; there
/// is deliberately **no force path** (`-29108` names the refusing
/// state; row hiding is deletion's job, not abandon's).
pub(crate) async fn abandon_tx(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: AbandonTxParams = parse_required_object(params, "abandon_tx")?;
    let txid = parse_hex32(&p.tx_hash).ok_or_else(|| {
        WalletRpcError::InvalidParams("tx_hash must be 64 lowercase hex characters".into())
    })?;

    let shared = require_open_engine(tenants).await?;
    // Abandon mutates under the engine's interior ledger lock and drives
    // its own crash-atomic save; exclusive Engine borrow is not required
    // (same shape as discard).
    let engine = shared.read().await;
    engine.abandon_tx_persisted(TxHash::from_bytes(txid))?;
    // Both outcomes (fresh abandon, idempotent re-abandon) answer with
    // the row's resulting state — the same vocabulary `get_transfers`
    // speaks.
    let result = AbandonTxResult {
        state: TransferState::Abandoned,
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize abandon_tx: {e}")))
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

fn parse_reservation_id(s: &str) -> Result<ReservationId, WalletRpcError> {
    let raw: u64 = s.parse().map_err(|_| {
        WalletRpcError::InvalidParams("pending_tx_id must be a decimal reservation id".into())
    })?;
    Ok(ReservationId::from_raw(raw))
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
