// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking read-only JSON-RPC methods (WI-RPC-1).
//!
//! Pure projections of [`Engine::staking_read_view`], the one authoritative
//! aggregation over the sealed pscan / pending-post records — never the
//! `bonded_slots` hint. All three methods are read-only (`&self` under the
//! engine read guard). Staking *actions* (unstake, claim) are out of scope:
//! they need Engine surfacing first.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{Engine, SoloSigner, StakedOutput, StakingReadView};

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, require_empty_object};
use crate::project::atomic_units_string;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{
    GetStakedBalanceResult, GetStakedOutputsResult, StakedOutputView, StakingInfoResult,
};

/// Params for `get_staked_outputs`.
#[derive(Debug, Default, Deserialize)]
struct GetStakedOutputsParams {
    /// Accepted for wire-shape stability; the authoritative set contains
    /// only finality-confirmed outputs at V3.0, so `false` changes nothing.
    #[allow(dead_code)]
    confirmed_only: Option<bool>,
}

pub(crate) async fn get_staked_balance(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "get_staked_balance")?;
    let view = read_view(tenants).await?;
    serde_json::to_value(balance_result(&view))
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_staked_balance: {e}")))
}

pub(crate) async fn get_staked_outputs(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let _p: GetStakedOutputsParams = parse_optional_object(params, "get_staked_outputs")?;
    let view = read_view(tenants).await?;
    let result = GetStakedOutputsResult {
        staked_outputs: view.outputs.iter().map(staked_output_view).collect(),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize get_staked_outputs: {e}")))
}

pub(crate) async fn staking_info(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    require_empty_object(params, "staking_info")?;
    let view = read_view(tenants).await?;
    let result = StakingInfoResult {
        staking_enabled: view.staking_enabled,
        balance: balance_result(&view),
        staked_output_count: i64::try_from(view.outputs.len()).unwrap_or(i64::MAX),
        pscan_synced_height: view
            .pscan_synced_height
            .map(|h| i64::try_from(h.to_raw()).unwrap_or(i64::MAX)),
    };
    serde_json::to_value(result)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize staking_info: {e}")))
}

/// Compute the authoritative view from an already-held engine read guard.
///
/// The single call site of `Engine::staking_read_view` in this crate, so the
/// off-the-worker discipline and the error mapping below have one home rather
/// than a copy per caller. `get_wallet_info` (`queries.rs`) calls this while
/// holding its own guard: it must read staking within the *same* guard as the
/// rest of its snapshot, both for coherence and because re-acquiring a read
/// while one is held can deadlock against a queued writer on a write-preferring
/// `RwLock`.
///
/// `staking_read_view` opens and decrypts the sealed `.wallet.pscan` /
/// `.wallet.pending` files inline (envelope KDF + AEAD + postcard decode), so
/// it is run through [`tokio::task::block_in_place`] — the same off-the-worker
/// discipline `lifecycle.rs` uses for its synchronous engine calls, so a large
/// seal cannot stall the tokio worker (and any tenant scheduled on it) for the
/// decrypt. Every runtime that hosts this server is multi-threaded — the
/// `#[tokio::main]` binary and the CLI's in-process
/// `Builder::new_multi_thread` spawn — so `block_in_place` never hits its
/// `current_thread` panic. A future single-threaded host would have to move
/// this to `spawn_blocking`, which is why the call is not scattered.
///
/// A corrupt or version-mismatched seal fails closed as `InternalError` with
/// a stable, detail-free client message (the cause can carry filesystem
/// paths; it is logged server-side only — same discipline as the
/// `PScanStartError::LoadFailed` mapping).
pub(crate) fn read_view_under_guard(
    engine: &Engine<SoloSigner>,
) -> Result<StakingReadView, WalletRpcError> {
    tokio::task::block_in_place(|| engine.staking_read_view()).map_err(|e| {
        tracing::warn!(error = %e, "staking read view failed");
        WalletRpcError::InternalError("staking state failed to load".into())
    })
}

/// Acquire the engine read guard and compute the authoritative view.
async fn read_view(
    tenants: &tokio::sync::Mutex<TenantState>,
) -> Result<StakingReadView, WalletRpcError> {
    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    read_view_under_guard(&engine)
}

fn balance_result(view: &StakingReadView) -> GetStakedBalanceResult {
    GetStakedBalanceResult {
        bonded_principal_confirmed: atomic_units_string(view.balance.bonded_principal_confirmed),
        bonded_principal_pending: atomic_units_string(view.balance.bonded_principal_pending),
        rewards_received_unspent: atomic_units_string(view.balance.rewards_received_unspent),
    }
}

fn staked_output_view(o: &StakedOutput) -> StakedOutputView {
    StakedOutputView {
        gindex: o.gindex.to_raw().to_string(),
        amount: atomic_units_string(o.amount),
        p_slot: i64::from(o.p_slot.to_raw()),
        unlock_height: i64::try_from(o.unlock_height.to_raw()).unwrap_or(i64::MAX),
        confirmed: o.confirmed,
    }
}
