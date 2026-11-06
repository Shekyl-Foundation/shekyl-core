// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `get_shard_view` (SV-D): one closed archival shard's aggregate, answered
//! through the open wallet's daemon.
//!
//! The arm is a transport: parse `shard_id`, take the engine's daemon
//! handle, call the contract's [`fetch_shard_view`]. Parsing, the daemon
//! call and the refusal mapping all live in `shekyl-wallet-contract` so an
//! embedding wallet's adapter and this server answer identically.

use serde_json::Value;
use shekyl_wallet_contract::shard_view::{fetch_shard_view, GetShardViewParams, GET_SHARD_VIEW};

use crate::error::WalletRpcError;
use crate::params::parse_required_object;
use crate::tenant::{require_open_engine, TenantState};

pub(crate) async fn get_shard_view(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let GetShardViewParams { shard_id } = parse_required_object(params, GET_SHARD_VIEW)?;
    let shared = require_open_engine(tenants).await?;
    // Clone the handle and drop the read guard: the daemon fetches the
    // body from a holder before it answers, and no other method should
    // wait on the engine for that.
    let daemon = shared.read().await.daemon().clone();
    let view = fetch_shard_view(&daemon, shard_id).await?;
    serde_json::to_value(view)
        .map_err(|e| WalletRpcError::InternalError(format!("serialize {GET_SHARD_VIEW}: {e}")))
}
