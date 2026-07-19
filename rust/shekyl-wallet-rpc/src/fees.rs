// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fee-estimate JSON-RPC methods (WI-RPC-1).
//!
//! Pure projections of the Engine's read-only fee/weight query surface
//! (`fee_query.rs`), which itself rides the one Phase-2a byte model
//! (`predict_weight` == `Transaction::weight()`) and the daemon's atomic
//! multi-tier fee snapshot. Nothing here re-derives a byte model or fee
//! rule, mutates state, or touches key material.

use serde::Deserialize;
use serde_json::Value;
use shekyl_engine_core::{InputCount, OutputCount};

use crate::error::WalletRpcError;
use crate::params::{parse_optional_object, parse_required_object};
use crate::project::atomic_units_string;
use crate::tenant::{require_open_engine, TenantState};
use crate::types::{EstimateTxSizeAndWeightResult, GetDefaultFeePriorityResult};

/// Params for `estimate_tx_size_and_weight`.
#[derive(Debug, Deserialize)]
struct EstimateTxSizeAndWeightParams {
    n_inputs: i64,
    n_outputs: i64,
    /// Expected fee in atomic units (feeds the weight's own `varint(fee)`
    /// term). Omitted → `0`, a floor estimate within 9 bytes of exact.
    fee: Option<String>,
}

/// Params for `get_default_fee_priority`. The shape defaults to the
/// canonical 2-in/2-out transfer when omitted.
#[derive(Debug, Default, Deserialize)]
struct GetDefaultFeePriorityParams {
    n_inputs: Option<i64>,
    n_outputs: Option<i64>,
}

pub(crate) async fn estimate_tx_size_and_weight(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: EstimateTxSizeAndWeightParams =
        parse_required_object(params, "estimate_tx_size_and_weight")?;
    let n_in = parse_input_count(p.n_inputs)?;
    let n_out = parse_output_count(p.n_outputs)?;
    let fee = match p.fee.as_deref() {
        None => 0,
        Some(s) => s.parse::<u64>().map_err(|_| {
            WalletRpcError::InvalidParams("fee must be a decimal atomic-units string".into())
        })?,
    };

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    let estimate = engine.estimate_tx_size_and_weight(n_in, n_out, fee).await;

    let result = EstimateTxSizeAndWeightResult {
        size: i64::try_from(estimate.size).unwrap_or(i64::MAX),
        weight: i64::try_from(estimate.weight).unwrap_or(i64::MAX),
        tree_depth: i64::from(estimate.tree_depth),
    };
    serde_json::to_value(result).map_err(|e| {
        WalletRpcError::InternalError(format!("serialize estimate_tx_size_and_weight: {e}"))
    })
}

pub(crate) async fn get_default_fee_priority(
    tenants: &tokio::sync::Mutex<TenantState>,
    params: &Value,
) -> Result<Value, WalletRpcError> {
    let p: GetDefaultFeePriorityParams = parse_optional_object(params, "get_default_fee_priority")?;
    let n_in = parse_input_count(p.n_inputs.unwrap_or(2))?;
    let n_out = parse_output_count(p.n_outputs.unwrap_or(2))?;

    let shared = require_open_engine(tenants).await?;
    let engine = shared.read().await;
    // One daemon fee snapshot + the same converge fixpoint the build path
    // runs; a failed snapshot maps to the same `-29102` the build path uses.
    let quote = engine
        .quote_fee_tiers(n_in, n_out)
        .await
        .map_err(|_e| WalletRpcError::FeeEstimationFailed)?;

    let result = GetDefaultFeePriorityResult {
        default_priority: "STANDARD".to_owned(),
        economy_fee: atomic_units_string(quote.economy_fee),
        standard_fee: atomic_units_string(quote.standard_fee),
        priority_fee: atomic_units_string(quote.priority_fee),
        tree_depth: i64::from(quote.tree_depth),
    };
    serde_json::to_value(result).map_err(|e| {
        WalletRpcError::InternalError(format!("serialize get_default_fee_priority: {e}"))
    })
}

/// Validate a client-supplied transaction count against the OpenAPI contract
/// range, rejecting (not clamping) an out-of-contract value.
///
/// Two bounds meet here:
/// - the **contract floor** `min` — a caller-visible per-field minimum
///   (`n_inputs` ≥ 1, `n_outputs` ≥ 2: a valid transfer always carries a
///   payment/change output pair, per `docs/api/wallet_rpc.yaml`);
/// - the bounded type's own `1..=MAX` ceiling — `clamp` maps the raw count
///   through it, so a value the clamp would have altered is above `MAX`.
///
/// The bounded types clamp silently at the Engine boundary (their internal
/// weight-predictor contract); at the RPC boundary an out-of-range count is a
/// caller error, so reject instead of clamping.
fn parse_count(
    n: i64,
    min: usize,
    field: &str,
    clamp: impl Fn(usize) -> usize,
) -> Result<usize, WalletRpcError> {
    let raw = usize::try_from(n).map_err(|_| {
        WalletRpcError::InvalidParams(format!("{field} must be a positive integer"))
    })?;
    if raw < min || clamp(raw) != raw {
        return Err(WalletRpcError::InvalidParams(format!(
            "{field} out of range for a valid transaction"
        )));
    }
    Ok(raw)
}

fn parse_input_count(n: i64) -> Result<InputCount, WalletRpcError> {
    parse_count(n, 1, "n_inputs", |r| InputCount::clamped(r).get()).map(InputCount::clamped)
}

fn parse_output_count(n: i64) -> Result<OutputCount, WalletRpcError> {
    parse_count(n, 2, "n_outputs", |r| OutputCount::clamped(r).get()).map(OutputCount::clamped)
}
