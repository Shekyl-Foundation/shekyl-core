// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC method dispatch with split routing.
//!
//! When the `rust-scanner` feature is enabled, scanner-backed read-only
//! methods (get_balance, get_transfers, incoming_transfers, etc.) are handled
//! natively in Rust via `shekyl-scanner`. All other methods route through
//! the C++ wallet2 FFI dispatcher.

use crate::wallet::{Wallet2, WalletError};
use serde_json::Value;
use tracing::debug;

#[cfg(feature = "rust-scanner")]
use crate::scanner_state::ScannerState;

/// Methods handled by the Rust scanner when the `rust-scanner` feature is active.
#[cfg(feature = "rust-scanner")]
const SCANNER_METHODS: &[&str] = &[
    "get_balance",
    "get_transfers",
    "incoming_transfers",
    "get_transfer_by_txid",
    "get_payments",
    "get_bulk_payments",
    "get_height",
    "get_staked_outputs",
    "get_staked_balance",
];

/// Dispatch a JSON-RPC method call.
///
/// Without the `rust-scanner` feature, all methods go through C++ FFI.
/// With `rust-scanner`, scanner-backed methods are handled in Rust.
pub fn dispatch(wallet: &Wallet2, method: &str, params: Value) -> Result<Value, WalletError> {
    debug!(method, "dispatching JSON-RPC method");
    let params_str = serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string());
    wallet.json_rpc_call(method, &params_str)
}

/// Dispatch with split routing: scanner-backed methods go to Rust, rest to FFI.
#[cfg(feature = "rust-scanner")]
pub fn dispatch_with_scanner(
    wallet: &Wallet2,
    scanner: &ScannerState,
    method: &str,
    params: Value,
) -> Result<Value, WalletError> {
    if SCANNER_METHODS.contains(&method) {
        debug!(method, "routing to Rust scanner");
        dispatch_scanner_method(scanner, method, params)
    } else {
        debug!(method, "routing to C++ FFI");
        dispatch(wallet, method, params)
    }
}

#[cfg(feature = "rust-scanner")]
fn dispatch_scanner_method(
    scanner: &ScannerState,
    method: &str,
    params: Value,
) -> Result<Value, WalletError> {
    match method {
        "get_balance" => scanner_get_balance(scanner, params),
        "get_height" => scanner_get_height(scanner),
        "get_transfers" => scanner_get_transfers(scanner, params),
        "incoming_transfers" => scanner_incoming_transfers(scanner, params),
        "get_staked_outputs" => scanner_get_staked_outputs(scanner),
        "get_staked_balance" => scanner_get_staked_balance(scanner),
        "get_transfer_by_txid" | "get_payments" | "get_bulk_payments" => {
            Err(WalletError {
                code: -1,
                message: format!("scanner handler for '{method}' not yet implemented"),
            })
        }
        _ => unreachable!("method not in SCANNER_METHODS"),
    }
}

#[cfg(feature = "rust-scanner")]
fn scanner_get_balance(
    scanner: &ScannerState,
    _params: Value,
) -> Result<Value, WalletError> {
    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;
    let height = state.height();
    let summary = state.balance(height);
    serde_json::to_value(&summary).map_err(|e| WalletError {
        code: -1,
        message: format!("JSON serialization error: {e}"),
    })
}

#[cfg(feature = "rust-scanner")]
fn scanner_get_height(scanner: &ScannerState) -> Result<Value, WalletError> {
    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;
    Ok(serde_json::json!({ "height": state.height() }))
}

#[cfg(feature = "rust-scanner")]
fn scanner_get_transfers(
    scanner: &ScannerState,
    params: Value,
) -> Result<Value, WalletError> {
    let want_in = params.get("in").and_then(|v| v.as_bool()).unwrap_or(false);
    let want_out = params.get("out").and_then(|v| v.as_bool()).unwrap_or(false);

    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;

    let mut result = serde_json::Map::new();

    if want_in {
        let incoming: Vec<Value> = state
            .transfers()
            .iter()
            .filter(|td| !td.spent)
            .map(transfer_to_json)
            .collect();
        result.insert("in".to_string(), Value::Array(incoming));
    }

    if want_out {
        let outgoing: Vec<Value> = state
            .transfers()
            .iter()
            .filter(|td| td.spent)
            .map(transfer_to_json)
            .collect();
        result.insert("out".to_string(), Value::Array(outgoing));
    }

    Ok(Value::Object(result))
}

#[cfg(feature = "rust-scanner")]
fn scanner_incoming_transfers(
    scanner: &ScannerState,
    params: Value,
) -> Result<Value, WalletError> {
    let transfer_type = params
        .get("transfer_type")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;
    let height = state.height();

    let transfers: Vec<Value> = state
        .transfers()
        .iter()
        .filter(|td| match transfer_type {
            "available" => td.is_spendable(height),
            "unavailable" => !td.is_spendable(height) && !td.spent,
            _ => !td.spent,
        })
        .map(transfer_to_json)
        .collect();

    Ok(serde_json::json!({ "transfers": transfers }))
}

#[cfg(feature = "rust-scanner")]
fn scanner_get_staked_outputs(
    scanner: &ScannerState,
) -> Result<Value, WalletError> {
    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;

    let staked: Vec<Value> = state
        .staked_outputs()
        .iter()
        .map(|td| {
            serde_json::json!({
                "tx_hash": hex::encode(td.tx_hash),
                "output_index": td.internal_output_index,
                "amount": td.amount(),
                "tier": td.stake_tier,
                "lock_until": td.stake_lock_until,
                "matured": td.is_matured_stake(state.height()),
            })
        })
        .collect();

    Ok(serde_json::json!({ "staked_outputs": staked }))
}

#[cfg(feature = "rust-scanner")]
fn scanner_get_staked_balance(
    scanner: &ScannerState,
) -> Result<Value, WalletError> {
    let state = scanner.state.lock().map_err(|e| WalletError {
        code: -1,
        message: format!("scanner lock poisoned: {e}"),
    })?;
    let height = state.height();
    let summary = state.balance(height);

    Ok(serde_json::json!({
        "staked_total": summary.staked_total,
        "staked_matured": summary.staked_matured,
        "staked_locked": summary.staked_locked,
    }))
}

#[cfg(feature = "rust-scanner")]
fn transfer_to_json(td: &shekyl_scanner::TransferDetails) -> Value {
    serde_json::json!({
        "txid": hex::encode(td.tx_hash),
        "height": td.block_height,
        "amount": td.amount(),
        "spent": td.spent,
        "staked": td.staked,
        "stake_tier": td.stake_tier,
        "stake_lock_until": td.stake_lock_until,
        "frozen": td.frozen,
        "global_index": td.global_output_index,
        "subaddr_index": td.subaddress.map(|s| {
            serde_json::json!({ "major": s.account(), "minor": s.address() })
        }),
    })
}
