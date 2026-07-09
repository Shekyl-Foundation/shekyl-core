// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! JSON-RPC 2.0 wire types conforming to `docs/api/wallet_rpc.yaml`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::WalletRpcError;

/// Monotonic API contract version. Pre-genesis this stays `1` — incompatible
/// changes are atomic cutovers, not versioned skew (rule 16 user-absent
/// context inversion; `GetVersionResult.api_version` in the OpenAPI spec).
pub const API_VERSION: u32 = 1;

/// Incoming JSON-RPC 2.0 request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Client-supplied id (string or integer per the spec).
    pub id: Value,
    /// Method name.
    pub method: String,
    /// Per-method params object; defaults to `null` when omitted.
    #[serde(default)]
    pub params: Value,
}

/// Outgoing JSON-RPC 2.0 response. Exactly one of `result` / `error` is set
/// (JSON-RPC 2.0 §5).
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Echo of the request id (may be null for notifications; we always echo).
    pub id: Value,
    /// Success payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcErrorBody>,
}

/// JSON-RPC `error` object.
#[derive(Debug, Serialize)]
pub struct JsonRpcErrorBody {
    /// Allocated code from `WalletRpcErrorCode`.
    pub code: i32,
    /// Human-readable summary (no secrets / amounts / counterparty addresses).
    pub message: String,
    /// Optional structured detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    /// Build a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response from a [`WalletRpcError`].
    pub fn from_error(id: Value, err: &WalletRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcErrorBody {
                code: err.code().as_i32(),
                message: err.message(),
                data: err.data(),
            }),
        }
    }

    /// Build an error response when the request id is unknown (parse error).
    pub fn parse_error() -> Self {
        Self::from_error(Value::Null, &WalletRpcError::ParseError)
    }
}

/// `get_version` result (`GetVersionResult` in the OpenAPI spec).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetVersionResult {
    /// `shekyl-wallet-rpc` semver.
    pub version: String,
    /// Monotonic API contract version (see [`API_VERSION`]).
    pub api_version: u32,
}
