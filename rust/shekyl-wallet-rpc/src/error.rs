// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletRpcError` and the stable JSON-RPC error-code table from
//! `docs/api/wallet_rpc.yaml` (`WalletRpcErrorCode`).

use serde_json::Value;
use thiserror::Error;

/// Allocated application / protocol error codes (spec enum).
///
/// Emitting a code outside this set is a conformance failure. RESERVED-range
/// codes land in the sub-PR that implements their method (rule 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WalletRpcErrorCode {
    /// JSON-RPC parse error.
    ParseError = -32700,
    /// JSON-RPC invalid request.
    InvalidRequest = -32600,
    /// JSON-RPC method not found (also covers RESERVED / not-yet-implemented).
    MethodNotFound = -32601,
    /// JSON-RPC invalid params.
    InvalidParams = -32602,
    /// JSON-RPC internal error.
    InternalError = -32603,
    /// A wallet is already open; close first.
    WalletAlreadyOpen = -29000,
    /// No wallet is open.
    WalletNotOpen = -29001,
    /// Create refused: wallet file already exists.
    WalletFileExists = -29002,
    /// Open failed: no such wallet file.
    WalletFileNotFound = -29003,
    /// Open / change_password: MAC / password failure.
    InvalidPassword = -29004,
    /// Operation requires a capability the open wallet lacks.
    CapabilityForbids = -29005,
    /// Build: address parse / network check failed.
    InvalidRecipient = -29100,
    /// Build: spendable balance too low.
    InsufficientFunds = -29101,
    /// Build: daemon fee query failed.
    FeeEstimationFailed = -29102,
    /// Submit: unknown / expired reservation handle.
    ReservationNotFound = -29103,
    /// Submit: reorg raced the reservation.
    SnapshotInvalidated = -29104,
    /// Submit: `seen_gen` ≠ `content_gen` (CT-5d).
    ContentGenMismatch = -29105,
    /// Submit: definite daemon rejection.
    SubmitRejected = -29106,
    /// Submit: transport-level ambiguity.
    SubmitAmbiguous = -29107,
    /// Refresh: single-flight violation.
    RefreshInProgress = -29200,
    /// Refresh / rescan: daemon RPC failed.
    DaemonUnreachable = -29201,
    /// `get_transfer_by_id`: no match.
    UnknownTransferId = -29400,
    /// Server: wallet-dir tenancy unavailable.
    TenantUnavailable = -29900,
}

impl WalletRpcErrorCode {
    /// Stable numeric code for the JSON-RPC `error.code` field.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Unified RPC-boundary error. Domain errors from `shekyl-engine-core`
/// convert into this enum in Phase 4b; Phase 4a only needs protocol /
/// scaffold variants.
#[derive(Debug, Error)]
pub enum WalletRpcError {
    /// JSON body could not be parsed.
    #[error("parse error")]
    ParseError,
    /// Request failed JSON-RPC 2.0 structural checks.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Method name is unknown, RESERVED, or not yet implemented.
    #[error("method not found: {0}")]
    MethodNotFound(String),
    /// Params failed schema / type checks.
    #[error("invalid params: {0}")]
    InvalidParams(String),
    /// Unexpected internal failure.
    #[error("internal error: {0}")]
    InternalError(String),
    /// HTTP basic auth failed or was missing when required.
    #[error("unauthorized")]
    Unauthorized,
}

impl WalletRpcError {
    /// Map to the allocated JSON-RPC error code.
    pub fn code(&self) -> WalletRpcErrorCode {
        match self {
            Self::ParseError => WalletRpcErrorCode::ParseError,
            Self::InvalidRequest(_) => WalletRpcErrorCode::InvalidRequest,
            Self::MethodNotFound(_) => WalletRpcErrorCode::MethodNotFound,
            Self::InvalidParams(_) => WalletRpcErrorCode::InvalidParams,
            Self::InternalError(_) => WalletRpcErrorCode::InternalError,
            // Auth failures are transport-level (HTTP 401), not JSON-RPC codes.
            // Callers that need a JSON-RPC code for tests use InvalidRequest.
            Self::Unauthorized => WalletRpcErrorCode::InvalidRequest,
        }
    }

    /// Human-readable message. Never carries secrets, counterparty
    /// addresses, or amounts (spec: error text is the most-logged surface).
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Optional structured `error.data` object.
    pub fn data(&self) -> Option<Value> {
        None
    }
}
