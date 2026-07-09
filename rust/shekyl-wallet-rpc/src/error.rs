// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `WalletRpcError` and the stable JSON-RPC error-code table from
//! `docs/api/wallet_rpc.yaml` (`WalletRpcErrorCode`).

use serde_json::{json, Value};
use shekyl_engine_core::engine::error::{RetryableRejectCause, TerminalErrorKind};
use shekyl_engine_core::engine::SubmitError;
use shekyl_engine_core::{
    Capability, ChangePasswordError, IoError, OpenError, PendingTxError, PersistenceError,
    RefreshError, SendError,
};
use shekyl_engine_file::WalletFileError;
use shekyl_rpc_client::{RejectCause, SubmitVerdict};
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
/// convert into this enum at the lifecycle / send boundary.
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
    /// A wallet is already open on this tenant.
    #[error("wallet already open")]
    WalletAlreadyOpen,
    /// No wallet is open on this tenant.
    #[error("wallet not open")]
    WalletNotOpen,
    /// Create refused: keys file already exists.
    #[error("wallet file exists")]
    WalletFileExists,
    /// Open failed: keys file not found.
    #[error("wallet file not found")]
    WalletFileNotFound,
    /// Open / change_password: wrong password (or corrupt envelope).
    #[error("invalid password")]
    InvalidPassword,
    /// Operation requires a capability the open wallet lacks.
    #[error("capability forbids this operation")]
    CapabilityForbids {
        /// OpenAPI capability mode string (`FULL` / `VIEW_ONLY` / …).
        capability: String,
    },
    /// Daemon RPC unreachable / failed.
    #[error("daemon unreachable")]
    DaemonUnreachable,
    /// Refresh already in flight (single-flight).
    #[error("refresh already running")]
    RefreshInProgress,
    /// Build: address parse / network check failed.
    #[error("invalid recipient")]
    InvalidRecipient,
    /// Build: spendable balance too low.
    #[error("insufficient funds")]
    InsufficientFunds,
    /// Build: daemon fee query failed.
    #[error("fee estimation failed")]
    FeeEstimationFailed,
    /// Submit: unknown / expired reservation handle.
    #[error("reservation not found")]
    ReservationNotFound,
    /// Submit: reorg raced the reservation.
    #[error("snapshot invalidated")]
    SnapshotInvalidated,
    /// Submit: `seen_gen` ≠ `content_gen` (CT-5d).
    #[error("content generation mismatch")]
    ContentGenMismatch {
        /// Current content generation the client must re-confirm.
        content_gen: u64,
    },
    /// Submit: definite daemon rejection.
    #[error("submit rejected")]
    SubmitRejected {
        /// OpenAPI `error.data`: serde-tagged [`SubmitVerdict`] projection.
        data: Value,
    },
    /// Submit: transport-level ambiguity.
    #[error("submit ambiguous")]
    SubmitAmbiguous,
    /// `get_transfer_by_id`: no match.
    #[error("unknown transfer id")]
    UnknownTransferId,
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
            Self::Unauthorized => WalletRpcErrorCode::InvalidRequest,
            Self::WalletAlreadyOpen => WalletRpcErrorCode::WalletAlreadyOpen,
            Self::WalletNotOpen => WalletRpcErrorCode::WalletNotOpen,
            Self::WalletFileExists => WalletRpcErrorCode::WalletFileExists,
            Self::WalletFileNotFound => WalletRpcErrorCode::WalletFileNotFound,
            Self::InvalidPassword => WalletRpcErrorCode::InvalidPassword,
            Self::CapabilityForbids { .. } => WalletRpcErrorCode::CapabilityForbids,
            Self::DaemonUnreachable => WalletRpcErrorCode::DaemonUnreachable,
            Self::RefreshInProgress => WalletRpcErrorCode::RefreshInProgress,
            Self::InvalidRecipient => WalletRpcErrorCode::InvalidRecipient,
            Self::InsufficientFunds => WalletRpcErrorCode::InsufficientFunds,
            Self::FeeEstimationFailed => WalletRpcErrorCode::FeeEstimationFailed,
            Self::ReservationNotFound => WalletRpcErrorCode::ReservationNotFound,
            Self::SnapshotInvalidated => WalletRpcErrorCode::SnapshotInvalidated,
            Self::ContentGenMismatch { .. } => WalletRpcErrorCode::ContentGenMismatch,
            Self::SubmitRejected { .. } => WalletRpcErrorCode::SubmitRejected,
            Self::SubmitAmbiguous => WalletRpcErrorCode::SubmitAmbiguous,
            Self::UnknownTransferId => WalletRpcErrorCode::UnknownTransferId,
        }
    }

    /// Human-readable message. Never carries secrets, counterparty
    /// addresses, or amounts (spec: error text is the most-logged surface).
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Optional structured `error.data` object.
    pub fn data(&self) -> Option<Value> {
        match self {
            Self::CapabilityForbids { capability } => Some(json!({ "capability": capability })),
            Self::ContentGenMismatch { content_gen } => Some(json!({ "content_gen": content_gen })),
            Self::SubmitRejected { data } => Some(data.clone()),
            _ => None,
        }
    }

    fn submit_rejected(cause: RejectCause) -> Self {
        let verdict = SubmitVerdict::Rejected { cause };
        let data = serde_json::to_value(verdict)
            .unwrap_or_else(|_| json!({ "verdict": "rejected", "cause": "unrecognized" }));
        Self::SubmitRejected { data }
    }
}

impl From<OpenError> for WalletRpcError {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::IncorrectPassword => Self::InvalidPassword,
            OpenError::CapabilityMismatch { found }
            | OpenError::CapabilityNotYetImplemented { capability: found } => {
                Self::CapabilityForbids {
                    capability: capability_mode_str(found).to_owned(),
                }
            }
            OpenError::OutstandingPendingTx { count } => Self::InternalError(format!(
                "cannot close: {count} pending transaction(s) still outstanding"
            )),
            OpenError::NetworkMismatch { wallet, expected } => Self::InternalError(format!(
                "network mismatch: wallet={wallet}, expected={expected}"
            )),
            OpenError::Io(IoError::WalletFile { detail }) => classify_wallet_file_detail(&detail),
            OpenError::Io(IoError::Daemon { .. }) => Self::DaemonUnreachable,
            OpenError::Io(other) => Self::InternalError(other.to_string()),
            OpenError::Key(e) => Self::InternalError(e.to_string()),
            OpenError::Persistence(e) => Self::InternalError(e.to_string()),
        }
    }
}

impl From<ChangePasswordError> for WalletRpcError {
    fn from(err: ChangePasswordError) -> Self {
        match err {
            ChangePasswordError::RotateFailed(PersistenceError::WalletFile(
                WalletFileError::Envelope(_),
            )) => Self::InvalidPassword,
            ChangePasswordError::RotateFailed(e) => Self::InternalError(e.to_string()),
            ChangePasswordError::RotatedButPrefsFlushFailed(e) => {
                Self::InternalError(format!("password rotated but prefs flush failed: {e}"))
            }
        }
    }
}

impl From<RefreshError> for WalletRpcError {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::AlreadyRunning => Self::RefreshInProgress,
            RefreshError::Io(IoError::Daemon { .. })
            | RefreshError::Io(IoError::Scanner { .. }) => Self::DaemonUnreachable,
            RefreshError::Io(other) => Self::InternalError(other.to_string()),
            RefreshError::ConcurrentMutation { wallet, result } => Self::InternalError(format!(
                "refresh concurrent mutation: wallet={wallet}, result={result}"
            )),
            RefreshError::MalformedScanResult { reason } => {
                Self::InternalError(format!("malformed scan result: {reason}"))
            }
            RefreshError::Cancelled => Self::InternalError("refresh cancelled".into()),
            RefreshError::InternalInvariantViolation { context } => {
                Self::InternalError(format!("refresh invariant: {context}"))
            }
            RefreshError::CurveTreeIngest { context, .. } => {
                Self::InternalError(format!("curve-tree ingest: {context}"))
            }
        }
    }
}

impl From<SendError> for WalletRpcError {
    fn from(err: SendError) -> Self {
        match err {
            SendError::InvalidRecipient { .. } => Self::InvalidRecipient,
            SendError::InsufficientFunds { .. } => Self::InsufficientFunds,
            SendError::Io(IoError::Daemon { .. }) => Self::FeeEstimationFailed,
            SendError::Io(other) => Self::InternalError(other.to_string()),
            SendError::Tx(e) => Self::InternalError(e.to_string()),
            SendError::CannotSign { reason } => {
                Self::InternalError(format!("cannot sign: {reason}"))
            }
            SendError::SpendUnavailableRebuilding { .. } => Self::InternalError(
                "spending temporarily unavailable while membership data rebuilds".into(),
            ),
            SendError::CurveTreeUnavailable { detail } => {
                Self::InternalError(format!("curve-tree unavailable: {detail}"))
            }
            SendError::OutputNotYetSpendable { .. } => {
                Self::InternalError("output not yet spendable at the reference block".into())
            }
            SendError::WalletTooYoungToSpend { .. } => {
                Self::InternalError("wallet too young to spend".into())
            }
            SendError::SubmitLoopBreakerTripped { .. } => {
                Self::InternalError("submit loop-breaker tripped".into())
            }
        }
    }
}

impl From<SubmitError> for WalletRpcError {
    fn from(err: SubmitError) -> Self {
        match err {
            SubmitError::ReservationNotFound { .. } => Self::ReservationNotFound,
            SubmitError::SnapshotInvalidated { .. } => Self::SnapshotInvalidated,
            SubmitError::ContentChanged { content_gen, .. } => {
                Self::ContentGenMismatch { content_gen }
            }
            SubmitError::DaemonRejectedTerminal { kind } => {
                Self::submit_rejected(terminal_to_reject_cause(kind))
            }
            SubmitError::DaemonRejectedRetryable { cause, .. } => {
                Self::submit_rejected(retryable_to_reject_cause(cause))
            }
            SubmitError::DaemonAmbiguous { .. } => Self::SubmitAmbiguous,
            SubmitError::SubmitAlreadyPending { .. } => {
                Self::InternalError("submit already pending for this reservation".into())
            }
            SubmitError::ReanchorUnavailable { .. } => {
                Self::InternalError("re-anchor unavailable; retry later".into())
            }
            SubmitError::ReselectionRequired { .. } => {
                Self::InternalError("reselection required; discard and rebuild".into())
            }
            other => Self::InternalError(other.to_string()),
        }
    }
}

/// Map Engine terminal reject kinds onto the wire [`RejectCause`] vocabulary.
fn terminal_to_reject_cause(kind: TerminalErrorKind) -> RejectCause {
    match kind {
        TerminalErrorKind::DoubleSpend => RejectCause::DoubleSpendConflict,
        TerminalErrorKind::FeeTooLow => RejectCause::FeeTooLow,
        TerminalErrorKind::Malformed => RejectCause::Malformed,
        TerminalErrorKind::Unrecognized => RejectCause::Unrecognized,
        // `TerminalErrorKind` is `#[non_exhaustive]`; unknown future kinds
        // take the fail-safe Unrecognized disposition (DAEMON_SUBMIT_VERDICT §2.5).
        _ => RejectCause::Unrecognized,
    }
}

/// Map Engine retryable reject causes onto the wire [`RejectCause`] vocabulary.
fn retryable_to_reject_cause(cause: RetryableRejectCause) -> RejectCause {
    match cause {
        RetryableRejectCause::StaleRoot => RejectCause::StaleRoot,
        RetryableRejectCause::ReferenceTooRecent => RejectCause::ReferenceTooRecent,
        RetryableRejectCause::ReferenceNotFound => RejectCause::ReferenceNotFound,
        _ => RejectCause::Unrecognized,
    }
}

impl From<PendingTxError> for WalletRpcError {
    fn from(err: PendingTxError) -> Self {
        match err {
            PendingTxError::ReservationNotFound { .. } | PendingTxError::UnknownHandle => {
                Self::ReservationNotFound
            }
            PendingTxError::ChainStateChanged { .. } | PendingTxError::TooOld { .. } => {
                Self::SnapshotInvalidated
            }
            PendingTxError::DiscardBlockedPendingDaemonAck { .. } => Self::SubmitAmbiguous,
            PendingTxError::SubmitAlreadyPending { .. } => {
                Self::InternalError("submit already pending for this reservation".into())
            }
            PendingTxError::Io(IoError::Daemon { .. }) => Self::SubmitAmbiguous,
            PendingTxError::Io(other) => Self::InternalError(other.to_string()),
            other => Self::InternalError(other.to_string()),
        }
    }
}

fn classify_wallet_file_detail(detail: &str) -> WalletRpcError {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("already exists") || lower.contains("refusing to overwrite") {
        WalletRpcError::WalletFileExists
    } else if lower.contains("not found") || lower.contains("no such file") {
        WalletRpcError::WalletFileNotFound
    } else if lower.contains("password") || lower.contains("corrupt") {
        WalletRpcError::InvalidPassword
    } else {
        WalletRpcError::InternalError(detail.to_owned())
    }
}

fn capability_mode_str(cap: Capability) -> &'static str {
    match cap {
        Capability::Full => "FULL",
        Capability::ViewOnly => "VIEW_ONLY",
        Capability::HardwareOffload => "HARDWARE_OFFLOAD",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_incorrect_password() {
        let err: WalletRpcError = OpenError::IncorrectPassword.into();
        assert_eq!(err.code(), WalletRpcErrorCode::InvalidPassword);
    }

    #[test]
    fn maps_keys_already_exists_detail() {
        let err = classify_wallet_file_detail(
            "refusing to overwrite existing keys file at /tmp/x.wallet.keys",
        );
        assert_eq!(err.code(), WalletRpcErrorCode::WalletFileExists);
    }

    #[test]
    fn maps_refresh_already_running() {
        let err: WalletRpcError = RefreshError::AlreadyRunning.into();
        assert_eq!(err.code(), WalletRpcErrorCode::RefreshInProgress);
    }

    #[test]
    fn maps_refresh_daemon_io() {
        let err: WalletRpcError = RefreshError::Io(IoError::Daemon {
            detail: "connection refused".into(),
        })
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::DaemonUnreachable);
    }

    #[test]
    fn submit_rejected_data_is_wire_submit_verdict() {
        use shekyl_engine_core::engine::error::TerminalErrorKind;
        use shekyl_engine_core::engine::SubmitError;

        let err: WalletRpcError = SubmitError::DaemonRejectedTerminal {
            kind: TerminalErrorKind::FeeTooLow,
        }
        .into();
        assert_eq!(err.code(), WalletRpcErrorCode::SubmitRejected);
        let data = err.data().expect("data");
        assert_eq!(data["verdict"], "rejected");
        assert_eq!(data["cause"], "fee_too_low");
    }
}
