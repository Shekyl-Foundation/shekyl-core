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
    ChangePasswordError, IoError, OpenError, PScanStartError, PendingTxError, PersistenceError,
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
    /// Refresh / rescan / proofs: daemon RPC failed.
    ///
    /// For `rescan_blockchain` only the **preflight** refusal uses this code
    /// (wallet untouched). A scan that fails *after* the reset is durable
    /// emits [`Self::RescanIncomplete`] instead — same daemon class of
    /// failure, opposite durability claim.
    DaemonUnreachable = -29201,
    /// Rescan: refused — transactions in flight whose spend record a chain
    /// replay cannot rebuild. A resolvable state conflict, not a bad request.
    RescanBlocked = -29202,
    /// Rescan: the reset persisted, then the producer failed before the
    /// ledger was rebuilt. History is empty until a rescan finishes; retry.
    RescanIncomplete = -29203,
    /// `check_*`: proof string failed decode / framing / size caps.
    ProofMalformed = -29300,
    /// `get_tx_proof` OUTBOUND: no retained per-tx secret for the txid.
    ProofTxSecretUnavailable = -29301,
    /// `get_tx_proof` INBOUND / `get_reserve_proof`: nothing to prove.
    ProofNoProvableOutputs = -29302,
    /// Proofs: a txid named by the request is unknown to the daemon.
    ProofTxNotFound = -29303,
    /// `get_transfer_by_id`: no match.
    UnknownTransferId = -29400,
    /// Stake: funding not ready (W1-clean refusal — fund the persona /
    /// let the scan catch up, then retry).
    StakeNotReady = -29500,
    /// Stake: a signed bond post is already awaiting dispatch.
    StakeInFlight = -29501,
    /// Stake: the wallet already holds a confirmed bond (idempotency).
    AlreadyStaked = -29502,
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
    /// Rescan refused: in-flight transactions whose spend record a chain
    /// replay cannot rebuild. Transient and client-resolvable — submit or
    /// discard reservations, wait for confirmations, then retry.
    #[error(
        "cannot rescan while transactions are in flight: {detail}; \
         submit or discard pending transactions, wait for confirmations, then retry"
    )]
    RescanBlocked {
        /// Server-side counts (`error.data.detail`) — no amounts, no txids.
        detail: String,
    },
    /// Rescan reset is durable but the subsequent scan failed. History is
    /// empty until a rescan finishes; the wallet is re-runnable.
    #[error(
        "rescan reset completed but the scan failed; history is empty until a \
         rescan finishes — retry once the problem is resolved"
    )]
    RescanIncomplete,
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
    /// `check_*`: proof string failed Bech32m decode, carried the wrong
    /// HRP, its wire framing did not parse, or it exceeds the section's
    /// size caps. The client message is deliberately stable and
    /// detail-free — the framing detail can echo client-controlled bytes
    /// (the HRP) and is logged server-side at the mapping site instead.
    #[error("proof string malformed")]
    ProofMalformed,
    /// `get_tx_proof` OUTBOUND: this wallet holds no retained per-tx
    /// secret for the txid (it did not send the tx, or another copy did).
    #[error("no retained tx secret for this transaction")]
    ProofTxSecretUnavailable,
    /// `get_tx_proof` INBOUND with no owned outputs in the tx, or
    /// `get_reserve_proof` with zero eligible outputs / unspent total
    /// below the requested amount.
    #[error("no provable outputs")]
    ProofNoProvableOutputs,
    /// Proofs: a txid named by the request (or embedded in a reserve
    /// proof's locators) is unknown to the daemon.
    #[error("transaction not found")]
    ProofTxNotFound,
    /// `get_transfer_by_id`: no match.
    #[error("unknown transfer id")]
    UnknownTransferId,
    /// Stake: funding not ready — a W1-clean refusal (nothing durable was
    /// written): fund the persona and/or wait for the wallet's persona scan
    /// to catch up, then call `stake` again.
    #[error("stake not ready: fund the wallet's staking balance and retry once synced")]
    StakeNotReady {
        /// Server-side detail (`error.data.detail`) — operational cause, no
        /// secrets or amounts.
        detail: String,
    },
    /// Stake: a signed bond post is already sealed and awaiting its
    /// scheduled broadcast; no action needed.
    #[error("stake already in flight: the bond will broadcast at its scheduled time")]
    StakeInFlight,
    /// Stake: the wallet already staked (a confirmed bond exists).
    #[error("already staking")]
    AlreadyStaked,
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
            Self::RescanBlocked { .. } => WalletRpcErrorCode::RescanBlocked,
            Self::RescanIncomplete => WalletRpcErrorCode::RescanIncomplete,
            Self::InvalidRecipient => WalletRpcErrorCode::InvalidRecipient,
            Self::InsufficientFunds => WalletRpcErrorCode::InsufficientFunds,
            Self::FeeEstimationFailed => WalletRpcErrorCode::FeeEstimationFailed,
            Self::ReservationNotFound => WalletRpcErrorCode::ReservationNotFound,
            Self::SnapshotInvalidated => WalletRpcErrorCode::SnapshotInvalidated,
            Self::ContentGenMismatch { .. } => WalletRpcErrorCode::ContentGenMismatch,
            Self::SubmitRejected { .. } => WalletRpcErrorCode::SubmitRejected,
            Self::SubmitAmbiguous => WalletRpcErrorCode::SubmitAmbiguous,
            Self::ProofMalformed => WalletRpcErrorCode::ProofMalformed,
            Self::ProofTxSecretUnavailable => WalletRpcErrorCode::ProofTxSecretUnavailable,
            Self::ProofNoProvableOutputs => WalletRpcErrorCode::ProofNoProvableOutputs,
            Self::ProofTxNotFound => WalletRpcErrorCode::ProofTxNotFound,
            Self::UnknownTransferId => WalletRpcErrorCode::UnknownTransferId,
            Self::StakeNotReady { .. } => WalletRpcErrorCode::StakeNotReady,
            Self::StakeInFlight => WalletRpcErrorCode::StakeInFlight,
            Self::AlreadyStaked => WalletRpcErrorCode::AlreadyStaked,
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
            Self::StakeNotReady { detail } | Self::RescanBlocked { detail } => {
                Some(json!({ "detail": detail }))
            }
            _ => None,
        }
    }

    fn submit_rejected(cause: RejectCause) -> Self {
        let verdict = SubmitVerdict::Rejected { cause };
        let data = serde_json::to_value(verdict)
            .unwrap_or_else(|_| json!({ "verdict": "rejected", "cause": "unrecognized" }));
        Self::SubmitRejected { data }
    }

    /// Map a producer failure that arrives **after** `start_rescan` returned
    /// a handle — i.e. after the reset is durable.
    ///
    /// Must not emit [`WalletRpcErrorCode::DaemonUnreachable`]: that code's
    /// rescan contract is "wallet untouched" (daemon preflight). A mid-scan
    /// daemon drop is the same *class* of failure and the opposite durability
    /// claim — clients that branch on `-29201` (CLI included) would otherwise
    /// tell the user nothing changed while history sits at zero.
    pub(crate) fn from_rescan_scan_failure(err: RefreshError) -> Self {
        match &err {
            // Retryable producer failures: reset held, scan did not finish.
            RefreshError::Io(io) => {
                tracing::warn!(detail = %io, "rescan scan failed after durable reset");
                Self::RescanIncomplete
            }
            RefreshError::Cancelled
            | RefreshError::MalformedScanResult { .. }
            | RefreshError::CurveTreeIngest { .. } => {
                tracing::warn!(?err, "rescan scan failed after durable reset");
                Self::RescanIncomplete
            }
            // Should be unreachable on the join path (raised only by
            // `start_rescan` before the producer spawns), but if they appear
            // keep their pre-reset codes rather than inventing a third story.
            RefreshError::AlreadyRunning
            | RefreshError::RescanBlocked { .. }
            | RefreshError::RescanPersist(_) => err.into(),
            other => {
                tracing::warn!(?other, "rescan scan failed after durable reset (internal)");
                internal_detail("rescan scan failed after reset", format!("{other:?}"))
            }
        }
    }
}

impl From<OpenError> for WalletRpcError {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::IncorrectPassword => Self::InvalidPassword,
            OpenError::CapabilityMismatch { found }
            | OpenError::CapabilityNotYetImplemented { capability: found } => {
                Self::CapabilityForbids {
                    capability: crate::types::capability_mode_str(found).to_owned(),
                }
            }
            OpenError::OutstandingPendingTx { count } => {
                Self::InternalError(format!("outstanding pending transaction(s): {count}"))
            }
            OpenError::NetworkMismatch { wallet, expected } => Self::InternalError(format!(
                "network mismatch: wallet={wallet}, expected={expected}"
            )),
            OpenError::Io(IoError::WalletFile { detail }) => classify_wallet_file_detail(&detail),
            OpenError::Io(IoError::Daemon { .. }) => Self::DaemonUnreachable,
            OpenError::Io(other) => internal_detail("wallet I/O error", other),
            OpenError::Key(e) => internal_detail("wallet key error", e),
            OpenError::Persistence(e) => internal_detail("wallet persistence error", e),
        }
    }
}

impl From<ChangePasswordError> for WalletRpcError {
    fn from(err: ChangePasswordError) -> Self {
        match err {
            ChangePasswordError::RotateFailed(PersistenceError::WalletFile(
                WalletFileError::Envelope(_),
            )) => Self::InvalidPassword,
            ChangePasswordError::RotateFailed(e) => internal_detail("password rotation failed", e),
            ChangePasswordError::RotatedButPrefsFlushFailed(e) => {
                internal_detail("password rotated but preferences flush failed", e)
            }
        }
    }
}

impl From<RefreshError> for WalletRpcError {
    fn from(err: RefreshError) -> Self {
        match err {
            RefreshError::AlreadyRunning => Self::RefreshInProgress,
            // A state conflict, not a malformed request: `rescan_blockchain`
            // takes an empty params object, so the params were by definition
            // correct. `-32602` here would tell an automated client its
            // request shape is permanently wrong when the truth is "retry
            // once the in-flight transactions settle".
            RefreshError::RescanBlocked {
                reservations,
                unconfirmed,
            } => Self::RescanBlocked {
                detail: format!(
                    "{reservations} reservation(s), {unconfirmed} unconfirmed transaction(s)"
                ),
            },
            // Past the point of no return for the in-memory ledger; durable
            // save may have failed. Category-only message — `detail` can
            // carry a local filesystem path (rule 30 / `message()` contract).
            RefreshError::RescanPersist(detail) => {
                internal_detail("rescan reset persistence failed", detail)
            }
            RefreshError::Io(IoError::Daemon { .. })
            | RefreshError::Io(IoError::Scanner { .. }) => Self::DaemonUnreachable,
            RefreshError::Io(other) => internal_detail("refresh I/O error", other),
            RefreshError::ConcurrentMutation { wallet, result } => internal_detail(
                "refresh concurrent mutation",
                format!("wallet={wallet}, result={result}"),
            ),
            RefreshError::MalformedScanResult { reason } => {
                internal_detail("malformed scan result", reason)
            }
            RefreshError::Cancelled => Self::InternalError("refresh cancelled".into()),
            RefreshError::InternalInvariantViolation { context } => {
                internal_detail("refresh invariant", context)
            }
            RefreshError::CurveTreeIngest { context, .. } => {
                internal_detail("curve-tree ingest", context)
            }
        }
    }
}

impl From<PScanStartError> for WalletRpcError {
    fn from(err: PScanStartError) -> Self {
        match err {
            // The auto-start (`start_pscan_if_staker`) guards on the stake engine
            // before spawning, and a fresh open holds a fresh single-flight slot,
            // so neither of these is reachable on the lifecycle path. Map them
            // defensively rather than panicking if a future caller hits them.
            PScanStartError::NoStakeEngine => {
                Self::InternalError("p-scan start: no stake engine".into())
            }
            PScanStartError::AlreadyRunning => {
                Self::InternalError("p-scan start: task already running".into())
            }
            // The reachable one: a corrupt / version-mismatched `.wallet.pscan`
            // (or `.wallet.pending`) seal. Fail the staker's open closed — a
            // staker whose firewall scan cannot start must not open into a state
            // where it silently is not scanning (privacy is not a degraded mode).
            //
            // The client message is deliberately stable and detail-free: the
            // boxed cause can carry a local filesystem path or internal schema
            // detail, and this string is returned over JSON-RPC. The detailed
            // cause is logged server-side at the reachable call site
            // (`lifecycle::wrap_and_start_pscan`), not handed to the client.
            PScanStartError::LoadFailed(_source) => {
                Self::InternalError("p-scan sealed state failed to load".into())
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

/// Map an internal error to a category-only RPC message, logging the raw cause
/// server-side. `message()` is the most-logged surface and, in remote mode,
/// crosses to the client, so it must never carry a local filesystem path or
/// internal schema (rule 30; the `message()` contract). The full detail is
/// preserved in the server's own logs for diagnosis — mirroring the
/// `PScanStartError::LoadFailed` discipline above.
fn internal_detail(category: &'static str, detail: impl std::fmt::Display) -> WalletRpcError {
    tracing::warn!(category, detail = %detail, "wallet-rpc internal error");
    WalletRpcError::InternalError(category.to_owned())
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

    /// Join-path failures after a durable reset must not reuse `-29201`:
    /// that code's rescan contract is "wallet untouched" (preflight only).
    #[test]
    fn post_reset_daemon_io_is_rescan_incomplete_not_unreachable() {
        let err = WalletRpcError::from_rescan_scan_failure(RefreshError::Io(IoError::Daemon {
            detail: "/tmp/wallet.keys connection refused".into(),
        }));
        assert_eq!(err.code(), WalletRpcErrorCode::RescanIncomplete);
        assert!(
            !err.message().contains("/tmp"),
            "post-reset scan failure must not echo local paths: {}",
            err.message()
        );
    }

    #[test]
    fn rescan_persist_is_category_only() {
        let err: WalletRpcError =
            RefreshError::RescanPersist("/home/user/.shekyl/wallet.keys: ENOSPC".into()).into();
        assert_eq!(err.code(), WalletRpcErrorCode::InternalError);
        assert_eq!(
            err.message(),
            "internal error: rescan reset persistence failed"
        );
        assert!(
            !err.message().contains("/home"),
            "persist failure must not leak filesystem paths"
        );
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
