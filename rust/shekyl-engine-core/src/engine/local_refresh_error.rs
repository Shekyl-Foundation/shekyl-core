// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The refresh producer's error vocabulary: [`LocalRefreshError`], its
//! projection onto [`RefreshError`], and the bounded [`ProtocolErrorKind`]
//! classification of an upstream [`RpcError`] for the diagnostic stream.
//!
//! Split from `local_refresh.rs` so the producer workflow file measures the
//! workflow. The terminal error carries no attacker-controlled string
//! (§5.4.7 R6); per-event detail flows through the
//! [`DiagnosticSink`](crate::engine::diagnostics::DiagnosticSink).
//! [`LocalRefreshError::PastFinality`] carries a [`FinalityStop`] because
//! the refusal's depth is the structural branch, not a daemon payload.

use shekyl_rpc_client::{DaemonFault, RpcError};

use crate::engine::diagnostics::ProtocolErrorKind;
use crate::engine::error::{FinalityStop, IoError, RefreshError};

// ============================================================================
// LocalRefreshError
// ============================================================================

/// Producer-side error type for [`LocalRefresh::produce_scan_result`].
///
/// No attacker-controlled `String`, per the §2.3 + §5.4.7 R6
/// two-channel binding pinned at
/// [`RefreshEngine::Error`](crate::engine::traits::refresh::RefreshEngine::Error)'s
/// rustdoc. Per-event detail (height, RPC payload, scanner
/// rejection class) flows through the [`DiagnosticSink`] channel.
/// [`Self::PastFinality`] is the one variant with fields: a
/// [`FinalityStop`], two block-counts and a closed breach, which is
/// what the orchestrator reports. A daemon payload cannot land there.
///
/// # Variant set
///
/// - [`Cancelled`](Self::Cancelled) — observed at cancellation
///   checkpoints 2, 3, or 5. Producer returns immediately with
///   no further scan work.
/// - [`DaemonUnreachable`](Self::DaemonUnreachable) /
///   [`DaemonProtocol`](Self::DaemonProtocol) — a daemon RPC
///   failed (block-fetch retry budget exhausted; daemon-tip RPC
///   failure), split by the branch its [`DaemonFault`] class
///   takes: retry later, or a reply that broke the contract.
///   Per-event classification flows via
///   [`RefreshDiagnostic::DaemonProtocolError`].
/// - [`Malformed`](Self::Malformed) — daemon delivered a
///   structurally-malformed block (either the producer's
///   excessive-outputs pre-pass tripped, or the scanner's own
///   structural validation rejected the block). The
///   `MalformedKind` discriminant is reported through
///   [`DiagnosticSink`] at the emit site.
/// - [`Internal`](Self::Internal) — structural invariant
///   violation that is not reachable from adversarial input
///   (e.g., scanner construction from validated view-material
///   fails). Reported to the orchestrator as
///   [`RefreshError::InternalInvariantViolation`] with a
///   `&'static str` context label.
///
/// [`LocalRefresh::produce_scan_result`]: crate::engine::traits::refresh::RefreshEngine::produce_scan_result
/// [`DiagnosticSink`]: crate::engine::diagnostics::DiagnosticSink
/// [`RefreshDiagnostic::DaemonProtocolError`]: crate::engine::diagnostics::RefreshDiagnostic::DaemonProtocolError
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LocalRefreshError {
    /// Cancellation observed at checkpoint 2, 3, or 5.
    #[error("scan cancelled before completing the requested range")]
    Cancelled,

    /// The daemon could not be reached, or stopped answering: the
    /// daemon-tip read failed, or the block-fetch retry budget ran out.
    /// Retry later, or check the daemon address.
    #[error("the daemon did not answer during refresh")]
    DaemonUnreachable,

    /// The daemon answered with something that breaks the RPC contract
    /// (a malformed, inconsistent or pruned reply). Another daemon may
    /// answer correctly.
    #[error("the daemon's reply broke the RPC contract during refresh")]
    DaemonProtocol,

    /// Daemon returned a structurally-malformed block (producer's
    /// pre-pass or scanner-side structural validation tripped).
    #[error("daemon returned a structurally malformed block")]
    Malformed,

    /// A further reorg was detected after the per-attempt rewind budget
    /// (`MAX_REORG_REWINDS_PER_ATTEMPT`) was spent. The attempt aborts
    /// rather than scanning on with detection disarmed — see the budget
    /// constant's docs for why merging a blind region is unsound for the
    /// bond watch's monotone adoptions.
    #[error("reorg storm: rewind budget exhausted and the chain diverged again")]
    ReorgStorm,

    /// Internal invariant violation; not reachable from
    /// adversarial input.
    #[error("internal invariant violation during refresh")]
    Internal,

    /// The fork walk cannot confirm a common ancestor inside the
    /// finality window. The scan attempt fails before a [`ScanResult`]
    /// with that rewind is emitted.
    ///
    /// [`ScanResult`]: crate::scan::ScanResult
    #[error("{0}")]
    PastFinality(FinalityStop),
}

impl LocalRefreshError {
    /// The structural branch a daemon failure takes. Only the fault's
    /// class crosses: its data stays behind, per the no-daemon-string binding.
    ///
    /// An identity refusal cannot reach the producer — the orchestrator
    /// settles identity first ([`prepare_refresh`]) and the client caches
    /// the verdict — and if one did, it is a daemon this wallet must not
    /// read from, which is the protocol branch.
    ///
    /// [`prepare_refresh`]: crate::engine::scan_floor::prepare_refresh
    pub(super) const fn from_daemon_fault(fault: DaemonFault) -> Self {
        match fault {
            DaemonFault::Unreachable => Self::DaemonUnreachable,
            DaemonFault::Identity(_) | DaemonFault::Protocol | DaemonFault::FeeResponse => {
                Self::DaemonProtocol
            }
            DaemonFault::Internal => Self::Internal,
        }
    }
}

impl From<LocalRefreshError> for RefreshError {
    fn from(e: LocalRefreshError) -> Self {
        let daemon = |fault, detail: &str| {
            RefreshError::Io(IoError::Daemon {
                fault,
                detail: detail.to_owned(),
            })
        };
        match e {
            LocalRefreshError::Cancelled => RefreshError::Cancelled,
            LocalRefreshError::DaemonUnreachable => daemon(
                DaemonFault::Unreachable,
                "LocalRefresh: the daemon did not answer within the retry budget",
            ),
            LocalRefreshError::DaemonProtocol => daemon(
                DaemonFault::Protocol,
                "LocalRefresh: the daemon's reply broke the RPC contract",
            ),
            LocalRefreshError::Malformed => daemon(
                DaemonFault::Protocol,
                "LocalRefresh: daemon returned a structurally malformed block",
            ),
            LocalRefreshError::ReorgStorm => RefreshError::ReorgStorm,
            LocalRefreshError::PastFinality(stop) => RefreshError::ReorgDeeperThanFinality { stop },
            LocalRefreshError::Internal => RefreshError::InternalInvariantViolation {
                context: "LocalRefresh: scanner construction or daemon request encoding failed",
            },
        }
    }
}

/// Classify an upstream [`RpcError`] into the bounded
/// [`ProtocolErrorKind`] tag without propagating the underlying
/// `String` payload.
///
/// Per [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §4 Phase 0e
/// and §5.4.7 R6 memory-amplifier closure (binding): the
/// producer's observability stream MUST carry only the bounded
/// variant-tag classification of `RpcError`; the `String` payload
/// that `InternalError(String)` / `ConnectionError(String)` /
/// `InvalidNode(String)` carry is dropped at this boundary so an
/// adversarial daemon cannot drive memory amplification into the
/// wallet's diagnostic stream.
///
/// # Refresh-reachable mapping
///
/// Refresh issues `get_height` and `fetch_scannable_block`, the
/// latter composing the `Rpc` transport primitives `get_block` /
/// `get_transactions` / `get_o_indexes` (the §8 step-4 `shekyl-wire`
/// migration replaced the single-call `get_scannable_block_by_number`
/// the Round 4 audit was written against). The refresh-reachable
/// upstream variants and their tags:
///
/// - [`RpcError::ConnectionError`] → [`ProtocolErrorKind::ConnectionError`]
/// - [`RpcError::InternalError`] → [`ProtocolErrorKind::InternalError`]
/// - [`RpcError::InvalidNode`] → [`ProtocolErrorKind::InvalidNode`]
/// - [`RpcError::InvalidTransaction`] → [`ProtocolErrorKind::InvalidTransaction`]
/// - [`RpcError::PrunedTransaction`] → [`ProtocolErrorKind::PrunedTransaction`]
/// - [`RpcError::IdentityMismatch`] → [`ProtocolErrorKind::IdentityMismatch`]
///   (settled by the orchestrator before the producer runs; tagged on its
///   own should one ever arrive)
/// - [`RpcError::TransactionsNotFound`] → [`ProtocolErrorKind::InvalidNode`]
///   (reachable via the `get_transactions` leg of the block fetch: a
///   daemon that names transaction hashes in a block and then reports
///   them missing is internally inconsistent, which from the refresh
///   path is the "unexpected envelope" `InvalidNode` signal).
///
/// # Defensive mapping for non-refresh-reachable variants
///
/// `RpcError::InvalidFee` / `RpcError::InvalidPriority` are not
/// reachable from refresh — they belong to the future
/// `PendingTxEngine` send-tx path. If they nonetheless surface from
/// this site (e.g., upstream RPC client behavior change), the
/// defensive classification is [`ProtocolErrorKind::InvalidNode`] —
/// "the daemon returned an envelope the producer did not expect from
/// this RPC method." [`ProtocolErrorKind`] is `#[non_exhaustive]`;
/// PR 5's `PendingTxEngine` extraction may grow the variant set
/// additively.
///
/// [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`]: ../../../../docs/completed/STAGE_1_PR_4_REFRESH_ENGINE.md
//
// `clippy::match_same_arms` would have us merge the
// `InvalidNode(_)` arm with the
// `TransactionsNotFound | InvalidFee | InvalidPriority` arm
// because both map to `ProtocolErrorKind::InvalidNode`. Keeping
// them separate preserves the rustdoc's reachability boundary:
// the grouped arm carries `TransactionsNotFound` (refresh-reachable
// via the block fetch's `get_transactions` leg — an inconsistent
// daemon, mapped to `InvalidNode`) alongside the genuinely
// non-refresh-reachable `InvalidFee` / `InvalidPriority` defensive
// fallbacks (send-tx path). Merging would lose that boundary, which
// future maintainers need when PR 5's `PendingTxEngine` extraction
// reaches this site.
#[allow(clippy::match_same_arms)]
pub(super) const fn classify_rpc_error(err: &RpcError) -> ProtocolErrorKind {
    match err {
        RpcError::ConnectionError(_) => ProtocolErrorKind::ConnectionError,
        RpcError::InternalError(_) => ProtocolErrorKind::InternalError,
        RpcError::InvalidNode(_) => ProtocolErrorKind::InvalidNode,
        RpcError::InvalidTransaction(_) => ProtocolErrorKind::InvalidTransaction,
        RpcError::PrunedTransaction => ProtocolErrorKind::PrunedTransaction,
        // All map to `InvalidNode`: `TransactionsNotFound` is
        // refresh-reachable (block fetch's `get_transactions` leg;
        // inconsistent daemon), while `InvalidFee` / `InvalidPriority`
        // are non-refresh-reachable defensive fallbacks. See rustdoc.
        RpcError::TransactionsNotFound(_) | RpcError::InvalidFee | RpcError::InvalidPriority => {
            ProtocolErrorKind::InvalidNode
        }
        RpcError::IdentityMismatch(_) => ProtocolErrorKind::IdentityMismatch,
    }
}
