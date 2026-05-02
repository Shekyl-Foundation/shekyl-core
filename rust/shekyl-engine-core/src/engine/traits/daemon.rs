// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `DaemonEngine` trait surface and its supporting value types.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.5, `DaemonEngine` is
//! the wallet-side trait the [`Engine`](super::super::Engine)
//! orchestrator binds against for daemon-bound calls. It is a
//! supertrait extension of [`shekyl_rpc::Rpc`] (the
//! upstream-vendored RPC trait that already covers
//! `get_height` / `get_scannable_block_by_*` / etc.), adding only
//! the wallet-specific methods that have no place on `Rpc`:
//! [`DaemonEngine::get_fee_estimates`] and
//! [`DaemonEngine::submit_transaction`].
//!
//! # Two-trait shape rationale (§2.5)
//!
//! `Rpc` lives in `shekyl-oxide` (the vendored upstream fork tracking
//! `monero-oxide`); adding wallet-specific methods to it would either
//! modify upstream-vendored code (increasing divergence pressure on
//! the canary tracked in [`docs/CI_BASELINE.md`]) or be defined as
//! an extension trait — which is exactly the two-trait shape under a
//! different name. Consumers that need the inherited `Rpc` methods
//! reach them through the supertrait bound rather than duplicating
//! the surface on `DaemonEngine`.
//!
//! # Stage-4 swap-in (§7)
//!
//! At Stage 4 the `Rpc + DaemonEngine` bound is satisfied by an
//! `ActorRef<DaemonActor>` rather than by the in-process
//! [`DaemonClient`](super::super::DaemonClient). Trait method
//! signatures do not change; only the implementor type does. Callers
//! that bind against `D: DaemonEngine` get the swap-in for free.
//!
//! [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`]: ../../../../../docs/V3_ENGINE_TRAIT_BOUNDARIES.md
//! [`docs/CI_BASELINE.md`]: ../../../../../docs/CI_BASELINE.md

use shekyl_rpc::{FeeRate, Rpc};

use crate::engine::error::IoError;
use crate::engine::pending::TxHash;

/// Multi-priority fee snapshot returned by
/// [`DaemonEngine::get_fee_estimates`].
///
/// Carries the daemon's fee-rate estimate at each of the three
/// non-`Custom` [`FeePriority`](super::super::FeePriority) tiers
/// captured atomically at the call instant. The wallet's
/// [`FeePriority::Custom`](super::super::FeePriority::Custom) variant
/// bypasses the daemon estimate entirely (per
/// [`docs/V3_WALLET_DECISION_LOG.md`]'s cross-cutting lock 8) and
/// therefore has no field on this struct.
///
/// # `#[non_exhaustive]`
///
/// Phase 2a is expected to extend this struct with per-snapshot
/// metadata (e.g. estimation timestamp, daemon-reported
/// `quantization_mask`, observed mempool weight). `#[non_exhaustive]`
/// permits the additive growth without a Stage 1 `DaemonEngine`
/// amendment per §8.2: callers construct via field-by-name and
/// match exhaustively only on the listed fields.
///
/// # Per-tier `FeeRate`
///
/// `FeeRate` is the `shekyl_rpc::FeeRate` (per-weight cost + rounding
/// mask) returned by [`Rpc::get_fee_rate`]. The three fields on this
/// struct correspond one-to-one with the three non-`Custom`
/// `FeePriority` variants; resolving a `FeePriority` to a `FeeRate`
/// is a structural projection rather than a fresh daemon call.
///
/// [`docs/V3_WALLET_DECISION_LOG.md`]: ../../../../../docs/V3_WALLET_DECISION_LOG.md
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FeeEstimates {
    /// Fee rate corresponding to
    /// [`FeePriority::Economy`](super::super::FeePriority::Economy):
    /// the slowest, cheapest tier targeting confirmation within a
    /// few blocks.
    pub economy: FeeRate,

    /// Fee rate corresponding to
    /// [`FeePriority::Standard`](super::super::FeePriority::Standard):
    /// the default tier balancing cost vs. confirmation time.
    pub standard: FeeRate,

    /// Fee rate corresponding to
    /// [`FeePriority::Priority`](super::super::FeePriority::Priority):
    /// the fastest tier short of fee-spiking, targeting next-block
    /// inclusion under normal mempool conditions.
    pub priority: FeeRate,
}

/// Outcome of a daemon transaction submission via
/// [`DaemonEngine::submit_transaction`].
///
/// Carries the daemon's view of the submission: whether the daemon
/// accepted the transaction freshly ([`Self::Submitted`]) or
/// recognized it as a duplicate of one it already knows
/// ([`Self::AlreadyKnown`]). Both variants carry the resulting
/// [`TxHash`] so callers can correlate with the wallet's local
/// reservation tracking and with §5.2's retry-contract verification:
/// resubmitting bytes for which the wallet already received a hash
/// must produce that same hash regardless of which variant the
/// daemon returned.
///
/// # `#[non_exhaustive]`
///
/// Phase 2a may add variants for richer daemon outcomes
/// (mempool-rejected-with-reason, relayed-but-unconfirmed, etc.);
/// `#[non_exhaustive]` lets the enum extend without a Stage 1
/// amendment per §8.2.
///
/// # Retry contract (§5.2)
///
/// Per the §5.2 retry contract, [`DaemonEngine::submit_transaction`]
/// is conditionally idempotent: same `tx_bytes` produce the same
/// [`TxHash`] (because the hash is a deterministic function of the
/// bytes) and the daemon dedupes by hash. A caller may retry on
/// transient transport failures and observe `AlreadyKnown` on the
/// second attempt; that is success, not duplicate work.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxSubmitOutcome {
    /// The daemon accepted this transaction as a fresh submission.
    /// Subsequent submission of the same bytes returns
    /// [`Self::AlreadyKnown`] with the same hash.
    Submitted {
        /// Hash of the submitted transaction. Deterministic in the
        /// `tx_bytes` argument: the daemon and the caller compute
        /// the same hash from the same bytes.
        hash: TxHash,
    },

    /// The daemon recognized this transaction as already-known. The
    /// caller may treat this as a successful idempotent retry per
    /// §5.2.
    AlreadyKnown {
        /// Hash of the submitted transaction. Equal to the hash the
        /// daemon returned on the original [`Self::Submitted`].
        hash: TxHash,
    },
}

/// Engine-side view of the daemon RPC surface (§2.5).
///
/// Implementors carry the RPC client (today: [`DaemonClient`] wrapping
/// `shekyl_simple_request_rpc::SimpleRequestRpc`; at Stage 4: an
/// `ActorRef<DaemonActor>` per §1.4). Callers
/// ([`Engine<S>`](super::super::Engine) orchestration,
/// `RefreshEngine::produce_scan_result`, `PendingTxEngine::submit`)
/// bind against the trait, not the concrete type, so the Stage 4
/// swap-in does not require call-site changes.
///
/// # Supertrait bounds
///
/// - `Rpc` — inherits the upstream block / height / output / mempool
///   methods. Consumers reach them through this bound rather than
///   re-importing.
/// - `Clone + Send + Sync + 'static` — the daemon handle is shared by
///   clone with the producer task in `run_refresh_task`'s
///   `tokio::spawn`'d future. `DaemonClient` /
///   `SimpleRequestRpc` already satisfy these bounds, and
///   `ActorRef<DaemonActor>` will at Stage 4.
///
/// [`DaemonClient`]: super::super::DaemonClient
pub(crate) trait DaemonEngine: Rpc + Clone + Send + Sync + 'static {
    /// Implementor-specific error. Convertible into
    /// [`IoError`] so [`Engine<S>`](super::super::Engine)
    /// orchestration code can propagate uniform errors regardless of
    /// implementor.
    type Error: Into<IoError>;

    /// Atomically snapshot the daemon's fee-rate estimate at each
    /// non-`Custom` priority tier.
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: a network read with no wallet-side side
    /// effect; dropping the returned future before completion has
    /// the same observable effect as never calling. Callers may
    /// race the call against a cancellation token.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: the daemon's fee-rate estimate is a
    /// snapshot read at call time; repeated calls return whatever
    /// the daemon's current estimate is. The §4 idempotency column
    /// describes the *property*; §5.2 describes the *retry
    /// contract* callers derive from it (read-only methods are
    /// always retry-safe).
    ///
    /// # Panics
    ///
    /// Never panics. Implementors that route through actor message
    /// handlers (Stage 4) surface handler panics as
    /// [`Self::Error`] (mappable to
    /// [`IoError::Daemon`]) per §5.1's `RuntimeFailure` discipline,
    /// not as a panic of this method.
    fn get_fee_estimates(
        &self,
    ) -> impl std::future::Future<Output = Result<FeeEstimates, Self::Error>> + Send;

    /// Submit serialized transaction bytes to the daemon for
    /// broadcast.
    ///
    /// # Cancellation
    ///
    /// Class **b** per §4: a network side-effecting call; dropping
    /// the returned future before completion does not cancel the
    /// daemon-side effect (the daemon may have already received
    /// and acted on the transaction). Callers that need to know
    /// whether a submission landed re-submit and observe
    /// [`TxSubmitOutcome::AlreadyKnown`].
    ///
    /// # Idempotency
    ///
    /// **Conditionally** per §4: the daemon dedupes by transaction
    /// hash, so resubmitting the same `tx_bytes` returns the same
    /// hash, with [`TxSubmitOutcome::AlreadyKnown`] indicating the
    /// daemon already had it. See §5.2 for the retry contract:
    /// callers MAY retry on transient transport failures.
    ///
    /// # Panics
    ///
    /// Never panics. Per `get_fee_estimates`'s panic note.
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<TxSubmitOutcome, Self::Error>> + Send;
}
