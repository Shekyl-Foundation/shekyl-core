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

use crate::engine::error::{IoError, TerminalErrorKind};
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
/// Phase 2a may extend this struct with further per-snapshot
/// metadata (e.g. estimation timestamp, observed mempool weight).
/// `#[non_exhaustive]` permits the additive growth without a Stage 1
/// `DaemonEngine` amendment per §8.2: callers construct via
/// field-by-name and match exhaustively only on the listed fields.
///
/// # Per-tier `FeeRate`
///
/// `FeeRate` is the `shekyl_rpc::FeeRate` (per-weight cost + rounding
/// mask) returned by [`Rpc::get_fee_rate`]. The three tier fields on
/// this struct correspond one-to-one with the three non-`Custom`
/// `FeePriority` variants; resolving a `FeePriority` to a `FeeRate`
/// is a structural projection rather than a fresh daemon call.
///
/// # Atomic single-RPC snapshot (§3.3)
///
/// Per `PHASE_2A_SEND_PATH.md` §3.3, the whole snapshot derives from
/// **one** `get_fee_estimate` JSON-RPC call (not three per-tier
/// `get_fee_rate` calls): the response's fee array maps to the three
/// tiers (`economy`/`standard`/`priority` → indices `0`/`1`/`3` per
/// `V3_WALLET_DECISION_LOG.md`) and its single `quantization_mask`
/// is stored once on [`Self::quantization_mask`]. This guarantees the
/// tier band and the
/// [`Custom`](super::super::FeePriority::Custom) feerate's rounding
/// mask all derive from the same daemon view, with no tier-vs-tier
/// skew from interleaved calls.
///
/// [`docs/V3_WALLET_DECISION_LOG.md`]: ../../../../../docs/V3_WALLET_DECISION_LOG.md
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeEstimates {
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

    /// The daemon's fee-rounding `quantization_mask` for this
    /// snapshot, carried **once** so a
    /// [`Custom`](super::super::FeePriority::Custom) feerate can be
    /// constructed against the same daemon view as the tier band
    /// (`FeeRate::new(rate, quantization_mask)`, §3.3). Identical to
    /// the `mask` already embedded in each tier `FeeRate`; surfaced
    /// here so the `Custom` path does not need a fresh daemon call.
    pub quantization_mask: u64,
}

/// Outcome of a daemon transaction submission via
/// [`DaemonEngine::submit_transaction`].
///
/// Carries the daemon's view of the submission. The variant set is the
/// **honest subset** the daemon's `send_raw_transaction` reply can
/// actually distinguish (§3.6, as amended), plus two variants the
/// orchestrator / a later phase produce rather than the daemon-verdict
/// mapping:
///
/// - [`Self::Submitted`] — daemon `status == "OK"`; accepted to the
///   pool.
/// - [`Self::DaemonRejectedTerminal`] — daemon `status != "OK"`; a
///   final, non-recoverable rejection. The daemon flags ~10 rejection
///   classes; the wallet maps only `double_spend` and `fee_too_low` to
///   distinct terminal kinds **by choice** (2a-1 needs no finer remedy)
///   and collapses the rest to [`TerminalErrorKind::Malformed`]. The
///   cases that are *genuinely* indistinguishable client-side are the
///   **unflagged** generics — an **already-known** duplicate and a
///   **stale FCMP++ root** — which set no dedicated flag and yield
///   `status == "Failed", reason == ""`. Verified against
///   `core_rpc_server.cpp::on_send_raw_transaction`.
/// - [`Self::AlreadyKnown`] — **not** produced by the daemon-verdict
///   mapping (the daemon gives no distinguishing signal). It is the
///   orchestrator's wallet-side product: on a §5.2 retry where the
///   wallet already recorded a [`TxHash`] for these exact bytes, a
///   generic daemon rejection is interpreted as already-known. Best
///   effort, by construction.
/// - [`Self::ProofStale`] — reactive stale-root signal whose
///   **detection is deferred to Phase 6** (the daemon currently emits
///   no stale-root-specific flag, so a stale root is presently
///   indistinguishable from a generic terminal rejection). The variant
///   exists now so the §3.6 bounded rebuild loop has a stable target;
///   the proactive `reference.rs` validity horizon is the interim
///   guard. Reopening criterion: a daemon-side stale-root signal
///   (`SHEKYLD_PREREQUISITE`, tracked in `docs/FOLLOWUPS.md`).
///
/// # Transport failures are not an outcome
///
/// A failed daemon round-trip (timeout, connection drop) is **not** a
/// `TxSubmitOutcome`: it is [`Self::Error`](DaemonEngine::Error), which
/// the orchestrator maps to
/// [`SubmitError::DaemonAmbiguous`](crate::engine::error::SubmitError::DaemonAmbiguous)
/// (R9 discipline — reservation retained). Ambiguity is the *absence*
/// of a daemon verdict; representing it here too would duplicate the
/// concept across two enums.
///
/// # `#[non_exhaustive]`
///
/// `#[non_exhaustive]` lets the enum extend without a Stage 1
/// amendment per §8.2 (e.g. a relayed-but-unconfirmed advisory once
/// daemon feedback supports it).
///
/// # Retry contract (§5.2)
///
/// Per the §5.2 retry contract, [`DaemonEngine::submit_transaction`]
/// is conditionally idempotent: same `tx_bytes` produce the same
/// [`TxHash`] (the hash is a deterministic function of the bytes) and
/// the daemon dedupes by hash. A caller may retry on transient
/// transport failures; the wallet-side hash record is what lets the
/// orchestrator recognize the retry as [`Self::AlreadyKnown`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Phase 2a-stub: production callers land with §5.2 retry contract.
pub(crate) enum TxSubmitOutcome {
    /// The daemon accepted this transaction as a fresh submission
    /// (`status == "OK"`).
    Submitted {
        /// Hash of the submitted transaction. Deterministic in the
        /// `tx_bytes` argument and computed **locally** from those
        /// bytes (§3.6 step 2), never read from a daemon field.
        hash: TxHash,
    },

    /// The transaction is already known to the daemon. Produced by the
    /// orchestrator's §5.2 retry-contract logic (wallet-side dedup by
    /// local hash), **not** by the daemon-verdict mapping — the daemon
    /// collapses already-known into the generic terminal bucket.
    AlreadyKnown {
        /// Hash of the submitted transaction. Equal to the hash
        /// recorded on the original [`Self::Submitted`].
        hash: TxHash,
    },

    /// The transaction's FCMP++ membership proof references a curve-tree
    /// root the daemon no longer accepts. Recoverable by rebuilding
    /// against a fresh root, re-signing, and re-submitting (§3.6); the
    /// spend selection may be preserved. **Detection deferred to Phase
    /// 6** (see the type-level reopening criterion); no code path
    /// constructs this variant yet.
    ProofStale {
        /// Hash of the (stale) submitted transaction, locally computed.
        hash: TxHash,
    },

    /// The daemon rejected the transaction with a final,
    /// non-recoverable outcome. The orchestrator drops the reservation
    /// from `in_flight` and releases its `output_locks`; recourse is to
    /// rebuild against current chain state.
    DaemonRejectedTerminal {
        /// The terminal sub-discriminant. The daemon distinguishes only
        /// [`TerminalErrorKind::DoubleSpend`] and
        /// [`TerminalErrorKind::FeeTooLow`]; all other terminal
        /// rejections map to [`TerminalErrorKind::Malformed`].
        kind: TerminalErrorKind,
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
    #[allow(dead_code)] // Phase 2a-stub: production callers land with §3.1 fee policy.
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
    #[allow(dead_code)] // Phase 2a-stub: production callers land with §5.2 retry contract.
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<TxSubmitOutcome, Self::Error>> + Send;
}
