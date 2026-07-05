// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `DaemonEngine` trait surface and its supporting value types.
//!
//! Per [`docs/V3_ENGINE_TRAIT_BOUNDARIES.md`] §2.5, `DaemonEngine` is
//! the wallet-side trait the [`Engine`](super::super::Engine)
//! orchestrator binds against for daemon-bound calls. It is a
//! supertrait extension of [`shekyl_rpc_client::Rpc`] (the
//! upstream-vendored RPC trait that covers the transport primitives —
//! `get_height` / `get_block` / `get_transactions` / `get_o_indexes` /
//! etc.), adding the wallet-specific methods that have no place on
//! `Rpc`: [`DaemonEngine::fetch_scannable_block`] — which composes
//! those transport primitives into a `shekyl-wire`-parsed
//! [`ScannableBlock`], superseding the legacy single-call
//! `Rpc::get_scannable_block_by_*` removed in the §8 step-4 migration
//! — plus [`DaemonEngine::get_fee_estimates`] and
//! [`DaemonEngine::submit_transaction`].
//!
//! # Two-trait shape rationale (§2.5)
//!
//! `Rpc` is the daemon-transport surface in `shekyl-rpc-client` (a first-party
//! crate relocated from the vendored `shekyl-oxide` `rpc` in the un-vendor, so the
//! original "don't modify upstream-vendored code / divergence-canary" pressure no
//! longer applies). The two-trait shape is retained on its own merits: `Rpc` stays
//! the generic, reusable daemon-transport surface and `DaemonEngine` carries the
//! wallet-specific methods as a supertrait extension. Consumers that need the
//! inherited `Rpc` methods reach them through the supertrait bound rather than
//! duplicating the surface on `DaemonEngine`.
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

use shekyl_rpc_client::{FeeRate, Rpc, RpcError};
use shekyl_scanner::ScannableBlock;

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
/// Phase 2a may extend this struct with further per-snapshot
/// metadata (e.g. estimation timestamp, observed mempool weight).
/// `#[non_exhaustive]` permits the additive growth without a Stage 1
/// `DaemonEngine` amendment per §8.2: callers construct via
/// field-by-name and match exhaustively only on the listed fields.
///
/// # Per-tier `FeeRate`
///
/// `FeeRate` is the `shekyl_rpc_client::FeeRate` (per-weight cost + rounding
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
/// The wallet-side projection of the daemon's atomic
/// [`SubmitVerdict`](shekyl_rpc_client::SubmitVerdict)
/// (`docs/design/DAEMON_SUBMIT_VERDICT.md` §2.1), plus the locally
/// computed [`TxHash`] on the identity-bearing variants. The verdict is
/// computed by the daemon's Rust admission engine with every mutable
/// premise re-checked under one lock scope, so the variants are mutually
/// consistent facts — never the racy multi-flag snapshot the deleted
/// `send_raw_transaction` reply carried. Per-cause wallet dispositions
/// are specified in §2.5 and applied by the orchestrator
/// (`LocalPendingTx`), not here.
///
/// The legacy wallet-side `AlreadyKnown` heuristic (interpreting a
/// generic rejection as a dedup hit via a local hash record) is retired:
/// [`Self::AlreadyInPool`] / [`Self::AlreadyInChain`] are daemon-attested
/// identity facts. The formerly-deferred `ProofStale` detection is now
/// constructible as [`RejectCause::StaleRoot`], closing the
/// `fcmp_root_stale` FOLLOWUPS reopening criterion (its named reopen was
/// exactly "a daemon-side stale-root signal").
///
/// # Transport failures are not an outcome
///
/// A failed daemon round-trip (timeout, connection drop, unknown
/// top-level verdict tag per the §2.3 skew rules) is **not** a
/// `TxSubmitOutcome`: it is [`Self::Error`](DaemonEngine::Error), which
/// the orchestrator maps to
/// [`SubmitError::DaemonAmbiguous`](crate::engine::error::SubmitError::DaemonAmbiguous)
/// (R9 discipline — reservation retained). Ambiguity is the *absence*
/// of a daemon verdict; representing it here too would duplicate the
/// concept across two enums.
///
/// # `#[non_exhaustive]`
///
/// New top-level verdict tags are a breaking wire change (F38) — but the
/// *outcome* enum stays `#[non_exhaustive]` so a coordinated
/// wire-version bump lands wallet-side additively.
///
/// # Retry contract (§5.2 / §2.5)
///
/// [`DaemonEngine::submit_transaction`] is idempotent as a status query:
/// resubmitting held bytes yields a definite verdict for every stable
/// state (mined → [`Self::AlreadyInChain`]; pool-resident →
/// [`Self::AlreadyInPool`], with **no** relay pulse per F31; competing
/// spend → [`RejectCause::DoubleSpendConflict`]; dead → re-offered
/// through full admission). Callers MAY retry on transient transport
/// failures.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxSubmitOutcome {
    /// Admitted to the daemon's pool at commit-check time; relay is
    /// daemon-owned from here. The pending-tx enters awaiting
    /// confirmation — liveness is keyed on chain confirmation observed
    /// via refresh, never on a daemon relay claim (§5.3).
    Submitted {
        /// Hash of the submitted transaction. Deterministic in the
        /// `tx_bytes` argument and computed **locally** from those
        /// bytes, never read from a daemon field.
        hash: TxHash,
    },

    /// Identity fact: these exact bytes (same txid) are already in the
    /// daemon's pool. Same wallet disposition as [`Self::Submitted`]
    /// (§2.5) — and it resolves prior transport ambiguity for this txid.
    AlreadyInPool {
        /// Locally computed hash, equal to the pool-resident txid.
        hash: TxHash,
    },

    /// Identity fact: this txid is in the main chain. Confirmation
    /// observed by verdict; refresh remains the settlement authority
    /// (reorgs happen — the verdict authorizes lock-lifecycle
    /// transitions only).
    AlreadyInChain {
        /// Locally computed hash, equal to the chain-resident txid.
        hash: TxHash,
        /// Daemon-claimed confirming-block height (F40, §2.2 carve-out).
        /// Consumed only as a **release-path discriminant** (§2.5) under
        /// the R1/R2 bounds — never as settlement truth.
        height: u64,
    },

    /// Not in pool, not in chain, and not admitted — `cause` says why.
    /// Under the single-egress theorem (§7.1) this carries the proof
    /// that the bytes were not relayed by this daemon, so lock release
    /// is safe where the §2.5 disposition calls for it.
    Rejected {
        /// Why the daemon refused the transaction. Dispositions per
        /// §2.5 are applied by the orchestrator.
        cause: shekyl_rpc_client::RejectCause,
    },
}

/// Engine-side view of the daemon RPC surface (§2.5).
///
/// Implementors carry the RPC client (today: [`DaemonClient`] wrapping
/// `shekyl_rpc_transport::SimpleRequestRpc`; at Stage 4: an
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

    /// Fetch the block at `number` in scannable form: the block, its pruned
    /// non-miner transactions, and the first global output index, all parsed
    /// through the canonical [`shekyl_wire`] parse.
    ///
    /// This is the engine-native replacement for the legacy
    /// `shekyl_rpc_client::Rpc::get_scannable_block_by_number`. The transport is the
    /// inherited [`Rpc`] surface (`get_block` / `get_transactions` /
    /// `get_o_indexes`), but parsing is `shekyl_wire`, which reads the coinbase
    /// `Null` committed base correctly (`GENESIS_TX_WIRE_FORMAT.md` §9.6/§9.9)
    /// where the legacy parse dropped it and rejected live coinbase blocks as
    /// `InvalidNode("invalid block")`.
    ///
    /// # Cancellation
    ///
    /// Class **a** per §4: read-only network calls with no wallet-side side
    /// effect; dropping the returned future is equivalent to never calling.
    ///
    /// # Idempotency
    ///
    /// **Yes** per §4: repeated calls return whatever the daemon currently
    /// serves at `number`. Read-only methods are always retry-safe (§5.2).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] for transport failures and malformed daemon
    /// responses; a block that fails the `shekyl_wire` parse surfaces as
    /// [`RpcError::InvalidNode`].
    ///
    /// # Default implementation
    ///
    /// The default delegates to the in-crate native fetch
    /// (`engine::block_fetch`). The Stage-4 `ActorRef<DaemonActor>` overrides
    /// it to route through the actor mailbox; the test `TestDaemon` overrides
    /// it to serve synthetic chains. Trait method signatures do not change
    /// across the swap-in (§7).
    fn fetch_scannable_block(
        &self,
        number: usize,
    ) -> impl std::future::Future<Output = Result<ScannableBlock, RpcError>> + Send {
        crate::engine::block_fetch::default_fetch_scannable_block(self, number)
    }

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
    /// [`TxSubmitOutcome::AlreadyInPool`] /
    /// [`TxSubmitOutcome::AlreadyInChain`].
    ///
    /// # Idempotency
    ///
    /// **Yes, as a status query** (`DAEMON_SUBMIT_VERDICT.md` §2.5):
    /// resubmitting the same `tx_bytes` returns the same locally
    /// computed hash and a definite verdict for every stable state —
    /// [`TxSubmitOutcome::AlreadyInPool`] for pool-resident bytes (no
    /// relay pulse, F31), [`TxSubmitOutcome::AlreadyInChain`] for mined
    /// bytes. Callers MAY retry on transient transport failures.
    ///
    /// # Panics
    ///
    /// Never panics. Per `get_fee_estimates`'s panic note.
    fn submit_transaction(
        &self,
        tx_bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<TxSubmitOutcome, Self::Error>> + Send;
}
