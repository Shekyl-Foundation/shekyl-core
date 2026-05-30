// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-domain error enums for the `Engine` orchestrator.
//!
//! Cross-cutting lock 2 in the rewrite plan locks the error shape:
//!
//! > Domain layer (`shekyl-engine-core`) ships per-domain error enums
//! > (`SendError`, `RefreshError`, `KeyError`, `IoError`, etc.) with
//! > `thiserror` + `#[from]` conversions for ergonomic `?` propagation.
//! > The RPC layer (`shekyl-engine-rpc`) defines a single
//! > `WalletRpcError` enum that every domain error converts into.
//!
//! Each enum is *closed* — no `Other(String)` catch-all — so a reviewer
//! can read the variants and know every distinguishable failure mode.
//! The RPC-layer translation is the single audited site for mapping
//! these to JSON-RPC error codes; the wallet-core API never returns a
//! stringly-typed error.
//!
//! # `#[from]` conversions
//!
//! This commit defines the variants but does not yet wire `#[from]`
//! impls for upstream errors (`shekyl_engine_file::WalletFileError`,
//! `shekyl_crypto_pq::CryptoError`, `shekyl_engine_state::WalletLedgerError`,
//! `shekyl_engine_prefs::PrefsError`, daemon-RPC errors, scanner
//! errors, tx-builder errors). Each `#[from]` lands in the same commit
//! that introduces the lifecycle / refresh / send method whose `?`
//! operator needs the conversion. This keeps each commit's dependency
//! graph minimal; an `#[from]` impl without a caller is dead code by
//! construction.
//!
//! # Variant names locked in by the plan
//!
//! - [`OpenError::NetworkMismatch`] — wallet file says network N, daemon
//!   client says network M.
//! - [`RefreshError::ConcurrentMutation`] — `apply_scan_result`'s
//!   `start_height` does not match the wallet's current `synced_height`
//!   (a second refresh raced ahead, or the caller mutated the wallet
//!   between snapshot and merge); caller retries.
//! - [`PendingTxError::TooOld`] — the tx was built outside the current
//!   reorg window.
//! - [`PendingTxError::ChainStateChanged`] — the wallet's recorded block
//!   hash at `built_at_height` no longer matches `built_at_tip_hash`.
//! - [`TxError::DaemonFeeUnreasonable`] — the daemon's `priority`
//!   estimate exceeds the configurable sanity ceiling, default loose at
//!   `10x` the daemon's `economy` estimate.

use shekyl_address::Network;

use super::pending::{ReservationId, SnapshotId};

// --- Open / lifecycle ------------------------------------------------------

/// Failures from
/// [`Engine::create`](super::Engine) /
/// [`Engine::open_full`](super::Engine) /
/// [`Engine::open_view_only`](super::Engine) /
/// [`Engine::open_hardware_offload`](super::Engine) /
/// [`Engine::change_password`](super::Engine) /
/// [`Engine::close`](super::Engine).
///
/// These are the lifecycle failures; once a wallet is open and refresh /
/// send paths are running, their failures live in [`RefreshError`] /
/// [`SendError`] / [`PendingTxError`].
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The on-disk wallet file failed to open or its envelope did not
    /// authenticate. Variant carries [`IoError`] for full upstream
    /// detail.
    #[error("wallet file IO/envelope failure: {0}")]
    Io(#[from] IoError),

    /// Re-derivation from the master seed failed. Carries a [`KeyError`]
    /// describing whether the failure was at HKDF, scalar reduction,
    /// ML-KEM seed expansion, or the consistency check between the
    /// rederived public bytes and the keys-file's stored public bytes.
    #[error("key (re)derivation failure: {0}")]
    Key(#[from] KeyError),

    /// User-supplied password did not authenticate the wallet envelope.
    ///
    /// Distinct from [`OpenError::Io`] because the wallet-file layer
    /// produces this as a typed branch, not a generic IO failure.
    #[error("incorrect password")]
    IncorrectPassword,

    /// The wallet file declared one network but the supplied daemon
    /// client (or the explicit `expected` parameter) declared another.
    /// See cross-cutting lock 5.
    #[error("network mismatch: wallet file is {wallet}, daemon/caller expected {expected}")]
    NetworkMismatch {
        /// Network the on-disk wallet file is bound to.
        wallet: Network,
        /// Network the caller asked the wallet to operate against.
        expected: Network,
    },

    /// The wallet file's capability byte is incompatible with the
    /// requested constructor. For example: opening a `ViewOnly` wallet
    /// via `open_full`.
    ///
    /// Returns the typed [`super::Capability`] read from the envelope so
    /// the caller can branch on it without re-opening.
    #[error(
        "capability mismatch: wallet is {found:?}, but the requested operation needs another mode"
    )]
    CapabilityMismatch {
        /// Capability declared by the wallet file's region 1.
        found: super::Capability,
    },

    /// `Engine::close` was called while at least one [`PendingTx`] was
    /// still in the reservation ledger. Caller must
    /// [`Engine::submit_pending_tx`] or
    /// [`Engine::discard_pending_tx`] each handle before close. See
    /// cross-cutting lock 4.
    ///
    /// [`PendingTx`]: super::Engine
    #[error("close refused: {count} PendingTx in flight; submit or discard first")]
    OutstandingPendingTx {
        /// How many in-flight reservations the close call observed.
        count: usize,
    },

    /// Final ledger/prefs flush during [`super::Engine::close`] failed.
    /// Distinct from [`Self::Io`] so save-path vocabulary is not
    /// squeezed into open-shaped variants (PR 6 R10 / §2.6).
    #[error("persistence failure during close: {0}")]
    Persistence(#[from] PersistenceError),

    /// **TRANSIENT — DELETE WHEN VIEW/HW BODIES LAND.**
    ///
    /// Tracked in `docs/FOLLOWUPS.md` § V3.0 → "View/HW lifecycle bodies".
    /// Blocks on `shekyl-crypto-pq` ViewOnly / HardwareOffload
    /// `AllKeysBlob` constructors. Once those land, this variant is
    /// removed and the stub methods get real bodies.
    ///
    /// Do not introduce new use sites. The variant exists only so the
    /// stub signatures can return a typed error rather than
    /// `unimplemented!()`.
    #[error("capability {capability:?} is not yet implemented in this build")]
    CapabilityNotYetImplemented {
        /// Capability the stub method represents.
        capability: super::Capability,
    },
}

// --- Persistence -----------------------------------------------------------

/// Failures from [`super::traits::persistence::PersistenceEngine`] steady-state
/// save / rotate paths (`save_state`, `save_prefs`, `rotate_password`).
///
/// Mapped at the lifecycle boundary: [`OpenError::Persistence`] on
/// [`super::Engine::close`](super::Engine::close);
/// [`ChangePasswordError`] on [`super::Engine::change_password`](super::Engine::change_password).
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// On-disk wallet envelope / atomic-write failure.
    #[error("wallet file error: {0}")]
    WalletFile(#[from] shekyl_engine_file::WalletFileError),

    /// Prefs sidecar load/save/HMAC failure.
    #[error("prefs error: {0}")]
    Prefs(#[from] shekyl_engine_prefs::PrefsError),
}

/// Failures from [`super::Engine::change_password`](super::Engine::change_password)
/// when rotation and prefs flush are separate steps (PR 6 §5.10 / segment 2b).
#[derive(Debug, thiserror::Error)]
pub enum ChangePasswordError {
    /// Password rotation (keys-file rewrap) failed before prefs were touched.
    #[error("password rotation failed: {0}")]
    RotateFailed(#[from] PersistenceError),

    /// Keys-file rotation succeeded but prefs flush failed — on-disk password
    /// and prefs may be inconsistent until the user retries or restores.
    #[error("password rotated but prefs flush failed: {0}")]
    RotatedButPrefsFlushFailed(PersistenceError),
}

// --- Refresh ---------------------------------------------------------------

/// Failures from [`Engine::refresh`](super::Engine) and the
/// `apply_scan_result` merge it drives. Carries the only audited code
/// path that ever mutates the scan-result slice of `WalletLedger`.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// `apply_scan_result.start_height` did not match the wallet's
    /// current `synced_height`. The caller (likely a polling RPC client
    /// that issued `refresh` while another `refresh` was in flight)
    /// should retry.
    ///
    /// This is the type-layer enforcement of the Phase 1 lock
    /// "additive-only, scoped, snapshot-consistency-checked merge."
    #[error(
        "concurrent mutation: wallet synced_height = {wallet}, scan result start_height = {result}; retry"
    )]
    ConcurrentMutation {
        /// `wallet.synced_height` observed at merge time.
        wallet: u64,
        /// `result.start_height` in the value passed to
        /// `apply_scan_result`.
        result: u64,
    },

    /// A second `refresh` was attempted while one was already in flight.
    /// Single-flight is normally enforced by the `&mut self` borrow on
    /// `refresh`; this variant covers cases where the binary layer
    /// surfaces the violation explicitly (e.g., a `tokio::Mutex`-guarded
    /// path that does not panic on re-entry).
    #[error("refresh already running")]
    AlreadyRunning,

    /// The scanner produced a [`crate::scan::ScanResult`] that violates
    /// the merge contract. Distinct from
    /// [`Self::ConcurrentMutation`] in that it is a **producer-side
    /// defect**, not a snapshot-disagreement: re-running the scan
    /// against the same daemon will produce the same contract
    /// violation, so the [`super::Engine::refresh`] retry loop does
    /// **not** retry on this variant — it surfaces immediately.
    ///
    /// `ConcurrentMutation` and `MalformedScanResult` together close
    /// the strict-contract gap surfaced by the PR #16 Copilot review:
    /// the former is the retry signal for races against `Engine<S>`,
    /// the latter is the audit signal for a producer that emitted a
    /// `ScanResult` whose internal shape disagrees with itself
    /// (out-of-range entries, duplicate heights, missing per-height
    /// block-hash record, residual entries left behind after the
    /// per-height apply loop).
    ///
    /// See `docs/V3_WALLET_DECISION_LOG.md`
    /// (`MalformedScanResult: producer-bug signal vs. ConcurrentMutation`,
    /// 2026-04-26) for the rationale.
    #[error("malformed ScanResult: {reason}")]
    MalformedScanResult {
        /// Static description of the contract violation, named at the
        /// call site so audit can read every distinguishable defect
        /// class from source.
        reason: &'static str,
    },

    /// The refresh task was cancelled before completing a block boundary.
    /// `RefreshHandle` checkpoints between blocks, so a cancellation is
    /// always reported back to the caller as this variant rather than
    /// surfacing as a partial-state failure.
    #[error("refresh cancelled")]
    Cancelled,

    /// Daemon-side refresh failure: an RPC call into `shekyld` failed,
    /// or the daemon returned data that the scanner / merge logic could
    /// not consume. Carries an [`IoError`] for upstream detail.
    #[error("daemon/scan IO failure: {0}")]
    Io(#[from] IoError),

    /// The orchestrator state machine reached a path the developer
    /// marked as "should never happen" — a structural invariant
    /// violation, distinct from both [`Self::ConcurrentMutation`]
    /// (retry-budget exhaustion under sustained merge contention) and
    /// [`Self::MalformedScanResult`] (a producer-bug signal carrying
    /// internal-shape violations of the scanner's output contract).
    ///
    /// # Why this is its own variant
    ///
    /// The two retry-loop call sites in
    /// `Engine::refresh` and `run_refresh_task` currently fall back on
    /// `MalformedScanResult` when the loop body exits without observing
    /// a `ConcurrentMutation`, with the comment *"falling through with
    /// `None` would mean the loop body itself is broken."* That case
    /// is structurally distinct from a scanner-produced contract
    /// violation: it is an orchestrator-side state-machine failure,
    /// not a producer-side defect. Routing both through
    /// `MalformedScanResult` would conflate "the scanner emitted a
    /// `ScanResult` whose internal shape disagrees with itself" with
    /// "the engine's retry loop reached an unreachable branch";
    /// downstream consumers (telemetry; future peer-reputation
    /// actors; future user-facing error surface) need different
    /// responses for the two cases. The variant separation is
    /// correctness-preserving, not stylistic.
    ///
    /// Routing through `ConcurrentMutation` is also wrong: that
    /// variant carries the snapshot-disagreement pair (`wallet`,
    /// `result`) the caller uses to decide whether to retry. An
    /// unreached-invariant case has no such pair to report.
    ///
    /// # Field
    ///
    /// `context` is a `&'static str` named at the call site so audit
    /// can read every distinguishable invariant-violation class from
    /// source. The unit-variant discipline on the producer trait
    /// surface (`RefreshEngine::Error: Into<RefreshError>` with
    /// trait-error vocabulary restricted to `Cancelled` / `Io` /
    /// `MalformedScanResult`) exists to close the memory-amplifier
    /// and log-exfiltration vectors on attacker-influenced data;
    /// neither vector applies here, because `context` is
    /// compile-time-fixed developer content at an
    /// orchestrator-internal call site — no daemon input or
    /// scanner-emitted bytes flow in.
    ///
    /// # Lifecycle
    ///
    /// The variant is added in PR 4 C3 ahead of any call-site
    /// migration. PR 4 C5 migrates the two retry-loop call sites
    /// (the `MalformedScanResult { reason: "..." }` fallbacks in
    /// `run_refresh_task` and `Engine::refresh`) over to
    /// `InternalInvariantViolation`, preserving the existing
    /// `&'static str` content as the `context` value at each site.
    /// Future orchestrator-internal "this branch should be
    /// unreachable" paths route here categorically rather than
    /// re-litigating where they belong.
    ///
    /// See `docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md` §4 Phase 0c
    /// ("Why `InternalInvariantViolation` is its own variant, not
    /// an extension of `ConcurrentMutation`") for the full rationale.
    #[error("internal invariant violation: {context}")]
    InternalInvariantViolation {
        /// Compile-time-fixed name of the violated invariant. Named
        /// at the call site so audit can read every distinguishable
        /// case from source rather than parsing a runtime-synthesized
        /// message.
        context: &'static str,
    },
}

// --- Ledger ----------------------------------------------------------------

/// Per-domain error for [`LedgerEngine`](super::traits::LedgerEngine),
/// the §2.2 trait that owns the wallet's confirmed-chain ledger.
///
/// # Empty-enum starter shape
///
/// Stage 1 PR 2 ships `LedgerError` with **no variants**. The §2.2
/// trait surface is structured so that:
///
/// - the three read methods (`synced_height`, `snapshot`, `balance`)
///   are infallible — they return `T`, not `Result<T, _>`, because
///   reading committed state under the `RwLock` read guard cannot
///   fail; and
/// - the lone mutating method (`apply_scan_result`) returns
///   [`RefreshError`] (specifically [`RefreshError::ConcurrentMutation`])
///   because the failure mode crosses the `LedgerEngine` /
///   `RefreshEngine` boundary — a snapshot-disagreement is a
///   refresh-loop concern, not a ledger-internal concern, per the
///   §1.5 actor-identity reasoning.
///
/// `LedgerError` therefore has no caller-visible variants today; it
/// exists as the named [`LedgerEngine::Error`] target so the
/// `type Error: Into<LedgerError>;` bound has somewhere to land. New
/// variants are additive (§7 / §8.2): a future read method that can
/// genuinely fail (e.g., a `transfer_details(id)` lookup that may
/// return "no such transfer") would land its variant here without
/// re-opening the trait surface.
///
/// [`LedgerEngine::Error`]: super::traits::LedgerEngine::Error
/// [`RefreshError`]: RefreshError
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum LedgerError {}

// --- Send / build / submit / discard --------------------------------------

/// Failures from [`Engine::build_pending_tx`](super::Engine) and the
/// rest of the send-side surface (excluding the `PendingTx` lifecycle
/// state machine, which has its own [`PendingTxError`]).
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// Selected output set could not cover `amount + fee`.
    #[error("insufficient funds: need {needed} atomic units, available {available}")]
    InsufficientFunds {
        /// Total amount-plus-fee the build attempted to cover.
        needed: u64,
        /// Spendable balance currently visible to the wallet (matured,
        /// non-reserved).
        available: u64,
    },

    /// The `TxRequest` named a destination that does not parse as a
    /// Shekyl address for the wallet's network, or that is on a
    /// different network than the wallet itself.
    #[error("invalid recipient: {reason}")]
    InvalidRecipient {
        /// Human-readable reason. (Intentionally a `&'static str` so
        /// every branch is named in source rather than synthesized at
        /// runtime.)
        reason: &'static str,
    },

    /// Tx-builder layer failed: range proofs, FCMP++ membership proofs,
    /// hybrid PQC signatures, or assembly. Carries [`TxError`] for
    /// upstream detail.
    #[error("transaction construction failure: {0}")]
    Tx(#[from] TxError),

    /// Daemon-side failure during build (typically: `get_fee_estimates`
    /// or output-spend-status RPC) or submit. Carries [`IoError`] for
    /// upstream detail.
    #[error("daemon IO failure: {0}")]
    Io(#[from] IoError),

    /// Spend-key material was not available to sign. This is the path
    /// taken when a `Engine<SoloSigner>` is asked to send but the
    /// capability is `ViewOnly`, or when an `HardwareOffload` wallet
    /// receives a build call without an out-of-band approval.
    #[error("wallet cannot sign: {reason}")]
    CannotSign {
        /// Human-readable reason as named at the call site.
        reason: &'static str,
    },
}

// --- PendingTx lifecycle ---------------------------------------------------

/// Failures from
/// [`Engine::submit_pending_tx`](super::Engine) /
/// [`Engine::discard_pending_tx`](super::Engine) and from the
/// reservation-bookkeeping logic of `build_pending_tx`. Cross-cutting
/// lock 4 binds the variants
/// [`Self::TooOld`] and [`Self::ChainStateChanged`].
///
/// `#[non_exhaustive]` per the Phase 0a binding form
/// (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4) so V3.x variant additions
/// land without a major-version break. The V3.0 audited surface is the
/// variant set below.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum PendingTxError {
    /// The `PendingTx`'s `built_at_height` is below
    /// `wallet.synced_height - max_reorg_depth` — the build is too old
    /// to safely submit. Caller must rebuild against current chain
    /// state.
    #[error(
        "pending tx too old: built_at_height = {built}, current_synced = {current}, max_reorg = {max_reorg}"
    )]
    TooOld {
        /// `PendingTx.built_at_height` of the offending handle.
        built: u64,
        /// `wallet.synced_height` observed at submit time.
        current: u64,
        /// Network's `max_reorg_depth` per `NetworkSafetyConstants`
        /// (after any per-wallet override).
        max_reorg: u64,
    },

    /// The wallet's recorded block hash at `built_at_height` no longer
    /// matches the `built_at_tip_hash` the `PendingTx` carries. A reorg
    /// orphaned the build's input set; rebuild required.
    #[error(
        "pending tx anchored to a chain state that no longer matches: built_at_height = {height}"
    )]
    ChainStateChanged {
        /// `PendingTx.built_at_height` of the offending handle.
        height: u64,
    },

    /// `submit_pending_tx` or `discard_pending_tx` was called with a
    /// handle that the wallet's reservation ledger does not recognize.
    /// `discard_pending_tx` is **idempotent and silent** on this case
    /// per cross-cutting lock 4; `submit_pending_tx` raises this error.
    ///
    /// Phase 1 handler-bodies emit this variant via the existing
    /// reservation-bookkeeping helpers. C5β rewrites the handler
    /// bodies under the (γ) three-collection lean shape; from C5β on,
    /// `discard` and `submit` discriminate "rid is unknown" via
    /// [`Self::ReservationNotFound`] (with the rid carried in the
    /// variant), and the unit `UnknownHandle` variant is retired
    /// from new emission sites. The variant is retained on the
    /// `#[non_exhaustive]` enum surface for the Phase 1 helpers'
    /// continued use; the C5β deletion target is named in
    /// `docs/FOLLOWUPS.md`.
    #[error("unknown PendingTx handle")]
    UnknownHandle,

    /// Submit-side: caller-initiated `discard_pending_tx` against a
    /// reservation that is currently `in_flight` (a daemon round-trip
    /// is outstanding). Per the F2 ownership-boundary adjudication
    /// (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F2) the consumer
    /// does not own discard authority on `in_flight` reservations —
    /// the daemon does. The R8 TTL safety-net is the eventual
    /// release path when the daemon never resolves.
    #[error("discard blocked: reservation {reservation_id:?} is in_flight pending daemon ack")]
    DiscardBlockedPendingDaemonAck {
        /// The reservation whose discard was refused.
        reservation_id: ReservationId,
    },

    /// Submit-side: second `submit_pending_tx` against a reservation
    /// whose first submit is still in-flight. P2 disposition per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.6.
    #[error("submit already pending for reservation {reservation_id:?}")]
    SubmitAlreadyPending {
        /// The reservation whose duplicate submit was refused.
        reservation_id: ReservationId,
    },

    /// Submit / discard / `signal_mempool_evicted`: the rid is in
    /// neither `consumer_held` nor `in_flight`. P3 disposition per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.6 — discriminates
    /// "never existed or already resolved" from the unit
    /// [`Self::UnknownHandle`] by carrying the rid for diagnostics.
    /// `discard_pending_tx`'s idempotent-and-silent contract is
    /// preserved at the trait surface: the engine maps the
    /// `ReservationNotFound` outcome to `Ok(())` on the discard
    /// path, surfacing it as an error only on `submit` and
    /// `signal_mempool_evicted`.
    #[error("reservation {reservation_id:?} not found")]
    ReservationNotFound {
        /// The rid the caller passed to the operation.
        reservation_id: ReservationId,
    },

    /// The submit RPC failed at the daemon. Carries [`IoError`] for
    /// detail; the reservation is **kept** until the caller chooses to
    /// retry submit or discard explicitly.
    #[error("daemon submit failure: {0}")]
    Io(#[from] IoError),
}

// --- Key (de)derivation ----------------------------------------------------

/// Failures while (re)deriving wallet key material from a master seed,
/// or while loading / sealing the keys-file payload. Wraps
/// [`shekyl_crypto_pq::CryptoError`] (lands as `#[from]` alongside the
/// `open_full` / `change_password` lifecycle commit).
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Re-derivation produced material whose public bytes do not match
    /// the keys-file's stored `account_public_address`. Indicates either
    /// disk corruption, a wallet-file format bug, or a mismatched
    /// derivation salt — never a normal-operation outcome.
    #[error("rederived public material does not match keys-file declaration")]
    PublicBytesMismatch,

    /// The keys file declared a `(network, seed_format)` pair that the
    /// derivation layer rejects as not permitted (e.g., mainnet with a
    /// raw 32-byte seed). The keys-file integrity check should have
    /// rejected this earlier; this variant is the defensive path.
    #[error("keys file declares unsupported (network, seed_format) pair")]
    UnsupportedDerivationPair,

    /// HKDF expand, scalar reduction, or ML-KEM seed expansion produced
    /// an invalid intermediate value. Almost certainly indicates a bug
    /// in `shekyl-crypto-pq`; the variant exists so a future audit can
    /// distinguish "unreachable in practice" failure paths from disk-
    /// corruption ones.
    #[error("crypto primitive failure during key derivation: {detail}")]
    Primitive {
        /// Human-readable description of which primitive failed
        /// (named at the call site, not synthesized).
        detail: &'static str,
    },
}

// --- KeyEngine runtime ops -------------------------------------------------

/// Failures during runtime
/// [`KeyEngine`](super::traits::key::KeyEngine) operations (signing,
/// hybrid decapsulation, ECDH, subaddress derivation). Distinct from
/// [`KeyError`], which scopes wallet-open / derivation failures.
///
/// Cross-trait coordination failures (e.g., concurrent key rotation
/// invalidating an in-progress signing attempt) do **not** appear
/// here per the §3.2 negative-space framing in
/// `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` — they accumulate on a
/// future cross-trait error type when concrete triggers materialize.
///
/// # Variant accretion
///
/// Per §7.2 of `STAGE_1_PR_3_KEY_ENGINE.md`, this mirrors PR 2's
/// `LedgerError` introduction: variants land at implementation
/// time, not speculatively in the spec round. The variants below
/// were surfaced by M3a Commit 4b's `LocalKeys` impl; further
/// variants accrete as later trait surfaces (M3b–M3e, PR 5+) reveal
/// additional failure modes.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyEngineError {
    /// [`KeyEngine::sign_transaction`](super::traits::key::KeyEngine::sign_transaction)
    /// cannot be bridged in M3a: the public on-chain per-input data
    /// (`output_key`, `commitment`, `amount`, `h_pqc`) and the
    /// FCMP++ tree-branch context required by
    /// [`shekyl_tx_builder::sign_transaction`] are carried on
    /// `TxToSign` fields (`outputs: Vec<TxOutputContext>`,
    /// `fcmp_plus_plus_context: FcmpPlusPlusContext`) that are
    /// forward-declared as empty stubs in M3a Commit 3 and pinned
    /// in PR 5 (`PendingTxEngine`) per
    /// `STAGE_1_PR_3_KEY_ENGINE.md`'s "TxToSign's exact field shape
    /// … is finalized in PR 5" framing.
    /// [`LocalKeys::sign_transaction`](super::local_keys::LocalKeys::sign_transaction)
    /// returns this variant until PR 5's shape lands.
    #[error(
        "sign_transaction trait surface is PR-5-pinned; LocalKeys cannot bridge in M3a (TxToSign's public-data and FCMP++ branch carriers are forward-declared)"
    )]
    SignTransactionTraitSurfaceIncomplete,

    /// [`KeyEngine::derive_subaddress`](super::traits::key::KeyEngine::derive_subaddress)
    /// with [`SubaddressPurpose::Recipient`](super::traits::key::SubaddressPurpose::Recipient)
    /// requires per-subaddress hybrid KEM keypair derivation
    /// (X25519 + ML-KEM-768 keyed by `(view_secret, subaddress_idx)`),
    /// which is **not yet implemented** in `shekyl-crypto-pq`. The
    /// account-level KEM keypair derivation
    /// (`shekyl_crypto_pq::account::ml_kem_keypair_from_d_z`) does
    /// not parameterize over a subaddress index. Per
    /// `STAGE_1_PR_3_KEY_ENGINE.md` §3.1.3 / §6.4, the
    /// per-subaddress derivation lands alongside the relocated
    /// classical Edwards-curve primitives in
    /// `shekyl_crypto_pq::subaddress` as
    /// `derive_subaddress_kem_keypair` once its infrastructure
    /// exists; until then,
    /// [`LocalKeys::derive_subaddress`](super::local_keys::LocalKeys::derive_subaddress)
    /// with `Recipient` purpose returns this variant.
    #[error(
        "recipient-context subaddress derivation requires per-subaddress hybrid KEM keygen (shekyl_crypto_pq::subaddress::derive_subaddress_kem_keypair, not yet implemented)"
    )]
    RecipientSubaddressKemKeygenNotImplemented,

    /// The deterministic-handle re-decap path (`LocalKeys::derive_source_secrets_bundle`,
    /// Layer 2 of M3b D1 per `STAGE_1_PR_3_M3B_PREFLIGHT.md` §2)
    /// failed to recover `combined_ss` from the persisted
    /// [`shekyl_crypto_pq::kem::HybridCiphertext`] using the wallet's
    /// view material.
    ///
    /// The expected operational case for this variant is **none**: the
    /// re-decap path is invoked only on outputs the wallet has already
    /// scanned and persisted as its own, so the ciphertext, view
    /// secret, and ML-KEM decap key all came from the same wallet's
    /// own state. A failure here implies storage corruption (the
    /// `TransferDetails.source_ciphertext` no longer matches the bytes
    /// originally written), key-engine state corruption (the wallet's
    /// view material has drifted), or — in the worst case — a
    /// malicious local actor who tampered with the persisted ledger.
    /// The variant is **loud, not silent**: surfaces as a typed error
    /// so the caller can refuse to construct a `TxToSign` against the
    /// affected output rather than silently fall back to derivation
    /// from suspect intermediate state.
    ///
    /// Carries the inner [`shekyl_crypto_pq::CryptoError`] so the
    /// caller (and audit logs) can see whether the failure was a
    /// low-order Montgomery rejection
    /// ([`shekyl_crypto_pq::CryptoError::LowOrderPoint`]),
    /// an invalid decap-key length
    /// ([`shekyl_crypto_pq::CryptoError::InvalidKeyMaterial`]), or
    /// an ML-KEM-768 decap rejection
    /// ([`shekyl_crypto_pq::CryptoError::DecapsulationFailed`]).
    /// All three indicate the same operational class (corrupted /
    /// tampered persisted state) but the inner detail names which
    /// step rejected the input.
    #[error("source ciphertext re-decapsulation failed: {0}")]
    SourceCiphertextDecapsulationFailed(#[from] shekyl_crypto_pq::CryptoError),
}

// --- IO --------------------------------------------------------------------

/// Failures at the wallet's IO boundary: filesystem, daemon RPC,
/// scanner network calls. Wraps the upstream error types via `#[from]`
/// (lands alongside the lifecycle / refresh commits that introduce the
/// call sites).
///
/// `IoError` is intentionally distinct from
/// [`std::io::Error`] — the wallet-core layer's IO surface includes
/// daemon RPC and scanner failures, not just filesystem syscalls. The
/// RPC binary maps each variant to a stable JSON-RPC error code.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// Engine-file envelope / atomic write / advisory lock / payload
    /// frame failure. Wraps [`shekyl_engine_file::WalletFileError`]
    /// (`#[from]` lands with the `open_*` commit).
    #[error("wallet-file failure: {detail}")]
    WalletFile {
        /// Stringified upstream error. Typed `#[from]` from
        /// `WalletFileError` lands alongside the open/save call sites.
        detail: String,
    },

    /// Daemon RPC call failed at the transport, JSON-decode, or
    /// daemon-application layer.
    #[error("daemon RPC failure: {detail}")]
    Daemon {
        /// Stringified upstream error.
        detail: String,
    },

    /// Scanner failure: chain scan, output identification, key-image
    /// computation, or pool-state retrieval.
    #[error("scanner failure: {detail}")]
    Scanner {
        /// Stringified upstream error.
        detail: String,
    },

    /// Bookkeeping-block / ledger-block (de)serialization failure.
    /// Wraps [`shekyl_engine_state::WalletLedgerError`] (`#[from]` lands
    /// with the lifecycle commit).
    #[error("ledger (de)serialization failure: {detail}")]
    Ledger {
        /// Stringified upstream error.
        detail: String,
    },
}

impl From<shekyl_rpc::RpcError> for IoError {
    /// Map the upstream `shekyl_rpc::RpcError` into an
    /// [`IoError::Daemon`] by stringifying the upstream variant.
    ///
    /// This conversion exists so the crate-internal `DaemonEngine`
    /// trait (in `crate::engine::traits`) can declare
    /// `type Error: Into<IoError>` and have
    /// [`Engine`](super::Engine) orchestration code propagate
    /// daemon-RPC failures uniformly via `?`. The stringification is
    /// deliberate: `IoError` is the wallet-core error surface, not
    /// the upstream's; preserving the upstream's typed shape would
    /// either leak the upstream type into the wallet-core API or
    /// require duplicating the upstream's variant taxonomy here.
    /// Stringification keeps the boundary clean while preserving the
    /// failure detail for logs and JSON-RPC error responses. The
    /// upstream type carries a `thiserror`-derived `Display` impl
    /// whose `#[error("...")]` attributes produce stable, human-
    /// readable messages (`"connection error (...)"`,
    /// `"invalid transaction (...)"`, etc.); `Display` is the
    /// canonical stringification rather than `Debug`, which would
    /// leak variant names and bracket-quoted field shapes that are
    /// brittle to upstream refactors.
    fn from(err: shekyl_rpc::RpcError) -> Self {
        IoError::Daemon {
            detail: err.to_string(),
        }
    }
}

// --- Tx ---------------------------------------------------------------------

/// Failures from the transaction-construction layer
/// ([`shekyl-tx-builder`]) and from the wallet's pre-build sanity
/// checks against daemon-supplied fee estimates.
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// The daemon's `priority` fee estimate exceeded the configurable
    /// sanity ceiling (default loose, e.g., `10x` the daemon's `economy`
    /// estimate). Defends against a compromised or buggy daemon
    /// returning extreme values; the ceiling is loose enough not to
    /// second-guess the daemon under normal conditions. See
    /// cross-cutting lock 8.
    #[error(
        "daemon fee estimate unreasonable: priority = {priority} atomic-units/byte, economy = {economy}, ceiling = {ceiling}x economy"
    )]
    DaemonFeeUnreasonable {
        /// Daemon's reported `priority` bucket.
        priority: u64,
        /// Daemon's reported `economy` bucket.
        economy: u64,
        /// Multiplier of `economy` above which `priority` triggers this
        /// error (e.g., default `10`).
        ceiling: u64,
    },

    /// Range-proof construction failed (likely indicates a bug in the
    /// builder or a corrupt input). The variant is named separately
    /// from the catch-all so audit can distinguish proof-system
    /// failures from input-selection failures.
    #[error("range proof construction failed: {detail}")]
    RangeProof {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// FCMP++ membership-proof construction failed. Same audit-distinct
    /// rationale as [`Self::RangeProof`].
    #[error("FCMP++ membership proof construction failed: {detail}")]
    Membership {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// Hybrid PQC signature production failed (Ed25519 path or ML-DSA-65
    /// path). Same audit-distinct rationale.
    #[error("hybrid PQC signature failed: {detail}")]
    Signature {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },

    /// Builder-level assembly produced a transaction that fails
    /// internal consistency checks (sums, key-image uniqueness, etc.).
    /// Should be unreachable in practice; surfaced as a typed error so
    /// it cannot silently land on the wire.
    #[error("transaction failed internal consistency check: {detail}")]
    InternalConsistency {
        /// Human-readable detail named at the call site.
        detail: &'static str,
    },
}

// --- Submit error vocabulary (PR 5) ----------------------------------------

/// Terminal submit-side daemon-rejection sub-discriminant. R9 closure
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.4: the daemon rejected
/// the transaction with a final, non-recoverable outcome. The
/// reservation is dropped from `in_flight`; its `output_locks` are
/// released; the consumer's recourse is to rebuild against the current
/// chain state.
///
/// Separation from [`AmbiguousErrorKind`] is load-bearing at the type
/// level: a terminal error means the outputs are genuinely free
/// (`DoubleSpend` — the inputs were spent elsewhere) or that the
/// transaction itself is not viable (`FeeTooLow` / `Malformed`), so the
/// engine moves the reservation to "gone" deterministically. Consumer
/// code matches on the variant rather than wildcard-handling a unified
/// enum.
///
/// `#[non_exhaustive]` per the segment-2h binding form so V3.x daemon-
/// rejection refinements (e.g., a future `DaemonOutOfMemory` triage
/// hint) land additively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminalErrorKind {
    /// At least one of the transaction's inputs was already spent on
    /// the chain the daemon saw. The reservation's `output_locks` are
    /// released; the consumer rebuilds against the post-spend
    /// snapshot. This is the canonical terminal-outcome case.
    DoubleSpend,

    /// The transaction's fee is below the daemon's relay floor at the
    /// time of submission. R9: terminal in the sense that this specific
    /// reservation is dropped, even though the consumer can rebuild
    /// against the same outputs with a higher fee — the rebuild is a
    /// new reservation, not a fee-bump on the existing one (transaction
    /// replacement is a V3.x consideration per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.4 R18).
    FeeTooLow,

    /// The transaction failed daemon-side structural validation
    /// (invalid signature, malformed proof, internally inconsistent
    /// commitments, …). Indicates a bug in the build path; the variant
    /// exists so audit can distinguish the structural-defect class from
    /// the spend-conflict and economic-policy classes.
    Malformed,
}

/// Ambiguous submit-side daemon-rejection sub-discriminant. R9
/// Finding 2 closure per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.4:
/// the daemon round-trip did not produce a definitive outcome
/// (timeout, transport failure). The reservation **remains** in
/// `in_flight` because the daemon may still relay the transaction —
/// auto-releasing the `output_locks` here would race the daemon's
/// eventual mempool-accept.
///
/// The consumer cannot force-discard an `AmbiguousErrorKind`
/// reservation per the F2 ownership-boundary adjudication; the R8
/// TTL safety-net is the eventual release path. Stage 4's actor
/// migration adds the V3.x `MempoolMonitorActor` consumer pattern
/// that observes daemon-mempool state and calls `signal_mempool_evicted`
/// on confirmed-evicted reservations (G1 per §5.6.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmbiguousErrorKind {
    /// The daemon RPC did not return within the submit-path timeout.
    /// The reservation stays in `in_flight`; the daemon may still
    /// have accepted the transaction.
    DaemonTimeout,

    /// The daemon RPC failed at the transport layer (connection
    /// refused, dropped midway, TLS error). Same disposition as
    /// `DaemonTimeout` — the daemon's authoritative state is
    /// unknown to the engine.
    DaemonUnavailable,
}

/// Failures from `PendingTxEngine::submit` (the trait surface that
/// `LocalPendingTx::submit` implements). R9 segment-2h binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0a.
///
/// The variant set splits a unified `SubmitErrorKind` (the prior
/// Round-3 shape) into [`TerminalErrorKind`] and [`AmbiguousErrorKind`]
/// so the lifecycle distinction (reservation gone vs. reservation
/// retained in `in_flight`) is load-bearing at the type level. The
/// design rationale lives in §5.6.4 of the PR 5 doc.
///
/// `#[non_exhaustive]` per Phase 0a so V3.x submit-side refinements
/// (e.g., a `MempoolFull` advisory variant once daemon-side feedback
/// supports it) land without a major-version break.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// R5: pre-daemon staleness check failed. The reservation's
    /// `snapshot_id` no longer matches the engine's `current_snapshot`,
    /// so submitting would race a reorg. **Lazy R5 (segment-2h):** the
    /// reservation does **not** auto-release its `output_locks` —
    /// the consumer must explicitly `discard(rid, ConsumerExplicit)`
    /// to release them (or rebuild, which will overlap the same
    /// outputs and surface them again). The eager-release alternative
    /// is a V3.x opt-in (`STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.7
    /// P9 trigger).
    #[error(
        "snapshot invalidated: reservation_snapshot = {reservation_snapshot:?}, current_snapshot = {current_snapshot:?}"
    )]
    SnapshotInvalidated {
        /// The `SnapshotId` recorded on the reservation at build time.
        reservation_snapshot: SnapshotId,
        /// The engine's current `SnapshotId` at submit time.
        current_snapshot: SnapshotId,
    },

    /// R9: the daemon round-trip completed with a terminal outcome.
    /// The rid is dropped from `in_flight`; `output_locks` are
    /// released; the consumer rebuilds against the current snapshot.
    #[error("daemon rejected submission terminally: {kind:?}")]
    DaemonRejectedTerminal {
        /// The terminal sub-discriminant.
        kind: TerminalErrorKind,
    },

    /// R9: the daemon round-trip completed with an ambiguous outcome.
    /// The rid **stays** in `in_flight`; `output_locks` are retained
    /// until either the daemon resolves (mempool-accept or
    /// mempool-evict) or the R8 TTL safety-net fires. Consumer-explicit
    /// discard is blocked per F2 ownership-boundary — see
    /// [`PendingTxError::DiscardBlockedPendingDaemonAck`].
    #[error("daemon submit ambiguous: {kind:?} (reservation {reservation_id:?} retained)")]
    DaemonAmbiguous {
        /// The ambiguous sub-discriminant.
        kind: AmbiguousErrorKind,
        /// The reservation that remains `in_flight`.
        reservation_id: ReservationId,
    },

    /// P3: rid was in neither `consumer_held` nor `in_flight` at
    /// submit entry. Either the rid was never issued, or it was
    /// already resolved (terminal-error path or successful
    /// daemon-accept) by the time the consumer called `submit`.
    #[error("reservation {reservation_id:?} not found")]
    ReservationNotFound {
        /// The rid the consumer passed.
        reservation_id: ReservationId,
    },

    /// P2: rid was found in `in_flight` at submit entry — a second
    /// `submit` is being attempted while the first is still
    /// daemon-pending.
    #[error("submit already pending for reservation {reservation_id:?}")]
    SubmitAlreadyPending {
        /// The rid whose duplicate submit was refused.
        reservation_id: ReservationId,
    },
}

// --- PendingTxEngine collaborator-error vocabulary (PR 5) -----------------

/// Failures from `OutputSelector::select_outputs` — the trait that
/// chooses spendable outputs for a build call. Phase 0i binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R13 segment-2c closure).
///
/// The trait isolates output-selection policy from the build pipeline:
/// the default implementation is wallet-greedy; consumers can plug in
/// alternative selectors for testing (`FaultyOutputSelector`) or for
/// privacy-improving strategies that emerge post-V3.0.
///
/// `#[non_exhaustive]` so V3.x selectors can extend the variant set
/// with their own failure modes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OutputSelectorError {
    /// The selector could not assemble a candidate set whose sum
    /// covers `needed`. Distinct from [`SendError::InsufficientFunds`]
    /// because it reports the selector's view, which may differ from
    /// the wallet's gross balance (selectors filter out
    /// locked / immature / dust outputs before reasoning about
    /// coverage).
    #[error("output selector: insufficient funds (need {needed}, available {available})")]
    InsufficientFunds {
        /// Total amount-plus-fee the selector was asked to cover.
        needed: u64,
        /// Sum of outputs the selector considered eligible.
        available: u64,
    },

    /// The selector returned an empty candidate set even though the
    /// wallet has spendable balance — typically because every output
    /// is locked by another in-flight reservation
    /// (`output_locks` filter per the (γ) three-collection lean
    /// shape's P6 disposition).
    #[error("output selector: no eligible outputs")]
    NoEligibleOutputs,

    /// F4 caller-side subset re-verification: the selector returned
    /// an output index that is **not** a subset of the filtered
    /// candidate set the engine passed in. R13 / F4 closure per
    /// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F4 — the engine
    /// re-verifies the selector's output set rather than trusting
    /// it blindly, so a buggy or malicious selector cannot bypass
    /// the `output_locks` filter the engine applied pre-selection.
    ///
    /// The variant carries the first offending index so audit can
    /// reproduce the violation deterministically. The selector
    /// surface is a trait, so the failure is a contract violation
    /// not a panic.
    #[error("output selector returned non-subset index: offending_index = {offending_index}")]
    ReturnedIndicesNotSubset {
        /// First selector-returned index that was not in the
        /// engine's candidate set. Indices are positions into the
        /// engine's wallet-output table; precise typing (e.g., a
        /// dedicated `OutputIndex` newtype) is a V3.x refinement
        /// item per `docs/FOLLOWUPS.md`.
        offending_index: usize,
    },
}

/// Failures from `FeeEstimator::estimate_fee`. Phase 0j binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R16 segment-2c closure
/// with segment-2d V3.0-lift evaluation).
///
/// The trait isolates fee-estimation policy from the build pipeline.
/// The default implementation forwards the daemon's `priority` /
/// `economy` buckets; consumers can plug in custom estimators for
/// testing or for offline-build flows.
///
/// `#[non_exhaustive]` so V3.x estimators can extend the variant set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeeEstimatorError {
    /// The daemon RPC the estimator depends on was unreachable.
    #[error("fee estimator: daemon unreachable")]
    DaemonUnreachable,

    /// The daemon returned a response that the estimator could not
    /// consume (missing field, out-of-range value, etc.). Carries
    /// a `&'static str` named at the call site so audit can read
    /// every distinguishable defect class from source.
    #[error("fee estimator: daemon response invalid ({reason})")]
    DaemonResponseInvalid {
        /// Compile-time-fixed description of the contract violation.
        reason: &'static str,
    },
}

/// Failures from `Signer::sign_transfer`. Phase 0h binding form
/// per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R11 (b) segment-2b
/// closure as separate `LocalSigner` / `SigningActor`).
///
/// The trait isolates spend-key access from the build pipeline so the
/// PR 5 design can survive the eventual V3.x `SigningActor` topology
/// without re-opening the trait surface. The default V3.0 impl is
/// `LocalSigner` (synchronous, in-process); the V3.x actor variant
/// lives behind the same trait.
///
/// `#[non_exhaustive]` so V3.x signers can extend the variant set
/// (e.g., a `HardwareApprovalDeclined` variant when offline-approval
/// flows land).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer has no spend-key material in scope (view-only
    /// wallet; hardware wallet not connected; signing actor not yet
    /// started). Distinct from [`SendError::CannotSign`] because it
    /// is the trait-method's outcome, not the engine's pre-build
    /// capability check.
    #[error("signer unavailable")]
    Unavailable,

    /// The signer attempted to sign but a downstream failure
    /// prevented completion (hardware-device error, remote-actor
    /// disconnect, etc.). Carries a `&'static str` named at the call
    /// site.
    #[error("signer remote failure ({reason})")]
    RemoteFailure {
        /// Compile-time-fixed description of the downstream failure.
        reason: &'static str,
    },
}
