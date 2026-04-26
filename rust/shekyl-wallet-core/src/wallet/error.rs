// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-domain error enums for the `Wallet` orchestrator.
//!
//! Cross-cutting lock 2 in the rewrite plan locks the error shape:
//!
//! > Domain layer (`shekyl-wallet-core`) ships per-domain error enums
//! > (`SendError`, `RefreshError`, `KeyError`, `IoError`, etc.) with
//! > `thiserror` + `#[from]` conversions for ergonomic `?` propagation.
//! > The RPC layer (`shekyl-wallet-rpc`) defines a single
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
//! impls for upstream errors (`shekyl_wallet_file::WalletFileError`,
//! `shekyl_crypto_pq::CryptoError`, `shekyl_wallet_state::WalletLedgerError`,
//! `shekyl_wallet_prefs::PrefsError`, daemon-RPC errors, scanner
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

// --- Open / lifecycle ------------------------------------------------------

/// Failures from
/// [`Wallet::create`](super::Wallet) /
/// [`Wallet::open_full`](super::Wallet) /
/// [`Wallet::open_view_only`](super::Wallet) /
/// [`Wallet::open_hardware_offload`](super::Wallet) /
/// [`Wallet::change_password`](super::Wallet) /
/// [`Wallet::close`](super::Wallet).
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

    /// `Wallet::close` was called while at least one [`PendingTx`] was
    /// still in the reservation ledger. Caller must
    /// [`Wallet::submit_pending_tx`] or
    /// [`Wallet::discard_pending_tx`] each handle before close. See
    /// cross-cutting lock 4.
    ///
    /// [`PendingTx`]: super::Wallet
    #[error("close refused: {count} PendingTx in flight; submit or discard first")]
    OutstandingPendingTx {
        /// How many in-flight reservations the close call observed.
        count: usize,
    },

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

// --- Refresh ---------------------------------------------------------------

/// Failures from [`Wallet::refresh`](super::Wallet) and the
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
}

// --- Send / build / submit / discard --------------------------------------

/// Failures from [`Wallet::build_pending_tx`](super::Wallet) and the
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
    /// taken when a `Wallet<SoloSigner>` is asked to send but the
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
/// [`Wallet::submit_pending_tx`](super::Wallet) /
/// [`Wallet::discard_pending_tx`](super::Wallet) and from the
/// reservation-bookkeeping logic of `build_pending_tx`. Cross-cutting
/// lock 4 binds the variants
/// [`Self::TooOld`] and [`Self::ChainStateChanged`].
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
    #[error("unknown PendingTx handle")]
    UnknownHandle,

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
    /// Wallet-file envelope / atomic write / advisory lock / payload
    /// frame failure. Wraps [`shekyl_wallet_file::WalletFileError`]
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
    /// Wraps [`shekyl_wallet_state::WalletLedgerError`] (`#[from]` lands
    /// with the lifecycle commit).
    #[error("ledger (de)serialization failure: {detail}")]
    Ledger {
        /// Stringified upstream error.
        detail: String,
    },
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
