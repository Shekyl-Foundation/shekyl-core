// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Open / lifecycle and persistence error vocabulary.

use shekyl_address::Network;

use super::{IoError, KeyError};

// --- Open / lifecycle ------------------------------------------------------

/// Failures from
/// [`Engine::create`](crate::engine::Engine) /
/// [`Engine::open_full`](crate::engine::Engine) /
/// [`Engine::open_view_only`](crate::engine::Engine) /
/// [`Engine::open_hardware_offload`](crate::engine::Engine) /
/// [`Engine::change_password`](crate::engine::Engine) /
/// [`Engine::close`](crate::engine::Engine).
///
/// These are the lifecycle failures; once a wallet is open and refresh /
/// send paths are running, their failures live in
/// [`RefreshError`](super::RefreshError) / [`SendError`](super::SendError) /
/// [`PendingTxError`](super::PendingTxError).
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
    /// Returns the typed [`crate::engine::Capability`] read from the envelope so
    /// the caller can branch on it without re-opening.
    #[error(
        "capability mismatch: wallet is {found:?}, but the requested operation needs another mode"
    )]
    CapabilityMismatch {
        /// Capability declared by the wallet file's region 1.
        found: crate::engine::Capability,
    },

    /// `Engine::close` was called while at least one [`PendingTx`] was
    /// still in the reservation ledger. Caller must
    /// [`Engine::submit_pending_tx`](crate::engine::Engine::submit_pending_tx) or
    /// [`Engine::discard_pending_tx`](crate::engine::Engine::discard_pending_tx)
    /// each handle before close. See
    /// cross-cutting lock 4.
    ///
    /// [`PendingTx`]: crate::engine::Engine
    #[error("close refused: {count} PendingTx in flight; submit or discard first")]
    OutstandingPendingTx {
        /// How many in-flight reservations the close call observed.
        count: usize,
    },

    /// Final ledger/prefs flush during [`crate::engine::Engine::close`] failed.
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
        capability: crate::engine::Capability,
    },

    /// **Conformance build only (S6).** The StakeEngine's session RNG self-cert
    /// failed at spawn: the OS CSPRNG graded non-conformant for the entry-gap
    /// timing draws (or the entropy source failed mid-draw). A degenerate timing
    /// RNG defeats the gate-6 decorrelation firewall, so the staker actor refuses
    /// to start and wallet-open fails loudly rather than staking on a CSPRNG that
    /// cannot produce unlinkable timing. This variant does not exist in the
    /// default (non-`conformance`) build — production carries no float/stats
    /// grader (`ARCHIVAL_BOND_S6_CERTIFY_DRAW_PLAN.md` §0).
    ///
    /// Carries the **structured** [`StakeSelfCertFailure`] (not a pre-rendered
    /// string), keeping the grade detail — the `CertifyReport` — available for
    /// logging / programmatic handling, per the module's no-stringly-typed-error
    /// rule. The `#[source]` chains it; `Display` still renders the human message.
    #[cfg(feature = "conformance")]
    #[error("wallet open refused: StakeEngine session RNG self-cert failed at startup: {0}")]
    StakeRngSelfCertFailed(#[source] StakeSelfCertFailure),
}

/// **Conformance build only (S6).** Why the StakeEngine startup session RNG
/// self-cert failed — structured so the grade detail survives to logging /
/// handling instead of being stringified at the actor boundary (the wallet-core
/// API does not return stringly-typed errors; see the module doc). Surfaced
/// through [`OpenError::StakeRngSelfCertFailed`].
#[cfg(feature = "conformance")]
#[derive(Debug, Clone, thiserror::Error)]
pub enum StakeSelfCertFailure {
    /// The OS CSPRNG graded **non-conformant** for the entry-gap timing draws.
    /// Carries the full [`CertifyReport`](shekyl_standoff::conformance::CertifyReport)
    /// (chi-square, the three property verdicts) — the data worth keeping.
    #[error("the OS CSPRNG graded non-conformant for entry-gap timing draws: {0:?}")]
    NonConformant(shekyl_standoff::conformance::CertifyReport),

    /// `on_start` failed before the grade completed — typically a panic from the
    /// OS entropy source failing mid-draw, or (future) another startup error.
    /// A panic / foreign start error has no richer structure than its rendered
    /// cause, so this case is honestly a string.
    #[error("StakeEngine startup failed before the self-cert completed: {0}")]
    StartupFailed(String),
}

// --- Persistence -----------------------------------------------------------

/// Failures from [`crate::engine::traits::persistence::PersistenceEngine`] steady-state
/// save / rotate paths (`save_state`, `save_prefs`, `rotate_password`).
///
/// Mapped at the lifecycle boundary: [`OpenError::Persistence`] on
/// [`crate::engine::Engine::close`](crate::engine::Engine::close);
/// [`ChangePasswordError`] on [`crate::engine::Engine::change_password`](crate::engine::Engine::change_password).
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// On-disk wallet envelope / atomic-write failure.
    #[error("wallet file error: {0}")]
    WalletFile(#[from] shekyl_engine_file::WalletFileError),

    /// Prefs sidecar load/save/HMAC failure.
    #[error("prefs error: {0}")]
    Prefs(#[from] shekyl_engine_prefs::PrefsError),
}

/// Failures from [`crate::engine::Engine::change_password`](crate::engine::Engine::change_password)
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
