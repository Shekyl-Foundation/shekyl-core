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

    /// This computer's random-number source failed the check the stake engine
    /// runs before it starts (S6), so the wallet did not open. Staking on a
    /// source that fails the check could link the wallet's stakes.
    ///
    /// A unit variant in every build, so an exhaustive match names it whether
    /// or not `conformance` is on. Only that build runs the check and returns
    /// this variant. The grade is logged at the check and is not carried
    /// here, so the default build has no float grader.
    #[error("wallet open refused: this computer's random-number source failed the stake check")]
    StakeRngSelfCertFailed,
}

/// Why the stake engine's startup random-number check failed (S6).
///
/// Conformance build only. Structured so the grade reaches the log instead
/// of being stringified at the actor boundary. The open path logs this value
/// and returns the unit [`OpenError::StakeRngSelfCertFailed`], which does
/// not carry it.
#[cfg(feature = "conformance")]
#[derive(Debug, Clone, thiserror::Error)]
pub(crate) enum StakeSelfCertFailure {
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
/// save / rotate paths (`save_state`, `rotate_password`).
///
/// Mapped at the lifecycle boundary: [`OpenError::Persistence`] on
/// [`crate::engine::Engine::close`](crate::engine::Engine::close); returned
/// as is from [`crate::engine::Engine::change_password`](crate::engine::Engine::change_password).
#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    /// On-disk wallet envelope / atomic-write failure. The target was not
    /// replaced.
    #[error("wallet file error: {0}")]
    WalletFile(#[from] shekyl_engine_file::WalletFileError),

    /// The rename landed and its durability was not confirmed, for this
    /// reason (on Unix the parent-directory fsync failed; on Windows the
    /// volume is not NTFS, or the confirmation failed otherwise). The write
    /// is applied, so the in-memory record stays; a broadcast must not. The
    /// reason's sentence names the fix: on a FAT, exFAT or ReFS volume, the
    /// file system and a move to an NTFS volume (Rick, 2026-11-18).
    #[error("the wallet save was applied but not confirmed on disk: {0}")]
    DurabilityUnconfirmed(shekyl_engine_file::Unconfirmed),
}
