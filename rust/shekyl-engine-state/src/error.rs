// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Errors produced when (de)serializing the postcard-encoded ledger blocks
//! that live on the `.wallet` side of the two-file wallet envelope.
//!
//! These errors are intentionally narrow: postcard-decode failures plus
//! version and length mismatches for the typed blocks in this crate. Per the
//! "no silent migration" stance pinned by rule 142 (serialization-policy) they
//! refuse rather than migrate on any version drift.

/// Errors produced by [`LedgerBlock`](crate::ledger_block::LedgerBlock) and
/// the other `.wallet`-side typed blocks in this crate.
#[derive(Debug, thiserror::Error)]
pub enum WalletLedgerError {
    /// The bundle-level `format_version` of the [`WalletLedger`] aggregator
    /// does not match the version this binary knows how to read. Bundle
    /// version is independent of the per-block `block_version` values and
    /// bumps only when the aggregator layout itself changes (e.g. a new
    /// top-level block is added or removed).
    ///
    /// [`WalletLedger`]: crate::wallet_ledger::WalletLedger
    #[error(
        "unsupported wallet-ledger format version: file = {file}, binary = {binary}; {}",
        version_remedy(*.file, *.binary)
    )]
    UnsupportedFormatVersion { file: u32, binary: u32 },

    /// The `format_version` of a group wallet's ledger
    /// ([`GroupWalletLedger`]) is not the one this binary reads. Its own
    /// variant: a group wallet has no seed, so the remedy is its member
    /// file (R-30).
    ///
    /// [`GroupWalletLedger`]: crate::group_ledger::GroupWalletLedger
    #[error(
        "unsupported group wallet ledger format version: file = {file}, binary = {binary}; {}",
        group_version_remedy(*.file, *.binary)
    )]
    UnsupportedGroupFormatVersion { file: u32, binary: u32 },

    /// A block's own `block_version` does not match the version this binary
    /// knows how to read for that block. Each block evolves independently;
    /// a mismatch on any block aborts the whole load per the "no silent
    /// migration" stance pinned by rule 142 (serialization-policy).
    #[error(
        "unsupported {block} block version: file = {file}, binary = {binary}; {}",
        version_remedy(*.file, *.binary)
    )]
    UnsupportedBlockVersion {
        block: &'static str,
        file: u32,
        binary: u32,
    },

    /// `postcard` failed to decode the bytes as the expected shape.
    /// Forwarded verbatim from the postcard error for diagnostics.
    #[error("postcard decode failed: {0}")]
    Postcard(#[from] postcard::Error),

    /// A [`GroupWalletLedger`]'s outputs are not a set: two of them share an
    /// output key or a key image. The scan skips a duplicate as it arrives;
    /// a file that already holds one is refused, because dropping it on open
    /// would change the balance the file claimed.
    ///
    /// [`GroupWalletLedger`]: crate::group_ledger::GroupWalletLedger
    #[error("group ledger invariant failed ({invariant}): {detail}")]
    GroupInvariantFailed {
        /// Stable name. `group-outputs-unique`.
        invariant: &'static str,
        /// Which identity was repeated.
        detail: String,
    },

    /// An aggregator-level invariant on the [`WalletLedger`] bundle
    /// failed. Unlike a version mismatch or a postcard decode error,
    /// this fires *after* every block decoded individually — the bytes
    /// on disk are internally consistent at the postcard layer but the
    /// *relationship* between blocks violates an invariant the runtime
    /// relies on (see `invariants` module for the closed set).
    ///
    /// The `invariant` field is a stable, machine-readable name (e.g.
    /// `"tip-height-not-below-transfer"`); the `detail` carries the
    /// specific shape that tripped the check. On the load path this is
    /// a typed refusal; on the save path it is the release-build
    /// fallback after a `debug_assert!` would have fired in debug.
    ///
    /// [`WalletLedger`]: crate::wallet_ledger::WalletLedger
    #[error("wallet ledger invariant failed ({invariant}): {detail}")]
    InvariantFailed {
        invariant: &'static str,
        detail: String,
    },
}

/// What to do about a file whose version this build does not read. A file
/// from an earlier build is not migrated (pre-genesis, rule 142): the wallet
/// is restored from its seed, and the refusal names what a restore does not
/// bring back (rule 82). The scan re-derives the received outputs, what is
/// spent and the balance from the chain; it cannot re-derive what only this
/// file held: the send journal (the history of the wallet's sends), the
/// random per-transaction secrets the outbound proofs need, the notes and
/// the payment requests. A file from a later build is opened with that
/// build.
/// The same answer for a group wallet's ledger. A group wallet is restored
/// from its member file, not a seed; the scan re-derives the group's
/// outputs and what is spent, and the notes this file held are not
/// restored.
fn group_version_remedy(file: u32, binary: u32) -> &'static str {
    if file < binary {
        "this build does not migrate files from earlier versions: restore the group wallet \
         from its member file; your notes are not restored"
    } else {
        "the file is from a later build: open it with that build"
    }
}

fn version_remedy(file: u32, binary: u32) -> &'static str {
    if file < binary {
        "this build does not migrate files from earlier versions: restore the wallet from its \
         seed; your send history, proofs for earlier sends, notes and payment requests are not \
         restored"
    } else {
        "the file is from a later build: open it with that build"
    }
}
