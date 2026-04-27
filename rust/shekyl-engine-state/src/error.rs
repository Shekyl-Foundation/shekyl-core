// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Errors produced when (de)serializing the postcard-encoded ledger blocks
//! that live on the `.wallet` side of the two-file wallet envelope.
//!
//! This is the `.wallet`-side counterpart of
//! [`shekyl_crypto_pq::wallet_state::WalletStateError`], which covers the
//! JSON-encoded metadata bundle on the `.wallet.keys` side. The two error
//! types are deliberately distinct: their wire formats, their version
//! domains (`CURRENT_METADATA_FORMAT_VERSION` vs. the ledger's own bundle
//! version arriving in commit 2g), and their failure modes (JSON-decode
//! vs. postcard-decode) do not overlap.

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
        "unsupported wallet-ledger format version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
    )]
    UnsupportedFormatVersion { file: u32, binary: u32 },

    /// A block's own `block_version` does not match the version this binary
    /// knows how to read for that block. Each block evolves independently;
    /// a mismatch on any block aborts the whole load per the rule-81 "no
    /// silent migration" stance.
    #[error(
        "unsupported {block} block version: file = {file}, binary = {binary}; \
         no migration path exists in this binary"
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
