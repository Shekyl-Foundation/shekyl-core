// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `.wallet`-side ledger aggregator.
//!
//! Bundles the four typed blocks — [`LedgerBlock`], [`BookkeepingBlock`],
//! [`TxMetaBlock`], and [`SyncStateBlock`] — into a single
//! postcard-serialized payload that the wallet-file orchestrator
//! (commit 2h) stores as Region 2 of the `.wallet` file.
//!
//! # Two-tier versioning
//!
//! Two independent version numbers live in this layout, and they evolve
//! on separate schedules:
//!
//! 1. **Bundle `format_version`**, defined here as
//!    [`WALLET_LEDGER_FORMAT_VERSION`]. Bumps only when the aggregator
//!    layout itself changes — a new top-level block added, removed, or
//!    reordered. All other bundle-wide metadata (if any) is pinned here.
//! 2. **Per-block `block_version`**, defined in each block module. Bumps
//!    when a single block's schema evolves without touching the others.
//!    Each block's load path enforces its own version independently; a
//!    mismatch on any block aborts the whole load.
//!
//! The load path checks both tiers:
//!
//! * First, `format_version` — if it disagrees with the binary, fail with
//!   [`WalletLedgerError::UnsupportedFormatVersion`] before trusting any
//!   inner bytes. Rule-81 ("no silent migration") applies here: we do
//!   not opportunistically try to decode as if it were the current
//!   format.
//! * Then, fan out per-block `check_version()` calls and fail fast on the
//!   first mismatch.
//!
//! # Wire format
//!
//! `postcard` over the four blocks in declared field order plus the
//! bundle `format_version`. Every inner block's `block_version` stays
//! within the block's own postcard frame, so a version bump on one
//! block does not accidentally shift the byte offsets of any other
//! block on disk.
//!
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock

use serde::{Deserialize, Serialize};

use crate::{
    bookkeeping_block::BookkeepingBlock, error::WalletLedgerError, ledger_block::LedgerBlock,
    sync_state_block::SyncStateBlock, tx_meta_block::TxMetaBlock,
};

/// Bundle-level `format_version`. V3.0 ships `1`. Bumps only when the
/// aggregator layout itself changes (new top-level block, removed
/// block, reordering). Per-block schema changes bump the block's own
/// `block_version`, not this constant.
pub const WALLET_LEDGER_FORMAT_VERSION: u32 = 1;

/// The `.wallet`-side ledger bundle: the four typed blocks + a
/// bundle-level `format_version`.
///
/// Deliberately NOT [`Clone`] at the aggregator level because
/// [`LedgerBlock`] and [`TxMetaBlock`] refuse to be cloned (they own
/// `Zeroize`-ing secrets for which clone semantics are ambiguous).
/// Callers that need a snapshot should re-serialize.
///
/// [`LedgerBlock`]: crate::ledger_block::LedgerBlock
/// [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
#[derive(Debug, Serialize, Deserialize, postcard_schema::Schema)]
pub struct WalletLedger {
    /// Bundle-level schema version. Always
    /// [`WALLET_LEDGER_FORMAT_VERSION`] on construction; rejected on
    /// load if it does not match.
    pub format_version: u32,

    /// Scanner-derived on-chain ledger: transfers, tip, reorg window.
    pub ledger: LedgerBlock,

    /// User-facing UX state: subaddress registry, labels, address
    /// book, account tags.
    pub bookkeeping: BookkeepingBlock,

    /// Per-tx side channel: tx secret keys, notes, attributes, pool
    /// observations.
    pub tx_meta: TxMetaBlock,

    /// Scan anchor + pending-tx tracking + daemon context.
    pub sync_state: SyncStateBlock,
}

impl WalletLedger {
    /// Fresh, empty wallet ledger pinned to the current format version.
    /// Every inner block starts at its own current `block_version`.
    pub fn empty() -> Self {
        Self {
            format_version: WALLET_LEDGER_FORMAT_VERSION,
            ledger: LedgerBlock::empty(),
            bookkeeping: BookkeepingBlock::empty(),
            tx_meta: TxMetaBlock::empty(),
            sync_state: SyncStateBlock::empty(),
        }
    }

    /// Assemble a wallet ledger from its four component blocks, pinning
    /// the bundle `format_version`. Caller-supplied blocks keep their
    /// own `block_version` values (already current by construction
    /// through each block's `new` / `empty` constructor).
    pub fn new(
        ledger: LedgerBlock,
        bookkeeping: BookkeepingBlock,
        tx_meta: TxMetaBlock,
        sync_state: SyncStateBlock,
    ) -> Self {
        Self {
            format_version: WALLET_LEDGER_FORMAT_VERSION,
            ledger,
            bookkeeping,
            tx_meta,
            sync_state,
        }
    }

    /// Serialize the full bundle to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize a full bundle from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. Enforces the bundle
    /// `format_version` gate, every inner block's `block_version`
    /// gate, and the aggregator-level invariants owned by
    /// [`crate::invariants`]. Fails fast on the first mismatch so the
    /// diagnostic points at the earliest failure rather than a
    /// downstream symptom.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let ledger: Self = postcard::from_bytes(bytes)?;
        ledger.check_format_version()?;
        ledger.check_all_block_versions()?;
        ledger.check_invariants()?;
        Ok(ledger)
    }

    /// Bundle-level version gate.
    pub fn check_format_version(&self) -> Result<(), WalletLedgerError> {
        if self.format_version != WALLET_LEDGER_FORMAT_VERSION {
            return Err(WalletLedgerError::UnsupportedFormatVersion {
                file: self.format_version,
                binary: WALLET_LEDGER_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// Fan out per-block version checks. Ordered ledger → bookkeeping
    /// → tx_meta → sync_state so failure diagnostics are predictable.
    pub fn check_all_block_versions(&self) -> Result<(), WalletLedgerError> {
        self.ledger.check_version()?;
        self.bookkeeping.check_version()?;
        self.tx_meta.check_version()?;
        self.sync_state.check_version()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bookkeeping_block::BOOKKEEPING_BLOCK_VERSION, ledger_block::LEDGER_BLOCK_VERSION,
        sync_state_block::SYNC_STATE_BLOCK_VERSION, tx_meta_block::TX_META_BLOCK_VERSION,
    };

    #[test]
    fn empty_bundle_roundtrips_and_pins_versions() {
        let w = WalletLedger::empty();
        assert_eq!(w.format_version, WALLET_LEDGER_FORMAT_VERSION);
        assert_eq!(w.ledger.block_version, LEDGER_BLOCK_VERSION);
        assert_eq!(w.bookkeeping.block_version, BOOKKEEPING_BLOCK_VERSION);
        assert_eq!(w.tx_meta.block_version, TX_META_BLOCK_VERSION);
        assert_eq!(w.sync_state.block_version, SYNC_STATE_BLOCK_VERSION);

        let bytes = w.to_postcard_bytes().expect("serialize");
        let back = WalletLedger::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back.format_version, WALLET_LEDGER_FORMAT_VERSION);
        assert_eq!(back.ledger.block_version, LEDGER_BLOCK_VERSION);
        assert_eq!(back.bookkeeping.block_version, BOOKKEEPING_BLOCK_VERSION);
        assert_eq!(back.tx_meta.block_version, TX_META_BLOCK_VERSION);
        assert_eq!(back.sync_state.block_version, SYNC_STATE_BLOCK_VERSION);
    }

    #[test]
    fn empty_bundle_is_byte_stable() {
        let w = WalletLedger::empty();
        let bytes1 = w.to_postcard_bytes().expect("serialize1");
        let back = WalletLedger::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(
            bytes1, bytes2,
            "bundle postcard encoding must be byte-stable"
        );
    }

    #[test]
    fn wrong_format_version_is_refused() {
        // Bundle version mismatch is a distinct error from any block
        // version mismatch, even though the wire shape is identical.
        let mut w = WalletLedger::empty();
        w.format_version = 999;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedFormatVersion { file, binary } => {
                assert_eq!(file, 999);
                assert_eq!(binary, WALLET_LEDGER_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
    }

    #[test]
    fn inner_ledger_block_version_bump_is_refused_by_aggregator() {
        // A stale `LedgerBlock.block_version` inside an otherwise-fresh
        // bundle must still abort the whole load. The aggregator does
        // NOT accept the ledger block silently just because the bundle
        // version is current.
        let mut w = WalletLedger::empty();
        w.ledger.block_version = 42;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "ledger");
                assert_eq!(file, 42);
                assert_eq!(binary, LEDGER_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(ledger), got {other:?}"),
        }
    }

    #[test]
    fn inner_bookkeeping_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.bookkeeping.block_version = 7;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "bookkeeping");
                assert_eq!(file, 7);
                assert_eq!(binary, BOOKKEEPING_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(bookkeeping), got {other:?}"),
        }
    }

    #[test]
    fn inner_tx_meta_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.tx_meta.block_version = 1234;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "tx_meta");
                assert_eq!(file, 1234);
                assert_eq!(binary, TX_META_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(tx_meta), got {other:?}"),
        }
    }

    #[test]
    fn inner_sync_state_block_version_bump_is_refused_by_aggregator() {
        let mut w = WalletLedger::empty();
        w.sync_state.block_version = 99;
        let bytes = w.to_postcard_bytes().expect("serialize");
        match WalletLedger::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "sync_state");
                assert_eq!(file, 99);
                assert_eq!(binary, SYNC_STATE_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion(sync_state), got {other:?}"),
        }
    }

    #[test]
    fn format_version_check_runs_before_block_version_checks() {
        // If BOTH the bundle version AND an inner block version are
        // wrong, the format-version gate wins — the aggregator fails
        // fast before trusting any inner block's bytes.
        let mut w = WalletLedger::empty();
        w.format_version = 42;
        w.ledger.block_version = 42;
        let bytes = w.to_postcard_bytes().expect("serialize");
        let err = WalletLedger::from_postcard_bytes(&bytes).unwrap_err();
        match err {
            WalletLedgerError::UnsupportedFormatVersion { file, binary } => {
                assert_eq!(file, 42);
                assert_eq!(binary, WALLET_LEDGER_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedFormatVersion to win ordering, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let w = WalletLedger::empty();
        let bytes = w.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        let is_postcard = matches!(
            WalletLedger::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }
}
