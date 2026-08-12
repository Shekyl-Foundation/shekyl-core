// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Sync-state block — wallet scan anchor, pending-tx tracker, and daemon
//! context needed to resume scanning across restarts.
//!
//! Fourth and last of the four `.wallet`-side ledger blocks
//! (after [`LedgerBlock`], [`BookkeepingBlock`], and [`TxMetaBlock`]).
//! This block captures the state that the scanner needs to pick up
//! where it left off, **beyond** what the ledger's own tip and reorg
//! window already provide:
//!
//! * `restore_from_height` — the wallet birthday (user-configured or
//!   derived from the seed epoch). Scans never descend below this height,
//!   so the scanner knows where to start when the ledger is empty.
//! * `creation_anchor_hash` — an optional block hash committing the
//!   wallet to a specific fork at creation time (the staking-canonicity
//!   "trust floor"). **Reserved:** V3.0 constructs it `None` and no code
//!   reads it yet — see the field docstring.
//! * `pending_tx_hashes` — txids the *user* has submitted locally but
//!   that have not yet been observed on-chain by the scanner. Used for
//!   the UX "pending outgoing" state; reconciled against
//!   [`LedgerBlock::transfers`] and [`TxMetaBlock::scanned_pool_txs`](crate::tx_meta_block::TxMetaBlock::scanned_pool_txs) at
//!   load time.
//!
//! SA-4 deleted three never-wired wallet2-lineage fields at block version
//! `2` (`scan_completed`, `confirmations_required`, `trusted_daemon`):
//! each had no writer, no reader, and a docstring naming a consumer that
//! did not exist (see [`SYNC_STATE_BLOCK_VERSION`]).
//!
//! # Wire format
//!
//! Postcard-serialized. Small, schema-narrow, and entirely
//! `PartialEq`-friendly — no secrets live in the sync-state block, so
//! the test matrix asserts strict value equality after round-trip.
//!
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`LedgerBlock::transfers`]: crate::ledger_block::LedgerBlock::transfers

use serde::{Deserialize, Serialize};

use crate::error::WalletLedgerError;

/// Schema version of the sync-state block. V3.0 ships version `2`.
/// Any field addition / removal / renaming bumps this; loads that see
/// a different version refuse rather than migrate.
///
/// Version history:
/// - `1` — initial shape; carried three never-wired wallet2-lineage
///   fields (`scan_completed`, `confirmations_required`, `trusted_daemon`).
/// - `2` — those three fields deleted (SA-4 dead persisted-field sweep,
///   rule-15 / rule-60): each had no production writer, no reader, and a
///   docstring asserting a consumer that did not exist. Reopen criteria
///   are per-field (a real restoring-progress UX, a confirmation-count
///   preference surface, and a network-posture trust gate, respectively).
pub const SYNC_STATE_BLOCK_VERSION: u32 = 2;

/// The sync-state block. See module docs for scope, versioning, and
/// design rationale.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct SyncStateBlock {
    /// Per-block schema version. Always [`SYNC_STATE_BLOCK_VERSION`]
    /// on construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Lowest height the scanner is willing to consider for this
    /// wallet. Typically the user-supplied restore height or, for
    /// fresh wallets, the current chain tip at creation time.
    pub restore_from_height: u64,

    /// Optional block-hash anchor pinning the wallet to a specific fork
    /// at creation — the "trust floor" of the staking-canonicity model
    /// (`ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`: below it trusted, above it
    /// exhaustiveness-verified).
    ///
    /// **Reserved — no writer/reader yet.** V3.0 always constructs this
    /// `None` and no code reads it; the fork-pin verification the concept
    /// implies (verify against the daemon on load, refuse on mismatch) is
    /// not built. Kept because it is a named design concept with a pending
    /// newtype migration (`RAW_TYPE_NEWTYPE_MIGRATION.md`), not wallet2
    /// cruft. Wiring the writer/reader is its own change.
    #[serde(default)]
    pub creation_anchor_hash: Option<[u8; 32]>,

    /// Locally-submitted txids that have not yet been observed on-chain.
    /// The orchestrator reconciles this list with the ledger's
    /// `transfers` and the tx-meta block's `scanned_pool_txs` on load.
    #[serde(default)]
    pub pending_tx_hashes: Vec<[u8; 32]>,
}

impl Default for SyncStateBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl SyncStateBlock {
    /// Fresh, empty sync-state block pinned to the current version.
    /// `restore_from_height = 0` marks the wallet as scanning from
    /// genesis until the orchestrator sets a real birthday.
    pub fn empty() -> Self {
        Self {
            block_version: SYNC_STATE_BLOCK_VERSION,
            restore_from_height: 0,
            creation_anchor_hash: None,
            pending_tx_hashes: Vec::new(),
        }
    }

    /// Construct a sync-state block with an explicit restore anchor.
    pub fn new(restore_from_height: u64, creation_anchor_hash: Option<[u8; 32]>) -> Self {
        Self {
            block_version: SYNC_STATE_BLOCK_VERSION,
            restore_from_height,
            creation_anchor_hash,
            pending_tx_hashes: Vec::new(),
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`].
    /// **Refuses a version mismatch before decoding the body**, so a blob
    /// written by another schema version reports its version rather than
    /// surfacing as a codec error (see [`crate::version_gate`]).
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        // Version first, body second — see [`crate::version_gate`]: postcard
        // carries no framing, so a stale blob decoded under the current
        // declaration fails as corruption before any post-decode check can
        // name the version. The gate reads only the leading varint.
        crate::version_gate::gate_leading_version(bytes, "sync_state", SYNC_STATE_BLOCK_VERSION)?;
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so [`WalletLedger`](crate::wallet_ledger::WalletLedger)
    /// can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(
            self.block_version,
            "sync_state",
            SYNC_STATE_BLOCK_VERSION,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn populated() -> SyncStateBlock {
        SyncStateBlock {
            block_version: SYNC_STATE_BLOCK_VERSION,
            restore_from_height: 3_141_592,
            creation_anchor_hash: Some([0xABu8; 32]),
            pending_tx_hashes: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        }
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = SyncStateBlock::empty();
        assert_eq!(b.block_version, SYNC_STATE_BLOCK_VERSION);
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = SyncStateBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_roundtrips_value_equality() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = SyncStateBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_is_byte_stable() {
        let b = populated();
        let bytes1 = b.to_postcard_bytes().expect("serialize1");
        let back = SyncStateBlock::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(bytes1, bytes2, "postcard encoding must be byte-stable");
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut b = SyncStateBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match SyncStateBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "sync_state");
                assert_eq!(file, 999);
                assert_eq!(binary, SYNC_STATE_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        let is_postcard = matches!(
            SyncStateBlock::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }

    proptest! {
        #[test]
        fn populated_block_round_trip_proptest(
            restore in any::<u64>(),
            anchor in any::<Option<[u8; 32]>>(),
            pending in proptest::collection::vec(any::<[u8; 32]>(), 0..6),
        ) {
            let b = SyncStateBlock {
                block_version: SYNC_STATE_BLOCK_VERSION,
                restore_from_height: restore,
                creation_anchor_hash: anchor,
                pending_tx_hashes: pending,
            };
            let bytes = b.to_postcard_bytes().expect("serialize");
            let back = SyncStateBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(&back, &b);
            let bytes2 = back.to_postcard_bytes().expect("serialize2");
            prop_assert_eq!(bytes, bytes2);
        }

        #[test]
        fn any_wrong_version_is_refused(bad in any::<u32>().prop_filter(
            "must differ from current version",
            |v| *v != SYNC_STATE_BLOCK_VERSION,
        )) {
            let mut b = SyncStateBlock::empty();
            b.block_version = bad;
            let bytes = b.to_postcard_bytes().expect("serialize");
            let err = SyncStateBlock::from_postcard_bytes(&bytes).unwrap_err();
            let is_version_err = matches!(
                err,
                WalletLedgerError::UnsupportedBlockVersion { .. }
            );
            prop_assert!(is_version_err, "expected UnsupportedBlockVersion");
        }
    }
}
