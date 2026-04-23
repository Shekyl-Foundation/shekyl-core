// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction-meta block — per-tx secret keys + notes + free-form attributes
//! + short-lived pool-tx observations.
//!
//! Third of four `.wallet`-side ledger blocks (after
//! [`LedgerBlock`](crate::ledger_block::LedgerBlock) and
//! [`BookkeepingBlock`](crate::bookkeeping_block::BookkeepingBlock)). This one
//! holds the "per-transaction side-channel" state:
//!
//! * **Per-tx secret keys** — the ephemeral tx secret scalar(s) the wallet
//!   generated when it *constructed* a tx. Kept so the user can later prove a
//!   payment to a third party without re-deriving from the seed.
//! * **User notes** — free-text notes the user attached to specific txids.
//! * **Attributes** — opaque `String -> String` key/value pairs used as a
//!   forward-compatible extension point for UX settings that the wallet
//!   wants to persist but has no dedicated field for yet.
//! * **Scanned pool transactions** — the live mempool observations the
//!   scanner has made. Short-lived by nature but persisted across runs so
//!   that a restart does not lose the "pending" state the user sees.
//!
//! # Wire format
//!
//! Postcard-serialized. Every map is a `BTreeMap` (not `HashMap`) so repeat
//! serialization of the same logical value produces the same bytes —
//! required for the byte-stability tests and any future "skip fsync if
//! unchanged" optimization.
//!
//! # Secret handling
//!
//! Tx secret keys are 32-byte canonical scalars that must never leak. They
//! are wrapped in [`TxSecretKey`], which holds a [`Zeroizing<[u8; 32]>`] and
//! serializes via the airtight [`zeroizing_bytes_32`] helper — deserialization
//! never leaves a copy of the scalar in un-zeroed heap memory. The wrapper
//! implements a redacted [`fmt::Debug`] (`"TxSecretKey(<redacted>)"`) so an
//! accidental `{:?}` on a `TxMetaBlock` does not spill the scalar to logs.
//!
//! # Follow-up: bounded `scanned_pool_txs`
//!
//! `scanned_pool_txs` is currently unbounded by this module — the map grows
//! with every distinct mempool tx the wallet has ever observed. The agreed
//! policy (filed with the user's pushback on `shekyl-scanner`'s transient
//! pool set) is that the orchestrator prunes this map on load and on write
//! using the tx's `first_seen_unix_secs` and a TTL. The persistence layer
//! just round-trips whatever the orchestrator hands it; the pruning policy
//! itself lands in a later commit (tracked as follow-up in the 2f plan
//! entry).
//!
//! [`zeroizing_bytes_32`]: crate::serde_helpers::zeroizing_bytes_32

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{error::WalletLedgerError, serde_helpers::zeroizing_bytes_32};

/// Schema version of the tx-meta block. V3.0 ships version `1`.
/// Any field addition / removal / renaming inside the block bumps this;
/// loads that see a different version refuse rather than migrate.
pub const TX_META_BLOCK_VERSION: u32 = 1;

/// A single 32-byte tx secret scalar, wrapped so both its in-memory
/// representation and its deserialization path zeroize on drop.
///
/// The wrapper deliberately does **not** implement [`Clone`] — duplicating
/// a secret into a second heap cell is a secret-handling anti-pattern, and
/// every caller that legitimately needs two copies can re-serialize. It
/// also implements a redacted [`fmt::Debug`] so logs and panic messages
/// never contain the raw scalar.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct TxSecretKey(#[serde(with = "zeroizing_bytes_32")] pub Zeroizing<[u8; 32]>);

impl TxSecretKey {
    /// Construct from a freshly-allocated `Zeroizing` buffer.
    pub fn new(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes. Callers must treat the returned slice as a
    /// secret and avoid copying it into non-zeroizing containers.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TxSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxSecretKey(<redacted>)")
    }
}

impl Zeroize for TxSecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Per-txid secret keys: the primary tx secret scalar plus any additional
/// per-output scalars that were emitted in the same transaction.
///
/// Shekyl's tx construction occasionally needs more than one scalar per tx
/// (e.g. a tx with multiple outputs destined to different subaddresses
/// derives a dedicated per-output key for each). The shape mirrors that
/// invariant: one required `primary`, zero or more `additional`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxSecretKeys {
    /// Primary tx secret key — always present.
    pub primary: TxSecretKey,

    /// Per-output additional tx secret keys, in the same order they were
    /// emitted at tx-construction time. Empty for the common single-output
    /// case.
    #[serde(default)]
    pub additional: Vec<TxSecretKey>,
}

/// One observed pool (mempool) transaction. Short-lived state; the
/// orchestrator is responsible for pruning.
///
/// Does NOT carry the tx payload — the scanner has already processed it and
/// emitted any relevant `TransferDetails` into the `LedgerBlock`. This
/// record exists so that a restart restores the user-visible "pending"
/// state without having to re-scan the pool from scratch.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannedPoolTx {
    /// Unix timestamp (seconds) when the wallet first saw this tx in the
    /// pool. Used by the orchestrator's pruning policy (TTL-based) and by
    /// the UX to display "pending for N minutes".
    pub first_seen_unix_secs: u64,

    /// True if the scanner has subsequently observed a conflicting
    /// confirmed tx (same key image). Lets the UX warn the user that a
    /// previously-pending tx will never confirm.
    pub double_spend_seen: bool,
}

/// The tx-meta block. See module docs for scope, versioning, and design
/// rationale.
///
/// Deliberately NOT [`Clone`] at the block level because [`TxSecretKey`]
/// refuses to be cloned. Callers that need a snapshot should re-serialize.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxMetaBlock {
    /// Per-block schema version. Always [`TX_META_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Per-txid secret keys (primary + optional per-output additional).
    #[serde(default = "BTreeMap::new")]
    pub tx_keys: BTreeMap<[u8; 32], TxSecretKeys>,

    /// User-authored free-text notes, keyed by txid.
    #[serde(default = "BTreeMap::new")]
    pub tx_notes: BTreeMap<[u8; 32], String>,

    /// Opaque `String -> String` attribute bag for forward-compatible UX
    /// state. Wallet2 used an `unordered_map<string, string>`; we keep the
    /// functional surface but insist on `BTreeMap` for byte stability.
    #[serde(default = "BTreeMap::new")]
    pub attributes: BTreeMap<String, String>,

    /// Scanner-observed mempool transactions. Bounded externally by the
    /// orchestrator's pruning policy (see module-level follow-up).
    #[serde(default = "BTreeMap::new")]
    pub scanned_pool_txs: BTreeMap<[u8; 32], ScannedPoolTx>,
}

impl Default for TxMetaBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl TxMetaBlock {
    /// Construct a fresh, empty tx-meta block at the current version.
    pub fn empty() -> Self {
        Self {
            block_version: TX_META_BLOCK_VERSION,
            tx_keys: BTreeMap::new(),
            tx_notes: BTreeMap::new(),
            attributes: BTreeMap::new(),
            scanned_pool_txs: BTreeMap::new(),
        }
    }

    /// Construct a tx-meta block from its component maps at the current
    /// version. Convenience for tests and the orchestrator's build path.
    pub fn new(
        tx_keys: BTreeMap<[u8; 32], TxSecretKeys>,
        tx_notes: BTreeMap<[u8; 32], String>,
        attributes: BTreeMap<String, String>,
        scanned_pool_txs: BTreeMap<[u8; 32], ScannedPoolTx>,
    ) -> Self {
        Self {
            block_version: TX_META_BLOCK_VERSION,
            tx_keys,
            tx_notes,
            attributes,
            scanned_pool_txs,
        }
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. Refuses any version mismatch.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so the `WalletLedger` aggregator (commit 2g) can
    /// fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.block_version != TX_META_BLOCK_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "tx_meta",
                file: self.block_version,
                binary: TX_META_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(a: u8, b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = a;
        k[1] = b;
        k
    }

    fn secret(a: u8) -> TxSecretKey {
        let mut bytes = [0u8; 32];
        bytes[0] = a;
        bytes[31] = a ^ 0xAA;
        TxSecretKey::new(Zeroizing::new(bytes))
    }

    fn populated() -> TxMetaBlock {
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            key(0x01, 0),
            TxSecretKeys {
                primary: secret(0x11),
                additional: vec![secret(0x12), secret(0x13)],
            },
        );
        tx_keys.insert(
            key(0x02, 0),
            TxSecretKeys {
                primary: secret(0x21),
                additional: Vec::new(),
            },
        );

        let mut tx_notes = BTreeMap::new();
        tx_notes.insert(key(0x01, 0), "rent".into());
        tx_notes.insert(key(0x03, 0), "alice".into());

        let mut attributes = BTreeMap::new();
        attributes.insert("display.fiat".into(), "USD".into());
        attributes.insert("display.theme".into(), "dark".into());

        let mut scanned_pool_txs = BTreeMap::new();
        scanned_pool_txs.insert(
            key(0x04, 0),
            ScannedPoolTx {
                first_seen_unix_secs: 1_700_000_000,
                double_spend_seen: false,
            },
        );
        scanned_pool_txs.insert(
            key(0x05, 0),
            ScannedPoolTx {
                first_seen_unix_secs: 1_700_000_500,
                double_spend_seen: true,
            },
        );

        TxMetaBlock::new(tx_keys, tx_notes, attributes, scanned_pool_txs)
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = TxMetaBlock::empty();
        assert_eq!(b.block_version, TX_META_BLOCK_VERSION);
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = TxMetaBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_roundtrips_value_equality() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = TxMetaBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_is_byte_stable() {
        let b = populated();
        let bytes1 = b.to_postcard_bytes().expect("serialize1");
        let back = TxMetaBlock::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(bytes1, bytes2, "postcard encoding must be byte-stable");
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut b = TxMetaBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match TxMetaBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "tx_meta");
                assert_eq!(file, 999);
                assert_eq!(binary, TX_META_BLOCK_VERSION);
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
            TxMetaBlock::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }

    #[test]
    fn tx_secret_key_debug_redacts_bytes() {
        // Defense-in-depth: an accidental `{:?}` on a TxMetaBlock must not
        // dump the raw scalar. This checks the Debug impl produces the
        // redacted marker and NOT any byte from the key.
        let sk = secret(0xFF);
        let rendered = format!("{sk:?}");
        assert_eq!(rendered, "TxSecretKey(<redacted>)");
    }

    #[test]
    fn tx_secret_key_roundtrips_via_postcard() {
        // Sanity check at the leaf level that a lone TxSecretKey makes it
        // through the airtight zeroizing helper intact.
        let sk = secret(0x77);
        let bytes = postcard::to_allocvec(&sk).expect("serialize");
        let back: TxSecretKey = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(sk.as_bytes(), back.as_bytes());
    }

    proptest! {
        // Arbitrary tx_notes + attributes + scanned_pool_txs sizes.
        // We deliberately keep tx_keys out of the proptest: TxSecretKey
        // has no Clone, which makes generic `Strategy` composition
        // awkward, and leaf-level coverage already lives in
        // `tx_secret_key_roundtrips_via_postcard`.
        #[test]
        fn populated_block_round_trip_proptest(
            notes in proptest::collection::btree_map(
                any::<[u8; 32]>(),
                "[a-zA-Z0-9 ]{0,32}",
                0..8,
            ),
            attrs in proptest::collection::btree_map(
                "[a-z.]{1,16}",
                "[a-z0-9 ]{0,16}",
                0..6,
            ),
            pool in proptest::collection::btree_map(
                any::<[u8; 32]>(),
                (any::<u64>(), any::<bool>()),
                0..6,
            ),
        ) {
            let scanned_pool_txs: BTreeMap<[u8; 32], ScannedPoolTx> = pool
                .into_iter()
                .map(|(k, (secs, dsp))| {
                    (
                        k,
                        ScannedPoolTx {
                            first_seen_unix_secs: secs,
                            double_spend_seen: dsp,
                        },
                    )
                })
                .collect();
            let b = TxMetaBlock::new(BTreeMap::new(), notes, attrs, scanned_pool_txs);
            let bytes = b.to_postcard_bytes().expect("serialize");
            let back = TxMetaBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(&back, &b);
            let bytes2 = back.to_postcard_bytes().expect("serialize2");
            prop_assert_eq!(bytes, bytes2);
        }

        #[test]
        fn any_wrong_version_is_refused(bad in any::<u32>().prop_filter(
            "must differ from current version",
            |v| *v != TX_META_BLOCK_VERSION,
        )) {
            let mut b = TxMetaBlock::empty();
            b.block_version = bad;
            let bytes = b.to_postcard_bytes().expect("serialize");
            let err = TxMetaBlock::from_postcard_bytes(&bytes).unwrap_err();
            let is_version_err = matches!(
                err,
                WalletLedgerError::UnsupportedBlockVersion { .. }
            );
            prop_assert!(is_version_err, "expected UnsupportedBlockVersion");
        }
    }
}
