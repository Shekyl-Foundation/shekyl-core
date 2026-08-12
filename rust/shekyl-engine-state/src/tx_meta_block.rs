// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction-meta block — per-tx secret keys + notes + short-lived
//! pool-tx observations.
//!
//! Third of four `.wallet`-side ledger blocks (after
//! [`LedgerBlock`](crate::ledger_block::LedgerBlock) and
//! [`BookkeepingBlock`](crate::bookkeeping_block::BookkeepingBlock)). This one
//! holds the "per-transaction side-channel" state:
//!
//! * **Per-tx secret keys** — the ephemeral tx secret scalar the wallet
//!   generated when it *constructed* a tx. Kept so the user can later prove a
//!   payment to a third party without re-deriving from the seed.
//! * **User notes** — free-text notes the user attached to specific txids.
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

/// Schema version of the tx-meta block. V3.0 ships version `3`.
/// Any field addition / removal / renaming inside the block bumps this;
/// loads that see a different version refuse rather than migrate.
///
/// Version history:
/// - `1` — initial shape; `TxSecretKeys` carried a per-output
///   `additional: Vec<TxSecretKey>`.
/// - `2` — `TxSecretKeys.additional` deleted (WI-RPC-3 pre-commit,
///   rule-15 dead-store removal): Shekyl's tx construction uses a
///   single tx secret scalar for every output including change
///   (`sign_bridge::sign_tx`), it has no subaddresses, and the field
///   had no producer whole-tree.
/// - `3` — `attributes` deleted (SA-4 dead persisted-field sweep,
///   executing the P3-5 ruling `WALLET_SEND_RECORD.md`): the untyped
///   `String -> String` wallet2-lineage bag had no writer, no reader,
///   and no defined semantics (rules 60/81). Reopen criterion: a named,
///   typed UX-state need that `tx_notes` cannot carry.
pub const TX_META_BLOCK_VERSION: u32 = 3;

/// Maximum length of **one** note, in UTF-8 bytes (SJ-DQ-7).
///
/// A note is persisted, rescan-preserved, schema-versioned state, so an
/// unbounded one is a storage-amplification vector. 4 KiB is generous for a
/// human note and small on disk.
///
/// **Enforced structurally**: the `tx_notes` map is private and
/// [`TxMetaBlock::set_note`] is its only insertion door, so every caller —
/// RPC, CLI, tests, and any future writer — passes this bound rather than
/// agreeing to. Boundaries may pre-check with this constant to fail before
/// taking a write lock, but they are not the enforcement.
///
/// **What this does not bound: the number of notes.** Entry count is not
/// capped here, deliberately and for the same reason `scanned_pool_txs` is
/// not (see the module docs): a count policy belongs to the orchestrator that
/// knows the wallet's transaction population, not to the persistence layer
/// that round-trips it, and no cap that would refuse a user's next annotation
/// has a derivation anyone can defend. The outer ceiling is real but
/// structural rather than note-specific — `shekyl-engine-file`'s
/// `PAYLOAD_BODY_MAX` refuses an over-large wallet payload on the *write*
/// path, so the map cannot grow the file without limit.
pub const TX_NOTE_MAX_BYTES: usize = 4 * 1024;

/// Refusal when a note exceeds [`TX_NOTE_MAX_BYTES`].
///
/// Carries **byte counts only** — never the note text — so counterparty-
/// bearing free text cannot escape through an error string (rules 35/36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("note exceeds the {max}-byte maximum ({len} bytes)")]
pub struct TxNoteTooLong {
    /// Observed UTF-8 byte length of the refused note.
    pub len: usize,
    /// Ceiling that was exceeded ([`TX_NOTE_MAX_BYTES`]).
    pub max: usize,
}

/// Enforce [`TX_NOTE_MAX_BYTES`] on a candidate note — the **single owner** of
/// the ceiling check.
///
/// [`TxMetaBlock::set_note`] calls it on the write path; a boundary (e.g. the
/// wallet-RPC handler) may also call it to fast-fail an over-length request
/// before doing work, but the comparison, the ceiling, and the refusal all
/// live here, so an early refusal can never differ from the write-door one.
/// Reports byte counts only — never the note content (rules 35/36).
///
/// # Errors
///
/// [`TxNoteTooLong`] when `note` exceeds [`TX_NOTE_MAX_BYTES`].
pub fn check_tx_note_len(note: &str) -> Result<(), TxNoteTooLong> {
    if note.len() > TX_NOTE_MAX_BYTES {
        return Err(TxNoteTooLong {
            len: note.len(),
            max: TX_NOTE_MAX_BYTES,
        });
    }
    Ok(())
}

/// The pre-write note value captured by [`TxMetaBlock::set_note`] and consumed
/// by [`TxMetaBlock::restore_note`] to undo a write after a failed durable
/// save (fail closed).
///
/// Its inner value is **private**, so the only way to obtain one is from
/// `set_note`. A caller cannot mint a `PriorNote` from an arbitrary string —
/// which is what keeps the restore path from re-admitting an unbounded note
/// the write door refused: restore only ever puts back a value that was
/// already in the map (hence already validated), never a fresh one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorNote(Option<String>);

/// Result of [`TxMetaBlock::set_note`]: whether the map changed (and thus
/// needs a durable save) or the write is already a no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetTxNoteOutcome {
    /// Map entry changed. `previous` is the pre-write value (an opaque
    /// [`PriorNote`], for fail-closed rollback via [`TxMetaBlock::restore_note`]);
    /// `stored` is the post-write value (`None` when cleared).
    Applied {
        /// Entry present before this write, if any — opaque, feed it straight
        /// to [`TxMetaBlock::restore_note`].
        previous: PriorNote,
        /// Entry present after this write (`None` when the note was cleared).
        stored: Option<String>,
    },
    /// Map already matched the requested state (clear of absent, or set of
    /// an identical string). No durable save is required.
    Unchanged {
        /// Authoritative post-write state (`None` when no note is set).
        stored: Option<String>,
    },
}

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

// ── `postcard-schema` support (see transfer.rs for the broader design). ──
//
// `#[serde(with = "zeroizing_bytes_32")]` makes the wire `NewtypeStruct(
// length-prefixed-bytes)`; postcard-schema's derive cannot see through
// `serde(with)`, so we delegate via a mirror newtype whose field is
// `Vec<u8>` (wire-identical to what `zeroizing_bytes_32` emits). The outer
// name is restored to `TxSecretKey` so the snapshot matches the public API.
#[derive(postcard_schema::Schema)]
#[allow(dead_code)]
struct TxSecretKeySchema(Vec<u8>);

impl postcard_schema::Schema for TxSecretKey {
    const SCHEMA: &'static postcard_schema::schema::NamedType =
        &postcard_schema::schema::NamedType {
            name: "TxSecretKey",
            ty: <TxSecretKeySchema as postcard_schema::Schema>::SCHEMA.ty,
        };
}

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

/// Per-txid secret keys: the single tx secret scalar the wallet generated
/// when it constructed the transaction.
///
/// Shekyl's tx construction uses **one** scalar per transaction for every
/// output including change (`sign_bridge::sign_tx` mints one
/// `tx_key_secret` and derives every output from it); Shekyl has no
/// subaddresses, so the wallet2-era per-output `additional` keys are
/// unrepresentable by design (deleted at `TX_META_BLOCK_VERSION` 2). The
/// struct wrapper is retained rather than flattened to a bare
/// [`TxSecretKey`] map value so a future additive field (e.g. a
/// retention-policy timestamp) is a version bump, not a map-shape change.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct TxSecretKeys {
    /// Primary tx secret key — always present.
    pub primary: TxSecretKey,
}

/// One observed pool (mempool) transaction. Short-lived state; the
/// orchestrator is responsible for pruning.
///
/// Does NOT carry the tx payload — the scanner has already processed it and
/// emitted any relevant `TransferDetails` into the `LedgerBlock`. This
/// record exists so that a restart restores the user-visible "pending"
/// state without having to re-scan the pool from scratch.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct TxMetaBlock {
    /// Per-block schema version. Always [`TX_META_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Per-txid secret keys (one primary scalar per tx).
    #[serde(default = "BTreeMap::new")]
    pub tx_keys: BTreeMap<[u8; 32], TxSecretKeys>,

    /// User-authored free-text notes, keyed by txid.
    ///
    /// **Private on purpose.** [`TX_NOTE_MAX_BYTES`] is enforced on every path
    /// that *authors* a note: [`Self::set_note`] is the only write door and
    /// refuses an over-length note (via [`check_tx_note_len`]), and
    /// [`Self::restore_note`] consumes only an opaque [`PriorNote`] that
    /// `set_note` already validated — so no in-memory API can insert an
    /// over-length note. [`Self::notes`] / [`Self::note`] are the only doors
    /// out.
    ///
    /// **`Deserialize` is deliberately not re-validated.** The sealed on-disk
    /// form is trusted input: the AEAD envelope authenticates it and this
    /// wallet only ever wrote it through `set_note`, so `Deserialize`
    /// *restores* prior values rather than admitting new ones. Validating on
    /// load would defend against a file this wallet cannot produce (an
    /// over-length note in a validly-sealed block) and would pay for it by
    /// making a wallet **unopenable** — the wrong trade for the one file that
    /// holds a user's seed-adjacent state. Declined by design, not overlooked.
    #[serde(default = "BTreeMap::new")]
    tx_notes: BTreeMap<[u8; 32], String>,

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
            scanned_pool_txs: BTreeMap::new(),
        }
    }

    /// Construct a tx-meta block from its component maps at the current
    /// version. Convenience for tests and the orchestrator's build path.
    ///
    /// Takes no notes map: notes are bounded state and enter only through
    /// [`Self::set_note`], so there is no constructor that can seed the block
    /// past [`TX_NOTE_MAX_BYTES`]. Callers that want notes set them after
    /// construction.
    pub fn new(
        tx_keys: BTreeMap<[u8; 32], TxSecretKeys>,
        scanned_pool_txs: BTreeMap<[u8; 32], ScannedPoolTx>,
    ) -> Self {
        Self {
            block_version: TX_META_BLOCK_VERSION,
            tx_keys,
            tx_notes: BTreeMap::new(),
            scanned_pool_txs,
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
        crate::version_gate::gate_leading_version(bytes, "tx_meta", TX_META_BLOCK_VERSION)?;
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so the `WalletLedger` aggregator (commit 2g) can
    /// fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(self.block_version, "tx_meta", TX_META_BLOCK_VERSION)
    }

    /// Read the user-authored note for `txid`, if any.
    #[must_use]
    pub fn note(&self, txid: &[u8; 32]) -> Option<&str> {
        self.tx_notes.get(txid).map(String::as_str)
    }

    /// The whole note map, read-only — for projections that annotate a batch
    /// of rows and would otherwise pay a lookup call per row.
    ///
    /// Shared immutably: reading notes is unrestricted, writing them is not —
    /// the map itself is private and [`Self::set_note`] is the only door in.
    #[must_use]
    pub fn notes(&self) -> &BTreeMap<[u8; 32], String> {
        &self.tx_notes
    }

    /// Set or clear the note for `txid`.
    ///
    /// - Empty `note` removes any entry (no separate delete method).
    /// - Non-empty `note` inserts or replaces; length is capped at
    ///   [`TX_NOTE_MAX_BYTES`] UTF-8 bytes.
    /// - Identical set / clear-of-absent returns
    ///   [`SetTxNoteOutcome::Unchanged`] so the caller can skip a durable
    ///   save (same discipline as abandon's already-abandoned short-circuit).
    ///
    /// # Errors
    ///
    /// [`TxNoteTooLong`] when `note` exceeds the byte ceiling. The error
    /// reports counts only — never the note content.
    pub fn set_note(
        &mut self,
        txid: [u8; 32],
        note: String,
    ) -> Result<SetTxNoteOutcome, TxNoteTooLong> {
        if note.is_empty() {
            return Ok(match self.tx_notes.remove(&txid) {
                None => SetTxNoteOutcome::Unchanged { stored: None },
                Some(previous) => SetTxNoteOutcome::Applied {
                    previous: PriorNote(Some(previous)),
                    stored: None,
                },
            });
        }

        check_tx_note_len(&note)?;

        if self.tx_notes.get(&txid).is_some_and(|cur| cur == &note) {
            return Ok(SetTxNoteOutcome::Unchanged { stored: Some(note) });
        }

        let previous = self.tx_notes.insert(txid, note.clone());
        Ok(SetTxNoteOutcome::Applied {
            previous: PriorNote(previous),
            stored: Some(note),
        })
    }

    /// Restore a prior note entry after a failed durable save (fail closed).
    ///
    /// `previous` is the opaque [`PriorNote`] from [`Self::set_note`]'s
    /// [`SetTxNoteOutcome::Applied`] arm — a previously-validated value, so the
    /// restore cannot re-admit an over-length note. Its `Some` re-inserts, its
    /// `None` removes.
    pub fn restore_note(&mut self, txid: [u8; 32], previous: PriorNote) {
        match previous.0 {
            Some(prior) => {
                self.tx_notes.insert(txid, prior);
            }
            None => {
                self.tx_notes.remove(&txid);
            }
        }
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
            },
        );
        tx_keys.insert(
            key(0x02, 0),
            TxSecretKeys {
                primary: secret(0x21),
            },
        );

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

        let mut block = TxMetaBlock::new(tx_keys, scanned_pool_txs);
        // Notes enter only through the bounded door.
        block
            .set_note(key(0x01, 0), "rent".into())
            .expect("in-bound note");
        block
            .set_note(key(0x03, 0), "alice".into())
            .expect("in-bound note");
        block
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
    fn set_note_set_clear_and_noop() {
        let mut b = TxMetaBlock::empty();
        let id = key(0x10, 0);

        // Clear of absent is a no-op.
        assert_eq!(
            b.set_note(id, String::new()).expect("clear-absent"),
            SetTxNoteOutcome::Unchanged { stored: None }
        );
        assert!(b.note(&id).is_none());

        // Set applies.
        match b.set_note(id, "rent".into()).expect("set") {
            SetTxNoteOutcome::Applied {
                previous: PriorNote(None),
                stored: Some(s),
            } => assert_eq!(s, "rent"),
            other => panic!("expected Applied first set, got {other:?}"),
        }
        assert_eq!(b.note(&id), Some("rent"));

        // Identical set is Unchanged (no dirty write).
        assert_eq!(
            b.set_note(id, "rent".into()).expect("identical"),
            SetTxNoteOutcome::Unchanged {
                stored: Some("rent".into())
            }
        );

        // Overwrite applies with previous.
        match b.set_note(id, "rent — March".into()).expect("overwrite") {
            SetTxNoteOutcome::Applied {
                previous: PriorNote(Some(p)),
                stored: Some(s),
            } => {
                assert_eq!(p, "rent");
                assert_eq!(s, "rent — March");
            }
            other => panic!("expected Applied overwrite, got {other:?}"),
        }

        // Clear applies and restores via restore_note — the opaque `PriorNote`
        // token round-trips straight back through the restore door.
        let outcome = b.set_note(id, String::new()).expect("clear");
        match &outcome {
            SetTxNoteOutcome::Applied {
                previous: PriorNote(Some(p)),
                stored: None,
            } => assert_eq!(p, "rent — March"),
            other => panic!("expected Applied clear, got {other:?}"),
        }
        if let SetTxNoteOutcome::Applied { previous, .. } = outcome {
            b.restore_note(id, previous);
        }
        assert_eq!(b.note(&id), Some("rent — March"));
    }

    #[test]
    fn set_note_refuses_over_length_without_mutating() {
        let mut b = TxMetaBlock::empty();
        let id = key(0x11, 0);
        b.set_note(id, "keep".into()).expect("seed");

        let over = "x".repeat(TX_NOTE_MAX_BYTES + 1);
        let err = b.set_note(id, over).expect_err("over-length must refuse");
        assert_eq!(err.max, TX_NOTE_MAX_BYTES);
        assert_eq!(err.len, TX_NOTE_MAX_BYTES + 1);
        // Map unchanged; error Display carries counts only.
        assert_eq!(b.note(&id), Some("keep"));
        let msg = err.to_string();
        assert!(msg.contains("maximum"), "{msg}");
        assert!(!msg.contains("xxxxx"), "refusal must not echo note body");
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
        // Arbitrary tx_notes + scanned_pool_txs sizes.
        // We deliberately keep tx_keys out of the proptest: TxSecretKey
        // has no Clone, which makes generic `Strategy` composition
        // awkward, and leaf-level coverage already lives in
        // `tx_secret_key_roundtrips_via_postcard`.
        #[test]
        fn populated_block_round_trip_proptest(
            // 1.. characters, not 0..: the empty string is not a storable
            // note — `set_note("")` is the clear operation — so generating one
            // would assert a round-trip the type deliberately does not offer.
            notes in proptest::collection::btree_map(
                any::<[u8; 32]>(),
                "[a-zA-Z0-9 ]{1,32}",
                0..8,
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
            let mut b = TxMetaBlock::new(BTreeMap::new(), scanned_pool_txs);
            for (txid, note) in notes {
                b.set_note(txid, note).expect("generated notes are in bound");
            }
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
