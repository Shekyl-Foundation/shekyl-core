// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `set_tx_note` — the wallet-local transaction annotation surface (SJ-DQ-7).
//!
//! A note is free-text the user attaches to a specific txid, persisted in
//! [`TxMetaBlock::tx_notes`](shekyl_engine_state::TxMetaBlock) and surfaced on
//! the transfer views the RPC returns. It is purely local UX state — no
//! consensus meaning, never on the wire, and keyed by the bare txid so it
//! annotates the *transaction*, not a single output row (a self-send's
//! incoming-change and outgoing rows share the one note).
//!
//! The write is crash-atomic under a single ledger write guard, the same
//! discipline as `abandon_tx_persisted`: mutate the map via
//! [`TxMetaBlock::set_note`], save, and on save failure restore the prior
//! entry (fail closed) so a retry starts from the pre-write state.
//! `WalletFile::save_state` writes via `atomic_write_file` (temp → fsync →
//! `rename(2)` → parent fsync), so a failed save leaves the on-disk state
//! byte-unchanged — the rollback's precondition holds. An empty note
//! **clears** the entry rather than storing an empty string, so there is no
//! separate delete method.
//!
//! No-ops (clear of an absent note, or set of an already-identical string)
//! short-circuit without a durable save — matching abandon's
//! already-abandoned path.
//!
//! # Secret disposition (stated, not assumed)
//!
//! A note is counterparty-bearing free text but **not** secret-class: it is
//! stored as a plain `String` in a `BTreeMap`, so it does not zeroize —
//! exactly like the send-journal's recipient addresses (`SendRecipient`),
//! which are the same not-a-key, disclosure-if-dumped class. In-memory
//! disclosure of a note is an **accepted residual**; the protection is the
//! AEAD wallet envelope at rest plus boundary discipline in transit (never
//! on the wire, never in a log or error string — rules 35/36).
//!
//! # Size bound
//!
//! [`shekyl_engine_state::TX_NOTE_MAX_BYTES`] is enforced on the write path
//! inside [`TxMetaBlock::set_note`]. Callers may pre-check the same constant
//! (e.g. RPC before taking a lock) but that is a fast-fail, not the sole
//! invariant.

use shekyl_engine_state::{SetTxNoteOutcome, TxNoteTooLong};
use shekyl_types::TxHash;

use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::traits::{DaemonEngine, PendingTxEngine, PersistenceEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

/// Failures from [`Engine::set_tx_note`].
#[derive(Debug, thiserror::Error)]
pub enum SetTxNoteError {
    /// Note exceeds [`shekyl_engine_state::TX_NOTE_MAX_BYTES`].
    ///
    /// Display reports **byte counts only** — never the note text.
    #[error(transparent)]
    TooLong(#[from] TxNoteTooLong),

    /// Durable save failed; the in-memory map entry was rolled back
    /// (fail closed).
    #[error("set_tx_note persistence failed: {0}")]
    Persistence(#[from] PersistenceError),
}

// Generic over `F: PersistenceEngine` so the durable save drives the normal
// crash-atomic ledger path — the same widening `abandon_tx.rs` /
// `payment_requests.rs` use. `WalletFile` satisfies the bound, so every
// existing caller is unaffected.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, LocalLedger, E, R, P, F>
{
    /// Set (or clear) the user's note for `txid` **and durably commit it**.
    ///
    /// An empty `note` removes any existing entry; a non-empty `note`
    /// inserts or replaces it (capped at
    /// [`shekyl_engine_state::TX_NOTE_MAX_BYTES`]). Returns the note as
    /// stored after the write (`None` when cleared). The mutation and the
    /// crash-atomic save run under one ledger write guard so a concurrent
    /// refresh/watchdog cannot interleave. Idempotent no-ops skip the
    /// durable save.
    ///
    /// # Errors
    ///
    /// - [`SetTxNoteError::TooLong`] — note exceeds the byte ceiling; map
    ///   unchanged.
    /// - [`SetTxNoteError::Persistence`] — durable save failed; the
    ///   in-memory map entry is rolled back to its pre-write value (fail
    ///   closed), so a retry starts from the prior state.
    pub fn set_tx_note(
        &self,
        txid: TxHash,
        note: String,
    ) -> Result<Option<String>, SetTxNoteError> {
        let key = txid.to_bytes();

        // One write guard for the map mutation + save (+ optional rollback);
        // `save_state` takes `&WalletLedger`, so no second lock is needed and
        // concurrent merge/watchdog block until we finish.
        let mut guard = self.ledger.write();
        let outcome = guard.ledger.tx_meta.set_note(key, note)?;

        match outcome {
            SetTxNoteOutcome::Unchanged { stored } => Ok(stored),
            SetTxNoteOutcome::Applied { previous, stored } => {
                let save_result = drive_persistence(
                    self.persistence
                        .save_state(self.state_wrap_key(), &guard.ledger),
                );
                if let Err(e) = save_result {
                    // Fail closed under the same exclusive guard.
                    guard.ledger.tx_meta.restore_note(key, previous);
                    return Err(SetTxNoteError::Persistence(e.into()));
                }
                Ok(stored)
            }
        }
    }

    /// Read the user's note for `txid`, if any. Pure read — no persistence.
    #[must_use]
    pub fn tx_note(&self, txid: TxHash) -> Option<String> {
        self.ledger
            .read()
            .ledger
            .tx_meta
            .note(&txid.to_bytes())
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_engine_state::TX_NOTE_MAX_BYTES;
    use shekyl_rpc_transport::HttpRpc;
    use shekyl_types::TxHash;

    use super::super::lifecycle::EngineCreateParams;
    use super::super::{Credentials, DaemonClient, Engine, SoloSigner};
    use super::SetTxNoteError;

    /// A `DaemonClient` over an unreachable URL — setting a note is a local,
    /// crash-atomic operation with no daemon I/O on any path under test.
    async fn daemon() -> DaemonClient {
        let rpc = HttpRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct HttpRpc against unreachable URL");
        DaemonClient::new(rpc)
    }

    fn seed(mul: u8) -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(mul);
        }
        s
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_read_and_clear_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"set_tx_note tests");
        let s = seed(7);
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &s);
        let engine = Engine::<SoloSigner>::create(params, daemon().await).expect("create");
        let txid = TxHash::from_bytes([0x11; 32]);

        // Absent by default.
        assert_eq!(engine.tx_note(txid), None);

        // Set → readable, and the write echoes the stored value.
        let stored = engine.set_tx_note(txid, "rent".to_owned()).expect("set");
        assert_eq!(stored.as_deref(), Some("rent"));
        assert_eq!(engine.tx_note(txid).as_deref(), Some("rent"));

        // Overwrite replaces.
        let stored = engine
            .set_tx_note(txid, "rent — March".to_owned())
            .expect("overwrite");
        assert_eq!(stored.as_deref(), Some("rent — March"));

        // Empty note clears (no separate delete method).
        let cleared = engine.set_tx_note(txid, String::new()).expect("clear");
        assert_eq!(cleared, None);
        assert_eq!(engine.tx_note(txid), None);

        // Clearing an already-absent note is a no-op that still succeeds
        // without requiring a dirty write (Unchanged short-circuit).
        let again = engine
            .set_tx_note(txid, String::new())
            .expect("clear-absent");
        assert_eq!(again, None);

        // Identical re-set is a no-op.
        engine
            .set_tx_note(txid, "same".to_owned())
            .expect("set same");
        let again = engine
            .set_tx_note(txid, "same".to_owned())
            .expect("identical set");
        assert_eq!(again.as_deref(), Some("same"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn over_length_note_is_refused_without_echo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"set_tx_note too long");
        let s = seed(3);
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &s);
        let engine = Engine::<SoloSigner>::create(params, daemon().await).expect("create");
        let txid = TxHash::from_bytes([0x33; 32]);

        let over = format!("CANARY{}", "x".repeat(TX_NOTE_MAX_BYTES));
        match engine
            .set_tx_note(txid, over)
            .expect_err("over-length must refuse")
        {
            SetTxNoteError::TooLong(e) => {
                assert_eq!(e.max, TX_NOTE_MAX_BYTES);
                let msg = e.to_string();
                assert!(
                    !msg.contains("CANARY"),
                    "refusal must not echo note content: {msg}"
                );
            }
            other => panic!("expected TooLong, got {other:?}"),
        }
        assert_eq!(engine.tx_note(txid), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn note_survives_a_reopen() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"set_tx_note reopen");
        let s = seed(13);
        let txid = TxHash::from_bytes([0x22; 32]);

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &s);
        let network = params.network;
        let engine = Engine::<SoloSigner>::create(params, daemon().await).expect("create");
        engine.set_tx_note(txid, "keep me".to_owned()).expect("set");
        // Release the advisory lock before reopening.
        engine.close(&creds).expect("close");

        // Reopen the same wallet files: the note is durable state.
        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            daemon().await,
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        let reopened = opened.into_wallet();
        assert_eq!(reopened.tx_note(txid).as_deref(), Some("keep me"));
    }
}
