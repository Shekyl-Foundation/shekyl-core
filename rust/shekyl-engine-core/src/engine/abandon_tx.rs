// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `abandon_tx` — the user-authored abandon of a dispatched send
//! (`docs/design/WALLET_SEND_RECORD.md` P3-4 / SJ-DQ-8, PR-SJ-3).
//!
//! The operation is the journal edge `Dispatched | PresumedDead →
//! Abandoned` **plus** the I-2 reference migration: the txid leaves
//! `sync_state.pending_tx_hashes` and the journal row itself becomes the
//! retained tx secret's live reference. Keys are never touched (C2 — the
//! FOLLOWUP's named hazard is deleting proof material for a tx that
//! later confirms), and there is deliberately **no force path** (P3-4:
//! hiding a row early is tier-1 deletion's job; nothing is blocked
//! waiting on an abandon since P3-1 retired the unconfirmed rescan
//! refusal).
//!
//! What abandon does *not* do: release the F14 input locks. An
//! abandoned-but-still-landable send keeps its carried-input locks (and
//! their rescan re-derivation) until the watchdog's confirmed-absent
//! evidence releases them — that is the SJ-DQ-4 self-link defence, and
//! it is evidence-owned, not intent-owned (C3). A late confirmation
//! flips the row `Abandoned → Confirmed` loudly through the merge
//! reconciler rather than staying wrong.
//!
//! # Crash ordering
//!
//! Edge, I-2 migration, and the durable save all run under **one** ledger
//! write guard and persist as a single atomic envelope replace
//! ([`drive_persistence`] → `save_state`). Holding the write across the
//! save is deliberate and differs from the payment-request pattern
//! (mutate → drop write → read-save): abandon is concurrent with refresh
//! merge and the confirmed-absent watchdog, either of which can
//! legitimately advance the same row (`Abandoned → Confirmed`, baseline
//! clear). Releasing the guard before save would let those edges
//! interleave, so a failed-save rollback could clobber a confirm or
//! leave a `Dispatched` row without its locks. Under exclusive write:
//! a crash never splits the edge from the migration, a failed save rolls
//! both back against the pre-abandon shape, and the success outcome
//! matches what was written.

use shekyl_engine_state::{AbandonEdge, SendState};
use shekyl_types::TxHash;

use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::traits::{DaemonEngine, PendingTxEngine, PersistenceEngine, RefreshEngine};
use super::{Engine, EngineSignerKind, LocalLedger};

/// Success outcome of [`Engine::abandon_tx_persisted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbandonTxOutcome {
    /// The row moved to `Abandoned` and the durable save committed.
    Abandoned,
    /// The row was already `Abandoned` — idempotent no-op (SJ-DQ-8);
    /// nothing needed saving.
    AlreadyAbandoned,
}

/// Refusals of [`Engine::abandon_tx_persisted`]. Each shape is a
/// distinct user-facing answer (rule 82); none collapses into another.
#[derive(Debug, thiserror::Error)]
pub enum AbandonTxError {
    /// No send-journal row exists for this txid — the wallet never
    /// dispatched it (or the row was pruned).
    #[error("no send record for this transaction")]
    NotFound,
    /// The row's state forbids abandoning: a `Confirmed` send is on
    /// chain, a `TerminalRejected` send was never relayed — neither has
    /// anything left to give up on.
    #[error("send state forbids abandon: {state:?}")]
    StateForbids {
        /// The state that refused the edge.
        state: SendState,
    },
    /// The durable save failed; the abandon was rolled back and the
    /// wallet is unchanged (fail closed).
    #[error("abandon persistence failed: {0}")]
    Persistence(#[from] PersistenceError),
}

// Generic over `F: PersistenceEngine` so the durable save drives the
// normal crash-atomic ledger path — the same widening
// `payment_requests.rs` / `stake_persist.rs` use. `WalletFile` satisfies
// the bound, so every existing caller is unaffected.
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
    /// Abandon a dispatched send **and durably commit it** (P3-4).
    ///
    /// Applies the journal edge, the I-2 reference migration, and the
    /// crash-atomic save under one ledger write guard so concurrent
    /// refresh/watchdog cannot interleave. Idempotent: abandoning an
    /// already-`Abandoned` row returns
    /// [`AbandonTxOutcome::AlreadyAbandoned`] without touching disk.
    ///
    /// # Errors
    ///
    /// - [`AbandonTxError::NotFound`] — no send record for `txid`.
    /// - [`AbandonTxError::StateForbids`] — the row is `Confirmed` or
    ///   `TerminalRejected`.
    /// - [`AbandonTxError::Persistence`] — the durable save failed; the
    ///   in-memory edge and migration were rolled back (fail closed),
    ///   so a retry starts from the pre-abandon state.
    pub fn abandon_tx_persisted(&self, txid: TxHash) -> Result<AbandonTxOutcome, AbandonTxError> {
        let key = txid.to_bytes();

        // One write guard for edge + migration + save (+ optional
        // rollback). `save_state` takes `&WalletLedger` — no second
        // lock — so concurrent merge/watchdog block until we finish.
        let mut guard = self.ledger.write();
        match guard.ledger.abandon_send(&key) {
            (AbandonEdge::AlreadyAbandoned, _) => {
                // Committed by a prior successful abandon_tx_persisted
                // (failure paths roll back), so disk already matches.
                Ok(AbandonTxOutcome::AlreadyAbandoned)
            }
            (AbandonEdge::NotFound, _) => Err(AbandonTxError::NotFound),
            (AbandonEdge::Forbidden { state }, _) => Err(AbandonTxError::StateForbids { state }),
            (AbandonEdge::Applied { previous }, was_pending) => {
                let save_result = drive_persistence(
                    self.persistence
                        .save_state(self.state_wrap_key(), &guard.ledger),
                );
                if let Err(e) = save_result {
                    // Fail closed under the same exclusive guard: restore
                    // the pre-abandon shape. Abandon never touched
                    // baseline/locks, so state + pending is a full undo.
                    guard.ledger.unabandon_send(&key, previous, was_pending);
                    return Err(AbandonTxError::Persistence(e.into()));
                }
                Ok(AbandonTxOutcome::Abandoned)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Engine-level abandon tests, including the crash-ordering
    //! (drop-then-confirm) pin the FOLLOWUPS abandon entry names.

    use std::sync::Arc;

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_state::{
        SendInputRef, SendRecord, SendState, TransferDetails, TxSecretKey, TxSecretKeys,
        WalletLedger,
    };
    use shekyl_rpc_transport::HttpRpc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;
    use zeroize::Zeroizing;

    use super::super::lifecycle::EngineCreateParams;
    use super::super::traits::LedgerEngine;
    use super::super::{Credentials, DaemonClient, Engine, SoloSigner};
    use super::{AbandonTxError, AbandonTxOutcome};

    /// Minimal unspent funding row at `gindex` (tests override spend
    /// fields where the scenario needs a confirmed spend).
    fn mk_row(seed: u8, gindex: u64) -> TransferDetails {
        TransferDetails {
            tx_hash: shekyl_types::TxHash::from_bytes([seed; 32]),
            internal_output_index: 0,
            global_output_index: gindex,
            block_height: 10,
            key: curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
            key_offset: curve25519_dalek::Scalar::ONE,
            commitment: shekyl_curve_primitives::Commitment::new(
                curve25519_dalek::Scalar::ONE,
                1_000,
            ),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 10,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: shekyl_engine_state::ReceiveAttribution::Unattributed,
        }
    }

    /// `Engine<SoloSigner>` over an unreachable daemon (abandon is a
    /// local operation; no daemon I/O on any path under test).
    async fn make_engine_arc() -> (Arc<RwLock<Engine<SoloSigner>>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"abandon_tx tests");
        let mut seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(11);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let rpc = HttpRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct HttpRpc against unreachable URL (no connect attempt yet)");
        let wallet = Engine::<SoloSigner>::create(params, DaemonClient::new(rpc))
            .expect("create FULL wallet for abandon_tx tests");
        (Arc::new(RwLock::new(wallet)), tmp)
    }

    /// Seed a dispatched send: journal row + retained key + pending
    /// reference — the exact shape `record_dispatched_send` +
    /// `record_retained_tx_key` leave behind.
    fn seed_dispatched(wallet: &mut WalletLedger, txid: [u8; 32], state: SendState) {
        wallet.tx_meta.tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0x5A; 32])),
            },
        );
        wallet.sync_state.pending_tx_hashes.push(txid);
        wallet.send_journal.rows.insert(
            txid,
            SendRecord {
                dispatched_at_height: 20,
                fee: 5,
                recipients: Vec::new(),
                change_amount: 0,
                inputs: vec![SendInputRef {
                    gindex: 7,
                    amount: 1,
                }],
                lock_baseline: None,
                state,
            },
        );
    }

    /// The full abandon contract in one pass: edge + migration applied
    /// and durably saved, keys retained, idempotent re-call, unknown
    /// and terminal txids refused with their own shapes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandon_migrates_persists_and_is_idempotent() {
        let (arc, _tmp) = make_engine_arc().await;
        let txid = [0x61; 32];
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            seed_dispatched(&mut guard.ledger, txid, SendState::PresumedDead);
        }

        let engine = arc.read().await;
        let outcome = engine
            .abandon_tx_persisted(shekyl_types::TxHash::from_bytes(txid))
            .expect("abandon applies from PresumedDead");
        assert_eq!(outcome, AbandonTxOutcome::Abandoned);
        {
            let guard = engine.ledger.read();
            let wallet = &guard.ledger;
            assert_eq!(wallet.send_journal.rows[&txid].state, SendState::Abandoned);
            assert!(
                wallet.sync_state.pending_tx_hashes.is_empty(),
                "the I-2 reference migrated off the pending set"
            );
            assert!(
                wallet.tx_meta.tx_keys.contains_key(&txid),
                "keys retained (C2)"
            );
            wallet
                .check_invariants()
                .expect("journal row carries I-2 after migration");
        }

        let again = engine
            .abandon_tx_persisted(shekyl_types::TxHash::from_bytes(txid))
            .expect("re-abandon is idempotent");
        assert_eq!(again, AbandonTxOutcome::AlreadyAbandoned);

        let missing = engine
            .abandon_tx_persisted(shekyl_types::TxHash::from_bytes([0xEE; 32]))
            .expect_err("unknown txid refuses");
        assert!(matches!(missing, AbandonTxError::NotFound));
    }

    /// Terminal states refuse with the state named — a confirmed send
    /// cannot be given up on, and the client hears which state refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandon_refuses_terminal_states() {
        let (arc, _tmp) = make_engine_arc().await;
        let confirmed = [0x62; 32];
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            guard.ledger.send_journal.rows.insert(
                confirmed,
                SendRecord {
                    dispatched_at_height: 20,
                    fee: 5,
                    recipients: Vec::new(),
                    change_amount: 0,
                    inputs: Vec::new(),
                    lock_baseline: None,
                    state: SendState::Confirmed { height: 25 },
                },
            );
        }
        let engine = arc.read().await;
        let err = engine
            .abandon_tx_persisted(shekyl_types::TxHash::from_bytes(confirmed))
            .expect_err("confirmed refuses");
        assert!(matches!(
            err,
            AbandonTxError::StateForbids {
                state: SendState::Confirmed { height: 25 }
            }
        ));
    }

    /// The drop-then-confirm window (the crash-ordering test the
    /// FOLLOWUPS abandon entry names): abandon a send the watchdog
    /// declared dead, then observe the spend confirm on chain anyway.
    /// The merge reconciler un-abandons loudly, the retained key stays
    /// live through every intermediate state, and the invariants hold
    /// at each persisted point.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_then_confirm_unabandons_loudly_with_keys_intact() {
        let (arc, _tmp) = make_engine_arc().await;
        let txid = [0x63; 32];
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            seed_dispatched(&mut guard.ledger, txid, SendState::PresumedDead);
        }

        // User abandons the presumed-dead send.
        {
            let engine = arc.read().await;
            engine
                .abandon_tx_persisted(shekyl_types::TxHash::from_bytes(txid))
                .expect("abandon applies");
        }

        // The tx confirms anyway: refresh observes the spend and the
        // merge post-pass reconciles journal + retention together —
        // exactly the window the FOLLOWUP names.
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            let wallet = &mut guard.ledger;
            let mut spent = mk_row(0x10, 7);
            spent.spent = true;
            spent.spent_height = Some(30);
            spent.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
                [0x33; 32],
            ));
            spent.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
            wallet.ledger.transfers.push(spent);
            wallet.ledger.tip.synced_height = 40;

            wallet.reconcile_after_scan_merge(None);

            assert_eq!(
                wallet.send_journal.rows[&txid].state,
                SendState::Confirmed { height: 30 },
                "late confirmation un-abandons loudly"
            );
            assert!(
                wallet.tx_meta.tx_keys.contains_key(&txid),
                "the retained key survived abandon -> confirm (the C2 hazard the \
                 FOLLOWUP names: proof material for a tx that later confirms)"
            );
            wallet
                .check_invariants()
                .expect("invariants hold after the flip");
        }
        // The wallet still reports the height it was seeded at.
        let engine = arc.read().await;
        assert_eq!(engine.ledger.synced_height(), 40);
    }

    /// Abandon-from-Dispatched keeps the carried-input locks alive
    /// across a rescan wipe: after `reset_scan_derived_state` + replay,
    /// the reconciler re-derives the F14 lock from the abandoned row's
    /// retained baseline (P3-1's non-terminal-or-abandoned set — the
    /// self-link defence for an abandoned-but-still-landable send).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_row_relocks_inputs_across_a_rescan_wipe() {
        let (arc, _tmp) = make_engine_arc().await;
        let txid = [0x64; 32];
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            seed_dispatched(&mut guard.ledger, txid, SendState::Dispatched);
            // An accepting verdict stamped the baseline (locks armed).
            if let Some(r) = guard.ledger.send_journal.rows.get_mut(&txid) {
                r.lock_baseline = Some(25);
            }
        }
        {
            let engine = arc.read().await;
            engine
                .abandon_tx_persisted(shekyl_types::TxHash::from_bytes(txid))
                .expect("abandon applies from Dispatched");
        }

        let engine = arc.write().await;
        let mut guard = engine.ledger.write();
        let state = &mut *guard;
        // The wipe, then replay re-creates the funding row.
        super::super::rescan::reset_scan_derived_state(&mut state.ledger, &mut state.indexes);
        let wallet = &mut state.ledger;
        wallet.ledger.transfers.push(mk_row(0x11, 7));
        wallet.ledger.tip.synced_height = 40;

        wallet.reconcile_after_scan_merge(None);

        // PR-SJ-1b: the lock is journal-derived, so it survives the wipe
        // by construction — the journal outlives the ledger reset and the
        // derivation reads it directly.
        let locks = wallet.f14_locks();
        let lock = locks
            .get(&7)
            .expect("the abandoned row's carried input stays locked across the wipe");
        assert_eq!(lock.tx_hash.to_bytes(), txid);
        assert_eq!(lock.accepted_at_height, 25);
        assert!(
            !wallet.ledger.transfers[0].is_spendable(u64::MAX, &locks),
            "the replayed funding row is excluded from selection"
        );
        assert_eq!(
            wallet.send_journal.rows[&txid].state,
            SendState::Abandoned,
            "the user's abandon survives the wipe"
        );
        wallet
            .check_invariants()
            .expect("invariants hold after the wipe and replay");
    }
}
