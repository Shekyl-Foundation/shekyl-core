// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Full-wallet rescan: reset scan-derived ledger state, then reuse refresh.
//!
//! Contract pin (`docs/api/wallet_rpc.yaml` `rescan_blockchain`,
//! `docs/FOLLOWUPS.md` Phase 4b rescan item): rescan is a **named** Engine
//! API that destroys and rebuilds scan-derived state from the wallet's scan
//! floor. It is not a silent "set height + refresh" shim.
//!
//! # Preserve vs clear
//!
//! The dividing line is **provenance, not topic**: a field is cleared iff a
//! chain replay reconstructs it. Anything the chain cannot re-derive is
//! user-authored or durably-committed state that a rescan must not touch —
//! clearing such a field is unrecoverable data loss, because the very scan
//! that is supposed to restore it never writes it.
//!
//! **Preserve (RESCAN-SURVIVING — not reconstructible from chain):**
//! - `sync_state.restore_from_height`, `creation_anchor_hash`, prefs
//! - `tx_meta.tx_keys` (+ `pending_tx_hashes` — I-2 live set with keys)
//! - `tx_meta.tx_notes`, `attributes`
//! - bookkeeping rows (primary label, address book, payment-request
//!   **records** — matches are unwound so replay can re-match)
//! - `staking.staking_enabled`, `p_slot`, **and `bonded_slots`**.
//!   `bonded_slots` is a durable bond record, not a scan hint: its only
//!   writer is [`Engine::persist_bond_record`](super::Engine) at bond-commit
//!   time, and the scan path never adds a slot
//!   ([`reconcile_phantom_bonded_slots`](super::stake_persist::reconcile_phantom_bonded_slots)
//!   only *removes* confirmed-absent ones). Clearing it would orphan a live
//!   on-chain bond from the wallet's record with no path back — every later
//!   `stake` would refuse `WrongSlot` against an empty set while the burned
//!   monotone cursor forbids re-adopting the slot. Phantom GC stays where it
//!   belongs: the open-time sweep, which is `absence-≠-unscanned` gated.
//!
//! **Clear / reset (scan-derived — the replay rebuilds all of it):**
//! - the whole [`LedgerBlock`] (transfers, tip, reorg window) — replaced
//!   wholesale rather than field-by-field, so a scan-derived field added
//!   later is reset by construction instead of by remembering this function
//! - runtime `LedgerIndexes`
//! - `sync_state.scan_completed`
//! - `tx_meta.scanned_pool_txs`
//! - payment-request match fields (via attribution rewind, classified
//!   against the **pre-reset** height)
//!
//! # The curve tree is not touched
//!
//! [`CurveTreeActor`](super::curve_tree_actor) owns a **chain-global**
//! anonymity-set store built from public on-chain material only — no wallet
//! secret ever enters it, and no wallet event invalidates it. Rolling it back
//! for a wallet rescan would discard a structure the wallet did not author
//! and force a full genesis-onward re-ingest (the `next < range_start`
//! daemon backfill in `curve_tree_ingest_scan_result`) for no gain: the
//! ingest cursor already skips heights it holds, and CT-5b verified each of
//! those roots when they were first ingested. Reorgs — the one event that
//! *does* invalidate tree suffixes — roll it back at the merge, which is
//! where that concern lives.

use shekyl_engine_state::{LedgerBlock, LedgerIndexes, WalletLedger};

use super::error::RefreshError;
use super::local_ledger::LocalLedger;
use super::refresh::{RefreshHandle, RefreshOptions};
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, LedgerEngine, RefreshEngine};
use super::Engine;
use crate::attribution::rewind_matched_payment_requests_after_reorg;

/// Reset scan-derived fields on an in-memory ledger aggregate.
///
/// Leaves key material, restore height, retained tx keys, payment-request
/// invoices, and staking records intact (see the module docs for the
/// provenance rule that draws the line). Callers must persist before
/// scanning; [`Engine::start_rescan`] is the only production caller.
pub(crate) fn reset_scan_derived_state(wallet: &mut WalletLedger, indexes: &mut LedgerIndexes) {
    // Captured before the tip is zeroed: the rewind below classifies an
    // unwound request's expiry against this height. Read from the emptied
    // ledger it would be 0, and `is_expired_at(0)` is false for every
    // non-zero expiry — a years-expired invoice would come back `Pending`
    // and sit in `get_payment_requests` as "awaiting payment" forever.
    let pre_reset_height = wallet.ledger.height();

    // Total reconstruction, not a field-by-field clear. `LedgerBlock` is
    // entirely scan-derived, so "reset" is "a fresh one at the current block
    // version" — and a field added to it later is then reset because it
    // exists, not because someone remembered to extend this function.
    wallet.ledger = LedgerBlock::empty();
    *indexes = LedgerIndexes::empty();

    wallet.sync_state.scan_completed = false;
    wallet.tx_meta.scanned_pool_txs.clear();

    // Preserve payment-request *rows*; unwind matches against the emptied
    // transfer set so a subsequent scan can re-attribute.
    rewind_matched_payment_requests_after_reorg(
        &mut wallet.bookkeeping.payment_requests,
        &wallet.ledger,
        pre_reset_height,
    );
}

// Same specialization as `Engine::start_refresh` (see `engine/refresh.rs`):
// `LocalLedger` because the spawned producer's merge step goes through the
// `LocalLedger`-specialized `Engine::apply_scan_result`.
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: super::traits::EconomicsEngine,
        R: RefreshEngine + super::scan_floor::ScanStartFloorProvider,
        P: super::traits::PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P>
{
    /// Full rescan from the wallet's scan floor.
    ///
    /// Named Engine API for OpenAPI `rescan_blockchain` (Phase 4c /
    /// FOLLOWUPS Phase 4b rescan item). Empties scan-derived ledger state
    /// (see [`reset_scan_derived_state`] for the preserve/clear line),
    /// persists the reset, then runs the same producer as
    /// [`Engine::start_refresh`](Self::start_refresh) under the shared
    /// `refresh_slot` (`AlreadyRunning` → RPC `-29200`).
    ///
    /// # Where the replay starts
    ///
    /// The producer restarts at the wallet's **scan floor** —
    /// `max(sync_state.restore_from_height, skip_to_height,
    /// refresh_from_block_height)`, fixed at wallet open by
    /// [`effective_scan_floor`](super::scan_floor::effective_scan_floor).
    /// For a wallet with no height overrides configured that is exactly
    /// `restore_from_height`; where an override raises it, honouring the
    /// floor is the point — it is the wallet's own "the chain below this is
    /// not mine" statement, and a rescan that ignored it would re-scan
    /// history the user has already declared irrelevant.
    ///
    /// # Ordering: everything that can refuse runs before anything destroys
    ///
    /// The reset is durable before the scan begins — that is inherent to
    /// rescan (the producer merges *into* the emptied ledger), so there is
    /// no post-hoc undo. What is controllable is how much can still fail
    /// after the point of no return, so every refusal is hoisted in front of
    /// it:
    ///
    /// 1. **Slot claim** — cheap CAS; a concurrent refresh loses here.
    /// 2. **Daemon preflight** — a `get_health` round-trip *before* the
    ///    wipe. An unreachable daemon is the overwhelmingly common rescan
    ///    failure (and the producer needs it immediately anyway, to anchor
    ///    the birthday). Preflighting turns "wallet silently emptied, scan
    ///    then failed" into a clean refusal with nothing destroyed.
    /// 3. **In-flight-transaction guard + reset + persist**, all under one
    ///    exclusive engine hold. The guard is *inside* the hold rather than
    ///    sampled ahead of it: a reservation registered between a
    ///    pre-sampled count and the wipe would have its transfers erased
    ///    underneath it, which is precisely what the guard exists to
    ///    prevent.
    ///
    /// # Errors
    ///
    /// All four leave the wallet **untouched** — they are raised before the
    /// reset, except [`RescanPersist`](RefreshError::RescanPersist), which
    /// is the one window where the in-memory ledger is emptied but the
    /// durable copy may not be:
    ///
    /// - [`RefreshError::AlreadyRunning`] — refresh/rescan already in flight.
    /// - [`RefreshError::Io`] — daemon preflight failed; retry when reachable.
    /// - [`RefreshError::RescanBlocked`] — outstanding pending-tx
    ///   reservations (consumer-held or in-flight) whose output locks a
    ///   chain replay cannot rebuild; see that variant.
    /// - [`RefreshError::RescanPersist`] — durable save of the reset failed.
    ///
    /// Scan-path errors surface via [`RefreshHandle::join`], same as refresh.
    /// A scan that fails *after* the reset leaves the wallet emptied and
    /// re-runnable; the RPC and CLI surfaces say so rather than reporting a
    /// bare I/O error over a wallet whose history just went to zero.
    pub async fn start_rescan(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        opts: RefreshOptions,
    ) -> Result<RefreshHandle, RefreshError>
    where
        S: EngineSignerKind + Send + Sync + 'static,
        Self: Send + Sync,
    {
        // 1. Single-flight, over the same slot `start_refresh` claims.
        let slot = self_arc.read().await.refresh_slot.clone();
        let slot_guard = slot.try_claim().ok_or(RefreshError::AlreadyRunning)?;

        // 2. Daemon preflight — the last refusal that costs the user nothing.
        //    Clone-then-drop so the read guard never spans daemon I/O.
        {
            let daemon = self_arc.read().await.daemon().clone();
            // `DaemonEngine::Error: Into<IoError>` — go through the trait's
            // own conversion rather than stringifying, so the preflight
            // reports the same I/O taxonomy the producer would have.
            daemon
                .get_health()
                .await
                .map_err(|e| RefreshError::Io(e.into()))?;
        }

        // 3. Guard, reset, and persist under one exclusive engine hold, so
        //    no reservation can appear between the check and the wipe.
        //    `drive_persistence` is synchronous by design — nothing here
        //    `.await`s while a `std::sync::RwLock` guard is alive (that
        //    would make this future `!Send`).
        let synced_height = {
            let engine = self_arc.write().await;
            let reservations = engine.outstanding_pending_txs();
            {
                let mut guard = engine.ledger.write();
                let state = &mut *guard;
                // PR-SJ-1: the unconfirmed half of this refusal retired —
                // the send journal carries dispatched input sets across
                // the wipe and the merge reconciler re-derives the F14
                // locks during replay (`WALLET_SEND_RECORD.md` P3-1).
                // Pre-dispatch reservations still refuse: no journal row
                // exists, and their in-memory locks index the rows the
                // wipe destroys. Discard-then-rescan is the remedy.
                if reservations > 0 {
                    return Err(RefreshError::RescanBlocked { reservations });
                }
                reset_scan_derived_state(&mut state.ledger, &mut state.indexes);
            }
            {
                let ledger_guard = engine.ledger.read();
                if let Err(e) = super::lifecycle::drive_persistence(
                    super::traits::PersistenceEngine::save_state(
                        &engine.persistence,
                        engine.state_wrap_key(),
                        &ledger_guard.ledger,
                    ),
                ) {
                    return Err(RefreshError::RescanPersist(e.to_string()));
                }
            }
            engine.ledger.synced_height()
        };

        Ok(Self::spawn_refresh_producer(
            self_arc,
            opts,
            slot_guard,
            synced_height,
        ))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_curve_primitives::Commitment;
    use shekyl_engine_state::{
        transfer::TransferDetails, BlockchainTip, LedgerIndexes, LocalLabel, PaymentRequest,
        PaymentRequestId, PaymentRequestState, ReceiveAttribution, ReorgBlocks, ScannedPoolTx,
        SyncStateBlock, TxSecretKey, TxSecretKeys, WalletLedger,
    };
    use shekyl_types::TxHash;
    use shekyl_units::AtomicUnits;
    use zeroize::Zeroizing;

    use super::reset_scan_derived_state;

    /// Tip state after a reset — always the unscanned bootstrap tip, with
    /// nothing scan-derived left behind.
    fn assert_unscanned(ledger: &shekyl_engine_state::LedgerBlock) {
        assert!(
            ledger.tip.is_unscanned(),
            "rescan reset must leave an unscanned tip"
        );
        assert!(ledger.transfers.is_empty());
        assert!(ledger.reorg_blocks.is_empty());
    }

    /// A minimal owned-output row. `pub(super)` so the integration tests in
    /// the sibling module can plant one without a second copy of the
    /// twenty-field literal.
    pub(super) fn sample_transfer(seed: u8) -> TransferDetails {
        TransferDetails {
            tx_hash: TxHash::from_bytes([seed; 32]),
            internal_output_index: 0,
            global_output_index: 0,
            block_height: 10,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1000),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: 0,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: ReceiveAttribution::Unattributed,
        }
    }

    #[test]
    fn reset_clears_scan_derived_and_preserves_retention() {
        let mut wallet = WalletLedger::empty();
        wallet.sync_state.restore_from_height = 42;
        wallet.sync_state.creation_anchor_hash = Some([7u8; 32]);
        wallet.sync_state.scan_completed = true;
        wallet.sync_state.pending_tx_hashes.push([9u8; 32]);
        wallet.sync_state.confirmations_required = 10;
        wallet.sync_state.trusted_daemon = true;

        wallet.ledger.transfers.push(sample_transfer(1));
        wallet.ledger.tip = BlockchainTip::new(50, [1u8; 32]);
        wallet.ledger.reorg_blocks = ReorgBlocks {
            blocks: vec![(40, [2u8; 32])],
        };

        let txid = [3u8; 32];
        wallet.tx_meta.tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([4u8; 32])),
            },
        );
        wallet.tx_meta.scanned_pool_txs.insert(
            [5u8; 32],
            ScannedPoolTx {
                first_seen_unix_secs: 1,
                double_spend_seen: false,
            },
        );

        wallet.bookkeeping.payment_requests.push(PaymentRequest {
            id: PaymentRequestId(0x00_00_00_00_00_06),
            label: LocalLabel::from_str("invoice"),
            amount_atomic: AtomicUnits::from_raw(100),
            created_at: 1,
            expiry: None,
            state: PaymentRequestState::Matched,
            matched_tx_hash: Some(TxHash::from_bytes([1u8; 32])),
            matched_output_index: Some(0),
        });

        wallet.staking.staking_enabled = true;
        wallet.staking.p_slot = 3;
        wallet.staking.bonded_slots = vec![1, 2];

        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);

        assert_unscanned(&wallet.ledger);
        assert!(!wallet.sync_state.scan_completed);
        assert_eq!(wallet.sync_state.restore_from_height, 42);
        assert_eq!(wallet.sync_state.creation_anchor_hash, Some([7u8; 32]));
        assert_eq!(wallet.sync_state.pending_tx_hashes, vec![[9u8; 32]]);
        assert_eq!(wallet.sync_state.confirmations_required, 10);
        assert!(wallet.sync_state.trusted_daemon);
        assert!(wallet.tx_meta.tx_keys.contains_key(&txid));
        assert!(wallet.tx_meta.scanned_pool_txs.is_empty());
        assert!(wallet.staking.staking_enabled);
        assert_eq!(wallet.staking.p_slot, 3);

        let req = &wallet.bookkeeping.payment_requests[0];
        assert_eq!(req.state, PaymentRequestState::Pending);
        assert!(req.matched_tx_hash.is_none());
        assert!(req.matched_output_index.is_none());
    }

    /// `bonded_slots` is a durable bond record, not a scan hint: nothing in
    /// the scan path re-adds a slot, so clearing it here would orphan a live
    /// on-chain bond permanently (see the module docs).
    #[test]
    fn reset_preserves_bonded_slots() {
        let mut wallet = WalletLedger::empty();
        wallet.staking.staking_enabled = true;
        wallet.staking.p_slot = 4;
        wallet.staking.bonded_slots = vec![3];
        wallet.ledger.transfers.push(sample_transfer(2));

        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);

        assert_eq!(
            wallet.staking.bonded_slots,
            vec![3],
            "a live bond survives rescan — the scan can never re-add it"
        );
        assert!(wallet.staking.staking_enabled);
        assert_eq!(wallet.staking.p_slot, 4);
    }

    /// The send journal is dispatch-authored, not scan-derived: nothing
    /// in a chain replay can rebuild recipients or the per-recipient
    /// split (CT), so the block lives outside `LedgerBlock` and survives
    /// the reset by construction (C6/C7 — see `send_journal_block`).
    #[test]
    fn reset_preserves_send_journal() {
        use shekyl_engine_state::{SendInputRef, SendRecipient, SendRecord, SendState};

        let mut wallet = WalletLedger::empty();
        wallet.send_journal.rows.insert(
            [5u8; 32],
            SendRecord {
                dispatched_at_height: 42,
                fee: 700,
                recipients: vec![SendRecipient {
                    address: "shekyl1example".to_owned(),
                    amount: 7_000,
                }],
                change_amount: 22_300,
                inputs: vec![SendInputRef {
                    gindex: 11,
                    amount: 30_000,
                }],
                lock_baseline: Some(43),
                state: SendState::Dispatched,
            },
        );
        wallet.ledger.transfers.push(sample_transfer(2));

        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);

        assert_unscanned(&wallet.ledger);
        let row = &wallet.send_journal.rows[&[5u8; 32]];
        assert_eq!(row.state, SendState::Dispatched);
        assert_eq!(
            row.lock_baseline,
            Some(43),
            "the baseline survives the wipe"
        );
        assert_eq!(
            row.inputs,
            vec![SendInputRef {
                gindex: 11,
                amount: 30_000
            }],
            "the carried input set survives — it is what re-derives the F14 locks"
        );
    }

    /// An invoice whose expiry height has already passed is unwound to
    /// `Expired`, not `Pending`: the rewind is classified against the
    /// pre-reset tip, not the zeroed one.
    #[test]
    fn reset_expires_payment_request_past_its_expiry_height() {
        let mut wallet = WalletLedger::empty();
        wallet.ledger.tip = BlockchainTip::new(500, [8u8; 32]);
        wallet.bookkeeping.payment_requests.push(PaymentRequest {
            id: PaymentRequestId(0x00_00_00_00_00_07),
            label: LocalLabel::from_str("stale invoice"),
            amount_atomic: AtomicUnits::from_raw(100),
            created_at: 1,
            expiry: Some(100),
            state: PaymentRequestState::Matched,
            matched_tx_hash: Some(TxHash::from_bytes([1u8; 32])),
            matched_output_index: Some(0),
        });

        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);

        assert_eq!(
            wallet.bookkeeping.payment_requests[0].state,
            PaymentRequestState::Expired,
            "expiry is classified against the pre-reset height"
        );
    }

    #[test]
    fn reset_is_idempotent_on_empty_ledger() {
        let mut wallet = WalletLedger::empty();
        wallet.sync_state = SyncStateBlock {
            restore_from_height: 7,
            ..SyncStateBlock::empty()
        };
        let mut indexes = LedgerIndexes::empty();
        reset_scan_derived_state(&mut wallet, &mut indexes);
        reset_scan_derived_state(&mut wallet, &mut indexes);
        assert_eq!(wallet.sync_state.restore_from_height, 7);
        assert_unscanned(&wallet.ledger);
    }
}

#[cfg(test)]
mod start_rescan_integration_tests {
    //! End-to-end tests for [`Engine::start_rescan`] against a real
    //! `Engine<SoloSigner>`, mirroring the `start_refresh` fixtures in
    //! `engine/refresh.rs`.
    //!
    //! The unreachable-daemon fixture is load-bearing rather than
    //! incidental here: it is exactly the shape the daemon preflight
    //! exists to catch, so "refuses without touching the wallet" is a
    //! directly assertable property.

    use std::sync::Arc;

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_state::BlockchainTip;
    use shekyl_rpc_transport::HttpRpc;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    use crate::engine::lifecycle::EngineCreateParams;
    use crate::engine::test_support::{TestDaemon, DEFAULT_TEST_SEED};
    use crate::engine::traits::LedgerEngine;
    use crate::engine::{
        Credentials, DaemonClient, Engine, IoError, RefreshError, RefreshOptions, SoloSigner,
    };

    /// `Engine<SoloSigner>` wired to an unreachable daemon, in the
    /// `Arc<RwLock<…>>` shape `start_rescan` takes. The `TempDir` comes back
    /// so the caller keeps the wallet file alive for the test's scope.
    async fn make_engine_arc() -> (Arc<RwLock<Engine<SoloSigner>>>, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"start-rescan integration tests");
        let mut seed = [0u8; MASTER_SEED_BYTES];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let rpc = HttpRpc::new("http://127.0.0.1:1".to_string())
            .await
            .expect("construct HttpRpc against unreachable URL (no connect attempt yet)");
        let wallet = Engine::<SoloSigner>::create(params, DaemonClient::new(rpc))
            .expect("create FULL wallet for start_rescan integration tests");
        (Arc::new(RwLock::new(wallet)), tmp)
    }

    /// The same engine with a reachable [`TestDaemon`] in place of the dead
    /// `DaemonClient`, per the §6.3 hybrid-construction discipline. Needed
    /// wherever a test has to get *past* the daemon preflight to reach a
    /// later refusal.
    async fn make_hybrid_engine_arc() -> (Arc<RwLock<Engine<SoloSigner, TestDaemon>>>, TempDir) {
        let (arc, tmp) = make_engine_arc().await;
        let real = Arc::try_unwrap(arc)
            .expect("sole owner of the engine arc")
            .into_inner();
        let hybrid = real.replace_daemon(TestDaemon::with_seed(DEFAULT_TEST_SEED));
        (Arc::new(RwLock::new(hybrid)), tmp)
    }

    /// Seed scan-derived state so a wipe is observable, and return the tip
    /// height it was seeded to.
    async fn seed_scanned_state<D>(arc: &Arc<RwLock<Engine<SoloSigner, D>>>) -> u64
    where
        D: crate::engine::traits::DaemonEngine,
    {
        let engine = arc.write().await;
        let mut guard = engine.ledger.write();
        guard.ledger.ledger.tip = BlockchainTip::new(500, [0xAB; 32]);
        guard.ledger.sync_state.scan_completed = true;
        500
    }

    /// Block until the single-flight slot is free, bounded so a regression
    /// fails the suite instead of hanging it.
    ///
    /// `RefreshHandle::join` resolving is **not** the same event as the slot
    /// being released: the producer fires the completion oneshot from inside
    /// `run_refresh_task`, and its `SlotGuard` drops later, as that function
    /// returns. Any test that starts a second scan after joining a first has
    /// to wait for the guard, or it races the task's own teardown — the same
    /// discipline the `start_refresh` fixtures follow.
    async fn await_slot_release<D>(arc: &Arc<RwLock<Engine<SoloSigner, D>>>)
    where
        D: crate::engine::traits::DaemonEngine,
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            tokio::task::yield_now().await;
            if !arc.read().await.refresh_slot.is_claimed() {
                return;
            }
            assert!(
                std::time::Instant::now() <= deadline,
                "single-flight slot still claimed 10s after the producer completed"
            );
        }
    }

    /// The daemon preflight refuses before anything destructive runs: an
    /// unreachable daemon leaves the wallet exactly as it was, and releases
    /// the single-flight slot for the retry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unreachable_daemon_refuses_without_touching_the_wallet() {
        let (arc, _tmp) = make_engine_arc().await;
        let seeded = seed_scanned_state(&arc).await;

        let err = Engine::start_rescan(arc.clone(), RefreshOptions::default())
            .await
            .expect_err("unreachable daemon must refuse the rescan");
        assert!(
            matches!(err, RefreshError::Io(IoError::Daemon { .. })),
            "expected Io(Daemon) from the preflight, got {err:?}"
        );

        let engine = arc.read().await;
        assert_eq!(
            engine.ledger.synced_height(),
            seeded,
            "a refused rescan must not reset the ledger"
        );
        assert!(
            engine.ledger.read().ledger.sync_state.scan_completed,
            "a refused rescan must not clear scan_completed"
        );
        assert!(
            !engine.refresh_slot.is_claimed(),
            "a refused rescan must release the single-flight slot"
        );
    }

    /// An unconfirmed submitted transaction no longer blocks the rescan
    /// (PR-SJ-1, P3-1): the send journal carries the dispatched input set
    /// across the wipe and the merge reconciler re-derives the F14 locks
    /// during replay, so the refusal's unconfirmed half is retired.
    ///
    /// Runs on the hybrid (reachable-daemon) fixture deliberately — the
    /// preflight sits ahead of this path, so a dead daemon would mask the
    /// property under test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unconfirmed_submitted_tx_no_longer_blocks_rescan() {
        // PR-SJ-1 (`WALLET_SEND_RECORD.md` P3-1): the unconfirmed half of
        // the -29202 refusal retired — the send journal carries the
        // dispatched input set across the wipe and the merge reconciler
        // re-derives the F14 locks during replay, so a pending submitted
        // tx no longer wedges rescan.
        let (arc, _tmp) = make_hybrid_engine_arc().await;
        let seeded = seed_scanned_state(&arc).await;
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            guard.ledger.sync_state.pending_tx_hashes.push([0x11; 32]);
        }

        let handle = Engine::start_rescan(arc.clone(), RefreshOptions::default())
            .await
            .expect("an unconfirmed submitted tx must NOT block the rescan (P3-1)");
        drop(handle);
        await_slot_release(&arc).await;

        let engine = arc.read().await;
        assert_ne!(
            engine.ledger.synced_height(),
            seeded,
            "the rescan proceeded: scan-derived state was reset"
        );
        assert!(
            !engine.refresh_slot.is_claimed(),
            "a blocked rescan must release the single-flight slot"
        );
    }

    /// The kept half of `-29202` (P3-1): a pre-dispatch reservation has
    /// no send-journal row and its in-memory output locks index the very
    /// rows the wipe destroys — rescan refuses, wallet untouched, and
    /// discard-then-rescan is the in-session remedy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_reservation_still_blocks_rescan_without_touching_the_wallet() {
        let (arc, _tmp) = make_hybrid_engine_arc().await;
        let seeded = seed_scanned_state(&arc).await;
        {
            let engine = arc.read().await;
            engine.test_hold_reservation();
        }

        let err = Engine::start_rescan(arc.clone(), RefreshOptions::default())
            .await
            .expect_err("a held reservation must still block the rescan");
        match err {
            RefreshError::RescanBlocked { reservations } => {
                assert_eq!(reservations, 1);
            }
            other => panic!("expected RescanBlocked, got {other:?}"),
        }

        let engine = arc.read().await;
        assert_eq!(
            engine.ledger.synced_height(),
            seeded,
            "a blocked rescan must not reset the ledger"
        );
        assert!(
            !engine.refresh_slot.is_claimed(),
            "a blocked rescan must release the single-flight slot"
        );
    }

    /// End-to-end: a rescan really does destroy and rebuild.
    ///
    /// Sync a wallet over a synthetic chain, then plant state the chain
    /// cannot justify — a phantom transfer and a payment request matched to
    /// it — and rescan. The phantom is gone afterwards because the replay
    /// rebuilds the transfer set from chain data alone, the invoice is
    /// unwound to `Pending` so a future scan can re-match it, and the wallet
    /// lands back at the same synced height. Together those pin the three
    /// halves of the contract that the unit tests can only assert in
    /// isolation: reset, persist, and producer restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rescan_rebuilds_the_ledger_from_chain_and_unwinds_matches() {
        use crate::engine::test_support::make_synthetic_block;
        use shekyl_engine_state::{
            LocalLabel, PaymentRequest, PaymentRequestId, PaymentRequestState,
        };
        use shekyl_types::TxHash;
        use shekyl_units::AtomicUnits;

        // `chain[h] = block at height h`; heights 0..=5, genesis at 0.
        let mut chain = Vec::new();
        let mut parent = [0u8; 32];
        for h in 0..6u64 {
            let block = make_synthetic_block(h, parent);
            parent = block.block.hash();
            chain.push(block);
        }
        let (arc, _tmp) = make_engine_arc().await;
        let real = Arc::try_unwrap(arc)
            .expect("sole owner of the engine arc")
            .into_inner();
        let hybrid = real.replace_daemon(TestDaemon::with_seed_and_chain(DEFAULT_TEST_SEED, chain));
        let arc = Arc::new(RwLock::new(hybrid));

        Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("initial refresh claims the slot")
            .join()
            .await
            .expect("initial refresh completes over the synthetic chain");
        await_slot_release(&arc).await;
        let synced_before = arc.read().await.ledger.synced_height();
        assert_eq!(synced_before, 5, "synthetic chain syncs to its tip");

        let phantom_tx = TxHash::from_bytes([0xDD; 32]);
        {
            let engine = arc.write().await;
            let mut guard = engine.ledger.write();
            let mut phantom = super::tests::sample_transfer(0xDD);
            phantom.tx_hash = phantom_tx;
            phantom.block_height = 3;
            guard.ledger.ledger.transfers.push(phantom);
            guard
                .ledger
                .bookkeeping
                .payment_requests
                .push(PaymentRequest {
                    id: PaymentRequestId(0x00_00_00_00_00_0A),
                    label: LocalLabel::from_str("invoice"),
                    amount_atomic: AtomicUnits::from_raw(1000),
                    created_at: 1,
                    expiry: None,
                    state: PaymentRequestState::Matched,
                    matched_tx_hash: Some(phantom_tx),
                    matched_output_index: Some(0),
                });
        }

        Engine::start_rescan(arc.clone(), RefreshOptions::default())
            .await
            .expect("rescan claims the slot")
            .join()
            .await
            .expect("rescan completes over the same chain");

        let engine = arc.read().await;
        let guard = engine.ledger.read();
        assert!(
            !guard
                .ledger
                .ledger
                .transfers
                .iter()
                .any(|t| t.tx_hash == phantom_tx),
            "the rescan rebuilt the transfer set from chain data, dropping the phantom"
        );
        assert_eq!(
            guard.ledger.bookkeeping.payment_requests[0].state,
            PaymentRequestState::Pending,
            "an unmatched invoice is unwound so a later scan can re-match it"
        );
        assert!(
            guard.ledger.bookkeeping.payment_requests[0]
                .matched_tx_hash
                .is_none(),
            "the stale match is cleared with the transfer it pointed at"
        );
        drop(guard);
        assert_eq!(
            engine.ledger.synced_height(),
            synced_before,
            "the replay returns the wallet to the chain tip"
        );
    }

    /// The single-flight slot is shared with `start_refresh`: a rescan while
    /// a refresh holds the slot is `AlreadyRunning`, refused before the
    /// preflight and before any reset.
    #[tokio::test(flavor = "current_thread")]
    async fn rescan_while_refresh_holds_the_slot_is_already_running() {
        let (arc, _tmp) = make_engine_arc().await;

        let refresh = Engine::start_refresh(arc.clone(), RefreshOptions::default())
            .await
            .expect("refresh claims the slot");
        let rescan = Engine::start_rescan(arc.clone(), RefreshOptions::default()).await;
        assert!(
            matches!(rescan, Err(RefreshError::AlreadyRunning)),
            "rescan must lose the shared slot to a running refresh, got {rescan:?}"
        );

        // Cleanup: drop the handle so the producer wakes on cancel and frees
        // the slot before the test ends.
        drop(refresh);
        await_slot_release(&arc).await;
    }
}
