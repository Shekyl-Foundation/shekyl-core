// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Aggregator-level invariants over a loaded [`WalletLedger`].
//!
//! The four typed blocks each enforce their own shape — version gates
//! (commits 2d–2g) and postcard decode (commit 2n). Those checks are
//! enough to detect *corruption of a single block*. They are not
//! enough to detect *inconsistency across blocks*: a ledger whose
//! every block decoded cleanly can still be semantically impossible
//! (a scanner tip below a recorded transfer; a key image reused across
//! two `TransferDetails`; an orphan per-tx secret whose transaction
//! has been garbage-collected from every live reference).
//!
//! This module owns the closed set of such cross-block invariants and
//! runs them once per boundary event:
//!
//! * On load — after [`WalletLedger::from_postcard_bytes`] has
//!   successfully decoded and passed every version gate — so that a
//!   typed refusal happens *before* the runtime ever treats the
//!   ledger as authoritative.
//! * On save — before the orchestrator writes the encoded bundle to
//!   disk — via [`WalletLedger::preflight_save`]. In debug builds
//!   this routes through `debug_assert!` so a logic bug that breaks
//!   an invariant during a live session aborts the test loudly; in
//!   release builds it returns the same typed error so a user never
//!   panics mid-save.
//!
//! # Why these five
//!
//! The invariants are derived from the §3.6 plan in
//! `docs/MID_REWIRE_HARDENING.md`, with two of the rows adjusted to
//! match the block shapes actually present in this crate (the plan
//! explicitly sanctions such adjustment on landing). The closed set:
//!
//! | Stable name                          | Cross-block relationship                                                              |
//! |--------------------------------------|---------------------------------------------------------------------------------------|
//! | `tip-height-not-below-transfer`      | `ledger.tip.synced_height >= max(ledger.transfers[*].block_height)`                   |
//! | `tx-keys-no-orphans`                 | Every tx-hash in `tx_meta.tx_keys` appears in a live reference (transfer tx_hash / spending_tx_hash / awaiting_confirmation, pool, or pending) |
//! | `reorg-trail-monotonic`              | `ledger.reorg_blocks.blocks` is strictly ascending and capped by `tip.synced_height`  |
//! | `spent-state-consistent`             | Within `ledger.transfers`: spend-triple self-consistency + key-image uniqueness       |
//! | `send-journal-lock-equivalence`      | F14 `awaiting_confirmation` ⟺ `send_journal` dispatch facts (derived-cache both-agree, `WALLET_SEND_RECORD.md` P3-1a; retired with the field at PR-SJ-1b) |
//!
//! # Cost
//!
//! Every check is O(n) in the number of transfers (or map keys), with
//! a single `HashSet<[u8; 32]>` allocated for `spent-state-consistent`
//! and `tx-keys-no-orphans`. For a 10 k-transfer wallet the combined
//! pass is comfortably under 100 µs on the hardware used by the
//! commit-3.2 benchmark — far below the Argon2id cost already paid on
//! the open path, and not a concern for any `crypto_bench_*` threshold.

use std::collections::HashSet;

use shekyl_crypto_pq::key_image::KeyImage;

use crate::{
    error::WalletLedgerError, ledger_block::LedgerBlock, sync_state_block::SyncStateBlock,
    transfer::TransferDetails, tx_meta_block::TxMetaBlock, wallet_ledger::WalletLedger,
};

/// Stable machine-readable name for invariant I-1.
pub const INV_TIP_NOT_BELOW_TRANSFER: &str = "tip-height-not-below-transfer";

/// Stable machine-readable name for invariant I-2.
pub const INV_TX_KEYS_NO_ORPHANS: &str = "tx-keys-no-orphans";

/// Stable machine-readable name for invariant I-3.
pub const INV_REORG_TRAIL_MONOTONIC: &str = "reorg-trail-monotonic";

/// Stable machine-readable name for invariant I-4.
pub const INV_SPENT_STATE_CONSISTENT: &str = "spent-state-consistent";

/// Stable name for the send-journal lock-equivalence invariant
/// (`WALLET_SEND_RECORD.md` P3-1a: the F14 awaiting-confirmation field
/// is a derived cache of `send_journal` dispatch facts — both must
/// agree until PR-SJ-1b deletes the field).
pub const INV_SEND_JOURNAL_LOCK_EQUIVALENCE: &str = "send-journal-lock-equivalence";

impl WalletLedger {
    /// Run every aggregator-level invariant against `self` and return
    /// a typed [`WalletLedgerError::InvariantFailed`] on the first
    /// violation. See the module docs for the closed set and the
    /// cost characterization.
    ///
    /// Called automatically by [`Self::from_postcard_bytes`] after the
    /// per-block version gates pass; callers that want to revalidate a
    /// ledger they assembled in-process can invoke it directly.
    pub fn check_invariants(&self) -> Result<(), WalletLedgerError> {
        check_tip_not_below_transfer(&self.ledger)?;
        check_tx_keys_no_orphans(&self.ledger, &self.tx_meta, &self.sync_state)?;
        check_reorg_trail_monotonic(&self.ledger)?;
        check_spent_state_consistent(&self.ledger)?;
        check_send_journal_lock_equivalence(&self.ledger, &self.send_journal)?;
        Ok(())
    }

    /// Pre-write gate for the orchestrator's save path.
    ///
    /// In **debug** builds, a broken invariant here is a logic bug in
    /// the live session (the scanner or runtime mutated the ledger
    /// into an impossible shape) and is surfaced via `debug_assert!`
    /// so the test harness aborts loudly with the full panic message.
    /// In **release** builds the same invariant failure returns the
    /// typed [`WalletLedgerError::InvariantFailed`] — panicking
    /// mid-save is strictly worse than refusing the save, and the
    /// orchestrator can surface the typed error to the user.
    ///
    /// The save path is where the release-build policy matters most:
    /// an `unwrap` on a `Result` would abort the process and lose the
    /// pending state transition (or, worse, leave a half-written temp
    /// file in place). The `Result` return lets the orchestrator keep
    /// the atomic-write helper atomic.
    pub fn preflight_save(&self) -> Result<(), WalletLedgerError> {
        let result = self.check_invariants();
        debug_assert!(
            result.is_ok(),
            "WalletLedger::preflight_save invariant failed: {:?}",
            result.as_ref().err()
        );
        result
    }
}

fn invariant_error(invariant: &'static str, detail: impl Into<String>) -> WalletLedgerError {
    WalletLedgerError::InvariantFailed {
        invariant,
        detail: detail.into(),
    }
}

/// I-1. The scanner's tip must never sit below a block at which this
/// wallet has observed an output. A regression in `synced_height`
/// below `max(block_height)` means either the scanner rolled backward
/// without dropping the now-impossible transfers, or a transfer
/// entered the ledger claiming it was mined at a height the scanner
/// has not yet visited. Both shapes are corruption.
fn check_tip_not_below_transfer(ledger: &LedgerBlock) -> Result<(), WalletLedgerError> {
    let Some(max_block_height) = ledger.transfers.iter().map(|t| t.block_height).max() else {
        // No transfers — nothing to bound the tip by.
        return Ok(());
    };
    let tip = ledger.tip.synced_height;
    if tip < max_block_height {
        return Err(invariant_error(
            INV_TIP_NOT_BELOW_TRANSFER,
            format!(
                "tip.synced_height = {tip} is below max(transfers[*].block_height) = \
                 {max_block_height}; the scanner has regressed past a recorded transfer"
            ),
        ));
    }
    Ok(())
}

/// I-2. Every tx-hash in `tx_meta.tx_keys` must still be referenced
/// by *something* the wallet actively tracks: a live
/// [`TransferDetails`] (the scanner observed it — as the receiving
/// txid, as a confirmed `spending_tx_hash` (WI-RPC-3 F-9
/// spend-quadruple), or as an in-flight `awaiting_confirmation`
/// lock), a scanned pool entry (we saw it in mempool), or the
/// user-submitted pending list (we originated it and it has not yet
/// been mined). A tx-hash in `tx_keys` with no live reference is an
/// orphan — the secret scalar for a transaction the wallet has
/// forgotten exists, which is both a secret-handling leak and a sign
/// that the garbage-collection logic is broken.
///
/// The `spending_tx_hash` leg is what keeps retention alive for a
/// no-change outbound tx: such a tx produces no owned output, so once
/// it confirms (leaving `pending_tx_hashes`) the *only* live
/// references to its txid are the spent rows it consumed.
///
/// `tx_notes` and `attributes` are deliberately *not* part of this
/// check: user-authored notes may legitimately reference an arbitrary
/// txid (e.g. an incoming payment from a friend, recorded before the
/// scanner has caught up), and stripping them on load would lose
/// user data.
fn check_tx_keys_no_orphans(
    ledger: &LedgerBlock,
    tx_meta: &TxMetaBlock,
    sync_state: &SyncStateBlock,
) -> Result<(), WalletLedgerError> {
    if tx_meta.tx_keys.is_empty() {
        return Ok(());
    }

    let mut live: HashSet<[u8; 32]> = HashSet::with_capacity(
        ledger.transfers.len()
            + tx_meta.scanned_pool_txs.len()
            + sync_state.pending_tx_hashes.len(),
    );
    for t in &ledger.transfers {
        // `live` unifies typed transfer hashes with the still-raw `tx_meta` /
        // `pending_tx_hashes` keys; convert at this boundary.
        live.insert(t.tx_hash.to_bytes());
        // Spend-quadruple leg (F-9): the confirmed tx that spent this
        // output keeps its retained secret live even when it produced
        // no owned output of its own.
        if let Some(spending) = &t.spending_tx_hash {
            live.insert(spending.to_bytes());
        }
        // F14 lock: a network-exposed spend awaiting confirmation is a
        // tracked tx — its secret must not be collected in the window
        // between broadcast-accept and refresh-observed confirmation.
        if let Some(lock) = &t.awaiting_confirmation {
            live.insert(lock.tx_hash.to_bytes());
        }
    }
    for h in tx_meta.scanned_pool_txs.keys() {
        live.insert(*h);
    }
    for h in &sync_state.pending_tx_hashes {
        live.insert(*h);
    }

    if let Some(orphan) = tx_meta.tx_keys.keys().find(|k| !live.contains(*k)) {
        return Err(invariant_error(
            INV_TX_KEYS_NO_ORPHANS,
            format!(
                "tx_meta.tx_keys contains an entry for tx_hash = {} that does not appear in \
                 ledger.transfers (tx_hash / spending_tx_hash / awaiting_confirmation), \
                 tx_meta.scanned_pool_txs, or sync_state.pending_tx_hashes",
                hex::encode(orphan)
            ),
        ));
    }
    Ok(())
}

/// I-3. The reorg-detection window is a rolling `(height, hash)`
/// tail the scanner keeps just behind the tip. Two invariants are
/// bundled here because they fail the same way (the window is
/// corrupt, whatever the cause): strict ascending order on height
/// (no duplicates, no decreases) and the final entry no taller than
/// the reported tip. A reorg window with a taller entry than the
/// tip would imply the scanner observed a block it has not yet
/// processed — impossible under the scanner's single-writer
/// invariant.
fn check_reorg_trail_monotonic(ledger: &LedgerBlock) -> Result<(), WalletLedgerError> {
    let blocks = &ledger.reorg_blocks.blocks;
    if blocks.is_empty() {
        return Ok(());
    }

    let mut prev: Option<u64> = None;
    for (i, (h, _hash)) in blocks.iter().enumerate() {
        if let Some(p) = prev {
            if *h <= p {
                return Err(invariant_error(
                    INV_REORG_TRAIL_MONOTONIC,
                    format!(
                        "reorg_blocks[{i}].height = {h} is not strictly greater than \
                         reorg_blocks[{}].height = {p}",
                        i - 1
                    ),
                ));
            }
        }
        prev = Some(*h);
    }

    // Last entry must not exceed the tip — the rolling window is
    // always a *suffix* of the scanned range.
    let last = prev.expect("non-empty blocks must have set prev");
    let tip = ledger.tip.synced_height;
    if last > tip {
        return Err(invariant_error(
            INV_REORG_TRAIL_MONOTONIC,
            format!("reorg_blocks tail height = {last} exceeds tip.synced_height = {tip}"),
        ));
    }
    Ok(())
}

/// I-4. Spend-tracking fields on [`TransferDetails`] are three
/// independent `Option<…>` + `bool` slots, but the valid shapes form
/// a small closed set:
///
/// * `spent = false` → `spent_height = None`. Any other combination
///   is incoherent (we cannot have a "not spent" output with a spend
///   height).
/// * `spent = true`  → `key_image = Some`. `spent_height` is `None`
///   while the spend is **in flight** — optimistically marked when the
///   wallet submits the spending tx, before any block confirms it — and
///   `Some` once a refresh scans the confirming block (a reorg that
///   orphans that block reverts the output to unspent). A spent output
///   without a recorded key image cannot have been spent by this wallet.
///
/// Separately, no two transfers may share the same `Some(key_image)`:
/// a key image uniquely identifies the output being spent, and two
/// transfers with the same image are either double-spend state or a
/// crashed-write that duplicated a transfer. `key_image = None` is
/// fine on multiple transfers (an output observed before the key
/// image has been derived).
fn check_spent_state_consistent(ledger: &LedgerBlock) -> Result<(), WalletLedgerError> {
    let mut seen_images: HashSet<KeyImage> = HashSet::with_capacity(ledger.transfers.len());
    for (i, t) in ledger.transfers.iter().enumerate() {
        check_spend_triple(i, t)?;
        if let Some(k) = t.key_image {
            if !seen_images.insert(k) {
                return Err(invariant_error(
                    INV_SPENT_STATE_CONSISTENT,
                    format!(
                        "transfers[{i}] reuses key_image {} already observed on an earlier \
                         transfer; key images must be unique across transfers",
                        hex::encode(k.as_bytes())
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn check_spend_triple(idx: usize, t: &TransferDetails) -> Result<(), WalletLedgerError> {
    match (t.spent, t.spent_height.is_some(), t.key_image.is_some()) {
        // Two valid shapes. (a) not-yet-spent: `spent = false`, no height; key_image
        // may be None or Some (the scanner derives it before spend). (b) a spend by
        // this wallet: `spent = true` with a key image — `spent_height` is `None`
        // while the spend is **in flight** (optimistically marked at submit by
        // `finalize_submit_accept`, before any block confirms it) and `Some` once a
        // refresh scans the confirming block. The scan fills in the height; a reorg
        // that orphans the confirming block reverts a confirmed spend to unspent
        // (`LedgerIndexes::handle_reorg`).
        (false, false, _) | (true, _, true) => Ok(()),
        (false, true, _) => Err(invariant_error(
            INV_SPENT_STATE_CONSISTENT,
            format!(
                "transfers[{idx}] has spent = false but spent_height = Some; a not-yet-spent \
                 output cannot carry a spend height"
            ),
        )),
        (true, _, false) => Err(invariant_error(
            INV_SPENT_STATE_CONSISTENT,
            format!(
                "transfers[{idx}] has spent = true but key_image = None; a spent output must \
                 record the key image that identified the spend"
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests: one positive (default bundle) plus one negative per invariant. Each
// negative test constructs the minimum `WalletLedger` that trips exactly
// one check and asserts on the stable `invariant` name.
// ---------------------------------------------------------------------------

/// I-5 (`send-journal-lock-equivalence`). The F14 awaiting-confirmation
/// field on a transfer is a **derived cache** of `send_journal` dispatch
/// facts (`WALLET_SEND_RECORD.md` C2 / P3-1a): until PR-SJ-1b deletes
/// the field, both representations must agree.
///
/// Forward: every locked transfer has a journal row in `Dispatched`
/// state whose `lock_baseline` equals the lock's baseline and whose
/// carried input set contains the transfer's gindex. Reverse: every
/// `Dispatched` row with a baseline has each carried input — **when
/// present in the ledger** (a mid-rescan ledger may not have replayed
/// the row yet) — either spent (confirmed evidence supersedes) or
/// locked by exactly this tx at exactly this baseline.
fn check_send_journal_lock_equivalence(
    ledger: &LedgerBlock,
    journal: &crate::send_journal_block::SendJournalBlock,
) -> Result<(), WalletLedgerError> {
    use crate::send_journal_block::SendState;

    for (idx, td) in ledger.transfers.iter().enumerate() {
        let Some(lock) = &td.awaiting_confirmation else {
            continue;
        };
        let key = lock.tx_hash.to_bytes();
        let Some(row) = journal.rows.get(&key) else {
            return Err(invariant_error(
                INV_SEND_JOURNAL_LOCK_EQUIVALENCE,
                format!("transfers[{idx}] holds an F14 lock for a tx with no send-journal row"),
            ));
        };
        if row.state != SendState::Dispatched {
            return Err(invariant_error(
                INV_SEND_JOURNAL_LOCK_EQUIVALENCE,
                format!(
                    "transfers[{idx}] holds an F14 lock but the journal row is {:?}, not Dispatched",
                    row.state
                ),
            ));
        }
        if row.lock_baseline != Some(lock.accepted_at_height) {
            return Err(invariant_error(
                INV_SEND_JOURNAL_LOCK_EQUIVALENCE,
                format!(
                    "transfers[{idx}] lock baseline {} != journal lock_baseline {:?}",
                    lock.accepted_at_height, row.lock_baseline
                ),
            ));
        }
        if !row
            .inputs
            .iter()
            .any(|i| i.gindex == td.global_output_index)
        {
            return Err(invariant_error(
                INV_SEND_JOURNAL_LOCK_EQUIVALENCE,
                format!(
                    "transfers[{idx}] (gindex {}) locked by a tx whose journal row does not carry it",
                    td.global_output_index
                ),
            ));
        }
    }

    for (txid, row) in &journal.rows {
        if row.state != SendState::Dispatched {
            continue;
        }
        let Some(base) = row.lock_baseline else {
            continue;
        };
        for inp in &row.inputs {
            let Some(td) = ledger
                .transfers
                .iter()
                .find(|t| t.global_output_index == inp.gindex)
            else {
                continue; // mid-rescan: not replayed yet — reconciler re-locks on arrival
            };
            if td.spent {
                continue; // confirmed evidence supersedes the lock
            }
            match &td.awaiting_confirmation {
                Some(lock)
                    if lock.tx_hash.to_bytes() == *txid && lock.accepted_at_height == base => {}
                other => {
                    return Err(invariant_error(
                        INV_SEND_JOURNAL_LOCK_EQUIVALENCE,
                        format!(
                            "journal row {} carries gindex {} but the transfer's lock is {:?}",
                            hex::encode(txid),
                            inp.gindex,
                            other
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_curve_primitives::Commitment;

    use crate::{
        bookkeeping_block::BookkeepingBlock,
        ledger_block::{BlockchainTip, LedgerBlock, ReorgBlocks},
        staking_block::StakingBlock,
        sync_state_block::SyncStateBlock,
        transfer::{TransferDetails, SPENDABLE_AGE},
        tx_meta_block::{ScannedPoolTx, TxMetaBlock, TxSecretKey, TxSecretKeys},
    };
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    /// Minimum-viable transfer at a chosen `block_height`. Returns a
    /// not-yet-spent output with no key image; individual tests
    /// override whatever field(s) they need.
    fn mk_transfer(seed: u8, block_height: u64) -> TransferDetails {
        TransferDetails {
            tx_hash: shekyl_types::TxHash::from_bytes([seed; 32]),
            internal_output_index: u64::from(seed),
            global_output_index: u64::from(seed),
            block_height,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1_000),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            awaiting_confirmation: None,
            spending_tx_hash: None,
            source_ciphertext: None,
            output_handle: None,
            eligible_height: block_height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
            receive_attribution: crate::ReceiveAttribution::default(),
        }
    }

    fn assert_invariant(err: WalletLedgerError, expected: &'static str) {
        match err {
            WalletLedgerError::InvariantFailed { invariant, detail } => {
                assert_eq!(
                    invariant, expected,
                    "unexpected invariant name (detail: {detail})"
                );
            }
            other => panic!("expected InvariantFailed({expected}), got {other:?}"),
        }
    }

    #[test]
    fn default_bundle_passes_all_invariants() {
        let w = WalletLedger::empty();
        w.check_invariants().expect("empty bundle is consistent");
        w.preflight_save().expect("empty bundle is save-safe");
    }

    #[test]
    fn populated_consistent_bundle_passes() {
        let transfers = vec![mk_transfer(1, 10), mk_transfer(2, 15), mk_transfer(3, 20)];
        let ledger = LedgerBlock::new(
            transfers,
            BlockchainTip::new(30, [0xAA; 32]),
            ReorgBlocks {
                blocks: vec![(28, [1; 32]), (29, [2; 32]), (30, [0xAA; 32])],
            },
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        w.check_invariants().expect("populated-consistent bundle");
    }

    #[test]
    fn tip_below_transfer_height_is_refused() {
        let transfers = vec![mk_transfer(1, 1_000)];
        let ledger = LedgerBlock::new(
            transfers,
            BlockchainTip::new(500, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_TIP_NOT_BELOW_TRANSFER,
        );
    }

    #[test]
    fn orphan_tx_key_is_refused() {
        // tx_keys entry for a hash that appears nowhere else.
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            [0x77; 32],
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0; 32])),
            },
        );
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            BookkeepingBlock::empty(),
            tx_meta,
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(w.check_invariants().unwrap_err(), INV_TX_KEYS_NO_ORPHANS);
    }

    #[test]
    fn tx_key_referenced_by_pending_is_accepted() {
        let txid = [0x77; 32];
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0; 32])),
            },
        );
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let mut sync = SyncStateBlock::empty();
        sync.pending_tx_hashes = vec![txid];
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            BookkeepingBlock::empty(),
            tx_meta,
            sync,
            StakingBlock::empty(),
        );
        w.check_invariants().expect("pending ref satisfies I-2");
    }

    #[test]
    fn tx_key_referenced_by_pool_is_accepted() {
        let txid = [0x77; 32];
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0; 32])),
            },
        );
        let mut pool = BTreeMap::new();
        pool.insert(txid, ScannedPoolTx::default());
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), pool);
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            BookkeepingBlock::empty(),
            tx_meta,
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        w.check_invariants().expect("pool ref satisfies I-2");
    }

    /// WI-RPC-3 F-9 spend-quadruple: a no-change outbound tx produces no
    /// owned output, so after confirmation its *only* live references
    /// are the spent rows' `spending_tx_hash`. The retained secret must
    /// stay I-2-live through that leg alone.
    #[test]
    fn tx_key_referenced_by_spending_tx_hash_is_accepted() {
        let txid = [0x77; 32];
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0; 32])),
            },
        );
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        // The spent row's own tx_hash differs from `txid`; only the
        // `spending_tx_hash` leg satisfies I-2 here.
        let mut spent_row = mk_transfer(0x11, 10);
        spent_row.spent = true;
        spent_row.spent_height = Some(20);
        spent_row.key_image = Some(shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(
            [0x33; 32],
        ));
        spent_row.spending_tx_hash = Some(shekyl_types::TxHash::from_bytes(txid));
        let ledger = LedgerBlock::new(
            vec![spent_row],
            BlockchainTip::new(30, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            tx_meta,
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        w.check_invariants()
            .expect("spending_tx_hash ref satisfies I-2");
    }

    /// F14 lock leg: a network-exposed spend awaiting confirmation is a
    /// tracked tx; its secret must not be orphaned in the window between
    /// broadcast-accept and refresh-observed confirmation.
    #[test]
    fn tx_key_referenced_by_awaiting_confirmation_is_accepted() {
        let txid = [0x77; 32];
        let mut tx_keys = BTreeMap::new();
        tx_keys.insert(
            txid,
            TxSecretKeys {
                primary: TxSecretKey::new(Zeroizing::new([0; 32])),
            },
        );
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let mut locked_row = mk_transfer(0x11, 10);
        locked_row.awaiting_confirmation = Some(crate::transfer::AwaitingConfirmation {
            tx_hash: shekyl_types::TxHash::from_bytes(txid),
            accepted_at_height: 25,
        });
        let ledger = LedgerBlock::new(
            vec![locked_row],
            BlockchainTip::new(30, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let mut w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            tx_meta,
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        {
            // The equivalence invariant (I-5) requires the lock's owning
            // journal row: dispatch facts the F14 cache derives from.
            use crate::send_journal_block::{SendInputRef, SendRecord, SendState};
            w.send_journal.rows.insert(
                txid,
                SendRecord {
                    dispatched_at_height: 20,
                    fee: 5,
                    recipients: Vec::new(),
                    change_amount: 0,
                    inputs: vec![SendInputRef {
                        gindex: 0x11,
                        amount: 1,
                    }],
                    lock_baseline: Some(25),
                    state: SendState::Dispatched,
                },
            );
        }
        w.check_invariants()
            .expect("awaiting_confirmation ref satisfies I-2");
    }

    #[test]
    fn reorg_trail_out_of_order_is_refused() {
        let ledger = LedgerBlock::new(
            Vec::new(),
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks {
                blocks: vec![(10, [1; 32]), (9, [2; 32])],
            },
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
    }

    #[test]
    fn reorg_trail_duplicate_height_is_refused() {
        let ledger = LedgerBlock::new(
            Vec::new(),
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks {
                blocks: vec![(10, [1; 32]), (10, [2; 32])],
            },
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
    }

    #[test]
    fn reorg_trail_above_tip_is_refused() {
        let ledger = LedgerBlock::new(
            Vec::new(),
            BlockchainTip::new(10, [0xAA; 32]),
            ReorgBlocks {
                blocks: vec![(11, [1; 32])],
            },
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
    }

    #[test]
    fn spent_in_flight_without_height_is_allowed() {
        // The in-flight (optimistically-spent) shape: marked spent at submit, with a
        // key image, but no confirming height until a refresh scans the block. This is
        // the state `finalize_submit_accept` produces; the invariant must admit it.
        let mut t = mk_transfer(1, 10);
        t.spent = true;
        t.spent_height = None;
        t.key_image = Some(KeyImage::from_canonical_bytes([1; 32]));
        let ledger = LedgerBlock::new(
            vec![t],
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert!(
            w.check_invariants().is_ok(),
            "in-flight spend (spent, no height, key_image present) must be valid"
        );
    }

    #[test]
    fn spent_in_flight_without_key_image_is_refused() {
        // In flight or confirmed, a spent output must carry the key image it was spent
        // by — relaxing the height requirement must not relax the key-image one.
        let mut t = mk_transfer(1, 10);
        t.spent = true;
        t.spent_height = None;
        t.key_image = None;
        let ledger = LedgerBlock::new(
            vec![t],
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_SPENT_STATE_CONSISTENT,
        );
    }

    #[test]
    fn spent_without_key_image_is_refused() {
        let mut t = mk_transfer(1, 10);
        t.spent = true;
        t.spent_height = Some(20);
        t.key_image = None;
        let ledger = LedgerBlock::new(
            vec![t],
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_SPENT_STATE_CONSISTENT,
        );
    }

    #[test]
    fn not_spent_with_spent_height_is_refused() {
        let mut t = mk_transfer(1, 10);
        t.spent = false;
        t.spent_height = Some(20);
        let ledger = LedgerBlock::new(
            vec![t],
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_SPENT_STATE_CONSISTENT,
        );
    }

    #[test]
    fn duplicate_key_image_is_refused() {
        let mut t1 = mk_transfer(1, 10);
        let mut t2 = mk_transfer(2, 15);
        t1.spent = true;
        t1.spent_height = Some(20);
        t1.key_image = Some(KeyImage::from_canonical_bytes([0xCC; 32]));
        t2.spent = true;
        t2.spent_height = Some(30);
        t2.key_image = Some(KeyImage::from_canonical_bytes([0xCC; 32]));
        let ledger = LedgerBlock::new(
            vec![t1, t2],
            BlockchainTip::new(100, [0xAA; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_SPENT_STATE_CONSISTENT,
        );
    }

    #[test]
    fn preflight_save_returns_typed_error_without_panicking() {
        // Construct a ledger that violates I-1. In release builds the
        // debug_assert is compiled out, so this assertion verifies the
        // typed-error return. The debug-build path is exercised by the
        // same check_invariants() call via `assert_invariant` above.
        let transfers = vec![mk_transfer(1, 100)];
        let ledger = LedgerBlock::new(
            transfers,
            BlockchainTip::new(50, [0; 32]),
            ReorgBlocks::default(),
        );
        let w = WalletLedger::new(
            ledger,
            BookkeepingBlock::empty(),
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
            StakingBlock::empty(),
        );
        // preflight_save runs debug_assert! in debug builds; skip the
        // assertion there to keep the test identical across profiles.
        #[cfg(debug_assertions)]
        let outcome = w.check_invariants();
        #[cfg(not(debug_assertions))]
        let outcome = w.preflight_save();
        assert_invariant(outcome.unwrap_err(), INV_TIP_NOT_BELOW_TRANSFER);
    }
}
