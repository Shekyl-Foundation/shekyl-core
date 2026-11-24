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
//! # The closed set
//!
//! The invariants are derived from the §3.6 plan in
//! `docs/MID_REWIRE_HARDENING.md`, with two of the rows adjusted to
//! match the block shapes actually present in this crate (the plan
//! explicitly sanctions such adjustment on landing). A fifth,
//! `send-journal-lock-equivalence` (I-5), held the line while the F14
//! `awaiting_confirmation` field was a derived cache of journal facts
//! (`WALLET_SEND_RECORD.md` P3-1a); PR-SJ-1b deleted the field, and the
//! invariant retired with it — consumers now derive the lock set from
//! the journal directly, so there are no longer two representations to
//! keep equal. The closed set:
//!
//! | Stable name                          | Cross-block relationship                                                              |
//! |--------------------------------------|---------------------------------------------------------------------------------------|
//! | `tip-height-not-below-transfer`      | `ledger.tip.synced_height >= max(ledger.transfers[*].block_height)`                   |
//! | `tx-keys-no-orphans`                 | Every tx-hash in `tx_meta.tx_keys` appears in a live reference (transfer tx_hash / spending_tx_hash, pool, pending, or a non-terminal-or-abandoned send-journal row) |
//! | `reorg-trail-monotonic`              | `ledger.reorg_blocks.blocks` is strictly ascending and capped by `tip.synced_height`  |
//! | `spent-state-consistent`             | Within `ledger.transfers`: spend-triple self-consistency + key-image uniqueness       |
//! | `group-payees-stored`                | Within `send_journal`: every group a row pays has its address stored, and every stored address parses and hashes to the fingerprint it is kept under (R-37) |
//!
//! The last is the load check that holds a fingerprint read from a file
//! to what [`crate::GroupFingerprint`] promises in memory: it names a
//! group address the wallet holds.
//!
//! # Cost
//!
//! Every check is O(n) in the number of transfers (or map keys), with
//! a single `HashSet<[u8; 32]>` allocated for `spent-state-consistent`
//! and `tx-keys-no-orphans`. For a 10 k-transfer wallet the combined
//! pass is comfortably under 100 µs on the hardware used by the
//! commit-3.2 benchmark — far below the Argon2id cost already paid on
//! the open path, and not a concern for any `crypto_bench_*` threshold.

use std::collections::{BTreeSet, HashSet};

use shekyl_crypto_pq::key_image::KeyImage;

use crate::{
    error::WalletLedgerError, group_payee::GroupFingerprint, ledger_block::LedgerBlock,
    send_journal_block::SendJournalBlock, sync_state_block::SyncStateBlock,
    transfer::TransferDetails, tx_meta_block::TxMetaBlock, wallet_ledger::WalletLedger,
};
use shekyl_types::BlockHeight;

/// Stable machine-readable name for invariant I-1.
pub const INV_TIP_NOT_BELOW_TRANSFER: &str = "tip-height-not-below-transfer";

/// Stable machine-readable name for invariant I-2.
pub const INV_TX_KEYS_NO_ORPHANS: &str = "tx-keys-no-orphans";

/// Stable machine-readable name for invariant I-3.
pub const INV_REORG_TRAIL_MONOTONIC: &str = "reorg-trail-monotonic";

/// Stable machine-readable name for invariant I-4.
pub const INV_SPENT_STATE_CONSISTENT: &str = "spent-state-consistent";

/// Stable machine-readable name for invariant I-6 (I-5 is retired; module
/// docs).
pub const INV_GROUP_PAYEES_STORED: &str = "group-payees-stored";

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
        check_tx_keys_no_orphans(
            &self.ledger,
            &self.tx_meta,
            &self.sync_state,
            &self.send_journal,
        )?;
        check_reorg_trail_monotonic(&self.ledger)?;
        check_spent_state_consistent(&self.ledger)?;
        check_group_payees_stored(&self.send_journal)?;
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
/// spend-quadruple), a scanned pool entry (we saw it in mempool), the
/// user-submitted pending list (we originated it and it has not yet
/// been mined), or a send-journal row in a non-terminal-or-`Abandoned`
/// state (`WALLET_SEND_RECORD.md` P3-4 — after `abandon_send` migrates
/// the pending entry, the journal row is the reference the retained
/// secret lives by; PR-SJ-1b also covers the broadcast-accept →
/// confirmation window that the retired F14 field once pinned). A
/// tx-hash in `tx_keys` with no live reference is
/// an orphan — the secret scalar for a transaction the wallet has
/// forgotten exists, which is both a secret-handling leak and a sign
/// that the garbage-collection logic is broken.
///
/// The `spending_tx_hash` leg is what keeps retention alive for a
/// no-change outbound tx: such a tx produces no owned output, so once
/// it confirms (leaving `pending_tx_hashes`) the *only* live
/// references to its txid are the spent rows it consumed.
///
/// `tx_notes` is deliberately *not* part of this check. A note is set only
/// on a transaction the wallet knows ([`WalletLedger::set_note`] refuses an
/// unknown txid), so notes do not create orphans at write time — but a tx
/// that was known when annotated can leave the live set later (a reorg drops
/// a confirmed transfer), and stripping the note on load would lose user
/// data. So notes ride along on load regardless; the membership rule lives at
/// the write door, not in this load-time invariant.
fn check_tx_keys_no_orphans(
    ledger: &LedgerBlock,
    tx_meta: &TxMetaBlock,
    sync_state: &SyncStateBlock,
    send_journal: &crate::send_journal_block::SendJournalBlock,
) -> Result<(), WalletLedgerError> {
    if tx_meta.tx_keys.is_empty() {
        return Ok(());
    }

    let mut live: HashSet<[u8; 32]> = HashSet::with_capacity(
        ledger.transfers.len()
            + tx_meta.scanned_pool_txs.len()
            + sync_state.pending_tx_hashes.len()
            + send_journal.rows.len(),
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
        // (The former F14-lock leg retired with the field at PR-SJ-1b:
        // a lock's owning journal row is Dispatched or Abandoned, both
        // covered by the journal leg below — the broadcast-accept →
        // confirmation window keeps its secret through that leg.)
    }
    for h in tx_meta.scanned_pool_txs.keys() {
        live.insert(*h);
    }
    for h in &sync_state.pending_tx_hashes {
        live.insert(*h);
    }
    // P3-4 journal leg: a retention-holding row is itself a live
    // reference (mirrored by `reconcile_tx_key_retention`).
    for (h, row) in &send_journal.rows {
        if row.state.holds_tx_key_retention() {
            live.insert(*h);
        }
    }

    if let Some(orphan) = tx_meta.tx_keys.keys().find(|k| !live.contains(*k)) {
        return Err(invariant_error(
            INV_TX_KEYS_NO_ORPHANS,
            format!(
                "tx_meta.tx_keys contains an entry for tx_hash = {} that does not appear in \
                 ledger.transfers (tx_hash / spending_tx_hash), \
                 tx_meta.scanned_pool_txs, sync_state.pending_tx_hashes, or a send-journal \
                 row in a non-terminal-or-abandoned state",
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

    let mut prev: Option<BlockHeight> = None;
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

fn check_group_payees_stored(journal: &SendJournalBlock) -> Result<(), WalletLedgerError> {
    let paid: BTreeSet<&GroupFingerprint> = journal.groups_paid().collect();
    if let Some(missing) = paid
        .iter()
        .find(|fingerprint| journal.group_address(fingerprint).is_none())
    {
        return Err(invariant_error(
            INV_GROUP_PAYEES_STORED,
            format!(
                "a send-journal row pays the group {} and the journal stores no address for it",
                hex::encode(missing.as_bytes())
            ),
        ));
    }
    for (fingerprint, stored) in journal.group_payees() {
        let named = hex::encode(fingerprint.as_bytes());
        let address = stored.address().map_err(|err| {
            invariant_error(
                INV_GROUP_PAYEES_STORED,
                format!("the stored address of the group {named} does not parse: {err}"),
            )
        })?;
        if GroupFingerprint::of(&address) != *fingerprint {
            return Err(invariant_error(
                INV_GROUP_PAYEES_STORED,
                format!("the address stored for the group {named} is another group's"),
            ));
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

#[cfg(test)]
#[path = "invariants_tests.rs"]
mod tests;
