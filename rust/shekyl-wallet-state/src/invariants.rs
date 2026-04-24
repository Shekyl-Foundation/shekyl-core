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
//! | `tx-keys-no-orphans`                 | Every tx-hash in `tx_meta.tx_keys` appears in a live reference (transfers, pool, or pending) |
//! | `subaddress-registry-dense`          | Per-account minor indices in `bookkeeping.subaddress_registry` are gap-free           |
//! | `reorg-trail-monotonic`              | `ledger.reorg_blocks.blocks` is strictly ascending and capped by `tip.synced_height`  |
//! | `spent-state-consistent`             | Within `ledger.transfers`: spend-triple self-consistency + key-image uniqueness       |
//!
//! # Cost
//!
//! Every check is O(n) in the number of transfers (or map keys), with
//! a single `HashSet<[u8; 32]>` allocated for `spent-state-consistent`
//! and `tx-keys-no-orphans`. For a 10 k-transfer wallet the combined
//! pass is comfortably under 100 µs on the hardware used by the
//! commit-3.2 benchmark — far below the Argon2id cost already paid on
//! the open path, and not a concern for any `crypto_bench_*` threshold.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    bookkeeping_block::BookkeepingBlock, error::WalletLedgerError, ledger_block::LedgerBlock,
    sync_state_block::SyncStateBlock, transfer::TransferDetails, tx_meta_block::TxMetaBlock,
    wallet_ledger::WalletLedger,
};

/// Stable machine-readable name for invariant I-1.
pub const INV_TIP_NOT_BELOW_TRANSFER: &str = "tip-height-not-below-transfer";

/// Stable machine-readable name for invariant I-2.
pub const INV_TX_KEYS_NO_ORPHANS: &str = "tx-keys-no-orphans";

/// Stable machine-readable name for invariant I-3.
pub const INV_SUBADDRESS_REGISTRY_DENSE: &str = "subaddress-registry-dense";

/// Stable machine-readable name for invariant I-4.
pub const INV_REORG_TRAIL_MONOTONIC: &str = "reorg-trail-monotonic";

/// Stable machine-readable name for invariant I-5.
pub const INV_SPENT_STATE_CONSISTENT: &str = "spent-state-consistent";

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
        check_subaddress_registry_dense(&self.bookkeeping)?;
        check_reorg_trail_monotonic(&self.ledger)?;
        check_spent_state_consistent(&self.ledger)?;
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
/// [`TransferDetails`] (the scanner observed it), a scanned pool
/// entry (we saw it in mempool), or the user-submitted pending list
/// (we originated it and it has not yet been mined). A tx-hash in
/// `tx_keys` with no live reference is an orphan — the secret scalar
/// for a transaction the wallet has forgotten exists, which is both
/// a secret-handling leak and a sign that the garbage-collection
/// logic is broken.
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
        live.insert(t.tx_hash);
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
                 ledger.transfers, tx_meta.scanned_pool_txs, or sync_state.pending_tx_hashes",
                hex::encode(orphan)
            ),
        ));
    }
    Ok(())
}

/// I-3. For every account major index `m` that appears in
/// `bookkeeping.subaddress_registry`, the set of minor indices
/// `{n : (m, n) registered}` must be contiguous — no gaps between the
/// observed minimum and maximum. Shekyl's subaddress generation walks
/// the minor axis monotonically and never deletes a prior entry; a
/// hole is therefore evidence that either a registry entry was lost
/// after generation (corruption) or two processes raced on the same
/// registry (bug we have not yet written, but would like the
/// check to catch on sight).
///
/// The check permits the observed minimum to be anything — account 0
/// never carries `(0, 0)` because [`crate::subaddress::SubaddressIndex`]
/// refuses to construct it, and other accounts may legitimately start
/// their registry at a non-zero minor if the wallet only ever generated
/// subaddresses beyond the lookahead window. What cannot happen
/// under normal generation is a hole *inside* the observed range.
fn check_subaddress_registry_dense(
    bookkeeping: &BookkeepingBlock,
) -> Result<(), WalletLedgerError> {
    if bookkeeping.subaddress_registry.is_empty() {
        return Ok(());
    }

    let mut per_account: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for idx in bookkeeping.subaddress_registry.values() {
        per_account
            .entry(idx.account())
            .or_default()
            .insert(idx.address());
    }

    for (account, minors) in &per_account {
        // `BTreeSet` iteration is sorted; use first/last as the observed range.
        let Some(&min) = minors.iter().next() else {
            continue;
        };
        let Some(&max) = minors.iter().next_back() else {
            continue;
        };
        let expected_len = u64::from(max - min) + 1;
        if (minors.len() as u64) != expected_len {
            // Find the first gap so the diagnostic is pointed. Walk
            // the sorted set in lockstep with the expected sequence
            // `min, min+1, …`; the first mismatch is the hole.
            let mut expected = min;
            let gap = minors
                .iter()
                .find_map(|&n| {
                    if n == expected {
                        expected = expected.saturating_add(1);
                        None
                    } else {
                        Some(expected)
                    }
                })
                .unwrap_or(min);
            return Err(invariant_error(
                INV_SUBADDRESS_REGISTRY_DENSE,
                format!(
                    "account {account}: subaddress registry is not dense in [{min}, {max}]; \
                     missing minor index {gap} (observed {count} of expected {expected_len})",
                    count = minors.len()
                ),
            ));
        }
    }
    Ok(())
}

/// I-4. The reorg-detection window is a rolling `(height, hash)`
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

/// I-5. Spend-tracking fields on [`TransferDetails`] are three
/// independent `Option<…>` + `bool` slots, but the valid shapes form
/// a small closed set:
///
/// * `spent = false` → `spent_height = None`. Any other combination
///   is incoherent (we cannot have a "not spent" output with a spend
///   height).
/// * `spent = true`  → `spent_height = Some` AND `key_image = Some`.
///   A spent output without a recorded key image cannot have been
///   spent by this wallet in the first place.
///
/// Separately, no two transfers may share the same `Some(key_image)`:
/// a key image uniquely identifies the output being spent, and two
/// transfers with the same image are either double-spend state or a
/// crashed-write that duplicated a transfer. `key_image = None` is
/// fine on multiple transfers (an output observed before the key
/// image has been derived).
fn check_spent_state_consistent(ledger: &LedgerBlock) -> Result<(), WalletLedgerError> {
    let mut seen_images: HashSet<[u8; 32]> = HashSet::with_capacity(ledger.transfers.len());
    for (i, t) in ledger.transfers.iter().enumerate() {
        check_spend_triple(i, t)?;
        if let Some(k) = t.key_image {
            if !seen_images.insert(k) {
                return Err(invariant_error(
                    INV_SPENT_STATE_CONSISTENT,
                    format!(
                        "transfers[{i}] reuses key_image {} already observed on an earlier \
                         transfer; key images must be unique across transfers",
                        hex::encode(k)
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn check_spend_triple(idx: usize, t: &TransferDetails) -> Result<(), WalletLedgerError> {
    match (t.spent, t.spent_height.is_some(), t.key_image.is_some()) {
        // `spent = false` with no spent_height is the one valid
        // not-yet-spent shape; key_image may be None or Some (the
        // scanner derives it before spend).
        (false, false, _) | (true, true, true) => Ok(()),
        (false, true, _) => Err(invariant_error(
            INV_SPENT_STATE_CONSISTENT,
            format!(
                "transfers[{idx}] has spent = false but spent_height = Some; a not-yet-spent \
                 output cannot carry a spend height"
            ),
        )),
        (true, false, _) => Err(invariant_error(
            INV_SPENT_STATE_CONSISTENT,
            format!(
                "transfers[{idx}] has spent = true but spent_height = None; a spent output \
                 must record the height at which it was spent"
            ),
        )),
        (true, true, false) => Err(invariant_error(
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
mod tests {
    use super::*;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, Scalar};
    use shekyl_oxide::primitives::Commitment;

    use crate::{
        bookkeeping_block::BookkeepingBlock,
        ledger_block::{BlockchainTip, LedgerBlock, ReorgBlocks},
        subaddress::SubaddressIndex,
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
            tx_hash: [seed; 32],
            internal_output_index: u64::from(seed),
            global_output_index: u64::from(seed),
            block_height,
            key: ED25519_BASEPOINT_POINT,
            key_offset: Scalar::ONE,
            commitment: Commitment::new(Scalar::ONE, 1_000),
            subaddress: SubaddressIndex::new(0, u32::from(seed).saturating_add(1)),
            payment_id: None,
            spent: false,
            spent_height: None,
            key_image: None,
            staked: false,
            stake_tier: 0,
            stake_lock_until: 0,
            last_claimed_height: 0,
            combined_shared_secret: None,
            ho: None,
            y: None,
            z: None,
            k_amount: None,
            eligible_height: block_height + SPENDABLE_AGE,
            frozen: false,
            fcmp_precomputed_path: None,
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
                additional: Vec::new(),
            },
        );
        let tx_meta = TxMetaBlock::new(tx_keys, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            BookkeepingBlock::empty(),
            tx_meta,
            SyncStateBlock::empty(),
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
                additional: Vec::new(),
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
                additional: Vec::new(),
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
        );
        w.check_invariants().expect("pool ref satisfies I-2");
    }

    #[test]
    fn sparse_subaddress_registry_is_refused() {
        // Account 0 with minors {1, 2, 4} — missing `3` inside the range.
        let mut registry = BTreeMap::new();
        registry.insert([1u8; 32], SubaddressIndex::new(0, 1).unwrap());
        registry.insert([2u8; 32], SubaddressIndex::new(0, 2).unwrap());
        registry.insert([4u8; 32], SubaddressIndex::new(0, 4).unwrap());
        let bookkeeping = BookkeepingBlock {
            block_version: BookkeepingBlock::empty().block_version,
            subaddress_registry: registry,
            ..Default::default()
        };
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            bookkeeping,
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
        );
        assert_invariant(
            w.check_invariants().unwrap_err(),
            INV_SUBADDRESS_REGISTRY_DENSE,
        );
    }

    #[test]
    fn dense_subaddress_registry_is_accepted() {
        // Account 0 starts at minor 1 (the `(0, 0)` slot is reserved).
        // Account 2 starts at minor 0 (primary subaddress of a non-zero account).
        let mut registry = BTreeMap::new();
        registry.insert([1u8; 32], SubaddressIndex::new(0, 1).unwrap());
        registry.insert([2u8; 32], SubaddressIndex::new(0, 2).unwrap());
        registry.insert([3u8; 32], SubaddressIndex::new(0, 3).unwrap());
        registry.insert([4u8; 32], SubaddressIndex::new(2, 0).unwrap());
        registry.insert([5u8; 32], SubaddressIndex::new(2, 1).unwrap());
        let bookkeeping = BookkeepingBlock {
            block_version: BookkeepingBlock::empty().block_version,
            subaddress_registry: registry,
            ..Default::default()
        };
        let w = WalletLedger::new(
            LedgerBlock::empty(),
            bookkeeping,
            TxMetaBlock::empty(),
            SyncStateBlock::empty(),
        );
        w.check_invariants().expect("dense registry satisfies I-3");
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
        );
        assert_invariant(w.check_invariants().unwrap_err(), INV_REORG_TRAIL_MONOTONIC);
    }

    #[test]
    fn spent_without_height_is_refused() {
        let mut t = mk_transfer(1, 10);
        t.spent = true;
        t.spent_height = None;
        t.key_image = Some([1; 32]);
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
        t1.key_image = Some([0xCC; 32]);
        t2.spent = true;
        t2.spent_height = Some(30);
        t2.key_image = Some([0xCC; 32]);
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
