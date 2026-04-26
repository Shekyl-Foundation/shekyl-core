// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Typed scan-result event vocabulary consumed by
//! [`Wallet::apply_scan_result`](crate::wallet::Wallet).
//!
//! `ScanResult` is the value the Phase 2a `Wallet::refresh()`
//! pipeline produces from a scanner pass and that
//! `apply_scan_result` merges into [`shekyl_wallet_state::WalletLedger`]
//! plus [`shekyl_wallet_state::LedgerIndexes`] under the wallet's
//! `&mut self` borrow. The type lives in `shekyl-wallet-core` (not
//! `shekyl-scanner`) because it is the *consumer contract* of the
//! merge, not a scanner internal — see
//! `docs/V3_WALLET_DECISION_LOG.md` (`ScanResult` type, 2026-04-25,
//! "Crate location" subsection) for the rationale.
//!
//! # Additive event vocabulary
//!
//! Every field of `ScanResult` represents an event the ledger
//! learned about during a scanner pass:
//!
//! - [`ScanResult::new_transfers`] — outputs identified as belonging
//!   to the wallet, with the block context needed to call
//!   [`shekyl_wallet_state::LedgerIndexes::ingest_block`] via the
//!   scanner's [`shekyl_scanner::LedgerIndexesExt::process_scanned_outputs`].
//! - [`ScanResult::spent_key_images`] — key images whose preimage
//!   transfer the wallet already owns, observed in the scanned blocks'
//!   inputs. Drives
//!   [`shekyl_wallet_state::LedgerIndexes::detect_spends`].
//! - [`ScanResult::stake_events`] — staker-pool aggregate state
//!   updates derived from the block. Phase 1 ships the
//!   [`StakeEvent::Accrual`] variant; further variants land alongside
//!   the `StakeInstance` work in Phase 2b.
//! - [`ScanResult::reorg_rewind`] — when present, indicates the
//!   merge must drop wallet state at and above
//!   [`ReorgRewind::fork_height`] before applying any of the
//!   per-height events. Drives
//!   [`shekyl_wallet_state::LedgerIndexes::handle_reorg`].
//!
//! Adding a new event class is a single-site change: extend the
//! type, extend the apply match, add the scanner emission. Compare
//! to wallet2's "scattered side effects" model where every scanning
//! site can mutate ledger state in arbitrary ways.
//!
//! # Why per-block hashes are recorded
//!
//! [`ScanResult::block_hashes`] carries one entry per height in
//! [`ScanResult::processed_height_range`], not just one per block
//! that produced events. The persisted ledger advances
//! `synced_height` *exactly once per scanned block* — even when the
//! block had zero events — so the merge needs the block hash for
//! every height. This is a small concession beyond the Decision Log
//! sketch's literal field list (which used "// ... typed event
//! vocabulary" as the placeholder for "everything else needed to
//! drive the merge"); the per-height hash record is what closes
//! the gap between event-vocabulary and the persisted-ledger advance
//! contract.
//!
//! # Secrets in `RecoveredWalletOutput`
//!
//! [`DetectedTransfer::output`] carries a
//! [`shekyl_scanner::RecoveredWalletOutput`] with PQC re-derivation
//! material (`ho`, `y`, `z`, `k_amount`, `combined_shared_secret`)
//! that the merge promotes into the persisted
//! [`shekyl_wallet_state::TransferDetails`]. Those fields are
//! `Zeroizing<[u8; 32]>` and the wrapping `RecoveredWalletOutput`
//! is `ZeroizeOnDrop`, so dropping a `ScanResult` (whether applied
//! or discarded) wipes the secret material in place. `ScanResult`
//! itself does not derive `ZeroizeOnDrop` — `Range<u64>` is not
//! `Zeroize` — but composition handles the secret-wipe contract.

use std::ops::Range;

use shekyl_scanner::RecoveredWalletOutput;
use shekyl_wallet_state::staker_pool::AccrualRecord;

/// Typed value produced by a scanner pass and consumed by
/// [`Wallet::apply_scan_result`](crate::wallet::Wallet).
///
/// Construct directly during refresh in Phase 2a; for tests and
/// examples, the field-by-field public construction is intentional
/// (no `new(...)` constructor) because every event class is
/// independently meaningful.
///
/// # Invariants checked at merge time
///
/// `apply_scan_result` rejects with
/// [`crate::wallet::RefreshError::ConcurrentMutation`] when:
///
/// - [`Self::processed_height_range`]`.start`
///   ≠ `wallet.synced_height + 1`, or
/// - [`Self::parent_hash`] does not agree with the wallet's stored
///   block hash at `start - 1` (must be `Some(h)` matching, except
///   when `start == 1`, where it must be `None`).
///
/// See `docs/V3_WALLET_DECISION_LOG.md`
/// (`Wallet::apply_scan_result invariants`, 2026-04-26) for the
/// rationale.
pub struct ScanResult {
    /// Half-open height range covered by this result. Empty ranges
    /// (`start == end`) are permitted and apply as a no-op.
    pub processed_height_range: Range<u64>,

    /// Block hash of `processed_height_range.start - 1`, or `None`
    /// when `start == 1` (the genesis case). The merge checks this
    /// against the wallet's recorded chain at `start - 1`; a
    /// mismatch indicates the wallet's chain shifted under the
    /// scanner between snapshot and merge.
    pub parent_hash: Option<[u8; 32]>,

    /// Block hashes for every height in `processed_height_range`,
    /// ascending. Every height must appear exactly once. The merge
    /// drives [`shekyl_wallet_state::LedgerIndexes::ingest_block`]
    /// per height, even when no events fired in that block, because
    /// the persisted ledger's `synced_height` advances per block.
    pub block_hashes: Vec<(u64, [u8; 32])>,

    /// Outputs detected as belonging to the wallet. Each carries
    /// the block height it was found in; the merge groups them by
    /// height and feeds each group through
    /// [`shekyl_scanner::LedgerIndexesExt::process_scanned_outputs`].
    pub new_transfers: Vec<DetectedTransfer>,

    /// Key images observed in scanned blocks' inputs whose
    /// preimage outputs the wallet already owns. The merge groups
    /// them by height and feeds each group through
    /// [`shekyl_wallet_state::LedgerIndexes::detect_spends`].
    pub spent_key_images: Vec<KeyImageObserved>,

    /// Staker-pool aggregate state events derived from the
    /// scanned blocks. Phase 1 supports the
    /// [`StakeEvent::Accrual`] variant; further variants land
    /// alongside the `StakeInstance` work in Phase 2b.
    pub stake_events: Vec<StakeEvent>,

    /// When `Some`, the merge must roll wallet state back to the
    /// fork height *before* applying any per-height events. Drives
    /// [`shekyl_wallet_state::LedgerIndexes::handle_reorg`].
    pub reorg_rewind: Option<ReorgRewind>,
}

/// A scanner-detected output: the recovered output material plus
/// the block height it was found in. The merge groups these by
/// height and feeds each group through the scanner's
/// `process_scanned_outputs` extension method to populate the
/// persisted [`shekyl_wallet_state::TransferDetails`].
pub struct DetectedTransfer {
    /// Block height the output was found in. Must be a height
    /// present in the enclosing
    /// [`ScanResult::processed_height_range`].
    pub block_height: u64,

    /// Recovered output material. Holds PQC re-derivation values
    /// (`ho`, `y`, `z`, `k_amount`, `combined_shared_secret`) that
    /// the merge promotes into the persisted ledger's
    /// `TransferDetails`. `ZeroizeOnDrop` — secrets are wiped when
    /// the enclosing `ScanResult` is dropped.
    pub output: RecoveredWalletOutput,
}

/// A key image observed in a scanned block's input set. The merge
/// looks up the matching wallet-owned transfer and marks it spent
/// at `block_height`.
#[derive(Debug, Clone)]
pub struct KeyImageObserved {
    /// Block height the spend was observed in.
    pub block_height: u64,

    /// Compressed key-image bytes as they appear on-wire in
    /// `Input::ToKey { key_image, .. }` and
    /// `Input::StakeClaim { key_image, .. }`.
    pub key_image: [u8; 32],
}

/// A staker-pool aggregate state event. The variant set is
/// `#[non_exhaustive]` because Phase 2b's `StakeInstance` work adds
/// further variants (broadcast / unconfirmed / locked / accruing
/// transitions); existing call sites must be prepared for new
/// variants without breaking.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StakeEvent {
    /// Per-height accrual record produced by the staker-pool
    /// aggregator. Drives
    /// [`shekyl_wallet_state::LedgerIndexes::insert_accrual`].
    Accrual {
        /// Block height this accrual applies to.
        height: u64,
        /// Accrual aggregate (emission, fee pool, weighted stake)
        /// for the height.
        record: AccrualRecord,
    },
}

/// A reorg-rewind directive. When present in a [`ScanResult`], the
/// merge first drops wallet transfers and stored block hashes at and
/// above `fork_height`, then applies the rest of the result against
/// the rewound state. The scanner is responsible for choosing
/// `fork_height` such that block hashes diverged at-and-above and
/// agreed below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorgRewind {
    /// Height at and above which the wallet's recorded chain
    /// diverged from the daemon's; the merge drops state at and
    /// above this height before applying the rest of the result.
    pub fork_height: u64,
}

impl ScanResult {
    /// An empty result covering the half-open range `start..start`
    /// — applies as a no-op but still passes the start-height
    /// invariant when `start == wallet.synced_height + 1`.
    ///
    /// Useful in tests and as the "nothing-changed" return shape
    /// from a scanner pass that found the wallet already at tip.
    pub fn empty_at(start: u64, parent_hash: Option<[u8; 32]>) -> Self {
        Self {
            processed_height_range: start..start,
            parent_hash,
            block_hashes: Vec::new(),
            new_transfers: Vec::new(),
            spent_key_images: Vec::new(),
            stake_events: Vec::new(),
            reorg_rewind: None,
        }
    }
}
