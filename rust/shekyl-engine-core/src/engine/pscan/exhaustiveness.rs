// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! 2d-1 SP-6 — the **exhaustiveness** primitive: proof that `P` scanned *every*
//! block in a contiguous range on the chain it was served.
//!
//! This is the **covered** half of the reconcile evidence (the *matches* half is
//! the decode/output-tree path that keeps using `curve_tree_root`). It proves
//! *exhaustiveness* — "no block in `[low, high)` was silently skipped" — **not**
//! *canonicity* ("this is the most-work chain"). Per the trust-anchor resolution
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md`), most-work needs a comparison
//! against competitors a single source cannot supply, so canonicity is a posture /
//! 2d-2-multi-source property carried as a separate token at the GC, never a
//! wallet-side PoW check. This primitive is pure light-client hashing.
//!
//! ## Recompute-from-received, not compare-to-claimed
//!
//! The load-bearing discipline: continuity recomputes `hash(block[N])` **from the
//! received material** — [`Block::hash`] rebuilds `tx_tree_hash` from the inline
//! miner body + the received `transaction_hashes`, reforms the `pow_blob`, and
//! hashes it — then checks that against `block[N+1].previous`. Comparing
//! `block[N+1].previous` against a *stored* or *source-claimed* hash of `N` would
//! verify the links but not that the tx set `P` holds is the committed one. Two
//! checks, two levels:
//!
//! - **Continuity (the hash list is complete-and-committed):** `block[N].previous`
//!   chains to the recomputed hash of its predecessor, anchored at `anchor` (the
//!   recomputed hash of the block before the batch, or the genesis `previous`).
//! - **Per-body (each body matches its committed hash):**
//!   `transactions[i].hash() == transaction_hashes[i]`. The miner tx is covered
//!   automatically — its body is inline and its hash is the first Merkle leaf in
//!   [`Block::hash`].
//!
//! A height gap, a continuity break, a body mismatch, or a missing/extra body is an
//! [`ExhaustivenessError`] — never a silent skip (and the `BlockSource` already
//! refuses to fabricate a `None`).

use shekyl_scanner::ScannableBlock;
use shekyl_types::BlockHeight;

/// A height range `[low, high)` `P` AFFIRMATIVELY, EXHAUSTIVELY verified on the
/// chain it was served (recompute-and-chain continuity + per-body tx-hash).
///
/// Claims **exhaustiveness**, NOT **canonicity**: that `[low, high)` is the
/// most-work chain is a separate token the 2d-2 GC requires alongside this — see the
/// module docs. Constructible **only** by [`verify_exhaustive`], never by hand, so a
/// `VerifiedRange` value is proof the verified scan path produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // transient — SP-6's `PReconcileSet` + the cursor advance are the lib consumers.
pub(crate) struct VerifiedRange {
    low: BlockHeight,
    high: BlockHeight,
}

#[allow(dead_code)] // transient — consumers land with SP-6 / the sweep wiring.
impl VerifiedRange {
    /// The first verified height (inclusive).
    pub(crate) fn low(&self) -> BlockHeight {
        self.low
    }

    /// One past the last verified height (exclusive).
    pub(crate) fn high(&self) -> BlockHeight {
        self.high
    }

    /// Whether the range covers no blocks (`low == high`).
    pub(crate) fn is_empty(&self) -> bool {
        self.low == self.high
    }
}

/// Why exhaustiveness verification failed. Every arm is a refusal to advance the
/// verified frontier — the cursor stays where the last block verified, never past a
/// gap or a tampered block.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[allow(dead_code)] // transient — surfaced through the sweep once wired.
pub(crate) enum ExhaustivenessError {
    /// The first block's `previous` did not match `anchor` (the recomputed hash of
    /// the block before the batch). The batch does not attach to the verified
    /// frontier.
    #[error("block {height} does not chain to the anchor")]
    AnchorMismatch { height: u64 },
    /// `block[N].previous` did not match the recomputed hash of `block[N-1]` — a
    /// gap, reorg, or a forged/substituted block within the batch.
    #[error("continuity break at block {height}: previous does not match the recomputed predecessor hash")]
    ContinuityBreak { height: u64 },
    /// A fetched transaction body's hash did not match its committed
    /// `transaction_hashes[i]` — a tampered or substituted body.
    #[error("body mismatch at block {height}, tx index {index}")]
    BodyMismatch { height: u64, index: usize },
    /// The fetched-body count did not equal the committed `transaction_hashes`
    /// count — a missing or extra body.
    #[error("body count mismatch at block {height}: {bodies} bodies vs {hashes} committed hashes")]
    BodyCountMismatch {
        height: u64,
        bodies: usize,
        hashes: usize,
    },
}

/// Verify that `blocks` — a contiguous batch starting at `first_height`, in height
/// order — is an exhaustively-scanned chain attaching to `anchor` (the recomputed
/// hash of the block before `blocks[0]`, or the genesis `previous` when `blocks[0]`
/// is genesis). Returns the [`VerifiedRange`] `[first_height, first_height + n)`.
///
/// Each block's `previous` is checked against the running recomputed hash (the
/// `anchor` for the first, [`Block::hash`] of the prior for the rest), and every
/// fetched body is checked against its committed hash. The first failure stops
/// verification with an [`ExhaustivenessError`] — the caller advances the cursor
/// only over the returned range, never past a refusal.
#[allow(dead_code)] // transient — the sweep + SP-6 are the lib consumers.
pub(crate) fn verify_exhaustive(
    first_height: BlockHeight,
    anchor: [u8; 32],
    blocks: &[ScannableBlock],
) -> Result<VerifiedRange, ExhaustivenessError> {
    let first = first_height.to_raw();
    let mut expected_previous = anchor;

    for (offset, sb) in blocks.iter().enumerate() {
        let height = first + offset as u64;

        // Continuity: this block's `previous` must match the recomputed hash of its
        // predecessor (the anchor for the first block, else the prior block's hash).
        if sb.block.header.previous != expected_previous {
            return Err(if offset == 0 {
                ExhaustivenessError::AnchorMismatch { height }
            } else {
                ExhaustivenessError::ContinuityBreak { height }
            });
        }

        // Per-body integrity: each fetched body hashes to its committed hash. The
        // miner tx is covered by `Block::hash` (its body is inline, its hash the
        // first Merkle leaf), so only the non-miner bodies need an explicit check.
        let hashes = &sb.block.transaction_hashes;
        if sb.transactions.len() != hashes.len() {
            return Err(ExhaustivenessError::BodyCountMismatch {
                height,
                bodies: sb.transactions.len(),
                hashes: hashes.len(),
            });
        }
        for (index, tx) in sb.transactions.iter().enumerate() {
            if tx.hash() != hashes[index] {
                return Err(ExhaustivenessError::BodyMismatch { height, index });
            }
        }

        // Advance: recompute this block's hash (from received material) as the
        // anchor for the next block.
        expected_previous = sb.block.hash();
    }

    Ok(VerifiedRange {
        low: first_height,
        high: BlockHeight::from_raw(first + blocks.len() as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::test_support::make_synthetic_block;

    const ANCHOR: [u8; 32] = [0xA0; 32];

    /// Build a chain of `len` synthetic blocks starting at `first`, each correctly
    /// linked to the recomputed hash of its predecessor (the first to `ANCHOR`).
    fn chain(first: u64, len: u64) -> Vec<ScannableBlock> {
        let mut blocks = Vec::new();
        let mut prev = ANCHOR;
        for h in first..first + len {
            let sb = make_synthetic_block(h, prev);
            prev = sb.block.hash();
            blocks.push(sb);
        }
        blocks
    }

    #[test]
    fn accepts_a_correctly_chained_batch() {
        let blocks = chain(100, 4);
        let covered = verify_exhaustive(BlockHeight::from_raw(100), ANCHOR, &blocks)
            .expect("a correctly chained, body-consistent batch verifies");
        assert_eq!(covered.low(), BlockHeight::from_raw(100));
        assert_eq!(covered.high(), BlockHeight::from_raw(104));
        assert!(!covered.is_empty());
    }

    #[test]
    fn empty_batch_is_an_empty_range() {
        let covered = verify_exhaustive(BlockHeight::from_raw(7), ANCHOR, &[]).expect("empty");
        assert!(covered.is_empty());
        assert_eq!(covered.low(), covered.high());
    }

    #[test]
    fn rejects_an_anchor_mismatch() {
        // First block's `previous` doesn't attach to the supplied anchor.
        let blocks = chain(100, 2);
        let err = verify_exhaustive(BlockHeight::from_raw(100), [0xFF; 32], &blocks)
            .expect_err("a batch that doesn't chain to the anchor must fail");
        assert_eq!(err, ExhaustivenessError::AnchorMismatch { height: 100 });
    }

    #[test]
    fn rejects_a_continuity_break() {
        // A forged middle block: block[101] does NOT chain to the recomputed hash of
        // block[100] (compare-to-claimed would miss this; recompute catches it).
        let mut blocks = chain(100, 3);
        blocks[1] = make_synthetic_block(101, [0xBB; 32]); // wrong `previous`
        let err = verify_exhaustive(BlockHeight::from_raw(100), ANCHOR, &blocks)
            .expect_err("a broken link must fail");
        assert_eq!(err, ExhaustivenessError::ContinuityBreak { height: 101 });
    }

    #[test]
    fn rejects_a_body_hash_mismatch() {
        // A single block whose `previous` matches the anchor (continuity OK) but
        // whose fetched body does not hash to its committed `transaction_hashes`.
        let mut sb = make_synthetic_block(100, ANCHOR);
        let body = sb.block.miner_transaction.clone();
        sb.transactions = vec![body];
        sb.block.transaction_hashes = vec![[0x77; 32]]; // != body.hash()
        let err = verify_exhaustive(BlockHeight::from_raw(100), ANCHOR, &[sb])
            .expect_err("a tampered body must fail");
        assert_eq!(
            err,
            ExhaustivenessError::BodyMismatch {
                height: 100,
                index: 0
            }
        );
    }

    #[test]
    fn accepts_a_body_that_matches_its_committed_hash() {
        let mut sb = make_synthetic_block(100, ANCHOR);
        let body = sb.block.miner_transaction.clone();
        sb.block.transaction_hashes = vec![body.hash()];
        sb.transactions = vec![body];
        let covered = verify_exhaustive(BlockHeight::from_raw(100), ANCHOR, &[sb])
            .expect("a body matching its committed hash verifies");
        assert_eq!(covered.high(), BlockHeight::from_raw(101));
    }

    #[test]
    fn rejects_a_body_count_mismatch() {
        // Committed one tx hash but delivered zero bodies (a withheld body).
        let mut sb = make_synthetic_block(100, ANCHOR);
        sb.block.transaction_hashes = vec![[0x11; 32]];
        sb.transactions = vec![];
        let err = verify_exhaustive(BlockHeight::from_raw(100), ANCHOR, &[sb])
            .expect_err("a missing body must fail");
        assert_eq!(
            err,
            ExhaustivenessError::BodyCountMismatch {
                height: 100,
                bodies: 0,
                hashes: 1
            }
        );
    }
}
