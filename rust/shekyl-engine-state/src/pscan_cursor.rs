// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-2 — [`PScanCursor`]: the archival persona (`P`) scan frontier.
//!
//! The single authoritative record of how far `P`'s firewalled scan has reached
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6 SP-2). It is a **distinct
//! newtype from the principal's `BlockchainTip`** — the compiler rejects passing
//! one where the other is expected, so the DQ4 cross-contamination is caught by
//! `cargo`, not by review.
//!
//! ## Crash-recovery: Design B (single frontier, resume-and-recompute)
//!
//! The cursor is the **one** durable scan-progress record. There is **no
//! forward-clamp on load** and no second "already-scanned" frontier: a scan
//! cursor has no chain-derived anchor to clamp to (unlike the slot floor, which
//! the bonded set anchors). On resume, `P` re-scans from the sealed
//! `synced_height` forward to the finality horizon; the per-epoch accrual is
//! idempotent (SP-4 `PFundingInflow`, in `shekyl-engine-core` — `pub(crate)`, so
//! not cross-crate-linkable here), so the re-scan is harmless. The safety
//! invariant is a **write discipline**, realized by the
//! scan loop (SP-5): persist the confirmed outputs durably, *then* seal the
//! cursor to that frontier — it **never seals past durable outputs**, so a crash
//! can only leave it at-or-behind real progress.
//!
//! ## Sealing
//!
//! This type provides the **postcard + version** half of the StakingBlock-class
//! seal (mirroring [`StakingBlock`](crate::staking_block::StakingBlock)). The
//! AEAD seal + crash-atomic `atomic_write_file` to a `P`-isolated file is the
//! engine layer's job (SP-5), exactly as the wallet ledger applies it to its
//! sub-blocks — the cursor stays a `P`-isolated record, not a principal-ledger
//! sub-block.

use serde::{Deserialize, Serialize};
use shekyl_types::BlockHeight;

use crate::error::WalletLedgerError;

/// Schema version of the `P`-scan cursor. V1 was a bare `synced_height`; **v2 adds
/// the verified-frontier `frontier_hash`** — the cursor is now a `(height, hash)`
/// verified frontier, not a bare height (see the struct docs for why). Any field
/// addition / removal / renaming bumps this; loads that see a different version
/// **refuse rather than migrate** (the `StakingBlock` precedent). No v1→v2 migration
/// exists because no deployed wallet ever persisted a v1 `.wallet.pscan` (the scan
/// task that writes it is not yet wired into the lifecycle).
pub const PSCAN_CURSOR_VERSION: u32 = 2;

/// `P`'s single authoritative durable scan frontier (SP-2).
///
/// Distinct from `BlockchainTip` by construction. The `version` is always
/// [`PSCAN_CURSOR_VERSION`] on construction and rejected on load if it does not
/// match.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PScanCursor {
    /// Per-cursor schema version — `PSCAN_CURSOR_VERSION` on construction,
    /// version-gated on load.
    version: u32,
    /// The one authoritative durable scan frontier: `P` has exhaustively verified
    /// every block up to (and including the seal-discipline's) this height.
    synced_height: BlockHeight,
    /// The recomputed block hash of the last verified block (`block[synced_height −
    /// 1]`), or the genesis `previous` (`[0; 32]`) at `synced_height == 0`.
    ///
    /// This makes the cursor a **verified `(height, hash)` frontier**, not a bare
    /// height: on resume the next batch's first block must chain to *this exact
    /// hash*, so a source cannot splice a different chain at the resume boundary. A
    /// height-only cursor structurally cannot refuse that splice (it can't say
    /// *which* chain's height N) — and under no-wallet-PoW a fabricated fork is free,
    /// so the only thing a forging source cannot change is a hash already in our own
    /// sealed state. Parity with the principal refresh's per-height `block_hash_at`
    /// continuity. A block hash is public chain state, not a secret.
    frontier_hash: [u8; 32],
}

impl PScanCursor {
    /// A fresh cursor at genesis (`synced_height = 0`, `frontier_hash = [0; 32]`) —
    /// the pre-scan state. The zero `frontier_hash` is the anchor block 0 chains to
    /// (its `previous`), matching `verify_exhaustive`'s genesis-anchor case.
    pub fn genesis() -> Self {
        Self::at(BlockHeight::ZERO, [0u8; 32])
    }

    /// A cursor pinned to `synced_height` with the recomputed hash of the last
    /// verified block (`frontier_hash`), stamped with the current version.
    pub fn at(synced_height: BlockHeight, frontier_hash: [u8; 32]) -> Self {
        Self {
            version: PSCAN_CURSOR_VERSION,
            synced_height,
            frontier_hash,
        }
    }

    /// The scan frontier.
    pub fn synced_height(&self) -> BlockHeight {
        self.synced_height
    }

    /// The recomputed hash of the last verified block — the anchor the next batch's
    /// first block must chain to on resume (the verified-frontier invariant).
    pub fn frontier_hash(&self) -> [u8; 32] {
        self.frontier_hash
    }

    /// The on-cursor schema version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Serialize to postcard bytes (the inner half of the seal; the engine
    /// applies the AEAD + atomic write).
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from [`Self::to_postcard_bytes`] output. **Refuses a version
    /// mismatch** — Design B's load is verify-and-decode only: no forward clamp,
    /// no `known_frontier`; the value is trusted as a resume point (a stale-low
    /// seal merely re-scans more, harmless under SP-4 idempotency).
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let cursor: Self = postcard::from_bytes(bytes)?;
        cursor.check_version()?;
        Ok(cursor)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed so a future composite loader can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.version != PSCAN_CURSOR_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "pscan_cursor",
                file: self.version,
                binary: PSCAN_CURSOR_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_preserves_frontier() {
        let cursor = PScanCursor::at(BlockHeight::from_raw(12_345), [0xC9; 32]);
        let bytes = cursor.to_postcard_bytes().expect("serialize");
        let back = PScanCursor::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, cursor);
        assert_eq!(back.synced_height(), BlockHeight::from_raw(12_345));
        assert_eq!(
            back.frontier_hash(),
            [0xC9; 32],
            "the frontier hash round-trips"
        );
    }

    #[test]
    fn genesis_is_height_zero_zero_anchor_current_version() {
        let cursor = PScanCursor::genesis();
        assert_eq!(cursor.synced_height(), BlockHeight::ZERO);
        assert_eq!(
            cursor.frontier_hash(),
            [0u8; 32],
            "genesis anchor is the zero `previous` block 0 chains to"
        );
        assert_eq!(cursor.version(), PSCAN_CURSOR_VERSION);
    }

    #[test]
    fn postcard_encoding_is_byte_stable() {
        let cursor = PScanCursor::at(BlockHeight::from_raw(777), [0x5A; 32]);
        let a = cursor.to_postcard_bytes().expect("serialize a");
        let b = PScanCursor::from_postcard_bytes(&a)
            .expect("deserialize")
            .to_postcard_bytes()
            .expect("serialize b");
        assert_eq!(a, b, "postcard encoding must be byte-stable");
    }

    #[test]
    fn rejects_a_version_mismatch_on_load() {
        // Construct a wrong-version cursor via its private fields (reachable from
        // this child module) and serialize it through the real `to_postcard_bytes`
        // path — no coupling to postcard's struct-vs-tuple encoding.
        let wrong = PScanCursor {
            version: PSCAN_CURSOR_VERSION + 1,
            synced_height: BlockHeight::from_raw(1),
            frontier_hash: [0u8; 32],
        };
        let forged = wrong
            .to_postcard_bytes()
            .expect("serialize wrong-version cursor");
        match PScanCursor::from_postcard_bytes(&forged) {
            Err(WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            }) => {
                assert_eq!(block, "pscan_cursor");
                assert_eq!(file, PSCAN_CURSOR_VERSION + 1);
                assert_eq!(binary, PSCAN_CURSOR_VERSION);
            }
            other => panic!("expected version rejection, got {other:?}"),
        }
    }
}
