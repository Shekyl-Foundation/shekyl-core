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
//!
//! ## The archival fold (`WSS-Q16`)
//!
//! The frontier also carries the chain's cumulative archival length through
//! its last block, checked block by block from genesis, and the height at
//! which each shard it has passed closed ([`ArchivalFold`]). Every block the
//! scan verifies reports the daemon's running total; the scan checks each
//! block's step against the txid-bound lengths of its own transactions, so
//! nothing in the fold is taken on a daemon's word
//! (`docs/design/WALLET_SIDE_STORE.md` §6.4.3, §6.5.9).

use serde::{Deserialize, Serialize};
use shekyl_types::{shard_of, shard_start, ArchivalLength, BlockHeight, ShardId, ShardRowsDigest};

use crate::error::WalletLedgerError;

/// Schema version of the `P`-scan cursor. V1 was a bare `synced_height`; v2 added
/// the verified-frontier `frontier_hash` — the cursor became a `(height, hash)`
/// verified frontier, not a bare height (see the struct docs for why). **v3 adds
/// the [`ArchivalFold`]**: the checked cumulative archival length at the frontier
/// and each passed shard's close height (`WSS-Q16`). Any field
/// addition / removal / renaming bumps this; loads that see a different version
/// **refuse rather than migrate** (the `StakingBlock` precedent). No v1→v2 migration
/// exists because no deployed wallet ever persisted a v1 `.wallet.pscan` (the scan
/// task that writes it is not yet wired into the lifecycle).
pub const PSCAN_CURSOR_VERSION: u32 = 3;

/// Diagnostic name of this block. The outer [`crate::pscan_state::PScanState`]
/// gate uses [`crate::pscan_state::PSCAN_STATE_BLOCK`]; a mismatch here is a
/// different refusal and must not be reported as that file's format.
pub const PSCAN_CURSOR_BLOCK: &str = "pscan_cursor";

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
    /// every block in `[0, synced_height)` — an **exclusive-end ordinal**
    /// (C6 `next_height`), not an inclusive tip. Last verified block is
    /// `block[synced_height − 1]`. Contrast [`crate::LedgerBlock::height`],
    /// which is the newest ingested block's own height (inclusive). Both
    /// are [`BlockHeight`]; they are not interchangeable.
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
    /// The checked archival fold through `block[synced_height − 1]`
    /// ([`ArchivalFold`]); empty at genesis.
    archival: ArchivalFold,
}

impl PScanCursor {
    /// A fresh cursor at genesis (`synced_height = 0`, `frontier_hash = [0; 32]`,
    /// an empty fold) — the pre-scan state. The zero `frontier_hash` is the anchor
    /// block 0 chains to (its `previous`), matching `verify_exhaustive`'s
    /// genesis-anchor case.
    pub fn genesis() -> Self {
        Self::at(BlockHeight::ZERO, [0u8; 32], ArchivalFold::genesis())
    }

    /// A cursor pinned to `synced_height` with the recomputed hash of the last
    /// verified block (`frontier_hash`) and the checked fold through it, stamped
    /// with the current version.
    pub fn at(synced_height: BlockHeight, frontier_hash: [u8; 32], archival: ArchivalFold) -> Self {
        Self {
            version: PSCAN_CURSOR_VERSION,
            synced_height,
            frontier_hash,
            archival,
        }
    }

    /// The checked archival fold at the frontier.
    pub fn archival(&self) -> &ArchivalFold {
        &self.archival
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
        // Version first, body second — see [`crate::version_gate`]: postcard
        // carries no framing, so a stale blob decoded under the current
        // declaration fails as corruption before any post-decode check can
        // name the version. The gate reads only the leading varint.
        crate::version_gate::gate_leading_version(bytes, PSCAN_CURSOR_BLOCK, PSCAN_CURSOR_VERSION)?;
        let cursor: Self = postcard::from_bytes(bytes)?;
        cursor.archival.check()?;
        Ok(cursor)
    }

    /// Version gate and the fold's shape. Called automatically by
    /// [`Self::from_postcard_bytes`]; the outer
    /// [`PScanState`](crate::pscan_state::PScanState) loader calls it on the
    /// cursor it decodes.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(self.version, PSCAN_CURSOR_BLOCK, PSCAN_CURSOR_VERSION)?;
        self.archival.check()
    }
}

/// The invariant name [`ArchivalFold::check`] reports on a decoded fold whose
/// close list disagrees with its total.
pub const ARCHIVAL_FOLD_INVARIANT: &str = "pscan-archival-fold-closes-match-total";

/// Where one shard closed, as the P-scan verified it: the closing block's
/// height and recomputed hash, the checked archival total entering that
/// block (through the block before it), and the shard's rows digest.
///
/// The entering total is what places the closing block's transactions: the
/// first of them sits at `before` plus the coinbase's length (zero), and each
/// one after it at the running sum of the bound lengths before it. The hash
/// pins the block itself, so a walk that re-reads a shard's blocks checks
/// both ends against this record and takes neither a total nor a block on a
/// daemon's word.
///
/// The rows digest ([`ShardRowsDigest`]) is the chain over the shard's
/// in-domain transactions' txid-bound rows, folded as the scan verified
/// them. A frame whose own digest equals it holds exactly the shard's
/// archival good, so a body store checks what it holds against this record
/// without asking a daemon.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct ShardClose {
    /// The closing block: the first whose running total reaches the shard's end.
    pub height: BlockHeight,
    /// The checked archival total through the block before it.
    pub before: ArchivalLength,
    /// The closing block's recomputed hash.
    pub hash: [u8; 32],
    /// The shard's rows digest.
    pub rows: ShardRowsDigest,
}

/// One verified block's step of the fold, as the scan computed it: the
/// block, the running total through it, the rows digest of every shard the
/// block closed (in shard order), and the running digest of the shard left
/// open after it. The scan derives all of it from txid-bound rows; the fold
/// checks that the shape agrees with the totals.
#[derive(Clone, Copy, Debug)]
pub struct BlockStep<'a> {
    /// The block's height.
    pub height: BlockHeight,
    /// The block's recomputed hash.
    pub hash: [u8; 32],
    /// The checked running total through the block.
    pub total: ArchivalLength,
    /// The rows digest of each shard this block closed, in shard order.
    pub closed: &'a [ShardRowsDigest],
    /// The running rows digest of the shard open after the block.
    pub open_rows: ShardRowsDigest,
}

/// The blocks that hold one closed shard's transactions, by their records.
///
/// A shard's first transaction sits in the block that closed the shard before
/// it (whose remaining transactions start the next shard), or at genesis for
/// shard 0. Its last sits in its own closing block. So shard `k` lies in
/// `opens.height ..= closes.height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardSpan {
    /// The previous shard's close, or `None` for shard 0, which opens at
    /// genesis with a zero total.
    pub opens: Option<ShardClose>,
    /// This shard's close.
    pub closes: ShardClose,
}

/// The chain's archival fold at the P-scan frontier (`WSS-Q16`): the cumulative
/// archival length through the frontier's last block, and where each shard
/// below it closed.
///
/// **Checked, not reported.** The P-scan verifies every block from genesis, and
/// for each one checks the daemon's reported running total against the previous
/// total plus the txid-bound archival lengths of the block's own transactions.
/// So the total here is the wallet's own sum, which every daemon reply after
/// genesis has had to agree with.
///
/// **Shard closes.** Shard `k` closes at the first block whose running total
/// reaches `(k + 1) · W` — consensus's `shard_close_height`
/// (`shekyl-chain-rules/src/archival/close.rs`). The list holds one
/// [`ShardClose`] per closed shard, in shard order, so `closes.len()` is always
/// `shard_of(total)`: the shards the fold has passed. A block that crosses two
/// boundaries closes two shards, with the same record.
///
/// Finality is the scan's, not this type's: the P-scan verifies only blocks
/// behind its finality horizon, so every close recorded here is at least that
/// deep.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct ArchivalFold {
    /// The checked cumulative archival length through the frontier's last block.
    total: ArchivalLength,
    /// `closes[k]` is where shard `k` closed.
    closes: Vec<ShardClose>,
    /// The running rows digest of the open shard, over its in-domain
    /// transactions so far. Sealed with the rest, so a batch boundary inside
    /// a shard does not lose it.
    open_rows: ShardRowsDigest,
}

impl ArchivalFold {
    /// The fold before genesis: nothing archived, no shard closed.
    pub fn genesis() -> Self {
        Self {
            total: ArchivalLength::ZERO,
            closes: Vec::new(),
            open_rows: ShardRowsDigest::EMPTY,
        }
    }

    /// A fold with `total`, the closes of every shard below it and the open
    /// shard's running digest, or `None` when the list is not well formed:
    /// one close per passed shard, in height order, each entering below its
    /// shard's end.
    pub fn new(
        total: ArchivalLength,
        closes: Vec<ShardClose>,
        open_rows: ShardRowsDigest,
    ) -> Option<Self> {
        let fold = Self {
            total,
            closes,
            open_rows,
        };
        fold.is_well_formed().then_some(fold)
    }

    /// Advance the fold in place by one verified block. The fold's own total is
    /// the total entering the block. `None`, with the fold unchanged, when the
    /// total shrinks, the block sits below the last close, or the closed list
    /// is not one digest per shard whose end the step reached.
    #[must_use]
    pub fn advance(&mut self, step: BlockStep<'_>) -> Option<()> {
        if step.total < self.total
            || self
                .closes
                .last()
                .is_some_and(|last| step.height < last.height)
        {
            return None;
        }
        let reached = shard_of(step.total)
            .to_raw()
            .checked_sub(self.closed_count())?;
        if u64::try_from(step.closed.len()).ok()? != reached {
            return None;
        }
        let entering = self.total;
        self.closes
            .extend(step.closed.iter().map(|rows| ShardClose {
                height: step.height,
                before: entering,
                hash: step.hash,
                rows: *rows,
            }));
        self.total = step.total;
        self.open_rows = step.open_rows;
        Some(())
    }

    /// The running rows digest of the open shard.
    pub fn open_rows(&self) -> ShardRowsDigest {
        self.open_rows
    }

    /// The checked cumulative archival length through the frontier's last block.
    pub fn total(&self) -> ArchivalLength {
        self.total
    }

    /// How many shards have closed: `shard_of(total)`.
    pub fn closed_count(&self) -> u64 {
        shard_of(self.total).to_raw()
    }

    /// Where `shard` closed, or `None` while it is open.
    pub fn close(&self, shard: ShardId) -> Option<ShardClose> {
        let index = usize::try_from(shard.to_raw()).ok()?;
        self.closes.get(index).copied()
    }

    /// The blocks that hold `shard`'s transactions, or `None` while it is open.
    pub fn span(&self, shard: ShardId) -> Option<ShardSpan> {
        let closes = self.close(shard)?;
        let opens = match shard.to_raw().checked_sub(1) {
            None => None,
            Some(previous) => Some(self.close(ShardId::from_raw(previous))?),
        };
        Some(ShardSpan { opens, closes })
    }

    fn is_well_formed(&self) -> bool {
        let count_matches =
            u64::try_from(self.closes.len()).is_ok_and(|n| n == self.closed_count());
        let in_order = self
            .closes
            .windows(2)
            .all(|pair| pair[0].height <= pair[1].height && pair[0].before <= pair[1].before);
        // The closing block of shard `k` is the first to reach `(k + 1)·W`, so
        // the total entering it is below that end.
        let each_enters_below_its_end = self.closes.iter().enumerate().all(|(k, close)| {
            u64::try_from(k)
                .ok()
                .and_then(|k| k.checked_add(1))
                .and_then(|next| shard_start(ShardId::from_raw(next)))
                .is_some_and(|end| close.before < end)
        });
        count_matches && in_order && each_enters_below_its_end
    }

    /// The load-side check: a decoded fold whose close list disagrees with its
    /// total is refused, never trusted.
    fn check(&self) -> Result<(), WalletLedgerError> {
        if self.is_well_formed() {
            return Ok(());
        }
        Err(WalletLedgerError::InvariantFailed {
            invariant: ARCHIVAL_FOLD_INVARIANT,
            detail: format!(
                "{} closes for a total of {} bytes ({} shards passed), or closes out of \
                 order or entering past their shard's end",
                self.closes.len(),
                self.total.to_raw(),
                self.closed_count()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::SHARD_LENGTH;

    fn bytes(n: u64) -> ArchivalLength {
        ArchivalLength::from_raw(n)
    }

    fn hash(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn rows(b: u8) -> ShardRowsDigest {
        ShardRowsDigest::from_bytes([b; 32])
    }

    /// Advance `fold` by a block at `height` (hash `[height; 32]`) whose
    /// running total is `total`, closing shards with `closed` digests.
    fn step(
        fold: &mut ArchivalFold,
        height: u8,
        total: u64,
        closed: &[ShardRowsDigest],
    ) -> Option<()> {
        fold.advance(BlockStep {
            height: BlockHeight::from_raw(u64::from(height)),
            hash: hash(height),
            total: bytes(total),
            closed,
            open_rows: rows(0xEE),
        })
    }

    #[test]
    fn a_block_that_reaches_a_shards_end_closes_it_there() {
        let w = SHARD_LENGTH.to_raw();
        let mut fold = ArchivalFold::genesis();
        step(&mut fold, 3, w - 1, &[]).expect("advances");
        assert_eq!(fold.closed_count(), 0, "one byte short of the end is open");
        assert_eq!(fold.close(ShardId::from_raw(0)), None);
        assert_eq!(fold.open_rows(), rows(0xEE), "the open digest is sealed");
        step(&mut fold, 4, w, &[rows(0xA0)]).expect("advances");
        assert_eq!(
            fold.close(ShardId::from_raw(0)),
            Some(ShardClose {
                height: BlockHeight::from_raw(4),
                before: bytes(w - 1),
                hash: hash(4),
                rows: rows(0xA0),
            }),
            "the first block whose total reaches (k + 1)·W closes k, entered at the total before it"
        );
    }

    #[test]
    fn one_block_crossing_two_ends_closes_both_at_its_height() {
        let w = SHARD_LENGTH.to_raw();
        let mut fold = ArchivalFold::genesis();
        step(&mut fold, 7, 2 * w + 5, &[rows(0xA0), rows(0xA1)]).expect("advances");
        assert_eq!(fold.closed_count(), 2);
        let close = |digest| ShardClose {
            height: BlockHeight::from_raw(7),
            before: ArchivalLength::ZERO,
            hash: hash(7),
            rows: digest,
        };
        assert_eq!(fold.close(ShardId::from_raw(0)), Some(close(rows(0xA0))));
        assert_eq!(fold.close(ShardId::from_raw(1)), Some(close(rows(0xA1))));
        assert_eq!(fold.close(ShardId::from_raw(2)), None);
    }

    #[test]
    fn a_step_whose_closed_digests_do_not_match_its_total_leaves_the_fold_unchanged() {
        let w = SHARD_LENGTH.to_raw();
        let mut fold = ArchivalFold::genesis();
        assert_eq!(step(&mut fold, 4, w, &[]), None, "a close with no digest");
        assert_eq!(
            step(&mut fold, 4, w - 1, &[rows(0xA0)]),
            None,
            "a digest with no close"
        );
        assert_eq!(fold, ArchivalFold::genesis());
    }

    #[test]
    fn a_span_runs_from_the_previous_close_to_its_own() {
        let w = SHARD_LENGTH.to_raw();
        let mut fold = ArchivalFold::genesis();
        step(&mut fold, 4, w + 10, &[rows(0xA0)]).expect("advances");
        step(&mut fold, 9, 2 * w, &[rows(0xA1)]).expect("advances");
        let first = fold.span(ShardId::from_raw(0)).expect("shard 0 closed");
        assert_eq!(first.opens, None, "shard 0 opens at genesis");
        assert_eq!(first.closes.height, BlockHeight::from_raw(4));
        let second = fold.span(ShardId::from_raw(1)).expect("shard 1 closed");
        assert_eq!(second.opens, Some(first.closes));
        assert_eq!(
            second.closes,
            ShardClose {
                height: BlockHeight::from_raw(9),
                before: bytes(w + 10),
                hash: hash(9),
                rows: rows(0xA1),
            }
        );
        assert_eq!(fold.span(ShardId::from_raw(2)), None, "shard 2 is open");
    }

    #[test]
    fn the_fold_never_shrinks_and_never_goes_back_in_height() {
        let w = SHARD_LENGTH.to_raw();
        let mut fold = ArchivalFold::genesis();
        step(&mut fold, 10, w, &[rows(0xA0)]).expect("advances");
        let sealed = fold.clone();
        assert_eq!(step(&mut fold, 11, w - 1, &[]), None);
        assert_eq!(step(&mut fold, 9, w, &[]), None);
        assert_eq!(fold, sealed);
    }

    #[test]
    fn a_decoded_fold_whose_closes_disagree_with_its_total_is_refused() {
        // Built through the private fields (reachable from this child module) and
        // serialized through the real path: two closes for a total that passes one.
        let close = |h: u64| ShardClose {
            height: BlockHeight::from_raw(h),
            before: ArchivalLength::ZERO,
            hash: hash(1),
            rows: rows(1),
        };
        let forged = PScanCursor {
            version: PSCAN_CURSOR_VERSION,
            synced_height: BlockHeight::from_raw(20),
            frontier_hash: [0u8; 32],
            archival: ArchivalFold {
                total: SHARD_LENGTH,
                closes: vec![close(5), close(6)],
                open_rows: ShardRowsDigest::EMPTY,
            },
        }
        .to_postcard_bytes()
        .expect("serialize");
        match PScanCursor::from_postcard_bytes(&forged) {
            Err(WalletLedgerError::InvariantFailed { invariant, .. }) => {
                assert_eq!(invariant, ARCHIVAL_FOLD_INVARIANT);
            }
            other => panic!("expected the fold invariant, got {other:?}"),
        }
        assert_eq!(
            ArchivalFold::new(SHARD_LENGTH, vec![], ShardRowsDigest::EMPTY),
            None,
            "the constructor refuses the same shape"
        );
    }

    #[test]
    fn a_close_entered_at_or_past_its_shards_end_is_refused() {
        // The closing block is the first to reach the end, so the total entering
        // it is below the end. A record entering at the end is not a close.
        let at_end = ShardClose {
            height: BlockHeight::from_raw(5),
            before: SHARD_LENGTH,
            hash: hash(5),
            rows: rows(5),
        };
        assert_eq!(
            ArchivalFold::new(SHARD_LENGTH, vec![at_end], ShardRowsDigest::EMPTY),
            None
        );
    }

    #[test]
    fn round_trips_and_preserves_frontier() {
        let mut fold = ArchivalFold::genesis();
        fold.advance(BlockStep {
            height: BlockHeight::from_raw(9_000),
            hash: hash(0x90),
            total: SHARD_LENGTH,
            closed: &[rows(0x91)],
            open_rows: rows(0x92),
        })
        .expect("a growing fold advances");
        let cursor = PScanCursor::at(BlockHeight::from_raw(12_345), [0xC9; 32], fold.clone());
        let bytes = cursor.to_postcard_bytes().expect("serialize");
        let back = PScanCursor::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, cursor);
        assert_eq!(back.synced_height(), BlockHeight::from_raw(12_345));
        assert_eq!(
            back.frontier_hash(),
            [0xC9; 32],
            "the frontier hash round-trips"
        );
        assert_eq!(back.archival(), &fold, "the fold round-trips");
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
        let cursor = PScanCursor::at(
            BlockHeight::from_raw(777),
            [0x5A; 32],
            ArchivalFold::genesis(),
        );
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
            archival: ArchivalFold::genesis(),
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
                assert_eq!(block, PSCAN_CURSOR_BLOCK);
                assert_eq!(file, PSCAN_CURSOR_VERSION + 1);
                assert_eq!(binary, PSCAN_CURSOR_VERSION);
            }
            other => panic!("expected version rejection, got {other:?}"),
        }
    }
}
