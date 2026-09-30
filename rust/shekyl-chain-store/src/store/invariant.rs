// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `SI-` register's code form.
//!
//! One variant per **`built`** row of `STORE_INVARIANT_REGISTER.md` §2;
//! `check_store_invariant_register.py` holds the two to a bijection in both
//! directions, so a variant with no row and a `built` row with no variant
//! are each red. A `ruled` row has no variant until the increment that first
//! enforces it lands (rule 23: no symbol before its producer).
//!
//! A value of this type is the payload of
//! [`StoreError::InvariantViolated`](super::StoreError::InvariantViolated):
//! the store was handed something that breaks its own coherence, so either
//! the validator has a hole or the file is corrupt. It is **fatal** (register
//! §1) and it **never** becomes a consensus verdict — C2-R8 Q2's conversion
//! ban, gated by `check_store_error_conversion_ban.py`. Once S-CHAIN-W's
//! writer refuses one, the tip carries it (`ChainTip.connect`,
//! `DAEMON_REDB_STORE.md` §3.6.2) so an operator can read which belt caught
//! the hole; that is why the type is `Copy + Eq` and names its row.

use crate::codec::CodecError;

/// A store invariant that the store itself enforces at the write, named by
/// its register row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreInvariant {
    /// **SI-1** — `spent_keys` is a set: inserting a key image already
    /// present is fatal.
    ///
    /// The belt beneath CEN-L1 / CEN-I7. A validator that admits a
    /// double spend has a hole; this is the store refusing to record what
    /// the rule should have refused, not a second copy of the rule.
    KeyImageNotFresh,
    /// **SI-2** — a connecting block's parent is the block recorded at
    /// height−1, that block is the tip, and there is one block per height.
    ///
    /// Armed by the parent-is-tip pre-check in `connect` and by the
    /// insert-once handles on `blocks` / `block_heights` / `block_info` /
    /// `hf_versions` / `block_burn`.
    TipMismatch,
    /// **SI-3** — `tx_indices` is keyed by tx hash: inserting a hash already
    /// present is fatal (CEN-G1's belt; CEN-F5's corollary for the miner
    /// tx).
    TxHashNotFresh,
    /// **SI-4** — the curve-tree root at height *h*+1 is written exactly
    /// once per connect and is the root the verdict derived
    /// (`ValidatedBlock::root_after`, DRS-E3 `CTW-Q1`).
    RootRewritten,
    /// **SI-6** — the undo log's top entry is the tip height, and a pop
    /// consumes exactly that entry.
    ///
    /// Armed at the two places the journal and the tables can disagree:
    /// sealing a height's journal row when one is already recorded there
    /// (the tip moved without its row being consumed), and replaying an
    /// entry whose target is not in the state the entry says it left
    /// (something wrote around the journal). Either way the file's
    /// pre-images no longer describe its tables, so no pop can be trusted
    /// to land on a coherent state; the writer halts (DRS §3.6.2).
    UndoLogIncoherent {
        /// The height whose journal row is at issue.
        height: u64,
        /// Which disagreement was found.
        fault: UndoFault,
    },
    /// **SI-7** — every cell read decodes under its canonical codec; an
    /// undecodable or missing sealed cell is fatal.
    ///
    /// Codecs are strict (`codec` module docs), so this is never "an older
    /// layout" — that is
    /// [`StoreCannot::SchemaVersionMismatch`](super::StoreCannot::SchemaVersionMismatch),
    /// a refusal. Both header cells land in the seal's one transaction, so a
    /// store with a valid `schema_version` and a broken `apply_policy` was
    /// modified by something other than this crate. The same row covers
    /// every typed cell the store reads back, `undo_log` rows included.
    /// Rebuild from the block corpus; there is no repair.
    CellCorrupt {
        /// The cell's key — a `properties` key, or the table name for a
        /// table-valued cell.
        key: &'static str,
        /// What is wrong with it.
        fault: CellFault,
    },
    /// **SI-8** — accumulator arithmetic never wraps: every fold uses
    /// checked arithmetic and an overflow is fatal, never a saturate or a
    /// mint. `total_burned` is the fold this increment writes.
    FoldOverflow {
        /// The `properties` key of the cell whose fold overflowed.
        cell: &'static str,
    },
    /// **SI-13** — a recorded fold never *decreases*: a prefix sum the
    /// store only ever adds to (`block_info.cumulative_tx_count`, S-CHAIN-R;
    /// `block_info.cumulative_archival_len`, `SHT-Q2`, armed by the
    /// retention prune's reads) is never smaller at a later height than at
    /// an earlier one. SI-8
    /// guards the write (no wrap); this is the read-side form. Like
    /// [`WorkNotIncreasing`](Self::WorkNotIncreasing) it is not armed by a
    /// write site but by a rule reading the store: CEN-F20's volume window is the
    /// difference of two prefix sums, and a negative difference is
    /// `Corrupt::TxCountNotMonotone { at }`, which the ingest pipeline hands
    /// to [`WriteBatch::refuse_corrupt`](super::WriteBatch::refuse_corrupt)
    /// to arm this row. Never a saturated zero: a zero window would price
    /// the chain as dormant, a wrong answer that looks valid.
    FoldNotMonotone {
        /// The `block_info` cell whose fold decreased.
        cell: &'static str,
        /// The later height, whose value is below an earlier one's.
        height: u64,
    },
    /// **SI-10** — recorded cumulative work strictly increases with height:
    /// `block_info[h].cumulative_difficulty > block_info[h−1].cumulative_difficulty`
    /// for every recorded `h ≥ 1`, because every block's target is at least
    /// one (CEN-D6, `Target` is `NonZeroU128`).
    ///
    /// The belt beneath CEN-D4. Unlike the rows above it is **not armed by a
    /// store write site** — the store records the work the verdict carries
    /// and computes none (C2-R8 Q4) — but by the **validator reading the
    /// store**: `D4`'s window walk over `BatchView` observes a height whose
    /// work is not above its parent's — a decrease or an equal pair
    /// (`Corrupt::CumulativeDifficultyNotMonotone { at }`) — and returns a
    /// `Fault::Corrupt`, which the ingest pipeline hands to
    /// [`WriteBatch::refuse_corrupt`](super::WriteBatch::refuse_corrupt) to
    /// arm this row. The validator saw what a belt would have seen; the
    /// store's halt is the consequence (DRS-E2 RD-Q4).
    WorkNotIncreasing {
        /// The recorded height whose cumulative work is not above its
        /// parent's — or, for a window that derived zero, the connecting
        /// height whose window it was.
        height: u64,
    },
    /// **SI-9** — store-derived ids are dense and fresh: `tx_id`,
    /// `output_id` and the per-amount `amount_index` are the owning table's
    /// entry count at write time, and the slot an insert targets under one
    /// is absent.
    ///
    /// Pure storage integrity — no consensus twin (SCW-4), which is why it
    /// is not folded into SI-3: R8-Q1's three-arm test needs rule-twinned
    /// belts and pure invariants to stay distinguishable.
    IdNotFresh,
    /// **SI-11** — `curve_tree_leaves` is dense over `[0, leaf_count)`:
    /// the summary row's count (`curve_tree_meta`, `CurveTreeState`) is the
    /// leaf table's entry count, and every position below it has a row.
    /// The C++ wrote the count and the leaves in one grow
    /// (`db_lmdb.cpp:8936–8966`) and every reader took the count as the
    /// bound; here the reads assert it instead of assuming it (DRS-E1
    /// S-CURVE §3.3, SCU-3).
    ///
    /// Armed by the reads and by the writer (`grow.rs`, DRS-E3). The payload
    /// says which observation fired: [`LeafDensity::Length`] is the summary
    /// read comparing the count with the table's length, [`LeafDensity::Hole`]
    /// is the leaf walk naming the first missing position in the range it was
    /// asked for, [`LeafDensity::NotContinued`] is the writer finding the
    /// verdict's starting count is not the summary's, and
    /// [`LeafDensity::Occupied`] is the writer finding a position it is about
    /// to append already holds a row. A length-preserving hole (a missing
    /// position made up for by a row past the count) is visible to the walk
    /// only.
    LeavesNotDense {
        /// Which disagreement the read observed.
        observed: LeafDensity,
    },
    /// **SI-12** — the summary's root is the live root:
    /// `curve_tree_meta.root == curve_tree_roots[tip + 1]` (or
    /// [`shekyl_types::CurveTreeRoot::EMPTY`] when the chain has no tip),
    /// **including** the seal's [`crate::codec::CurveTreeState::EMPTY`].
    /// Since DRS-E3 the root `connect` records is the validator's derivation
    /// (SI-4), so an EMPTY summary claims nothing has drained and the live
    /// root must be EMPTY too; the grow path (`grow.rs`) moves both together
    /// at the first drain. The summary read compares them on every read
    /// (widened from grown-only 2026-09-27, #878 review: a non-empty live
    /// root beneath the seal's row is a corrupt roots table that CEN-B5
    /// would otherwise judge the honest next header against).
    SummaryRootDiverged,
    /// **SI-15** — every `archival_serve_credit` row belongs to a persona
    /// with a bond record. The connect hook that writes a pass bit refuses
    /// one for an unknown persona (CEN-L7's fatal backstop), so a row whose
    /// `PCanonicalId` prefix has no `archival_bond` row is a write that
    /// bypassed the writer. Observed by the serve-credit reads (A3, A4,
    /// A5), which have the persona in hand; the read that found it names
    /// it.
    ServeCreditWithoutBond {
        /// The persona the orphaned rows name.
        persona: shekyl_types::PCanonicalId,
    },
    /// **SI-16** — a pool entry is one entry: `pool_meta[h]` exists iff
    /// `pool_blob[h]` exists. `insert` writes both, `remove` deletes both,
    /// `update` touches only the meta row, and no other writer exists; a
    /// key present in one table and absent from the other is a write that
    /// bypassed the store. Observed by the enumeration's blob read and by
    /// `insert` (DRS-E1 S-POOL, `DRS_E1_SPOOL.md` §5).
    PoolEntryUnpaired {
        /// The transaction whose two rows disagree.
        txid: shekyl_types::TxHash,
    },
    /// **SI-17** — `output_to_leaf` and `leaf_to_output` are inverse
    /// bijections over the drained outputs: one position per drained
    /// output, one output per position, neither written twice. Armed by
    /// the connect's phase 3 when either map already holds the key it is
    /// about to insert (DRS-E3 `CTW-4`, §3.7). A drain cannot name a
    /// different number of outputs than leaves: that pair is
    /// [`shekyl_chain_rules::DrainedOutput`], one sequence.
    PositionMapsNotBijective,
    /// **SI-18** — the per-height leaf count advances by exactly what
    /// drained: `curve_tree_leaf_counts[h + 1] − curve_tree_leaf_counts[h]`
    /// is the connect of `h`'s drained leaf count, and the row is written
    /// once per connect. Armed by the writer (`grow.rs`) at the two places
    /// the chain of counts can break: the row it is about to write is
    /// already present ([`LeafCountFault::SuccessorPresent`] — the tip moved
    /// without its count row, or a write bypassed `connect`), or the row
    /// the previous connect wrote does not equal the summary's count the
    /// drain continues from ([`LeafCountFault::PredecessorDisagrees`] — a
    /// historical count nobody would otherwise re-read, which `leaf_count_at`
    /// / `depth_at` would then serve as fact).
    LeafCountNotAdvanced {
        /// Which break the writer observed.
        observed: LeafCountFault,
    },
    /// **SI-19** — a persona has at most one record, and a JoinMarket is
    /// the only insert. `archival_bond[p]` is written insert-once by the
    /// JoinMarket arm and only upserted — pre-image journaled — by every
    /// later change (Release, Reinstate, a claim's record update, a slash);
    /// a second insert for a persona is a writer that re-ran a join. The
    /// belt beneath CEN-J14's rule, bound at the insert handle's open in
    /// the archival writer's phase 2 (DRS-E4 §3.2, §4; CEN-L14 site 2).
    BondRecordNotFresh,
    /// **SI-20** — `Σ bonded_total` over `archival_bond` equals the total
    /// the delta implies: after the block's record writes, the new sum is
    /// the old sum minus the pre-images the writes displaced plus the
    /// post-images they left. A disagreement is a writer that changed a
    /// record the delta did not describe, or a sum that would not fit.
    /// Armed by the archival writer's phase 2 after its record writes and
    /// by phase 9 after the slashes' (DRS-E4 `ARW-7`, `ARW-Q9`).
    BondedTotalDisagrees {
        /// The sum the writes imply.
        expected: shekyl_units::AtomicUnits,
        /// The sum the table holds after them.
        found: shekyl_units::AtomicUnits,
    },
    /// **SI-21** — an epoch closes whole. `archival_sigma_work[E]` and
    /// `archival_budget[E]` exist together with every `(shard, E)` row of
    /// `archival_r_market` the close's snapshot named — zero rows written,
    /// not skipped (`ARW-Q4`) — or none does; each is insert-once on `E`,
    /// so a second close of `E` refuses rather than overwriting (CEN-L14's
    /// O-2 adversary). Bound at the three insert handles' open in phase 9
    /// (DRS-E4 `ARW-8`).
    EpochCloseRewritten {
        /// The epoch a close was already recorded for.
        epoch: shekyl_types::SettlementEpoch,
    },
    /// **SI-22** — the slash log is dense per height, and every row is an
    /// applied slash. `archival_slash_log`'s rows at height `h` are
    /// `(h, 0) … (h, n−1)` and no other, and each row's `(persona, shard,
    /// epoch)` is a key of `archival_slash_applied`. Armed by phase 9 when
    /// the log already holds a row at the connecting height before the
    /// first slash is appended, when `(h, seq)` is present at the append,
    /// or when the applied key is present at its insert — a scheduler that
    /// wrote out of order or slashed twice (DRS-E4 `ARW-2`, `ARW-Q2`).
    SlashLogNotDense {
        /// The connecting height whose rows are not `(h, 0) … (h, n−1)`.
        height: u64,
    },
    /// **SI-23** — the accruing table holds at most one row, the open
    /// epoch's. `archival_budget_accruing[E]` is upserted every connect of
    /// epoch `E` and deleted in the transaction that writes
    /// `archival_budget[E]` (`ARW-Q3`, second half); a second row is a
    /// close that did not finish or a re-key, and a stale accumulator is
    /// this refusal rather than a silently wrong operand of the next close.
    /// Armed by phase 9: a row keyed by another epoch when the open
    /// epoch's is written ([`AccrualFault::StaleRow`]), or no row for `E`
    /// when the close deletes it ([`AccrualFault::AbsentAtClose`], the
    /// remove handle's bound row).
    AccruingNotSingular {
        /// Which shape the writer observed.
        observed: AccrualFault,
    },
    /// **SI-24** — the archival fold is the sum of its rows:
    /// `block_info[h].cumulative_archival_len` equals the parent's value
    /// plus the `txs_archival_len` rows (absent ⇔ `0`) of the storage ids
    /// `h` issued (`SHT-Q2`). `connect` writes both from one measurement of
    /// the segments, so they cannot disagree at the write; a disagreement
    /// is a row or a cell changed under the store. Armed by the prune's
    /// descent (`prune.rs` `walk_block`), which checks every block it
    /// passes and would otherwise place a shard boundary by a cell the rows
    /// do not support.
    ArchivalLengthsDisagree {
        /// The height whose rows were summed.
        height: u64,
        /// What the parent's cell plus the block's rows sum to.
        rows: u64,
        /// What the block's own cell records.
        cell: u64,
    },
}

/// What an SI-18 write observed (payload of
/// [`StoreInvariant::LeafCountNotAdvanced`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafCountFault {
    /// `curve_tree_leaf_counts[h + 1]` already holds a row.
    SuccessorPresent,
    /// `curve_tree_leaf_counts[h]` (`0` by definition at `h = 0`) is not
    /// the summary's leaf count the connect of `h` starts from.
    PredecessorDisagrees {
        /// The count the row at `h` records.
        recorded: u64,
        /// The count `curve_tree_meta` holds.
        summary: u64,
    },
}

/// What an SI-23 write observed (payload of
/// [`StoreInvariant::AccruingNotSingular`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccrualFault {
    /// `archival_budget_accruing` holds a row keyed by `epoch`, which is
    /// not the open epoch the writer is accruing into: a close that did not
    /// delete its row, or a re-key.
    StaleRow {
        /// The epoch the stale row is keyed by.
        epoch: shekyl_types::SettlementEpoch,
    },
    /// The close of `E` found no `archival_budget_accruing[E]` to delete:
    /// the epoch closed without having accrued.
    AbsentAtClose,
}

/// What an SI-11 observation was. A length comparison does not know which
/// position is missing, and a walk knows the position and not the table's
/// length. The writer has two more, and neither of them is a length: the
/// verdict's starting count against the summary, and a position the append
/// found already occupied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafDensity {
    /// `curve_tree_meta`'s `leaf_count` is not `curve_tree_leaves`' length.
    /// `count` is the summary; `rows` is the table.
    Length { count: u64, rows: u64 },
    /// `position` is inside `[0, leaf_count)` and the leaf table has no row
    /// there. This is the first such position in the range the walk was
    /// asked for.
    Hole { position: u64 },
    /// The growth continues a tree of `from` leaves; the summary holds
    /// `summary`. The writer observed this before appending.
    NotContinued { from: u64, summary: u64 },
    /// A position the drain is about to write already holds a leaf. The
    /// insert-once handle does not know which key.
    Occupied,
}

impl StoreInvariant {
    /// The register row this invariant is, as the `n` of `SI-n`.
    #[must_use]
    pub const fn row(&self) -> u32 {
        match self {
            Self::KeyImageNotFresh => 1,
            Self::TipMismatch => 2,
            Self::TxHashNotFresh => 3,
            Self::RootRewritten => 4,
            Self::UndoLogIncoherent { .. } => 6,
            Self::WorkNotIncreasing { .. } => 10,
            Self::LeavesNotDense { .. } => 11,
            Self::SummaryRootDiverged => 12,
            Self::CellCorrupt { .. } => 7,
            Self::FoldOverflow { .. } => 8,
            Self::FoldNotMonotone { .. } => 13,
            Self::IdNotFresh => 9,
            Self::ServeCreditWithoutBond { .. } => 15,
            Self::PoolEntryUnpaired { .. } => 16,
            Self::PositionMapsNotBijective => 17,
            Self::LeafCountNotAdvanced { .. } => 18,
            Self::BondRecordNotFresh => 19,
            Self::BondedTotalDisagrees { .. } => 20,
            Self::EpochCloseRewritten { .. } => 21,
            Self::SlashLogNotDense { .. } => 22,
            Self::AccruingNotSingular { .. } => 23,
            Self::ArchivalLengthsDisagree { .. } => 24,
        }
    }
}

impl core::fmt::Display for StoreInvariant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SI-{} violated: ", self.row())?;
        match self {
            Self::KeyImageNotFresh => f.write_str(
                "a key image handed to connect is already in spent_keys; the validator admitted \
                 a double spend",
            ),
            Self::TipMismatch => f.write_str(
                "the connecting block's parent is not the recorded tip, or its height is already \
                 recorded",
            ),
            Self::TxHashNotFresh => f.write_str(
                "a transaction hash handed to connect is already in tx_indices; the validator \
                 admitted a duplicate",
            ),
            Self::RootRewritten => f.write_str(
                "the curve-tree root at the connecting height is already recorded; a root is \
                 written exactly once",
            ),
            Self::FoldOverflow { cell } => write!(
                f,
                "the `{cell}` fold overflowed u64; a fold never saturates and never mints"
            ),
            Self::IdNotFresh => f.write_str(
                "a store-derived id (tx_id / output_id / amount_index) names an occupied slot; \
                 the table's count and its keys disagree",
            ),
            Self::WorkNotIncreasing { height } => write!(
                f,
                "recorded cumulative work does not increase at height {height}; the validator \
                 read a store whose block_info rows contradict CEN-D4/D6, rebuild from the \
                 block corpus"
            ),
            Self::FoldNotMonotone { cell, height } => write!(
                f,
                "the `{cell}` fold decreases at height {height}; a prefix sum the store only \
                 adds to went backwards — the validator read a store that does not hold what it \
                 claims, rebuild from the block corpus"
            ),
            Self::UndoLogIncoherent { height, fault } => write!(
                f,
                "undo log at height {height}: {fault}; the journal no longer describes the \
                 tables, rebuild from the block corpus"
            ),
            Self::LeavesNotDense { observed } => match observed {
                LeafDensity::Length { count, rows } => write!(
                    f,
                    "curve_tree_leaves has {rows} rows and the summary's leaf count is {count}; \
                     the summary and the leaf table disagree, rebuild from the block corpus"
                ),
                LeafDensity::Hole { position } => write!(
                    f,
                    "curve_tree_leaves has no row at position {position}; the summary's leaf \
                     count includes that position, rebuild from the block corpus"
                ),
                LeafDensity::NotContinued { from, summary } => write!(
                    f,
                    "the drain continues a tree of {from} leaves but curve_tree_meta holds \
                     {summary}; the growth does not continue the tree the store holds, rebuild \
                     from the block corpus"
                ),
                LeafDensity::Occupied => f.write_str(
                    "a leaf position the drain is writing already holds a row; the append would \
                     overlap the dense range, rebuild from the block corpus",
                ),
            },
            Self::SummaryRootDiverged => f.write_str(
                "the grown curve_tree_meta root is not the live root at curve_tree_roots[tip + 1]; \
                 the summary and the recorded root disagree, rebuild from the block corpus",
            ),
            Self::ServeCreditWithoutBond { persona } => write!(
                f,
                "archival_serve_credit holds rows for persona {persona} but archival_bond has no \
                 record for it; a pass bit was written past the connect hook's refusal"
            ),
            Self::PoolEntryUnpaired { txid } => write!(
                f,
                "pool entry {txid} has a row in one of pool_meta / pool_blob and not the other; \
                 a write bypassed the pool store"
            ),
            Self::PositionMapsNotBijective => f.write_str(
                "output_to_leaf / leaf_to_output would stop being inverse bijections: a drained \
                 output or a leaf position is already mapped",
            ),
            Self::LeafCountNotAdvanced { observed } => match observed {
                LeafCountFault::SuccessorPresent => f.write_str(
                    "curve_tree_leaf_counts already holds a row at the connecting height's \
                     successor; the count is written once per connect",
                ),
                LeafCountFault::PredecessorDisagrees { recorded, summary } => write!(
                    f,
                    "curve_tree_leaf_counts records {recorded} going into the connecting height but \
                     curve_tree_meta holds {summary}; the per-height counts no longer chain to the \
                     tree, rebuild from the block corpus"
                ),
            },
            Self::BondRecordNotFresh => f.write_str(
                "archival_bond already holds a record for the persona a JoinMarket is inserting; \
                 a join was re-run past the validator",
            ),
            Self::BondedTotalDisagrees { expected, found } => write!(
                f,
                "Σ bonded_total over archival_bond is {found} after the block's record writes \
                 but the writes imply {expected}; a record changed that the delta did not \
                 describe, rebuild from the block corpus"
            ),
            Self::EpochCloseRewritten { epoch } => write!(
                f,
                "settlement epoch {epoch} already has a close row (archival_r_market / \
                 archival_sigma_work / archival_budget); an epoch closes once"
            ),
            Self::SlashLogNotDense { height } => write!(
                f,
                "archival_slash_log's rows at height {height} would not be (h, 0) … (h, n−1) \
                 of applied slashes; the scheduler wrote out of order or slashed twice"
            ),
            Self::AccruingNotSingular { observed } => match observed {
                AccrualFault::StaleRow { epoch } => write!(
                    f,
                    "archival_budget_accruing holds a row for epoch {epoch}, which is not the \
                     open epoch; a close did not delete its accumulator, rebuild from the block \
                     corpus"
                ),
                AccrualFault::AbsentAtClose => f.write_str(
                    "the epoch close found no archival_budget_accruing row to delete; the epoch \
                     closed without having accrued, rebuild from the block corpus",
                ),
            },
            Self::ArchivalLengthsDisagree { height, rows, cell } => write!(
                f,
                "block {height}'s txs_archival_len rows sum to {rows} from its parent's \
                 cumulative_archival_len, but its own cell records {cell}; the shard boundaries \
                 cannot be placed, rebuild from the block corpus"
            ),
            Self::CellCorrupt { key, fault } => write!(
                f,
                "typed cell `{key}` is {fault}; the file was modified outside this crate, \
                 rebuild from the block corpus"
            ),
        }
    }
}

impl core::error::Error for StoreInvariant {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::CellCorrupt {
                fault: CellFault::Undecodable(e),
                ..
            } => Some(e),
            Self::CellCorrupt {
                fault: CellFault::Absent,
                ..
            }
            | Self::KeyImageNotFresh
            | Self::WorkNotIncreasing { .. }
            | Self::FoldNotMonotone { .. }
            | Self::TipMismatch
            | Self::TxHashNotFresh
            | Self::RootRewritten
            | Self::FoldOverflow { .. }
            | Self::IdNotFresh
            | Self::LeavesNotDense { .. }
            | Self::SummaryRootDiverged
            | Self::ServeCreditWithoutBond { .. }
            | Self::PoolEntryUnpaired { .. }
            | Self::PositionMapsNotBijective
            | Self::LeafCountNotAdvanced { .. }
            | Self::BondRecordNotFresh
            | Self::BondedTotalDisagrees { .. }
            | Self::EpochCloseRewritten { .. }
            | Self::SlashLogNotDense { .. }
            | Self::AccruingNotSingular { .. }
            | Self::ArchivalLengthsDisagree { .. }
            | Self::UndoLogIncoherent { .. } => None,
        }
    }
}

/// How the undo log and the tables disagreed (SI-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndoFault {
    /// Sealing this height's journal found a row already recorded there.
    RowAlreadyRecorded,
    /// `pop` found the journal's top row at `top`, not at the tip.
    TopIsNotTip {
        /// The height of the journal's highest row.
        top: u64,
    },
    /// `pop` found a block recorded at the tip, the tip at or above the
    /// persisted `undo_log_floor`, and **no** journal row for it. The
    /// retention prune keeps every row from the floor to the tip, so this
    /// is a journal that does not describe its tables, not a retention
    /// limit (below the floor is `StoreCannot::PopBelowFloor`).
    NoRowForTip,
    /// The journal's lowest row is at `first`, but the persisted
    /// `undo_log_floor` says `floor`. The cell and the table record the
    /// same fact — rows are contiguous from the floor to the tip — and the
    /// cell is kept because the table cannot name the floor once every
    /// retained row has been popped (SPR-4); whenever the table is
    /// non-empty the two must agree, and this is the check that can fail
    /// (rule 16). Checked at `pop` and at every boundary after rows are
    /// retired.
    FloorMismatch {
        /// The journal's lowest key.
        first: u64,
        /// The persisted floor.
        floor: u64,
    },
    /// Replaying entry `index` (in write order) found its target key or
    /// member not in the state the entry left it in — absent where the
    /// entry inserted, or, for a restore, absent where it replaced.
    EntryNotReversible {
        /// Position of the entry in the row, in write order.
        index: u32,
    },
    /// Replaying entry `index` found its key present but holding a value
    /// whose post-image digest is not the one the journaled write left —
    /// something wrote around the journal, or the file is corrupt. Found
    /// after the inverse displaced the value, inside the poisoned
    /// transaction, so nothing lands.
    PostImageMismatch {
        /// Position of the entry in the row, in write order.
        index: u32,
    },
}

impl core::fmt::Display for UndoFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RowAlreadyRecorded => {
                f.write_str("a journal row is already recorded for this height")
            }
            Self::TopIsNotTip { top } => write!(
                f,
                "the journal's top row is at height {top}, not at the tip"
            ),
            Self::NoRowForTip => f.write_str(
                "a block is recorded at the tip, inside the undo retention, but the journal has \
                 no row for it",
            ),
            Self::FloorMismatch { first, floor } => write!(
                f,
                "the journal's lowest row is at height {first} but the persisted undo floor is \
                 {floor}"
            ),
            Self::EntryNotReversible { index } => write!(
                f,
                "entry {index} cannot be reversed: its target is not in the state the entry left"
            ),
            Self::PostImageMismatch { index } => write!(
                f,
                "entry {index} cannot be reversed: the value under its key is not the one the journaled write left"
            ),
        }
    }
}

/// What is wrong with a typed `properties` cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellFault {
    /// The cell is not in the table.
    Absent,
    /// The cell's bytes are not an encoding of its value type.
    Undecodable(CodecError),
}

impl core::fmt::Display for CellFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("absent"),
            Self::Undecodable(e) => write!(f, "undecodable ({e})"),
        }
    }
}
