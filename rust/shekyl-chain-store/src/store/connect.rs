// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `connect`: the connect write set (S-CHAIN-W commit 6; `DRS_E1_SCHAIN_W.md`
//! §2.3, §3.1, §3.2, §3.5, §4).
//!
//! The port of `BlockchainDB::add_block` (`blockchain_db.cpp:435`) and the
//! LMDB helpers it reaches, as one method on the batch that takes a
//! [`ChainValid`] the validator alone can mint (C2-R8 Q3) and the
//! consensus-visible values the store records and never derives (Q4,
//! [`ConnectFacts`]). Every write is a declared verb through a handle bound
//! to its `SI-` row (§7.3), every write is journaled for `pop` (Q5), and the
//! phases run in the C++ funnel's order so E3 (curve tree) and E4
//! (archival) attach at the same points without re-opening this contract:
//!
//! ```text
//!  1. belts        parent = recorded tip (SI-2); rule set in force (B3)
//!  2. transactions miner tx then listed → tx_indices, txs_*, tx_outputs,
//!                  output_txs, output_amounts, spent_keys (SI-3, SI-9, SI-1)
//!  3. [E3 hook]    pending leaves → drain → grow → segment freeze
//!  4. root         curve_tree_roots[h + 1] = facts.root_after (SI-4) — every
//!                  connect, grown or not (the C++ write at :663–:664 is
//!                  outside the growth gate; SCW-19)
//!  5. [E4 hook]    attestation witness
//!  6. block        blocks[h], block_heights[hash], block_info[h] (SI-2)
//!  7. rule set     hf_versions[h] = in_force (the CEN-B3 belt)
//!  8. burn         only if h > 0 && burned > 0 (blockchain.cpp:6148):
//!                  block_burn[h]; total_burned += burned (SI-8)
//!  9. [E4 hook]    accrual row, slash, epoch close
//! 10. journal      undo_log[h] (SI-6)
//! ```
//!
//! A `[hook]` phase has no body here; E3 / E4 land bodies, not new phases.
//! `pop` has no phase list — it is the reverse replay of step 10's row.
//!
//! # What the connect stamps (§3.8)
//!
//! Between the belts and the writes, `connect` widens the file's
//! [`Provenance`](crate::provenance::Provenance) inside this batch's own
//! transaction with two things a parity claim must know: the census rows
//! `in_force` enforces that the verdict's coverage did **not** evaluate
//! (C2-R8 §9.4), and the [`ConnectFacts`] fields that were passed through
//! rather than derived (SCW-1). Both are unions that never narrow; an
//! aborted batch leaves no taint. A file with either non-empty is not
//! parity evidence, and says which rows or fields have to land for it to
//! become so.
//!
//! # What the store keys by itself
//!
//! `tx_id`, `output_id` and the per-amount `amount_index` are the owning
//! table's next dense key at write time (`last + 1`, which equals the
//! entry count when the primary is dense — LMDB's `mdb_stat` /
//! `mdb_cursor_count` at `db_lmdb.cpp:1078`, `:1284`, `:1314`). All three
//! primaries are unique-key tables — `output_amounts` has been a keyed
//! `(amount, amount_index)` table since S-OUT-KI's layout v6 (SOK-1), so
//! `last + 1 == len` is complete for each. The insert under each is bound
//! to **SI-9**: a collision or a hole is a corrupted index, not a consensus
//! fact.
//!
//! `output_amounts` keeps LMDB's logical keying (SCW-8): every coinbase and
//! emission vout is stored under amount `0` with its ct-base commitment, and
//! every other vout under its own amount — which CEN-H14 makes `0` — so the
//! table holds **one bucket** and the E2 comparator projects it 1:1 onto
//! LMDB's `DUPSORT` pairs. The amount dimension is carried, not chosen:
//! whether `amount_index` is ever *exposed* stays R8b-2's question
//! (`DRS_E1_SOUT_KI.md` §3.4). The single-bucket premise is what makes the
//! SI-9 density check exact, and SOK-Q2 states it as a premise: a second
//! bucket fails the check rather than passing it.

use shekyl_chain_rules::{ChainValid, RuleSet, RuleSetId, TxIdentity};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    BlockHash, BlockHeight, BlockWeight, CommitmentBytes, CurveTreeRoot, LongTermWeight,
    OneTimePubkey, OutputIndexInTx,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

use crate::codec::{
    stored_timelock, BlockBody, BlockInfo, Canonical, Coded, CoverageGaps, OutKey, OutTx,
    PassedThroughFacts, Present, PropertyCell, Raw, TotalBurnedCell, TxIndex, TxOutputIndices,
    TxPqcAuthsSegment, TxPrunableSegment, TxPrunedSegment,
};
use crate::ids::{AmountIndex, OutputStorageId, TxStorageId};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{
    BLOCKS, BLOCK_BURN, BLOCK_HEIGHTS, BLOCK_INFO, CURVE_TREE_ROOTS, HF_VERSIONS, OUTPUT_AMOUNTS,
    OUTPUT_TXS, SPENT_KEYS, TXS_PQC_AUTHS, TXS_PQC_AUTH_HASH, TXS_PRUNABLE, TXS_PRUNABLE_HASH,
    TXS_PRUNED, TX_INDICES, TX_OUTPUTS,
};

use super::error::{CellFault, EngineError, StoreCannot, StoreError, StoreInvariant};
use super::header;
use super::keyed::KeyedTable;
use super::view::BatchView;
use super::write::WriteBatch;

/// Where a consensus-visible value came from (SCW-1).
///
/// The same mechanism as the validator's `RuleCoverage` (rows actually
/// checked) and the file's `Provenance` (families actually applied), a
/// third time: the store records what it is handed and stamps how it got
/// it. When every field of [`ConnectFacts`] is `Derived`, this type and
/// [`Fact`] are deleted, not left as a permanent `Derived` (rule 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The validator derived it under the census row that defines it.
    Derived,
    /// The driver passed it through from another source — under DRS-E2's
    /// parity replay, the LMDB `block_info` row of the block being
    /// replayed. Not parity evidence for the field it carries.
    PassedThrough,
}

/// One asserted value with its origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fact<T> {
    /// The value the store records.
    pub value: T,
    /// How the caller came by it.
    pub origin: Origin,
}

impl<T> Fact<T> {
    /// A value the validator derived.
    pub const fn derived(value: T) -> Self {
        Self {
            value,
            origin: Origin::Derived,
        }
    }

    /// A value passed through from a non-validator source.
    pub const fn passed_through(value: T) -> Self {
        Self {
            value,
            origin: Origin::PassedThrough,
        }
    }
}

/// Which census rows derive a fact — and so delete its [`Fact`] wrapper.
///
/// Named on the type, so the store shows its own E6 dependency rather than
/// only E6's plan showing it (`DRS_E1_SCHAIN_W.md` §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeletedBy {
    /// The `ConnectFacts` field.
    pub field: &'static str,
    /// The census rows whose landing makes the field `Derived`.
    pub rows: &'static [&'static str],
    /// The DRS §7.5.2 E6 slice those rows arrive in.
    pub slice: &'static str,
}

/// The consensus-visible values the store records and never derives
/// (C2-R8 Q4) — exactly what `Blockchain` hands `BlockchainDB::add_block`
/// today (`blockchain_db.cpp:435`–`:440`, `:664`; `blockchain.cpp:6157`),
/// minus E4's `archival_budget_accrual`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectFacts {
    /// `block_weight`.
    pub weight: Fact<BlockWeight>,
    /// `long_term_block_weight`.
    pub long_term_weight: Fact<LongTermWeight>,
    /// Cumulative difficulty through this block.
    pub cumulative_difficulty: Fact<CumulativeDifficulty>,
    /// Coins generated through this block (`already_generated_coins`).
    pub coins_generated: Fact<AtomicUnits>,
    /// This block's destroyed amount. `0` (and genesis, whatever its amount)
    /// writes no `block_burn` row and no `total_burned` fold — LMDB's
    /// absent-reads-as-0 convention and the `blockchain.cpp:6148` guard,
    /// kept so the digest domain and the undo row match.
    pub burned: Fact<AtomicUnits>,
    /// The tree root **after this block's drain** — the state the *next*
    /// header must carry (CEN-B5) and a spend referencing `h + 1` anchors to
    /// (CEN-I12); recorded at `curve_tree_roots[h + 1]` on every connect
    /// (SI-4: one row per connect), grown or not. Not this block's own
    /// header root: that is the state *before* its drain, already at key `h`
    /// from the parent's connect (SCW-19).
    pub root_after: Fact<CurveTreeRoot>,
    /// The long-term weight median **in force for** this block — the value
    /// it was validated and fee-floored against, the ring's `rm` at its
    /// iteration (`relay_floor_ring.cpp:196`–`:200`), **not** the recompute
    /// after its own weight enters the window (that is the next block's;
    /// SCR-19, `DRS_E1_SCHAIN_R.md` §3.6). Recorded at `block_info[h]` for
    /// the O(1) read FL-R3-STORE owes; a consensus computation, so passed
    /// through exactly like `long_term_weight` until CEN-G6 derives it.
    pub long_term_effective_median: Fact<LongTermWeight>,
}

impl ConnectFacts {
    /// The fields, each with the rows that will derive it, in declaration
    /// order. The table `DRS_E1_SCHAIN_W.md` §3.2 carries, as data.
    pub const DELETED_BY: [DeletedBy; 7] = [
        DeletedBy {
            field: "weight",
            rows: &["CEN-G6", "CEN-G6b"],
            slice: "7 (4.G, over the CEN-H3 / CEN-F14 weight function)",
        },
        DeletedBy {
            field: "long_term_weight",
            rows: &["CEN-G6", "CEN-G6b"],
            slice: "7 (4.G)",
        },
        DeletedBy {
            field: "cumulative_difficulty",
            rows: &["CEN-D4", "CEN-D5"],
            slice: "2 (4.D, body in shekyl-difficulty)",
        },
        DeletedBy {
            field: "coins_generated",
            rows: &["CEN-F13", "CEN-F14", "CEN-F14b"],
            slice: "4 (4.F, body in shekyl-economics)",
        },
        DeletedBy {
            field: "burned",
            rows: &["CEN-F17", "CEN-G11"],
            slice: "4 (4.F)",
        },
        DeletedBy {
            field: "root_after",
            rows: &["CEN-B5", "CEN-I12"],
            slice: "1 / 6, through the curve-tree crate (S-CURVE grows it)",
        },
        DeletedBy {
            field: "long_term_effective_median",
            rows: &["CEN-G6", "CEN-G6b"],
            slice: "7 (4.G), beside long_term_weight",
        },
    ];

    const fn origins(&self) -> [Origin; 7] {
        [
            self.weight.origin,
            self.long_term_weight.origin,
            self.cumulative_difficulty.origin,
            self.coins_generated.origin,
            self.burned.origin,
            self.root_after.origin,
            self.long_term_effective_median.origin,
        ]
    }

    /// The fields still passed through, each with the rows that will
    /// delete it. Empty when every field is derived — the moment `Fact`
    /// and `Origin` themselves are deleted.
    ///
    /// `count()` is **the set of facts the store does not derive**, not a
    /// progress bar: it grows as facts are discovered (S-CHAIN-R added
    /// `long_term_effective_median`, so it rose from six to seven when that
    /// landed — `DRS_E1_SCHAIN_R.md` §3.6) and shrinks as E6 lands the rows
    /// that derive them. An increase is not a regression; the items are the
    /// critical path.
    pub fn passed_through(&self) -> impl Iterator<Item = DeletedBy> + '_ {
        Self::DELETED_BY
            .into_iter()
            .zip(self.origins())
            .filter(|(_, origin)| *origin == Origin::PassedThrough)
            .map(|(field, _)| field)
    }

    /// The passed-through fields as the file records them (§3.8).
    fn passed_through_set(&self) -> PassedThroughFacts {
        PassedThroughFacts::of_positions(
            self.origins()
                .into_iter()
                .enumerate()
                .filter(|(_, origin)| *origin == Origin::PassedThrough)
                .map(|(i, _)| i),
        )
    }
}

/// What `connect` recorded. Nothing consensus-visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connected {
    /// The height the block was recorded at.
    pub height: BlockHeight,
    /// Entries in the block's `undo_log` row.
    pub journaled: usize,
}

impl<'id> WriteBatch<'_, 'id> {
    /// Record a validated block at tip + 1.
    ///
    /// `valid` is branded with this batch (`'id`) and with this batch's
    /// view type, so a verdict minted anywhere else does not unify.
    /// `in_force` is the rule set the driver's schedule names for the
    /// height (`RuleSchedule::rules_at`); the store compares it with the
    /// verdict's and refuses a mismatch, holding no schedule and no
    /// `Network` itself (rule 71).
    ///
    /// May be called repeatedly on one batch: the view for block *h+1*
    /// sees block *h*, and each call journals its own row.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RuleSetNotInForce`] if `valid` was judged under a
    /// rule set other than `in_force`; [`StoreCannot::OutputWithoutCommitment`]
    /// for a hand-built shape the parser would not produce; the `SI-`
    /// belts — SI-2 (parent / height), SI-3 (tx hash), SI-9 (store id),
    /// SI-1 (key image), SI-4 (root), SI-8 (`total_burned` overflow) — each
    /// [`StoreError::InvariantViolated`] and each poisoning the batch;
    /// engine errors.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the verdict is a one-shot token: connect takes it by value so a connected block cannot be connected again from the same ChainValid"
    )]
    pub fn connect(
        &self,
        valid: ChainValid<'id, BatchView<'_, 'id>>,
        facts: ConnectFacts,
        in_force: RuleSetId,
    ) -> Result<Connected, StoreError> {
        // ---- 1. belts -------------------------------------------------
        // The connecting height is known from the tip's key alone and is
        // noted **before** any belt can fire: a violation here must halt
        // the writer at this height (§3.6.2), and the halt reads the noted
        // height — a belt that poisoned first would leave the writer live.
        // The parent's `cumulative_tx_count` rides out of the same decoded
        // tip row (§3.6): genesis has no parent and starts the count at 0.
        let (height, parent_tx_count) = {
            let tip = self.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?;
            let last = tip.last()?;
            let height = last.as_ref().map_or(0, |(h, _)| h.value() + 1);
            self.journal().note_height(height);
            let mut parent_tx_count = 0;
            if let Some((_, info)) = last {
                let info = info.value().decode().map_err(|cause| {
                    self.poison().arm(StoreInvariant::CellCorrupt {
                        key: "block_info",
                        fault: CellFault::Undecodable(cause),
                    })
                })?;
                if valid.block().header().previous != info.hash {
                    return Err(self.poison().arm(StoreInvariant::TipMismatch));
                }
                parent_tx_count = info.cumulative_tx_count;
            }
            (height, parent_tx_count)
        };
        // Resolve `in_force` before comparing it with the verdict's id: a
        // `ChainValid` only ever carries an issued id, so an unissued
        // `in_force` would otherwise always report as a mismatch and the
        // unknown-id refusal could never fire (PR #757 review). With one
        // rule set issued today the mismatch arm is reached only once a
        // second set exists; it is the contract, not dead code.
        let rule_set = RuleSet::for_id(in_force).ok_or(StoreCannot::RuleSetUnknown(in_force))?;
        if valid.rule_set_id() != in_force {
            return Err(StoreCannot::RuleSetNotInForce {
                height,
                judged: valid.rule_set_id(),
                in_force,
            }
            .into());
        }

        // ---- provenance (§3.8): what this verdict did NOT bring ----------
        // Widened before the writes and inside this transaction, so it
        // lands with the rows or not at all; header cells are engine-local
        // and are not journaled (a popped block's verdict is still evidence
        // the file once accepted it).
        // An SI-7 from either cell is routed through the poison latch so
        // `complete` halts the writer for it like every other violation a
        // connect observes (§3.6.2).
        header::widen_gaps(
            self.txn(),
            CoverageGaps::of(
                rule_set
                    .enforced()
                    .filter(|row| !valid.coverage().contains(*row)),
            ),
        )
        .map_err(|e| self.arm_if_invariant(e))?;
        header::widen_passed_through(self.txn(), facts.passed_through_set())
            .map_err(|e| self.arm_if_invariant(e))?;

        let block = valid.block();
        let recording = self.record_undo(height);

        // ---- 2. transactions -------------------------------------------
        let (miner_identity, miner_tx) = block.miner_tx();
        let mut rct_outputs = self.record_tx(height, miner_identity, miner_tx, true)?;
        for (identity, tx) in block.transactions() {
            rct_outputs += self.record_tx(height, *identity, tx, false)?;
        }

        // ---- 3. [E3 hook] pending leaves → drain → grow → segment freeze --
        // ---- 4. root ---------------------------------------------------
        self.open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)?
            .insert(height + 1, facts.root_after.value.encoded().as_encoded())?;

        // ---- 5. [E4 hook] attestation witness --------------------------
        // ---- 6. block --------------------------------------------------
        let hash = BlockHash::from_bytes(*block.hash().as_bytes());
        self.open_insert_table(BLOCKS, StoreInvariant::TipMismatch)?
            .insert(height, Raw::<BlockBody>::new(&block.block().serialize()))?;
        self.open_insert_table(BLOCK_HEIGHTS, StoreInvariant::TipMismatch)?
            .insert(
                LmdbHashKey::from(hash),
                BlockHeight::from_raw(height).encoded().as_encoded(),
            )?;
        let info = BlockInfo {
            timestamp: shekyl_types::Timestamp::from_raw(block.header().timestamp),
            coins_generated: facts.coins_generated.value,
            weight: facts.weight.value,
            cumulative_difficulty: facts.cumulative_difficulty.value,
            hash,
            // Per-block, not accumulated: LMDB's `bi_cum_rct` is this block's
            // count and the accumulation arm is dead (CEN-L15) — see
            // `BlockInfo::rct_outputs`.
            rct_outputs,
            long_term_weight: facts.long_term_weight.value,
            // Store-derived running total (§3.6): the parent's plus this
            // block's listed transactions, under SI-8 like `total_burned`.
            cumulative_tx_count: parent_tx_count
                .checked_add(u64::try_from(block.transactions().len()).expect("tx count fits u64"))
                .ok_or(StoreInvariant::FoldOverflow {
                    cell: "block_info.cumulative_tx_count",
                })
                .map_err(|row| self.poison().arm(row))?,
            // Passed through, and stored at **this** height: the median in
            // force for `h`, not the recompute that belongs to `h + 1`
            // (SCR-19).
            long_term_effective_median: facts.long_term_effective_median.value,
        };
        self.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?
            .insert(height, info.encoded().as_encoded())?;

        // ---- 7. rule set (CEN-B3's belt) --------------------------------
        self.open_insert_table(HF_VERSIONS, StoreInvariant::TipMismatch)?
            .insert(height, in_force.encoded().as_encoded())?;

        // ---- 8. burn ---------------------------------------------------
        // Conditional as a whole, exactly as `blockchain.cpp:6148`
        // (`new_height > 0 && block_burn_amount > 0`): a zero-burn block and
        // genesis write neither row nor a `total_burned` pre-image, so the
        // declared write set and the undo row are the C++'s.
        let burned = facts.burned.value;
        if height > 0 && burned != AtomicUnits::ZERO {
            self.open_insert_table(BLOCK_BURN, StoreInvariant::TipMismatch)?
                .insert(height, burned.encoded().as_encoded())?;
            let total = self
                .get_property::<TotalBurnedCell>()?
                .unwrap_or(AtomicUnits::ZERO)
                .checked_add(burned)
                .ok_or(StoreInvariant::FoldOverflow {
                    cell: TotalBurnedCell::KEY,
                })
                .map_err(|row| self.poison().arm(row))?;
            self.upsert_property::<TotalBurnedCell>(&total)?;
        }

        // ---- 9. [E4 hook] accrual row, slash, epoch close ---------------
        // ---- 10. journal -----------------------------------------------
        let journaled = recording.seal()?;
        Ok(Connected {
            height: BlockHeight::from_raw(height),
            journaled,
        })
    }

    /// One transaction's rows (`add_transaction` / `add_transaction_data` /
    /// `add_output` / `add_tx_amount_output_indices`). Returns how many of
    /// its outputs count toward `block_info.rct_outputs`.
    fn record_tx(
        &self,
        height: u64,
        identity: TxIdentity,
        tx: &Transaction,
        miner: bool,
    ) -> Result<u64, StoreError> {
        let tx_hash = identity.hash;
        let emission = tx
            .prefix
            .inputs
            .iter()
            .any(|input| matches!(input, Input::ArchivalRewardEmission { .. }));

        // Key images (SI-1). The archival vin arms — serve-credit bit,
        // bond post, emission claim — are E4's hooks and write nothing here.
        let mut spent = self.open_insert_table(SPENT_KEYS, StoreInvariant::KeyImageNotFresh)?;
        for input in &tx.prefix.inputs {
            if let Input::ToKey { key_image, .. } = input {
                spent.insert(LmdbHashKey::from_bytes(*key_image), Present)?;
            }
        }
        drop(spent);

        // The hash-keyed index (SI-3), then the id-keyed bodies (SI-9).
        // `tx_id` is `txs_pruned`'s next dense key: unique keys make
        // `last + 1 == len` complete, so a hole (`{0, 3}` → len 2) poisons
        // instead of minting key 2 over the gap (PR #757 review).
        let mut pruned = self.open_insert_table(TXS_PRUNED, StoreInvariant::IdNotFresh)?;
        let tx_id = TxStorageId::from_raw(
            next_dense_id(
                pruned.last()?.as_ref().map(|(k, _)| k.value()),
                pruned.len()?,
            )
            .ok_or_else(|| self.poison().arm(StoreInvariant::IdNotFresh))?,
        );
        self.open_insert_table(TX_INDICES, StoreInvariant::TxHashNotFresh)?
            .insert(
                LmdbHashKey::from(tx_hash),
                TxIndex {
                    tx_id,
                    unlock_time: stored_timelock(tx.prefix.unlock_time),
                    height: BlockHeight::from_raw(height),
                }
                .encoded()
                .as_encoded(),
            )?;
        let segments = tx
            .write_segments()
            .expect("write_segments writes into Vecs; Vec writes are infallible");
        pruned.insert(
            tx_id.to_raw(),
            Raw::<TxPrunedSegment>::new(&segments.pruned),
        )?;
        drop(pruned);
        if !segments.pqc_auths.is_empty() {
            self.open_insert_table(TXS_PQC_AUTHS, StoreInvariant::IdNotFresh)?
                .insert(
                    tx_id.to_raw(),
                    Raw::<TxPqcAuthsSegment>::new(&segments.pqc_auths),
                )?;
        }
        self.open_insert_table(TXS_PRUNABLE, StoreInvariant::IdNotFresh)?
            .insert(
                tx_id.to_raw(),
                Raw::<TxPrunableSegment>::new(&segments.prunable),
            )?;
        self.open_insert_table(TXS_PRUNABLE_HASH, StoreInvariant::IdNotFresh)?
            .insert(
                tx_id.to_raw(),
                identity.prunable_hash.encoded().as_encoded(),
            )?;
        // The txid's third component, present ⇔ the txid is 4-part
        // (`PDM-Q-F26` leg 1; DRS §7.7). `None` is *the txid has no such
        // component* — coinbase, empty-auths spend — and writes no row; leg 2
        // (segment ⇒ row) is `validate`'s, which derived this identity
        // beside the body (CEN-B6) and refuses the one shape that could
        // split them. Never deleted by a prune: a row without its segment
        // is *discarded*, leg 3, not a fault.
        if let Some(pqc_auth_hash) = identity.pqc_auth_hash {
            self.open_insert_table(TXS_PQC_AUTH_HASH, StoreInvariant::IdNotFresh)?
                .insert(tx_id.to_raw(), pqc_auth_hash.encoded().as_encoded())?;
        }

        // Outputs: `output_txs` by global id, `output_amounts` under
        // `(amount, amount_index)` with the amount zeroed for miner /
        // emission, then the per-tx index list.
        let commitments = match &tx.ct {
            Ct::Null(base) | Ct::Fcmp { base, .. } => &base.commitments,
        };
        let mut output_txs = self.open_insert_table(OUTPUT_TXS, StoreInvariant::IdNotFresh)?;
        let mut amounts = self.open_insert_table(OUTPUT_AMOUNTS, StoreInvariant::IdNotFresh)?;
        let mut indices = Vec::with_capacity(tx.prefix.outputs.len());
        let mut rct = 0u64;
        for (i, output) in tx.prefix.outputs.iter().enumerate() {
            let local_index = u64::try_from(i).expect("vout count fits u64");
            let Some(commitment) = commitments.get(i) else {
                return Err(StoreCannot::OutputWithoutCommitment {
                    tx: identity.hash,
                    index: local_index,
                }
                .into());
            };
            let output_id = OutputStorageId::from_raw(
                next_dense_id(
                    output_txs.last()?.as_ref().map(|(k, _)| k.value()),
                    output_txs.len()?,
                )
                .ok_or_else(|| self.poison().arm(StoreInvariant::IdNotFresh))?,
            );
            output_txs.insert(
                output_id.to_raw(),
                OutTx {
                    tx_hash,
                    local_index: OutputIndexInTx::from_raw(local_index),
                }
                .encoded()
                .as_encoded(),
            )?;
            let amount = if miner || emission { 0 } else { output.amount };
            // `amount_index` is the bucket's next dense key (LMDB's
            // `mdb_cursor_count` after positioning on the amount). Under the
            // keyed `(amount, amount_index)` table (S-OUT-KI SOK-1) a
            // duplicate is unrepresentable — `insert` refuses a present key
            // — so SI-9's belt is density alone, stated with the premise
            // that makes it exact (SOK-Q2): the whole table holds **one**
            // bucket, because every miner and emission vout is stored under
            // `0` and CEN-H14 makes every other vout's amount `0`. So
            // `len() == last + 1` is exact, and a *second* bucket appearing
            // here is itself the breach: a non-miner, non-emission vout with
            // a non-zero amount reached the store, which the validator was
            // to refuse (`StoreInvariantViolated`, never a verdict — the
            // validator has the hole). SOK-2's belt rides the same check:
            // `output_id` is `output_txs`' next dense key, so with one
            // bucket `amount_index == output_id` for every output.
            let amount_index = AmountIndex::from_raw(
                next_amount_index(&amounts, amount)?
                    .filter(|next| *next == output_id.to_raw())
                    .ok_or_else(|| self.poison().arm(StoreInvariant::IdNotFresh))?,
            );
            let record = OutKey {
                output_id,
                pubkey: OneTimePubkey::from_bytes(output.key),
                unlock_time: stored_timelock(tx.prefix.unlock_time),
                height: BlockHeight::from_raw(height),
                commitment: CommitmentBytes::from_bytes(*commitment),
            };
            amounts.insert(
                (amount, amount_index.to_raw()),
                record.encoded().as_encoded(),
            )?;
            indices.push(amount_index);
            if miner || emission || output.amount == 0 {
                rct += 1;
            }
        }
        drop(output_txs);
        drop(amounts);
        self.open_insert_table(TX_OUTPUTS, StoreInvariant::IdNotFresh)?
            .insert(
                tx_id.to_raw(),
                TxOutputIndices(indices).encoded().as_encoded(),
            )?;
        Ok(rct)
    }
}

/// Next store-derived id for a unique-key primary. Dense iff the table is
/// empty or `last + 1 == len`; unique keys make that complete (keys
/// `{0, 3}` have `len == 2` and fail).
fn next_dense_id(last: Option<u64>, len: u64) -> Option<u64> {
    match last {
        None if len == 0 => Some(0),
        Some(last) if last.checked_add(1) == Some(len) => Some(len),
        _ => None,
    }
}

/// Next `amount_index` for one amount's bucket of the keyed
/// `(amount, amount_index)` table, or `None` if the table is not one dense
/// bucket (SI-9 as SOK-Q2 states it).
///
/// Two O(log n) reads: the bucket's last key and the table's length. Unique
/// keys make a duplicate unrepresentable, so density is `last + 1 == len`;
/// that equality is exact only when the bucket is the whole table, which is
/// the single-bucket premise — a second bucket makes it fail rather than
/// pass, because per-bucket indices are dense from zero (the belt is
/// self-guarding). The multimap's end-peek for a compensating
/// hole-plus-duplicate (`[0, 2, 2]`, PR #757 review) has nothing left to
/// catch.
fn next_amount_index<W>(
    amounts: &KeyedTable<'_, (u64, u64), Coded<OutKey>, W>,
    amount: u64,
) -> Result<Option<u64>, StoreError> {
    let last_in_bucket = amounts
        .range((amount, 0)..=(amount, u64::MAX))?
        .next_back()
        .transpose()
        .map_err(EngineError::Storage)?
        .map(|(key, _)| key.value().1);
    let len = amounts.len()?;
    Ok(next_dense_id(last_in_bucket, len))
}
