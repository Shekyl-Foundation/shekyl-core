// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `connect`: the connect write set (S-CHAIN-W commit 6; `DRS_E1_SCHAIN_W.md`
//! §2.3, §3.1, §3.2, §3.5, §4).
//!
//! The port of `BlockchainDB::add_block` (`blockchain_db.cpp:435`) and the
//! LMDB helpers it reaches, as one method on the batch that takes a
//! [`ChainValid`] the validator alone can mint (C2-R8 Q3) — every
//! consensus-visible value it records is the verdict's, and it derives
//! none (Q4; the last handed-in fact left with E6 slice 7 wave B). Every
//! write is a declared verb through a handle bound
//! to its `SI-` row (§7.3), every write is journaled for `pop` (Q5), and the
//! phases run in the C++ funnel's order so E3 (curve tree) and E4
//! (archival) attach at the same points without re-opening this contract:
//!
//! ```text
//!  1. belts        parent = recorded tip (SI-2); rule set in force (B3)
//!  2. transactions miner tx then listed → tx_indices, txs_*, tx_outputs,
//!                  output_txs, output_amounts, spent_keys (SI-3, SI-9, SI-1);
//!                  then the delta's archival_bond post-images (SI-19/20)
//!                  and archival_serve_credit bits (SI-15) —
//!                  `archival_write.rs`, DRS-E4
//!  3. tree         the verdict's drain → curve_tree_leaves, the position
//!                  maps, curve_tree_layers, curve_tree_meta (SI-11/12/17);
//!                  curve_tree_leaf_counts[h + 1] every connect (SI-18) —
//!                  `grow.rs`, DRS-E3
//!  4. root         curve_tree_roots[h + 1] = the verdict's root_after (SI-4)
//!                  — every connect, grown or not (the C++ write at
//!                  :663–:664 is outside the growth gate; SCW-19)
//!  5. witness      archival_attestation_witness[h] = the verdict's sidecar,
//!                  when non-empty — `archival_write.rs`
//!  6. block        blocks[h], block_heights[hash], block_info[h] (SI-2)
//!  7. rule set     hf_versions[h] = in_force (the CEN-B3 belt)
//!  8. burn         block_burn[h] only if h > 0 && burned > 0
//!                  (blockchain.cpp:6148); total_burned += burned + Σ slash
//!                  burns, one fold (SI-8; ARW-6) — `archival_write.rs`
//!  9. archival     archival_budget_accruing[E] upserted, or removed at E's
//!                  close (SI-23); slash log + applied + watermark (SI-22);
//!                  r_market / sigma_work / budget at a close (SI-21) —
//!                  `archival_write.rs`, DRS-E4
//! 10. journal      undo_log[h] (SI-6)
//! ```
//!
//! Every phase has a body: E3's landed in phase 3 (`grow.rs`), E4's in
//! phases 2, 5, 8 and 9 (`archival_write.rs`). `pop` has no phase list — it
//! is the reverse replay of step 10's row.
//!
//! # What the connect stamps (§3.8)
//!
//! Between the belts and the writes, `connect` widens the file's
//! [`Provenance`](crate::provenance::Provenance) inside this batch's own
//! transaction with what a parity claim must know: the census rows
//! `in_force` enforces that the verdict's coverage did **not** evaluate
//! (C2-R8 §9.4). A union that never narrows; an aborted batch leaves no
//! taint. A file with it non-empty is not parity evidence, and says which
//! rows have to land for it to become so. (A second set — the fields the
//! caller passed through rather than the validator derived, SCW-1 — was
//! stamped beside it until E6 slice 7 wave B derived the last one; the
//! cell and its vocabulary left the layout then, `SCHEMA_VERSION` 17.)
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
//! (`DRS_E1_SOUT_KI.md` §3.4). The single-bucket premise is checked at
//! both ends of the table before `len` is trusted as the bucket's
//! cardinality: a second bucket, or a hole compensated by a foreign row,
//! is SI-9, never a verdict.

use shekyl_chain_rules::{ChainValid, RuleSet, TxIdentity};
use shekyl_types::{
    ArchivalLength, BlockHash, BlockHeight, CommitmentBytes, OneTimePubkey, OutputIndexInTx,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Ct, Input, Transaction};

use crate::codec::{
    stored_timelock, BlockBody, BlockInfo, Canonical, Coded, CoverageGaps, OutKey, OutTx, Present,
    Raw, RuleSetInForce, TxIndex, TxOutputIndices, TxPqcAuthsSegment, TxPrunableSegment,
    TxPrunedSegment,
};
use crate::ids::{AmountIndex, OutputSlot, OutputStorageId, TxStorageId};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{
    BLOCKS, BLOCK_HEIGHTS, BLOCK_INFO, CURVE_TREE_ROOTS, HF_VERSIONS, OUTPUT_AMOUNTS, OUTPUT_TXS,
    SPENT_KEYS, TXS_ARCHIVAL_LEN, TXS_PQC_AUTHS, TXS_PQC_AUTH_HASH, TXS_PRUNABLE,
    TXS_PRUNABLE_HASH, TXS_PRUNED, TX_INDICES, TX_OUTPUTS,
};

use super::error::{CellFault, StoreCannot, StoreError, StoreInvariant};
use super::header;
use super::keyed::KeyedTable;
use super::prune::Pruned;
use super::view::BatchView;
use super::write::WriteBatch;

// `ConnectFacts`, `Fact`, `Origin` and `DeletedBy` lived here from S-CHAIN-W
// commit 6 (2026-09-13) to E6 slice 7 wave B (2026-09-29): the
// consensus-visible values the store recorded and never derived (C2-R8 Q4),
// each stamped `Derived` or `PassedThrough` (SCW-1) and each named with the
// census rows whose landing would delete it (`DRS_E1_SCHAIN_W.md` §3.2's
// table, as data). Seven fields at the peak; `cumulative_difficulty` left
// with CEN-D4 (slice 2), `root_after` with DRS-E3, the two weights, the
// median and `coins_generated` with slice 7 commits 4–5, and `burned` — the
// last — with CEN-F17 / G11. `connect` reads every one off the verdict now,
// and the types went with their last field, as their own docs said they
// would rather than survive as a permanent `Derived` (rule 15).

/// What `connect` recorded. Nothing consensus-visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connected {
    /// The height the block was recorded at.
    pub height: BlockHeight,
    /// Entries in the block's `undo_log` row.
    pub journaled: usize,
    /// What the retention prune retired in this connect's transaction —
    /// `Some` only at a boundary `E·SEB`, `E ≥ 2` (DRS-E1 S-PRUNE,
    /// `store/prune.rs`).
    pub pruned: Option<Pruned>,
}

impl<'id> WriteBatch<'_, 'id> {
    /// Record a validated block at tip + 1.
    ///
    /// `valid` is branded with this batch (`'id`) and with this batch's
    /// view type, so a verdict minted anywhere else does not unify.
    /// `in_force` is the rule set the driver's schedule names for the
    /// height — **the set itself, by value** (DRS-E2 RD-Q10), not its id:
    /// Fakechain `Fixed` sets reuse `RuleSetId::GENESIS` by design, so no id
    /// resolves to one and an id parameter could never name the set a
    /// regtest driver has in force. The store compares the value with the
    /// verdict's and refuses a mismatch, holding no schedule and no `Network`
    /// itself (rule 71): it receives a value and compares. Resolving an id to
    /// a set — and refusing an id no schedule issued — is the schedule's job,
    /// where the id→set mapping lives.
    ///
    /// May be called repeatedly on one batch: the view for block *h+1*
    /// sees block *h*, and each call journals its own row.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::RuleSetNotInForce`] if `valid` was judged under a
    /// rule set other than `in_force` (compared by value); [`StoreCannot::OutputWithoutCommitment`]
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
        in_force: RuleSet,
    ) -> Result<Connected, StoreError> {
        // ---- 1. belts -------------------------------------------------
        // The connecting height is known from the tip's key alone and is
        // noted **before** any belt can fire: a violation here must halt
        // the writer at this height (§3.6.2), and the halt reads the noted
        // height — a belt that poisoned first would leave the writer live.
        // The parent's `cumulative_tx_count` and `cumulative_archival_len`
        // ride out of the same decoded tip row (§3.6): genesis has no parent
        // and starts both at 0.
        let (height, parent_tx_count, parent_archival_len) = {
            let tip = self.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?;
            let last = tip.last()?;
            let height = last.as_ref().map_or(0, |(h, _)| h.value() + 1);
            self.journal().note_height(height);
            let mut parent_tx_count = 0;
            let mut parent_archival_len = ArchivalLength::ZERO;
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
                parent_archival_len = info.cumulative_archival_len;
            }
            (height, parent_tx_count, parent_archival_len)
        };
        // Compared by **value** (d6ba4d98f; RD-Q10): Fakechain `Fixed`
        // reuses `RuleSetId::GENESIS`, so an id-only check would accept
        // fixed-target work as public-network GENESIS work — and an id
        // *parameter* could never name a Fakechain set as in force at all,
        // which is why the caller hands the set (RD-F13). No resolution
        // happens here: an id no schedule issued is the schedule's refusal.
        if valid.rule_set() != in_force {
            return Err(StoreCannot::RuleSetNotInForce {
                height,
                judged: Box::new(valid.rule_set()),
                in_force: Box::new(in_force),
            }
            .into());
        }
        // SCW-7 and SCW-2 at the height they apply to: the undo retention
        // covers the in-force set's reorg cap, or a legal reorg from this
        // block would meet `PopBelowFloor`; and the pinned settlement epoch
        // is the in-force set's, or the verdict's archival rows were judged
        // under a geometry this file does not hold. The open refused both
        // against what the caller named; this is the same pair against the
        // set actually handed in, so a schedule step that moves either is
        // refused at its first block, not discovered at its first reorg or
        // its first mislabeled claim.
        self.horizons().check_against(&in_force)?;

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
                in_force
                    .enforced()
                    .filter(|row| !valid.coverage().contains(*row)),
            ),
        )
        .map_err(|e| self.arm_if_invariant(e))?;

        let block = valid.block();
        let recording = self.record_undo(height);

        // ---- 2. transactions -------------------------------------------
        // Each transaction's archival length folds onto the parent's in
        // recording order — the order storage ids are issued — so the running
        // value before a transaction is the offset it starts from (SHT-Q2).
        let (miner_identity, miner_tx) = block.miner_tx();
        let miner = self.record_tx(height, miner_identity, miner_tx, true)?;
        let mut rct_outputs = miner.rct;
        let mut archival_len = parent_archival_len.checked_add(miner.archival_len);
        for (identity, tx) in block.transactions() {
            let recorded = self.record_tx(height, *identity, tx, false)?;
            rct_outputs += recorded.rct;
            archival_len = archival_len.and_then(|len| len.checked_add(recorded.archival_len));
        }
        let cumulative_archival_len = archival_len
            .ok_or(StoreInvariant::FoldOverflow {
                cell: "block_info.cumulative_archival_len",
            })
            .map_err(|row| self.poison().arm(row))?;
        // The archival half (DRS-E4; `archival_write.rs`): the bond records
        // and serve credits the block's transactions produced — written
        // once, from the delta's per-persona post-images, after the loop
        // that recorded the transactions themselves.
        self.record_archival_records(height, &valid)?;

        // ---- 3. tree (DRS-E3; `grow.rs`) --------------------------------
        self.record_drain(height, &valid)?;

        // ---- 4. root ---------------------------------------------------
        // The verdict's, derived by `validate` over this batch's view
        // (`CTW-Q1`: the root determines future validity, so the authority
        // over validity derives it). The store records it; the next
        // header must carry it (CEN-B5) and a spend referencing `h + 1`
        // anchors to it (CEN-I12).
        self.open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)?
            .insert(height + 1, block.root_after().encoded().as_encoded())?;

        // ---- 5. attestation witness (DRS-E4; `archival_write.rs`) -------
        // The verdict's sidecar, written unjudged until CEN-B4 lands in
        // `validate`: the provenance widening above records B4 as a
        // coverage gap for exactly as long as that is so.
        self.record_attestation_witness(height, block.attestation_witness())?;

        // ---- 6. block --------------------------------------------------
        let hash = BlockHash::from_bytes(*block.hash().as_bytes());
        self.open_insert_table(BLOCKS, StoreInvariant::TipMismatch)?
            .insert(height, Raw::<BlockBody>::new(&block.block().serialize()))?;
        self.open_insert_table(BLOCK_HEIGHTS, StoreInvariant::TipMismatch)?
            .insert(
                LmdbHashKey::from(hash),
                BlockHeight::from_raw(height).encoded().as_encoded(),
            )?;
        // The weights (CEN-G6/G6b) and the paid emission (CEN-F14b, G12)
        // are the verdict's, derived by `validate` over this batch's view
        // and carried on it (slice 7 Q5); the store records what the rules
        // computed and computes nothing consensus-visible (C2-R8 Q4).
        let weights = block.weights();
        let info = BlockInfo {
            timestamp: shekyl_types::Timestamp::from_raw(block.header().timestamp),
            // G12: the parent's accumulator advanced by F14b's paid reward.
            coins_generated: block.emission().coins_generated,
            weight: weights.weight,
            // Derived by the validator (CEN-D4: the parent's work plus this
            // block's target, `checked_add` there) and carried on the
            // verdict (E6 slice 2 Q5).
            cumulative_difficulty: block.cumulative_difficulty(),
            hash,
            // Per-block, not accumulated: LMDB's `bi_cum_rct` is this block's
            // count and nothing accumulates it (CEN-L15) — see
            // `BlockInfo::rct_outputs`.
            rct_outputs,
            // G6b: the block's weight clamped under the median in force.
            long_term_weight: weights.long_term_weight,
            // Store-derived running total (§3.6): the parent's plus this
            // block's listed transactions, under SI-8 like `total_burned`.
            cumulative_tx_count: parent_tx_count
                .checked_add(u64::try_from(block.transactions().len()).expect("tx count fits u64"))
                .ok_or(StoreInvariant::FoldOverflow {
                    cell: "block_info.cumulative_tx_count",
                })
                .map_err(|row| self.poison().arm(row))?,
            // G6: the median in force **for** `h` — derived at `connecting =
            // h` over the weights below it — stored at `h`, not the
            // recompute that belongs to `h + 1` (SCR-19). The verdict can
            // carry no other: `Medians::derive` reads the window that ends
            // at the connecting height.
            long_term_effective_median: weights.medians.long_term_effective_median,
            // Store-derived running total (SHT-Q2), folded above under SI-8.
            cumulative_archival_len,
        };
        self.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?
            .insert(height, info.encoded().as_encoded())?;

        // ---- 7. rule set (CEN-B3's belt) --------------------------------
        // The belt stores the **id**, and the id is not the set: under
        // `DifficultyRule::Fixed` two different Fakechain sets both carry
        // `RuleSetId::GENESIS` (`RuleSet::fakechain`'s doc — id equality is
        // not a proxy for set equality). This row records which *issued*
        // schedule position the height was judged at; a reader that needs
        // the set (a Fakechain target) does not have it here and must not
        // pretend to (RD-Q10, ruled 2026-09-19).
        self.open_insert_table(HF_VERSIONS, StoreInvariant::TipMismatch)?
            .insert(height, RuleSetInForce(in_force.id()).encoded().as_encoded())?;

        // ---- 8. burn (`archival_write.rs`) ------------------------------
        // The emission burn is the verdict's (CEN-F17 / G11: the fee split
        // the validator priced over its own parent-state reads; E6 slice 7
        // wave B); the slash burns are the verdict's too (the delta's). The
        // row is conditional exactly as `blockchain.cpp:6148` (`new_height
        // > 0 && block_burn_amount > 0`); the cell takes both contributors
        // through one fold (DRS-E4 `ARW-6`, SI-8).
        self.record_burn(height, block.emission().burned(), block.archival())?;

        // ---- 9. accrual row, slash, epoch close (`archival_write.rs`) ---
        self.record_archival_epoch(BlockHeight::from_raw(height), &valid)?;

        // ---- 10. journal -----------------------------------------------
        let journaled = recording.seal()?;
        // ---- 11. the retention prune (S-PRUNE) -------------------------
        // After the seal, so the boundary block's undo row carries the
        // block's writes and none of the prune's (a discard is not
        // pop-reversible, `prune.rs`); inside this transaction, so a chain
        // connected past `E·SEB` with `D(E)` un-run is unrepresentable.
        let pruned = self.prune_at_boundary(height)?;
        Ok(Connected {
            height: BlockHeight::from_raw(height),
            journaled,
            pruned,
        })
    }

    /// One transaction's rows (`add_transaction` / `add_transaction_data` /
    /// `add_output` / `add_tx_amount_output_indices`), plus its archival
    /// length row. Returns what the block row folds: how many of its outputs
    /// count toward `block_info.rct_outputs`, and its archival length.
    fn record_tx(
        &self,
        height: u64,
        identity: TxIdentity,
        tx: &Transaction,
        miner: bool,
    ) -> Result<RecordedTx, StoreError> {
        let tx_hash = identity.hash;
        let emission = tx
            .prefix
            .inputs
            .iter()
            .any(|input| matches!(input, Input::ArchivalRewardEmission { .. }));

        // Key images (SI-1). The archival vin arms — serve-credit bit,
        // bond post, emission claim — write nothing here: what they do to
        // the archival state is the verdict's delta, written once after the
        // transaction loop (`archival_write.rs`).
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
        // The archival length (SHT-Q2): measured on the two segments just
        // written, so the row and the bytes a prune discards are one
        // serialization. Sparse — present ⇔ `> 0` ⇔ the transaction carries
        // archival good (pinned class by class in `shekyl-chain-rules`'
        // `tx_domain_tests`) — and permanent: a prune never deletes it.
        let archival_len = segments.archival_len();
        if archival_len > ArchivalLength::ZERO {
            self.open_insert_table(TXS_ARCHIVAL_LEN, StoreInvariant::IdNotFresh)?
                .insert(tx_id.to_raw(), archival_len.encoded().as_encoded())?;
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
            let bucket = if miner || emission {
                OutputSlot::CONFIDENTIAL_AMOUNT
            } else {
                AtomicUnits::from_raw(output.amount)
            };
            // SI-9 / SOK-2: one dense bucket whose next index is this output_id.
            let slot = next_output_slot(&amounts, bucket, output_id)?
                .ok_or_else(|| self.poison().arm(StoreInvariant::IdNotFresh))?;
            let record = OutKey {
                output_id,
                pubkey: OneTimePubkey::from_bytes(output.key),
                unlock_time: stored_timelock(tx.prefix.unlock_time),
                height: BlockHeight::from_raw(height),
                commitment: CommitmentBytes::from_bytes(*commitment),
            };
            amounts.insert(slot.key(), record.encoded().as_encoded())?;
            indices.push(slot.index());
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
        Ok(RecordedTx { rct, archival_len })
    }
}

/// What one transaction's rows contribute to its block's `block_info` row.
struct RecordedTx {
    /// Outputs counted toward `block_info.rct_outputs`.
    rct: u64,
    /// Its archival length, folded into `block_info.cumulative_archival_len`.
    archival_len: ArchivalLength,
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

/// The slot `output_id` occupies in `bucket`, or `None` if SI-9 would not
/// hold: the table is not exactly that one dense bucket, or its next index
/// is not `output_id` (SOK-2).
///
/// Three O(log n) reads: first key, last key, length. Keys sort by
/// `(amount, index)`, so a foreign-bucket row sits at an end — both ends
/// carrying `bucket` **is** the single-bucket premise. Only then is `len`
/// the bucket's cardinality; unique keys make density `last + 1 == len`.
/// A hole compensated by a foreign row (`(0,0), (0,2), (7,x)`) would pass
/// the length check alone. Mixed first/last is not an empty table.
fn next_output_slot<W>(
    amounts: &KeyedTable<'_, (u64, u64), Coded<OutKey>, W>,
    bucket: AtomicUnits,
    output_id: OutputStorageId,
) -> Result<Option<OutputSlot>, StoreError> {
    let next = match (amounts.first()?, amounts.last()?) {
        (None, None) => next_dense_id(None, 0),
        (Some((first, _)), Some((last, _))) => {
            let first = OutputSlot::from_key(first.value());
            let last = OutputSlot::from_key(last.value());
            if first.amount() != bucket || last.amount() != bucket {
                return Ok(None);
            }
            next_dense_id(Some(last.index().to_raw()), amounts.len()?)
        }
        _ => return Ok(None),
    };
    match next {
        Some(n) if n == output_id.to_raw() => {
            Ok(Some(OutputSlot::new(bucket, AmountIndex::from_raw(n))))
        }
        _ => Ok(None),
    }
}
