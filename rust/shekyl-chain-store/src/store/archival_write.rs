// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connect's archival phase bodies — the archival writer (DRS-E4,
//! `DRS_E4_ARCHIVAL_WRITER.md` §3.2; `ARW-Q1` RULED: the verdict derives
//! the transition, the store records it). The bodies of the `[E4 hook]`s
//! in `connect`'s phase list: the bond records and serve credits after the
//! transactions (phase 2), the attestation witness (phase 5), the slash
//! burn folded into `total_burned` (phase 8), and the accrual, the slashes
//! and the epoch close (phase 9).
//!
//! **The store persists; it does not compute** (C2-R8 principle 3). Every
//! row written here is a part of the verdict's [`ArchivalDelta`] — the
//! record post-images, the credit keys, the slash entries and what each
//! burned, the accruing total, the close's frozen facts. What the store
//! adds is the belts: SI-15 (a credit names a persona with a record),
//! SI-19 (a join inserts once), SI-20 (an update replaces a present
//! persona), SI-21 (an epoch closes whole, once), SI-22 (the slash log is
//! dense per height, and an applied key is written once), SI-23 (the
//! accruing table holds the open epoch's row and no other), and SI-8 for
//! the burn fold. A delta that does not fit the tables is not adjusted;
//! the writer halts.
//!
//! ```text
//!  2.  records   archival_bond[p] = post-image — Insert (SI-19) / Replace (SI-20)
//!      credits   archival_serve_credit[(p, s, E, h)] = Present      (SI-15)
//!  5.  witness   archival_attestation_witness[h] = bytes, non-empty only
//!  8.  burn      total_burned += emission burn + Σ slash burns       (SI-8)
//!  9a. accrual   archival_budget_accruing[E] = total — or, at E's close,
//!                the row is removed                                 (SI-23)
//!  9b. slashes   archival_slash_log[(h, seq)] = entry, seq dense    (SI-22)
//!                archival_slash_applied[(p, s, E)] = Present
//!                archival_last_slash_epoch = watermark, when it moves
//!  9c. close     archival_r_market[(s, E)], archival_sigma_work[E],
//!                archival_budget[E] — each insert-once on E          (SI-21)
//! ```
//!
//! The C++'s order is kept where the C++ had one (`blockchain_db.cpp:680–
//! 693`: the accrual row, then `process_archival_slash_at_height`, then
//! `process_archival_epoch_close_at_height`). Where the plan placed the
//! record writes *inside* `record_tx` — one write per archival vin — the
//! delta made that shape unavailable and the better one obvious: the delta
//! carries each persona's **final** post-image for the block, slashes
//! folded in, so the records are written **once, after the transaction
//! loop**. An update replaces a present row (SI-20); there is no second
//! pass over the table.
//!
//! # Skip-and-widen (`ARW-9`)
//!
//! A family this session's [`ApplyPolicy`](crate::ApplyPolicy) stubs is
//! **skipped**, not refused: the phase body asks
//! [`ApplyPolicy::applies`](crate::ApplyPolicy::applies) before opening
//! the family's table, and the commit widens the file's provenance with
//! the stubbed set exactly as it would have had the body run into
//! `admit`'s refusal. This is what makes a sufficiency red attributable —
//! a file connected under a stub is not parity evidence, and its
//! provenance says which family it is missing. The one Rust-only table,
//! `archival_budget_accruing`, has no C++ family of its own and is
//! governed by the family whose per-height rows it replaced,
//! `ArchivalFamily::BudgetAccrual` (`ARW-Q3`). The belts that read across
//! families — SI-15 reads `archival_bond` for a credit — run only when
//! both families apply: a stubbed `Bond` leaves no records, and a credit
//! written against that absence is the stub, not a fault.
//!
//! # What the slash burns into (`ARW-6`)
//!
//! `total_burned` is not an archival family: it is the chain-state cell
//! phase 8 owns, and the slash contribution goes through phase 8's one
//! fold. `block_burn[h]` stays the emission burn alone, as the C++ has it
//! (`apply_archival_slash_one` adds to `total_burned` and to nothing
//! per-height, `db_lmdb.cpp:5615–5618`); the cell's write is one
//! `checked_add` over both contributors, so SI-8 sees one running total.
//!
//! # The regtest injector (§3.8 item 3)
//!
//! [`ChainStore::regtest_inject_serve_credit`](super::ChainStore::regtest_inject_serve_credit)
//! is the writer's own test hook — the door the C++'s
//! `regtest_inject_archival_serve_credit` (`blockchain.cpp:4708`) opened,
//! writing a serve-credit bit the rules did not admit, attributed to the
//! tip's height, refused off Fakechain. It lives beside the phase bodies
//! because it writes their table and nothing else may. It is **not
//! journaled**: it runs in its own transaction outside any block's
//! recording, so no `undo_log` row names it, and a pop below its height
//! leaves the bit — the C++'s behaviour, and the corpus's `Inject` event
//! (commit 7) is a pipeline barrier for the same reason.

use shekyl_chain_rules::{
    ArchivalDelta, ChainValid, ChainView, RecordWriteKind, ReleaseAnchors, Trust,
};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_units::AtomicUnits;

use crate::apply_policy::ArchivalFamily;
use crate::codec::{
    ArchivalLastSlashEpochCell, AttestationWitnessBytes, Canonical, Present, PropertyCell, Raw,
    TotalBurnedCell,
};
use crate::ids::{ServeCreditKey, SlashAppliedKey, SlashLogKey};
use crate::schema::{
    ARCHIVAL_ATTESTATION_WITNESS, ARCHIVAL_BOND, ARCHIVAL_BUDGET, ARCHIVAL_BUDGET_ACCRUING,
    ARCHIVAL_R_MARKET, ARCHIVAL_SERVE_CREDIT, ARCHIVAL_SIGMA_WORK, ARCHIVAL_SLASH_APPLIED,
    ARCHIVAL_SLASH_LOG, BLOCK_BURN, BLOCK_INFO,
};

use super::archival_reads;
use super::error::{
    AccrualFault, EngineError, SlashFault, StoreCannot, StoreError, StoreInvariant,
};
use super::write::WriteBatch;
use super::ChainStore;

impl<'id> WriteBatch<'_, 'id> {
    /// Phase 2's archival half: the block's bond records and serve credits.
    ///
    /// Runs after the transaction loop — see the module doc for why the
    /// records are written once rather than per vin.
    pub(super) fn record_archival_records<V: ChainView<'id>>(
        &self,
        height: u64,
        valid: &ChainValid<'id, V>,
    ) -> Result<(), StoreError> {
        let delta = valid.block().archival();
        let bonds_apply = self.apply_policy().applies(ArchivalFamily::Bond);
        if bonds_apply {
            self.write_bond_records(delta)?;
        }
        if self.apply_policy().applies(ArchivalFamily::ServeCredit) {
            self.write_serve_credits(height, delta, bonds_apply)?;
        }
        Ok(())
    }

    /// `archival_bond[p] = post-image` for every record the delta carries.
    /// A join inserts once (SI-19). A later change replaces a present row
    /// (SI-20): an absent persona is the bound row, returned before any
    /// journal entry. The two handles do not coexist — redb holds one
    /// handle per table per transaction.
    fn write_bond_records(&self, delta: &ArchivalDelta) -> Result<(), StoreError> {
        let records = delta.records();
        if records.is_empty() {
            return Ok(());
        }
        {
            let mut inserts =
                self.open_insert_table(ARCHIVAL_BOND, StoreInvariant::BondRecordNotFresh)?;
            for write in records
                .iter()
                .filter(|w| w.kind() == RecordWriteKind::Insert)
            {
                inserts.insert(
                    *write.persona().as_bytes(),
                    write.record().encoded().as_encoded(),
                )?;
            }
        }
        {
            let mut updates =
                self.open_replace_table(ARCHIVAL_BOND, StoreInvariant::BondRecordAbsent)?;
            for write in records
                .iter()
                .filter(|w| w.kind() == RecordWriteKind::Update)
            {
                updates.replace(
                    *write.persona().as_bytes(),
                    write.record().encoded().as_encoded(),
                )?;
            }
        }
        Ok(())
    }

    /// `archival_serve_credit[(p, s, E, h)] = Present` for every credit the
    /// block earns. Upserted: the bit is a set membership, and the C++
    /// `set_archival_serve_credit_bit` is idempotent on it. `check_bonds`
    /// arms SI-15's write side — a credit for a persona with no record.
    fn write_serve_credits(
        &self,
        height: u64,
        delta: &ArchivalDelta,
        check_bonds: bool,
    ) -> Result<(), StoreError> {
        let credits = delta.serve_credits();
        if credits.is_empty() {
            return Ok(());
        }
        if check_bonds {
            for credit in credits {
                let record = archival_reads::bond_record(self.txn(), &credit.persona)
                    .map_err(|f| self.arm_read_fault(f))?;
                if record.is_none() {
                    return Err(self.poison().arm(StoreInvariant::ServeCreditWithoutBond {
                        persona: credit.persona,
                    }));
                }
            }
        }
        let mut table = self.open_upsert_table(ARCHIVAL_SERVE_CREDIT)?;
        let height = BlockHeight::from_raw(height);
        for credit in credits {
            let key = ServeCreditKey::new(credit.persona, credit.shard, credit.epoch, height);
            table.upsert(key.key(), Present)?;
        }
        Ok(())
    }

    /// Phase 5: `archival_attestation_witness[h] = witness` when the
    /// verdict carries one. An empty set is no row — the type cannot hold
    /// one ([`AttestationWitness::new`]), so the absence is `None` here.
    /// Insert-once per height on the tip's row (SI-2): a row already at
    /// `h` is a connect at the wrong height.
    pub(super) fn record_attestation_witness(
        &self,
        height: u64,
        witness: Option<&AttestationWitness>,
    ) -> Result<(), StoreError> {
        let Some(witness) = witness else {
            return Ok(());
        };
        if !self
            .apply_policy()
            .applies(ArchivalFamily::AttestationWitness)
        {
            return Ok(());
        }
        self.open_insert_table(ARCHIVAL_ATTESTATION_WITNESS, StoreInvariant::TipMismatch)?
            .insert(
                height,
                Raw::<AttestationWitnessBytes>::new(witness.as_bytes()),
            )?;
        Ok(())
    }

    /// Phase 8: the burn — the emission burn's row, and `total_burned`
    /// advanced by the emission burn **and** every slash's burn in one
    /// fold (`ARW-6`; SI-8). `block_burn[h]` is written only when the
    /// emission burn is non-zero and `h > 0` (`blockchain.cpp:6148`); the
    /// cell is written when either contributor is, so a slash-only block
    /// moves the running total and writes no per-height row — the C++'s
    /// declared write set.
    pub(super) fn record_burn(
        &self,
        height: u64,
        emission_burn: AtomicUnits,
        delta: &ArchivalDelta,
    ) -> Result<(), StoreError> {
        if height == 0 {
            return Ok(());
        }
        let slashed = delta
            .slashes()
            .iter()
            .try_fold(AtomicUnits::ZERO, |sum, slash| {
                sum.checked_add(slash.burned)
            })
            .ok_or(StoreInvariant::FoldOverflow {
                cell: TotalBurnedCell::KEY,
            })
            .map_err(|row| self.poison().arm(row))?;
        if emission_burn != AtomicUnits::ZERO {
            self.open_insert_table(BLOCK_BURN, StoreInvariant::TipMismatch)?
                .insert(height, emission_burn.encoded().as_encoded())?;
        }
        if emission_burn == AtomicUnits::ZERO && slashed == AtomicUnits::ZERO {
            return Ok(());
        }
        let total = self
            .get_property::<TotalBurnedCell>()?
            .unwrap_or(AtomicUnits::ZERO)
            .checked_add(emission_burn)
            .and_then(|total| total.checked_add(slashed))
            .ok_or(StoreInvariant::FoldOverflow {
                cell: TotalBurnedCell::KEY,
            })
            .map_err(|row| self.poison().arm(row))?;
        self.upsert_property::<TotalBurnedCell>(&total)
    }

    /// Phase 9: the accrual, the slashes, the close — in the C++'s order
    /// (`blockchain_db.cpp:689–693`).
    pub(super) fn record_archival_epoch<V: ChainView<'id>>(
        &self,
        connecting: BlockHeight,
        valid: &ChainValid<'id, V>,
    ) -> Result<(), StoreError> {
        let delta = valid.block().archival();
        if self.apply_policy().applies(ArchivalFamily::BudgetAccrual) {
            self.write_accrual(delta)?;
        }
        self.write_slashes(connecting, delta)?;
        if let Some(close) = delta.close() {
            let policy = self.apply_policy();
            let epoch = close.epoch();
            if policy.applies(ArchivalFamily::RMarket) {
                let mut table = self.open_insert_table(
                    ARCHIVAL_R_MARKET,
                    StoreInvariant::EpochCloseRewritten { epoch },
                )?;
                for (shard, r_market) in close.r_market() {
                    table.insert(
                        (shard.to_raw(), epoch.to_raw()),
                        r_market.encoded().as_encoded(),
                    )?;
                }
            }
            if policy.applies(ArchivalFamily::SigmaWork) {
                self.open_insert_table(
                    ARCHIVAL_SIGMA_WORK,
                    StoreInvariant::EpochCloseRewritten { epoch },
                )?
                .insert(epoch.to_raw(), close.sigma_work().encoded().as_encoded())?;
            }
            if policy.applies(ArchivalFamily::Budget) {
                self.open_insert_table(
                    ARCHIVAL_BUDGET,
                    StoreInvariant::EpochCloseRewritten { epoch },
                )?
                .insert(epoch.to_raw(), close.budget().encoded().as_encoded())?;
            }
        }
        Ok(())
    }

    /// 9a. `archival_budget_accruing[E] = total` — or, when this block
    /// closes `E`, the row is **removed** (`ARW-Q3`, second half: the
    /// budget row is the total's permanent home, and the accruing row a
    /// second copy). SI-23 either way: before the write, every row the
    /// table holds is keyed by `E` or the table is empty (a row keyed
    /// otherwise is a close that did not delete, or a re-key); at the
    /// close, the row must be there to remove. The second cannot fire
    /// spuriously: a session's geometry has `SEB ≥ 2`
    /// ([`Horizons`](super::Horizons) holds `cap < SEB` with `cap ≥ 1`), so
    /// `E`'s first block is never its closing block and always wrote the
    /// row.
    fn write_accrual(&self, delta: &ArchivalDelta) -> Result<(), StoreError> {
        let accrual = delta.accrual();
        let epoch = accrual.epoch;
        {
            // Admission runs because the handle opens through the verb.
            // Every row keyed by `E`: a B-tree's first and last keys equal
            // `E` iff every key does. The handle drops before the remove
            // or the upsert — redb holds one per table per transaction.
            let table = self.open_upsert_table(ARCHIVAL_BUDGET_ACCRUING)?;
            let ends = [table.first()?, table.last()?];
            for (key, _) in ends.into_iter().flatten() {
                let found = SettlementEpoch::from_raw(key.value());
                if found != epoch {
                    return Err(self.poison().arm(StoreInvariant::AccruingNotSingular {
                        observed: AccrualFault::StaleRow { epoch: found },
                    }));
                }
            }
        }
        if let Some(close) = delta.close() {
            debug_assert_eq!(close.epoch(), epoch, "a close closes the open epoch");
            self.open_remove_table(
                ARCHIVAL_BUDGET_ACCRUING,
                StoreInvariant::AccruingNotSingular {
                    observed: AccrualFault::AbsentAtClose,
                },
            )?
            .remove(epoch.to_raw())?;
            return Ok(());
        }
        self.open_upsert_table(ARCHIVAL_BUDGET_ACCRUING)?
            .upsert(epoch.to_raw(), accrual.total.encoded().as_encoded())?;
        Ok(())
    }

    /// 9b. The slashes: `archival_slash_log[(h, seq)] = entry` for `seq`
    /// dense from `0`, `archival_slash_applied[(p, s, E)] = Present`, then
    /// the watermark cell when it moves. Density is SI-22's
    /// [`SlashFault::NotDense`], bound at the log handle and checked once
    /// more before the first append: a row already at `h` means the log
    /// is not dense at this height. A repeated applied key is
    /// [`SlashFault::AlreadyApplied`] for that key — the persona is not
    /// known when the handle opens, so the insert names it.
    ///
    /// **The log row's `h` is the connecting height** — the block whose
    /// connect ran the deadline scan that decided the slash — and the
    /// signature says so: `connecting: BlockHeight`, the ordinal of a block
    /// that exists at decision time, never the [`ChainCount`] the schedule
    /// comparisons take (`Transition::count()`, one above). The C++ keys
    /// the same row by that count (`db_lmdb.cpp` `apply_archival_slash_one`
    /// is handed `prev_height + 1`), so the two writers' rows for one fold
    /// sit one apart; no document specifies which is meant, and the choice
    /// is **posed, not ruled** — `DRS_E4_ARCHIVAL_WRITER.md` `ARW-Q17`,
    /// with the read-side consequence for `slash_log_after` /
    /// `holds_shard_at` stated there. Until it is ruled, this is the Rust
    /// writer's position, typed so that moving it is a signature change,
    /// not a renumbering.
    ///
    /// [`ChainCount`]: shekyl_types::ChainCount
    fn write_slashes(
        &self,
        connecting: BlockHeight,
        delta: &ArchivalDelta,
    ) -> Result<(), StoreError> {
        let policy = self.apply_policy();
        let log_applies = policy.applies(ArchivalFamily::SlashLog);
        let applied_applies = policy.applies(ArchivalFamily::SlashApplied);
        let slashes = delta.slashes();
        let height = connecting.to_raw();
        let not_dense = StoreInvariant::SlashLogNotDense {
            height,
            observed: SlashFault::NotDense,
        };
        if log_applies && !slashes.is_empty() {
            let mut log = self.open_insert_table(ARCHIVAL_SLASH_LOG, not_dense)?;
            // Dense means `(h, 0)` is the first row at or above `(h, 0)`
            // only if nothing sits at `h` yet: the first key from there
            // being `h`'s is a prior append at this height.
            let first_at_or_above = log
                .range(SlashLogKey::new(connecting, 0).key()..)?
                .next()
                .transpose()
                .map_err(EngineError::Storage)?
                .map(|(key, _)| key.value().0);
            if first_at_or_above == Some(height) {
                return Err(self.poison().arm(not_dense));
            }
            for (seq, slash) in (0u32..).zip(slashes) {
                log.insert(
                    SlashLogKey::new(connecting, seq).key(),
                    slash.entry.encoded().as_encoded(),
                )?;
            }
        }
        if applied_applies && !slashes.is_empty() {
            // The row bound at open is what `insert` would report. Every
            // write here goes through `insert_observing`, whose row names
            // this key.
            let mut applied = self.open_insert_table(ARCHIVAL_SLASH_APPLIED, not_dense)?;
            for slash in slashes {
                let entry = &slash.entry;
                applied.insert_observing(
                    SlashAppliedKey::new(entry.persona, entry.shard, entry.epoch).key(),
                    Present,
                    StoreInvariant::SlashLogNotDense {
                        height,
                        observed: SlashFault::AlreadyApplied {
                            persona: entry.persona,
                            shard: entry.shard,
                            epoch: entry.epoch,
                        },
                    },
                )?;
            }
        }
        if log_applies {
            if let Some(watermark) = delta.slash_watermark() {
                self.upsert_property::<ArchivalLastSlashEpochCell>(&watermark)?;
            }
        }
        Ok(())
    }
}

impl ChainStore {
    /// The regtest injector: `archival_serve_credit[(persona, shard, epoch,
    /// tip)] = Present`, a bit no block earned, attributed to the tip's
    /// height — the C++'s `regtest_inject_archival_serve_credit`
    /// (`blockchain.cpp:4708`), the Gate-6 stand-in that lets a regtest
    /// reach a closed epoch with a credit in it. Refused off Fakechain as
    /// the C++ refuses it: `trust` must be [`Trust::UNANCHORED`] — the one
    /// posture no release vouches for, which is what a Fakechain node
    /// always is and a public-network node never is
    /// ([`ReleaseAnchors`] has no constructor from arbitrary entries, so
    /// the empty table cannot be minted for a public network). The store
    /// holds no nettype (rule 71); it reads the posture the caller runs
    /// under, and the ingest maps `ChainRules::Regtest` to it.
    ///
    /// Its own transaction, **not journaled** (module doc): a pop below the
    /// returned height leaves the bit, as the C++'s does. Returns the
    /// height the bit was attributed to.
    ///
    /// # Errors
    ///
    /// [`StoreCannot::InjectionOffFakechain`] if `trust` carries any
    /// anchor; [`StoreCannot::ChainEmpty`] with no block recorded (no tip
    /// to attribute the bit to); [`StoreCannot::InjectionForUnbondedPersona`]
    /// if `persona` has no bond record — every serve-credit read arms
    /// SI-15, so a bit for a stranger would be a file the reads refuse
    /// (the C++ does not check because the C++ has no such read belt);
    /// [`StoreCannot::FamilyStubbed`] if this session stubs `ServeCredit`
    /// — the door writes one family and does not skip; the admission and
    /// engine errors of [`write`](Self::write).
    pub fn regtest_inject_serve_credit(
        &self,
        trust: Trust,
        persona: PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<BlockHeight, StoreError> {
        if *trust.anchors() != ReleaseAnchors::EMPTY {
            return Err(StoreCannot::InjectionOffFakechain.into());
        }
        self.write(|batch| {
            let tip = {
                let info = batch.open_insert_table(BLOCK_INFO, StoreInvariant::TipMismatch)?;
                let tip = info.last()?.map(|(h, _)| h.value());
                tip
            };
            let Some(tip) = tip else {
                return Err(StoreCannot::ChainEmpty.into());
            };
            let height = BlockHeight::from_raw(tip);
            // The stub refusal first: the door's own contract before the
            // file's state.
            let mut credits = batch.open_upsert_table(ARCHIVAL_SERVE_CREDIT)?;
            let record = archival_reads::bond_record(batch.txn(), &persona)
                .map_err(|f| batch.arm_read_fault(f))?;
            if record.is_none() {
                return Err(StoreCannot::InjectionForUnbondedPersona { persona }.into());
            }
            credits.upsert(
                ServeCreditKey::new(persona, shard, epoch, height).key(),
                Present,
            )?;
            Ok::<_, StoreError>(height)
        })
    }
}
