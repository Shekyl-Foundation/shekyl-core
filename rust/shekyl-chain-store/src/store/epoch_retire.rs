// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-epoch retirement at a pruning boundary (`SO-D12h`).
//!
//! [`WriteBatch::prune_at_boundary`](super::WriteBatch::prune_at_boundary)
//! calls [`WriteBatch::retire_epoch_rows`] once. Each family loses the rows
//! below its floor. The three key shapes stay written out — an epoch range,
//! [`IssuedDrawKey::below`], and the persona-first and shard-first retains —
//! because a generic walker would hide which shape a table has.

use redb::WriteTransaction;
use shekyl_chain_rules::{
    BlockDrawsFloor, Claimable, EpochFloor, Pricing, SettlementSchedule, Settling,
};
use shekyl_types::{BlockHeight, SettlementEpoch};

use crate::apply_policy::ArchivalFamily;
use crate::ids::{IssuedDrawKey, IssuedDrawTuple};
use crate::schema::{
    ARCHIVAL_BUDGET, ARCHIVAL_COMPLETE_TREES, ARCHIVAL_DRAWABLE_DIGEST, ARCHIVAL_ISSUED_DIGEST,
    ARCHIVAL_ISSUED_DRAW, ARCHIVAL_R_MARKET, ARCHIVAL_SETTLEMENT, ARCHIVAL_SIGMA_WORK,
    ARCHIVAL_SLASH_APPLIED,
};

use super::error::{EngineError, StoreError};
use super::write::WriteBatch;

/// The three per-epoch floors a boundary retires below
/// ([`EpochFloor::at_boundary`]). Each is the family's floor whatever the
/// session applies: a stubbed family's tables are not opened, and hold no
/// rows to retire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochFloors {
    /// `archival_sigma_work`, `archival_budget`, `archival_complete_trees`,
    /// `archival_settlement`.
    pub claimable: EpochFloor<Claimable>,
    /// `archival_issued_draw`, `archival_issued_digest`,
    /// `archival_drawable_digest`, `archival_slash_applied`.
    pub settling: EpochFloor<Settling>,
    /// `archival_r_market`.
    pub pricing: EpochFloor<Pricing>,
    /// `archival_block_draws`. The first retained height, beside the
    /// journal's floor.
    pub draws: BlockDrawsFloor,
}

impl EpochFloors {
    /// Every family's floor for the boundary batch at `boundary` under
    /// `schedule` ([`EpochFloor::at_boundary`]), computed once per batch:
    /// the per-epoch retirement and the Release journal's floor
    /// (`ReleaseJournalFloor::of(settling)`) read the same values.
    #[must_use]
    pub fn at_boundary(boundary: BlockHeight, schedule: SettlementSchedule) -> Self {
        Self {
            claimable: EpochFloor::at_boundary(boundary, schedule),
            settling: EpochFloor::at_boundary(boundary, schedule),
            pricing: EpochFloor::at_boundary(boundary, schedule),
            draws: BlockDrawsFloor::retired_by(
                schedule.epoch_at_height(boundary.to_raw()),
                schedule,
            ),
        }
    }
}

impl WriteBatch<'_, '_> {
    /// Delete each per-epoch table's rows below its family's floor at this
    /// boundary (`shekyl_chain_rules::EpochFloor::at_boundary`;
    /// `ARCHIVAL_SETTLEMENT_WRITER.md` §17). The floors are the rule set's
    /// expression and nothing the store holds, so every node deletes the
    /// same rows. Not journaled and not pop-reversible, like the slash
    /// log's: every block that can connect after this one is in epoch
    /// `B − 1` or later and reads each family at or above the floor
    /// retired here (SI-32 refuses one that does not).
    ///
    /// The epoch-keyed tables and the epoch-major issued-draw index lose
    /// one range. `archival_settlement` and `archival_slash_applied` are
    /// keyed persona-first and `archival_r_market` shard-first, so their
    /// retirement walks the table: a cost linear in the rows each family
    /// keeps (its window of epochs), once an epoch.
    pub(super) fn retire_epoch_rows(&self, floors: EpochFloors) -> Result<EpochFloors, StoreError> {
        let policy = self.apply_policy();
        let txn = self.txn();
        if let Some(kept) = floors.claimable.kept_from().map(SettlementEpoch::to_raw) {
            if policy.applies(ArchivalFamily::SigmaWork) {
                retire_epochs_below(txn, ARCHIVAL_SIGMA_WORK, kept)?;
                retire_epochs_below(txn, ARCHIVAL_COMPLETE_TREES, kept)?;
            }
            if policy.applies(ArchivalFamily::Budget) {
                retire_epochs_below(txn, ARCHIVAL_BUDGET, kept)?;
            }
            if policy.applies(ArchivalFamily::Settlement) {
                txn.open_table(ARCHIVAL_SETTLEMENT)
                    .map_err(EngineError::Table)?
                    .retain(|(_, _, epoch), _| epoch >= kept)
                    .map_err(EngineError::Storage)?;
            }
        }
        if let Some(kept) = floors.settling.kept_from() {
            txn.open_table(ARCHIVAL_ISSUED_DRAW)
                .map_err(EngineError::Table)?
                .retain_in::<IssuedDrawTuple, _>(IssuedDrawKey::below(kept), |_, _| false)
                .map_err(EngineError::Storage)?;
            retire_epochs_below(txn, ARCHIVAL_ISSUED_DIGEST, kept.to_raw())?;
            retire_epochs_below(txn, ARCHIVAL_DRAWABLE_DIGEST, kept.to_raw())?;
            if policy.applies(ArchivalFamily::SlashApplied) {
                let kept = kept.to_raw();
                txn.open_table(ARCHIVAL_SLASH_APPLIED)
                    .map_err(EngineError::Table)?
                    .retain(|(_, _, epoch), _| epoch >= kept)
                    .map_err(EngineError::Storage)?;
            }
        }
        if let Some(kept) = floors.pricing.kept_from().map(SettlementEpoch::to_raw) {
            if policy.applies(ArchivalFamily::RMarket) {
                txn.open_table(ARCHIVAL_R_MARKET)
                    .map_err(EngineError::Table)?
                    .retain(|(_, epoch), _| epoch >= kept)
                    .map_err(EngineError::Storage)?;
            }
        }
        Ok(floors)
    }
}

/// Delete every row of an epoch-keyed table below `kept` — the per-epoch
/// retirement's verb on the raw table (`prune` module docs, *Not journaled,
/// by design*).
fn retire_epochs_below<V: redb::Value + 'static>(
    txn: &WriteTransaction,
    table: redb::TableDefinition<'static, u64, V>,
    kept: u64,
) -> Result<(), StoreError> {
    let mut table = txn.open_table(table).map_err(EngineError::Table)?;
    table
        .retain_in::<u64, _>(..kept, |_, _| false)
        .map_err(EngineError::Storage)?;
    Ok(())
}
