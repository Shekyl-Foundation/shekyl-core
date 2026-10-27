// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The admission journal (`SO-D12` increment 4a).
//!
//! [`admission_plan`] builds the reduction, the ordinals and the digest
//! terms. This module writes that plan into the connecting block's batch
//! and computes none of it. The height is the view's: the view was built
//! at the block being connected, so a second height cannot disagree.
//!
//! The writes land before the journal seals. `pop` of the block removes
//! the reveals, the index rows and the digest folds with it.

use std::collections::BTreeMap;

use shekyl_chain_rules::{
    admission_plan, AdmissionPlan, AdmissionPlanFault, Admitted, BlockDrawsFloor, EpochFloor,
    Settling,
};
use shekyl_types::archival::BlockDraws;
use shekyl_types::BlockHeight;

use crate::codec::Canonical;
use crate::ids::IssuedDrawKey;
use crate::schema::{ARCHIVAL_BLOCK_DRAWS, ARCHIVAL_ISSUED_DIGEST, ARCHIVAL_ISSUED_DRAW};

use super::archival_reads;
use super::bundle_view::StoreBundleView;
use super::error::{AdmissionWriteFault, SettlementFault, StoreError, StoreInvariant};
use super::view::BatchView;
use super::write::WriteBatch;

impl<'id> WriteBatch<'_, 'id> {
    /// Journal `admitted` for the block the view was built at.
    ///
    /// An empty slice writes nothing: the count phase of this block already
    /// stored `issued_short` as zero. Otherwise the plan is built from the
    /// view's visible counts, then journaled. One replace per draw row,
    /// including the connecting row when this block only stamps
    /// `issued_short` and does not reveal its own seed.
    ///
    /// # Errors
    ///
    /// SI-36 when a height is revealed twice, a draw row is missing, the
    /// reduction does not fit, or a draw ordinal does not fit the key.
    /// SI-25 [`SettlementFault::IndexDrift`] when an issued-draw key is
    /// already present. SI-39 when a pair's visible count does not fit
    /// `u32`. The view's own faults pass through.
    pub(super) fn write_admissions(
        &self,
        view: &StoreBundleView<'_, BatchView<'_, 'id>>,
        admitted: &[Admitted],
    ) -> Result<(), StoreError> {
        if admitted.is_empty() {
            return Ok(());
        }
        let connecting = view.including();
        let schedule = view.schedule();
        let epoch = schedule.epoch_at(connecting);
        let before = view.visible_counts(epoch, connecting)?;
        let plan = match admission_plan(connecting, schedule, admitted, &before) {
            Ok(plan) => plan,
            Err(fault) => return Err(self.plan_fault(connecting, fault)),
        };
        self.journal_plan(view, &plan)
    }

    fn plan_fault(&self, connecting: BlockHeight, fault: AdmissionPlanFault) -> StoreError {
        let (height, observed) = match fault {
            AdmissionPlanFault::RepeatedReveal { height } => {
                (height, AdmissionWriteFault::AlreadyRevealed)
            }
            AdmissionPlanFault::ReductionPastWidth => {
                (connecting, AdmissionWriteFault::ReductionPastWidth)
            }
            AdmissionPlanFault::OrdinalPastWidth => {
                (connecting, AdmissionWriteFault::OrdinalPastWidth)
            }
        };
        self.admission_fault(height, observed)
    }

    fn journal_plan(
        &self,
        view: &StoreBundleView<'_, BatchView<'_, 'id>>,
        plan: &AdmissionPlan,
    ) -> Result<(), StoreError> {
        let connecting = view.including();
        let schedule = view.schedule();
        let floor = BlockDrawsFloor::in_force(connecting, schedule);
        let mut rows: BTreeMap<BlockHeight, BlockDraws> = BTreeMap::new();
        for &height in plan.revealed() {
            rows.insert(height, self.reveal_row(height, floor)?);
        }
        self.stamp_issued_short(&mut rows, connecting, floor, plan.issued_short())?;
        for (height, draws) in &rows {
            self.open_replace_table(
                ARCHIVAL_BLOCK_DRAWS,
                StoreInvariant::AdmissionWrite {
                    height: *height,
                    observed: AdmissionWriteFault::RowAbsent,
                },
            )?
            .replace(height.to_raw(), draws.encoded().as_encoded())?;
        }

        let settle_floor = EpochFloor::<Settling>::under(connecting, schedule);
        for issues in plan.epochs() {
            let collision = StoreInvariant::SettlementNotSound {
                epoch: issues.epoch(),
                observed: SettlementFault::IndexDrift,
            };
            {
                let mut index = self.open_insert_table(ARCHIVAL_ISSUED_DRAW, collision)?;
                for draw in issues.draws() {
                    let key = IssuedDrawKey::new(
                        issues.epoch(),
                        draw.persona,
                        draw.shard,
                        draw.issuing_height,
                        draw.draw,
                    );
                    index.insert_observing(
                        key.key(),
                        draw.state.encoded().as_encoded(),
                        collision,
                    )?;
                }
            }
            let mut digest =
                archival_reads::issued_digest(self.txn(), issues.epoch(), settle_floor)
                    .map_err(|fault| self.arm_read_fault(fault))?;
            for term in issues.terms() {
                digest.fold(&term);
            }
            self.open_upsert_table(ARCHIVAL_ISSUED_DIGEST)?
                .upsert(issues.epoch().to_raw(), digest.encoded().as_encoded())?;
        }
        Ok(())
    }

    /// The draw row at `height`, marked revealed. A missing row, or one
    /// already revealed, is SI-36 at that height.
    fn reveal_row(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<BlockDraws, StoreError> {
        let Some(mut row) = archival_reads::block_draws(self.txn(), height, floor)
            .map_err(|fault| self.arm_read_fault(fault))?
        else {
            return Err(self.admission_fault(height, AdmissionWriteFault::RowAbsent));
        };
        if row.revealed {
            return Err(self.admission_fault(height, AdmissionWriteFault::AlreadyRevealed));
        }
        row.revealed = true;
        Ok(row)
    }

    /// Put `issued_short` on the connecting row. A bundle that reveals
    /// this block's own seed already loaded the row; any other admission
    /// loads it here. The count phase of this same batch wrote
    /// `revealed = false`, so a row that is only being stamped is not a
    /// second reveal.
    fn stamp_issued_short(
        &self,
        rows: &mut BTreeMap<BlockHeight, BlockDraws>,
        connecting: BlockHeight,
        floor: BlockDrawsFloor,
        issued_short: u32,
    ) -> Result<(), StoreError> {
        if let Some(row) = rows.get_mut(&connecting) {
            row.issued_short = issued_short;
            return Ok(());
        }
        let Some(mut row) = archival_reads::block_draws(self.txn(), connecting, floor)
            .map_err(|fault| self.arm_read_fault(fault))?
        else {
            return Err(self.admission_fault(connecting, AdmissionWriteFault::RowAbsent));
        };
        row.issued_short = issued_short;
        rows.insert(connecting, row);
        Ok(())
    }

    fn admission_fault(&self, height: BlockHeight, observed: AdmissionWriteFault) -> StoreError {
        self.poison()
            .arm(StoreInvariant::AdmissionWrite { height, observed })
    }
}
