// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The admission plan (`SO-D12` increment 4a).
//!
//! The verifier returns [`Admitted`]. This module turns those draws into
//! the rows the store journals: which heights become revealed, the issued
//! draws of each epoch, the terms of the epoch digest, and `issued_short`.
//! It derives no selection. The pair of a draw is the one [`Admitted`]
//! already carries.
//!
//! `issued_short(h_incl)` reduces the shortfall of `D(epoch(h_incl))` only.
//! A bundle whose height lies in another epoch contributes none of it. Its
//! index rows and digest terms are still issued, into `epoch(h)`.
//!
//! Nothing here is called from `form` or `validate`. Increment 4b is the
//! caller that judges a block; until then the plan runs only when a connect
//! is handed bundles.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_types::archival::{IndexedDraw, IssuedDraw, COUNTED_DRAWS, ISSUED_DIGEST_LEN};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use super::Admitted;
use crate::SettlementSchedule;

/// Why [`admission_plan`] cannot build the rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionPlanFault {
    /// Two bundles name one height. A height is revealed once.
    RepeatedReveal {
        /// The height named twice.
        height: BlockHeight,
    },
    /// The shortfall reduction does not fit `issued_short`.
    ReductionPastWidth,
    /// A draw's place in its bundle does not fit the issued-draw key.
    OrdinalPastWidth,
}

/// What connecting one block admits, ready to journal.
///
/// Built only by [`admission_plan`]. The fields are private so a journal
/// cannot carry a reduction other than the one these draws produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPlan {
    issued_short: u32,
    revealed: Vec<BlockHeight>,
    epochs: Vec<EpochIssues>,
}

/// The issued draws of one epoch, and the digest terms those draws fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochIssues {
    epoch: SettlementEpoch,
    draws: Vec<IndexedDraw>,
}

impl AdmissionPlan {
    /// The reduction against `D(epoch(h_incl))`.
    #[must_use]
    pub const fn issued_short(&self) -> u32 {
        self.issued_short
    }

    /// Heights whose seed this block reveals, each once.
    #[must_use]
    pub fn revealed(&self) -> &[BlockHeight] {
        &self.revealed
    }

    /// Issued draws grouped by the epoch of the block that drew them.
    #[must_use]
    pub fn epochs(&self) -> &[EpochIssues] {
        &self.epochs
    }
}

impl EpochIssues {
    /// The epoch these draws are issued into.
    #[must_use]
    pub const fn epoch(&self) -> SettlementEpoch {
        self.epoch
    }

    /// The index rows, in the order the bundles named their draws.
    #[must_use]
    pub fn draws(&self) -> &[IndexedDraw] {
        &self.draws
    }

    /// One digest term per issued draw. The term names the ordinal `j`,
    /// the draw's place in its bundle, which is the key's draw component.
    pub fn terms(&self) -> impl Iterator<Item = [u8; ISSUED_DIGEST_LEN]> + '_ {
        let epoch = self.epoch;
        self.draws.iter().map(move |draw| {
            issued_draw_term(
                &draw.persona,
                draw.shard,
                epoch,
                draw.issuing_height,
                draw.draw,
            )
        })
    }
}

/// The rows `admitted` journals at `including`.
///
/// `visible_before` is how many of each pair's draws in
/// `epoch(including)` are already visible below `including`
/// (`revealed_at < including`). A pair absent from the map has none.
///
/// Each same-epoch pair contributes `min(room, new)` to `issued_short`,
/// where `room` is [`COUNTED_DRAWS`] minus the draws already visible, and
/// `new` is how many draws this block issues to the pair. A contribution
/// is at most [`COUNTED_DRAWS`], so the per-pair count cannot overflow.
/// The sum is checked and is [`AdmissionPlanFault::ReductionPastWidth`]
/// when it does not fit `u32`. Draws beyond the room are still issued.
///
/// The key's draw component is the ordinal `j`, the draw's place in
/// `Admitted::draws`. [`DerivedDraw::index`](super::DerivedDraw::index) is
/// the pair's place in `D`. Selection is with replacement, so two draws
/// may name one index and must not share a key.
///
/// # Errors
///
/// [`AdmissionPlanFault::RepeatedReveal`] when two bundles name one
/// height; [`AdmissionPlanFault::OrdinalPastWidth`] when a draw's place
/// does not fit `u32`; [`AdmissionPlanFault::ReductionPastWidth`] when the
/// counted width or the reduction does not fit `u32`.
pub fn admission_plan(
    including: BlockHeight,
    schedule: SettlementSchedule,
    admitted: &[Admitted],
    visible_before: &BTreeMap<(PCanonicalId, ShardId), u32>,
) -> Result<AdmissionPlan, AdmissionPlanFault> {
    let cap = u32::try_from(COUNTED_DRAWS).map_err(|_| AdmissionPlanFault::ReductionPastWidth)?;
    let epoch = schedule.epoch_at(including);
    let mut revealed = BTreeSet::new();
    let mut counted: BTreeMap<(PCanonicalId, ShardId), u32> = BTreeMap::new();
    let mut by_epoch: BTreeMap<SettlementEpoch, Vec<IndexedDraw>> = BTreeMap::new();

    for bundle in admitted {
        let h = bundle.kept.h;
        if !revealed.insert(h) {
            return Err(AdmissionPlanFault::RepeatedReveal { height: h });
        }
        let draw_epoch = schedule.epoch_at(h);
        let same_epoch = draw_epoch == epoch;
        for (ordinal, draw) in bundle.draws.iter().enumerate() {
            let j = u32::try_from(ordinal).map_err(|_| AdmissionPlanFault::OrdinalPastWidth)?;
            if same_epoch {
                let pair = (draw.pair.persona, draw.pair.shard);
                let prior = visible_before.get(&pair).copied().unwrap_or(0);
                let room = cap - prior.min(cap);
                let seen = counted.entry(pair).or_insert(0);
                if *seen < room {
                    // `room` is at most the counted width, so this add fits.
                    // The checked form is what a wider cap still has to pass.
                    *seen = seen
                        .checked_add(1)
                        .ok_or(AdmissionPlanFault::ReductionPastWidth)?;
                }
            }
            by_epoch.entry(draw_epoch).or_default().push(IndexedDraw {
                persona: draw.pair.persona,
                shard: draw.pair.shard,
                issuing_height: h,
                draw: j,
                state: IssuedDraw {
                    revealed_at: including,
                    passed: draw.passed,
                },
            });
        }
    }

    let mut issued_short = 0u32;
    for added in counted.values() {
        issued_short = issued_short
            .checked_add(*added)
            .ok_or(AdmissionPlanFault::ReductionPastWidth)?;
    }

    Ok(AdmissionPlan {
        issued_short,
        revealed: revealed.into_iter().collect(),
        epochs: by_epoch
            .into_iter()
            .map(|(epoch, draws)| EpochIssues { epoch, draws })
            .collect(),
    })
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod admission_tests;
