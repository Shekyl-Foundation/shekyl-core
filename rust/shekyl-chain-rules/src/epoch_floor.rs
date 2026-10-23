// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where each per-epoch table's rows stop being read, and so may be retired
//! (`ARCHIVAL_SETTLEMENT_WRITER.md` §17, `SO-D12h`, ruled 2026-10-17).
//!
//! # The rule
//!
//! A per-epoch table is retired below the epoch where its **last reader**
//! stops. The boundary batch of epoch `B` (the connect of height `B·SEB`,
//! `store/prune.rs`) runs the retirement, unjournaled, beside the body,
//! undo and slash-log retirements. Every horizon here is a function of the
//! epoch calendar and consensus constants — the rule set in hand — and of
//! nothing a node holds, so every node retires the same rows (`prune.rs`
//! module docs, §8; `SLK-2`'s shape: the store compares, it does not
//! source).
//!
//! # One expression for the read and the retirement
//!
//! A block connecting at `h` asks a family for no epoch below
//! `epoch(h) − LAG`, where `LAG` is the family's reach (the table below).
//! That is the family's [`EpochFloor`] at `h` ([`EpochFloor::under`]).
//!
//! The batch retires below the floor of the **lowest height that can
//! connect after it**. After the boundary of `B` connects, a reorg can pop
//! back to the undo floor, `B·SEB − retention`, and reconnect from there.
//! The store holds `retention < SEB` at open and at every connect
//! (`Horizons::new`), so the undo floor is inside epoch `B − 1` whatever
//! retention an operator chose, and every block at or above
//! `(B − 1)·SEB + 1` may connect again. The batch of `B` therefore retires
//! below `(B − 1) − LAG` ([`EpochFloor::at_boundary`]), not `B − LAG`: the
//! retirement is not pop-reversible, and the epoch of slack is what makes
//! that safe. Every block that can connect after it is in epoch `B − 1` or
//! later, so its floor is at or above what was retired.
//!
//! # The three families
//!
//! A family is the set of tables whose last reader is the same; its `LAG`
//! is how many epochs back from the connecting block's epoch that reader
//! reaches.
//!
//! | Family | Tables | Last reader | `LAG` |
//! | --- | --- | --- | --- |
//! | [`Claimable`] | `archival_sigma_work`, `archival_budget`, `archival_complete_trees`, `archival_settlement`, `archival_support_settlement` | a claim (CEN-J23 reads `E ≥ epoch(h) − W`, after the expiry check) and the failure window (`settlement_retention_floor`, the same `epoch(h) − W`) | `W` (`MAX_CLAIM_AGE_W`) |
//! | [`Settling`] | `archival_issued_draw`, `archival_issued_digest`, `archival_drawable_digest`, `archival_slash_applied`, `archival_support_issued` | `E`'s own slash pass, in epoch `E + k` | `k` (`SLASH_GRACE_EPOCHS`) |
//! | [`Pricing`] | `archival_r_market` | CEN-J15, at the slash watermark: at `h` the watermark is at least `epoch(h) − 1 − k` | `k + 1` |
//!
//! Each `LAG` is exact: the reader asks for `epoch(h) − LAG` at some `h`
//! (a claim at the window's floor, the pass for its own epoch, J15 in the
//! first block of an epoch), so a floor one higher would refuse a read the
//! chain makes, and one lower would keep a row no block can ask for.
//!
//! `archival_drawable_digest`'s reader is the pass's compare against the
//! re-walk (`SO-D10g`), in the epoch the pass settles, with the other
//! settling tables.
//!
//! # The Release journal
//!
//! `archival_release_journal` is keyed by height, not epoch. Its reader is
//! the drawable walk, which reads strictly above `h_open` of an epoch the
//! settling family still keeps. [`ReleaseJournalFloor`] is that height —
//! one above that open — and the boundary batch retires below it. The
//! slash log keeps its own floor ([`crate::SlashLogFloor`]): the walk
//! undoes slashes across the failure window, which is longer than the
//! journal's span.
//!
//! # The draw rows
//!
//! `archival_block_draws` is keyed by height. [`BlockDrawsFloor`] is the
//! first height still retained, computed beside the journal's floor and
//! retired by the same boundary batch. At the boundary of epoch `B` that
//! height is `(B − 1)·SEB + 1 − W₂`, or `(B − 1)·SEB` when the schedule
//! has no response window. A read below it is refused (SI-34). The floor
//! sits strictly under the undo floor: after the boundary the minimum
//! undo floor is `(B − 1)·SEB + 1` (`retention < SEB`), and `W₂` is at
//! least one on every schedule that has a window.
//!
//! # A read below its horizon is refused
//!
//! Each read of these tables takes its family's [`EpochFloor`] from the
//! caller, computed at the connecting height, and the store refuses a read
//! below it (SI-32) rather than answer "absent": absent means *never
//! written*, and a retired row was written. The floor at the connecting
//! height is never below the one the last batch retired at, so the check is
//! at least as strict as what the table has undergone. Every reader asks
//! inside its family by construction — a claim's cited epochs pass
//! CEN-J25's window before CEN-J23 reads them — so the refusal fires on a
//! mis-composed schedule, never on data.

use core::marker::PhantomData;

use shekyl_archival_retention::{
    claim_window_floor, SettlementSchedule, CHALLENGE_RESPONSE_BLOCKS, MAX_CLAIM_AGE_W,
    SETTLEMENT_EPOCH_BLOCKS, SLASH_GRACE_EPOCHS,
};
use shekyl_types::{BlockHeight, SettlementEpoch};

/// A family of per-epoch tables that share a last reader (module docs).
pub trait EpochFamily: Copy + core::fmt::Debug + Eq {
    /// How many epochs back from the connecting block's epoch the family's
    /// last reader reaches.
    const LAG: u64;

    /// The oldest epoch a block in epoch `current` can ask the family for:
    /// `current − LAG`, zero while the chain is younger. A family whose
    /// reader states its own window answers with that window's expression,
    /// so the floor and the reader cannot be two derivations of one fact.
    #[must_use]
    fn oldest_read(current: u64) -> u64 {
        current.saturating_sub(Self::LAG)
    }
}

/// The tables a claim reads (module docs): retained for the claim window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claimable {}

/// The tables an epoch's own slash pass reads and no later block does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settling {}

/// The table CEN-J15 prices a join by, at the slash watermark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pricing {}

impl EpochFamily for Claimable {
    const LAG: u64 = MAX_CLAIM_AGE_W;

    /// The claim window's own floor ([`claim_window_floor`]): the epoch
    /// CEN-J25's window, the verify's `EpochClaimExpired` and the failure
    /// window's walk (which takes this floor) all stop at.
    fn oldest_read(current: u64) -> u64 {
        claim_window_floor(current)
    }
}

impl EpochFamily for Settling {
    const LAG: u64 = SLASH_GRACE_EPOCHS;
}

impl EpochFamily for Pricing {
    const LAG: u64 = SLASH_GRACE_EPOCHS + 1;
}

// The compile-time half of "a reorg never needs a retired row": every
// height that writes or reads a family's row of epoch `E` lies in an epoch
// no later than `E + LAG`. A retired `E` has `E + LAG < B − 1`, so all of
// those heights are below `(B − 1)·SEB`, under the undo floor (whose
// runtime half, `retention < SEB`, `Horizons::new` refuses at open).
//
// - Claimable: the close writes `budget(E)` in epoch `E`, the pass writes
//   the other three in `E + k`, and the claim window and the failure
//   window read through `E + W`. So `k ≤ W` is the condition.
// - Settling: issuance writes through the slash deadline and the pass
//   reads in `E + k`. `LAG = k` by definition.
// - Pricing: the pass writes in `E + k`; J15 reads at the watermark until
//   the pass of `E + 1`, in `E + 1 + k`. `LAG = k + 1` by definition.
const _: () = assert!(
    SLASH_GRACE_EPOCHS <= MAX_CLAIM_AGE_W,
    "the slash pass writes Σwork(E) and its siblings in epoch E + k; a claim window shorter than \
     the grace would retire them before the pass that writes them is below the undo floor"
);

// The draw rows' floor sits strictly under the undo floor. After the
// boundary of `B` the minimum undo floor is `(B − 1)·SEB + 1`
// (`retention < SEB`, `Horizons::new`). A windowed schedule retires draws
// below that height minus `W₂`, so `W₂ ≥ 1` is what puts the floor under
// the undo floor, and `W₂ < SEB` is what keeps the subtraction inside the
// epoch the boundary can still reach. A windowless schedule retires below
// `(B − 1)·SEB`, one under the same undo floor, and names no `W₂`.
const _: () = assert!(
    CHALLENGE_RESPONSE_BLOCKS >= 1 && CHALLENGE_RESPONSE_BLOCKS < SETTLEMENT_EPOCH_BLOCKS,
    "the genesis response window is at least one block and shorter than the epoch, so the draw \
     rows' floor is strictly below the undo floor"
);

/// The lowest epoch of family `F` a reader may still ask for: rows below
/// it may be retired, rows at or above it are kept. Computed from the rule
/// set's schedule at a height (module docs), typed per family so a floor
/// for one family cannot be handed to another family's read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochFloor<F: EpochFamily> {
    kept_from: Option<SettlementEpoch>,
    _family: PhantomData<F>,
}

impl<F: EpochFamily> EpochFloor<F> {
    /// Nothing retired. Private: a production read always carries the
    /// floor its connecting height names, so no caller can switch SI-32
    /// off by passing this.
    const NOTHING: Self = Self {
        kept_from: None,
        _family: PhantomData,
    };

    /// Nothing retired, for a test whose chain is younger than every
    /// family's horizon. Not built into production code.
    #[cfg(any(test, feature = "harness"))]
    pub const NONE: Self = Self::NOTHING;

    /// The family's floor for a block connecting at `connecting` under
    /// `schedule`: [`EpochFamily::oldest_read`] of its epoch, the oldest
    /// epoch that block can ask the family for. A read passes this; the
    /// store refuses a read below it (SI-32).
    #[must_use]
    pub fn under(connecting: BlockHeight, schedule: SettlementSchedule) -> Self {
        Self::reading_from(schedule.epoch_at_height(connecting.to_raw()))
    }

    /// The floor the boundary batch at `boundary` retires below: the
    /// floor of the lowest height that can connect after the batch,
    /// `(B − 1)·SEB + 1`, in epoch `B − 1` (module docs). Nothing at a
    /// height that is not past the first epoch.
    #[must_use]
    pub fn at_boundary(boundary: BlockHeight, schedule: SettlementSchedule) -> Self {
        match schedule.epoch_at_height(boundary.to_raw()).checked_sub(1) {
            Some(previous) => Self::reading_from(previous),
            None => Self::NOTHING,
        }
    }

    /// The floor of a block in epoch `current`: nothing retired while the
    /// oldest epoch it reads is zero.
    fn reading_from(current: u64) -> Self {
        match F::oldest_read(current) {
            0 => Self::NOTHING,
            e => Self {
                kept_from: Some(SettlementEpoch::from_raw(e)),
                _family: PhantomData,
            },
        }
    }

    /// The lowest retained epoch, or `None` while nothing is retired.
    #[must_use]
    pub const fn kept_from(self) -> Option<SettlementEpoch> {
        self.kept_from
    }

    /// The floor `epoch` lies below, if it does: the comparison SI-32
    /// refuses on, stated once.
    #[must_use]
    pub fn below(self, epoch: SettlementEpoch) -> Option<SettlementEpoch> {
        self.kept_from.filter(|&floor| epoch < floor)
    }

    /// Whether `epoch` is retained under this floor.
    #[must_use]
    pub fn retains(self, epoch: SettlementEpoch) -> bool {
        self.below(epoch).is_none()
    }
}

/// The lowest height of `archival_release_journal` a walk may still read
/// (module docs, *The Release journal*).
///
/// One expression, two sites. The boundary batch retires below
/// [`Self::height`]; A20 refuses a scan whose start lies below it (SI-28).
/// The store compares and does not source the floor: the caller builds it
/// from the settling [`EpochFloor`] it already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseJournalFloor(Option<BlockHeight>);

impl ReleaseJournalFloor {
    /// Nothing retired: the settling family still keeps every epoch. For a
    /// test whose chain is younger than the horizon; not built into
    /// production code.
    #[cfg(any(test, feature = "harness"))]
    pub const NONE: Self = Self(None);

    /// The journal floor the settling family's `floor` names under
    /// `schedule`. The walk of the oldest kept epoch reads strictly above
    /// its open, so the first retained height is one above that open. The
    /// row at the open itself is never read.
    ///
    /// # Panics
    ///
    /// If a kept epoch opens at `u64::MAX`. A kept epoch is below the
    /// boundary's epoch, so its open is below a recorded height.
    #[must_use]
    pub const fn of(floor: EpochFloor<Settling>, schedule: SettlementSchedule) -> Self {
        let Some(epoch) = floor.kept_from() else {
            return Self(None);
        };
        let open = schedule.open_height(epoch.to_raw());
        match open.checked_add(1) {
            Some(height) => Self(Some(BlockHeight::from_raw(height))),
            None => panic!("a kept epoch opens below a recorded height"),
        }
    }

    /// The lowest retained height, or `None` while nothing is retired.
    /// The store builds the retired key range from this height and refuses
    /// a scan whose start lies in it (SI-28).
    #[must_use]
    pub const fn height(self) -> Option<BlockHeight> {
        self.0
    }
}

/// The first height of `archival_block_draws` a read may still ask for
/// (module docs, *The draw rows*).
///
/// One expression, two sites. The boundary batch of epoch `B` retires
/// strictly below [`Self::retired_by`]; a count or an admission that asks
/// for a height below [`Self::in_force`] is refused (SI-34). The store
/// compares and does not source the floor.
///
/// With a response window the first retained height is
/// `(B − 1)·SEB + 1 − W₂`. With none it is `(B − 1)·SEB`. Either
/// expression at or below zero retires nothing: the chain is not yet old
/// enough for a row to have fallen out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDrawsFloor(Option<BlockHeight>);

impl BlockDrawsFloor {
    /// Nothing retired. For a test whose chain is younger than the
    /// horizon; not built into production code.
    #[cfg(any(test, feature = "harness"))]
    pub const NONE: Self = Self(None);

    /// The floor the boundary batch of epoch `B` (`boundary_epoch`, the
    /// epoch of the boundary height `B·SEB`) retires below.
    ///
    /// Nothing for `B = 0`, and nothing when the kept height would be
    /// zero: there is no row below height zero.
    #[must_use]
    pub const fn retired_by(boundary_epoch: u64, schedule: SettlementSchedule) -> Self {
        let Some(previous) = boundary_epoch.checked_sub(1) else {
            return Self(None);
        };
        let open = previous.saturating_mul(schedule.blocks().get());
        let kept = match schedule.challenge_response_blocks() {
            Some(window) => open.saturating_add(1).saturating_sub(window.get()),
            None => open,
        };
        if kept == 0 {
            Self(None)
        } else {
            Self(Some(BlockHeight::from_raw(kept)))
        }
    }

    /// The floor in force while a block connects at `connecting`: the
    /// floor of the last boundary whose batch has completed. The boundary
    /// block's own prune has not run while that block is being validated,
    /// so at height `h` the epoch is `(h − 1) / SEB` once `h − 1` is at
    /// least one epoch, and nothing before that.
    #[must_use]
    pub const fn in_force(connecting: BlockHeight, schedule: SettlementSchedule) -> Self {
        let height = connecting.to_raw();
        if height == 0 {
            return Self(None);
        }
        let previous = height - 1;
        let seb = schedule.blocks().get();
        if previous < seb {
            return Self(None);
        }
        Self::retired_by(previous / seb, schedule)
    }

    /// The first retained height, or `None` while nothing is retired.
    /// The store retires every row strictly below this height and refuses
    /// a read of one (SI-34).
    #[must_use]
    pub const fn height(self) -> Option<BlockHeight> {
        self.0
    }
}

#[cfg(test)]
#[path = "epoch_floor_tests.rs"]
mod tests;
