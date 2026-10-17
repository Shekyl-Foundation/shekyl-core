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
//! | [`Claimable`] | `archival_sigma_work`, `archival_budget`, `archival_complete_trees`, `archival_settlement` | a claim (CEN-J23 reads `E ≥ epoch(h) − W`, after the expiry check) and the failure window (`settlement_retention_floor`, the same `epoch(h) − W`) | `W` (`MAX_CLAIM_AGE_W`) |
//! | [`Settling`] | `archival_issued_draw`, `archival_issued_digest`, `archival_drawable_digest`, `archival_slash_applied` | `E`'s own slash pass, in epoch `E + k` | `k` (`SLASH_GRACE_EPOCHS`) |
//! | [`Pricing`] | `archival_r_market` | CEN-J15, at the slash watermark: at `h` the watermark is at least `epoch(h) − 1 − k` | `k + 1` |
//!
//! Each `LAG` is exact: the reader asks for `epoch(h) − LAG` at some `h`
//! (a claim at the window's floor, the pass for its own epoch, J15 in the
//! first block of an epoch), so a floor one higher would refuse a read the
//! chain makes, and one lower would keep a row no block can ask for.
//!
//! `archival_drawable_digest`'s reader — the pass's compare against a
//! re-walk (`SO-D10g`) — is ruled and not built in Rust. Its horizon is
//! that reader's, and nothing reads it yet.
//!
//! # A read below its horizon is refused
//!
//! Each read of these tables takes its family's [`EpochFloor`] from the
//! caller, computed at the connecting height, and the store refuses a read
//! below it (SI-29) rather than answer "absent": absent means *never
//! written*, and a retired row was written. The floor at the connecting
//! height is never below the one the last batch retired at, so the check is
//! at least as strict as what the table has undergone. Every reader asks
//! inside its family by construction — a claim's cited epochs are checked
//! against the claim window first (CEN-J23) — so the refusal fires on a
//! mis-composed schedule, never on data.

use core::marker::PhantomData;

use shekyl_archival_retention::{SettlementSchedule, MAX_CLAIM_AGE_W, SLASH_GRACE_EPOCHS};
use shekyl_types::{BlockHeight, SettlementEpoch};

/// A family of per-epoch tables that share a last reader (module docs).
pub trait EpochFamily: Copy + core::fmt::Debug + Eq {
    /// Epochs below `B − 1` that the family's rows stay at the boundary of
    /// `B`.
    const LAG: u64;
    /// The family as a fault names it.
    const NAME: &'static str;
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
    const NAME: &'static str = "claimable";
}

impl EpochFamily for Settling {
    const LAG: u64 = SLASH_GRACE_EPOCHS;
    const NAME: &'static str = "settling";
}

impl EpochFamily for Pricing {
    const LAG: u64 = SLASH_GRACE_EPOCHS + 1;
    const NAME: &'static str = "pricing";
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
    /// Nothing retired: the floor of a chain younger than the family's
    /// horizon, and of a read no retirement has touched.
    pub const NONE: Self = Self {
        kept_from: None,
        _family: PhantomData,
    };

    /// The family's floor for a block connecting at `connecting` under
    /// `schedule`: `epoch(connecting) − LAG`, the oldest epoch that block
    /// can ask the family for. A read passes this; the store refuses a
    /// read below it (SI-29).
    #[must_use]
    pub const fn under(connecting: BlockHeight, schedule: SettlementSchedule) -> Self {
        Self::below_epoch(schedule.epoch_at_height(connecting.to_raw()))
    }

    /// The floor the boundary batch at `boundary` retires below: the
    /// floor of the lowest height that can connect after the batch,
    /// `(B − 1)·SEB + 1`, which is `(B − 1) − LAG` (module docs). `None`
    /// at a height that is not past the first epoch.
    #[must_use]
    pub const fn at_boundary(boundary: BlockHeight, schedule: SettlementSchedule) -> Self {
        match schedule.epoch_at_height(boundary.to_raw()).checked_sub(1) {
            Some(previous) => Self::below_epoch(previous),
            None => Self::NONE,
        }
    }

    /// `epoch − LAG`, or [`Self::NONE`] while that is not above zero.
    const fn below_epoch(epoch: u64) -> Self {
        let kept_from = match epoch.checked_sub(F::LAG) {
            Some(0) | None => None,
            Some(e) => Some(SettlementEpoch::from_raw(e)),
        };
        Self {
            kept_from,
            _family: PhantomData,
        }
    }

    /// The lowest retained epoch, or `None` while nothing is retired.
    #[must_use]
    pub const fn kept_from(self) -> Option<SettlementEpoch> {
        self.kept_from
    }

    /// Whether `epoch` is retained under this floor.
    #[must_use]
    pub fn retains(self, epoch: SettlementEpoch) -> bool {
        self.kept_from.is_none_or(|floor| epoch >= floor)
    }
}

#[cfg(test)]
#[path = "epoch_floor_tests.rs"]
mod tests;
