// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E — the genesis pin's rules.
//!
//! The rows of [`GenesisPin`](crate::GenesisPin), the release's
//! genesis pin. No coded checkpoint pins anything above it (S1, design
//! review 2026-11-03):
//!
//! - **CEN-E5** — the file a node opens records this network's genesis.
//!   Not a per-block predicate: it is run **once, at open**, over the
//!   recorded chain ([`E5::conflict_over`]; [`E5::conflict_with`] is that
//!   walk over a [`HeaderView`]), and its finding is an [`GenesisConflict`]:
//!   the file is another network's, and the writer does not run. The first
//!   row this crate enforces at a site other than `validate` —
//!   `RowStatus::EnforcedAt` is its registry status (slice 3 Q4).
//! - **CEN-E1** — a genesis candidate is the pinned genesis. Per block,
//!   view-bound ([`E1`], a header rule); reads the pin from the `Trust`
//!   input that carries it into `validate`.

use shekyl_types::{BlockHash, BlockHeight};

use crate::genesis_pin::GenesisPin;
use crate::census::CenRow;
use crate::fault::ViewRead;
use crate::rules::{HeaderContext, HeaderRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::{AtHeight, HeaderView, Tip};

/// CEN-E1: a block connecting at height 0 is the genesis the release pins.
///
/// Reads the pin through the [`Trust`](crate::Trust) input (`cx.trust`) and
/// the block's identity through the token (`form` derived it once,
/// CEN-B6). Above genesis nothing is pinned, and the rule is vacuously
/// satisfied and **recorded as evaluated**: the coverage says the row ran.
///
/// `form` cannot evaluate it: the connecting height is the view's (F12),
/// so the refusal is a view-bound `InvalidBlock { rule: E1, locus: Block }`.
pub(crate) struct E1;

impl Rule for E1 {
    const ROW: CenRow = CenRow::E1;
}

impl HeaderRule for E1 {
    fn check<'id, P, H: HeaderView<'id>>(
        cx: &HeaderContext<'_, P>,
        _view: &H,
    ) -> Result<Verdict<()>, ViewRead<H::Fault>> {
        match cx.trust.genesis_pin().expected_at(cx.connecting) {
            Some(expected) if expected != cx.facts.identity() => refused(Self::ROW, Locus::Block),
            Some(_) | None => Ok(Ok(())),
        }
    }
}

/// CEN-E5: at open, the file's block 0 is the genesis the binary pins.
///
/// What survives of the census row after `PDM-Q-F23` removed the runtime
/// checkpoint file and S1 removed coded checkpoints: C2-R1b clause (3)'s
/// genesis arm, run once at open. The check is [`E5::conflict_over`];
/// [`E5::conflict_with`] is that walk over a [`ChainView`]. A conflict is
/// a file from another network, and the store refuses to open it.
pub(crate) struct E5;

impl Rule for E5 {
    const ROW: CenRow = CenRow::E5;
}

impl E5 {
    /// The pin the recorded chain contradicts, if any: the genesis
    /// identity at height 0.
    ///
    /// `tip` is the recorded tip. `None` is an empty file, which
    /// contradicts nothing: there is no block for a pin to disagree with
    /// (the C++ skips every point at or above height 0 when the DB is
    /// empty). `recorded_at` answers a pinned height at or below that tip:
    /// `Some` is the block's identity, `None` is a hole where the chain
    /// claims a block. Pins above the tip are not yet checkable and are
    /// skipped, as the C++ `continue`s past `pt.first >= blockchain_height`.
    ///
    /// `Err` is the reader failing to answer — a fault, not a conflict.
    /// [`conflict_with`](Self::conflict_with) is this walk over a view.
    pub(crate) fn conflict_over<E>(
        anchors: &GenesisPin,
        tip: Option<Tip>,
        mut recorded_at: impl FnMut(BlockHeight) -> Result<Option<BlockHash>, E>,
    ) -> Result<Option<GenesisConflict>, E> {
        let Some(tip) = tip else {
            return Ok(None);
        };
        for (height, expected) in anchors.pins() {
            if height > tip.height {
                break;
            }
            // Heights at or below the tip are dense (the store's
            // invariant). A hole at a pinned height is the file missing a
            // block it claims to have — a conflict, with nothing recorded
            // to name. A reader that cannot answer returns `Err` instead,
            // and that stays a fault.
            let recorded = recorded_at(height)?;
            if recorded != Some(expected) {
                return Ok(Some(GenesisConflict {
                    height,
                    expected,
                    recorded,
                }));
            }
        }
        Ok(None)
    }

    /// [`conflict_over`](Self::conflict_over) over `view`: the tip, then
    /// each pinned block's identity — header facts, so a header view
    /// suffices (an alt chain's genesis is checked the same way).
    pub(crate) fn conflict_with<'id, H: HeaderView<'id>>(
        anchors: &GenesisPin,
        view: &H,
    ) -> Result<Option<GenesisConflict>, H::Fault> {
        Self::conflict_over(anchors, view.tip()?, |height| {
            Ok(match view.header_at(height)? {
                AtHeight::Recorded(record) => Some(record.hash),
                AtHeight::AboveTip => None,
            })
        })
    }
}

/// A recorded chain whose genesis is not the one the release pins (CEN-E5's
/// finding): the file is another network's, and the writer does not run.
/// No pop can resolve it: genesis cannot be popped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisConflict {
    /// The pinned height: genesis.
    pub height: BlockHeight,
    /// The identity the release vouches for there.
    pub expected: BlockHash,
    /// The identity the file recorded there. `None` when the file has no
    /// block at a height at or below its own tip — a hole where the store's
    /// density invariant says there cannot be one.
    pub recorded: Option<BlockHash>,
}

impl GenesisPin {
    /// **CEN-E5.** The pin the recorded chain contradicts, if any.
    ///
    /// `tip` is the recorded tip (`None`: an empty file, which contradicts
    /// nothing). `recorded_at` answers a pinned height at or below that
    /// tip. Pins above the tip are not yet checkable. Run once, at open,
    /// before connecting anything.
    ///
    /// [`conflict_with`](Self::conflict_with) is this walk over a
    /// [`HeaderView`](crate::HeaderView). A reader that is not a view — the
    /// store's snapshot, whose view impl is deferred — calls this with the
    /// tip and the identity it recorded, so the two cannot grow different
    /// policies.
    ///
    /// # Errors
    ///
    /// `recorded_at`'s error, when the reader could not answer. A fault is
    /// not a conflict.
    pub fn conflict_over<E>(
        &self,
        tip: Option<Tip>,
        recorded_at: impl FnMut(BlockHeight) -> Result<Option<BlockHash>, E>,
    ) -> Result<Option<GenesisConflict>, E> {
        E5::conflict_over(self, tip, recorded_at)
    }

    /// **CEN-E5** over a [`HeaderView`](crate::HeaderView).
    ///
    /// [`conflict_over`](Self::conflict_over) is the walk. This is that walk
    /// with the view's tip and `header_at` — header facts, which every
    /// [`ChainView`](crate::ChainView) answers and an alt view answers too.
    ///
    /// # Errors
    ///
    /// The view's own fault, when it could not answer. A fault is not a
    /// conflict.
    pub fn conflict_with<'id, H: HeaderView<'id>>(
        &self,
        view: &H,
    ) -> Result<Option<GenesisConflict>, H::Fault> {
        E5::conflict_with(self, view)
    }
}

#[cfg(test)]
#[path = "genesis_tests.rs"]
mod genesis_tests;
