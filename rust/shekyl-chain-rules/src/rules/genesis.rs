// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E — the genesis pin's rules.
//!
//! The rows of [`GenesisPin`](crate::GenesisPin). No coded checkpoint pins
//! anything above genesis (S1, design review 2026-11-03):
//!
//! - **CEN-E5** — the file a node opens records this network's genesis.
//!   Not a per-block predicate: it is run **once, at open**. The comparison
//!   is [`E5::conflict`]; [`E5::conflict_with`] reads a [`HeaderView`] and
//!   calls it. The finding is a [`GenesisConflict`]: the file is another
//!   network's, and the writer does not run. The first row this crate
//!   enforces at a site other than `validate` — `RowStatus::EnforcedAt` is
//!   its registry status (slice 3 Q4).
//! - **CEN-E1** — a genesis candidate is the pinned genesis. Per block,
//!   view-bound ([`E1`], a header rule); reads the pin from the `Trust`
//!   input that carries it into `validate`.

use shekyl_types::{BlockHash, BlockHeight};

use crate::census::CenRow;
use crate::fault::ViewRead;
use crate::genesis_pin::GenesisPin;
use crate::rules::{HeaderContext, HeaderRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::{AtHeight, HeaderView};

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
/// genesis arm, run once at open. [`E5::conflict`] compares the pin to the
/// genesis the caller already read. [`E5::conflict_with`] is that
/// comparison over a [`HeaderView`]. A conflict is a file from another
/// network, and the store refuses to open it.
pub(crate) struct E5;

impl Rule for E5 {
    const ROW: CenRow = CenRow::E5;
}

impl E5 {
    /// The pin against the genesis already read.
    ///
    /// `recorded` is block 0 when the file has a tip, and `None` when the
    /// file is empty. An empty file contradicts nothing: there is no block
    /// for a pin to disagree with. A pin that names nothing contradicts
    /// nothing. Both present and different is the conflict. A read that
    /// could not produce `recorded` is that read's fault, returned before
    /// this is called: a fault is not a conflict, and a hole below the tip
    /// is the read's own fault (the chain is dense to its tip).
    #[must_use]
    pub(crate) fn conflict(
        pin: &GenesisPin,
        recorded: Option<BlockHash>,
    ) -> Option<GenesisConflict> {
        let expected = pin.expected_at(BlockHeight::ZERO)?;
        let recorded = recorded?;
        (expected != recorded).then_some(GenesisConflict { expected, recorded })
    }

    /// [`conflict`](Self::conflict) over `view`.
    ///
    /// An empty view agrees. A view with a tip has a block at height 0:
    /// heights at or below the tip are dense. `AboveTip` there is a broken
    /// view, not a foreign genesis.
    pub(crate) fn conflict_with<'id, H: HeaderView<'id>>(
        pin: &GenesisPin,
        view: &H,
    ) -> Result<Option<GenesisConflict>, H::Fault> {
        if view.tip()?.is_none() {
            return Ok(None);
        }
        let recorded = match view.header_at(BlockHeight::ZERO)? {
            AtHeight::Recorded(record) => record.hash,
            AtHeight::AboveTip => unreachable!("a tip exists, so block 0 is recorded"),
        };
        Ok(Self::conflict(pin, Some(recorded)))
    }
}

/// A recorded chain whose block 0 is not the genesis the release pins
/// (CEN-E5). The file is another network's, and the writer does not run.
/// No pop can resolve it: genesis cannot be popped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisConflict {
    /// The identity the release vouches for at block 0.
    pub expected: BlockHash,
    /// The identity the file recorded at block 0.
    pub recorded: BlockHash,
}

impl GenesisPin {
    /// **CEN-E5.** The pin against the genesis the caller already read.
    ///
    /// `recorded` is block 0, or `None` for an empty file. The store calls
    /// this with the hash its snapshot read.
    /// [`conflict_with`](Self::conflict_with) reads a
    /// [`HeaderView`](crate::HeaderView) and calls the same comparison, so
    /// the two cannot grow different policies.
    #[must_use]
    pub fn conflict(&self, recorded: Option<BlockHash>) -> Option<GenesisConflict> {
        E5::conflict(self, recorded)
    }

    /// **CEN-E5** over a [`HeaderView`](crate::HeaderView).
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
