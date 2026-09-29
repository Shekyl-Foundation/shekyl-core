// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where `connect`'s facts come from — the seam between the validator's
//! verdict and the store's record (`CHAIN_RULES_SLICE_6.md` §5.3.2).
//!
//! The store persists consensus facts computed by their owners and never
//! computes them (C2-R8 principle 3). Until every fact is derived by a
//! landed census row and carried on the verdict, something has to
//! **compose** the [`ConnectFacts`] `connect` takes, and this module names
//! the two things that do:
//!
//! - [`Trace`] — the E2 replay: every fact **passed through** from the LMDB
//!   harvest of the chain being replayed. E2-only; the harness that reads
//!   a trace is the only thing that has one.
//! - [`Composed`] — production: facts assembled from their owners for a
//!   block that has no trace, which is every block live ingest will ever
//!   connect and every block the slice-6 scenario driver builds. The
//!   driver is its first consumer; E3 is its second. It is written here,
//!   beside the connector, **not** as test support — as test support it
//!   would be a second implementation the daemon redoes; here it is the
//!   boundary advancing, and when a row lands (F14b prices the reward on
//!   the verdict, G6 derives the median) one field's [`Origin`] flips from
//!   `PassedThrough` to `Derived` inside a function that already exists —
//!   or, as DRS-E3 did for the root, the field leaves `ConnectFacts`
//!   because the verdict carries the value itself.
//!
//! # What `Composed` composes, and what it passes through
//!
//! The origins are **honest about who computed the value**, and the reason
//! is stronger than bookkeeping: `Provenance::is_parity_evidence` refuses
//! a file any of whose facts the consensus path did not produce. `Derived`
//! means the *validator* derived it under the row that defines it; marking
//! a self-computed field `Derived` would let a driver-built store claim
//! parity evidence for a field no rule judged. So a value an owner crate
//! computed on the producer's operands is `PassedThrough` even when the
//! arithmetic is the owner's, until the `DeletedBy` row that derives it
//! lands on the verdict.
//!
//! `PassedThrough` therefore covers two distances from done, and the
//! per-field test records which is which so `Provenance::passed_through`
//! decomposes when someone asks how far E6 has to go:
//!
//! - **Composed** — a provisional source of our own, one line that becomes
//!   a deletion when the row lands.
//! - **No source yet** — nothing of ours produces the value; the caller
//!   supplies it exactly as the E2 trace did.
//!
//! | field | composed from | why passed through | flips when |
//! | --- | --- | --- | --- |
//! | `burned` | the producer's priced burn (`shekyl-economics` in the template) | composed by the producer | CEN-F17/G11 (slice 7 wave B) |
//!
//! One row left of seven. Each of the others left `ConnectFacts`
//! altogether rather than flipping to `Derived` here, because the verdict
//! carries the value itself: `cumulative_difficulty` (E6 slice 2, CEN-D4),
//! `root_after` (DRS-E3, 2026-09-26: `validate` derives the drain and the
//! root), and on 2026-09-28 (E6 slice 7 commits 4–5) `weight` and
//! `long_term_weight` (CEN-G6b, `ValidatedBlock::weights`),
//! `long_term_effective_median` (CEN-G6, the same) and `coins_generated`
//! (CEN-F14b / G12, `ValidatedBlock::emission` — the parent's accumulator
//! advanced by the *paid* reward, which the validator prices and no
//! producer is asked for any more).
//!
//! The caller's priced figure ([`Priced`]) comes from whoever built the
//! block: the scenario driver hands over what `shekyl-block-template`
//! priced the burn at; live ingest reads it off the verdict once F17/G11
//! land and this table's last row deletes its pass-through. **`Composed`
//! derives nothing** — every definition it once composed over is on the
//! verdict, and a second copy of one here is the duplication the seam
//! exists to prevent.

use shekyl_chain_rules::{ChainValid, ChainView, Corrupt, ViewRead};
use shekyl_chain_store::store::{ConnectFacts, Fact};
use shekyl_types::BlockHeight;
use shekyl_units::AtomicUnits;

use crate::trace::Trace;

/// Why a provider could not hand `connect` its facts. Never a verdict.
#[derive(Debug)]
pub enum FactsFault<VF> {
    /// The provider has nothing for this height: a trace that does not
    /// cover it, or a [`Priced`] the caller did not supply.
    None {
        /// The height asked for.
        height: BlockHeight,
    },
    /// A view read faulted while composing (the parent's record).
    View(VF),
    /// The parent read observed a store invariant — a hole below the tip
    /// ([`Corrupt::HoleBelowTip`]). The connector halts the writer on it,
    /// the same class a rule's [`recorded`] read raises.
    Corrupt(Corrupt),
}

impl<VF> From<ViewRead<VF>> for FactsFault<VF> {
    fn from(read: ViewRead<VF>) -> Self {
        match read {
            ViewRead::View(fault) => Self::View(fault),
            ViewRead::Corrupt(corrupt) => Self::Corrupt(corrupt),
        }
    }
}

/// The seam. One method: the facts `connect` persists for `valid` at
/// `height`, read against `view` (the batch's view, so the parent is what
/// the verdict was judged against).
pub trait FactsFor {
    /// # Errors
    ///
    /// A [`FactsFault`]; the connector maps `None` to
    /// [`crate::connector::RunFault::NoFacts`], `View` to the store fault
    /// it carries, and `Corrupt` through `refuse_corrupt` so the writer halts.
    fn facts_for<'id, V: ChainView<'id>>(
        &self,
        height: BlockHeight,
        valid: &ChainValid<'id, V>,
        view: &V,
    ) -> Result<ConnectFacts, FactsFault<V::Fault>>;
}

impl FactsFor for Trace {
    /// E2: every fact passed through from the harvest (`trace.rs`'s
    /// `From<Borrowed<Facts>>`); nothing read, nothing derived.
    fn facts_for<'id, V: ChainView<'id>>(
        &self,
        height: BlockHeight,
        _valid: &ChainValid<'id, V>,
        _view: &V,
    ) -> Result<ConnectFacts, FactsFault<V::Fault>> {
        self.borrow(height)
            .map(Into::into)
            .ok_or(FactsFault::None { height })
    }
}

/// The figure the block's producer priced it at — what [`Composed`] passes
/// through until the census rows that derive it land on the verdict
/// (module docs). The scenario driver reads it off
/// `shekyl_block_template::Template`. The paid reward and the median were
/// fields here until E6 slice 7 derived them (`ValidatedBlock::{emission,
/// weights}`); a producer is asked for neither now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priced {
    /// This block's destroyed amount (CEN-F17's `actually_destroyed`).
    pub burned: AtomicUnits,
}

/// Who knows what a height was priced at. The driver answers from the
/// template it built; a live producer answers from its own template.
pub trait PricedAt {
    /// The priced figures for `height`, or `None` if the caller has none —
    /// which is [`FactsFault::None`], not a default.
    fn priced_at(&self, height: BlockHeight) -> Option<Priced>;
}

/// Production composition of `connect`'s facts from their owners (module
/// docs). Generic over where the priced figures come from.
#[derive(Debug)]
pub struct Composed<P> {
    priced: P,
}

impl<P> Composed<P> {
    /// Compose over `priced`.
    pub const fn new(priced: P) -> Self {
        Self { priced }
    }

    /// The pass-through source.
    pub const fn priced(&self) -> &P {
        &self.priced
    }
}

impl<P: PricedAt> FactsFor for Composed<P> {
    fn facts_for<'id, V: ChainView<'id>>(
        &self,
        height: BlockHeight,
        _valid: &ChainValid<'id, V>,
        _view: &V,
    ) -> Result<ConnectFacts, FactsFault<V::Fault>> {
        let priced = self
            .priced
            .priced_at(height)
            .ok_or(FactsFault::None { height })?;
        // `PassedThrough` — the producer computed it on its own operands;
        // no landed row has derived it on the verdict (module docs). The
        // flip is one line, here. Nothing is read from the view any more:
        // the parent-side read this function made for `coins_generated`
        // left with the field (the validator makes it, once, under F13).
        Ok(ConnectFacts {
            burned: Fact::passed_through(priced.burned),
        })
    }
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod facts_tests;
