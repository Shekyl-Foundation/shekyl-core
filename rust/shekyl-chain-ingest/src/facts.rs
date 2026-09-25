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
//!   the verdict, S-CURVE grows the tree, G6 derives the median) one
//!   field's [`Origin`] flips from `PassedThrough` to `Derived` inside a
//!   function that already exists.
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
//! | `weight` | the coinbase's `Transaction::weight` plus the bodies' — the wire's weight, read off the verdict | composed | CEN-G6/G6b (slice 7) |
//! | `long_term_weight` | `shekyl_economics::long_term_weight(median, weight)` | composed (over a median that has no source yet) | CEN-G6/G6b |
//! | `coins_generated` | the parent's record advanced by the producer's priced reward through `shekyl_economics::advance_already_generated` | composed — **one source, one owner, one addition**: the reward is the template's, which is `shekyl-economics`'; the only ingest-local logic is the `+` | CEN-F13/F14/F14b: the verdict carries the priced reward |
//! | `burned` | the producer's priced burn (`shekyl-economics` in the template) | composed by the producer | CEN-F17/G11 |
//! | `root_after` | the caller's | no source yet — nothing here grows the tree | CEN-B5/I12 through S-CURVE (E3 writes the tree) |
//! | `long_term_effective_median` | the caller's | no source yet — G6 is slice 7 | CEN-G6/G6b |
//!
//! The caller's priced figures ([`Priced`]) come from whoever built the
//! block: the scenario driver hands over what `shekyl-block-template`
//! priced the coinbase at; live ingest (E3) will read them off the verdict
//! once F14b lands and this table's first three rows delete their
//! pass-through. **`Composed` does not re-derive the emission** — F13, F15
//! and F20 are landed definitions in `shekyl-chain-rules` whose value
//! stays off the verdict until F14b by ruling (`CHAIN_RULES_SLICE_4.md`
//! §4); a second copy of those definitions here is the duplication the
//! seam exists to prevent.

use shekyl_chain_rules::{recorded, ChainValid, ChainView, Corrupt, ViewRead};
use shekyl_chain_store::store::{ConnectFacts, Fact};
use shekyl_economics::{advance_already_generated, long_term_weight};
use shekyl_types::{BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;

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

/// The figures the block's producer priced it at — what [`Composed`]
/// passes through until the census rows that derive them land on the
/// verdict (module docs). The scenario driver reads these off
/// `shekyl_block_template::Template`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priced {
    /// The paid (penalised) block reward — what advances the parent's
    /// `coins_generated` (CEN-F13's accumulator).
    pub block_reward: AtomicUnits,
    /// This block's destroyed amount (CEN-F17's `actually_destroyed`).
    pub burned: AtomicUnits,
    /// The tree state after this block's drain (CEN-B5's next operand).
    pub root_after: CurveTreeRoot,
    /// The long-term median in force for this block (CEN-G6's operand).
    pub long_term_effective_median: LongTermWeight,
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

/// One transaction's weight as `u64`. A validated transaction has already
/// passed CEN-H1 (`MAX_TX_SIZE`), so the `usize` fits.
fn weight_u64(tx: &Transaction) -> u64 {
    u64::try_from(tx.weight()).expect("a validated transaction's weight fits u64")
}

/// The wire weight of a validated block: the coinbase plus every listed
/// body (`blockchain.cpp:5445`'s `coinbase_weight + Σ td.weight`, the
/// CEN-F14 operand). Checked, not saturated: a sum that does not fit is a
/// block the size bound already made unrepresentable.
#[must_use]
pub fn block_weight<'id, V: ChainView<'id>>(valid: &ChainValid<'id, V>) -> BlockWeight {
    let block = valid.block();
    let coinbase = weight_u64(block.miner_tx().1);
    let total = block.transactions().iter().fold(coinbase, |acc, (_, tx)| {
        acc.checked_add(weight_u64(tx))
            .expect("a validated block's weight fits u64")
    });
    BlockWeight::from_raw(total)
}

impl<P: PricedAt> FactsFor for Composed<P> {
    fn facts_for<'id, V: ChainView<'id>>(
        &self,
        height: BlockHeight,
        valid: &ChainValid<'id, V>,
        view: &V,
    ) -> Result<ConnectFacts, FactsFault<V::Fault>> {
        let priced = self
            .priced
            .priced_at(height)
            .ok_or(FactsFault::None { height })?;

        // CEN-F13's accumulator: the parent's gross emission, advanced by
        // this block's paid reward. Genesis starts the fold at zero. The
        // parent read is the rules' own (`recorded`): a hole is
        // `Corrupt::HoleBelowTip`, not a second fault.
        let parent_coins = match height.to_raw().checked_sub(1) {
            None => AtomicUnits::ZERO,
            Some(parent) => recorded(view, BlockHeight::from_raw(parent))?.coins_generated,
        };
        let coins_generated = AtomicUnits::from_raw(advance_already_generated(
            parent_coins.to_raw(),
            priced.block_reward.to_raw(),
        ));

        let weight = block_weight(valid);
        let long_term = LongTermWeight::from_raw(long_term_weight(
            priced.long_term_effective_median.to_raw(),
            weight.to_raw(),
        ));

        // Every origin `PassedThrough` — the owners computed these on the
        // producer's operands; no landed row has derived them on the
        // verdict (module docs). The flip is one line per field, here.
        Ok(ConnectFacts {
            weight: Fact::passed_through(weight),
            long_term_weight: Fact::passed_through(long_term),
            coins_generated: Fact::passed_through(coins_generated),
            burned: Fact::passed_through(priced.burned),
            root_after: Fact::passed_through(priced.root_after),
            long_term_effective_median: Fact::passed_through(priced.long_term_effective_median),
        })
    }
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod facts_tests;
