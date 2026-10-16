// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver's target claim: what `form` is told the CEN-D4 target is,
//! from the header chain the driver is replaying — never guessed.
//!
//! `form` judges CEN-D1 against a claimed target before any body work, so a
//! block short of its proof-of-work costs RandomX and nothing more (#1081's
//! review, item 1). The target is a function of the headers below the
//! connecting height alone: the LWMA-1 window of `N + 1` timestamps and
//! cumulative difficulties, or a Fakechain's fixed value. `form` runs ahead
//! of `connect`, in parallel, on blocks the store has not recorded yet, so
//! the driver keeps those headers itself, as it keeps the seed's
//! ([`crate::seed`]):
//!
//! - the [`TargetLedger`] — a window of [`HeaderRecord`]s ending at the
//!   last block the driver handed to `form`, each recorded with the target
//!   the driver claimed for it and the work that target adds
//!   ([`cumulative_difficulty_after`], the validator's own step);
//! - the **store** — every block already connected, which answers a height
//!   the window lacks: at the start of a run, and after a rewind moves the
//!   connecting height backwards.
//!
//! The claim runs the validator's derivation over the ledger
//! ([`target_claim`]), so the claim and the check cannot spell LWMA-1
//! differently. `validate` checks every claim against the store (the same
//! derivation over the committed headers): agreement is the normal case,
//! and a disagreement is a **driver defect** in replay (RD-Q5) — the ledger
//! and the store described different chains — surfaced as
//! [`RunFault::StaleTarget`](crate::connector::RunFault::StaleTarget), never
//! retried away.
//!
//! **A corrupt window is the writer's to judge.** The ledger's own records
//! only ever add a target of at least one to their parent's work, so a
//! hole, a work decrease or an overflow the derivation observes traces back
//! to a record the store supplied. [`TargetLedger::claim`] and
//! [`TargetLedger::extend`] return that observation instead of acting on
//! it. The driver stops reading, lets the blocks already in flight drain —
//! any of them may lead the writer to observe the same rows itself — and
//! then has the writer re-derive the target and its work over its own view
//! at exactly this height (`ObserveTarget`), so the halt is always the
//! writer's own observation of its own store.
//!
//! **A D6 refusal is the claim's verdict.** When the derivation itself
//! refuses (CEN-D6: the algorithm derived zero), `validate` would refuse
//! the block on the same headers. There is no target to claim, and the
//! driver emits that refusal as the block's verdict without forming it.

use core::convert::Infallible;
use std::collections::BTreeMap;

use shekyl_chain_rules::{
    cumulative_difficulty_after, target_claim, AtHeight, Corrupt, Fault, HeaderRecord, HeaderView,
    RuleSet, Target, Tip, Verdict,
};
use shekyl_difficulty::N_USIZE;
use shekyl_types::BlockHeight;
use shekyl_wire::Block;

/// Header records the driver has seen or fetched, by height, for claiming
/// targets.
#[derive(Clone, Debug, Default)]
pub struct TargetLedger {
    headers: BTreeMap<u64, HeaderRecord>,
}

impl TargetLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The heights a claim for `connecting` reads that the ledger lacks:
    /// the parent, whose work the next record extends, and the LWMA-1
    /// window below it. Empty at genesis admission.
    #[must_use]
    pub fn missing_for(&self, connecting: BlockHeight) -> Vec<BlockHeight> {
        let Some(parent) = connecting.to_raw().checked_sub(1) else {
            return Vec::new();
        };
        let n = u64::try_from(N_USIZE).expect("N fits u64");
        (parent.saturating_sub(n)..=parent)
            .filter(|h| !self.headers.contains_key(h))
            .map(BlockHeight::from_raw)
            .collect()
    }

    /// Record the store's header at `height` (a height
    /// [`Self::missing_for`] named).
    pub fn record(&mut self, height: BlockHeight, record: HeaderRecord) {
        self.headers.insert(height.to_raw(), record);
    }

    /// The target to claim for a block connecting at `connecting` under
    /// `rule_set`. The caller has recorded every height
    /// [`Self::missing_for`] named.
    ///
    /// # Errors
    ///
    /// The derivation's [`Corrupt`] observation: a hole or a work decrease
    /// in the window. The ledger's own records only ever add a target of at
    /// least one to their parent's work, so a decrease involves a record the
    /// store supplied — the caller has the writer re-derive over its own
    /// view, which halts on the same observation (`refuse_corrupt`).
    pub fn claim(
        &self,
        connecting: BlockHeight,
        rule_set: &RuleSet,
    ) -> Result<Verdict<Target>, Corrupt> {
        match target_claim(self, connecting, rule_set) {
            Ok(verdict) => Ok(verdict),
            Err(Fault::View(never)) => match never {},
            Err(Fault::Corrupt(corrupt)) => Err(corrupt),
            Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
        }
    }

    /// Record `block`, connecting at `connecting`, as claimed with `target`:
    /// its header, its identity, and the parent's work plus `target`.
    ///
    /// # Errors
    ///
    /// The step's [`Corrupt`] observation: a hole at the parent, or the sum
    /// overflowing (SI-10's belt). As for [`Self::claim`], the parent's work
    /// traces back to a record the store supplied, and the caller has the
    /// writer re-derive over its own view.
    pub fn extend(
        &mut self,
        connecting: BlockHeight,
        block: &Block,
        target: Target,
    ) -> Result<(), Corrupt> {
        let cumulative_difficulty = match cumulative_difficulty_after(self, connecting, target) {
            Ok(work) => work,
            Err(Fault::View(never)) => match never {},
            Err(Fault::Corrupt(corrupt)) => return Err(corrupt),
            Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
        };
        self.record(
            connecting,
            HeaderRecord {
                hash: block.hash(),
                header: block.header.clone(),
                cumulative_difficulty,
            },
        );
        Ok(())
    }

    /// Forget every height above `to` — the post-rewind chain (RD-Q13).
    pub fn rewind_to(&mut self, to: BlockHeight) {
        self.headers.split_off(&to.to_raw().saturating_add(1));
    }

    /// Forget heights a claim for `connecting` no longer reads: everything
    /// below the parent's LWMA-1 window. Between rewinds the window only
    /// moves up; after one, the store answers. Keeps the ledger a window.
    pub fn forget_below_window_of(&mut self, connecting: BlockHeight) {
        let n = u64::try_from(N_USIZE).expect("N fits u64");
        let floor = connecting.to_raw().saturating_sub(1).saturating_sub(n);
        let keep = self.headers.split_off(&floor);
        self.headers = keep;
    }

    /// How many headers the ledger holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Whether the ledger holds no header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

/// The ledger as the derivation reads it: a header chain whose tip is its
/// highest record. Infallible — a missing height is
/// [`AtHeight::AboveTip`], which the derivation reports as a corrupt hole
/// and [`TargetLedger::claim`] as a ledger defect.
impl HeaderView<'static> for TargetLedger {
    type Fault = Infallible;

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(self.headers.last_key_value().map(|(height, record)| Tip {
            height: BlockHeight::from_raw(*height),
            hash: record.hash,
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, Infallible> {
        Ok(match self.headers.get(&height.to_raw()) {
            Some(record) => AtHeight::Recorded(record.clone()),
            None => AtHeight::AboveTip,
        })
    }
}

#[cfg(test)]
mod tests {
    use shekyl_chain_rules::harness::fixture::candidate;
    use shekyl_chain_rules::harness::{expected_target, MockChain};
    use shekyl_difficulty::CumulativeDifficulty;

    use super::*;

    fn h(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    fn n() -> u64 {
        u64::try_from(N_USIZE).expect("N fits u64")
    }

    fn record_at(work: u128) -> HeaderRecord {
        let block = candidate(Vec::new()).block;
        HeaderRecord {
            hash: block.hash(),
            header: block.header,
            cumulative_difficulty: CumulativeDifficulty::from_raw(work),
        }
    }

    /// Genesis admission reads nothing and claims what the validator
    /// derives on an empty chain.
    #[test]
    fn genesis_reads_nothing_and_claims_the_validators_target() {
        let ledger = TargetLedger::new();
        assert!(ledger.missing_for(h(0)).is_empty());
        assert_eq!(
            ledger.claim(h(0), &RuleSet::GENESIS),
            Ok(Ok(expected_target(
                &MockChain::default(),
                &RuleSet::GENESIS
            )))
        );
    }

    /// The store is asked for the parent and the LWMA-1 window below it —
    /// `N + 1` heights once the chain is that long, fewer before — and only
    /// for what the ledger lacks.
    #[test]
    fn the_store_is_asked_for_the_window_the_ledger_lacks() {
        let mut ledger = TargetLedger::new();
        assert_eq!(ledger.missing_for(h(3)), vec![h(0), h(1), h(2)]);
        let connecting = n() + 10;
        let missing = ledger.missing_for(h(connecting));
        assert_eq!(missing.len(), N_USIZE + 1, "the parent and N below it");
        assert_eq!(missing.first(), Some(&h(connecting - 1 - n())));
        assert_eq!(missing.last(), Some(&h(connecting - 1)));
        ledger.record(h(connecting - 1), record_at(1));
        assert_eq!(ledger.missing_for(h(connecting)).len(), N_USIZE);
    }

    /// A formed block joins the ledger with its parent's work plus the
    /// target claimed for it — the validator's own step.
    #[test]
    fn extend_adds_the_claimed_target_to_the_parents_work() {
        let mut ledger = TargetLedger::new();
        ledger.record(h(4), record_at(1_000));
        let target = ledger
            .claim(h(5), &RuleSet::GENESIS)
            .expect("consistent")
            .expect("a target");
        let block = candidate(Vec::new()).block;
        ledger.extend(h(5), &block, target).expect("consistent");
        let AtHeight::Recorded(extended) = ledger.header_at(h(5)).expect("infallible") else {
            panic!("the formed block is recorded");
        };
        assert_eq!(
            extended.cumulative_difficulty.to_raw(),
            1_000 + target.difficulty().to_raw()
        );
        assert_eq!(extended.hash, block.hash());
        assert_eq!(
            ledger.tip().expect("infallible").map(|tip| tip.height),
            Some(h(5))
        );
    }

    /// A rewind drops the abandoned branch; forgetting keeps exactly the
    /// window the next claim reads.
    #[test]
    fn rewind_drops_the_fork_and_forget_keeps_the_window() {
        let mut ledger = TargetLedger::new();
        let top = n() + 20;
        for height in 0..=top {
            ledger.record(h(height), record_at(u128::from(height) + 1));
        }
        ledger.rewind_to(h(top - 5));
        assert_eq!(
            ledger.tip().expect("infallible").map(|tip| tip.height),
            Some(h(top - 5))
        );
        ledger.forget_below_window_of(h(top - 4));
        assert_eq!(ledger.len(), N_USIZE + 1);
        assert!(ledger.missing_for(h(top - 4)).is_empty());
    }
}
