// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scenario's pool helpers.
//!
//! [`Scenario::read_chain`] and [`Scenario::with_store`] stop the connector
//! and start it again the way [`Scenario::reopen`] does, so a test can read
//! the store the connector owns. [`Scenario::reorganize_with_pool`] offers
//! a switch's returned transactions to the pool after the switch lands.
//! [`Scenario::connecting_economy_rate`] is the fee the daemon serves for
//! the next block, and [`Scenario::admit`] is the daemon's pool admission:
//! the chain forge prices every transaction it lists at the one and passes
//! it through the other (`CHAIN_FORGE.md` §11.4).

use shekyl_mempool::{Admission, Pool};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use crate::pow::Pow;
use crate::scenario::{Mined, StepOutcome};

use super::Scenario;

/// A listed transaction the daemon's pool did not take, and its answer.
#[derive(Debug)]
pub struct PoolRefused {
    /// The transaction refused.
    pub txid: TxHash,
    /// What the pool answered: a refusal by the door, a duplicate, a full
    /// pool, or an admission that evicted something.
    pub answer: Admission,
}

impl core::fmt::Display for PoolRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the pool does not take {}: {:?}", self.txid, self.answer)
    }
}

/// Why a block listing transactions was not mined.
#[derive(Debug)]
pub enum ListingFault {
    /// The daemon's pool refused a listed transaction.
    Pool(PoolRefused),
    /// The block did not connect.
    Step(StepOutcome),
}

impl core::fmt::Display for ListingFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pool(refused) => refused.fmt(f),
            Self::Step(outcome) => outcome.fmt(f),
        }
    }
}

impl<P: Pow> Scenario<P> {
    /// The switch, then the pool (DRS-E5 PR-b b4): the demoted blocks'
    /// listed transactions go to `pool` after the switch lands
    /// (`SwitchDone::returned`'s caller), through the door against the chain
    /// the switch left, at `now`. The pool's answer decides their relay and
    /// templates only: the switch read every body it connected from the
    /// store.
    pub async fn reorganize_with_pool(
        &mut self,
        plan: &crate::connector::SwitchPlan,
        pool: &mut shekyl_mempool::Pool,
        now: shekyl_types::UnixSeconds,
    ) -> Result<
        (
            crate::connector::Switched,
            Vec<(shekyl_types::TxHash, shekyl_mempool::Admission)>,
        ),
        crate::connector::RunFault,
    > {
        let switched = self.reorganize(plan).await?;
        let admissions = match &switched {
            crate::connector::Switched::Done(done) => {
                let returned = done.returned.clone();
                let offers = self
                    .read_chain(|view, rule_set| {
                        pool.returned(
                            returned,
                            now,
                            view,
                            rule_set,
                            &shekyl_chain_rules::AdmissionPolicy::GENESIS,
                        )
                    })
                    .await;
                assert!(
                    offers.faults.is_empty(),
                    "the pool faulted on the returns: {:?}",
                    offers.faults
                );
                offers.admissions
            }
            _ => Vec::new(),
        };
        Ok((switched, admissions))
    }

    /// Run `f` over the chain the store holds now, through the committed
    /// snapshot's view (`SnapshotView`, what the pool door judges against),
    /// with the rule set in force at the height the next block connects at
    /// ([`Self::with_store`]).
    ///
    /// # Panics
    ///
    /// If the snapshot cannot be begun or its tip read: the store this
    /// driver just held is unreadable, which is not a scenario outcome.
    pub async fn read_chain<R>(
        &mut self,
        f: impl FnOnce(&shekyl_chain_store::store::SnapshotView<'_>, &shekyl_chain_rules::RuleSet) -> R,
    ) -> R {
        self.with_store(|store, rules| {
            let snapshot = store
                .begin_read()
                .expect("a snapshot of the scenario's store");
            let view = shekyl_chain_store::store::SnapshotView::new(&snapshot);
            let connecting = shekyl_chain_rules::Tip::connecting_height(
                shekyl_chain_rules::HeaderView::tip(&view)
                    .expect("the tip of the scenario's store")
                    .as_ref(),
            );
            f(&view, &rules.in_force(connecting))
        })
        .await
    }

    /// The minimum relay floor at the height the next block connects at:
    /// the floor window's least member (`CEN-M3`).
    ///
    /// # Panics
    ///
    /// If the window cannot be read or is empty: the chain this driver
    /// just held has no floor, which is not a scenario outcome.
    pub async fn connecting_relay_floor(&mut self) -> u64 {
        self.read_chain(|view, _| {
            let connecting = shekyl_chain_rules::Tip::connecting_height(
                shekyl_chain_rules::HeaderView::tip(view)
                    .expect("the tip of the scenario's store")
                    .as_ref(),
            );
            match shekyl_chain_rules::relay_floor_window(view, connecting).expect("floors") {
                shekyl_chain_rules::AtHeight::Recorded(floors) => {
                    floors.into_iter().min().expect("a window")
                }
                shekyl_chain_rules::AtHeight::AboveTip => {
                    unreachable!("the connecting height is recorded")
                }
            }
        })
        .await
    }

    /// The fee per weight a transaction listed in the next block pays: the
    /// economy rung of the fee ladder the daemon serves at the height that
    /// block connects at (`shekyl_chain_rules::fee_ladder_at`, the node's
    /// `fee_estimate`; FL-R6: the economy rung is the relay floor).
    ///
    /// # Panics
    ///
    /// If the ladder cannot be read: the chain this driver just held has no
    /// fee, which is not a scenario outcome.
    pub async fn connecting_economy_rate(&mut self) -> u64 {
        self.read_chain(|view, _| {
            let connecting = shekyl_chain_rules::Tip::connecting_height(
                shekyl_chain_rules::HeaderView::tip(view)
                    .expect("the tip of the scenario's store")
                    .as_ref(),
            );
            match shekyl_chain_rules::fee_ladder_at(view, connecting).expect("the fee ladder") {
                shekyl_chain_rules::AtHeight::Recorded(ladder) => ladder.economy,
                shekyl_chain_rules::AtHeight::AboveTip => {
                    unreachable!("the connecting height is recorded")
                }
            }
        })
        .await
    }

    /// Offer `listed`, in its order, to the daemon's pool over the chain the
    /// next block extends: a pool opened fresh on that chain, admitting
    /// under [`AdmissionPolicy::GENESIS`](shekyl_chain_rules::AdmissionPolicy::GENESIS)
    /// and this chain's network, the node's own policy. Each must be
    /// admitted with nothing evicted, so each later one is judged with the
    /// earlier ones held (a second spend of one key image is refused). The
    /// admitted transactions are kept for [`Self::take_admitted`].
    ///
    /// The receive time is the driver's clock: the node this driver stands
    /// in for has no other, and the pool's receive time enters no rule.
    ///
    /// # Errors
    ///
    /// [`PoolRefused`] for the first transaction the pool does not take;
    /// none of `listed` is then kept.
    ///
    /// # Panics
    ///
    /// If the pool cannot be opened or faults: a fresh pool over a chain
    /// this driver just held, which is not a scenario outcome.
    pub async fn admit(&mut self, listed: &[Transaction]) -> Result<(), PoolRefused> {
        let network = self.network_id();
        let now = UnixSeconds::from_raw(self.substrate.now().to_raw());
        let dir = tempfile::tempdir_in(self.path.dir()).expect("a pool directory");
        let policy = shekyl_chain_rules::AdmissionPolicy::GENESIS;
        let admitted = self
            .read_chain(|view, rule_set| {
                let (mut pool, _, _) = Pool::open(
                    dir.path().join("pool.redb"),
                    now,
                    view,
                    rule_set,
                    &network,
                    &policy,
                )
                .unwrap_or_else(|fault| panic!("the pool opens: {fault:?}"));
                let mut admitted = Vec::with_capacity(listed.len());
                for tx in listed {
                    let txid = tx.txid_parts().hash;
                    let answer = pool
                        .admit(tx.clone(), now, view, rule_set, &policy)
                        .unwrap_or_else(|fault| panic!("the pool judges {txid}: {fault:?}"));
                    match answer {
                        Admission::Admitted { evicted } if evicted.is_empty() => {
                            admitted.push(txid);
                        }
                        answer => return Err(PoolRefused { txid, answer }),
                    }
                }
                Ok(admitted)
            })
            .await?;
        self.admitted.extend(admitted);
        Ok(())
    }

    /// [`Self::admit`] `listed`, then [`Self::mine_listing`] it.
    ///
    /// # Errors
    ///
    /// [`ListingFault::Pool`] when the pool refuses one, and nothing is
    /// mined; [`ListingFault::Step`] when the block does not connect.
    pub async fn mine_admitted(&mut self, listed: Vec<Transaction>) -> Result<Mined, ListingFault> {
        self.admit(&listed).await.map_err(ListingFault::Pool)?;
        self.mine_listing(listed).await.map_err(ListingFault::Step)
    }

    /// Whether the daemon's pool admitted `txid` ([`Self::admit`]), taking
    /// it: a transaction is taken once, by the block that lists it.
    pub fn take_admitted(&mut self, txid: &TxHash) -> bool {
        self.admitted.remove(txid)
    }

    /// Lend `f` the store itself and the rules it runs under — for a reader
    /// that begins its own snapshots (the submit engine's shim over the
    /// pool). The connector is stopped so the store can be opened here, and
    /// a fresh one is started over the same file after, as
    /// [`reopen`](Self::reopen) does.
    pub async fn with_store<R>(
        &mut self,
        f: impl FnOnce(&shekyl_chain_store::store::ChainStore, crate::schedule::ChainRules) -> R,
    ) -> R {
        self.stop_connector().await;
        let out = {
            let store = (self.opener)(self.path.path());
            f(&store, self.rules)
        };
        self.start_connector();
        out
    }
}
