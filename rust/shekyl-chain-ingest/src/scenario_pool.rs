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

use shekyl_chain_rules::Substrate;

use super::Scenario;

impl<P: Substrate + Send + Sync + 'static> Scenario<P>
where
    P::Fault: std::fmt::Debug + Send,
{
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
            let store = (self.opener)(&self.path);
            f(&store, self.rules)
        };
        self.start_connector();
        out
    }
}
