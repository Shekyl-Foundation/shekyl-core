// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-M9, prepared (DRS-E5 PR-b): the submit engine over the Rust pool —
//! `RustPoolShim`, the `SubmitStateShim` the DRS-X flip routes in place of
//! the C++ one — judged end to end over a scenario chain with the
//! production verifier. Not routed: nothing in the daemon constructs it.

use std::sync::Arc;

use shekyl_chain_rules::{AdmissionPolicy, HeaderView, RuleSet, Tip};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, SnapshotView};
use shekyl_daemon_rpc::submit::{
    ChainSource, DaemonTxVerifier, RustPoolShim, ShimFault, SubmitCaller, SubmitEngine,
};
use shekyl_mempool::Pool;
use shekyl_rpc_types::{RejectCause, SubmitVerdict};
use shekyl_types::UnixSeconds;

use crate::pool_door_tests::{matured, paying_the_floor, AT};
use crate::schedule::ChainRules;
use crate::test_support::{h, tmp};

/// The scenario's store as the shim's chain: one snapshot per read, and
/// the rule set in force at its connecting height.
struct Store<'s> {
    store: &'s ChainStore,
    rules: ChainRules,
}

impl ChainSource for Store<'_> {
    fn read<R>(&self, f: impl FnOnce(&ReadSnapshot<'_>, &RuleSet) -> R) -> Result<R, ShimFault> {
        let snapshot = self.store.begin_read().map_err(|_| ShimFault)?;
        let connecting = Tip::connecting_height(
            SnapshotView::new(&snapshot)
                .tip()
                .map_err(|_| ShimFault)?
                .as_ref(),
        );
        Ok(f(&snapshot, &self.rules.in_force(connecting)))
    }
}

fn hex(tx: &shekyl_wire::Transaction) -> String {
    tx.serialize().iter().map(|b| format!("{b:02x}")).collect()
}

/// A spend paying the floor is accepted and held by the pool, not public
/// (the engine's own submit is a relay origination); the same bytes again
/// are `AlreadyInPool`, the identity the shim's facts carry; a spend paying
/// one atomic unit is refused on its fee.
#[tokio::test]
async fn the_engine_submits_through_the_rust_pool_and_its_door() {
    let (mut scenario, mined) = matured("pool-submit").await;
    let paid = paying_the_floor(&mut scenario, &mined, 0).await;
    let cheap = shekyl_harness_spender::Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(1),
        h(AT),
        1,
    );
    let txid = paid.txid_parts().hash;
    let path = tmp("pool-submit-pool");
    let (first, again, below, held) = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let shim = Arc::new(RustPoolShim::new(
                chain,
                pool,
                AdmissionPolicy::GENESIS,
                || UnixSeconds::from_raw(1),
            ));
            let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
            let first = engine.submit(&hex(&paid), SubmitCaller::Owner);
            let again = engine.submit(&hex(&paid), SubmitCaller::Owner);
            let below = engine.submit(&hex(&cheap), SubmitCaller::Owner);
            let held = shim.with_pool(|pool| pool.record(&txid)).expect("the lock");
            (first, again, below, held)
        })
        .await;
    assert_eq!(first.expect("no engine fault"), SubmitVerdict::Accepted);
    assert_eq!(
        again.expect("no engine fault"),
        SubmitVerdict::AlreadyInPool
    );
    assert_eq!(
        below.expect("no engine fault"),
        SubmitVerdict::Rejected {
            cause: RejectCause::FeeTooLow
        }
    );
    let held = held.expect("the pool holds the accepted spend");
    assert!(
        !held.public,
        "a submit is an origination: not public until fluffed"
    );
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The race arm of the seam: a twin spending the accepted spend's image is
/// refused as a double spend — the shim's facts classify the image as
/// another transaction's, the C++ `classify_key_image`'s answer.
#[tokio::test]
async fn a_twin_of_an_accepted_spend_is_a_double_spend_conflict() {
    let (mut scenario, mined) = matured("pool-submit-twin").await;
    let paid = paying_the_floor(&mut scenario, &mined, 0).await;
    let fee = match &paid.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => unreachable!("a spend"),
    };
    let twin = shekyl_harness_spender::Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(AT),
        fee + 1_000,
    );
    let path = tmp("pool-submit-twin-pool");
    let (first, second) = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let engine = SubmitEngine::new(
                RustPoolShim::new(chain, pool, AdmissionPolicy::GENESIS, || {
                    UnixSeconds::from_raw(1)
                }),
                DaemonTxVerifier,
            );
            (
                engine.submit(&hex(&paid), SubmitCaller::Owner),
                engine.submit(&hex(&twin), SubmitCaller::Owner),
            )
        })
        .await;
    assert_eq!(first.expect("no engine fault"), SubmitVerdict::Accepted);
    assert_eq!(
        second.expect("no engine fault"),
        SubmitVerdict::Rejected {
            cause: RejectCause::DoubleSpendConflict
        }
    );
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The bond arm of the seam, in the live lane: two JoinMarket posts (a
/// compact shard set, a complete tree) over closed shards, priced at the
/// chain's floor, are accepted through the shim — the BP3 record-absent
/// fact the shim reads off the store, the validator's door at commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes. Run in the live lane: cargo test -p shekyl-chain-ingest --features pipeline -- --ignored join_posts_are_accepted_through"]
async fn join_posts_are_accepted_through_the_rust_pool_shim() {
    use crate::archival_driver::{first_spending_height, ENDPOINT, FEE};
    use crate::scenario::{FreeHash, Scenario};
    use crate::scenario_archival::{complete_tree, shard_set, Persona};
    use crate::scenario_shard::{
        close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, mine_to,
    };
    use shekyl_types::BlockHeight;

    let rules = levered_rules();
    let mut scenario = Scenario::open_under("pool-submit-join", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, 10, 2).await;
    let shards: Vec<u64> = filled.closed.iter().map(|c| c.shard.to_raw()).collect();
    let connecting = inside_one_epoch(
        filled
            .closed
            .iter()
            .map(|&close| first_admissible_compact_join(&rules, close))
            .max()
            .expect("two shards closed"),
        2,
    );
    mine_to(&mut scenario, &mut mined, connecting).await;
    let floor = scenario
        .read_chain(|view, _| {
            let next = Tip::connecting_height(view.tip().expect("tip").as_ref());
            match shekyl_chain_rules::relay_floor_window(view, next).expect("floors") {
                shekyl_chain_rules::AtHeight::Recorded(f) => f.into_iter().min().expect("a window"),
                shekyl_chain_rules::AtHeight::AboveTip => unreachable!("the connecting height"),
            }
        })
        .await;
    let spender = shekyl_harness_spender::Spender::over(&mined);
    let (compact, whole) = (Persona::at(1), Persona::at(2));
    let posts = [
        (0, compact.join(shard_set(shards), ENDPOINT)),
        (1, whole.join(complete_tree(), ENDPOINT)),
    ];
    let listed: Vec<shekyl_wire::Transaction> = posts
        .iter()
        .map(|(coinbase, post)| {
            let mut fee = FEE;
            for _ in 0..8 {
                let tx = spender.spend_coinbase_posting(
                    scenario.wallet(),
                    BlockHeight::from_raw(*coinbase),
                    connecting,
                    fee,
                    Some(post),
                );
                let weight = u64::try_from(tx.weight()).expect("fits");
                let needed = shekyl_economics::quantized_fee(weight, floor).expect("priced");
                if needed <= fee {
                    return tx;
                }
                fee = needed;
            }
            panic!("the floor price did not settle")
        })
        .collect();
    let path = tmp("pool-submit-join-pool");
    let verdicts = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let engine = SubmitEngine::new(
                RustPoolShim::new(chain, pool, AdmissionPolicy::GENESIS, || {
                    UnixSeconds::from_raw(1)
                }),
                DaemonTxVerifier,
            );
            listed
                .iter()
                .map(|tx| engine.submit(&hex(tx), SubmitCaller::Owner))
                .collect::<Vec<_>>()
        })
        .await;
    for verdict in verdicts {
        assert_eq!(verdict.expect("no engine fault"), SubmitVerdict::Accepted);
    }
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}
