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

use crate::chain_drive::RELAY_FEE_REPRICE_STEPS;
use crate::pool_door_tests::{matured, paying_the_floor, AT};
use crate::scenario_shard::FILL_FROM_COINBASE;
use crate::schedule::ChainRules;
use crate::test_support::{h, tmp};

/// The scenario's store as the shim's chain: one snapshot per read, and
/// the rule set in force at its connecting height.
pub(crate) struct Store<'s> {
    pub(crate) store: &'s ChainStore,
    pub(crate) rules: ChainRules,
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

pub(crate) fn hex(tx: &shekyl_wire::Transaction) -> String {
    tx.serialize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The pool the submit shim shares with the ingest service keeps admitting
/// after a panic poisoned its lock: the service takes such a lock back, and
/// a shim that faulted on it would refuse every later submit for good (the
/// review of #1165, M7). Red edit: the shim maps a poisoned lock to a fault.
#[tokio::test]
async fn a_poisoned_pool_still_admits() {
    let (mut scenario, mined) = matured("pool-poisoned").await;
    let paid = paying_the_floor(&mut scenario, &mined, 0).await;
    let path = tmp("pool-poisoned-pool");
    let verdict = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        shekyl_types::UnixSeconds::from_raw(1),
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let pool = Arc::new(std::sync::Mutex::new(pool));
            let poisoner = Arc::clone(&pool);
            let panicked = std::thread::spawn(move || {
                let _held = poisoner.lock();
                panic!("a panic under the pool's lock");
            })
            .join();
            assert!(
                panicked.is_err() && pool.is_poisoned(),
                "the lock is poisoned"
            );
            let shim = Arc::new(RustPoolShim::new(
                chain,
                pool,
                AdmissionPolicy::GENESIS,
                || UnixSeconds::from_raw(1),
            ));
            SubmitEngine::new(shim, DaemonTxVerifier).submit(&hex(&paid), SubmitCaller::Owner)
        })
        .await;
    drop(std::fs::remove_file(&path));
    scenario.close().await;
    assert_eq!(verdict.expect("no engine fault"), SubmitVerdict::Accepted);
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
                        shekyl_types::UnixSeconds::from_raw(1),
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
                std::sync::Arc::new(std::sync::Mutex::new(pool)),
                AdmissionPolicy::GENESIS,
                || UnixSeconds::from_raw(1),
            ));
            let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
            let first = engine.submit(&hex(&paid), SubmitCaller::Owner);
            let again = engine.submit(&hex(&paid), SubmitCaller::Owner);
            let below = engine.submit(&hex(&cheap), SubmitCaller::Owner);
            let held = shim.with_pool(|pool| pool.record(&txid));
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
                        shekyl_types::UnixSeconds::from_raw(1),
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let engine = SubmitEngine::new(
                RustPoolShim::new(
                    chain,
                    std::sync::Arc::new(std::sync::Mutex::new(pool)),
                    AdmissionPolicy::GENESIS,
                    || UnixSeconds::from_raw(1),
                ),
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

/// The live lane's archival setup: two shards closed with real proofs,
/// the chain mined to where a compact join over both is admissible, and
/// the relay floor a transaction connecting next pays.
async fn closed_shards_lane(
    name: &str,
) -> (
    crate::scenario::Scenario<crate::scenario::FreeHash>,
    Vec<crate::scenario::Mined>,
    Vec<u64>,
    shekyl_types::BlockHeight,
    u64,
) {
    use crate::archival_driver::first_spending_height;
    use crate::scenario::{FreeHash, Scenario};
    use crate::scenario_shard::{
        close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, mine_to,
    };

    let rules = levered_rules();
    let mut scenario = Scenario::open_under(name, FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 2).await;
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
    let floor = scenario.connecting_relay_floor().await;
    (scenario, mined, shards, connecting, floor)
}

/// A post spending coinbase `coinbase`, paying the relay floor `floor`.
fn priced_post(
    spender: &shekyl_harness_spender::Spender,
    wallet: &shekyl_harness_spender::MinerWallet,
    coinbase: u64,
    connecting: shekyl_types::BlockHeight,
    floor: u64,
    post: &shekyl_harness_spender::PostedBond<'_>,
) -> shekyl_wire::Transaction {
    let mut fee = crate::archival_driver::FEE;
    for _ in 0..RELAY_FEE_REPRICE_STEPS {
        let tx = spender.spend_coinbase_posting(
            wallet,
            shekyl_types::BlockHeight::from_raw(coinbase),
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
}

/// The bond arm of the seam, in the live lane: two JoinMarket posts (a
/// compact shard set, a complete tree) over closed shards, priced at the
/// chain's floor, are accepted through the shim — the BP3 record-absent
/// fact the shim reads off the store, the validator's door at commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn join_posts_are_accepted_through_the_rust_pool_shim() {
    use crate::archival_driver::ENDPOINT;
    use crate::scenario_archival::{complete_tree, shard_set, Persona};

    let (mut scenario, mined, shards, connecting, floor) =
        closed_shards_lane("pool-submit-join").await;
    let spender = shekyl_harness_spender::Spender::over(&mined);
    let (compact, whole) = (Persona::at(1), Persona::at(2));
    let posts = [
        (0, compact.join(shard_set(shards), ENDPOINT)),
        (1, whole.join(complete_tree(), ENDPOINT)),
    ];
    let listed: Vec<shekyl_wire::Transaction> = posts
        .iter()
        .map(|(coinbase, post)| {
            priced_post(
                &spender,
                scenario.wallet(),
                *coinbase,
                connecting,
                floor,
                post,
            )
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
                        shekyl_types::UnixSeconds::from_raw(1),
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            let engine = SubmitEngine::new(
                RustPoolShim::new(
                    chain,
                    std::sync::Arc::new(std::sync::Mutex::new(pool)),
                    AdmissionPolicy::GENESIS,
                    || UnixSeconds::from_raw(1),
                ),
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

/// CEN-G10 at template selection, in the live lane: two JoinMarket posts by
/// one persona, funded by different coinbases, are each valid against the
/// chain — the door admits both, and the pool holds both — but a block
/// listing both is refused. The template selects one, names the other
/// conflicted on G10 (neither refused nor evicted), selects the other
/// persona's post beside it, and the block it lists connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn two_posts_by_one_persona_are_held_and_the_template_selects_one() {
    use crate::archival_driver::ENDPOINT;
    use crate::scenario_archival::{complete_tree, shard_set, Persona};
    use shekyl_chain_rules::CenRow;
    use shekyl_mempool::{select, Admission};

    let (mut scenario, mined, shards, connecting, floor) =
        closed_shards_lane("pool-template-g10").await;
    let spender = shekyl_harness_spender::Spender::over(&mined);
    let (compact, whole) = (Persona::at(1), Persona::at(2));
    let posts = [
        (0, compact.join(shard_set(shards), ENDPOINT)),
        (1, compact.join(complete_tree(), ENDPOINT)),
        (2, whole.join(complete_tree(), ENDPOINT)),
    ];
    let listed: Vec<shekyl_wire::Transaction> = posts
        .iter()
        .map(|(coinbase, post)| {
            priced_post(
                &spender,
                scenario.wallet(),
                *coinbase,
                connecting,
                floor,
                post,
            )
        })
        .collect();
    let txids: Vec<_> = listed.iter().map(|tx| tx.txid_parts().hash).collect();
    let path = tmp("pool-template-g10-pool");
    let selected = scenario
        .read_chain(|view, rule_set| {
            let mut pool = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("open")
            .0;
            for tx in &listed {
                let admission = pool
                    .admit(
                        tx.clone(),
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault");
                assert_eq!(
                    admission,
                    Admission::Admitted {
                        evicted: Vec::new()
                    },
                    "each post is valid alone"
                );
                assert!(pool.fluffed(&tx.txid_parts().hash).expect("published"));
            }
            select(&pool, view, rule_set, u64::MAX).expect("no fault")
        })
        .await;
    assert!(selected.refused.is_empty(), "{:?}", selected.refused);
    assert!(selected.stale.is_empty());
    let chosen: Vec<_> = selected.transactions.iter().map(|body| body.id).collect();
    assert_eq!(
        chosen.len(),
        2,
        "one of the persona's posts and the other persona's"
    );
    assert!(chosen.contains(&txids[2]));
    let (kept, other) = if chosen.contains(&txids[0]) {
        (txids[0], txids[1])
    } else {
        (txids[1], txids[0])
    };
    assert!(chosen.contains(&kept));
    assert_eq!(selected.conflicted, vec![(other, CenRow::G10)]);
    let bodies = selected
        .transactions
        .into_iter()
        .map(|body| body.tx)
        .collect();
    scenario
        .mine_listing(bodies)
        .await
        .unwrap_or_else(|o| panic!("the selected template connects: {o}"));
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// B2 (the review of #1102), the foreign tier of every verdict over the
/// Rust pool. A spend this node submitted is held in its stem phase. To a
/// foreign caller its bytes again are a fresh accept, a twin over its image
/// is a fresh accept that is not admitted, an unrelated spend is admitted,
/// and one paying a unit is `FeeTooLow` — and the three accepts verify the
/// same proofs, counted (never timed). Once the spend is fluffed, its bytes
/// are `AlreadyInPool` and the twin is a `DoubleSpendConflict`.
#[tokio::test]
async fn a_foreign_caller_is_told_nothing_the_stem_phase_holds() {
    use shekyl_chain_rules::probes;

    let (mut scenario, mined) = matured("pool-submit-foreign").await;
    let paid = paying_the_floor(&mut scenario, &mined, 0).await;
    let fresh = paying_the_floor(&mut scenario, &mined, 2).await;
    let (twin, cheap) = {
        let spender = shekyl_harness_spender::Spender::over(&mined);
        let wallet = scenario.wallet();
        let fee = match &paid.ct {
            shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
            shekyl_wire::transaction::Ct::Null(_) => unreachable!("a spend"),
        };
        (
            spender.spend_coinbase(wallet, h(0), h(AT), fee + 1_000),
            spender.spend_coinbase(wallet, h(1), h(AT), 1),
        )
    };
    let path = tmp("pool-submit-foreign-pool");
    let (stem, after) = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        UnixSeconds::from_raw(1),
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
                std::sync::Arc::new(std::sync::Mutex::new(pool)),
                AdmissionPolicy::GENESIS,
                || UnixSeconds::from_raw(1),
            ));
            let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
            let counted = |tx: &shekyl_wire::Transaction, caller| {
                let before = (probes::fcmp_verifies(), probes::signature_verifies());
                let verdict = engine.submit(&hex(tx), caller).expect("no engine fault");
                let after = (probes::fcmp_verifies(), probes::signature_verifies());
                (verdict, (after.0 - before.0, after.1 - before.1))
            };
            let owned = counted(&paid, SubmitCaller::Owner);
            assert_eq!(owned.0, SubmitVerdict::Accepted);
            let stem = (
                counted(&paid, SubmitCaller::Foreign),
                counted(&twin, SubmitCaller::Foreign),
                counted(&fresh, SubmitCaller::Foreign),
                counted(&cheap, SubmitCaller::Foreign).0,
                shim.with_pool(|pool| (pool.len(), pool.record(&twin.txid_parts().hash).is_some())),
            );
            assert!(shim.fluffed(&paid.txid_parts().hash).expect("fluffed"));
            let after = (
                counted(&paid, SubmitCaller::Foreign).0,
                counted(&twin, SubmitCaller::Foreign).0,
            );
            (stem, after)
        })
        .await;
    let (duplicate, conflict, accepted, below, (held, twin_held)) = stem;
    assert_eq!(
        duplicate.0,
        SubmitVerdict::Accepted,
        "a held stem duplicate is concealed"
    );
    assert_eq!(
        conflict.0,
        SubmitVerdict::Accepted,
        "a stem spender's conflict is concealed"
    );
    assert_eq!(accepted.0, SubmitVerdict::Accepted);
    assert_eq!(
        below,
        SubmitVerdict::Rejected {
            cause: RejectCause::FeeTooLow
        }
    );
    assert!(!twin_held, "the concealed twin is not admitted");
    assert_eq!(held, 2, "the stem spend and the fresh one");
    assert_eq!(
        (duplicate.1, conflict.1),
        (accepted.1, accepted.1),
        "a concealed answer verifies what a fresh accept does"
    );
    assert!(
        accepted.1 .0 > 0,
        "the subject exists: proofs were verified"
    );
    assert_eq!(after.0, SubmitVerdict::AlreadyInPool, "fluffed: disclosed");
    assert_eq!(
        after.1,
        SubmitVerdict::Rejected {
            cause: RejectCause::DoubleSpendConflict
        },
        "fluffed: the conflict is disclosed"
    );
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// A full pool is no presence oracle (Copilot, #1102). The pool holds one
/// entry's weight, and the owner's stem spend fills it. A foreign caller
/// resubmitting those bytes gets the answer a fresh spend of the same
/// weight and fee gets — refused for room, `FeeTooLow` — not a concealed
/// `Accepted` that only a held transaction could earn. Over `RustPoolShim`
/// and the production verifier.
#[tokio::test]
async fn a_full_pool_answers_a_stem_duplicate_as_a_fresh_spend_at_its_rate() {
    let (mut scenario, mined) = matured("pool-submit-full").await;
    let held = paying_the_floor(&mut scenario, &mined, 0).await;
    let fee = match &held.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => unreachable!("a spend"),
    };
    let peer = shekyl_harness_spender::Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(2),
        h(AT),
        fee,
    );
    assert_eq!(held.weight(), peer.weight(), "the same shape");
    let path = tmp("pool-submit-full-pool");
    let (owned, duplicate, fresh, unpublished) = scenario
        .with_store(|store, rules| {
            let chain = Store { store, rules };
            let mut pool = chain
                .read(|snapshot, rule_set| {
                    Pool::open(
                        &path,
                        UnixSeconds::from_raw(1),
                        &SnapshotView::new(snapshot),
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("open")
                    .0
                })
                .expect("a snapshot");
            pool.set_limits(shekyl_mempool::Limits {
                max_weight: u64::try_from(held.weight()).expect("fits"),
            });
            let shim = Arc::new(RustPoolShim::new(
                chain,
                std::sync::Arc::new(std::sync::Mutex::new(pool)),
                AdmissionPolicy::GENESIS,
                || UnixSeconds::from_raw(1),
            ));
            let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
            let submit = |tx: &shekyl_wire::Transaction, caller| {
                engine.submit(&hex(tx), caller).expect("no engine fault")
            };
            let owned = submit(&held, SubmitCaller::Owner);
            let duplicate = submit(&held, SubmitCaller::Foreign);
            let fresh = submit(&peer, SubmitCaller::Foreign);
            let unpublished =
                shim.with_pool(|pool| pool.record(&held.txid_parts().hash).map(|r| r.public));
            (owned, duplicate, fresh, unpublished)
        })
        .await;
    assert_eq!(
        owned,
        SubmitVerdict::Accepted,
        "the stem spend fills the pool"
    );
    assert_eq!(unpublished, Some(false), "held in its stem phase");
    assert_eq!(
        fresh,
        SubmitVerdict::Rejected {
            cause: RejectCause::FeeTooLow
        },
        "a fresh spend at its rate finds no room"
    );
    assert_eq!(duplicate, fresh, "and so does the held one, concealed");
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// A lone regtest node's own transaction (DX-Q3, Q9; no opt-in, rule 71):
/// submitted through the node's one pool, it enters in its stem phase and
/// the node's template does not list it; once the relay's entry marks it
/// shown (`RustPoolShim::fluffed`, what the relay driver calls at embargo
/// expiry), the node's next template lists it. The transaction is submitted
/// before the service starts, so the first job is built over it; every
/// observation is taken before the service stops and judged after, so a
/// failure reports instead of hanging the runtime's drop. Red edit: let the
/// producer list an entry in its stem phase.
#[tokio::test(flavor = "multi_thread")]
async fn a_lone_nodes_own_transaction_is_listed_once_the_relay_shows_it() {
    use crate::follower::Posting;
    use crate::service::{Arrival, ArrivalTag, Follow, Origin, PoolWiring, Reply, Service};
    let (mut scenario, mined) = matured("lone-own-tx").await;
    let paid = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = paid.txid_parts().hash;
    let copy = tmp("lone-own-tx-node");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &copy).expect("a copy of the chain");
        })
        .await;
    // The tip the node will meet next: mined after the copy was taken.
    let next = scenario.mine(1).await;
    let store = Arc::new(crate::test_support::open_store_under(
        &copy,
        &crate::scenario::RULES.in_force(h(0)),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    ));
    let pool_path = tmp("lone-own-tx-pool");
    let chain = Store {
        store: &store,
        rules: crate::scenario::RULES,
    };
    let pool = chain
        .read(|snapshot, rule_set| {
            Pool::open(
                &pool_path,
                UnixSeconds::from_raw(1),
                &SnapshotView::new(snapshot),
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("open")
            .0
        })
        .expect("a snapshot");
    let pool = Arc::new(std::sync::Mutex::new(pool));
    let board = Arc::new(shekyl_miner::JobBoard::new());
    let (_sync_tx, sync) = tokio::sync::watch::channel(shekyl_chain_sync::SyncState::Synced);
    let (seat, _sender, mut posting) =
        crate::test_support::job_seat(&board, Some(crate::test_support::harness_keys()), sync);
    let shim = Arc::new(RustPoolShim::new(
        Store {
            store: &store,
            rules: crate::scenario::RULES,
        },
        Arc::clone(&pool),
        AdmissionPolicy::GENESIS,
        || UnixSeconds::from_raw(1),
    ));
    let engine = SubmitEngine::new(Arc::clone(&shim), DaemonTxVerifier);
    assert_eq!(
        engine
            .submit(&hex(&paid), SubmitCaller::Owner)
            .expect("no engine fault"),
        SubmitVerdict::Accepted
    );
    let service = Service::start(
        Arc::clone(&store),
        crate::scenario::RULES,
        Arc::new(crate::service::service_tests::Gated::new()),
        crate::service::ServiceConfig::default(),
        shekyl_hash_budget::Budget::of_host(),
        Follow {
            job: Some(seat),
            pool: Some(PoolWiring {
                pool: Arc::clone(&pool),
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(|| UnixSeconds::from_raw(1)),
            }),
        },
    );
    let listed_now = |board: &shekyl_miner::JobBoard| {
        board
            .posted()
            .map(|(_, job)| job.listed.iter().any(|body| body.id == txid))
    };
    let posted = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        posting.wait_for(|now| matches!(now, Posting::Posted(_))),
    )
    .await
    .is_ok_and(|seen| seen.is_ok());
    let at_wait = posting.borrow().clone();
    let first = listed_now(&board);
    let shown = shim.fluffed(&txid).expect("the lock");
    let connected = service
        .door()
        .offer(Arrival {
            tag: ArrivalTag(1),
            origin: Origin::Local,
            block: next[0].template.block.serialize(),
            bodies: Vec::new(),
        })
        .expect("room")
        .reply()
        .await
        .reply;
    let started = std::time::Instant::now();
    let mut later = listed_now(&board);
    while later != Some(true) && started.elapsed() < std::time::Duration::from_secs(60) {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        later = listed_now(&board);
    }
    service.stop().await.expect("stops");
    drop(std::fs::remove_file(&pool_path));
    crate::test_support::cleanup(&copy);
    scenario.close().await;
    assert!(posted, "the node posts a job; the board reads {at_wait:?}");
    assert_eq!(first, Some(false), "a stem entry is not listed");
    assert!(shown, "the relay shows it");
    assert!(
        matches!(connected, Reply::Connected { .. }),
        "{connected:?}"
    );
    assert_eq!(
        later,
        Some(true),
        "the next template lists the shown transaction"
    );
}
