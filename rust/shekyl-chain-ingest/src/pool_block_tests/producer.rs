// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The template producer over a real pool: admission, eviction, and pop.

use super::*;

/// The producer's admission (`select_admitting`, the fill's `admit`) is
/// asked of each candidate the parent admits, in selection order. One it
/// declines is named in `declined`, is not listed, and the next candidate
/// is still offered: the fill passes over a body, it does not stop.
#[tokio::test]
async fn a_body_the_admission_declines_is_passed_over_and_the_next_is_listed() {
    let (mut scenario, mined) = matured("pool-template-declined").await;
    let first = paying_the_floor(&mut scenario, &mined, 0).await;
    let second = paying_the_floor(&mut scenario, &mined, 1).await;
    let dear = {
        let floor = fee_of(&second);
        Spender::over(&mined).spend_coinbase(scenario.wallet(), h(2), h(AT), floor * 10)
    };
    let dear_id = dear.txid_parts().hash;
    let path = tmp("pool-template-declined-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let (selected, offered) = scenario
        .read_chain(|view, rule_set| {
            for tx in [first.clone(), second.clone(), dear.clone()] {
                let txid = tx.txid_parts().hash;
                assert_eq!(
                    pool.admit(
                        tx,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault"),
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
                assert!(pool.fluffed(&txid).expect("publish"));
            }
            let dear_fee = fee_of(&dear);
            let mut offered = 0;
            let selected =
                shekyl_mempool::select_admitting(&pool, view, rule_set, u64::MAX, |_, fee| {
                    offered += 1;
                    fee != dear_fee
                })
                .expect("template");
            (selected, offered)
        })
        .await;
    assert_eq!(offered, 3, "every candidate the parent admits is offered");
    assert_eq!(selected.declined, vec![dear_id]);
    let listed: Vec<_> = selected.transactions.iter().map(|body| body.id).collect();
    assert_eq!(listed.len(), 2, "the two after it are listed: {listed:?}");
    assert!(!listed.contains(&dear_id));
    assert!(selected.refused.is_empty() && selected.conflicted.is_empty());
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The node's producer (`template`) lists the pool's bodies under the
/// reward-aware fill priced at the coinbase reserve (DX-Q3, N2). The
/// template's block weight and reward are `Fill`'s for the same bodies at
/// the coinbase the block actually carried, every body the parent admits
/// below the median is listed, and the block connects.
#[tokio::test]
async fn the_producer_prices_its_listing_at_the_built_coinbase_and_the_block_connects() {
    use crate::template::{produce, Producer};
    let (mut scenario, mined) = matured("producer-fill").await;
    let first = paying_the_floor(&mut scenario, &mined, 0).await;
    let second = paying_the_floor(&mut scenario, &mined, 1).await;
    let path = tmp("producer-fill-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    scenario
        .read_chain(|view, rule_set| {
            for tx in [first.clone(), second.clone()] {
                let txid = tx.txid_parts().hash;
                assert_eq!(
                    pool.admit(
                        tx,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault"),
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
                assert!(pool.fluffed(&txid).expect("publish"));
            }
        })
        .await;
    let listed_weights: std::collections::BTreeMap<_, _> = pool
        .listing()
        .map(|(txid, listed)| (txid, listed.weight))
        .collect();
    let keys = crate::test_support::harness_keys();
    let params = shekyl_economics::EconomicParams::default();
    let pool = std::sync::Mutex::new(pool);
    let (produced, facts, target) = scenario
        .with_store(|store, rules| {
            let snap = store.begin_read().expect("a snapshot");
            let facts = crate::connector::chain_facts_on(&snap).expect("the facts");
            let now = facts
                .median_timestamp
                .map_or(crate::scenario::CLOCK_START, |median| {
                    shekyl_types::Timestamp::from_raw(median.to_raw() + 1)
                });
            let producer = Producer {
                rules,
                keys: &keys,
                params: &params,
                now,
            };
            let produced = produce(&snap, &producer, Some(&pool), |_| true).expect("a template");
            let (_, _, target) = crate::router::claim_next(&snap, rules).expect("the claim");
            (produced, facts, target)
        })
        .await;
    let listed: Vec<_> = produced
        .transactions
        .iter()
        .map(|tx| tx.txid_parts().hash)
        .collect();
    assert_eq!(
        listed.len(),
        2,
        "both bodies, far below the median: {listed:?}"
    );
    let bodies_weight: u64 = listed.iter().map(|txid| listed_weights[txid]).sum();
    let fees: u64 = produced.transactions.iter().map(fee_of).sum();
    let fill = shekyl_block_template::Fill::listed(
        facts.medians.effective_median.to_raw(),
        produced.coinbase_weight,
        facts.parent_coins_generated.to_raw(),
        facts.tx_volume,
        &params,
        bodies_weight,
        fees,
    )
    .expect("priced");
    assert_eq!(produced.block_weight, fill.block_weight(), "the weight");
    assert_eq!(produced.block_reward.to_raw(), fill.reward(), "the reward");
    assert!(produced.evicted.is_empty(), "nothing the parent refuses");
    let height = produced.job.height;
    let next = crate::scenario::NextBlock {
        height,
        seed: produced.job.seed,
        target,
        template: shekyl_block_template::Template {
            block: produced.job.block.clone(),
            transactions: produced.transactions.clone(),
            block_weight: produced.block_weight,
            block_reward: produced.block_reward,
            miner_emission: shekyl_units::AtomicUnits::ZERO,
            total_fees: shekyl_units::AtomicUnits::ZERO,
            miner_fee_income: shekyl_units::AtomicUnits::ZERO,
            fees_burned: shekyl_units::AtomicUnits::ZERO,
        },
    };
    let connected = scenario
        .connect_template(next)
        .await
        .unwrap_or_else(|outcome| panic!("the producer's block connects: {outcome}"));
    assert_eq!(connected.height, height);
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// A template on an older tip than the pool's last judgement posts nothing
/// and evicts nothing (the review of #1165, M4). The spend references a
/// block mined after the copy the producer runs over (six blocks on, past
/// the reference's minimum age), so the older parent refuses it, and
/// evicting it would drop an entry valid where it was judged. Red edit:
/// drop the producer's check of the pool's judged tip.
#[tokio::test]
async fn a_template_on_an_older_tip_than_the_pools_posts_and_evicts_nothing() {
    use crate::template::{produce, NoTemplate, Producer};
    let (mut scenario, mined) = matured("older-tip").await;
    let copy = tmp("older-tip-copy");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &copy).expect("a copy of the chain");
        })
        .await;
    let newer = scenario.mine(6).await;
    let connecting = h(newer.last().expect("six").height.to_raw() + 1);
    let all: Vec<Mined> = mined.iter().chain(&newer).cloned().collect();
    let paid =
        crate::pool_door_tests::paying_the_floor_at(&mut scenario, &all, 0, connecting).await;
    let txid = paid.txid_parts().hash;
    let path = tmp("older-tip-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    scenario
        .read_chain(|view, rule_set| {
            assert_eq!(
                pool.admit(
                    paid,
                    UnixSeconds::from_raw(1),
                    view,
                    rule_set,
                    &AdmissionPolicy::GENESIS,
                )
                .expect("no fault"),
                Admission::Admitted {
                    evicted: Vec::new()
                }
            );
            assert!(pool.fluffed(&txid).expect("publish"));
        })
        .await;
    let older = crate::test_support::open_store_under(
        &copy,
        &crate::scenario::RULES.in_force(h(0)),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    );
    let keys = crate::test_support::harness_keys();
    let params = shekyl_economics::EconomicParams::default();
    let pool = std::sync::Mutex::new(pool);
    let produced = {
        let snap = older.begin_read().expect("a snapshot");
        let facts = crate::connector::chain_facts_on(&snap).expect("the facts");
        let now = facts
            .median_timestamp
            .map_or(crate::scenario::CLOCK_START, |median| {
                shekyl_types::Timestamp::from_raw(median.to_raw() + 1)
            });
        let producer = Producer {
            rules: crate::scenario::RULES,
            keys: &keys,
            params: &params,
            now,
        };
        produce(&snap, &producer, Some(&pool), |_| true).map(|produced| produced.evicted)
    };
    let held = pool
        .lock()
        .expect("the pool")
        .listing()
        .any(|(id, _)| id == txid);
    drop(pool);
    drop(older);
    drop(std::fs::remove_file(&path));
    crate::test_support::cleanup(&copy);
    scenario.close().await;
    assert!(
        matches!(produced, Err(NoTemplate::PoolOnAnotherTip)),
        "no template on another tip: {produced:?}"
    );
    assert!(held, "the entry judged at the newer tip is still held");
}

/// `pop_blocks` (DX-Q3, Q7) through the service: a count that would pop
/// genesis is refused before any pop; a count of two pops both blocks and
/// returns both their transactions to the pool through its door, as a
/// switch's demoted bodies are; and the writer is up after either, so the
/// same two blocks connect again.
#[tokio::test(flavor = "multi_thread")]
async fn pop_blocks_refuses_genesis_and_returns_two_blocks_bodies_to_the_pool() {
    use crate::connector::Rewound;
    use crate::service::{Arrival, ArrivalTag, Follow, Origin, PoolWiring, Reply, Service};
    use shekyl_types::BlockHeight;
    use std::sync::Arc;
    let (mut scenario, mined) = matured("pop-blocks").await;
    let first = paying_the_floor(&mut scenario, &mined, 0).await;
    let second = paying_the_floor(&mut scenario, &mined, 1).await;
    let a = scenario
        .mine_listing(vec![first.clone()])
        .await
        .unwrap_or_else(|o| panic!("the first spend lands: {o}"));
    let b = scenario
        .mine_listing(vec![second.clone()])
        .await
        .unwrap_or_else(|o| panic!("the second spend lands: {o}"));
    let copy = tmp("pop-blocks-service");
    scenario
        .reopen(|path| {
            std::fs::copy(path, &copy).expect("a copy of the chain");
        })
        .await;
    let store = Arc::new(crate::test_support::open_store_under(
        &copy,
        &crate::scenario::RULES.in_force(BlockHeight::ZERO),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    ));
    let pool_path = tmp("pop-blocks-pool");
    let pool = {
        let snap = store.begin_read().expect("a snapshot");
        let view = shekyl_chain_store::store::SnapshotView::new(&snap);
        let tip = HeaderView::tip(&view).expect("tip");
        let rule_set = crate::scenario::RULES.in_force(Tip::connecting_height(tip.as_ref()));
        Pool::open(
            &pool_path,
            UnixSeconds::from_raw(1),
            &view,
            &rule_set,
            &AdmissionPolicy::GENESIS,
        )
        .expect("open")
        .0
    };
    let pool = Arc::new(std::sync::Mutex::new(pool));
    let service = Service::start(
        Arc::clone(&store),
        crate::scenario::RULES,
        // A clock ahead of the scenario's blocks, so they connect again.
        Arc::new(crate::service::service_tests::Gated::new()),
        crate::service::ServiceConfig::default(),
        shekyl_hash_budget::Budget::of_host(),
        Follow {
            job: None,
            pool: Some(PoolWiring {
                pool: Arc::clone(&pool),
                policy: AdmissionPolicy::GENESIS,
                wall: Arc::new(|| UnixSeconds::from_raw(1)),
            }),
        },
    );
    let rewinder = service.rewinder();
    let tip = b.height;
    let refused = rewinder
        .pop_blocks(tip.to_raw() + 1)
        .await
        .expect("a reply, not a fault");
    assert_eq!(
        refused,
        Rewound::Refused {
            tip,
            floor: BlockHeight::from_raw(1),
        },
        "popping genesis is refused before any pop"
    );
    let popped = rewinder.pop_blocks(2).await.expect("it pops");
    let Rewound::Popped { popped, bodies, .. } = popped else {
        panic!("two blocks pop: {popped:?}");
    };
    assert_eq!(popped, 2);
    let returned: Vec<_> = bodies.iter().map(|tx| tx.txid_parts().hash).collect();
    let ids = [first.txid_parts().hash, second.txid_parts().hash];
    assert_eq!(returned, ids, "both bodies, lowest block first");
    {
        let pool = pool.lock().expect("the pool");
        for id in &ids {
            assert!(
                pool.relay_view().record(id).is_some(),
                "{id:?} is back in the pool"
            );
        }
    }
    for (tag, block) in [(1, &a), (2, &b)] {
        let reply = service
            .door()
            .offer(Arrival {
                tag: ArrivalTag(tag),
                origin: Origin::Local,
                block: block.template.block.serialize(),
                bodies: block
                    .template
                    .transactions
                    .iter()
                    .map(shekyl_wire::Transaction::serialize)
                    .collect(),
            })
            .expect("room")
            .reply()
            .await
            .reply;
        assert!(matches!(reply, Reply::Connected { .. }), "{reply:?}");
    }
    service.stop().await.expect("stops");
    drop(std::fs::remove_file(&pool_path));
    crate::test_support::cleanup(&copy);
    scenario.close().await;
}

fn fee_of(tx: &shekyl_wire::Transaction) -> u64 {
    match &tx.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => 0,
    }
}

/// Template selection (b6) as a pure function of the pool and the parent:
/// most fee per weight first, a candidate too heavy for what is left
/// skipped; each candidate judged again by `tx_against` against the
/// parent, so an admitted entry whose image the chain spent since it was
/// admitted is not selected, and CEN-M10 evicts it from the template's
/// refusals.
#[tokio::test]
async fn the_template_rejudges_against_its_parent_and_m10_evicts_what_it_refuses() {
    let (mut scenario, mined) = matured("pool-template").await;
    let first = paying_the_floor(&mut scenario, &mined, 0).await;
    let second = paying_the_floor(&mut scenario, &mined, 1).await;
    let dear = {
        let floor = fee_of(&second);
        Spender::over(&mined).spend_coinbase(scenario.wallet(), h(2), h(AT), floor * 10)
    };
    let (id1, id2, id3) = (
        first.txid_parts().hash,
        second.txid_parts().hash,
        dear.txid_parts().hash,
    );
    let path = tmp("pool-template-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let (ordered, budgeted) = scenario
        .read_chain(|view, rule_set| {
            for tx in [first.clone(), second.clone(), dear.clone()] {
                let txid = tx.txid_parts().hash;
                assert_eq!(
                    pool.admit(
                        tx,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault"),
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
                assert!(pool.fluffed(&txid).expect("publish"));
            }
            let all = shekyl_mempool::select(&pool, view, rule_set, u64::MAX).expect("template");
            let weight = pool
                .listing()
                .find(|(txid, _)| *txid == id3)
                .expect("shown")
                .1
                .weight;
            let one = shekyl_mempool::select(&pool, view, rule_set, weight).expect("template");
            (all, one)
        })
        .await;
    assert_eq!(
        ordered.transactions[0].id, id3,
        "the dearest per weight first"
    );
    assert_eq!(ordered.transactions.len(), 3);
    assert_eq!(
        budgeted
            .transactions
            .iter()
            .map(|body| body.id)
            .collect::<Vec<_>>(),
        vec![id3],
        "the budget holds only the first"
    );

    // Another body over `first`'s image connects; the pool is not told.
    let twin = Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(AT),
        fee_of(&first) + 1_000,
    );
    let _connected = scenario
        .mine_listing(vec![twin])
        .await
        .unwrap_or_else(|o| panic!("the twin connects: {o}"));
    let template = scenario
        .read_chain(|view, rule_set| {
            shekyl_mempool::select(&pool, view, rule_set, u64::MAX).expect("template")
        })
        .await;
    assert_eq!(
        template
            .transactions
            .iter()
            .map(|body| body.id)
            .collect::<Vec<_>>(),
        vec![id3, id2],
        "the spent one is not selected"
    );
    assert_eq!(template.refused.len(), 1);
    assert_eq!(template.refused[0].0, id1);
    assert_eq!(
        template.refused[0].1.rule,
        CenRow::I7,
        "judged against the parent"
    );
    let refused: Vec<_> = template.refused.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        pool.evict(&refused, &[]).expect("evict"),
        vec![(id1, Evicted::Refused)]
    );
    assert!(pool.relay_view().record(&id2).is_some() && pool.relay_view().record(&id3).is_some());
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// CEN-M10 at admission (the review of #1102, B3), over real spends: with
/// room for one, a spend paying more per weight than the held one evicts it
/// in the same write as its own insert, and a spend paying less is refused
/// as `PoolFull` before the door runs. The pool file agrees.
#[tokio::test]
async fn a_full_pool_admits_a_better_payer_by_evicting_the_cheapest() {
    let (mut scenario, mined) = matured("pool-full").await;
    let low = paying_the_floor(&mut scenario, &mined, 0).await;
    let fee = fee_of(&low);
    let (high, lower) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(1), h(AT), fee * 4),
            spender.spend_coinbase(wallet, h(2), h(AT), fee * 2),
        )
    };
    let (low_id, high_id) = (low.txid_parts().hash, high.txid_parts().hash);
    let room = [&low, &high, &lower]
        .iter()
        .map(|tx| u64::try_from(tx.weight()).expect("fits"))
        .max()
        .expect("three");
    let path = tmp("pool-full-pool");
    let (first, second, third, held) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let now = UnixSeconds::from_raw(1);
            let (mut pool, _, _) = Pool::open(&path, now, view, rule_set, &policy).expect("open");
            pool.set_limits(Limits { max_weight: room });
            let mut admit = |tx: &shekyl_wire::Transaction| {
                pool.admit(tx.clone(), now, view, rule_set, &policy)
                    .expect("no fault")
            };
            let first = admit(&low);
            let second = admit(&high);
            let third = admit(&lower);
            let held: Vec<_> = pool.listing().map(|(txid, _)| txid).collect();
            (first, second, third, held)
        })
        .await;
    assert_eq!(
        first,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    assert_eq!(
        second,
        Admission::Admitted {
            evicted: vec![low_id]
        },
        "the cheaper entry left to make room"
    );
    assert_eq!(third, Admission::PoolFull, "the rising minimum");
    assert_eq!(
        held,
        Vec::<shekyl_types::TxHash>::new(),
        "nothing is fluffed"
    );
    let (store, _) = PoolStore::create(&path).expect("the file");
    let filed: Vec<_> = store.begin_read().expect("read").txids().expect("txids");
    assert_eq!(
        filed,
        vec![high_id],
        "the eviction and the insert were one write"
    );
    drop(store);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// An admitted entry has no timer (B3): once the chain has moved past
/// CEN-I11's window from its reference, the reconcile removes it on that
/// refusal.
#[tokio::test]
async fn an_admitted_entry_leaves_when_its_reference_leaves_the_window() {
    let (mut scenario, mined) = matured("pool-window").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-window-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let admitted = scenario
        .read_chain(|view, rule_set| {
            pool.admit(
                spend,
                UnixSeconds::from_raw(1),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("no fault")
        })
        .await;
    assert_eq!(
        admitted,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    scenario
        .mine(shekyl_chain_rules::REFERENCE_BLOCK_MAX_AGE.to_raw())
        .await;
    let reconciled = scenario
        .read_chain(|view, rule_set| {
            pool.reconcile(view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("reconcile")
        })
        .await;
    match reconciled.removed.as_slice() {
        [(id, shekyl_mempool::Removed::Refused(Judged::Chain(refused)))] => {
            assert_eq!(*id, txid);
            assert_eq!(refused.rule, CenRow::I11, "the reference aged out");
        }
        other => panic!("removed on CEN-I11: {other:?}"),
    }
    assert!(pool.relay_view().is_empty());
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The bytes are judged once per process (the review of #1102, S1): a
/// block connecting under a pool of admitted spends, and the reconcile that
/// follows it, verify no signature, no range proof and no FCMP++ proof
/// again — only the view-bound half and the policy run. Counted by the
/// validator's own probes.
#[tokio::test]
async fn a_connect_under_the_pool_verifies_nothing_again() {
    let (mut scenario, mined) = matured("pool-once").await;
    let a = paying_the_floor(&mut scenario, &mined, 0).await;
    let b = paying_the_floor(&mut scenario, &mined, 1).await;
    let path = tmp("pool-once-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    scenario
        .read_chain(|view, rule_set| {
            for tx in [a.clone(), b.clone()] {
                let admitted = pool
                    .admit(
                        tx,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault");
                assert_eq!(
                    admitted,
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
            }
        })
        .await;
    scenario.mine(1).await;
    let (counts, reconciled) = scenario
        .read_chain(|view, rule_set| {
            let count = || {
                (
                    probes::signature_verifies(),
                    probes::range_proof_verifies(),
                    probes::fcmp_verifies(),
                )
            };
            let before = count();
            let reconciled = pool
                .reconcile(view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("reconcile");
            let after = count();
            (
                (after.0 - before.0, after.1 - before.1, after.2 - before.2),
                reconciled,
            )
        })
        .await;
    assert_eq!(reconciled.admitted.len(), 2, "both still admitted");
    assert_eq!(counts, (0, 0, 0), "signatures, range proofs, FCMP++ proofs");
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The follower lists, under the pool lock, every entry whose pass no
/// longer holds, and runs step 1 for it outside the lock. Staged, the
/// reconcile verifies nothing while it holds the pool. A pass that holds
/// is not listed. The rule set is what moves here; a reorg that moves an
/// entry's reference fails the same comparison (`holds_under`).
#[tokio::test]
async fn a_pass_that_no_longer_holds_is_verified_outside_the_pool_lock() {
    let (mut scenario, mined) = matured("pool-needing").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-needing-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let (held, listed, under_lock) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let now = UnixSeconds::from_raw(1);
            pool.admit(spend.clone(), now, view, rule_set, &policy)
                .expect("no fault");
            let held = pool.needing_step1(view, rule_set).expect("reads").len();
            let other = shekyl_chain_rules::RuleSet::fakechain(
                Some(std::num::NonZeroU128::new(7).expect("non-zero")),
                shekyl_chain_rules::FakechainSchedule::PRODUCTION,
            );
            assert_ne!(other, *rule_set, "fixture");
            let listed: Vec<_> = pool
                .needing_step1(view, &other)
                .expect("reads")
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            // Outside the lock: step 1 for what was listed, then staged.
            let step1 = shekyl_mempool::stateless(&spend, view, &other, None).expect("judged");
            pool.stage_step1(txid, step1);
            let before = probes::fcmp_verifies();
            let reconciled = pool.reconcile(view, &other, &policy).expect("reconcile");
            assert_eq!(reconciled.admitted, vec![txid]);
            (held, listed, probes::fcmp_verifies() - before)
        })
        .await;
    assert_eq!(held, 0, "a pass that holds is not listed");
    assert_eq!(listed, vec![txid], "a pass that no longer holds is listed");
    assert_eq!(under_lock, 0, "staged: no proof verified under the lock");
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}
