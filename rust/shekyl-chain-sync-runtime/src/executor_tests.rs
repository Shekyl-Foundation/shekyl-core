// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor's cache plans and its budget class, over real RandomX.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_chain_ingest::{Metrics, ProductionSubstrate};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    target_claim, FakechainSchedule, FormAttempt, HeaderView, RuleSet, SettlementEpochBlocks,
};
use shekyl_hash_budget::{Budget, Class};
use shekyl_pow_randomx::{CacheStore, Seedhash};
use shekyl_types::{BlockCount, BlockHash};

use super::{prove, Executor};
use shekyl_chain_sync::{CachePlan, HashClass, ProveItem, Proved};

/// A fakechain rule set at a fixed `target` with a reorg cap of `blocks`.
fn fixed(target: u128, blocks: u64) -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        FakechainSchedule::new(epoch, BlockCount::from_raw(blocks)).expect("cap inside the epoch");
    RuleSet::fakechain(core::num::NonZeroU128::new(target), schedule)
}

/// One header at a fixed target of 1, so any hash passes, claimed under
/// `seed`.
fn item(seed: BlockHash) -> ProveItem {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let block = candidate_on(&main, Vec::new()).block;
    main.with_view(|view| {
        let tip = view.tip().expect("answers").expect("a tip");
        let target = target_claim(&view, tip.height + BlockCount::ONE, &rules)
            .expect("answers")
            .expect("claimed");
        ProveItem {
            pow: block.pow_blob(),
            seed,
            target,
            attempt: FormAttempt::FIRST,
            rule_set: rules,
        }
    })
}

struct Rig {
    executor: Arc<Executor>,
    caches: Arc<CacheStore>,
    metrics: Arc<Metrics>,
}

fn rig(budget: Budget) -> Rig {
    let caches = Arc::new(CacheStore::new());
    let metrics = Arc::new(Metrics::new());
    let substrate = ProductionSubstrate::new(Arc::clone(&caches), Arc::clone(&metrics));
    Rig {
        executor: Arc::new(Executor::new(budget, substrate)),
        caches,
        metrics,
    }
}

fn seed(byte: u8) -> BlockHash {
    BlockHash::from_bytes([byte; 32])
}

fn held(caches: &CacheStore, seed: BlockHash) -> bool {
    caches
        .lookup(&Seedhash::from_bytes(*seed.as_bytes()))
        .is_some()
}

/// A main seed the slots do not hold is `NotHeld`, and nothing is hashed
/// or derived for it.
#[tokio::test(flavor = "multi_thread")]
async fn a_main_seed_not_held_answers_not_held_and_never_derives() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Main(seed(1)),
        vec![item(seed(1)), item(seed(1))],
    )
    .await;
    assert!(
        matches!(results.as_slice(), [Proved::NotHeld]),
        "{results:?}"
    );
    let metrics = rig.metrics.snapshot();
    assert_eq!((metrics.hashes, metrics.cache_derives), (0, 0));
    assert!(!held(&rig.caches, seed(1)));
}

/// Stopping the executor ends a job parked on a full budget: the stop
/// wakes the budget, so the wait sees the flag now, not when a permit
/// frees. The job answers nothing for the item it did not prove.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_ends_a_job_waiting_on_a_full_budget() {
    let budget = Budget::new(NonZeroUsize::MIN);
    let busy = budget.acquire(Class::HeaderPow);
    let rig = rig(budget.clone());
    let job = tokio::spawn(prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Main(seed(1)),
        vec![item(seed(1))],
    ));
    let parked = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while budget.waiting(Class::HeaderPow) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(parked.is_ok(), "the job never waited for a permit");
    rig.executor.stop();
    let answered = tokio::time::timeout(std::time::Duration::from_secs(5), job).await;
    drop(busy);
    let results = answered
        .expect("the stop woke the waiting job")
        .expect("joined");
    assert!(results.is_empty(), "{results:?}");
}

/// A branch seed is derived once and kept for the next job on that seed,
/// replaced when the seed changes, and never put in the store's slots.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_cache_is_derived_once_per_seed_and_never_enters_the_store() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let first = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Branch(seed(2)),
        vec![item(seed(2)), item(seed(2))],
    )
    .await;
    assert!(
        first
            .iter()
            .all(|proved| matches!(proved, Proved::Formed(_)))
            && first.len() == 2,
        "{first:?}"
    );
    let again = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Branch(seed(2)),
        vec![item(seed(2))],
    )
    .await;
    assert!(matches!(again.as_slice(), [Proved::Formed(_)]));
    assert_eq!(
        rig.metrics.snapshot().cache_derives,
        1,
        "one derive per seed"
    );
    assert_eq!(rig.executor.branch_seed(), Some(seed(2)));
    let other = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Branch(seed(3)),
        vec![item(seed(3))],
    )
    .await;
    assert!(matches!(other.as_slice(), [Proved::Formed(_)]));
    let metrics = rig.metrics.snapshot();
    assert_eq!((metrics.hashes, metrics.cache_derives), (4, 2));
    assert_eq!(rig.executor.branch_seed(), Some(seed(3)));
    assert!(!held(&rig.caches, seed(2)) && !held(&rig.caches, seed(3)));
}

/// On a budget of two with a miner holding one permit, the evidence job
/// takes the other: the class sits above the miner's, and needs one free.
/// Its cache is the job's own.
#[tokio::test(flavor = "multi_thread")]
async fn an_evidence_job_runs_beside_a_miner_on_a_budget_of_two() {
    let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
    let mining = budget.acquire(Class::Miner);
    let rig = rig(budget.clone());
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::Evidence,
        CachePlan::Evidence(seed(4)),
        vec![item(seed(4)), item(seed(4))],
    )
    .await;
    assert!(
        results
            .iter()
            .all(|proved| matches!(proved, Proved::Formed(_)))
            && results.len() == 2,
        "{results:?}"
    );
    assert_eq!(rig.metrics.snapshot().cache_derives, 1);
    assert!(!held(&rig.caches, seed(4)));
    assert_eq!(
        rig.executor.branch_seed(),
        None,
        "evidence is not the branch"
    );
    drop(mining);
}

/// A job's items are spread across the permits and answered in item order;
/// the answer ends at the first item that is not formed.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_answers_in_item_order_and_ends_at_its_first_refusal() {
    let rig = rig(Budget::new(NonZeroUsize::new(2).expect("two")));
    let mut broken = item(seed(5));
    broken.pow = vec![0xFF; 3];
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        CachePlan::Branch(seed(5)),
        vec![
            item(seed(5)),
            item(seed(5)),
            broken,
            item(seed(5)),
            item(seed(5)),
        ],
    )
    .await;
    assert!(
        matches!(
            results.as_slice(),
            [Proved::Formed(_), Proved::Formed(_), Proved::Refused(_)]
        ),
        "{results:?}"
    );
    assert!(
        rig.metrics.snapshot().hashes <= 4,
        "nothing past the refusal is awaited"
    );
}
