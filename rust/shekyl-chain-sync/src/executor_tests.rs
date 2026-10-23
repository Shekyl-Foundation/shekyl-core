// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor's cache plans and its budget class, over real RandomX.

use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use shekyl_chain_ingest::{Metrics, ProductionSubstrate};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{target_claim, FormAttempt, HeaderView};
use shekyl_hash_budget::{Budget, Class};
use shekyl_pow_randomx::{CacheStore, Seedhash};
use shekyl_types::{BlockCount, BlockHash};

use super::Executor;
use crate::model::{CachePlan, HashClass, ProveItem, Proved};
use crate::proof::fixed;

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
    executor: Executor,
    caches: Arc<CacheStore>,
    metrics: Arc<Metrics>,
}

fn rig(budget: Budget) -> Rig {
    let caches = Arc::new(CacheStore::new());
    let metrics = Arc::new(Metrics::new());
    let substrate = ProductionSubstrate::new(Arc::clone(&caches), Arc::clone(&metrics));
    Rig {
        executor: Executor::new(budget, substrate, Arc::new(AtomicBool::new(false))),
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
#[test]
fn a_main_seed_not_held_answers_not_held_and_never_derives() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let results = rig.executor.run(
        HashClass::HeaderPow,
        CachePlan::Main(seed(1)),
        &[item(seed(1)), item(seed(1))],
    );
    assert!(
        matches!(results.as_slice(), [Proved::NotHeld]),
        "{results:?}"
    );
    let metrics = rig.metrics.snapshot();
    assert_eq!((metrics.hashes, metrics.cache_derives), (0, 0));
    assert!(!held(&rig.caches, seed(1)));
}

/// A branch seed is derived once and kept for the next job on that seed,
/// replaced when the seed changes, and never put in the store's slots.
#[test]
fn a_branch_cache_is_derived_once_per_seed_and_never_enters_the_store() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let first = rig.executor.run(
        HashClass::HeaderPow,
        CachePlan::Branch(seed(2)),
        &[item(seed(2)), item(seed(2))],
    );
    assert!(
        first
            .iter()
            .all(|proved| matches!(proved, Proved::Formed(_)))
            && first.len() == 2,
        "{first:?}"
    );
    let again = rig.executor.run(
        HashClass::HeaderPow,
        CachePlan::Branch(seed(2)),
        &[item(seed(2))],
    );
    assert!(matches!(again.as_slice(), [Proved::Formed(_)]));
    assert_eq!(
        rig.metrics.snapshot().cache_derives,
        1,
        "one derive per seed"
    );
    assert_eq!(rig.executor.branch_seed(), Some(seed(2)));
    let other = rig.executor.run(
        HashClass::HeaderPow,
        CachePlan::Branch(seed(3)),
        &[item(seed(3))],
    );
    assert!(matches!(other.as_slice(), [Proved::Formed(_)]));
    let metrics = rig.metrics.snapshot();
    assert_eq!((metrics.hashes, metrics.cache_derives), (4, 2));
    assert_eq!(rig.executor.branch_seed(), Some(seed(3)));
    assert!(!held(&rig.caches, seed(2)) && !held(&rig.caches, seed(3)));
}

/// On a budget of two with a miner holding one permit, the evidence job
/// takes the other: the class sits above the miner's, and needs one free.
/// Its cache is the job's own.
#[test]
fn an_evidence_job_runs_beside_a_miner_on_a_budget_of_two() {
    let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
    let mining = budget.acquire(Class::Miner);
    let rig = rig(budget.clone());
    let results = rig.executor.run(
        HashClass::Evidence,
        CachePlan::Evidence(seed(4)),
        &[item(seed(4)), item(seed(4))],
    );
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
