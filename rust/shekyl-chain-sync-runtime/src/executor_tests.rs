// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The executor's jobs on a real hasher, over real RandomX: what a job
//! borrows, what stays resident after it, and who waits for whom.
//!
//! Each test starts a hasher of its own. `quiet` waits for the hasher to
//! settle and returns what is resident then: a cache nothing lists, holds
//! or waits for has been freed, and each listed seed's cache is built.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use shekyl_chain_ingest::pow::Pow;
use shekyl_chain_ingest::{Metrics, ProductionPow};
use shekyl_chain_rules::harness::fixture::{candidate_on, chain_of};
use shekyl_chain_rules::{
    target_claim, CappedEpoch, FormAttempt, HeaderView, RuleSet, SettlementEpochBlocks,
};
use shekyl_hash_budget::Budget;
use shekyl_hasher::{Class, Hasher, Owner, Ranked, Residency};
use shekyl_pow_randomx::Seedhash;
use shekyl_types::{BlockCount, BlockHash};

use super::{prove, Executor};
use shekyl_chain_sync::{HashClass, ProveItem, Proved};

/// A fakechain rule set at a fixed `target` with a reorg cap of `blocks`.
fn fixed(target: u128, blocks: u64) -> RuleSet {
    let epoch = SettlementEpochBlocks::new(512).expect("512");
    let schedule =
        CappedEpoch::new(epoch, BlockCount::from_raw(blocks)).expect("cap inside the epoch");
    RuleSet::GENESIS.with_levers(core::num::NonZeroU128::new(target), schedule)
}

/// One header at a fixed target of 1, so any hash passes, claimed under
/// `seed`.
fn item(seed: BlockHash) -> ProveItem {
    let rules = fixed(1, 64);
    let main = chain_of(8);
    let block = candidate_on(&main, Vec::new()).block;
    main.with_view(|view| {
        let tip = view.tip().expect("answers").expect("a tip");
        let target = target_claim(&view, tip.height + BlockCount::ONE, &rules).expect("answers");
        ProveItem {
            pow: block.pow_blob(),
            seed,
            target,
            attempt: FormAttempt::FIRST,
            rule_set: rules,
        }
    })
}

/// An executor over a hasher of its own. The owner is last: it stops the
/// hasher when the rig drops, after every job has ended.
struct Rig {
    executor: Arc<Executor>,
    pow: ProductionPow,
    hasher: Hasher,
    metrics: Arc<Metrics>,
    _owner: Owner,
}

fn rig(budget: Budget) -> Rig {
    let (hasher, owner) = Hasher::start(budget).expect("the builder thread starts");
    let metrics = Arc::new(Metrics::new());
    let pow = ProductionPow::new(hasher.clone(), Arc::clone(&metrics));
    Rig {
        executor: Arc::new(Executor::new(pow.clone())),
        pow,
        hasher,
        metrics,
        _owner: owner,
    }
}

fn seed(byte: u8) -> BlockHash {
    BlockHash::from_bytes([byte; 32])
}

fn as_seed(seed: BlockHash) -> Seedhash {
    Seedhash::from_bytes(*seed.as_bytes())
}

fn all_formed(results: &[Proved], count: usize) -> bool {
    results.len() == count
        && results
            .iter()
            .all(|proved| matches!(proved, Proved::Formed(_)))
}

impl Rig {
    /// The list: `window` seeds, canonical first, then the third.
    fn rank(&self, window: &[u8], third: Option<u8>) {
        self.hasher.rank(
            Ranked::new(
                as_seed(seed(window[0])),
                window.get(1).map(|other| as_seed(seed(*other))),
                third.map(|third| (as_seed(seed(third)), Class::HeaderPow)),
            )
            .expect("distinct seeds"),
        );
    }

    fn builds(&self) -> u64 {
        self.hasher.resident().borrow().builds
    }

    /// Wait until every resident cache is warm and they are exactly
    /// `expected`, which is what the hasher is quiet on. Panics with what
    /// is resident when that does not happen within a minute.
    fn quiet_on(&self, expected: &[u8]) {
        let expected: BTreeSet<[u8; 32]> = expected.iter().map(|byte| [*byte; 32]).collect();
        let resident = self.hasher.resident();
        let started = Instant::now();
        loop {
            let now = resident.borrow().clone();
            let warm: BTreeSet<[u8; 32]> = now
                .caches
                .iter()
                .filter(|(_, state)| *state == Residency::Warm)
                .map(|(seed, _)| *seed.as_bytes())
                .collect();
            if warm == expected && now.caches.len() == expected.len() {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the hasher never went quiet on {expected:?}: {now:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A job gets its cache whether or not anything ranks its seed (HA-R1),
/// and a cache nothing ranks is freed when its job ends: a header run that
/// ends leaves nothing behind (`RANDOMX_CACHE_ACTOR.md` §8, HA-F1).
///
/// Red edit: in `shekyl-hasher`'s refill, keep an unlisted idle entry
/// (skip `settle_once`'s first step): the cache stays resident.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_gets_its_cache_and_an_unranked_one_is_freed_after_it() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        seed(1),
        vec![item(seed(1)), item(seed(1))],
    )
    .await;
    assert!(all_formed(&results, 2), "{results:?}");
    let artifact = rig.executor.artifact();
    assert_eq!((artifact.hashes, artifact.cache_derives), (2, 1));
    rig.quiet_on(&[]);
}

/// Stopping the executor ends a job parked on a full budget: the stop
/// wakes the hasher, so the wait sees the flag now, not when a permit
/// frees. The job answers nothing for the item it did not prove.
///
/// The one permit is held, so the job's cache cannot be built and the job
/// waits for it. Red edit: drop `self.pow.wake()` from `Executor::stop`:
/// the job stays parked until the permit is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_ends_a_job_waiting_on_a_full_budget() {
    let budget = Budget::new(NonZeroUsize::MIN);
    let busy = budget.acquire(Class::Chain);
    let rig = rig(budget.clone());
    let job = tokio::spawn(prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        seed(1),
        vec![item(seed(1))],
    ));
    let parked = tokio::time::timeout(Duration::from_secs(10), async {
        while budget.waiting(Class::HeaderPow) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        parked.is_ok(),
        "the job's build never waited for a permit in the job's class"
    );
    rig.executor.stop();
    let answered = tokio::time::timeout(Duration::from_secs(5), job).await;
    drop(busy);
    let results = answered
        .expect("the stop woke the waiting job")
        .expect("joined");
    assert!(results.is_empty(), "{results:?}");
}

/// A seed on the ranked list is built once and serves every job on it, and
/// when the list stops naming it its cache is freed. This is the header
/// frontier's life: the owner publishes it while a run proves, and takes
/// it back when the run ends (HA-F1).
///
/// Red edit: drop the second `rank` below: seed 2 stays resident.
#[tokio::test(flavor = "multi_thread")]
async fn a_ranked_seed_is_built_once_across_jobs_and_freed_when_the_list_drops_it() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    rig.rank(&[9], Some(2));
    for count in [2, 1] {
        let results = prove(
            Arc::clone(&rig.executor),
            HashClass::HeaderPow,
            seed(2),
            vec![item(seed(2)); count],
        )
        .await;
        assert!(all_formed(&results, count), "{results:?}");
    }
    rig.quiet_on(&[9, 2]);
    assert_eq!(rig.builds(), 2, "one build per seed, two jobs on seed 2");
    rig.rank(&[9], None);
    rig.quiet_on(&[9]);
    assert_eq!(rig.builds(), 2, "and nothing was rebuilt");
}

/// On a budget of two with a miner holding one permit, the evidence job
/// takes the other: the class sits above the miner's, and needs one free.
/// Its cache is the job's own, freed when the job ends (HA-R3).
#[tokio::test(flavor = "multi_thread")]
async fn an_evidence_job_runs_beside_a_miner_on_a_budget_of_two() {
    let budget = Budget::new(NonZeroUsize::new(2).expect("two"));
    let mining = budget.acquire(Class::Miner);
    let rig = rig(budget.clone());
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::Evidence,
        seed(4),
        vec![item(seed(4)), item(seed(4))],
    )
    .await;
    assert!(all_formed(&results, 2), "{results:?}");
    assert_eq!(rig.builds(), 1);
    rig.quiet_on(&[]);
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
        seed(5),
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
        rig.metrics.snapshot(rig.pow.derives()).hashes <= 4,
        "nothing past the refusal is taken"
    );
}

/// An item that names a seed other than its job's is not judged, and it
/// ends the answer: a defect in the model's batching, never a verdict on
/// the header.
///
/// Red edit: in `prove_one`, answer `SeedNotLent` as
/// `Proved::Refused(...)`: the session would be closed for our defect.
#[tokio::test(flavor = "multi_thread")]
async fn an_item_under_another_seed_is_not_judged() {
    let rig = rig(Budget::new(NonZeroUsize::MIN));
    let results = prove(
        Arc::clone(&rig.executor),
        HashClass::HeaderPow,
        seed(6),
        vec![item(seed(6)), item(seed(7)), item(seed(6))],
    )
    .await;
    assert!(
        matches!(results.as_slice(), [Proved::Formed(_)]),
        "the answer ends before the item that could not be judged: {results:?}"
    );
    assert_eq!(rig.builds(), 1, "and nothing was built for the other seed");
}

/// `RANDOMX_CACHE_ACTOR.md` §8, HA-R3: an evidence check while the third
/// cache is warm. The window names two seeds and the third is warm, so
/// all three places are in use. The check runs: the warm third is freed
/// for it, the check's cache is freed when it ends, and the third is back
/// at quiescence. Five builds: the three listed, the check's, and the
/// third again.
///
/// Red edit: in the hasher's core, let the third keep its place while a
/// job queues (`warm third is freed for a job`): the check waits for ever
/// and this test times out.
#[tokio::test(flavor = "multi_thread")]
async fn an_evidence_check_takes_the_warm_thirds_place_and_the_third_comes_back() {
    let rig = rig(Budget::of_host());
    rig.rank(&[1, 2], Some(3));
    rig.quiet_on(&[1, 2, 3]);
    assert_eq!(rig.builds(), 3);
    let results = tokio::time::timeout(
        Duration::from_secs(60),
        prove(
            Arc::clone(&rig.executor),
            HashClass::Evidence,
            seed(4),
            vec![item(seed(4)), item(seed(4))],
        ),
    )
    .await
    .expect("the evidence check runs while the third is warm");
    assert!(all_formed(&results, 2), "{results:?}");
    rig.quiet_on(&[1, 2, 3]);
    assert_eq!(
        rig.builds(),
        5,
        "the check's cache, then the third's refill: neither window seed was rebuilt"
    );
}

/// `RANDOMX_CACHE_ACTOR.md` §8, HA-R8: an evidence check queued behind a
/// stream of header-proof jobs for another seed runs after the one job
/// ahead of it, not after the stream.
///
/// The window names two seeds, so jobs outside it share one place. A job
/// on seed 3 holds that place. The evidence check on seed 4 queues for it,
/// then three more jobs on seed 3 are asked for. When the first job ends,
/// the check is granted next, although seed 3's cache is the one resident.
///
/// Red edit: in the hasher's core, let a job whose seed is resident join
/// it while the queue is not empty: the three later jobs pass the check.
#[tokio::test(flavor = "multi_thread")]
async fn an_evidence_check_runs_after_the_one_job_ahead_of_it_not_the_stream() {
    static RUNNING: AtomicBool = AtomicBool::new(false);
    let rig = rig(Budget::of_host());
    rig.rank(&[1, 2], None);
    rig.quiet_on(&[1, 2]);
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let (hold, held) = std::sync::mpsc::channel::<()>();
    let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
    // The job ahead: on seed 3, holding the one outside place until told.
    let first = {
        let (pow, order) = (rig.pow.clone(), Arc::clone(&order));
        std::thread::spawn(move || {
            pow.lend(Class::HeaderPow, seed(3), &RUNNING, |_job| {
                order.lock().expect("order").push("first header job");
                entered_tx.send(()).expect("the test waits");
                held.recv().expect("the test releases the job");
            })
        })
    };
    entered
        .recv_timeout(Duration::from_secs(60))
        .expect("the first job is granted");
    // The evidence check queues for the place the first job holds.
    let check = {
        let (executor, order) = (Arc::clone(&rig.executor), Arc::clone(&order));
        tokio::spawn(async move {
            let results = prove(executor, HashClass::Evidence, seed(4), vec![item(seed(4))]).await;
            order.lock().expect("order").push("evidence check");
            results
        })
    };
    // It is queued once the hasher has reserved nothing new and the check
    // has not answered: give its request time to reach the queue.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!check.is_finished(), "the check waits for the place");
    // The stream behind it: three more jobs on the resident seed.
    let stream: Vec<_> = (0..3)
        .map(|_| {
            let (pow, order) = (rig.pow.clone(), Arc::clone(&order));
            std::thread::spawn(move || {
                pow.lend(Class::HeaderPow, seed(3), &RUNNING, |_job| {
                    order.lock().expect("order").push("stream header job");
                })
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        *order.lock().expect("order"),
        vec!["first header job"],
        "nothing passes the first job while it holds the place"
    );
    hold.send(()).expect("the first job waits");
    let results = tokio::time::timeout(Duration::from_secs(60), check)
        .await
        .expect("the check runs")
        .expect("joined");
    assert!(all_formed(&results, 1), "{results:?}");
    first.join().expect("joins").expect("granted");
    for job in stream {
        job.join().expect("joins").expect("granted");
    }
    let order = order.lock().expect("order").clone();
    assert_eq!(
        order,
        vec![
            "first header job",
            "evidence check",
            "stream header job",
            "stream header job",
            "stream header job"
        ],
        "the check runs after the one job ahead of it"
    );
    rig.quiet_on(&[1, 2]);
}

/// `RANDOMX_CACHE_ACTOR.md` §8, HA-R7: two jobs outside the window while
/// the window names two seeds. Neither frees a window seed: they take the
/// one outside place in turn. Four builds in all, the window's two and one
/// for each job, and the window's caches are the two resident afterwards.
///
/// Red edit: in the hasher's core, let an outside job free the
/// lowest-ranked idle entry even when it is a window seed: a window seed
/// is rebuilt, and the build count is five or more.
#[tokio::test(flavor = "multi_thread")]
async fn two_jobs_outside_a_two_seed_window_free_no_window_seed() {
    let rig = rig(Budget::of_host());
    rig.rank(&[1, 2], None);
    rig.quiet_on(&[1, 2]);
    let jobs: Vec<_> = [5u8, 6]
        .into_iter()
        .map(|outside| {
            tokio::spawn(prove(
                Arc::clone(&rig.executor),
                HashClass::HeaderPow,
                seed(outside),
                vec![item(seed(outside))],
            ))
        })
        .collect();
    for job in jobs {
        let results = tokio::time::timeout(Duration::from_secs(60), job)
            .await
            .expect("each outside job gets its turn")
            .expect("joined");
        assert!(all_formed(&results, 1), "{results:?}");
    }
    rig.quiet_on(&[1, 2]);
    assert_eq!(
        rig.builds(),
        4,
        "the window's two and one for each outside job: no window seed was rebuilt"
    );
}
