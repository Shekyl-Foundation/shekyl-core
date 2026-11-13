// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ProductionPow`] over a real hasher: what a job's substrate hashes
//! under, what it refuses, and what the sink counts. That a hash under a
//! lent cache is the verifier's own is `shekyl-hasher`'s test over the
//! RandomX vectors; this module does not derive a cache to compare with,
//! because nothing outside the hasher may.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use shekyl_hasher::{Class, Ranked, Resident};
use shekyl_pow_randomx::Seedhash;
use shekyl_types::{BlockHash, PowHash, Timestamp};

use super::{LendJob, Pow, ProductionPow, RunJob};
use crate::metrics::Derives;
use crate::scenario::{Scenario, RULES};
use crate::service::service_tests::arrival;
use crate::service::{Reply, Service, ServiceConfig, ServiceFault};
use crate::substrate::SubstrateFault;
use crate::test_support::{open_store, own_hasher, tmp};

static RUNNING: AtomicBool = AtomicBool::new(false);

fn seed(fill: u8) -> BlockHash {
    BlockHash::from_bytes([fill; 32])
}

fn as_seed(seed: &BlockHash) -> Seedhash {
    Seedhash::from_bytes(*seed.as_bytes())
}

/// A `run` job and a `lend` job hash the same blob under the same seed to
/// the same value, another seed gives another value (the seed is
/// load-bearing, CEN-D3), and the sink saw each hash and each lease while
/// the derives are the hasher's count.
///
/// Red edit: in `LendSubstrate::longhash`, drop `self.metrics.hashed`:
/// the sink counts two hashes, not three.
#[test]
fn a_job_hashes_under_its_seed_and_the_sink_counts_hashes_and_leases() {
    let own = own_hasher();
    let (a, b) = (seed(0x5e), seed(0x5f));
    let blob = b"shekyl ingest pow probe";
    let under_a = own
        .pow
        .run(Class::Chain, a, &RUNNING, |job| job.longhash(blob, &a))
        .expect("granted")
        .expect("the job's own seed");
    let lent_a = own
        .pow
        .lend(Class::Chain, a, &RUNNING, |job| job.longhash(blob, &a))
        .expect("granted")
        .expect("the job's own seed");
    assert_eq!(under_a, lent_a, "one seed, one blob, one hash");
    let under_b = own
        .pow
        .run(Class::Chain, b, &RUNNING, |job| job.longhash(blob, &b))
        .expect("granted")
        .expect("the job's own seed");
    assert_ne!(under_a, under_b, "another seed is another hash");
    let seen = own.pow.artifact();
    assert_eq!(seen.hashes, 3, "every hash is counted, held permit or lent");
    assert_eq!(seen.leases, 3, "every job's lease wait is counted");
    let Derives { builds, .. } = own.pow.derives();
    assert_eq!(
        seen.cache_derives, builds,
        "the artifact's derives are the hasher's"
    );
    assert!(
        (2..=3).contains(&builds),
        "one build per seed, and one more when the first seed's cache was freed between its \\
         two jobs: {builds}"
    );
}

/// A longhash asked for a seed other than the job's is a fault that names
/// both, in a `run` job and in a `lend` job, and it builds nothing. Where
/// no job was asked for, any longhash is that fault.
///
/// Red edit: drop the seed check in `RunSubstrate::longhash`: the job
/// hashes seed B's blob under seed A's cache and returns a hash.
#[test]
fn a_longhash_for_another_seed_faults_and_builds_nothing() {
    let own = own_hasher();
    let (lent, asked) = (seed(0x61), seed(0x62));
    let run = own
        .pow
        .run(Class::Chain, lent, &RUNNING, |job| {
            job.longhash(b"x", &asked)
        })
        .expect("granted");
    let lend = own
        .pow
        .lend(Class::Chain, lent, &RUNNING, |job| {
            job.longhash(b"x", &asked)
        })
        .expect("granted");
    let fault = SubstrateFault::SeedNotLent {
        asked,
        lent: Some(lent),
    };
    assert_eq!((run, lend), (Err(fault), Err(fault)));
    assert!(!ProductionPow::stopped(&fault), "a defect, not a stop");
    let unlent = own.pow.unlent(|job| job.longhash(b"x", &asked));
    assert_eq!(
        unlent,
        Err(SubstrateFault::SeedNotLent { asked, lent: None })
    );
    let resident = own.hasher.resident();
    let seen: Vec<Seedhash> = resident
        .borrow()
        .caches
        .iter()
        .map(|(seed, _)| *seed)
        .collect();
    assert!(
        !seen.contains(&as_seed(&asked)),
        "nothing was built for the seed that was not lent: {seen:?}"
    );
    assert_eq!(own.pow.artifact().hashes, 0, "and nothing was hashed");
}

/// A ranked seed is built once: a second job on it finds it warm. An
/// unranked seed's cache is freed when its job ends, so the rank is what
/// keeps an epoch's cache between forms (the replay run ranks for that).
///
/// Red edit: drop the `rank` call below: the second job builds again.
#[test]
fn a_ranked_seed_is_built_once() {
    let own = own_hasher();
    let a = seed(0x5d);
    own.pow
        .rank(Ranked::new(as_seed(&a), None, None).expect("one seed"));
    for _ in 0..2 {
        own.pow
            .run(Class::Chain, a, &RUNNING, |job| job.longhash(b"y", &a))
            .expect("granted")
            .expect("hashes");
    }
    assert_eq!(own.pow.derives().builds, 1, "a hit, not a second fill");
    assert!(own.pow.warm(&a), "and it is warm for a warm loan");
    assert!(!own.pow.warm(&seed(0x5c)), "an unbuilt seed is not");
}

/// A stop set before a job is asked for grants nothing, and a stop that
/// reaches a lent hash's permit wait is the `Stopped` fault, which the
/// boundary reads as a stop.
#[test]
fn a_stop_grants_no_job_and_is_not_a_fault() {
    let own = own_hasher();
    let stopped = AtomicBool::new(true);
    let a = seed(0x41);
    assert!(own.pow.run(Class::Chain, a, &stopped, |_| ()).is_none());
    assert!(own.pow.lend(Class::Chain, a, &stopped, |_| ()).is_none());
    assert!(ProductionPow::stopped(&SubstrateFault::Stopped));
    assert!(!ProductionPow::stopped(&SubstrateFault::ClockBeforeEpoch));
    assert_eq!(own.pow.derives().builds, 0, "and nothing was built");
}

#[test]
fn the_clock_is_now_in_unix_seconds() {
    let own = own_hasher();
    let now = own.pow.clock().expect("after the epoch");
    // Not before this test was written, not absurdly far ahead.
    assert!(now.to_raw() > 1_780_000_000, "{now:?}");
    assert!(now.to_raw() < 4_000_000_000, "{now:?}");
    let in_job = own.pow.unlent(|job| job.local_clock()).expect("clock");
    assert!(
        in_job.to_raw() >= now.to_raw(),
        "a job reads the same clock"
    );
}

/// The caller's defect §1.3 names: a job asked for on one seed while the
/// form's claims name another. This boundary asks every job on a fixed
/// wrong seed, and is otherwise the production one.
struct Misdirected {
    pow: ProductionPow,
    wrong: BlockHash,
}

impl Pow for Misdirected {
    type Fault = SubstrateFault;

    fn clock(&self) -> Result<Timestamp, SubstrateFault> {
        self.pow.clock()
    }

    fn run<R>(
        &self,
        class: Class,
        _seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&RunJob<'job, SubstrateFault>) -> R,
    ) -> Option<R> {
        self.pow.run(class, self.wrong, stop, job)
    }

    fn lend<R>(
        &self,
        class: Class,
        _seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&LendJob<'job, SubstrateFault>) -> R,
    ) -> Option<R> {
        self.pow.lend(class, self.wrong, stop, job)
    }

    fn wake(&self) {
        self.pow.wake();
    }

    fn rank(&self, list: Ranked) {
        self.pow.rank(list);
    }

    fn warm(&self, seed: &BlockHash) -> bool {
        self.pow.warm(seed)
    }

    fn resident(&self) -> Option<tokio::sync::watch::Receiver<Resident>> {
        self.pow.resident()
    }

    fn permits(&self) -> usize {
        self.pow.permits()
    }

    fn derives(&self) -> Derives {
        self.pow.derives()
    }

    fn unlent<R>(&self, job: impl for<'job> FnOnce(&LendJob<'job, SubstrateFault>) -> R) -> R {
        self.pow.unlent(job)
    }

    fn stopped(fault: &SubstrateFault) -> bool {
        ProductionPow::stopped(fault)
    }
}

/// A form whose claims name seed A, run as a job on seed B, ends the
/// service with the fault that names both. It is never a verdict: no block
/// is refused and none is stored, because a valid block refused for this
/// would split the chain (`substrate` module docs).
///
/// Red edit: in `span::connect_run`, answer a `SeedNotLent` fault as
/// `FormStop::Refused` with any verdict: the arrival is refused and the
/// service keeps running.
#[tokio::test(flavor = "multi_thread")]
async fn a_form_on_a_job_for_another_seed_ends_the_service_and_refuses_nothing() {
    let mut y = Scenario::open("pow-seed-not-lent-y");
    let blocks = y.mine(1).await;
    let own = own_hasher();
    let wrong = seed(0x77);
    let path = tmp("pow-seed-not-lent");
    let store = Arc::new(open_store(&path));
    let service = Service::start(
        Arc::clone(&store),
        RULES,
        Arc::new(Misdirected {
            pow: own.pow.clone(),
            wrong,
        }),
        ServiceConfig::default(),
        crate::service::Follow::default(),
    );
    let reply = service
        .door()
        .offer(arrival(1, 1, &blocks[0]))
        .expect("room")
        .reply()
        .await
        .reply;
    assert_eq!(
        reply,
        Reply::Stopped,
        "no verdict: the arrival is not refused"
    );
    let mut ended = service.ended();
    let end = ended
        .wait_for(Option::is_some)
        .await
        .expect("the service publishes its end")
        .clone()
        .expect("checked");
    let fault = service
        .stop()
        .await
        .expect_err("the service ended on a fault");
    assert!(
        matches!(
            fault,
            ServiceFault::Substrate(SubstrateFault::SeedNotLent {
                asked,
                lent: Some(lent),
            }) if asked == BlockHash::NULL && lent == wrong
        ),
        "{fault:?}"
    );
    assert!(
        end.to_string().contains("SeedNotLent"),
        "the exit line names the fault: {end}"
    );
    let snap = store.begin_read().expect("read");
    assert!(
        snap.tip().expect("tip").recorded.is_none(),
        "nothing stored"
    );
    assert_eq!(snap.alt_block_count().expect("alts"), 0, "and no alt row");
    drop(snap);
    y.close().await;
}

/// Kept so an unused import is a compile error here, not a silent drift:
/// the lend job's substrate is `Sync`, which the switch's scoped threads
/// and chain sync's lanes rely on.
#[test]
fn a_lend_job_hashes_from_scoped_threads() {
    let own = own_hasher();
    let a = seed(0x33);
    let hashes: Vec<Result<PowHash, SubstrateFault>> = own
        .pow
        .lend(Class::Chain, a, &RUNNING, |job| {
            std::thread::scope(|scope| {
                let lanes: Vec<_> = (0u8..2)
                    .map(|lane| scope.spawn(move || job.longhash(&[lane], &a)))
                    .collect();
                lanes
                    .into_iter()
                    .map(|lane| lane.join().expect("joins"))
                    .collect()
            })
        })
        .expect("granted");
    assert!(hashes.iter().all(Result::is_ok), "{hashes:?}");
    assert_ne!(hashes[0], hashes[1], "two blobs, two hashes");
}
