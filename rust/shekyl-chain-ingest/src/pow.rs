// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ingest's proof-of-work boundary (`RANDOMX_CACHE_ACTOR.md` §5.3).
//!
//! A hash happens inside a job, and a job borrows one seed's cache for its
//! scope. [`Pow`] mirrors the hasher's two entry points, and each job is
//! handed a [`Substrate`] whose longhash hashes only under the job's seed.
//!
//! Production plugs in [`ProductionPow`], over the node's one
//! [`Hasher`]. A test plugs in a [`Fixture`], a substrate that is its own
//! job and holds no cache. The two differ only in the type plugged in:
//! there is no flag, and no optional hasher.
//!
//! # No permit of the caller's own
//!
//! Every permit is taken through a job: [`Pow::run`] holds one for the
//! job, and a [`Pow::lend`] job takes one per hash. A caller that held a
//! permit while it asked for a job could wait for the build that needs
//! that permit (`shekyl-hasher` crate docs, *Deadlock*).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use shekyl_chain_rules::Substrate;
use shekyl_hasher::{Class, Hasher, Lent, Loan, Ranked, Residency, Resident, Unhashed};
use shekyl_pow_randomx::Seedhash;
use shekyl_types::{BlockHash, PowHash, Timestamp};

use crate::metrics::{Derives, Metrics};
use crate::substrate::SubstrateFault;

/// What a [`Pow::run`] job hashes through.
pub type RunJob<'job, F> = dyn Substrate<Fault = F> + 'job;

/// What a [`Pow::lend`] job hashes through. `Sync`: the job may hash from
/// several scoped threads.
pub type LendJob<'job, F> = dyn Substrate<Fault = F> + Sync + 'job;

/// The proof-of-work service the ingest runs over (module docs).
pub trait Pow: Send + Sync + 'static {
    /// What a job's substrate can fail with. A fault is not a verdict.
    type Fault: core::fmt::Debug + Send + 'static;

    /// The local wall clock, for a caller that judges without hashing.
    ///
    /// # Errors
    ///
    /// The clock could not be read.
    fn clock(&self) -> Result<Timestamp, Self::Fault>;

    /// Run `job` under `seed`'s cache with one permit of `class` held for
    /// the whole job: one form. `None` when `stop` was set before the job
    /// was granted. Blocking.
    fn run<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&RunJob<'job, Self::Fault>) -> R,
    ) -> Option<R>;

    /// Run `job` under `seed`'s cache with no permit held for the job:
    /// each hash takes one of `class`. `None` when `stop` was set before
    /// the job was granted. Blocking.
    fn lend<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&LendJob<'job, Self::Fault>) -> R,
    ) -> Option<R>;

    /// Wake every job waiting for a cache or a permit to read its stop
    /// flag again.
    fn wake(&self);

    /// The seeds the node needs now, in rank order.
    fn rank(&self, list: Ranked);

    /// Whether `seed`'s cache is built: a warm loan on it could be granted.
    fn warm(&self, seed: &BlockHash) -> bool;

    /// What is resident, for a caller that waits for [`warm`](Self::warm)
    /// to change. `None` when every seed is always warm.
    fn resident(&self) -> Option<tokio::sync::watch::Receiver<Resident>>;

    /// The most hashes that run at once: the threads a `lend` job is worth
    /// spreading over.
    fn permits(&self) -> usize;

    /// The caches derived so far and the time they took: the metrics
    /// artifact's one source for both.
    fn derives(&self) -> Derives;

    /// Run `job` over the clock and no cache: a block whose hash this node
    /// already recorded is re-judged through it. A longhash that reaches
    /// it is a fault and builds nothing.
    fn unlent<R>(&self, job: impl for<'job> FnOnce(&LendJob<'job, Self::Fault>) -> R) -> R;

    /// Whether `fault` is a stop that reached a hash, and not a fault: the
    /// job's permit wait ended on the caller's stop flag.
    fn stopped(fault: &Self::Fault) -> bool;
}

/// RandomX through the node's one [`Hasher`], and the system clock
/// (`DRS_E2_REPLAY_DRIVER.md` RD-Q3).
///
/// This is the one implementation every Shekyl validator runs: the replay
/// driver, the live daemon, chain sync's executor. It holds no cache and
/// no budget. A hash is [`Lent::hash`] or [`Loan::hash`] inside a job.
/// Never the mining JIT; never `VmStatePool`, which is bench scaffolding
/// (RD-F14).
///
/// # Measurement
///
/// This is the first workload that runs RandomX verification at volume
/// over a real chain, so the dataset-mode question (`RANDOMX_V2_RUST.md`
/// §9, measure-first) is answered by numbers this pipeline emits (RD-F11).
/// Each hash is timed into the shared [`Metrics`] sink, and so is each
/// job's wait for its lease: from the call to the job's first line, which
/// is the wait for a place, a build and, for `run`, the permit. Derives
/// are not counted here: [`Resident::builds`] is their one source.
#[derive(Clone)]
pub struct ProductionPow {
    hasher: Hasher,
    /// The RandomX measurement sink (RD-F11); shared with the pipeline,
    /// which times each block's `form` into the same counters.
    metrics: Arc<Metrics>,
}

impl ProductionPow {
    /// The boundary over `hasher`, recording into `metrics`.
    #[must_use]
    pub const fn new(hasher: Hasher, metrics: Arc<Metrics>) -> Self {
        Self { hasher, metrics }
    }

    /// The sink this boundary records into.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// The artifact, as of now: this sink's counters and the hasher's
    /// derives.
    #[must_use]
    pub fn artifact(&self) -> crate::metrics::MetricsArtifact {
        self.metrics.snapshot(self.derives())
    }

    /// The hasher this boundary asks.
    #[must_use]
    pub const fn hasher(&self) -> &Hasher {
        &self.hasher
    }
}

/// The system clock, never a timestamp of zero.
fn system_clock() -> Result<Timestamp, SubstrateFault> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SubstrateFault::ClockBeforeEpoch)?;
    Ok(Timestamp::from_raw(since_epoch.as_secs()))
}

fn seedhash(seed: &BlockHash) -> Seedhash {
    Seedhash::from_bytes(*seed.as_bytes())
}

/// The job's substrate under a held permit ([`Hasher::run`]).
struct RunSubstrate<'a, 'job> {
    lent: &'a Lent<'job>,
    seed: BlockHash,
    metrics: &'a Metrics,
}

impl Substrate for RunSubstrate<'_, '_> {
    type Fault = SubstrateFault;

    fn local_clock(&self) -> Result<Timestamp, SubstrateFault> {
        system_clock()
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, SubstrateFault> {
        if *seed != self.seed {
            return Err(SubstrateFault::SeedNotLent {
                asked: *seed,
                lent: Some(self.seed),
            });
        }
        let hash = self.metrics.timed_hash(|| self.lent.hash(pow_blob));
        Ok(PowHash::from_bytes(hash))
    }
}

/// The job's substrate with one permit per hash ([`Hasher::lend`]).
struct LendSubstrate<'a, 'job> {
    loan: &'a Loan<'job>,
    seed: BlockHash,
    metrics: &'a Metrics,
}

impl Substrate for LendSubstrate<'_, '_> {
    type Fault = SubstrateFault;

    fn local_clock(&self) -> Result<Timestamp, SubstrateFault> {
        system_clock()
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, SubstrateFault> {
        if *seed != self.seed {
            return Err(SubstrateFault::SeedNotLent {
                asked: *seed,
                lent: Some(self.seed),
            });
        }
        // The hash's own time: the permit wait inside the loan is not in
        // it.
        match self.loan.hash_timed(pow_blob) {
            Ok((hash, took)) => {
                self.metrics.hashed(took);
                Ok(PowHash::from_bytes(hash))
            }
            Err(Unhashed::Stopped) => Err(SubstrateFault::Stopped),
            Err(Unhashed::Cancelled) => {
                unreachable!("a job's loan is never cancelled (HA-R1): only a warm loan is")
            }
        }
    }
}

/// The clock and no cache ([`Pow::unlent`]).
struct Unlent;

impl Substrate for Unlent {
    type Fault = SubstrateFault;

    fn local_clock(&self) -> Result<Timestamp, SubstrateFault> {
        system_clock()
    }

    fn longhash(&self, _pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, SubstrateFault> {
        Err(SubstrateFault::SeedNotLent {
            asked: *seed,
            lent: None,
        })
    }
}

impl Pow for ProductionPow {
    type Fault = SubstrateFault;

    fn clock(&self) -> Result<Timestamp, SubstrateFault> {
        system_clock()
    }

    fn run<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&RunJob<'job, SubstrateFault>) -> R,
    ) -> Option<R> {
        let asked = Instant::now();
        self.hasher.run(class, seedhash(&seed), stop, |lent| {
            self.metrics.leased(asked.elapsed());
            job(&RunSubstrate {
                lent,
                seed,
                metrics: &self.metrics,
            })
        })
    }

    fn lend<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&LendJob<'job, SubstrateFault>) -> R,
    ) -> Option<R> {
        let asked = Instant::now();
        self.hasher.lend(class, seedhash(&seed), stop, |loan| {
            self.metrics.leased(asked.elapsed());
            job(&LendSubstrate {
                loan,
                seed,
                metrics: &self.metrics,
            })
        })
    }

    fn wake(&self) {
        self.hasher.wake();
    }

    fn rank(&self, list: Ranked) {
        self.hasher.rank(list);
    }

    fn warm(&self, seed: &BlockHash) -> bool {
        let seed = seedhash(seed);
        self.hasher
            .resident()
            .borrow()
            .caches
            .iter()
            .any(|(held, state)| {
                *held == seed && matches!(state, Residency::Warm | Residency::Leased)
            })
    }

    fn resident(&self) -> Option<tokio::sync::watch::Receiver<Resident>> {
        Some(self.hasher.resident())
    }

    fn permits(&self) -> usize {
        self.hasher.permits()
    }

    fn derives(&self) -> Derives {
        let resident = self.hasher.resident();
        let resident = resident.borrow();
        Derives {
            builds: resident.builds,
            build_ns: resident.build_ns,
        }
    }

    fn unlent<R>(&self, job: impl for<'job> FnOnce(&LendJob<'job, SubstrateFault>) -> R) -> R {
        job(&Unlent)
    }

    fn stopped(fault: &SubstrateFault) -> bool {
        matches!(fault, SubstrateFault::Stopped)
    }
}

/// A substrate that is its own job: it holds no cache, so `run` and `lend`
/// call the job with it, a rank is ignored, and every seed reads as warm.
/// The feature tests' boundary, which never touches RandomX.
#[cfg(any(test, feature = "bench-internals"))]
pub trait Fixture: Substrate + Send + Sync + 'static
where
    Self::Fault: core::fmt::Debug + Send + 'static,
{
}

#[cfg(any(test, feature = "bench-internals"))]
impl<S> Pow for S
where
    S: Fixture,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    type Fault = S::Fault;

    fn clock(&self) -> Result<Timestamp, S::Fault> {
        self.local_clock()
    }

    fn run<R>(
        &self,
        _class: Class,
        _seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&RunJob<'job, S::Fault>) -> R,
    ) -> Option<R> {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        Some(job(self))
    }

    fn lend<R>(
        &self,
        _class: Class,
        _seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&LendJob<'job, S::Fault>) -> R,
    ) -> Option<R> {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        Some(job(self))
    }

    fn wake(&self) {}

    fn rank(&self, _list: Ranked) {}

    fn warm(&self, _seed: &BlockHash) -> bool {
        true
    }

    fn resident(&self) -> Option<tokio::sync::watch::Receiver<Resident>> {
        None
    }

    fn permits(&self) -> usize {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    }

    fn derives(&self) -> Derives {
        Derives::default()
    }

    fn unlent<R>(&self, job: impl for<'job> FnOnce(&LendJob<'job, S::Fault>) -> R) -> R {
        job(self)
    }

    fn stopped(_fault: &S::Fault) -> bool {
        false
    }
}
