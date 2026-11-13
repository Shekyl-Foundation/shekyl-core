// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scenario driver's clock and the values a scripted step returns.
//!
//! These are the driver's vocabulary. The actor, the store and the mining
//! loop stay in [`super`]: a step still asks the connector what the chain
//! is, forms the block and connects it. Callers keep the names on
//! `crate::scenario`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use shekyl_archival_retention::BundleBody;
use shekyl_block_template::{Template, TemplateError};
use shekyl_chain_rules::{
    ArchivalDelta, Candidate, CenRow, InvalidBlock, PaidEmission, Substrate, Target, Weights,
};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHash, BlockHeight, PowHash, Timestamp};
use shekyl_wire::Transaction;

use shekyl_hasher::{Class, Ranked, Resident};

use crate::connector::RunFault;
use crate::pow::{Fixture, LendJob, Pow, RunJob};

/// The seconds between the driver's blocks by default — the DAA target, so
/// a scripted chain's timestamps look like a chain's.
const BLOCK_INTERVAL: u64 = 120;

/// Where the driver's clock starts: after the harness fixtures' epoch so a
/// scenario and a fixture never share a timestamp by accident.
pub const CLOCK_START: Timestamp = Timestamp::from_raw(1_800_000_000);

/// A substrate whose clock the driver owns and advances, over a longhash
/// the caller chooses. Production PoW is `Clocked<ProductionPow>`;
/// the default is the harness's always-satisfying longhash.
pub struct Clocked<P> {
    clock: AtomicU64,
    /// Seconds per [`tick`](Self::tick).
    interval: AtomicU64,
    pow: P,
}

impl<P> Clocked<P> {
    /// A clock at [`CLOCK_START`] over `pow`'s longhash, ticking one DAA
    /// target per block.
    pub const fn new(pow: P) -> Self {
        Self {
            clock: AtomicU64::new(CLOCK_START.to_raw()),
            interval: AtomicU64::new(BLOCK_INTERVAL),
            pow,
        }
    }

    /// Tick `seconds` per block from now on: a chain whose blocks come
    /// faster or slower than the DAA's target.
    pub fn set_interval(&self, seconds: core::num::NonZeroU64) {
        self.interval.store(seconds.get(), Ordering::Relaxed);
    }

    /// The clock now.
    pub fn now(&self) -> Timestamp {
        Timestamp::from_raw(self.clock.load(Ordering::Relaxed))
    }

    /// Advance the clock by one block interval and return the new reading.
    pub fn tick(&self) -> Timestamp {
        let interval = self.interval.load(Ordering::Relaxed);
        let next = self
            .clock
            .fetch_add(interval, Ordering::Relaxed)
            .saturating_add(interval);
        Timestamp::from_raw(next)
    }
}

/// A job's substrate under the driver's clock: the inner job's longhash,
/// and the instant the driver set.
struct ClockedJob<'a, J: ?Sized> {
    now: Timestamp,
    job: &'a J,
}

impl<J: Substrate + ?Sized> Substrate for ClockedJob<'_, J> {
    type Fault = J::Fault;

    fn local_clock(&self) -> Result<Timestamp, J::Fault> {
        Ok(self.now)
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, J::Fault> {
        self.job.longhash(pow_blob, seed)
    }
}

/// The inner boundary's jobs, each judged at the driver's clock. Every
/// other call is the inner boundary's: a clock over a production pow asks
/// its hasher, or a rank through the clock would rank nothing.
impl<P: Pow> Pow for Clocked<P> {
    type Fault = P::Fault;

    fn clock(&self) -> Result<Timestamp, P::Fault> {
        Ok(self.now())
    }

    fn run<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&RunJob<'job, P::Fault>) -> R,
    ) -> Option<R> {
        self.pow.run(class, seed, stop, |inner| {
            job(&ClockedJob {
                now: self.now(),
                job: inner,
            })
        })
    }

    fn lend<R>(
        &self,
        class: Class,
        seed: BlockHash,
        stop: &AtomicBool,
        job: impl for<'job> FnOnce(&LendJob<'job, P::Fault>) -> R,
    ) -> Option<R> {
        self.pow.lend(class, seed, stop, |inner| {
            job(&ClockedJob {
                now: self.now(),
                job: inner,
            })
        })
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

    fn derives(&self) -> crate::metrics::Derives {
        self.pow.derives()
    }

    fn unlent<R>(&self, job: impl for<'job> FnOnce(&LendJob<'job, P::Fault>) -> R) -> R {
        self.pow.unlent(|inner| {
            job(&ClockedJob {
                now: self.now(),
                job: inner,
            })
        })
    }

    fn stopped(fault: &P::Fault) -> bool {
        P::stopped(fault)
    }
}

impl<P> Clocked<P> {
    /// The boundary this clock is over.
    pub const fn inner(&self) -> &P {
        &self.pow
    }
}

/// The harness longhash as a substrate: every target satisfied, no cache.
pub struct FreeHash;

impl Fixture for FreeHash {}

impl Substrate for FreeHash {
    type Fault = std::convert::Infallible;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(CLOCK_START)
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Self::Fault> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

/// Where a timed switch spent its time ([`Scenario::reorganize_timed`](super::Scenario::reorganize_timed)).
#[derive(Clone, Copy, Debug)]
pub struct ReorgTiming {
    /// Forming the demoted and promoted blocks — the RandomX, off the actor,
    /// across every core the host offers.
    pub form: std::time::Duration,
    /// The [`Reorganize`](crate::connector::Reorganize) message: the plan held to the store, the demoted
    /// blocks through the cheap tier, the write closure.
    pub switch: std::time::Duration,
}

/// The next block before it is mined: the template and the producer's two
/// claims about it ([`Scenario::next_template`](super::Scenario::next_template)).
#[derive(Clone, Debug)]
pub struct NextBlock {
    /// The connecting height.
    pub height: BlockHeight,
    /// The template; its block's nonce is the miner's to set.
    pub template: Template,
    /// The seed the producer claims (CEN-D3).
    pub seed: BlockHash,
    /// The target the producer claims (CEN-D4).
    pub target: Target,
}

/// One mined block: what the template priced and what the validator
/// judged it under.
#[derive(Clone, Debug)]
pub struct Mined {
    /// The connecting height.
    pub height: BlockHeight,
    /// The block's identity.
    pub hash: BlockHash,
    /// The template as built.
    pub template: Template,
    /// The census rows the validator recorded for this block.
    pub judged_by: Vec<CenRow>,
    /// The emission the verdict priced the block at (`Applied::emission`).
    pub emission: PaidEmission,
    /// The weight, long-term weight and medians the verdict derived for the
    /// block (`Applied::weights`; CEN-G6/G6b). The witness that a listed
    /// body's weight is the block's addend, which a `MockChain` block
    /// cannot carry once the body has to be a real spend (slice 6 row 6).
    pub weights: Weights,
    /// What the verdict derived the block does to the archival state
    /// (`Applied::archival`). The witness the archival scenarios read,
    /// because the store does not write it until the E4 writer lands.
    pub archival: ArchivalDelta,
    /// The seed the producer claimed (CEN-D3) — what a second driver needs
    /// to `form` this block when it arrives there as an alternative.
    pub seed: BlockHash,
    /// The target the producer claimed (CEN-D4), likewise.
    pub target: Target,
    /// The bundle references the block carried beside it
    /// (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5): the section its header's
    /// `section_root` commits, `None` when it admitted no bundle.
    pub bundle_references: Option<BundleReferences>,
    /// The body each reference names, in section order; empty with no
    /// references.
    pub bundle_bodies: Vec<BundleBody>,
}

impl Mined {
    /// The block as a candidate: the template's block, its listed bodies,
    /// and the section it carried. A block's header commits its section, so
    /// without it a block that admitted a bundle is refused at CEN-J29.
    #[must_use]
    pub fn candidate(&self) -> Candidate {
        Candidate::new(
            self.template.block.clone(),
            self.template.transactions.clone(),
        )
        .with_bundle_references(self.bundle_references.clone())
        .with_bundle_bodies(self.bundle_bodies.clone())
    }
}

/// A block this driver formed and did not connect ([`Scenario::assemble_unconnected`](super::Scenario::assemble_unconnected)).
/// Its header is in the driver's target ledger; the store has never held it.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct Unconnected {
    /// The connecting height the facts named.
    pub height: BlockHeight,
    /// The block's identity.
    pub hash: BlockHash,
    /// The block and its listed bodies.
    pub candidate: Candidate,
    /// The seed the producer claimed (CEN-D3).
    pub seed: BlockHash,
    /// The target the producer claimed (CEN-D4).
    pub target: Target,
}

impl shekyl_harness_spender::MinedBlock for Mined {
    fn height(&self) -> BlockHeight {
        self.height
    }

    fn hash(&self) -> BlockHash {
        self.hash
    }

    fn miner_transaction(&self) -> &Transaction {
        &self.template.block.miner_transaction
    }

    fn listed(&self) -> &[Transaction] {
        &self.template.transactions
    }
}

/// Why a scripted step did not land. Refusals are data (the scenario asked
/// for a block the chain refuses, which some scenarios do on purpose);
/// faults are the stack's.
#[derive(Debug)]
pub enum StepOutcome {
    /// The validator refused the candidate.
    Refused(InvalidBlock),
    /// The template could not be built for the chain's facts.
    Template(TemplateError),
    /// The connector faulted.
    Connector(RunFault),
}

impl std::fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refused) => write!(f, "refused: {refused}"),
            Self::Template(e) => write!(f, "template: {e}"),
            Self::Connector(e) => write!(f, "connector: {e}"),
        }
    }
}
