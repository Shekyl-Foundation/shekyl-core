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

use std::sync::atomic::{AtomicU64, Ordering};

use shekyl_block_template::{Template, TemplateError};
use shekyl_chain_rules::{
    ArchivalDelta, Candidate, CenRow, InvalidBlock, PaidEmission, Substrate, Target, Weights,
};
use shekyl_types::{BlockHash, BlockHeight, PowHash, Timestamp};
use shekyl_wire::Transaction;

use crate::connector::RunFault;

/// The seconds between the driver's blocks — the DAA target, so a
/// scripted chain's timestamps look like a chain's.
const BLOCK_INTERVAL: u64 = 120;

/// Where the driver's clock starts: after the harness fixtures' epoch so a
/// scenario and a fixture never share a timestamp by accident.
pub const CLOCK_START: Timestamp = Timestamp::from_raw(1_800_000_000);

/// A substrate whose clock the driver owns and advances, over a longhash
/// the caller chooses. Production PoW is `Clocked<ProductionSubstrate>`;
/// the default is the harness's always-satisfying longhash.
pub struct Clocked<P> {
    clock: AtomicU64,
    pow: P,
}

impl<P> Clocked<P> {
    /// A clock at [`CLOCK_START`] over `pow`'s longhash.
    pub const fn new(pow: P) -> Self {
        Self {
            clock: AtomicU64::new(CLOCK_START.to_raw()),
            pow,
        }
    }

    /// The clock now.
    pub fn now(&self) -> Timestamp {
        Timestamp::from_raw(self.clock.load(Ordering::Relaxed))
    }

    /// Advance the clock by one block interval and return the new reading.
    pub fn tick(&self) -> Timestamp {
        let next = self
            .clock
            .fetch_add(BLOCK_INTERVAL, Ordering::Relaxed)
            .saturating_add(BLOCK_INTERVAL);
        Timestamp::from_raw(next)
    }
}

impl<P: Substrate> Substrate for Clocked<P> {
    type Fault = P::Fault;

    fn local_clock(&self) -> Result<Timestamp, P::Fault> {
        Ok(self.now())
    }

    fn longhash(&self, pow_blob: &[u8], seed: &BlockHash) -> Result<PowHash, P::Fault> {
        self.pow.longhash(pow_blob, seed)
    }

    /// The pin is the longhash's: a clock over a production substrate pins
    /// its cache store, or a pin through the clock would pin nothing.
    fn pin_seed(&self, seed: &BlockHash) {
        self.pow.pin_seed(seed);
    }
}

/// The harness longhash as a substrate: every target satisfied, no cache.
pub struct FreeHash;

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
}

impl Mined {
    /// The block as a candidate: the template's block and listed bodies,
    /// no witness (the driver mints no attestation records).
    #[must_use]
    pub fn candidate(&self) -> Candidate {
        Candidate::new(
            self.template.block.clone(),
            self.template.transactions.clone(),
        )
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
