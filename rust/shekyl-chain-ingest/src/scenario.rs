// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scenario driver — a scripted chain over the production stack
//! (`CHAIN_RULES_SLICE_6.md` §5.3, RULED 2026-09-24).
//!
//! `mine(n)` builds each block the way a miner does: ask the connector
//! what the chain is ([`TemplateFacts`] — the tip, the root at the
//! connecting height, the parent's emission, the F20 window and the C2
//! median, all read on the view the validator will judge against and
//! through the validator's own definitions), price a coinbase with
//! `shekyl-block-template`, `form` it under a substrate, and `Apply` it.
//! The block that lands is one the validator admitted; the facts the store
//! recorded are the ones [`Composed`] assembled from the owners; nothing
//! here writes state a rule reads back. That is what makes a chain built
//! here a **witness** rather than a fixture (`50-testing.mdc`): every rule
//! that has landed judged every block, and a rule that lands later judges
//! the same blocks again.
//!
//! # One event at a time — and what that does not cover
//!
//! Template generation is serial: a miner cannot build `h + 1` until `h`
//! is connected, because `h + 1`'s header carries the root *after* `h`
//! and its coinbase is priced at `h`'s record. The driver models that path
//! faithfully — template, form, connect, repeat — and so exercises
//! `form → validate → connect` and **deliberately not the sequencer's
//! lookahead**. Replay-with-a-trace (`pipeline::run` over a corpus) covers
//! that. Two instruments, two subjects: scenario coverage is not ingest
//! end-to-end coverage, and a test that wants the pipeline's concurrency
//! judged uses the replay.
//!
//! # What is real and what is placeholder
//!
//! Real: the template, the coinbase and its hybrid-KEM output, the
//! validator, the store, the facts fold. Under a [`ProductionSubstrate`]
//! the PoW is real RandomX at the fixed regtest difficulty; the default
//! [`Clocked`] over the harness longhash keeps the clock deterministic and
//! the hash free. Placeholder, and said so where it is set: `root_after`
//! (nothing here grows the tree — S-CURVE), the long-term median and the
//! effective median weight (G6, slice 7), the frozen-segment count (E4).
//! Each is the caller's pass-through in [`Priced`] and the template's
//! context, exactly as the E2 trace supplied it, and each is a line that
//! becomes a derivation when its owner lands.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use kameo::actor::{ActorRef, Spawn};
use shekyl_block_template::{
    build, EmissionOperands, MinerKeys, Template, TemplateContext, TemplateError,
};
use shekyl_chain_rules::{
    form, seed_height, Candidate, CenRow, FormAttempt, InvalidBlock, RuleSet, Substrate,
    EMISSION_SPLIT_EPOCH,
};
use shekyl_crypto_hash::keccak256;
use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation};
use shekyl_economics::{EconomicParams, FrozenSegmentCount, FULL_REWARD_ZONE};
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, LongTermWeight, PowHash, Timestamp,
};
use shekyl_wire::Transaction;

use crate::connector::{
    Apply, ChainFacts, Connector, ConnectorArgs, HashAt, Rewind, Rewound, RunFault, TemplateFacts,
};
use crate::facts::{Composed, Priced, PricedAt};
use crate::schedule::ChainRules;
use crate::test_support::{cleanup, open_store, tmp};

/// The seconds between the driver's blocks — the DAA target, so a
/// scripted chain's timestamps look like a chain's.
pub const BLOCK_INTERVAL: u64 = 120;

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

/// The producer's ledger: what it priced each height at, answered to
/// [`Composed`] through [`PricedAt`]. Shared with the connector, written
/// by the driver before each `Apply`.
#[derive(Default)]
pub struct Ledger(Mutex<BTreeMap<u64, Priced>>);

impl PricedAt for Ledger {
    fn priced_at(&self, height: BlockHeight) -> Option<Priced> {
        self.0
            .lock()
            .expect("ledger lock")
            .get(&height.to_raw())
            .copied()
    }
}

/// The root the driver passes through as the state after `height`'s drain.
/// **Placeholder**: nothing here grows the curve tree (S-CURVE is E3's);
/// what matters to the rules that have landed is that the next header
/// carries what the store recorded (CEN-B5), which holds because the next
/// template reads `root_at` off the store. Derived from the height so it
/// is deterministic and distinct per block.
#[must_use]
pub fn placeholder_root_after(height: BlockHeight) -> CurveTreeRoot {
    let mut preimage = *b"shekyl-scenario-root-after\0\0\0\0\0\0";
    preimage[26..].copy_from_slice(&height.to_raw().to_le_bytes()[..6]);
    CurveTreeRoot::from_bytes(keccak256(&preimage))
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

/// The driver. Owns the connector (and through it the store), the ledger,
/// the miner's keys and the clock.
pub struct Scenario<P> {
    path: PathBuf,
    connector: ActorRef<Connector<Composed<Ledger>>>,
    ledger: Arc<Composed<Ledger>>,
    substrate: Clocked<P>,
    miner: MinerKeys,
    params: EconomicParams,
    rules: ChainRules,
    next_tx_secret: u64,
}

/// The rules every scenario runs under: regtest at fixed difficulty one,
/// so a nonce of zero satisfies any longhash — real or free — and the
/// subject stays the chain, not the search.
pub const RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: Some(std::num::NonZeroU128::MIN),
};

impl Scenario<FreeHash> {
    /// A scenario over the free longhash, at a fresh store named `name`.
    pub fn open(name: &str) -> Self {
        Self::open_with(name, FreeHash)
    }
}

impl<P: Substrate + Send + Sync + 'static> Scenario<P>
where
    P::Fault: std::fmt::Debug,
{
    /// A scenario over `pow`'s longhash, at a fresh store named `name`.
    pub fn open_with(name: &str, pow: P) -> Self {
        let path = tmp(name);
        let ledger = Arc::new(Composed::new(Ledger::default()));
        let connector = Connector::spawn(ConnectorArgs {
            store: open_store(&path),
            rules: RULES,
            facts: Arc::clone(&ledger),
        });
        Self {
            path,
            connector,
            ledger,
            substrate: Clocked::new(pow),
            miner: deterministic_miner(),
            params: EconomicParams::default(),
            rules: RULES,
            next_tx_secret: 1,
        }
    }

    /// The connector, for a test that wants to ask it something directly.
    pub const fn connector(&self) -> &ActorRef<Connector<Composed<Ledger>>> {
        &self.connector
    }

    /// What the chain is now, as the producer reads it.
    pub async fn facts(&self) -> Result<ChainFacts, RunFault> {
        self.connector
            .ask(TemplateFacts)
            .await
            .map_err(handler_error)
    }

    /// Mine `n` empty blocks; every one must land.
    pub async fn mine(&mut self, n: u64) -> Vec<Mined> {
        let mut mined = Vec::with_capacity(usize::try_from(n).expect("fits"));
        for _ in 0..n {
            mined.push(
                self.mine_listing(Vec::new())
                    .await
                    .unwrap_or_else(|outcome| panic!("an empty block always lands: {outcome}")),
            );
        }
        mined
    }

    /// Build the next block listing `listed`, form it, and apply it.
    /// A refusal is returned, not panicked: some scenarios ask for one.
    pub async fn mine_listing(&mut self, listed: Vec<Transaction>) -> Result<Mined, StepOutcome> {
        let facts = self.facts().await.map_err(StepOutcome::Connector)?;
        let now = self.substrate.tick();
        let template = self
            .template(&facts, now, &listed)
            .map_err(StepOutcome::Template)?;
        let height = facts.connecting;

        // The producer records what it priced before the block can connect:
        // `Composed` answers `connect` from this ledger.
        self.ledger.priced().0.lock().expect("ledger lock").insert(
            height.to_raw(),
            Priced {
                block_reward: template.block_reward,
                burned: template.fees_burned,
                root_after: placeholder_root_after(height),
                // G6 (slice 7): until the median is derived it is the
                // zone, the value the C++ floors a short chain's median to.
                long_term_effective_median: LongTermWeight::from_raw(FULL_REWARD_ZONE),
            },
        );

        // D3: the seed the honest producer claims — the identity at the
        // seed height, or the null hash below the first epoch.
        let seed = match seed_height(height) {
            None => BlockHash::NULL,
            Some(at) => self
                .connector
                .ask(HashAt { height: at })
                .await
                .map_err(handler_error)
                .map_err(StepOutcome::Connector)?
                .expect("the seed height is below the tip"),
        };

        let candidate = Candidate::new(template.block.clone(), template.transactions.clone());
        let formed = form(
            candidate,
            &self.rules.in_force(height),
            &self.substrate,
            seed,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault");
        let formed = formed.map_err(StepOutcome::Refused)?;

        let applied = self
            .connector
            .ask(Apply(vec![(height, Ok(formed))]))
            .await
            .map_err(handler_error)
            .map_err(StepOutcome::Connector)?;
        if let Some((_, refused)) = applied.refused {
            return Err(StepOutcome::Refused(refused));
        }
        let (_, hash) = applied.connected[0];
        let judged_by = CenRow::ALL
            .iter()
            .copied()
            .filter(|row| applied.exercised.contains(row.as_str()))
            .collect();
        Ok(Mined {
            height,
            hash,
            template,
            judged_by,
        })
    }

    /// Pop the chain back to `to`.
    pub async fn rewind_to(&mut self, to: BlockHeight) -> Result<Rewound, RunFault> {
        self.connector
            .ask(Rewind { to })
            .await
            .map_err(handler_error)
    }

    /// The block's identity at `height`, if recorded.
    pub async fn hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, RunFault> {
        self.connector
            .ask(HashAt { height })
            .await
            .map_err(handler_error)
    }

    /// Stop the connector, release the store, remove the file.
    pub async fn close(self) {
        self.connector.stop_gracefully().await.expect("stop");
        self.connector.wait_for_shutdown().await;
        cleanup(&self.path);
    }

    /// The template for `facts`, listing `listed`, at clock `now`.
    fn template(
        &mut self,
        facts: &ChainFacts,
        now: Timestamp,
        listed: &[Transaction],
    ) -> Result<Template, TemplateError> {
        let mut tx_key_secret = [0u8; 32];
        tx_key_secret[..8].copy_from_slice(&self.next_tx_secret.to_le_bytes());
        self.next_tx_secret += 1;
        let rule_set: RuleSet = self.rules.in_force(facts.connecting);
        build(&TemplateContext {
            height: facts.connecting,
            previous: facts.previous,
            curve_tree_root: facts.curve_tree_root,
            attestation_root: AttestationRoot::from_bytes([0; 32]),
            major_version: rule_set.header_major_version(),
            minor_version: 0,
            now,
            median_timestamp: facts.median_timestamp,
            unlock_window: rule_set.mined_money_unlock_window(),
            emission: EmissionOperands {
                already_generated_coins: facts.parent_coins_generated,
                total_burned: facts.total_burned,
                // G6 (slice 7): the effective median is the zone until derived.
                median_weight: FULL_REWARD_ZONE,
                tx_volume: facts.tx_volume,
                // E4: no frozen segments are recorded on a scenario chain.
                frozen_segments: FrozenSegmentCount::ZERO,
                emission_split_epoch: EMISSION_SPLIT_EPOCH,
            },
            params: &self.params,
            miner: &self.miner,
            tx_key_secret,
            extra_nonce: [0; shekyl_wire::tx_extra::COINBASE_NONCE_BYTES],
            listed,
        })
    }
}

/// The reply error's handler arm, or a panic on a transport failure — the
/// actor is in-process and a dead mailbox is a test-harness defect.
fn handler_error<M>(e: kameo::error::SendError<M, RunFault>) -> RunFault {
    match e {
        kameo::error::SendError::HandlerError(fault) => fault,
        other => panic!("connector mailbox: {other}"),
    }
}

/// A miner with a fixed Edwards spend key and a fresh hybrid KEM keypair.
/// The KEM keys are drawn per scenario (the library offers no seeded
/// generation); every template in one scenario pays the same miner.
fn deterministic_miner() -> MinerKeys {
    let k = Scalar::from_bytes_mod_order([0x5c; 32]);
    let (pk, _sk) = HybridX25519MlKem
        .keypair_generate()
        .expect("hybrid KEM keypair generation");
    MinerKeys {
        spend_public: EdwardsPoint::mul_base(&k).compress().to_bytes(),
        x25519_pk: pk.x25519,
        ml_kem_ek: pk.ml_kem,
    }
}

#[cfg(test)]
#[path = "scenario_tests.rs"]
mod scenario_tests;
