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
//! The block that lands is one the validator admitted; everything the store
//! recorded is the verdict's; nothing here writes state a rule reads back.
//! That is what makes a chain built
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
//! validator, the store, the burn fold. Under a [`ProductionSubstrate`]
//! the PoW is real RandomX at the fixed regtest difficulty; the default
//! [`Clocked`] over the harness longhash keeps the clock deterministic and
//! the hash free. Nothing is a placeholder any more: the curve-tree root
//! stopped being one with DRS-E3, the two medians with slice 7 commit 4,
//! and the frozen-segment count and the burn with slice 7 wave B — each
//! read through the validator's own definition on the view it judges
//! against, and the producer's ledger of what it priced (`Priced`, handed
//! to `connect` through `Composed`) went with the last of them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kameo::actor::{ActorRef, Spawn};
use shekyl_block_template::{
    build, EmissionOperands, MinerKeys, Template, TemplateContext, TemplateError,
};
use shekyl_chain_rules::{
    form, seed_height, ArchivalDelta, Candidate, CenRow, FormAttempt, InvalidBlock, PaidEmission,
    RuleSet, Substrate, Weights,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::ChainStore;
use shekyl_economics::EconomicParams;
use shekyl_harness_wallet::MinerWallet;
use shekyl_types::archival::BondRecord;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, PCanonicalId, PowHash, SettlementEpoch,
    Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;
use zeroize::Zeroizing;

use crate::connector::{
    Apply, BondRecordOf, BudgetAccruingOf, ChainFacts, Connector, ConnectorArgs, HashAt, Rewind,
    Rewound, RootAt, RunFault, TemplateFacts,
};
use crate::schedule::ChainRules;
use crate::test_support::{cleanup, open_store, open_store_under, tmp};

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

/// The driver. Owns the connector (and through it the store) and the
/// clock; every block it mines pays the harness miner.
pub struct Scenario<P> {
    path: PathBuf,
    connector: ActorRef<Connector>,
    substrate: Clocked<P>,
    /// The harness miner (`shekyl-harness-wallet`): the one wallet the
    /// rules fixture, the store's tests and this driver all pay, so a
    /// spend the spender builds over any of their chains is of an output
    /// the same secrets recover.
    wallet: &'static MinerWallet,
    /// The template's view of the miner, built once from the wallet's
    /// public half.
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
    schedule: shekyl_chain_rules::FakechainSchedule::PRODUCTION,
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
        Self::open_under_with(name, pow, RULES, open_store)
    }

    /// A scenario under `rules` rather than [`RULES`] — a levered regtest
    /// schedule, with the store opened under that schedule's pair the way
    /// the daemon opens it (`test_support::open_store_under`, `ARW-15`).
    /// The callers are the chains that need a slash deadline inside what a
    /// test can mine: slice 8's reinstate measurement
    /// (`archival_slash_tests`, the open interval only a slash writes).
    pub fn open_under(name: &str, pow: P, rules: ChainRules) -> Self {
        Self::open_under_with(name, pow, rules, |path| {
            open_store_under(
                path,
                &rules.in_force(BlockHeight::from_raw(0)),
                ApplyPolicy::Full,
            )
        })
    }

    fn open_under_with(
        name: &str,
        pow: P,
        rules: ChainRules,
        store: impl FnOnce(&std::path::Path) -> ChainStore,
    ) -> Self {
        let path = tmp(name);
        let connector = Connector::spawn(ConnectorArgs {
            store: store(&path),
            rules,
        });
        Self {
            path,
            connector,
            substrate: Clocked::new(pow),
            wallet: MinerWallet::harness(),
            miner: {
                let recipient = MinerWallet::harness().recipient();
                MinerKeys {
                    spend_public: recipient.spend_public,
                    x25519_pk: recipient.x25519_pk,
                    ml_kem_ek: recipient.ml_kem_ek.clone(),
                }
            },
            params: EconomicParams::default(),
            rules,
            next_tx_secret: 1,
        }
    }

    /// The connector, for a test that wants to ask it something directly.
    pub const fn connector(&self) -> &ActorRef<Connector> {
        &self.connector
    }

    /// The miner every block of this scenario pays, secrets included.
    pub const fn wallet(&self) -> &'static MinerWallet {
        self.wallet
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
        // Nothing the producer priced is handed to `connect`: the reward it
        // priced is judged by F14b/F18, the burn by F17, and both are
        // recorded from the verdict (the ledger that carried the burn left
        // with wave B).

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
        let (_, emission) = applied.emission[0];
        let (_, weights) = applied.weights[0];
        let (_, archival) = applied
            .archival
            .into_iter()
            .next()
            .expect("one connected block carries one archival delta");
        Ok(Mined {
            height,
            hash,
            template,
            judged_by,
            emission,
            weights,
            archival,
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

    /// The store's curve-tree root going into `height` (`RootAt`).
    pub async fn root_at(&self, height: BlockHeight) -> Result<Option<CurveTreeRoot>, RunFault> {
        self.connector
            .ask(RootAt { height })
            .await
            .map_err(handler_error)
    }

    /// `persona`'s bond record as the store holds it (`BondRecordOf`).
    pub async fn bond_record(&self, persona: PCanonicalId) -> Result<Option<BondRecord>, RunFault> {
        self.connector
            .ask(BondRecordOf { persona })
            .await
            .map_err(handler_error)
    }

    /// `epoch`'s accruing budget as the store holds it (`BudgetAccruingOf`).
    pub async fn budget_accruing(
        &self,
        epoch: SettlementEpoch,
    ) -> Result<Option<AtomicUnits>, RunFault> {
        self.connector
            .ask(BudgetAccruingOf { epoch })
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
        // Written straight into the zeroizing cell: no bare copy of the
        // scalar's bytes exists on this stack after the context drops.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        tx_key_secret[..8].copy_from_slice(&self.next_tx_secret.to_le_bytes());
        self.next_tx_secret += 1;
        let rule_set: RuleSet = self.rules.in_force(facts.connecting);
        build(&TemplateContext {
            height: facts.connecting,
            previous: facts.previous,
            curve_tree_root: facts.curve_tree_root,
            // The driver mints no attestation records (CEN-I20 admits no
            // 0x0B field on the coinbase), so every template commits the
            // empty set's root — the arm CEN-B4 judges a witness-less block
            // against (slice 8 row 10).
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
            major_version: rule_set.header_major_version(),
            now,
            median_timestamp: facts.median_timestamp,
            unlock_window: rule_set.mined_money_unlock_window(),
            emission: EmissionOperands {
                already_generated_coins: facts.parent_coins_generated,
                total_burned: facts.total_burned,
                // CEN-G6b: the effective median the validator will judge
                // this block's weight against, read on the same view.
                median_weight: facts.medians.effective_median.to_raw(),
                tx_volume: facts.tx_volume,
                // CEN-F17's `n`, as the validator reads it: the shards the
                // parent chain has closed, read on the same view by the
                // validator's own definition. (Zero until a scenario chain
                // issues `T` ids; it was a literal zero until wave B.)
                closed_shards: facts.closed_shards,
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

#[cfg(test)]
#[path = "scenario_tests.rs"]
mod scenario_tests;
