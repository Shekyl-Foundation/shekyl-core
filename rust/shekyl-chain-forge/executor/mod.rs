// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain forge's executor (`CHAIN_FORGE.md` §11.1, §11.3): a plan in,
//! a forged chain out.
//!
//! Each block is built the way the scenario driver builds one (the
//! connector's template facts, the production template, `form`, `validate`
//! and `connect` against a real store), on a chain carrying regtest's
//! identity (§6), and written to the corpus as it lands. Every randomness
//! source the blocks reach draws from the plan's seed ([`seeds`]). When the
//! plan is done, the trace is produced **from the written corpus** by the
//! code `shekyl-chain-replay baseline` runs, on a fresh store, under the
//! production proof-of-work: the trace is the production pipeline's verdict
//! on the bytes on disk, so a forge that wrote other bytes than it
//! connected fails there.
//!
//! A module tree outside `src/`, included by the crate's test-kind targets
//! (the `forge` example, and the determinism, forged-chain and producer-audit
//! tests) with `#[path]`: it compiles against the dev-dependencies, which
//! the library never sees.
//!
//! The chain is written as corpus layout 5 (`CORPUS_FORMAT_VERSION`): a
//! reorg is the competing branch written as `offer` records after the
//! blocks it competes with. No record says the chain switched; the replay
//! that produces the trace derives the switch through the fork choice,
//! and the manifest records where it did (`CHAIN_FORGE.md` §7.1, §7.2).

mod built;
mod checks;
pub mod claim;
pub mod produce;
pub mod seeds;

pub use built::{Built, BuiltKind};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufWriter;
use std::num::{NonZeroU128, NonZeroUsize};
use std::path::Path;
use std::sync::Arc;

use shekyl_archival_retention::RELEASE_COOLDOWN_EPOCHS;
use shekyl_bundle_producer::DrawTarget;
use shekyl_chain_forge::{
    close_event, sha256_hex, Action, BlocksTxt, Branch, Difference, EpochBlocks, EventRecord,
    FillTo, Line, Manifest, Plan, PlanRef, ScheduleRecord, SwitchRecord, MANIFEST_FORMAT_VERSION,
};
use shekyl_chain_ingest::admitted_draws::{
    assert_issued_pair, mine_serving, serve_to, DriverWitness,
};
use shekyl_chain_ingest::archival_driver::ENDPOINT;
use shekyl_chain_ingest::chain_drive::{failure_window_epochs, spender_owning_before, Driven};
use shekyl_chain_ingest::metrics::Metrics;
use shekyl_chain_ingest::pipeline::PipelineConfig;
use shekyl_chain_ingest::priced::{assert_priced, fee_at, SIZING_FEE};
use shekyl_chain_ingest::rebaseline::{baseline, ReplayFault};
use shekyl_chain_ingest::scenario::{FreeHash, Mined, Scenario};
use shekyl_chain_ingest::scenario_archival::{complete_tree, shard_set};
use shekyl_chain_ingest::scenario_shard::{
    close_shards_drawing, first_admissible_compact_join, inside_one_epoch_of, maturity, mine_to,
    settled_epoch_blocks, ClosedShard, FILL_FROM_COINBASE,
};
use shekyl_chain_ingest::schedule::ChainRules;
use shekyl_chain_ingest::source::SequenceNo;
use shekyl_chain_ingest::ProductionPow;
use shekyl_chain_ingest::Rewound;
use shekyl_chain_rules::{
    CappedEpoch, CenRow, ChainView as _, SettlementEpochBlocks, SettlementSchedule,
};
use shekyl_corpus::{CorpusFault, CorpusWriter, CORPUS_FORMAT_VERSION};
use shekyl_harness_spender::{MinerWallet, Owner, Persona, PostedBond, Recipient, Spender};
use shekyl_network::Network;
use shekyl_types::archival::SettlementOutcome;
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use checks::{harness_persona, HarnessFunding, LastReorg};
use seeds::{PlanDraws, Seeds, Source};

/// The corpus's file name in a forged chain's directory.
pub const CORPUS_FILE: &str = "corpus.e2";
/// The trace's.
pub const TRACE_FILE: &str = "trace.e2";
/// The manifest's.
pub const MANIFEST_FILE: &str = "manifest.json";
/// The KAT ledger's.
pub const BLOCKS_FILE: &str = "blocks.txt";
/// Every file a forging writes, in the order they are compared.
pub const FILES: [&str; 4] = [BLOCKS_FILE, MANIFEST_FILE, CORPUS_FILE, TRACE_FILE];

/// How one forging runs.
pub struct Options {
    /// The sources a negative control swaps to the OS's randomness.
    pub swapped: BTreeSet<Source>,
    /// A committed `blocks.txt`: stop at the first block that differs from
    /// it. A control's run ends there, red, without forging the rest.
    pub stop_at_difference: Option<BlocksTxt>,
    /// `form` workers hashing at once in the trace's replay.
    pub hashers: NonZeroUsize,
    /// How a `produce` step's producer runs.
    pub producer: ProducerOptions,
}

/// How a `produce` step's producer runs.
pub struct ProducerOptions {
    /// Draw every producer input from the OS, through the seams a node
    /// runs, instead of the plan's seed: the live cross-check's run
    /// (`CF-R18` (2)).
    pub live: bool,
    /// The spread each read's start delay is drawn below, in place of the
    /// plan's: a run that varies the timing on purpose (`CF-R18` (3)).
    /// `None` is the plan's own.
    pub start_spread: Option<std::time::Duration>,
}

impl Default for ProducerOptions {
    /// A planned run at the plan's own spread.
    fn default() -> Self {
        Self {
            live: false,
            start_spread: None,
        }
    }
}

/// A forged chain.
pub struct Forged {
    /// Its manifest, as written.
    pub manifest: Manifest,
    /// Its `blocks.txt`, as written.
    pub blocks: BlocksTxt,
    /// The harness persona's funding output and the block that listed it,
    /// for a walk's owner to check against the wallet it restores.
    pub harness_funding: Option<([u8; 32], BlockHeight)>,
}

/// What a forging came to.
pub enum Outcome {
    /// The plan ran to its end and every file is written.
    Forged(Box<Forged>),
    /// A block differed from the committed ledger
    /// ([`Options::stop_at_difference`]): the ledger up to it, and where.
    Differed {
        /// The lines written, the differing one last.
        blocks: BlocksTxt,
        /// The first difference.
        difference: Difference,
    },
}

/// Why a forging did not finish.
#[derive(Debug, thiserror::Error)]
pub enum ForgeFault {
    /// A file could not be written.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The corpus writer refused a record.
    #[error("corpus: {0}")]
    Corpus(#[from] CorpusFault),
    /// The trace's replay of the corpus failed.
    #[error("trace: {0}")]
    Replay(#[from] ReplayFault),
    /// The trace's hasher did not start.
    #[error("hasher: {0}")]
    Hasher(String),
    /// The plan asks for what the chain cannot do.
    #[error("plan: {0}")]
    Plan(String),
    /// A reorg's rewind was refused: the lowest block it would pop is below
    /// the store's undo floor. The plan's branch would be built on a chain
    /// the store did not pop, so the forging stops here.
    #[error("the rewind to {fork} was refused: the lowest poppable height is {floor}")]
    RewindRefused {
        /// The height the reorg forks at.
        fork: BlockHeight,
        /// The store's lowest poppable height.
        floor: BlockHeight,
    },
}

/// The rules `plan`'s chain is forged and replayed under: regtest at the
/// plan's settlement epoch and reorg cap, at difficulty 1.
///
/// # Errors
///
/// [`ForgeFault::Plan`] for a schedule regtest's levers refuse.
pub fn rules_for(plan: &Plan) -> Result<(ChainRules, CappedEpoch), ForgeFault> {
    let epoch_blocks = match plan.schedule.settlement_epoch_blocks {
        EpochBlocks::Settled => settled_epoch_blocks(),
        EpochBlocks::Blocks(blocks) => blocks,
    };
    let capped = CappedEpoch::new(
        SettlementEpochBlocks::new(epoch_blocks)
            .ok_or_else(|| ForgeFault::Plan("a settlement epoch of zero blocks".into()))?,
        BlockCount::from_raw(plan.schedule.reorg_cap_blocks),
    )
    .map_err(|refused| ForgeFault::Plan(format!("the schedule: {refused:?}")))?;
    let rules = ChainRules::new(Network::Regtest, Some(NonZeroU128::MIN), capped)
        .map_err(|refused| ForgeFault::Plan(format!("regtest's levers: {refused}")))?;
    Ok((rules, capped))
}

/// Forge `plan` (read from `plan_ref.path`) into `out`: the corpus, the
/// trace, the manifest and `blocks.txt`.
///
/// # Errors
///
/// [`ForgeFault`]. A block the validator refuses panics in the driver: a
/// plan the chain cannot carry is a broken plan, not a verdict.
pub async fn forge(
    plan: &Plan,
    plan_ref: PlanRef,
    out: &Path,
    options: Options,
) -> Result<Outcome, ForgeFault> {
    let hashers = options.hashers;
    let mut forge = Forge::open(plan, out, options).await?;
    if let Some(difference) = forge.run(plan).await? {
        forge.scenario.take().expect("home").close().await;
        return Ok(Outcome::Differed {
            blocks: forge.ledger,
            difference,
        });
    }
    forge
        .finish(plan, plan_ref, out, hashers)
        .await
        .map(|forged| Outcome::Forged(Box::new(forged)))
}

/// A persona the plan joined.
struct Joined {
    persona: Persona,
    /// The closed shards it holds, ascending; none for a complete tree.
    shards: Vec<ClosedShard>,
    join_epoch: SettlementEpoch,
    backing_key: [u8; 32],
    fee_key: [u8; 32],
    join_height: BlockHeight,
    /// The output its release paid it, and the block that listed it.
    released: Option<([u8; 32], BlockHeight)>,
}

impl Joined {
    /// The one shard a single-pair step reads.
    fn only_shard(&self) -> Result<ClosedShard, ForgeFault> {
        match self.shards.as_slice() {
            [shard] => Ok(*shard),
            held => Err(ForgeFault::Plan(format!(
                "this step reads one held shard; the persona holds {}",
                held.len()
            ))),
        }
    }
}

/// A block [`Forge::write_new`] appended, and the corpus record it occupies.
///
/// The record is assigned as the block is written. A rewind earlier in the
/// corpus makes the record differ from the height; counting back from the
/// tip would name the wrong record.
struct WrittenBlock {
    height: BlockHeight,
    record: u64,
}

/// One `shard-<k>-closed` event per close whose block is in `written`
/// (`CHAIN_FORGE.md` §11.2). The event's record is that block's record.
///
/// When the forging stopped early, closes past the last block written are
/// left unnamed: the manifest is not what a stopped forging publishes.
/// A close missing from a forging that ran to the end of the fill is an
/// invariant break.
fn close_events(
    closes: &[ClosedShard],
    written: &[WrittenBlock],
    stopped_early: bool,
) -> Vec<EventRecord> {
    let mut events = Vec::with_capacity(closes.len());
    for closed in closes {
        let height = closed.close_height;
        let Some(record) = written
            .iter()
            .rev()
            .find(|block| block.height == height)
            .map(|block| block.record)
        else {
            if stopped_early {
                break;
            }
            panic!(
                "shard {} closed at {height}, and this fill did not write that block",
                closed.shard
            );
        };
        events.push(EventRecord {
            name: close_event(closed.shard.to_raw()),
            height: height.to_raw(),
            branch: Branch::Main.to_string(),
            record,
        });
    }
    events
}

/// One forging's state: the live scenario and its chain, the corpus being
/// written, and what the plan has built so far.
pub struct Forge {
    /// Taken out while a driver helper owns it ([`mine_serving`]).
    scenario: Option<Scenario<FreeHash>>,
    /// The chain from block 0, each block at its height's place.
    chain: Vec<Mined>,
    /// Blocks of `chain` already in the corpus.
    written: usize,
    corpus: CorpusWriter<BufWriter<File>>,
    ledger: BlocksTxt,
    /// The branch new blocks are written on: [`Branch::Main`] as `extend`
    /// records, an alternative as `offer` records.
    branch: Branch,
    /// Alternative branches written so far; the next is `alt:<n + 1>`.
    alternatives: u32,
    /// The switches the plan's reorgs expect the fork choice to make.
    expected: Vec<SwitchRecord>,
    /// Corpus records written, blocks, rewinds and offers.
    records: u64,
    /// Transactions listed, coinbases excluded.
    transactions: u64,
    events: Vec<EventRecord>,
    seeds: Arc<Seeds>,
    /// The next spend's place in the plan (every spend's seeds are keyed
    /// by it).
    spends: u64,
    /// The next emission claim's place in the plan.
    claims: u64,
    /// The next coinbase kept for the plan's own spends and posts: the
    /// regtest miner's first is block 1's (block 0's pays the table's
    /// recipients), and a fill spends from [`FILL_FROM_COINBASE`] up.
    reserved: u64,
    /// The next coinbase at or above [`FILL_FROM_COINBASE`] that no fill
    /// and no kept spend has taken: a later fill starts here, and the
    /// plan's spends take from here once those below the fill are gone.
    above_fill: u64,
    /// The epoch of the last block a served step mined.
    last_served: Option<SettlementEpoch>,
    /// The first coinbase the plan's own spends take.
    first_kept: u64,
    /// The plan's reorg cap.
    reorg_cap: u64,
    /// Each main-chain height's corpus record and branch.
    record_at: Vec<(u64, Branch)>,
    /// The block the running step's event belongs to, when not the tip.
    event_at: Option<BlockHeight>,
    /// The last reorg the plan made.
    last_reorg: Option<LastReorg>,
    /// The harness persona's funding output.
    harness_funding: Option<HarnessFunding>,
    /// The block before the first admissible join a step mined to.
    join_eve: Option<BlockHeight>,
    closed: Vec<ClosedShard>,
    personas: BTreeMap<u32, Joined>,
    rules: ChainRules,
    schedule: SettlementSchedule,
    stop: Option<BlocksTxt>,
    stopped: Option<Difference>,
    built: Vec<Built>,
    producer: ProducerOptions,
}

impl Forge {
    /// Open a forging of `plan` into `out`: regtest's genesis connected and
    /// written, no step run.
    ///
    /// # Errors
    ///
    /// [`ForgeFault`].
    pub async fn open(plan: &Plan, out: &Path, options: Options) -> Result<Self, ForgeFault> {
        let seed = plan
            .seed()
            .map_err(|fault| ForgeFault::Plan(fault.to_string()))?;
        let (rules, capped) = rules_for(plan)?;

        std::fs::create_dir_all(out)?;
        let corpus = CorpusWriter::create(
            BufWriter::new(File::create(out.join(CORPUS_FILE))?),
            Network::Regtest,
            BlockHeight::ZERO,
        )?;
        let (scenario, genesis) =
            Scenario::open_regtest_mined(&format!("forge-{}", plan.chain), FreeHash, capped).await;
        let spacing = std::num::NonZeroU64::new(plan.block_seconds)
            .ok_or_else(|| ForgeFault::Plan("block_seconds is at least 1".into()))?;
        scenario.space_blocks(spacing);
        let first_kept = plan.first_kept_coinbase.unwrap_or(1);
        let mut forge = Self {
            scenario: Some(scenario),
            chain: vec![genesis],
            written: 0,
            corpus,
            ledger: BlocksTxt::new(),
            branch: Branch::Main,
            alternatives: 0,
            expected: Vec::new(),
            records: 0,
            transactions: 0,
            events: Vec::new(),
            seeds: Arc::new(Seeds::new(seed, options.swapped)),
            spends: 0,
            claims: 0,
            reserved: first_kept.min(FILL_FROM_COINBASE),
            above_fill: first_kept.max(FILL_FROM_COINBASE),
            last_served: None,
            first_kept,
            reorg_cap: plan.schedule.reorg_cap_blocks,
            record_at: Vec::new(),
            event_at: None,
            last_reorg: None,
            harness_funding: None,
            join_eve: None,
            closed: Vec::new(),
            personas: BTreeMap::new(),
            rules,
            schedule: capped.settlement(),
            stop: options.stop_at_difference,
            stopped: None,
            built: Vec::new(),
            producer: options.producer,
        };
        forge.write_new()?;
        Ok(forge)
    }

    /// Run every step of `plan`, indexing each named event. `Some` is the
    /// first block that differed from the committed ledger
    /// ([`Options::stop_at_difference`]); the forging stopped there.
    ///
    /// A fill's closes are events the step itself returns, one per shard,
    /// taken from the corpus record [`write_new`] assigned that block.
    ///
    /// # Errors
    ///
    /// [`ForgeFault`].
    pub async fn run(&mut self, plan: &Plan) -> Result<Option<Difference>, ForgeFault> {
        for step in &plan.steps {
            if self.stopped.is_none() {
                let named = self.step(&step.action).await?;
                self.events.extend(named);
            }
            if let Some(difference) = self.stopped.take() {
                return Ok(Some(difference));
            }
            if let Some(name) = &step.event {
                let tip = self.chain.last().expect("genesis at least").height;
                let height = self.event_at.take().unwrap_or(tip);
                let (written_at, branch) =
                    self.record_at[usize::try_from(height.to_raw()).expect("a height fits")];
                // A block written as an offer is on the chain only from the
                // record its branch won at: a snapshot stopped earlier does
                // not hold it.
                let record = match branch {
                    Branch::Main => written_at,
                    Branch::Alt(_) => self
                        .expected
                        .iter()
                        .map(|switch| switch.at_record)
                        .filter(|at| *at >= written_at)
                        .min()
                        .expect("an offered block on the chain is on a branch that won"),
                };
                self.events.push(EventRecord {
                    name: name.clone(),
                    height: height.to_raw(),
                    branch: branch.to_string(),
                    record,
                });
            }
        }
        Ok(None)
    }

    /// The live scenario.
    pub fn scenario(&mut self) -> &mut Scenario<FreeHash> {
        self.scenario
            .as_mut()
            .expect("the scenario is home between steps")
    }

    /// The chain from block 0, each block at its height's place.
    #[must_use]
    pub fn chain(&self) -> &[Mined] {
        &self.chain
    }

    /// The rules the chain runs.
    #[must_use]
    pub const fn rules(&self) -> ChainRules {
        self.rules
    }

    /// The settlement schedule the plan's epochs run on.
    #[must_use]
    pub const fn schedule(&self) -> SettlementSchedule {
        self.schedule
    }

    /// Every body the plan built, in the order it built them.
    #[must_use]
    pub fn built(&self) -> &[Built] {
        &self.built
    }

    /// Persona `slot`, as the plan joined it.
    #[must_use]
    pub fn persona(&self, slot: u32) -> Option<&Persona> {
        self.personas.get(&slot).map(|joined| &joined.persona)
    }

    /// The live scenario beside persona `slot`: a caller that drives the
    /// chain while the persona signs holds both.
    pub fn scenario_with(&mut self, slot: u32) -> (&mut Scenario<FreeHash>, Option<&Persona>) {
        (
            self.scenario
                .as_mut()
                .expect("the scenario is home between steps"),
            self.personas.get(&slot).map(|joined| &joined.persona),
        )
    }

    /// The witness the plan's blocks commit their draws to: its key and its
    /// draws from the plan's seed.
    #[must_use]
    pub fn witness(&self) -> DriverWitness {
        let (key_ed, key_fn) = self.seeds.witness_key();
        DriverWitness::keyed(
            &key_ed,
            &key_fn,
            Box::new(PlanDraws(Arc::clone(&self.seeds))),
        )
    }

    /// Stop the scenario without finishing the chain: a forging a test held
    /// open and is done with.
    pub async fn abandon(mut self) {
        self.scenario.take().expect("home").close().await;
    }

    /// The height the next block connects at.
    fn connecting(&self) -> BlockHeight {
        BlockHeight::from_raw(u64::try_from(self.chain.len()).expect("a chain's length fits"))
    }

    /// A spender over the chain as it stands.
    fn spender(&mut self) -> Spender {
        let network = self.scenario().network_id();
        Spender::on(network, &self.chain)
    }

    /// The next spend's place in the plan.
    fn next_spend(&mut self) -> u64 {
        let index = self.spends;
        self.spends += 1;
        index
    }

    /// The next kept coinbase, matured for a block at `connecting`.
    fn reserve(&mut self, connecting: BlockHeight) -> Result<BlockHeight, ForgeFault> {
        let below_fill = self.reserved < FILL_FROM_COINBASE;
        let coinbase = if below_fill {
            self.reserved
        } else {
            self.above_fill
        };
        if coinbase + maturity() > connecting.to_raw() {
            return Err(ForgeFault::Plan(format!(
                "coinbase {coinbase} is not spendable at {connecting}: mine to {} first",
                coinbase + maturity()
            )));
        }
        if below_fill {
            self.reserved += 1;
        } else {
            self.above_fill += 1;
        }
        Ok(BlockHeight::from_raw(coinbase))
    }

    /// Write every block of the chain not yet in the corpus, and its line.
    /// With a committed ledger to stop at, the first line that differs from
    /// it ends the run ([`Outcome::Differed`]).
    ///
    /// Each returned block carries the corpus record it was written at, so a
    /// later event names that record instead of counting back from the tip.
    fn write_new(&mut self) -> Result<Vec<WrittenBlock>, ForgeFault> {
        let mut written_blocks = Vec::new();
        while self.written < self.chain.len() {
            let mined = &self.chain[self.written];
            let block = mined.template.block.serialize();
            let listed: Vec<Vec<u8>> = mined
                .template
                .transactions
                .iter()
                .map(shekyl_wire::Transaction::serialize)
                .collect();
            let references: Vec<Vec<u8>> = mined
                .bundle_references
                .as_ref()
                .map(|section| section.as_slice().to_vec())
                .unwrap_or_default();
            let bodies: Vec<Vec<u8>> = mined
                .bundle_bodies
                .iter()
                .map(|body| body.as_bytes().to_vec())
                .collect();
            match self.branch {
                Branch::Main => {
                    self.corpus
                        .append_carrying(&block, &listed, &references, &bodies)?
                }
                Branch::Alt(_) => self.corpus.offer(&block, &listed, &references, &bodies)?,
            }
            let record = self.records;
            self.records += 1;
            self.record_at.truncate(self.written);
            self.record_at.push((record, self.branch));
            written_blocks.push(WrittenBlock {
                height: mined.height,
                record,
            });
            // A listing that skipped the pool stops the forge here, whichever
            // step built the block (`CHAIN_FORGE.md` §11.4).
            assert!(
                mined.pool_passage_agrees(),
                "block {} lists transactions the daemon's pool never admitted",
                mined.height
            );
            self.transactions += u64::try_from(listed.len()).expect("a block's list fits");
            let line = Line {
                height: mined.height.to_raw(),
                branch: self.branch,
                id: *mined.hash.as_bytes(),
            };
            self.ledger.push(line);
            self.written += 1;
            if let Some(committed) = &self.stop {
                let at = self.ledger.lines().len();
                if committed.lines().get(at - 1) != Some(&line) {
                    self.stopped = Some(Difference {
                        line: at,
                        ours: Some(line),
                        theirs: committed.lines().get(at - 1).copied(),
                    });
                    return Ok(written_blocks);
                }
            }
        }
        Ok(written_blocks)
    }

    async fn step(&mut self, action: &Action) -> Result<Vec<EventRecord>, ForgeFault> {
        let mut closes = Vec::new();
        match action {
            Action::Mine { blocks } => {
                let mined = self.scenario().mine(*blocks).await;
                self.chain.extend(mined);
            }
            Action::Spend { inputs, outputs } => match outputs {
                None => self.spend(*inputs).await?,
                Some(outputs) => self.spend_paying(*inputs, *outputs).await?,
            },
            Action::MineTo { epoch, offset } => {
                let to = BlockHeight::from_raw(epoch * self.schedule.blocks().get() + offset + 1);
                self.mine_until(to).await;
            }
            Action::MineBeforeJoin { shards } => self.mine_before_join(shards).await?,
            Action::FundHarness => self.fund_harness().await?,
            Action::FillBlock { to } => self.fill_block(*to).await?,
            Action::ServeTo {
                persona,
                epoch,
                offset,
                withhold,
            } => {
                self.serve_to_height(
                    *persona,
                    epoch * self.schedule.blocks().get() + offset,
                    *withhold,
                )
                .await?;
            }
            Action::Check {
                what,
                persona,
                shard,
            } => self.event_at = self.check(*what, *persona, *shard).await?,
            Action::FillShards { count } => closes = self.fill(*count).await,
            Action::Join { persona, shards } => self.join(*persona, shards).await?,
            Action::Serve { persona } => self.serve(*persona).await?,
            Action::Claim { persona } => claim::step(self, *persona).await?,
            Action::Reorg { depth } => self.reorg(*depth).await?,
            Action::JoinTree { persona } => self.join_tree(*persona).await?,
            Action::ServeEpochs {
                persona,
                epochs,
                withhold,
            } => self.serve_epochs(*persona, *epochs, *withhold).await?,
            Action::Slash { persona, shard } => self.slash(*persona, *shard).await?,
            Action::Reinstate { persona } => self.reinstate(*persona).await?,
            Action::Release { persona } => self.release(*persona).await?,
            Action::Collect { persona } => self.collect(*persona).await?,
            Action::SpendDiscarded { shard } => self.spend_discarded(*shard).await?,
            Action::Produce {
                persona,
                start_spread_ms,
            } => {
                let spread = self
                    .producer
                    .start_spread
                    .unwrap_or(std::time::Duration::from_millis(*start_spread_ms));
                produce::step(self, *persona, spread).await?;
            }
        }
        let written = self.write_new()?;
        Ok(close_events(&closes, &written, self.stopped.is_some()))
    }

    /// The miner spends `inputs` kept coinbases in one transaction, paying
    /// what the daemon asks of it (`CHAIN_FORGE.md` §11.4).
    async fn spend(&mut self, inputs: u32) -> Result<(), ForgeFault> {
        let connecting = self.connecting();
        let heights = (0..inputs)
            .map(|_| self.reserve(connecting))
            .collect::<Result<Vec<_>, _>>()?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        let (sized, _) = spender.spend_coinbases(wallet, &heights, connecting, SIZING_FEE);
        let (spend, _) = spender.drawing(seeds).spend_coinbases(
            wallet,
            &heights,
            connecting,
            fee_at(&sized, rate),
        );
        assert_priced(&spend, &sized, rate);
        self.built.push(Built {
            body: spend.clone(),
            connecting,
            kind: BuiltKind::Spend { coinbases: heights },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![spend])
            .await
            .unwrap_or_else(|fault| panic!("the plan's spend connects: {fault}"));
        self.chain.push(block);
        Ok(())
    }

    /// One kept coinbase spent to the miner in `outputs` outputs, listed in
    /// the next block (CF-E3).
    async fn spend_paying(&mut self, inputs: u32, outputs: u32) -> Result<(), ForgeFault> {
        if inputs != 1 {
            return Err(ForgeFault::Plan(
                "a spend that names its outputs has one input".into(),
            ));
        }
        let outputs = usize::try_from(outputs).expect("a count fits");
        let connecting = self.connecting();
        let coinbase = self.reserve(connecting)?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        let sized =
            spender.spend_coinbase_paying(wallet, coinbase, connecting, SIZING_FEE, outputs);
        let body = spender.drawing(seeds).spend_coinbase_paying(
            wallet,
            coinbase,
            connecting,
            fee_at(&sized, rate),
            outputs,
        );
        assert_priced(&body, &sized, rate);
        assert_eq!(body.prefix.outputs.len(), outputs, "the spend's outputs");
        self.built.push(Built {
            body: body.clone(),
            connecting,
            kind: BuiltKind::Paying { coinbase },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![body])
            .await
            .unwrap_or_else(|fault| panic!("the plan's spend connects: {fault}"));
        self.chain.push(block);
        Ok(())
    }

    /// Mine empty blocks until the next block connects at `to`.
    async fn mine_until(&mut self, to: BlockHeight) {
        let mut chain = std::mem::take(&mut self.chain);
        mine_to(self.scenario.as_mut().expect("home"), &mut chain, to).await;
        self.chain = chain;
    }

    /// [`Action::MineBeforeJoin`].
    async fn mine_before_join(&mut self, shards: &[u64]) -> Result<(), ForgeFault> {
        let mut admissible = None;
        for id in shards {
            let close = self.close_of(*id)?;
            let height = first_admissible_compact_join(&self.rules, close);
            admissible = admissible.max(Some(height));
        }
        let admissible =
            admissible.ok_or_else(|| ForgeFault::Plan("a join holds a closed shard".into()))?;
        let join_height = inside_one_epoch_of(self.schedule, admissible, 1);
        self.mine_until(join_height).await;
        self.join_eve = Some(
            join_height
                .checked_sub_count(BlockCount::ONE)
                .expect("a join is above genesis"),
        );
        Ok(())
    }

    /// [`Action::FundHarness`].
    async fn fund_harness(&mut self) -> Result<(), ForgeFault> {
        if self.harness_funding.is_some() {
            return Err(ForgeFault::Plan(
                "the harness persona is funded once: its bond post consumes every funding output"
                    .into(),
            ));
        }
        let connecting = self.connecting();
        let coinbase = self.reserve(connecting)?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        let harness = harness_persona();
        let recipient = Recipient::persona(harness.keys());
        let sized =
            spender.spend_coinbase_to(wallet, coinbase, connecting, SIZING_FEE, None, &recipient);
        let body = spender.drawing(seeds).spend_coinbase_to(
            wallet,
            coinbase,
            connecting,
            fee_at(&sized, rate),
            None,
            &recipient,
        );
        assert_priced(&body, &sized, rate);
        let output_key = body.prefix.outputs[0].key;
        self.built.push(Built {
            body: body.clone(),
            connecting,
            kind: BuiltKind::Funding { coinbase },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![body])
            .await
            .unwrap_or_else(|fault| panic!("the harness funding connects: {fault}"));
        self.chain.push(block);
        self.harness_funding = Some(HarnessFunding {
            output_key,
            paid_at: connecting,
        });
        Ok(())
    }

    /// [`Action::FillBlock`]: real spends of kept coinbases, as many as
    /// reach the weight `to` names over the median the tip was judged at.
    /// The block's own verdict then holds the count to it.
    async fn fill_block(&mut self, to: FillTo) -> Result<(), ForgeFault> {
        let connecting = self.connecting();
        let params = shekyl_economics::EconomicParams::default();
        let before = self.chain.last().expect("genesis at least");
        if !before.template.transactions.is_empty() {
            return Err(ForgeFault::Plan(
                "a filled block follows one that lists nothing: its weight is the coinbase's"
                    .into(),
            ));
        }
        let coinbase_weight = before.weights.weight.to_raw();
        let median = before.weights.medians.effective_median.to_raw();
        let limit = before.weights.medians.limit(&params).to_raw();
        let first = self.reserve(connecting)?;
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let sized = spender.spend_coinbase(self.scenario().wallet(), first, connecting, SIZING_FEE);
        let fee = fee_at(&sized, rate);
        let body_weight = u64::try_from(sized.weight()).expect("a weight fits");
        let count = match to {
            FillTo::Median => median.saturating_sub(coinbase_weight) / body_weight + 1,
            FillTo::Bound => limit.saturating_sub(coinbase_weight) / body_weight,
        };
        let mut coinbases = vec![first];
        for _ in 1..count {
            coinbases.push(self.reserve(connecting)?);
        }
        let seeds: Vec<_> = coinbases
            .iter()
            .map(|_| {
                let spend = self.next_spend();
                self.seeds.spend(spend)
            })
            .collect();
        let wallet = self.scenario.as_ref().expect("home").wallet();
        let listed: Vec<shekyl_wire::Transaction> = std::thread::scope(|scope| {
            let handles: Vec<_> = coinbases
                .iter()
                .zip(seeds)
                .map(|(&coinbase, seeds)| {
                    let (spender, sized) = (&spender, &sized);
                    scope.spawn(move || {
                        let body = spender
                            .drawing(seeds)
                            .spend_coinbase(wallet, coinbase, connecting, fee);
                        assert_priced(&body, sized, rate);
                        body
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("a spend builds"))
                .collect()
        });
        for (body, coinbase) in listed.iter().zip(&coinbases) {
            self.built.push(Built {
                body: body.clone(),
                connecting,
                kind: BuiltKind::Spend {
                    coinbases: vec![*coinbase],
                },
            });
        }
        let block = self
            .scenario()
            .mine_admitted(listed)
            .await
            .unwrap_or_else(|fault| panic!("the filled block connects: {fault}"));
        let weight = block.weights.weight.to_raw();
        let in_force = block.weights.medians.effective_median.to_raw();
        let limit = block.weights.medians.limit(&params).to_raw();
        let reaches = match to {
            FillTo::Median => weight > in_force && weight - body_weight <= in_force,
            FillTo::Bound => weight <= limit && weight + body_weight > limit,
        };
        if !reaches {
            return Err(ForgeFault::Plan(format!(
                "the {to:?} block weighs {weight}: median {in_force}, limit {limit}, body {body_weight}"
            )));
        }
        self.chain.push(block);
        Ok(())
    }

    /// [`Action::ServeTo`].
    async fn serve_to_height(
        &mut self,
        slot: u32,
        height: u64,
        withhold: Option<u64>,
    ) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let withheld = withhold.map(|shard| (joined.persona.id(), ShardId::from_raw(shard)));
        self.serve_until(withheld, BlockHeight::from_raw(height))
            .await;
        Ok(())
    }

    /// Real spends until `count` shards are closed (S9). The new closes, in
    /// the order the fold counted them.
    async fn fill(&mut self, count: u64) -> Vec<ClosedShard> {
        let seeds = Arc::clone(&self.seeds);
        let mut next = self.spends;
        let mut chain = std::mem::take(&mut self.chain);
        let first_coinbase = self.above_fill;
        let first_spend = next;
        let filled = close_shards_drawing(
            self.scenario.as_mut().expect("home"),
            &mut chain,
            first_coinbase,
            count,
            || {
                let index = next;
                next += 1;
                seeds.fill_spend(index)
            },
        )
        .await;
        self.chain = chain;
        self.above_fill = first_coinbase + (next - first_spend);
        self.spends = next;
        self.closed.extend(filled.closed.iter().copied());
        filled.closed
    }

    /// Persona `slot` joins `shards`, funded by a kept coinbase.
    async fn join(&mut self, slot: u32, shards: &[u64]) -> Result<(), ForgeFault> {
        let closes: Vec<ClosedShard> = shards
            .iter()
            .map(|id| {
                self.closed
                    .iter()
                    .find(|closed| closed.shard == ShardId::from_raw(*id))
                    .copied()
                    .ok_or_else(|| ForgeFault::Plan(format!("shard {id} is not closed")))
            })
            .collect::<Result<_, _>>()?;
        // Admissible once every held shard is: the latest of their heights.
        let admissible = closes
            .iter()
            .map(|close| first_admissible_compact_join(&self.rules, *close))
            .max()
            .ok_or_else(|| ForgeFault::Plan("a compact join holds a closed shard".into()))?;
        // The join and the block after it sit in one epoch, neither a close.
        let join_height = inside_one_epoch_of(self.schedule, admissible, 1);
        self.post_join(slot, shard_set(shards.to_vec()), closes, join_height)
            .await
    }

    /// Persona `slot` joins as a complete tree at the next height that
    /// sits, with the block after it, inside one epoch.
    async fn join_tree(&mut self, slot: u32) -> Result<(), ForgeFault> {
        let join_height = inside_one_epoch_of(self.schedule, self.connecting(), 1);
        self.post_join(slot, complete_tree(), Vec::new(), join_height)
            .await
    }

    /// The join block: persona `slot` funded by a kept coinbase whose spend
    /// carries its join of `holdings`, at `join_height`.
    async fn post_join(
        &mut self,
        slot: u32,
        holdings: shekyl_archival_retention::HoldingsDescriptor,
        closes: Vec<ClosedShard>,
        join_height: BlockHeight,
    ) -> Result<(), ForgeFault> {
        let shards: Vec<u64> = closes.iter().map(|close| close.shard.to_raw()).collect();
        let mut chain = std::mem::take(&mut self.chain);
        mine_to(
            self.scenario.as_mut().expect("home"),
            &mut chain,
            join_height,
        )
        .await;
        self.chain = chain;
        self.write_new()?;
        if self.stopped.is_some() {
            return Ok(());
        }
        let persona =
            Persona::from_master(&self.seeds.persona_master(slot), Network::Regtest, slot)
                .with_signing_seed(&self.seeds.persona_signing(slot));
        let recipient = Recipient::persona(persona.keys());
        let coinbase = self.reserve(join_height)?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        // The sizing build's post is signed from the OS's randomness, by the
        // same persona's keys: the seeded persona signs one post, the one
        // listed (`crate::priced`'s reason).
        let sizing = Persona::from_master(&self.seeds.persona_master(slot), Network::Regtest, slot);
        let sized = spender.spend_coinbase_to(
            wallet,
            coinbase,
            join_height,
            SIZING_FEE,
            Some(&sizing.join(holdings.clone(), ENDPOINT)),
            &recipient,
        );
        let join = persona.join(holdings, ENDPOINT);
        let funding = spender.drawing(seeds).spend_coinbase_to(
            wallet,
            coinbase,
            join_height,
            fee_at(&sized, rate),
            Some(&join),
            &recipient,
        );
        assert_priced(&funding, &sized, rate);
        let backing_key = funding.prefix.outputs[0].key;
        let fee_key = funding.prefix.outputs[1].key;
        self.built.push(Built {
            body: funding.clone(),
            connecting: join_height,
            kind: BuiltKind::Join {
                coinbase,
                slot,
                shards,
            },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![funding])
            .await
            .unwrap_or_else(|fault| panic!("the join connects: {fault}"));
        assert_eq!(block.height, join_height);
        assert!(
            block.judged_by.contains(&CenRow::J15),
            "J15 judged the join"
        );
        self.chain.push(block);
        let join_epoch = self.schedule.epoch_at(join_height);
        self.personas.insert(
            slot,
            Joined {
                persona,
                shards: closes,
                join_epoch,
                backing_key,
                fee_key,
                join_height,
                released: None,
            },
        );
        Ok(())
    }

    /// Mine through the first epoch persona `slot` is drawn in, with the
    /// chain's draws admitted and every draw served (S7, S8).
    async fn serve(&mut self, slot: u32) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let served = SettlementEpoch::from_raw(joined.join_epoch.to_raw() + 1);
        let until = BlockHeight::from_raw((served.to_raw() + 1) * self.schedule.blocks().get());
        let witness = self.witness();
        let scenario = self.scenario.take().expect("home");
        let chain = std::mem::take(&mut self.chain);
        let (scenario, chain) =
            mine_serving(scenario, chain, &witness, &[&joined.persona], until).await;
        let shard = joined.only_shard()?.shard;
        assert_issued_pair(&scenario, served, (joined.persona.id(), shard));
        self.scenario = Some(scenario);
        self.chain = chain;
        Ok(())
    }

    /// Mine to `until` with every block's draws committed and filed: every
    /// joined persona passes its draws, except the one pair `withheld`.
    async fn serve_until(&mut self, withheld: Option<(PCanonicalId, ShardId)>, until: BlockHeight) {
        let witness = self.witness();
        let mut drive = Driven::begin(
            self.scenario.take().expect("home"),
            std::mem::take(&mut self.chain),
        );
        {
            let signers: Vec<&Persona> = self
                .personas
                .values()
                .map(|joined| &joined.persona)
                .collect();
            let passes = move |_: BlockHeight, target: &DrawTarget| {
                withheld != Some((target.persona, target.shard))
            };
            serve_to(&mut drive, &witness, &signers, &passes, until).await;
        }
        let (scenario, chain) = drive.into_parts();
        self.scenario = Some(scenario);
        self.chain = chain;
        let tip = self.chain.last().expect("genesis at least").height;
        self.last_served = Some(self.schedule.epoch_at(tip));
    }

    /// [`Action::ServeEpochs`].
    async fn serve_epochs(
        &mut self,
        slot: u32,
        epochs: u64,
        withhold: Option<u64>,
    ) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let through = joined.join_epoch.to_raw() + epochs;
        let withheld = withhold.map(|shard| (joined.persona.id(), ShardId::from_raw(shard)));
        let at_pass = BlockHeight::from_raw(self.schedule.slash_deadline_height(through));
        self.serve_until(withheld, at_pass).await;
        let mut chain = std::mem::take(&mut self.chain);
        mine_to(
            self.scenario.as_mut().expect("home"),
            &mut chain,
            at_pass + BlockCount::ONE,
        )
        .await;
        self.chain = chain;
        Ok(())
    }

    /// [`Action::Slash`]: the pass of each epoch is read as it lands, and
    /// the step ends after the one that slashes the withheld pair.
    async fn slash(&mut self, slot: u32, shard: u64) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let persona = joined.persona.id();
        let join_epoch = joined.join_epoch.to_raw();
        let held = ShardId::from_raw(shard);
        let needed = failure_window_epochs();
        let mut misses = 0u64;
        let mut outcomes = Vec::new();
        for epoch in join_epoch + 1..=join_epoch + 3 * needed {
            let deadline = self.schedule.slash_deadline_height(epoch);
            let after_pass = BlockHeight::from_raw(deadline + 1);
            if self.connecting() < after_pass {
                self.serve_until(Some((persona, held)), after_pass).await;
            }
            let pass = &self.chain[usize::try_from(deadline).expect("small")].archival;
            let outcome = pass
                .settlements()
                .iter()
                .find(|row| {
                    row.epoch.to_raw() == epoch && row.persona == persona && row.shard == held
                })
                .map(|row| row.row.outcome());
            outcomes.push((epoch, outcome));
            misses += u64::from(outcome == Some(SettlementOutcome::Missed));
            let slashed = pass
                .slashes()
                .iter()
                .any(|slash| slash.entry.persona == persona && slash.entry.shard == held);
            if slashed != (outcome == Some(SettlementOutcome::Missed) && misses == needed) {
                return Err(ForgeFault::Plan(format!(
                    "epoch {epoch}: the slash is the pass of miss {needed}; settled {outcomes:?}"
                )));
            }
            if slashed {
                return Ok(());
            }
        }
        Err(ForgeFault::Plan(format!(
            "no slash of shard {shard} in three failure windows; settled {outcomes:?}"
        )))
    }

    /// A kept coinbase's spend carrying the post `make` builds for persona
    /// `slot`, in the next block, paying the persona when `pays_persona`.
    async fn post(
        &mut self,
        slot: u32,
        pays_persona: bool,
        make: impl for<'p> Fn(&'p Persona) -> PostedBond<'p>,
    ) -> Result<shekyl_wire::Transaction, ForgeFault> {
        if !self.personas.contains_key(&slot) {
            return Err(ForgeFault::Plan(format!("persona {slot} has not joined")));
        }
        let connecting = self.connecting();
        let coinbase = self.reserve(connecting)?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let rate = self.scenario().connecting_default_rate().await;
        let spender = self.spender();
        let body = {
            let wallet = self.scenario.as_ref().expect("home").wallet();
            let persona = &self.personas[&slot].persona;
            let recipient = if pays_persona {
                Recipient::persona(persona.keys())
            } else {
                wallet.recipient().clone()
            };
            // The sizing post is signed from the OS's randomness, by the
            // same persona's keys (`crate::priced`'s reason).
            let sizing =
                Persona::from_master(&self.seeds.persona_master(slot), Network::Regtest, slot);
            let sized = spender.spend_coinbase_to(
                wallet,
                coinbase,
                connecting,
                SIZING_FEE,
                Some(&make(&sizing)),
                &recipient,
            );
            let body = spender.drawing(seeds).spend_coinbase_to(
                wallet,
                coinbase,
                connecting,
                fee_at(&sized, rate),
                Some(&make(persona)),
                &recipient,
            );
            assert_priced(&body, &sized, rate);
            body
        };
        self.built.push(Built {
            body: body.clone(),
            connecting,
            kind: BuiltKind::Post { coinbase, slot },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![body.clone()])
            .await
            .unwrap_or_else(|fault| panic!("persona {slot}'s post connects: {fault}"));
        self.chain.push(block);
        Ok(body)
    }

    /// Persona `id`'s stored bond record, which must exist.
    async fn bond_record(&self, id: PCanonicalId) -> shekyl_types::archival::BondRecord {
        self.scenario
            .as_ref()
            .expect("home")
            .bond_record(id)
            .await
            .expect("the store answers")
            .expect("the persona has a record")
    }

    /// [`Action::Reinstate`].
    async fn reinstate(&mut self, slot: u32) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let id = joined.persona.id();
        let record = self.bond_record(id).await;
        self.post(slot, false, |persona| persona.reinstate(&record))
            .await?;
        Ok(())
    }

    /// [`Action::Release`].
    async fn release(&mut self, slot: u32) -> Result<(), ForgeFault> {
        let last = self
            .last_served
            .ok_or_else(|| ForgeFault::Plan("a release follows a served epoch".into()))?;
        let opens = BlockHeight::from_raw(
            self.schedule
                .open_height(last.to_raw() + RELEASE_COOLDOWN_EPOCHS),
        );
        let mut chain = std::mem::take(&mut self.chain);
        mine_to(self.scenario.as_mut().expect("home"), &mut chain, opens).await;
        self.chain = chain;
        self.write_new()?;
        if self.stopped.is_some() {
            return Ok(());
        }
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let id = joined.persona.id();
        let bonded = self.bond_record(id).await.bonded_total.to_raw();
        let connecting = self.connecting();
        let body = self
            .post(slot, true, |persona| persona.release(bonded))
            .await?;
        let paid = body.prefix.outputs[0].key;
        self.personas.get_mut(&slot).expect("checked").released = Some((paid, connecting));
        Ok(())
    }

    /// One owned output spent in the next block once it is spendable.
    async fn spend_output(
        &mut self,
        owner: &Owner<'_>,
        output_key: [u8; 32],
        paid_at: BlockHeight,
        recipient: &Recipient,
    ) {
        let connecting = self.connecting();
        let network = self.scenario().network_id();
        let spender = spender_owning_before(network, &self.chain, paid_at, &[output_key]);
        let sized = spender.spend_owned(
            vec![spender.owned_input(owner, output_key, connecting)],
            connecting,
            SIZING_FEE,
            recipient,
        );
        let rate = self.scenario().connecting_default_rate().await;
        let spend = self.next_spend();
        let body = spender.drawing(self.seeds.spend(spend)).spend_owned(
            vec![spender.owned_input(owner, output_key, connecting)],
            connecting,
            fee_at(&sized, rate),
            recipient,
        );
        assert_priced(&body, &sized, rate);
        self.built.push(Built {
            body: body.clone(),
            connecting,
            kind: BuiltKind::Owned { output_key },
        });
        let block = self
            .scenario()
            .mine_admitted(vec![body])
            .await
            .unwrap_or_else(|fault| panic!("the owned spend connects: {fault}"));
        self.chain.push(block);
    }

    /// [`Action::Collect`].
    async fn collect(&mut self, slot: u32) -> Result<(), ForgeFault> {
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not joined")))?;
        let (paid, listed) = joined
            .released
            .ok_or_else(|| ForgeFault::Plan(format!("persona {slot} has not released")))?;
        let spendable = listed + BlockCount::from_raw(maturity());
        let mut chain = std::mem::take(&mut self.chain);
        mine_to(self.scenario.as_mut().expect("home"), &mut chain, spendable).await;
        self.chain = chain;
        self.write_new()?;
        if self.stopped.is_some() {
            return Ok(());
        }
        // The persona's keys are read through a copy of its master: the
        // spend borrows the forge mutably while it signs.
        let persona =
            Persona::from_master(&self.seeds.persona_master(slot), Network::Regtest, slot);
        let owner = Owner::persona(persona.keys());
        let recipient = Recipient::persona(persona.keys());
        self.spend_output(&owner, paid, listed, &recipient).await;
        Ok(())
    }

    /// [`Action::SpendDiscarded`]: output 0 of the first spend in the block
    /// before the shard's close, which the shard's body carries.
    async fn spend_discarded(&mut self, shard: u64) -> Result<(), ForgeFault> {
        let closed = self.close_of(shard)?;
        let discarded = self.discard_boundary(closed);
        if self.connecting() <= discarded {
            return Err(ForgeFault::Plan(format!(
                "shard {shard}'s bodies are discarded at {discarded}; the tip is below it"
            )));
        }
        let paid_at = closed
            .close_height
            .checked_sub_count(BlockCount::ONE)
            .expect("a shard closes above genesis");
        let block = &self.chain[usize::try_from(paid_at.to_raw()).expect("small")];
        let output_key = block
            .template
            .transactions
            .first()
            .ok_or_else(|| ForgeFault::Plan(format!("block {paid_at} lists no spend")))?
            .prefix
            .outputs[0]
            .key;
        let wallet = MinerWallet::harness_regtest();
        let owner = Owner::miner(wallet);
        self.spend_output(&owner, output_key, paid_at, wallet.recipient())
            .await;
        Ok(())
    }

    /// A competing branch of `depth + 1` blocks from `depth` below the tip,
    /// the first listing a spend of a kept coinbase the branch it competes
    /// with did not list, written as `offer` records on a new alternative
    /// branch after the blocks it competes with.
    ///
    /// The scenario pops to the fork and mines the branch there, so every
    /// block of it is built on its own chain's facts and is the block a
    /// rival miner would have sent. The forge's own chain takes the branch
    /// by that pop; the replay that produces the trace meets it as a node
    /// does, as blocks that arrive and do not extend its tip, and switches
    /// through the fork choice once the branch is heavier. At a fixed
    /// difficulty that is its last block, `depth + 1` against `depth`: the
    /// switch the plan expects, which [`Forge::finish`] holds the replay's
    /// derived switch to.
    async fn reorg(&mut self, depth: u64) -> Result<(), ForgeFault> {
        let tip = self.chain.last().expect("genesis at least").height;
        let fork = tip
            .checked_sub_count(BlockCount::from_raw(depth))
            .ok_or_else(|| ForgeFault::Plan(format!("a reorg of {depth} below genesis")))?;
        // The tree at the fork and above the popped tip: the rewind must
        // restore the first, and the two say whether it crossed a chunk.
        let above_tip = tip + BlockCount::ONE;
        let above_fork = fork + BlockCount::ONE;
        let (at_fork, leaves_above_fork, leaves_above_tip) = self
            .scenario()
            .read_chain(move |view, _| {
                let leaves = |height| match view.leaf_count_at(height).expect("the count reads") {
                    shekyl_chain_rules::AtHeight::Recorded(count) => count,
                    shekyl_chain_rules::AtHeight::AboveTip => {
                        unreachable!("one past the tip is the next drain's count")
                    }
                };
                (
                    (
                        view.root_at(above_fork).expect("the root reads"),
                        view.depth_at(above_fork).expect("the depth reads"),
                        leaves(above_fork),
                    ),
                    leaves(above_fork),
                    leaves(above_tip),
                )
            })
            .await;
        match self
            .scenario()
            .rewind_to(fork)
            .await
            .unwrap_or_else(|fault| panic!("the rewind to {fork}: {fault:?}"))
        {
            Rewound::Popped { .. } => {}
            Rewound::Refused { floor, .. } => {
                return Err(ForgeFault::RewindRefused { fork, floor })
            }
        }
        let after = self
            .scenario()
            .read_chain(move |view, _| {
                (
                    view.root_at(above_fork).expect("the root reads"),
                    view.depth_at(above_fork).expect("the depth reads"),
                    match view.leaf_count_at(above_fork).expect("the count reads") {
                        shekyl_chain_rules::AtHeight::Recorded(count) => count,
                        shekyl_chain_rules::AtHeight::AboveTip => {
                            unreachable!("one past the tip is the next drain's count")
                        }
                    },
                )
            })
            .await;
        self.last_reorg = Some(LastReorg {
            fork,
            popped_tip: tip,
            leaves_above_fork,
            leaves_above_tip,
            restored: after == at_fork,
        });
        self.chain
            .truncate(usize::try_from(fork.to_raw() + 1).expect("a height fits"));
        self.written = self.chain.len();
        self.alternatives += 1;
        self.branch = Branch::Alt(self.alternatives);
        self.spend(1).await?;
        let rest = self.scenario().mine(depth).await;
        self.chain.extend(rest);
        self.write_new()?;
        self.branch = Branch::Main;
        self.expected.push(SwitchRecord {
            at_record: self.records - 1,
            fork_height: fork.to_raw(),
            depth,
        });
        Ok(())
    }

    /// Close the corpus and the scenario, replay the corpus into the trace,
    /// and write the manifest and `blocks.txt`.
    ///
    /// # Errors
    ///
    /// [`ForgeFault`].
    pub async fn finish(
        mut self,
        plan: &Plan,
        plan_ref: PlanRef,
        out: &Path,
        hashers: NonZeroUsize,
    ) -> Result<Forged, ForgeFault> {
        self.corpus.finish()?;
        let genesis_hash = hex::encode(self.chain[0].hash.as_bytes());
        let tip_height = self.chain.last().expect("genesis at least").height.to_raw();
        self.scenario.take().expect("home").close().await;

        let corpus_path = out.join(CORPUS_FILE);
        let trace_path = out.join(TRACE_FILE);
        let store = tempfile::Builder::new()
            .prefix("shekyl-chain-forge-")
            .tempdir()?;
        let metrics = Arc::new(Metrics::new());
        let (hasher, owner) =
            shekyl_hasher::Hasher::start(shekyl_hash_budget::Budget::new(hashers))
                .map_err(|fault| ForgeFault::Hasher(format!("{fault:?}")))?;
        let pow = Arc::new(ProductionPow::new(hasher, Arc::clone(&metrics)));
        // The trace carries the store's tables digest right after each
        // indexed event's record (`CHAIN_FORGE.md` §8): the expectation a
        // replay, and a snapshot opened at the event, are held to.
        let event_records: Vec<SequenceNo> = self
            .events
            .iter()
            .map(|event| SequenceNo::from_raw(event.record))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let replayed = baseline(
            &corpus_path,
            &store.path().join("trace.redb"),
            self.rules,
            PipelineConfig {
                window: PipelineConfig::DEFAULT_WINDOW,
                hashers,
                digest_each_commit: false,
            },
            pow,
            metrics,
            &trace_path,
            &event_records,
        )
        .await;
        owner.stop();
        let report = replayed?;
        assert_eq!(
            report.connected.last().map(|(height, _)| height.to_raw()),
            Some(tip_height),
            "the replay connects the forged chain to its tip"
        );
        // The switches are the replay's: derived by the fork choice from
        // the corpus, never written by the forge (`CHAIN_FORGE.md` §7.1).
        // The forge's own expectation from the plan is held to them here,
        // so a forging whose replay switched elsewhere, or not at all, is
        // refused rather than recorded.
        let derived: Vec<SwitchRecord> = report
            .switches
            .iter()
            .map(|switch| SwitchRecord {
                at_record: switch.record.to_raw(),
                fork_height: switch.fork.to_raw(),
                depth: switch.depth,
            })
            .collect();
        if derived != self.expected {
            return Err(ForgeFault::Plan(format!(
                "the replay's fork choice switched at {derived:?}, the plan expects {:?}",
                self.expected
            )));
        }

        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            chain: plan.chain.clone(),
            plan: plan_ref,
            seed: plan.seed.clone(),
            network: Network::Regtest.name().to_owned(),
            genesis_hash,
            schedule: ScheduleRecord {
                settlement_epoch_blocks: self.schedule.blocks().get(),
                reorg_cap_blocks: plan.schedule.reorg_cap_blocks,
                fixed_difficulty: Some(plan.fixed_difficulty),
                block_seconds: plan.block_seconds,
            },
            corpus_format_version: CORPUS_FORMAT_VERSION,
            blocks: u64::try_from(self.ledger.lines().len()).expect("fits"),
            tip_height,
            transactions: self.transactions,
            corpus_sha256: sha256_hex(&std::fs::read(&corpus_path)?),
            trace_sha256: sha256_hex(&std::fs::read(&trace_path)?),
            events: self.events,
            switches: derived,
        };
        std::fs::write(out.join(MANIFEST_FILE), manifest.render())?;
        std::fs::write(out.join(BLOCKS_FILE), self.ledger.render())?;
        Ok(Forged {
            manifest,
            blocks: self.ledger,
            harness_funding: self
                .harness_funding
                .map(|funding| (funding.output_key, funding.paid_at)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(height: BlockHeight, record: u64) -> WrittenBlock {
        WrittenBlock { height, record }
    }

    fn close(shard: u64, close_height: BlockHeight) -> ClosedShard {
        ClosedShard {
            shard: ShardId::from_raw(shard),
            close_height,
        }
    }

    fn at(height: u64) -> BlockHeight {
        BlockHeight::from_raw(height)
    }

    #[test]
    fn a_close_takes_the_record_of_the_block_that_closed_it() {
        // Height 11's record is 12: a rewind record sits between it and the
        // block at height 10. Counting back from the tip would name record
        // 11 for the first close.
        let written = vec![block(at(10), 10), block(at(11), 12)];
        let events = close_events(&[close(0, at(10)), close(1, at(11))], &written, false);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].name, "shard-0-closed");
        assert_eq!(events[0].height, 10);
        assert_eq!(events[0].record, 10);
        assert_eq!(events[1].name, "shard-1-closed");
        assert_eq!(events[1].height, 11);
        assert_eq!(events[1].record, 12);
        assert_eq!(events[0].branch, "main");
    }

    #[test]
    fn a_forging_that_stopped_names_only_the_closes_it_wrote() {
        let events = close_events(
            &[close(0, at(10)), close(1, at(11))],
            &[block(at(10), 10)],
            true,
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].record, 10);
    }
}
