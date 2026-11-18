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
//! The chain is written as corpus layout 4 (`CORPUS_FORMAT_VERSION`): a
//! reorg is a rewind record and the branch after it. Layout 5's `offer`
//! record is `CF-3`'s.

mod built;
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

use shekyl_chain_forge::{
    close_event, sha256_hex, Action, BlocksTxt, Branch, Difference, EpochBlocks, EventRecord, Line,
    Manifest, Plan, PlanRef, ScheduleRecord, MANIFEST_FORMAT_VERSION,
};
use shekyl_chain_ingest::admitted_draws::{assert_issued_pair, mine_serving, DriverWitness};
use shekyl_chain_ingest::archival_driver::{ENDPOINT, FEE};
use shekyl_chain_ingest::corpus::{CorpusFault, CorpusWriter, CORPUS_FORMAT_VERSION};
use shekyl_chain_ingest::metrics::Metrics;
use shekyl_chain_ingest::pipeline::PipelineConfig;
use shekyl_chain_ingest::rebaseline::{baseline, ReplayFault};
use shekyl_chain_ingest::scenario::{FreeHash, Mined, Scenario};
use shekyl_chain_ingest::scenario_archival::shard_set;
use shekyl_chain_ingest::scenario_shard::{
    close_shards_drawing, first_admissible_compact_join, inside_one_epoch_of, maturity, mine_to,
    settled_epoch_blocks, ClosedShard, FILL_FROM_COINBASE,
};
use shekyl_chain_ingest::schedule::ChainRules;
use shekyl_chain_ingest::ProductionPow;
use shekyl_chain_rules::{CappedEpoch, CenRow, SettlementEpochBlocks, SettlementSchedule};
use shekyl_harness_spender::{Persona, Recipient, Spender};
use shekyl_network::Network;
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};

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
    shard: ClosedShard,
    join_epoch: SettlementEpoch,
    backing_key: [u8; 32],
    fee_key: [u8; 32],
    join_height: BlockHeight,
}

/// A block [`Forge::write_new`] appended, and the corpus record it occupies.
///
/// The record is assigned as the block is written. A rewind earlier in the
/// corpus makes the record differ from the height; counting back from the
/// tip would name the wrong record.
struct WrittenBlock {
    height: u64,
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
        let height = closed.close_height.to_raw();
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
            height,
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
    /// Corpus records written, blocks and rewinds.
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
        let mut forge = Self {
            scenario: Some(scenario),
            chain: vec![genesis],
            written: 0,
            corpus,
            ledger: BlocksTxt::new(),
            records: 0,
            transactions: 0,
            events: Vec::new(),
            seeds: Arc::new(Seeds::new(seed, options.swapped)),
            spends: 0,
            claims: 0,
            reserved: 1,
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
                let tip = self.chain.last().expect("genesis at least");
                self.events.push(EventRecord {
                    name: name.clone(),
                    height: tip.height.to_raw(),
                    branch: Branch::Main.to_string(),
                    record: self.records - 1,
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
        let coinbase = self.reserved;
        if coinbase >= FILL_FROM_COINBASE {
            return Err(ForgeFault::Plan(format!(
                "the plan's spends and posts use the coinbases below {FILL_FROM_COINBASE}; it asked for more"
            )));
        }
        if coinbase + maturity() > connecting.to_raw() {
            return Err(ForgeFault::Plan(format!(
                "coinbase {coinbase} is not spendable at {connecting}: mine to {} first",
                coinbase + maturity()
            )));
        }
        self.reserved += 1;
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
            let height = mined.height.to_raw();
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
            self.corpus
                .append_carrying(&block, &listed, &references, &bodies)?;
            let record = self.records;
            self.records += 1;
            written_blocks.push(WrittenBlock { height, record });
            self.transactions += u64::try_from(listed.len()).expect("a block's list fits");
            let line = Line {
                height: mined.height.to_raw(),
                branch: Branch::Main,
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
            Action::Spend { inputs } => self.spend(*inputs).await?,
            Action::FillShards { count } => closes = self.fill(*count).await,
            Action::Join { persona, shards } => self.join(*persona, shards).await?,
            Action::Serve { persona } => self.serve(*persona).await?,
            Action::Claim { persona } => claim::step(self, *persona).await?,
            Action::Reorg { depth } => self.reorg(*depth).await?,
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

    /// The miner spends `inputs` kept coinbases in one transaction.
    async fn spend(&mut self, inputs: u32) -> Result<(), ForgeFault> {
        let connecting = self.connecting();
        let heights = (0..inputs)
            .map(|_| self.reserve(connecting))
            .collect::<Result<Vec<_>, _>>()?;
        let spend = self.next_spend();
        let seeds = self.seeds.spend(spend);
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        let (spend, _) = spender
            .drawing(seeds)
            .spend_coinbases(wallet, &heights, connecting, FEE);
        self.built.push(Built {
            body: spend.clone(),
            connecting,
            kind: BuiltKind::Spend { coinbases: heights },
        });
        let block = self
            .scenario()
            .mine_listing(vec![spend])
            .await
            .unwrap_or_else(|outcome| panic!("the plan's spend connects: {outcome}"));
        self.chain.push(block);
        Ok(())
    }

    /// Real spends until `count` shards are closed (S9). The new closes, in
    /// the order the fold counted them.
    async fn fill(&mut self, count: u64) -> Vec<ClosedShard> {
        let seeds = Arc::clone(&self.seeds);
        let mut next = self.spends;
        let mut chain = std::mem::take(&mut self.chain);
        let filled = close_shards_drawing(
            self.scenario.as_mut().expect("home"),
            &mut chain,
            FILL_FROM_COINBASE,
            count,
            || {
                let index = next;
                next += 1;
                seeds.fill_spend(index)
            },
        )
        .await;
        self.chain = chain;
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
        let [close] = closes.as_slice() else {
            return Err(ForgeFault::Plan(
                "a join holds one closed shard in this increment".into(),
            ));
        };
        // The join and the block after it sit in one epoch, neither a close.
        let join_height = inside_one_epoch_of(
            self.schedule,
            first_admissible_compact_join(&self.rules, *close),
            1,
        );
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
        let spender = self.spender();
        let wallet = self.scenario().wallet();
        let join = persona.join(shard_set(shards.to_vec()), ENDPOINT);
        let funding = spender.drawing(seeds).spend_coinbase_to(
            wallet,
            coinbase,
            join_height,
            FEE,
            Some(&join),
            &recipient,
        );
        let backing_key = funding.prefix.outputs[0].key;
        let fee_key = funding.prefix.outputs[1].key;
        self.built.push(Built {
            body: funding.clone(),
            connecting: join_height,
            kind: BuiltKind::Join {
                coinbase,
                slot,
                shards: shards.to_vec(),
            },
        });
        let block = self
            .scenario()
            .mine_listing(vec![funding])
            .await
            .unwrap_or_else(|outcome| panic!("the join connects: {outcome}"));
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
                shard: *close,
                join_epoch,
                backing_key,
                fee_key,
                join_height,
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
        assert_issued_pair(&scenario, served, (joined.persona.id(), joined.shard.shard));
        self.scenario = Some(scenario);
        self.chain = chain;
        Ok(())
    }

    /// Pop the last `depth` blocks and mine `depth + 1` on the fork, the
    /// first listing a spend of a kept coinbase the popped branch did not
    /// list: a rewind record, then the branch.
    async fn reorg(&mut self, depth: u64) -> Result<(), ForgeFault> {
        let tip = self.chain.last().expect("genesis at least").height;
        let fork = tip
            .checked_sub_count(BlockCount::from_raw(depth))
            .ok_or_else(|| ForgeFault::Plan(format!("a reorg of {depth} below genesis")))?;
        self.scenario()
            .rewind_to(fork)
            .await
            .unwrap_or_else(|fault| panic!("the rewind to {fork}: {fault:?}"));
        self.corpus.rewind(fork)?;
        self.records += 1;
        self.chain
            .truncate(usize::try_from(fork.to_raw() + 1).expect("a height fits"));
        self.written = self.chain.len();
        self.spend(1).await?;
        let rest = self.scenario().mine(depth).await;
        self.chain.extend(rest);
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
        )
        .await;
        owner.stop();
        let report = replayed?;
        assert_eq!(
            report.connected.last().map(|(height, _)| height.to_raw()),
            Some(tip_height),
            "the replay connects the forged chain to its tip"
        );

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
            switches: Vec::new(),
        };
        std::fs::write(out.join(MANIFEST_FILE), manifest.render())?;
        std::fs::write(out.join(BLOCKS_FILE), self.ledger.render())?;
        Ok(Forged {
            manifest,
            blocks: self.ledger,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(height: u64, record: u64) -> WrittenBlock {
        WrittenBlock { height, record }
    }

    fn close(shard: u64, height: u64) -> ClosedShard {
        ClosedShard {
            shard: ShardId::from_raw(shard),
            close_height: BlockHeight::from_raw(height),
        }
    }

    #[test]
    fn a_close_takes_the_record_of_the_block_that_closed_it() {
        // Height 11's record is 12: a rewind record sits between it and the
        // block at height 10. Counting back from the tip would name record
        // 11 for the first close.
        let written = vec![block(10, 10), block(11, 12)];
        let events = close_events(&[close(0, 10), close(1, 11)], &written, false);
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
        let events = close_events(&[close(0, 10), close(1, 11)], &[block(10, 10)], true);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].record, 10);
    }
}
