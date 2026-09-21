// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver: `Source → form (N workers) → Sequencer → Connector → sinks`
//! (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q11, RD-Q13).
//!
//! One [`Drive`] owns the loop. It reads events from the [`Source`], claims
//! each block's seed from the [`SeedLedger`] (falling back to the store for
//! blocks recorded before this replay began), hands the block to a blocking
//! `form` worker (`shekyl-chain-rules::form` — this crate does not wrap
//! it), restores order through the [`Sequencer`], and sends bounded runs of
//! consecutive `Extend`s to the [`Connector`] in one message each — one
//! write closure per message. A `Rewind` is a **barrier**: no block after
//! it is formed until the pops have committed, because its seed context is
//! the post-rewind chain. The rewind occupies a sequence number;
//! [`Sequencer::advance`] moves past it without a formed payload.
//!
//! Stateless stages are plain tasks; the one stateful stage is the actor
//! (RD-Q11). The only state this loop holds between events is the ledger,
//! the sequencer's cursor and the report.
//!
//! # Sinks
//!
//! The trace carries at most one checkpoint, at its covered tip (RD-F18).
//! After that height connects, the loop asks the connector for the
//! redb-side [`crate::trace::Digest`] and records it beside the trace's
//! expectation. A refusal is a **recorded verdict**: the writer stays up;
//! this driver ends the run (an honest chain that refuses is a
//! disagreement; E3 and the mutation family keep the same actor and decide
//! for themselves). A store halt is a fault.

use std::sync::Arc;

use kameo::actor::PreparedActor;
use kameo::error::SendError;
use shekyl_chain_rules::{form, FormAttempt, InvalidBlock, StructurallyValid, Substrate, Verdict};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use tokio::task::JoinSet;

use crate::connector::{Apply, Connector, ConnectorArgs, Digest, Rewind, RunFault};
use crate::grader::Observations;
use crate::metrics::{Metrics, MetricsArtifact};
use crate::schedule::ChainRules;
use crate::seed::{SeedLedger, SeedSchedule};
use crate::sequencer::{SequenceError, Sequencer};
use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};
use crate::substrate::EpochPin;
use crate::trace::Trace;

/// Knobs with a rationale each (rule 75).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Blocks formed ahead of the writer at once — the speculative window.
    /// Bounded well below `SEEDHASH_EPOCH_LAG` (64) so a seed claim for a
    /// block in flight always names a block already read; also the maximum
    /// run length one [`Apply`] carries.
    pub window: usize,
}

impl PipelineConfig {
    /// The default window: half of `SEEDHASH_EPOCH_LAG` (64). A seed claim
    /// for a block in flight always names a block already read, with the
    /// same margin again to spare; and small enough that one `Apply` run
    /// stays a few dozen blocks.
    pub const DEFAULT_WINDOW: usize = (shekyl_difficulty::SEEDHASH_EPOCH_LAG / 2) as usize;
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            window: Self::DEFAULT_WINDOW,
        }
    }
}

/// The seed-epoch schedule the driver claims under — the validator's
/// (slice 2 F5: the mainnet constants at every nettype, no environment),
/// so it is not a knob (`schedule` module docs).
const SEEDS: SeedSchedule = SeedSchedule::MAINNET;

/// What a run produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Blocks connected, in order.
    pub connected: Vec<(BlockHeight, BlockHash)>,
    /// Blocks popped by rewinds.
    pub popped: u64,
    /// The refusal that ended the run, if a verdict did.
    pub refused: Option<(BlockHeight, InvalidBlock)>,
    /// The redb-side digest at the trace's covered-tip checkpoint, beside
    /// the trace's expectation, when that height connected.
    pub checkpoint: Option<(BlockHeight, crate::trace::Digest, crate::trace::Digest)>,
    /// What the grader reads (RD-Q9): exercised rows, the refusal, digest
    /// agreement.
    pub observations: Observations,
    /// The RandomX measurement (RD-F11), as of the run's end.
    pub metrics: MetricsArtifact,
    /// One entry per committed `Rewind`: the digest **after the pop**, at
    /// `to` — the reorg family's "digest after each switch" (§3.8), and the
    /// pop-symmetry check through the actor (the state at `to` must be the
    /// state the chain had when `to` was first the tip).
    pub switches: Vec<Switch>,
}

/// A committed rewind and the state it left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    /// The tip after the pop.
    pub to: BlockHeight,
    /// How many blocks the pop removed.
    pub popped: u64,
    /// The store's logical state at `to`, after the pop.
    pub digest: crate::trace::Digest,
}

/// Why a run ended in an error.
#[derive(Debug, thiserror::Error)]
pub enum PipelineFault<SrcF, SubF> {
    /// The source failed.
    #[error("source: {0:?}")]
    Source(SrcF),
    /// The verifier could not compute (§1.1: terminal for the run).
    #[error("substrate: {0:?}")]
    Substrate(SubF),
    /// A `form` worker was cancelled or panicked.
    #[error("form worker: {0}")]
    Worker(#[from] tokio::task::JoinError),
    /// The sequencer refused a position (a driver defect).
    #[error(transparent)]
    Sequence(#[from] SequenceError),
    /// No seed could be claimed for `height`: neither the ledger nor the
    /// store has the block at its seed height.
    #[error("no seed for height {height}: the block at seed height {seed_height} is neither read nor recorded")]
    SeedUnknown {
        /// The connecting height.
        height: BlockHeight,
        /// The height whose hash was needed.
        seed_height: BlockHeight,
    },
    /// A store read outside the actor failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The connector replied with a fault.
    #[error(transparent)]
    Connector(#[from] RunFault),
    /// The connector could not be reached: not running, stopped, or its
    /// mailbox full.
    #[error("connector unreachable")]
    Mailbox,
}

type Formed<F> = Sequenced<(BlockHeight, Result<Verdict<StructurallyValid>, F>)>;
/// Sequencer payload: a formed height, or the substrate's inability to compute.
type SequencedForm<F> = Result<(BlockHeight, Verdict<StructurallyValid>), F>;

/// A handler's own error is the connector's fault; every other way an
/// `ask` can fail is the mailbox.
fn collapse<M, SrcF, SubF>(err: SendError<M, RunFault>) -> PipelineFault<SrcF, SubF> {
    match err {
        SendError::HandlerError(e) => PipelineFault::Connector(e),
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => PipelineFault::Mailbox,
    }
}

/// Run a source to exhaustion against `store`.
///
/// # Errors
///
/// Any [`PipelineFault`]; the report up to the fault is not returned (the
/// store carries what landed).
pub async fn run<Src, S>(
    source: &mut Src,
    substrate: Arc<S>,
    metrics: Arc<Metrics>,
    rules: ChainRules,
    store: ChainStore,
    trace: Arc<Trace>,
    cfg: PipelineConfig,
) -> Result<RunReport, PipelineFault<Src::Fault, S::Fault>>
where
    Src: Source,
    S: Substrate + EpochPin + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    assert!(cfg.window > 0, "a window of zero forms nothing");
    let starting_tip = store.begin_read()?.tip()?.recorded.map(|t| t.height);
    // Seeds for blocks recorded before this run come from the store, read
    // once here; the actor owns the store from now on.
    let mut ledger = SeedLedger::new();
    if let Some(tip) = starting_tip {
        let snap = store.begin_read()?;
        // Only the heights a future claim can name: seed heights are
        // non-decreasing, so from the current one up to the tip.
        let from = SEEDS.seed_height(
            tip.checked_add(BlockCount::ONE)
                .expect("height space exhausted"),
        );
        for h in from.to_raw()..=tip.to_raw() {
            if let shekyl_chain_rules::AtHeight::Recorded(info) =
                snap.block_info(BlockHeight::from_raw(h))?
            {
                ledger.record(BlockHeight::from_raw(h), info.hash);
            }
        }
    }
    let form_at = starting_tip.map_or(BlockHeight::from_raw(0), |t| {
        t.checked_add(BlockCount::ONE)
            .expect("height space exhausted")
    });

    // Prepared rather than `Connector::spawn`, so the task handle is ours:
    // the actor owns the store, and `run` must not return before the task
    // has dropped it (a caller reopening the file would otherwise race the
    // engine's lock).
    let prepared = PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
    let connector = prepared.actor_ref().clone();
    let actor_task = prepared.spawn(ConnectorArgs {
        store,
        rules,
        trace: Arc::clone(&trace),
    });

    let mut drive = Drive {
        source,
        substrate,
        metrics: &metrics,
        rules,
        connector: &connector,
        trace: &trace,
        cfg,
        ledger: &mut ledger,
        form_at,
        checkpoint_at: trace.checkpoint().map(|(h, _)| h),
        report: RunReport {
            metrics: metrics.snapshot(),
            ..RunReport::default()
        },
        sequencer: Sequencer::new(SequenceNo::FIRST),
        pinned: None,
        in_flight: JoinSet::new(),
        pending_rewind: None,
        exhausted: false,
    };
    let outcome = drive.run_loop().await;

    // On every path — a finished run or a fault — stop the actor and wait
    // for its task to end, which is when the store it owns is dropped. A
    // stop refused because the actor already stopped on its own is the same
    // outcome.
    let _already_stopped = connector.stop_gracefully().await.is_err();
    connector.wait_for_shutdown().await;
    let _actor_and_reason = actor_task.await;
    outcome
}

/// The loop's state, named. Fill, collect, apply, rewind are the four
/// steps; a `Drive` is what holds them together.
struct Drive<'a, Src, S>
where
    Src: Source,
    S: Substrate + EpochPin + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    source: &'a mut Src,
    substrate: Arc<S>,
    metrics: &'a Arc<Metrics>,
    rules: ChainRules,
    connector: &'a kameo::actor::ActorRef<Connector>,
    trace: &'a Arc<Trace>,
    cfg: PipelineConfig,
    ledger: &'a mut SeedLedger,
    form_at: BlockHeight,
    checkpoint_at: Option<BlockHeight>,
    report: RunReport,
    sequencer: Sequencer<SequencedForm<S::Fault>>,
    pinned: Option<BlockHash>,
    in_flight: JoinSet<Formed<S::Fault>>,
    pending_rewind: Option<Sequenced<BlockHeight>>,
    exhausted: bool,
}

impl<Src, S> Drive<'_, Src, S>
where
    Src: Source,
    S: Substrate + EpochPin + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    async fn run_loop(&mut self) -> Result<RunReport, PipelineFault<Src::Fault, S::Fault>> {
        loop {
            self.fill().await?;
            self.collect_one().await?;
            self.apply_ready().await?;
            if self.report.refused.is_some() {
                break;
            }
            self.try_rewind().await?;
            if self.exhausted
                && self.in_flight.is_empty()
                && self.pending_rewind.is_none()
                && self.sequencer.pending() == 0
            {
                break;
            }
        }
        self.report.metrics = self.metrics.snapshot();
        Ok(std::mem::take(&mut self.report))
    }

    async fn fill(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        while !self.exhausted
            && self.pending_rewind.is_none()
            && self.in_flight.len() < self.cfg.window
        {
            let Some(event) = self.source.next().map_err(PipelineFault::Source)? else {
                self.exhausted = true;
                break;
            };
            match event.event {
                IngestEvent::Rewind { to } => {
                    self.pending_rewind = Some(Sequenced {
                        seq: event.seq,
                        event: to,
                    });
                }
                IngestEvent::Extend(candidate) => {
                    let height = self.form_at;
                    self.form_at = height
                        .checked_add(BlockCount::ONE)
                        .expect("height space exhausted");
                    self.ledger.record(height, candidate.block.hash());
                    let seed_height = SEEDS.seed_height(height);
                    let Some(seed) = self.ledger.claim(SEEDS, height) else {
                        return Err(PipelineFault::SeedUnknown {
                            height,
                            seed_height,
                        });
                    };
                    self.ledger.forget_below(seed_height);
                    if seed != BlockHash::NULL && self.pinned != Some(seed) {
                        let s = Arc::clone(&self.substrate);
                        tokio::task::spawn_blocking(move || s.pin_epoch(&seed)).await?;
                        self.pinned = Some(seed);
                    }
                    let substrate = Arc::clone(&self.substrate);
                    let metrics = Arc::clone(self.metrics);
                    let seq = event.seq;
                    let in_force = self.rules.in_force(height);
                    self.in_flight.spawn_blocking(move || {
                        let started = std::time::Instant::now();
                        let verdict =
                            form(*candidate, &in_force, &*substrate, seed, FormAttempt::FIRST);
                        metrics.block_formed(started.elapsed());
                        Sequenced {
                            seq,
                            event: (height, verdict),
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn collect_one(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(done) = self.in_flight.join_next().await else {
            return Ok(());
        };
        let item = done?;
        self.sequencer.push(Sequenced {
            seq: item.seq,
            event: match item.event {
                (height, Ok(verdict)) => Ok((height, verdict)),
                (_, Err(fault)) => Err(fault),
            },
        })?;
        Ok(())
    }

    async fn apply_ready(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let mut run: Vec<(BlockHeight, Verdict<StructurallyValid>)> = Vec::new();
        while let Some(item) = self.sequencer.pop_ready() {
            match item.event {
                Err(fault) => return Err(PipelineFault::Substrate(fault)),
                Ok((height, formed)) => run.push((height, formed)),
            }
        }
        if run.is_empty() {
            return Ok(());
        }
        let applied = self.connector.ask(Apply(run)).await.map_err(collapse)?;
        self.report
            .observations
            .exercised
            .extend(applied.exercised.iter().copied());
        for (height, hash) in &applied.connected {
            self.report.connected.push((*height, *hash));
        }
        if let Some(at) = self.checkpoint_at {
            if applied.connected.iter().any(|(h, _)| *h == at) {
                let ours = self.connector.ask(Digest).await.map_err(collapse)?;
                let theirs = *self
                    .trace
                    .expect(at)
                    .expect("checkpoint_at comes from the trace")
                    .value();
                self.report.observations.checkpoint(ours == theirs);
                self.report.checkpoint = Some((at, ours, theirs));
            }
        }
        if let Some((height, refused)) = applied.refused {
            self.report.observations.refused = Some((refused.rule.as_str(), height));
            self.report.refused = Some((height, refused));
        }
        Ok(())
    }

    async fn try_rewind(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(rewind) = self.pending_rewind.take() else {
            return Ok(());
        };
        if !(self.in_flight.is_empty() && self.sequencer.pending() == 0) {
            self.pending_rewind = Some(rewind);
            return Ok(());
        }
        self.sequencer.advance(rewind.seq)?;
        let rewound = self
            .connector
            .ask(Rewind { to: rewind.event })
            .await
            .map_err(collapse)?;
        self.report.popped += rewound.popped;
        let digest = self.connector.ask(Digest).await.map_err(collapse)?;
        self.report.switches.push(Switch {
            to: rewind.event,
            popped: rewound.popped,
            digest,
        });
        self.ledger.rewind_to(rewind.event);
        self.form_at = rewind
            .event
            .checked_add(BlockCount::ONE)
            .expect("height space exhausted");
        Ok(())
    }
}
