// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver: `Source → form (N workers) → Sequencer → Connector → sinks`
//! (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q11, RD-Q13).
//!
//! One [`Drive`] owns the loop. It reads events from the [`Source`],
//! asserting their numbering as it goes; claims each block's seed from the
//! [`SeedLedger`] (asking the store, through the connector, for a seed
//! height the ledger's window has moved past — `seed` module docs); hands
//! the block to a blocking `form` worker (`shekyl-chain-rules::form` — this
//! crate does not wrap it); restores order through the [`Sequencer`]; and
//! sends runs of consecutive `Extend`s to the [`Connector`] in one message
//! each — one write closure per message. A `Rewind` is a **barrier**: no
//! block after it is formed until the pops have committed, because its seed
//! context is the post-rewind chain. The rewind occupies a sequence number;
//! [`Sequencer::advance`] moves past it without a formed payload.
//!
//! # Two bounds, two knobs
//!
//! [`PipelineConfig::window`] bounds what is formed **ahead of the writer**
//! — blocks in flight plus blocks formed and waiting in the sequencer — so
//! memory is a window's worth of formed candidates, and one [`Apply`] run
//! is at most a window. [`PipelineConfig::hashers`] bounds how many `form`
//! workers run **at once** — RandomX light mode is memory-bound, and more
//! hashers than cores thrash the 64 MiB scratchpad set rather than hash
//! (RD-F11: the per-hash wall grows with concurrency). The two are
//! independent: a wide window with few hashers keeps the writer fed while
//! the hashers stay honest.
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

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use kameo::actor::PreparedActor;
use kameo::error::SendError;
use shekyl_chain_rules::{form, FormAttempt, InvalidBlock, StructurallyValid, Substrate, Verdict};
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::connector::{Apply, Connector, ConnectorArgs, Digest, HashAt, Rewind, RunFault};
use crate::grader::Observations;
use crate::metrics::{Concurrency, Metrics, MetricsArtifact};
use crate::schedule::ChainRules;
use crate::seed::{SeedClaim, SeedLedger};
use crate::sequencer::{SequenceError, Sequencer};
use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};
use crate::trace::Trace;

/// Knobs with a rationale each (rule 75; module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Blocks formed ahead of the writer at once — in flight plus waiting
    /// in the sequencer — and so the maximum run length one [`Apply`]
    /// carries.
    pub window: NonZeroUsize,
    /// `form` workers hashing at once.
    pub hashers: NonZeroUsize,
}

impl PipelineConfig {
    /// The default window: half of `SEEDHASH_EPOCH_LAG` (64) — a few dozen
    /// formed candidates in memory, and one `Apply` run of the same size,
    /// which amortises the two-fsync commit over a run without holding a
    /// write transaction open long.
    pub const DEFAULT_WINDOW: NonZeroUsize =
        match NonZeroUsize::new((shekyl_difficulty::SEEDHASH_EPOCH_LAG / 2) as usize) {
            Some(n) => n,
            None => unreachable!(),
        };

    /// The default hasher count: the host's parallelism, one when the
    /// platform will not say. Read at run time, never provisioned as a
    /// constant (rule 76: the floor is a stated device, and a knob that
    /// silently assumed it would mis-size every other host).
    #[must_use]
    pub fn default_hashers() -> NonZeroUsize {
        std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            window: Self::DEFAULT_WINDOW,
            hashers: Self::default_hashers(),
        }
    }
}

/// What a run produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Blocks connected, in order.
    pub connected: Vec<(BlockHeight, BlockHash)>,
    /// The census rows the connected blocks' verdicts exercised — the union
    /// of every `ChainValid`'s coverage.
    pub exercised: BTreeSet<&'static str>,
    /// The refusal that ended the run, if a verdict did.
    pub refused: Option<(BlockHeight, InvalidBlock)>,
    /// The redb-side digest at the trace's covered-tip checkpoint, beside
    /// the trace's expectation, when that height connected.
    pub checkpoint: Option<Checkpoint>,
    /// The RandomX measurement (RD-F11), as of the run's end.
    pub metrics: MetricsArtifact,
    /// One entry per committed `Rewind`: the digest **after the pop**, at
    /// `to` — the reorg family's "digest after each switch" (§3.8), and the
    /// pop-symmetry check through the actor (the state at `to` must be the
    /// state the chain had when `to` was first the tip).
    pub switches: Vec<Switch>,
}

/// The covered-tip checkpoint, compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The height after which both digests were taken.
    pub at: BlockHeight,
    /// The redb-side logical state.
    pub ours: crate::trace::Digest,
    /// The trace's expectation (the LMDB side).
    pub theirs: crate::trace::Digest,
}

impl Checkpoint {
    /// Whether the two sides agree.
    #[must_use]
    pub fn identical(&self) -> bool {
        self.ours == self.theirs
    }
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

/// A way the run disagreed with the chain it replayed — what a caller with
/// no register to grade against must still not read as a pass (§1.3: the
/// success condition is *no unadjudicated disagreement*, and with no
/// register nothing is adjudicated).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disagreement {
    /// Rust refused a block the chain holds.
    Refused {
        /// Where.
        height: BlockHeight,
        /// The verdict.
        verdict: InvalidBlock,
    },
    /// The redb digest differed from the trace's checkpoint.
    Diverged {
        /// The checkpoint height.
        at: BlockHeight,
    },
}

impl RunReport {
    /// Blocks popped over every committed rewind.
    #[must_use]
    pub fn popped(&self) -> u64 {
        self.switches.iter().map(|s| s.popped).sum()
    }

    /// What the grader reads (RD-Q9), derived from the report so the two
    /// cannot disagree: exercised rows, the refusal, digest agreement.
    #[must_use]
    pub fn observations(&self) -> Observations {
        Observations {
            exercised: self.exercised.clone(),
            refused: self
                .refused
                .as_ref()
                .map(|(height, verdict)| (verdict.rule.as_str(), *height)),
            digest_identical: self.checkpoint.as_ref().map(Checkpoint::identical),
        }
    }

    /// Every way the run disagreed with the chain, in the order they can
    /// occur: a checkpoint that diverged, a refusal that ended the run.
    pub fn disagreements(&self) -> impl Iterator<Item = Disagreement> + '_ {
        let diverged = self
            .checkpoint
            .as_ref()
            .filter(|c| !c.identical())
            .map(|c| Disagreement::Diverged { at: c.at });
        let refused = self
            .refused
            .as_ref()
            .map(|(height, verdict)| Disagreement::Refused {
                height: *height,
                verdict: *verdict,
            });
        diverged.into_iter().chain(refused)
    }
}

/// Why a run ended in an error.
#[derive(Debug, thiserror::Error)]
pub enum PipelineFault<SrcF, SubF> {
    /// The source failed.
    #[error("source: {0:?}")]
    Source(SrcF),
    /// The source's first `Extend` is not the store's next height: formed
    /// as is, it would be judged at the wrong height and its refusal read
    /// as a verdict (`Source::first_height`).
    #[error("the source starts at height {source_first}, the store's next height is {store_next}")]
    Misaligned {
        /// Where the source's first block belongs.
        source_first: BlockHeight,
        /// The height the store would connect next.
        store_next: BlockHeight,
    },
    /// The verifier could not compute (§1.1: terminal for the run).
    #[error("substrate: {0:?}")]
    Substrate(SubF),
    /// A `form` worker was cancelled or panicked.
    #[error("form worker: {0}")]
    Worker(#[from] tokio::task::JoinError),
    /// The sequencer refused a position, or the source's numbering has a
    /// hole (a driver or source defect).
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

/// What a `form` worker hands the sequencer: the formed height, or the
/// substrate's inability to compute.
type Formed<F> = Result<(BlockHeight, Verdict<StructurallyValid>), F>;

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

/// The height after `tip`, or the first height on an empty store. A chain
/// does not reach `u64::MAX` blocks; the store itself refuses to record a
/// tip there, so no honest source can ask for its successor.
fn next_height(tip: Option<BlockHeight>) -> BlockHeight {
    tip.map_or(BlockHeight::ZERO, |t| {
        t.checked_add(BlockCount::ONE)
            .expect("the height space is not exhausted by a recorded chain")
    })
}

/// Run a source to exhaustion against `store`.
///
/// `metrics` must be the sink `substrate` records into (`substrate` module
/// docs): the pipeline times each block's `form` into it and snapshots it
/// for the report.
///
/// # Errors
///
/// Any [`PipelineFault`]; the report up to the fault is not returned (the
/// store carries what landed; `metrics` carries the measurement).
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
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    let form_at = next_height(store.begin_read()?.tip()?.recorded.map(|t| t.height));
    if source.first_height() != form_at {
        return Err(PipelineFault::Misaligned {
            source_first: source.first_height(),
            store_next: form_at,
        });
    }
    metrics.configured(Concurrency {
        hashers: cfg.hashers.get(),
        window: cfg.window.get(),
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
        ledger: SeedLedger::new(),
        form_at,
        next_seq: SequenceNo::FIRST,
        checkpoint_at: trace.checkpoint().map(|(h, _)| h),
        report: RunReport::default(),
        sequencer: Sequencer::new(SequenceNo::FIRST),
        pinned: None,
        hashers: Arc::new(Semaphore::new(cfg.hashers.get())),
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
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    source: &'a mut Src,
    substrate: Arc<S>,
    metrics: &'a Arc<Metrics>,
    rules: ChainRules,
    connector: &'a kameo::actor::ActorRef<Connector>,
    trace: &'a Arc<Trace>,
    cfg: PipelineConfig,
    ledger: SeedLedger,
    /// The height the next `Extend` connects at.
    form_at: BlockHeight,
    /// The sequence number the next event must carry.
    next_seq: SequenceNo,
    checkpoint_at: Option<BlockHeight>,
    report: RunReport,
    sequencer: Sequencer<Formed<S::Fault>>,
    /// The seed last pinned on the substrate.
    pinned: Option<BlockHash>,
    /// One permit per hasher; a worker holds its permit for the life of
    /// its `form`.
    hashers: Arc<Semaphore>,
    in_flight: JoinSet<Sequenced<Formed<S::Fault>>>,
    pending_rewind: Option<Sequenced<BlockHeight>>,
    exhausted: bool,
}

impl<Src, S> Drive<'_, Src, S>
where
    Src: Source,
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    async fn run_loop(&mut self) -> Result<RunReport, PipelineFault<Src::Fault, S::Fault>> {
        loop {
            self.fill().await?;
            self.collect().await?;
            self.apply_ready().await?;
            if self.report.refused.is_some() {
                break;
            }
            self.try_rewind().await?;
            if self.exhausted && self.in_flight.is_empty() && self.pending_rewind.is_none() {
                // Nothing left to read, form or pop. Every numbered event
                // was formed or advanced over, so nothing can be waiting;
                // if something is, it is a defect to surface, not a queue
                // to spin on.
                if self.sequencer.pending() != 0 {
                    return Err(SequenceError::Stranded {
                        next: self.sequencer.next_expected(),
                        pending: self.sequencer.pending(),
                    }
                    .into());
                }
                break;
            }
        }
        self.report.metrics = self.metrics.snapshot();
        Ok(std::mem::take(&mut self.report))
    }

    /// Read events and start forming them, while the window has room and a
    /// hasher is free. Stops at a `Rewind` (the barrier) and at exhaustion.
    async fn fill(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        while !self.exhausted
            && self.pending_rewind.is_none()
            && self.in_flight.len() + self.sequencer.pending() < self.cfg.window.get()
        {
            // The permit is taken before the event is read, so no event is
            // pulled from the source and then held with nowhere to go.
            let Ok(permit) = Arc::clone(&self.hashers).try_acquire_owned() else {
                break;
            };
            let Some(event) = self.source.next().map_err(PipelineFault::Source)? else {
                self.exhausted = true;
                break;
            };
            self.take_sequence(event.seq)?;
            match event.event {
                IngestEvent::Rewind { to } => {
                    self.pending_rewind = Some(Sequenced {
                        seq: event.seq,
                        event: to,
                    });
                }
                IngestEvent::Extend(candidate) => {
                    self.spawn_form(event.seq, candidate, permit).await?;
                }
            }
        }
        Ok(())
    }

    /// The numbering contract, asserted at the event: consecutive from
    /// `FIRST`, or the source is defective and the run says so here rather
    /// than parking items behind a number nothing will fill.
    fn take_sequence(&mut self, seq: SequenceNo) -> Result<(), SequenceError> {
        if seq != self.next_seq {
            return Err(SequenceError::NotNext {
                expected: self.next_seq,
                found: seq,
            });
        }
        self.next_seq = seq.next();
        Ok(())
    }

    /// Assign the next height, claim its seed, pin the epoch if it changed,
    /// and start the worker. The permit rides with the worker and is
    /// released when `form` returns.
    async fn spawn_form(
        &mut self,
        seq: SequenceNo,
        candidate: Box<shekyl_chain_rules::Candidate>,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let height = self.form_at;
        self.form_at = next_height(Some(height));
        self.ledger.record(height, candidate.block.hash());
        let seed = self.claim_seed(height).await?;
        if seed != BlockHash::NULL && self.pinned != Some(seed) {
            let substrate = Arc::clone(&self.substrate);
            tokio::task::spawn_blocking(move || substrate.pin_seed(&seed)).await?;
            self.pinned = Some(seed);
        }
        let substrate = Arc::clone(&self.substrate);
        let metrics = Arc::clone(self.metrics);
        let in_force = self.rules.in_force(height);
        self.in_flight.spawn_blocking(move || {
            let started = std::time::Instant::now();
            let verdict = form(*candidate, &in_force, &*substrate, seed, FormAttempt::FIRST);
            metrics.block_formed(started.elapsed());
            drop(permit);
            Sequenced {
                seq,
                event: verdict.map(|verdict| (height, verdict)),
            }
        });
        Ok(())
    }

    /// The seed for a block connecting at `connecting`: the ledger's, or
    /// the store's for a seed height the ledger's window has moved past
    /// (`seed` module docs), recorded so the next claim at that seed
    /// height is the ledger's. Between rewinds seed heights never decrease,
    /// so what lies below this one is forgotten.
    async fn claim_seed(
        &mut self,
        connecting: BlockHeight,
    ) -> Result<BlockHash, PipelineFault<Src::Fault, S::Fault>> {
        let seed = match self.ledger.claim(connecting) {
            SeedClaim::Known(seed) => seed,
            SeedClaim::Unread { seed_height } => {
                let recorded = self
                    .connector
                    .ask(HashAt {
                        height: seed_height,
                    })
                    .await
                    .map_err(collapse)?;
                let Some(seed) = recorded else {
                    return Err(PipelineFault::SeedUnknown {
                        height: connecting,
                        seed_height,
                    });
                };
                self.ledger.record(seed_height, seed);
                seed
            }
        };
        if let Some(seed_height) = shekyl_chain_rules::seed_height(connecting) {
            self.ledger.forget_below(seed_height);
        }
        Ok(seed)
    }

    /// Wait for one worker, then take every other one already finished, so
    /// a run covers everything formed by the time the writer is asked.
    async fn collect(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(done) = self.in_flight.join_next().await else {
            return Ok(());
        };
        self.sequencer.push(done?)?;
        while let Some(done) = self.in_flight.try_join_next() {
            self.sequencer.push(done?)?;
        }
        Ok(())
    }

    /// Send the releasable run — at most a window, by the fill bound — to
    /// the writer, and record what it did.
    async fn apply_ready(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let mut run: Vec<(BlockHeight, Verdict<StructurallyValid>)> = Vec::new();
        while let Some(item) = self.sequencer.pop_ready() {
            run.push(item.event.map_err(PipelineFault::Substrate)?);
        }
        if run.is_empty() {
            return Ok(());
        }
        let applied = self.connector.ask(Apply(run)).await.map_err(collapse)?;
        self.report
            .exercised
            .extend(applied.exercised.iter().copied());
        self.report
            .connected
            .extend(applied.connected.iter().copied());
        if let Some(at) = self.checkpoint_at {
            if applied.connected.iter().any(|(h, _)| *h == at) {
                let ours = self.connector.ask(Digest).await.map_err(collapse)?;
                let theirs = *self
                    .trace
                    .expect(at)
                    .expect("checkpoint_at comes from the trace")
                    .value();
                self.report.checkpoint = Some(Checkpoint { at, ours, theirs });
            }
        }
        if let Some(refused) = applied.refused {
            self.report.refused = Some(refused);
        }
        Ok(())
    }

    /// Commit the pending rewind once nothing is in flight ahead of it: the
    /// barrier. Records the digest after the pop and moves the ledger and
    /// the next height to the post-rewind chain.
    async fn try_rewind(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(rewind) = self.pending_rewind.take() else {
            return Ok(());
        };
        if !(self.in_flight.is_empty() && self.sequencer.pending() == 0) {
            self.pending_rewind = Some(rewind);
            return Ok(());
        }
        self.sequencer.advance(rewind.seq)?;
        let to = rewind.event;
        let rewound = self.connector.ask(Rewind { to }).await.map_err(collapse)?;
        let digest = self.connector.ask(Digest).await.map_err(collapse)?;
        self.report.switches.push(Switch {
            to,
            popped: rewound.popped,
            digest,
        });
        self.ledger.rewind_to(to);
        self.form_at = next_height(Some(to));
        Ok(())
    }
}
