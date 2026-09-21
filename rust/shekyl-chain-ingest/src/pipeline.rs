// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The driver: `Source → form (N workers) → Sequencer → Connector → sinks`
//! (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q11, RD-Q13).
//!
//! One loop owns the whole run. It reads events from the [`Source`],
//! claims each block's seed from the [`SeedLedger`] (falling back to the
//! store for blocks recorded before this replay began), hands the block to
//! a blocking `form` worker, restores order through the [`Sequencer`], and
//! sends bounded runs of consecutive `Extend`s to the [`Connector`] in one
//! message each — one write closure per message, the checkpoint
//! granularity. A `Rewind` is a **barrier**: no block after it is formed
//! until the pops have committed, because its seed context is the
//! post-rewind chain.
//!
//! Stateless stages are plain tasks; the one stateful stage is the actor
//! (RD-Q11). The only state this loop holds between events is the ledger,
//! the sequencer's cursor and the report.
//!
//! # Sinks
//!
//! Where the trace has a checkpoint, the loop asks the connector for the
//! redb-side [`LogicalStateDigestV0`] right after that height connects and
//! records it in the [`RunReport`] beside the trace's expectation; grading
//! is commit 7's. A refusal ends the run as a **recorded verdict**, not a
//! fault; a fault ends it as an error, with what connected before it in
//! the report.

use std::sync::Arc;

use kameo::actor::PreparedActor;
use kameo::error::SendError;
use shekyl_chain_rules::{FormAttempt, InvalidBlock, Substrate};
use shekyl_chain_store::digest_v0::LogicalStateDigestV0;
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_types::{BlockHash, BlockHeight};
use tokio::task::JoinSet;

use crate::connector::{Apply, Connector, ConnectorArgs, Digest, Rewind, RunFault};
use crate::grader::Observations;
use crate::metrics::{Metrics, MetricsArtifact};
use crate::schedule::ChainRules;
use crate::seed::{SeedLedger, SeedSchedule};
use crate::sequencer::{SequenceError, Sequencer};
use crate::source::{IngestEvent, Seq, Sequenced, Source};
use crate::stage::{form_extend, Staged};
use crate::trace::Trace;

/// Knobs with a rationale each (rule 75).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Blocks formed ahead of the writer at once — the speculative window.
    /// Bounded well below `SEEDHASH_EPOCH_LAG` (64) so a seed claim for a
    /// block in flight always names a block already read; also the maximum
    /// run length one [`Apply`] carries, hence the checkpoint granularity.
    pub window: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self { window: 32 }
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
    /// Redb-side digests taken at the trace's checkpoint heights, beside
    /// the trace's expectation there.
    pub checkpoints: Vec<(BlockHeight, LogicalStateDigestV0, LogicalStateDigestV0)>,
    /// What the grader reads (RD-Q9): exercised rows, the refusal, digest
    /// agreement.
    pub observations: Observations,
    /// The RandomX measurement (RD-F11), as of the run's end.
    pub metrics: MetricsArtifact,
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
    /// The source emitted an `Extend` whose height is not the next one.
    #[error("source emitted height {found}, the pipeline expected {expected}")]
    HeightOrder {
        /// The height the source should have emitted.
        expected: BlockHeight,
        /// What it emitted.
        found: BlockHeight,
    },
}

type Formed<F> = Sequenced<Result<Staged, F>>;

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
    S: Substrate + Send + Sync + 'static,
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
        let from = SEEDS.seed_height(BlockHeight::from_raw(tip.to_raw() + 1));
        for h in from.to_raw()..=tip.to_raw() {
            if let shekyl_chain_rules::AtHeight::Recorded(info) =
                snap.block_info(BlockHeight::from_raw(h))?
            {
                ledger.record(BlockHeight::from_raw(h), info.hash);
            }
        }
    }
    let expected_next = starting_tip.map_or(0, |t| t.to_raw() + 1);
    let checkpoints: Vec<BlockHeight> = trace.checkpoint_heights().collect();

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

    let outcome = drive(
        source,
        substrate,
        &metrics,
        rules,
        &connector,
        &trace,
        cfg,
        &mut ledger,
        expected_next,
        &checkpoints,
    )
    .await;

    // On every path — a finished run or a fault — stop the actor and wait
    // for its task to end, which is when the store it owns is dropped. A
    // stop refused because the actor already stopped on its own is the same
    // outcome.
    let _already_stopped = connector.stop_gracefully().await.is_err();
    connector.wait_for_shutdown().await;
    let _actor_and_reason = actor_task.await;
    outcome
}

/// The loop proper; `run` owns the actor's lifecycle around it.
#[expect(
    clippy::too_many_arguments,
    reason = "the loop's state is named, not bundled: each argument is one thing the loop reads"
)]
async fn drive<Src, S>(
    source: &mut Src,
    substrate: Arc<S>,
    metrics: &Arc<Metrics>,
    rules: ChainRules,
    connector: &kameo::actor::ActorRef<Connector>,
    trace: &Arc<Trace>,
    cfg: PipelineConfig,
    ledger: &mut SeedLedger,
    mut expected_next: u64,
    checkpoints: &[BlockHeight],
) -> Result<RunReport, PipelineFault<Src::Fault, S::Fault>>
where
    Src: Source,
    S: Substrate + Send + Sync + 'static,
    S::Fault: Send + 'static,
{
    let mut report = RunReport {
        metrics: metrics.snapshot(),
        ..RunReport::default()
    };
    let mut sequencer: Sequencer<Result<Staged, S::Fault>> = Sequencer::new(Seq::FIRST);
    let mut in_flight: JoinSet<Formed<S::Fault>> = JoinSet::new();
    let mut pending_rewind: Option<Sequenced<BlockHeight>> = None;
    let mut exhausted = false;

    'run: loop {
        // ---- fill the window from the source -----------------------------
        while !exhausted && pending_rewind.is_none() && in_flight.len() < cfg.window {
            let Some(event) = source.next().map_err(PipelineFault::Source)? else {
                exhausted = true;
                break;
            };
            match event.item {
                IngestEvent::Rewind { to } => {
                    // Barrier: everything in flight must land before the pops.
                    pending_rewind = Some(Sequenced::new(event.seq, to));
                }
                IngestEvent::Extend(block) => {
                    let height = block.height;
                    if height.to_raw() != expected_next {
                        return Err(PipelineFault::HeightOrder {
                            expected: BlockHeight::from_raw(expected_next),
                            found: height,
                        });
                    }
                    expected_next += 1;
                    ledger.record(height, block.candidate.block.hash());
                    let seed_height = SEEDS.seed_height(height);
                    let Some(seed) = ledger.claim(SEEDS, height) else {
                        return Err(PipelineFault::SeedUnknown {
                            height,
                            seed_height,
                        });
                    };
                    ledger.forget_below(seed_height);
                    let substrate = Arc::clone(&substrate);
                    let metrics = Arc::clone(metrics);
                    let seq = event.seq;
                    let in_force = rules.in_force(height);
                    in_flight.spawn_blocking(move || {
                        let started = std::time::Instant::now();
                        let staged =
                            form_extend(*block, &in_force, &*substrate, seed, FormAttempt::FIRST);
                        metrics.block_formed(started.elapsed());
                        Sequenced::new(seq, staged)
                    });
                }
            }
        }

        // ---- collect one finished form (or learn there is none) ------------
        let finished = in_flight.join_next().await;
        if let Some(done) = finished {
            sequencer.push(done?)?;
        }

        // ---- release in order, apply in runs -------------------------------
        let mut run: Vec<(BlockHeight, _)> = Vec::new();
        while let Some(item) = sequencer.pop_ready() {
            match item.item {
                Err(fault) => return Err(PipelineFault::Substrate(fault)),
                Ok(Staged::Extend { height, formed }) => run.push((height, *formed)),
                Ok(Staged::Rewind { .. }) => unreachable!("rewinds are not formed"),
            }
        }
        if !run.is_empty() {
            let applied = connector.ask(Apply(run)).await.map_err(collapse)?;
            report
                .observations
                .exercised
                .extend(applied.exercised.iter().copied());
            for (height, hash) in &applied.connected {
                report.connected.push((*height, *hash));
                if checkpoints.contains(height) {
                    let ours = connector.ask(Digest).await.map_err(collapse)?;
                    let theirs = trace
                        .expect(*height)
                        .expect("checkpoint heights come from the trace")
                        .value()
                        .clone();
                    report.observations.checkpoint(ours == theirs);
                    report.checkpoints.push((*height, ours, theirs));
                }
            }
            if let Some((height, refused)) = applied.refused {
                report.observations.refused = Some((refused.rule.as_str(), height));
                report.refused = Some((height, refused));
                break 'run;
            }
        }

        // ---- the barrier: rewind once everything before it has landed ------
        if let Some(rewind) = pending_rewind.take() {
            if in_flight.is_empty() && sequencer.pending() == 0 {
                if sequencer.next_expected() != rewind.seq {
                    return Err(PipelineFault::Sequence(SequenceError::AlreadyReleased(
                        rewind.seq,
                    )));
                }
                let rewound = connector
                    .ask(Rewind { to: rewind.item })
                    .await
                    .map_err(collapse)?;
                report.popped += rewound.popped;
                ledger.rewind_to(rewind.item);
                expected_next = rewind.item.to_raw() + 1;
                // The sequencer moves past the rewind's position.
                sequencer.push(Sequenced::new(
                    rewind.seq,
                    Ok(Staged::Rewind { to: rewind.item }),
                ))?;
                let _ = sequencer.pop_ready();
            } else {
                pending_rewind = Some(rewind);
            }
        }

        if exhausted && in_flight.is_empty() && pending_rewind.is_none() && sequencer.pending() == 0
        {
            break 'run;
        }
    }

    report.metrics = metrics.snapshot();
    Ok(report)
}
