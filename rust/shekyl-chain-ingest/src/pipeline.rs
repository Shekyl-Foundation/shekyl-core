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
//! When the run is over and its committed tip is that height, the loop
//! asks the connector once for the redb side's state — the
//! [`crate::trace::Digest`] and the archival rows (DRS-E4 §3.8.1, version
//! `0x01`), one read — and records the digest beside the trace's
//! expectation and the rows' diff against the trace's `0x04` record. At the
//! end, not at the connect: an `Inject` filed at the covered tip commits
//! after the block it is attributed to, and the trace's rows already carry
//! it. A refusal is a **recorded verdict**: the writer stays up;
//! this driver ends the run (an honest chain that refuses is a
//! disagreement; E3 and the mutation family keep the same actor and decide
//! for themselves). A store halt is a fault.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use kameo::actor::PreparedActor;
use kameo::error::SendError;
use shekyl_chain_rules::{
    form, FormAttempt, InvalidBlock, PaidEmission, StructurallyValid, Substrate, Verdict, Weights,
};
use shekyl_chain_store::archival_snapshot::SnapshotDiff;
use shekyl_chain_store::store::{ChainStore, StoreError};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight,
};
use shekyl_units::AtomicUnits;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use crate::connector::{
    Apply, CheckpointState, Connector, ConnectorArgs, Digest, HashAt, Inject, Rewind, RunFault,
};
use crate::grader::Observations;
use crate::metrics::{Concurrency, Metrics, MetricsArtifact};
use crate::schedule::ChainRules;
use crate::seed::{SeedClaim, SeedLedger};
use crate::sequencer::{SequenceError, Sequencer};
use crate::source::{IngestEvent, Injection, SequenceNo, Sequenced, ServeCredit, Source};
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
    /// the trace's expectation — read after the run's last committed event,
    /// when the committed tip is that height. `None` when the run ended
    /// elsewhere: **not compared**, never identical.
    pub checkpoint: Option<Checkpoint>,
    /// The checkpoint's other encoding (DRS-E4 §3.8.1, `ARW-25`): the
    /// redb-side archival rows at the covered tip diffed against the
    /// trace's `0x04` record, family by family, from the same read as
    /// `checkpoint` and `None` exactly when it is.
    pub archival: Option<ArchivalCheckpoint>,
    /// The derived-vs-trace root comparison, per connected height the trace
    /// has facts for (DRS-E3 CTW-5, `DRS_E3_CURVE_WRITER.md` §3.8): how many
    /// heights were compared, and every one that disagreed. **Every**
    /// covered height of the **canonical** chain, never a sample — this
    /// comparison exists only while the LMDB trace does. The trace is
    /// indexed by height and describes the chain the daemon ended on, so a
    /// height an abandoned branch connected is not a comparison against
    /// anything: a `Rewind { to }` retracts every result above `to`, and the
    /// re-extension compares afresh. Zero compared on a trace with facts is
    /// a run that connected nothing, which the connected count already
    /// says; a gate over this field asserts the count first (rule 47).
    pub roots: RootComparisons,
    /// The derived-vs-trace **weights** comparison (CEN-G6/G6b, slice 7
    /// commit 4), the same shape and the same canonical-heights-only
    /// discipline as `roots`: at every connected height the trace has
    /// facts for, the verdict's `weight`, `long_term_weight` and
    /// `long_term_effective_median` against the C++'s two `block_info`
    /// columns and the exporter's re-derived median. The parity pin for
    /// the two medians over every captured chain, taken while the LMDB
    /// trace exists; a divergence is recorded, never patched.
    pub weights: WeightComparisons,
    /// The derived-vs-trace **emission** comparison (CEN-F14b / G12, slice
    /// 7 commit 5; CEN-F17 / G11, wave B), the same shape: at every
    /// connected height the trace has facts for, the verdict's
    /// `coins_generated` against the C++'s `block_info.bi_coins` and the
    /// verdict's burn against its `block_burn`. Consecutive accumulator
    /// rows differ by the paid reward, so this is the penalty's parity
    /// oracle wherever a captured block is over the median (`median-full`'s
    /// block 211 is the one on record); the burn column is the fee split's
    /// — the burn ratio over the FL-R16c supply and the escalation operand
    /// — wherever a captured block carries a fee.
    pub emission: EmissionComparisons,
    /// The RandomX measurement (RD-F11), as of the run's end.
    pub metrics: MetricsArtifact,
    /// One entry per committed `Rewind`: the digest **after the pop**, at
    /// `to` — the reorg family's "digest after each switch" (§3.8), and the
    /// pop-symmetry check through the actor (the state at `to` must be the
    /// state the chain had when `to` was first the tip).
    pub switches: Vec<Switch>,
    /// One entry per committed `Inject` (DRS-E4 §3.8 item 3): the credit
    /// and the height the store attributed it to. The record a later
    /// `Rewind` is checked against — a pop below an injection's height
    /// would strand the bit, so it is refused
    /// ([`PipelineFault::RewindBelowInjection`]) — and the trace half of
    /// the capture's out-of-band contract: a vector's manifest names each
    /// one, and the replay reports each one.
    pub injected: Vec<Injection>,
}

/// The per-height root oracle's results (`RunReport::roots`), one per
/// canonical height compared: `None` where the derived root was the
/// recorded one, the divergence where it was not. Keyed by height so a
/// rewind can retract the abandoned branch's results and a re-extension
/// can replace them — a `Vec` of divergences would keep a popped height's
/// verdict forever.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootComparisons {
    results: BTreeMap<BlockHeight, Option<RootDivergence>>,
}

impl RootComparisons {
    /// Connected canonical heights whose trace facts carried a root to
    /// compare.
    #[must_use]
    pub fn compared(&self) -> u64 {
        u64::try_from(self.results.len()).expect("a height count fits u64")
    }

    /// Every canonical height where the derived root was not the recorded
    /// one, ascending.
    pub fn diverged(&self) -> impl Iterator<Item = &RootDivergence> + '_ {
        self.results.values().flatten()
    }

    /// Whether any compared height diverged.
    #[must_use]
    pub fn any_diverged(&self) -> bool {
        self.diverged().next().is_some()
    }

    /// Record one height's comparison, replacing an earlier result at the
    /// same height (a re-extension after a rewind).
    fn record(&mut self, at: BlockHeight, ours: CurveTreeRoot, theirs: CurveTreeRoot) {
        let result = (ours != theirs).then_some(RootDivergence { at, ours, theirs });
        self.results.insert(at, result);
    }

    /// Retract every result above `to`: the heights a rewind popped were
    /// connected on a branch the chain abandoned, and the trace's row at
    /// those heights describes the branch it kept.
    fn retract_above(&mut self, to: BlockHeight) {
        self.results.retain(|height, _| *height <= to);
    }
}

/// One height where the store's derived root differed from the trace's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootDivergence {
    /// The connected height whose drain produced the root.
    pub at: BlockHeight,
    /// The verdict's derivation, recorded at `curve_tree_roots[at + 1]`.
    pub ours: CurveTreeRoot,
    /// The trace's `root_after` — what the C++ grower left.
    pub theirs: CurveTreeRoot,
}

/// The per-height weights oracle's results (`RunReport::weights`), keyed
/// by height for the same reason [`RootComparisons`] is: a rewind retracts
/// the abandoned branch's results and a re-extension replaces them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WeightComparisons {
    results: BTreeMap<BlockHeight, Option<WeightDivergence>>,
}

impl WeightComparisons {
    /// Connected canonical heights whose trace facts carried weights to
    /// compare.
    #[must_use]
    pub fn compared(&self) -> u64 {
        u64::try_from(self.results.len()).expect("a height count fits u64")
    }

    /// Every canonical height where a derived weight value was not the
    /// recorded one, ascending.
    pub fn diverged(&self) -> impl Iterator<Item = &WeightDivergence> + '_ {
        self.results.values().flatten()
    }

    /// Whether any compared height diverged.
    #[must_use]
    pub fn any_diverged(&self) -> bool {
        self.diverged().next().is_some()
    }

    /// Record one height's comparison — the three values the trace holds
    /// and the verdict derives — replacing an earlier result at the same
    /// height.
    fn record(&mut self, at: BlockHeight, ours: Weights, theirs: RecordedWeightFacts) {
        let same = ours.weight == theirs.weight
            && ours.long_term_weight == theirs.long_term_weight
            && ours.medians.long_term_effective_median == theirs.long_term_effective_median;
        let result = (!same).then_some(WeightDivergence { at, ours, theirs });
        self.results.insert(at, result);
    }

    fn retract_above(&mut self, to: BlockHeight) {
        self.results.retain(|height, _| *height <= to);
    }
}

/// The trace's three weight facts for one height — what the C++ recorded
/// (`block_info.bi_weight`, `bi_long_term_block_weight`) and what the
/// exporter re-derived with the daemon's own rolling median.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedWeightFacts {
    /// `block_info.bi_weight`.
    pub weight: BlockWeight,
    /// `block_info.bi_long_term_block_weight`.
    pub long_term_weight: LongTermWeight,
    /// The long-term effective median in force for the block.
    pub long_term_effective_median: LongTermWeight,
}

impl From<&crate::trace::Facts> for RecordedWeightFacts {
    fn from(facts: &crate::trace::Facts) -> Self {
        Self {
            weight: facts.weight,
            long_term_weight: facts.long_term_weight,
            long_term_effective_median: facts.long_term_effective_median,
        }
    }
}

/// One height where a derived weight value differed from the trace's.
/// Carries all three on each side: which one moved is the finding, and
/// the other two are its context (a wrong median moves the long-term
/// weight with it; a wrong weight alone does not).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WeightDivergence {
    /// The connected height.
    pub at: BlockHeight,
    /// The verdict's derivation.
    pub ours: Weights,
    /// The trace's record.
    pub theirs: RecordedWeightFacts,
}

/// The per-height emission oracle's results (`RunReport::emission`), keyed
/// by height for the same reason the other two are.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmissionComparisons {
    results: BTreeMap<BlockHeight, Option<EmissionDivergence>>,
}

impl EmissionComparisons {
    /// Connected canonical heights whose trace facts carried an
    /// accumulator to compare.
    #[must_use]
    pub fn compared(&self) -> u64 {
        u64::try_from(self.results.len()).expect("a height count fits u64")
    }

    /// Every canonical height where the derived accumulator was not the
    /// recorded one, ascending.
    pub fn diverged(&self) -> impl Iterator<Item = &EmissionDivergence> + '_ {
        self.results.values().flatten()
    }

    /// Whether any compared height diverged.
    #[must_use]
    pub fn any_diverged(&self) -> bool {
        self.diverged().next().is_some()
    }

    fn record(&mut self, at: BlockHeight, ours: PaidEmission, theirs: RecordedEmissionFacts) {
        let same = ours.coins_generated == theirs.coins_generated && ours.burned() == theirs.burned;
        let result = (!same).then_some(EmissionDivergence { at, ours, theirs });
        self.results.insert(at, result);
    }

    fn retract_above(&mut self, to: BlockHeight) {
        self.results.retain(|height, _| *height <= to);
    }
}

/// The two emission values the trace records per height, as the oracle
/// compares them: the C++'s accumulator (`block_info.bi_coins`, CEN-G12)
/// and its destroyed amount (`block_burn`, CEN-F17 / G11 — the fee split
/// over the same parent-state operands, so a match here is the burn ratio,
/// the supply definition and the escalation operand agreeing, not the
/// accumulator alone).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedEmissionFacts {
    /// The trace's `coins_generated`.
    pub coins_generated: AtomicUnits,
    /// The trace's `burned`.
    pub burned: AtomicUnits,
}

impl From<&crate::trace::Facts> for RecordedEmissionFacts {
    fn from(facts: &crate::trace::Facts) -> Self {
        Self {
            coins_generated: facts.coins_generated,
            burned: facts.burned,
        }
    }
}

/// One height where the derived accumulator or burn differed from the
/// trace's. Carries the whole `PaidEmission`: the paid reward, its split
/// and the fee split are the context that says whether the penalty, the
/// emission curve, the burn ratio or the fold moved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmissionDivergence {
    /// The connected height.
    pub at: BlockHeight,
    /// The verdict's derivation.
    pub ours: PaidEmission,
    /// The trace's record.
    pub theirs: RecordedEmissionFacts,
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

/// The covered-tip archival snapshot, compared row by row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalCheckpoint {
    /// The height after which both sides' rows were taken.
    pub at: BlockHeight,
    /// The redb rows against the trace's, per family: `ours` is the redb
    /// side, `theirs` the trace's (the LMDB side).
    pub diff: SnapshotDiff,
}

impl ArchivalCheckpoint {
    /// Whether every family agreed.
    #[must_use]
    pub fn identical(&self) -> bool {
        self.diff.is_identical()
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
    /// The redb archival rows differed from the trace's `0x04` record at
    /// the checkpoint (DRS-E4 §3.8.1); the report's
    /// [`ArchivalCheckpoint`] names the family and the key.
    ArchivalDiverged {
        /// The checkpoint height.
        at: BlockHeight,
    },
    /// The derived curve-tree root after a block differed from the root
    /// the trace recorded for it (DRS-E3 CTW-5). Adjudicated against the
    /// spec, never patched around: the fixtures are chains the C++
    /// accepted and the root is the validator's.
    RootDiverged {
        /// The connected height.
        at: BlockHeight,
    },
    /// A derived weight value — the block's weight, its long-term weight
    /// or the long-term effective median it was judged under — differed
    /// from what the trace recorded for that height (CEN-G6/G6b). The
    /// same discipline as `RootDiverged`: adjudicated, never patched.
    WeightsDiverged {
        /// The connected height.
        at: BlockHeight,
    },
    /// The derived accumulator — the parent's plus the paid reward
    /// (CEN-F14b / G12) — differed from the trace's `coins_generated`, or
    /// the derived burn (CEN-F17 / G11) from its `burned`.
    EmissionDiverged {
        /// The connected height.
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
    /// cannot disagree: exercised rows, the refusal, the covered-tip digest,
    /// the per-height root oracle (CTW-5), and the archival oracle at the
    /// checkpoint (DRS-E4 §3.8.1). The digest and the oracles stay
    /// separate. The digest carries only the live root, so an interior
    /// miss is invisible to it, and it carries no archival state;
    /// `digest_identical` is `None` and `archival.compared` is `false`
    /// when no checkpoint was compared.
    #[must_use]
    pub fn observations(&self) -> Observations {
        Observations {
            exercised: self.exercised.clone(),
            refused: self
                .refused
                .as_ref()
                .map(|(height, verdict)| (verdict.rule.as_str(), *height)),
            digest_identical: self.checkpoint.as_ref().map(Checkpoint::identical),
            roots: crate::grader::RootOracle {
                compared: self.roots.compared(),
                diverged_at: self.roots.diverged().map(|d| d.at).collect(),
            },
            archival: self
                .archival
                .as_ref()
                .map(|a| crate::grader::ArchivalOracle::from_diff(a.at, &a.diff))
                .unwrap_or_default(),
        }
    }

    /// Every way the run disagreed with the chain, in the order they can
    /// occur: a root that diverged at a height, a checkpoint that diverged
    /// (digest, then archival rows), a refusal that ended the run.
    pub fn disagreements(&self) -> impl Iterator<Item = Disagreement> + '_ {
        let roots = self
            .roots
            .diverged()
            .map(|d| Disagreement::RootDiverged { at: d.at });
        let weights = self
            .weights
            .diverged()
            .map(|d| Disagreement::WeightsDiverged { at: d.at });
        let emission = self
            .emission
            .diverged()
            .map(|d| Disagreement::EmissionDiverged { at: d.at });
        let diverged = self
            .checkpoint
            .as_ref()
            .filter(|c| !c.identical())
            .map(|c| Disagreement::Diverged { at: c.at });
        let archival = self
            .archival
            .as_ref()
            .filter(|a| !a.identical())
            .map(|a| Disagreement::ArchivalDiverged { at: a.at });
        let refused = self
            .refused
            .as_ref()
            .map(|(height, verdict)| Disagreement::Refused {
                height: *height,
                verdict: *verdict,
            });
        roots
            .chain(weights)
            .chain(emission)
            .chain(diverged)
            .chain(archival)
            .chain(refused)
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
    /// A `Rewind { to }` below the height an `Inject` was attributed to.
    /// The bit is not block-owned and not journaled, so the pop would not
    /// carry it away: the store would hold a credit at a height the chain
    /// no longer has — the stranding the C++ warns of at its injector.
    /// No source the capture produces does this (the injector writes
    /// after the chain is final); one that does is defective.
    #[error("rewind to {to} is below the serve credit injected at {injected_at} (persona {persona}, shard {shard}, epoch {epoch}); the bit is not block-owned and the pop would strand it", persona = credit.persona, shard = credit.shard, epoch = credit.epoch)]
    RewindBelowInjection {
        /// The rewind's target.
        to: BlockHeight,
        /// Where the bit was attributed.
        injected_at: BlockHeight,
        /// The bit.
        credit: ServeCredit,
    },
}

/// A barrier event waiting for the stage ahead of it to drain: no `Extend`
/// is formed past it, and it commits once nothing is in flight.
enum Barrier {
    /// Pop to `to`.
    Rewind {
        /// The target.
        to: BlockHeight,
    },
    /// Write the out-of-band serve credit at the tip.
    Inject(ServeCredit),
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
    let actor_task = prepared.spawn(ConnectorArgs { store, rules });

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
        pending_barrier: None,
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

/// The loop's state, named. Fill, collect, apply, barrier are the four
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
    /// The barrier read but not yet committed, if any; `fill` reads
    /// nothing past it.
    pending_barrier: Option<Sequenced<Barrier>>,
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
            self.try_barrier().await?;
            if self.exhausted && self.in_flight.is_empty() && self.pending_barrier.is_none() {
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
        self.compare_checkpoint().await?;
        self.report.metrics = self.metrics.snapshot();
        Ok(std::mem::take(&mut self.report))
    }

    /// Read events and start forming them, while the window has room and a
    /// hasher is free. Stops at a barrier (`Rewind`, `Inject`) and at
    /// exhaustion.
    async fn fill(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        while !self.exhausted
            && self.pending_barrier.is_none()
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
                    self.pending_barrier = Some(Sequenced {
                        seq: event.seq,
                        event: Barrier::Rewind { to },
                    });
                }
                IngestEvent::Inject(credit) => {
                    self.pending_barrier = Some(Sequenced {
                        seq: event.seq,
                        event: Barrier::Inject(credit),
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
        // CTW-5: the derived root against the trace's, at every connected
        // height the trace covers. The trace's root is the comparison
        // input, not a fact the store was handed (it left `ConnectFacts`
        // with DRS-E3); a disagreement is recorded, never patched.
        for (at, ours) in &applied.roots {
            if let Some(facts) = self.trace.borrow(*at) {
                self.report
                    .roots
                    .record(*at, *ours, facts.value().root_after);
            }
        }
        // CEN-G6/G6b: the verdict's weights against the trace's three
        // recorded values, the same way.
        for (at, ours) in &applied.weights {
            if let Some(facts) = self.trace.borrow(*at) {
                self.report
                    .weights
                    .record(*at, *ours, RecordedWeightFacts::from(facts.value()));
            }
        }
        // CEN-F14b / G12 and F17 / G11: the verdict's accumulator and burn
        // against the trace's.
        for (at, ours) in &applied.emission {
            if let Some(facts) = self.trace.borrow(*at) {
                self.report
                    .emission
                    .record(*at, *ours, RecordedEmissionFacts::from(facts.value()));
            }
        }
        if let Some(refused) = applied.refused {
            self.report.refused = Some(refused);
        }
        Ok(())
    }

    /// The covered-tip checkpoint (RD-F18; DRS-E4 §3.8.1), both encodings
    /// in one read, taken **after the run's last committed event**. The
    /// trace's walker read one LMDB snapshot after the daemon's last write
    /// — blocks and the regtest injector's out-of-band row alike — and the
    /// redb side is read the same way: once, at the end, through
    /// [`CheckpointState`]. Not when the covered tip connects: an `Inject`
    /// attributed to that tip is a barrier that commits *after* the block
    /// it is attributed to, so a comparison at the connect would hold the
    /// trace's rows (credit included) against a redb side that had not yet
    /// written it, and a faithful replay would read as divergent.
    ///
    /// Compared only when the committed tip *is* the covered tip; a run
    /// that ended elsewhere leaves both fields `None` — not compared, never
    /// identical. A trace carries both encodings or neither
    /// (`TraceFault::MissingSnapshot`), so a checkpoint height without a
    /// snapshot is unreachable here.
    async fn compare_checkpoint(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(at) = self.checkpoint_at else {
            return Ok(());
        };
        let ours = self
            .connector
            .ask(CheckpointState)
            .await
            .map_err(collapse)?;
        if ours.tip != Some(at) {
            return Ok(());
        }
        let theirs = *self
            .trace
            .expect(at)
            .expect("checkpoint_at comes from the trace")
            .value();
        self.report.checkpoint = Some(Checkpoint {
            at,
            ours: ours.digest,
            theirs,
        });
        let (_, theirs) = self
            .trace
            .archival_snapshot()
            .expect("a trace with a checkpoint carries its archival snapshot");
        self.report.archival = Some(ArchivalCheckpoint {
            at,
            diff: ours.archival.diff(theirs.value()),
        });
        Ok(())
    }

    /// Commit the pending barrier once nothing is in flight ahead of it.
    /// A `Rewind` records the digest after the pop and moves the ledger and
    /// the next height to the post-rewind chain; an `Inject` writes the
    /// credit at the tip and records where the store attributed it.
    async fn try_barrier(&mut self) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let Some(barrier) = self.pending_barrier.take() else {
            return Ok(());
        };
        if !(self.in_flight.is_empty() && self.sequencer.pending() == 0) {
            self.pending_barrier = Some(barrier);
            return Ok(());
        }
        self.sequencer.advance(barrier.seq)?;
        match barrier.event {
            Barrier::Rewind { to } => self.rewind(to).await,
            Barrier::Inject(credit) => self.inject(credit).await,
        }
    }

    /// Write the out-of-band credit at the committed tip (DRS-E4 §3.8
    /// item 3). The store attributes it; the report records where.
    async fn inject(
        &mut self,
        credit: ServeCredit,
    ) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        let injected = self.connector.ask(Inject(credit)).await.map_err(collapse)?;
        self.report.injected.push(Injection {
            at: injected.at,
            credit,
        });
        Ok(())
    }

    /// Pop to `to`, unless a committed injection sits above it — the bit is
    /// not block-owned, and the pop would strand it.
    async fn rewind(&mut self, to: BlockHeight) -> Result<(), PipelineFault<Src::Fault, S::Fault>> {
        if let Some(stranded) = self.report.injected.iter().find(|i| i.at > to) {
            return Err(PipelineFault::RewindBelowInjection {
                to,
                injected_at: stranded.at,
                credit: stranded.credit,
            });
        }
        let rewound = self.connector.ask(Rewind { to }).await.map_err(collapse)?;
        let digest = self.connector.ask(Digest).await.map_err(collapse)?;
        self.report.switches.push(Switch {
            to,
            popped: rewound.popped,
            digest,
        });
        // The popped heights' root comparisons were against the trace's
        // rows for a branch the chain has now left; the re-extension will
        // compare the canonical blocks at those heights.
        self.report.roots.retract_above(to);
        self.report.weights.retract_above(to);
        self.report.emission.retract_above(to);
        self.ledger.rewind_to(to);
        self.form_at = next_height(Some(to));
        Ok(())
    }
}
