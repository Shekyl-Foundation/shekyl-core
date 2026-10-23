// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Validate+Connect actor — the pipeline's single writer
//! (`DRS_E2_REPLAY_DRIVER.md` §1.1, RD-Q11).
//!
//! **What it owns is the [`ChainStore`], not a `WriteBatch`.** A batch
//! exists only inside `ChainStore::write`'s branded closure and cannot be
//! held across mailbox messages — the brand doing its job. So the
//! transaction boundary is **one `write` closure per handler**: an
//! [`Apply`] is a bounded run of consecutive `Extend`s in one closure (the
//! write-transaction granularity), a [`Rewind`] is one closure of pops.
//! Between messages the actor holds the store, the rule set in force, and
//! the drawable memo. The memo is rules-side state the count reads
//! (`SO-D12b`): not chain state, not persisted, and not undone. (A facts
//! provider sat beside them until E6 slice 7
//! wave B — the E2 trace's `borrow` door or production composition from
//! the owners — handing `connect` what the validator did not yet derive;
//! every such value is the verdict's now, and `connect` takes the verdict
//! alone.)
//!
//! # The supervision table, as code
//!
//! Every non-verdict outcome the contracts can return maps to a lifecycle;
//! none inherits the framework's default. The [`Apply`] handler is the
//! table (§1.1). **Store-terminal faults end the actor; everything else is
//! a reply the driver owns.** A replay driver may treat a stale seed as
//! run-ending; the live daemon (DRS-X) re-forms on the same actor. A refusal is never `Over`.
//!
//! | outcome | here |
//! | --- | --- |
//! | `form` refused (`Err(InvalidBlock)` in the formed verdict) or `validate` refused | **a verdict, not a fault**: recorded in [`Applied::refused`]; this run of `Extend`s stops there (its child cannot connect) and what connected before it lands; **the writer stays up** |
//! | `Fault::View(store error)` | **halt**: the batch aborts, the error is the reply, the actor is over |
//! | `Fault::Corrupt` | `WriteBatch::refuse_corrupt` arms the halt (SI-10) and its `InvariantViolated` — carrying the validator's value — is the reply; the batch aborts; **terminal** |
//! | `Fault::Stale(Seed { .. })` | a **driver defect** in replay (RD-Q5): the reply carries the claim, the expectation, and the validator's `Retry`; the writer stays up so a later caller can re-`form` |
//! | `Fault::Stale(Target { .. })` | a **driver defect** in replay (the target ledger and the store described different chains, `target` module docs): surfaced with the claim, the expectation and the `Retry`; the writer stays up |
//! | `Fault::Stale(RuleSet { .. })` | a **driver defect** (the schedule handed the two stages different sets): surfaced; the writer stays up |
//! | the source's height for an `Extend` is not `tip + 1` on the batch's view | a **driver defect** ([`RunFault::HeightClaim`]): surfaced before the rule set is chosen under the wrong height; the writer stays up |
//! | a parent-side read observes a hole ([`shekyl_chain_rules::Corrupt::HoleBelowTip`]) | `refuse_corrupt` arms SI-7 and the writer **halts**, the same class a rule raises |
//! | the tip has no successor height | surfaced ([`RunFault::NoNextHeight`]); the writer stays up |
//!
//! **No restart.** `on_panic` breaks; nothing supervises this actor into
//! coming back (RD-Q11, RULED): a halt laundered into a retry loop is the
//! `InvalidBlock`-mapping failure in another shape. Once a **store-terminal**
//! fault has been replied, every later `Apply` / `Rewind` is refused with
//! [`RunFault::Over`] until the driver stops the actor — the test written
//! first in this commit holds that the actor does not come back. The latch
//! is structural, not a convention each handler remembers: the store sits
//! behind a [`Writer`] whose `write` is the only write path and refuses
//! after the first terminal fault; its reads stay open, so [`Digest`] and
//! [`HashAt`] are diagnosis reads on a halted store.
//!
//! **No fault becomes a verdict, no verdict becomes a fault.** A refusal is
//! data on the reply; a fault is the reply's error; the two never meet.

use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::sync::Arc;

use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::error::{ActorStopReason, PanicError};
use kameo::message::{Context, Message};
use shekyl_chain_rules::{
    recorded, validate_with_memo, ArchivalDelta, AtHeight, CenRow, ChainView, Corrupt,
    DrawableMemo, EffectiveMedian, Fault, HeaderRecord, HeaderView, InvalidBlock, PaidEmission,
    PerHeightRecord, StructurallyValid, Verdict, ViewRead, Weights,
};
use shekyl_chain_store::archival_snapshot::ArchivalSnapshot;
use shekyl_chain_store::codec::{FollowingDegraded, FollowingDegradedCell};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError, WriteBatch};
use shekyl_types::archival::{BondRecord, IndexedDraw, IssuedDigest};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, PCanonicalId, SettlementEpoch,
};
use shekyl_units::AtomicUnits;

use crate::schedule::ChainRules;
use crate::source::ServeCredit;

#[path = "run_fault.rs"]
mod run_fault;
#[path = "switch.rs"]
mod switch;
pub(crate) use run_fault::fault_reply;
pub use run_fault::{PlanMismatchReason, RunEnd, RunFault};
#[cfg(test)]
pub use switch::AnchorForTests;
pub use switch::{
    AltBlocksHeld, OfferAlt, Offered, PlannedBlock, PlannedDemotion, PlannedPromotion,
    PopBeyondReorgCap, RefusePromotion, Reorganize, SwitchDone, SwitchPlan, Switched, TableRows,
};

/// What an [`Apply`] did: the blocks that landed, and the refusal that
/// stopped the run of `Extend`s if one did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Connected blocks, in order.
    pub connected: Vec<(BlockHeight, BlockHash)>,
    /// The curve-tree root **after** each connected block's drain — the
    /// verdict's derivation (`ValidatedBlock::root_after`, DRS-E3), one per
    /// entry of `connected`, in the same order. The replay compares each
    /// against the trace's recorded root at that height (CTW-5): the
    /// per-height oracle the LMDB trace makes possible while it exists.
    pub roots: Vec<(BlockHeight, CurveTreeRoot)>,
    /// Each connected block's weight, long-term weight and the long-term
    /// effective median it was judged under — the verdict's derivation
    /// (`ValidatedBlock::weights`, CEN-G6/G6b, slice 7), one per entry of
    /// `connected`, in the same order. The replay compares each against
    /// the trace's three recorded values at that height: the C++'s
    /// `block_info` columns and the exporter's re-derived median — the
    /// parity oracle for the medians while the LMDB trace exists.
    pub weights: Vec<(BlockHeight, Weights)>,
    /// Each connected block's paid emission — the reward F14b priced, its
    /// split, the accumulator G12 advanced (`ValidatedBlock::emission`,
    /// slice 7 commit 5) — one per entry of `connected`. The replay
    /// compares the accumulator against the trace's `coins_generated` at
    /// that height: the C++'s `block_info.bi_coins`, hence the paid reward
    /// at every height by difference — the penalty's parity oracle on the
    /// one captured block over the median.
    pub emission: Vec<(BlockHeight, PaidEmission)>,
    /// Each connected block's archival transition — what the verdict says
    /// the block does to the bond records, the serve credits, the slash log
    /// and the epoch state (`ValidatedBlock::archival`, DRS-E4 commit 4) —
    /// one per entry of `connected`. The scenario driver reads it for the
    /// blocks it mines and compares it with what the store wrote from it
    /// (E4 commit 5: `BondRecordOf`, `BudgetAccruingOf`).
    pub archival: Vec<(BlockHeight, ArchivalDelta)>,
    /// The census rows the connected blocks' verdicts exercised — the
    /// union of each `ChainValid`'s coverage, for the grader's clause (1).
    pub exercised: BTreeSet<&'static str>,
    /// A refusal — `form`'s or `validate`'s verdict — and where.
    pub refused: Option<(BlockHeight, InvalidBlock)>,
}

/// What a [`Rewind`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewound {
    /// Blocks popped. The tip afterwards is the `to` the message named —
    /// the handler returns only when it is.
    pub popped: u64,
}

/// Connect a run of consecutive formed blocks in one write closure.
#[derive(Debug)]
pub struct Apply(pub Vec<(BlockHeight, Verdict<StructurallyValid>)>);

/// Pop until the tip is `to`, in one write closure.
#[derive(Clone, Copy, Debug)]
pub struct Rewind {
    /// The height that is the tip afterwards.
    pub to: BlockHeight,
}

/// Write the out-of-band serve credit at the tip, in its own store
/// transaction, through the store's regtest door
/// (`ChainStore::regtest_inject_serve_credit`, DRS-E4 §3.8 item 3). Not
/// journaled: a later `Rewind` below the attributed height does not carry
/// it away, which is why the pipeline refuses one.
#[derive(Clone, Copy, Debug)]
pub struct Inject(pub ServeCredit);

/// What an [`Inject`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Injected {
    /// The height the store attributed the bit to: the tip when it was
    /// written.
    pub at: BlockHeight,
}

/// Write issued draws into `epoch`'s index, in their own store transaction,
/// through the store's regtest door (`ChainStore::regtest_issue_draws`;
/// `ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D10f`): the stand-in for admission,
/// which does not exist yet, so a scenario's slash pass has draws to
/// settle. `digest` is the epoch's running digest with these draws folded
/// in; the caller folds it, as admission will. Not journaled, like
/// [`Inject`].
#[derive(Clone, Debug)]
pub struct IssueDraws {
    /// The epoch the draws were issued in.
    pub epoch: SettlementEpoch,
    /// The draws, each with whether it was passed.
    pub draws: Vec<IndexedDraw>,
    /// The epoch's digest after them.
    pub digest: IssuedDigest,
}

/// The redb-side logical state now (commit 2), for the digest sink.
#[derive(Clone, Copy, Debug)]
pub struct Digest;

/// The redb-side archival state now, as `DRS_E4_ARCHIVAL_WRITER.md`
/// §3.8.1's rows (`ReadSnapshot::archival_snapshot`): the checkpoint's
/// other encoding, diffed against the trace's `0x04` record rather than
/// hashed (`ARW-25`). The scenario driver's read for holding the writer to
/// its archival rows after one step; the pipeline's checkpoint takes both
/// encodings together through [`CheckpointState`].
#[derive(Clone, Copy, Debug)]
pub struct ArchivalState;

/// The redb side's covered-tip checkpoint, read in **one** snapshot: the
/// recorded tip, the logical-state digest and the archival rows. The
/// trace's two checkpoint records came from one LMDB snapshot the walker
/// took after the daemon's last write; this is the redb side's one read
/// after the replay's, so the two encodings describe the same state and
/// the tip says which. A tip other than the trace's covered tip is the
/// pipeline's signal not to compare.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointState;

/// [`CheckpointState`]'s reply: the state at the recorded tip, both
/// encodings from the same read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipEncodings {
    /// The recorded tip the digest and rows describe; `None` on an empty
    /// chain.
    pub tip: Option<BlockHeight>,
    /// The logical-state digest (commit 2).
    pub digest: crate::trace::Digest,
    /// §3.8.1's rows (`ARW-25`).
    pub archival: ArchivalSnapshot,
}

/// The hash of the block recorded at a height, for the driver's seed claim
/// when its ledger's window has moved past that height (`seed` module
/// docs). `None` above the tip.
#[derive(Clone, Copy, Debug)]
pub struct HashAt {
    /// The height asked for.
    pub height: BlockHeight,
}

/// The header record at a height — identity, header, cumulative difficulty
/// — for the driver's target claim when its ledger lacks a height the
/// LWMA-1 window reads (`target` module docs). `None` above the tip.
#[derive(Clone, Copy, Debug)]
pub struct HeaderAt {
    /// The height asked for.
    pub height: BlockHeight,
}

/// Re-derive CEN-D4's target for `height`, and the work it adds, over the
/// writer's own view, when the driver's target ledger observed a corrupt
/// window — a hole, a work decrease or an overflowing sum — in records the
/// store supplied (`target` module docs). The writer acts on its own
/// observation, never on the driver's: a corrupt chain halts it through
/// `refuse_corrupt`, as `validate`'s derivation would; a consistent one
/// replies `Ok`, and the ledger was the defect.
///
/// `height` must be the height the store connects at next. Above it the
/// derivation would read past the tip, and a height the writer cannot see
/// is not a hole; the reply is then `HeightClaim`, a driver defect, and
/// nothing is halted.
#[derive(Clone, Copy, Debug)]
pub struct ObserveTarget {
    /// The connecting height whose window is re-read.
    pub height: BlockHeight,
}

/// The curve-tree root going into `height` — `curve_tree_roots[height]`,
/// the state the header at `height` commits to (SCW-19; `EMPTY` at `0`).
/// `None` above `tip + 1`. The read the scenario driver holds the
/// wallet-side tree to (DRS-E3 §2.5).
#[derive(Clone, Copy, Debug)]
pub struct RootAt {
    /// The height asked for.
    pub height: BlockHeight,
}

/// `persona`'s bond record as the store holds it — `archival_bond[persona]`
/// (DRS-E1 A1), the row CEN-L7 reads a persona's standing from. `None` is
/// no record. The read the archival scenarios hold the writer to: a join
/// the validator admitted is `Some` here in the same block, with the
/// fields the verdict's delta carried (`DRS_E4_ARCHIVAL_WRITER.md` §6 row
/// 5).
#[derive(Clone, Copy, Debug)]
pub struct BondRecordOf {
    /// The persona asked for.
    pub persona: PCanonicalId,
}

/// The open epoch's accrued staker inflow as the store holds it —
/// `archival_budget_accruing[epoch]` (DRS-E1 A13). `None` before the
/// epoch's first accrual and after its close (SI-23), so a scenario can
/// derive what a block's accrual post-image must be from the row the
/// writer folds it onto, and hold the writer to the row's removal at the
/// close.
#[derive(Clone, Copy, Debug)]
pub struct BudgetAccruingOf {
    /// The epoch asked for.
    pub epoch: SettlementEpoch,
}

/// What a block producer needs from the chain to build the next
/// candidate, read on the view the validator will judge it against and
/// through the definitions the validator uses (`tx_volume_window`,
/// `mtp_median_at`) — so the template is priced at the operands it will be
/// judged by, never at a second copy of them. The `get_block_template`
/// read path in the shape the live daemon (DRS-X) will serve it; the slice-6 scenario driver is
/// its first consumer.
#[derive(Clone, Copy, Debug)]
pub struct TemplateFacts;

/// [`TemplateFacts`]' reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainFacts {
    /// The height the next block connects at (`tip + 1`; `0` when empty).
    pub connecting: BlockHeight,
    /// The tip's identity, [`BlockHash::NULL`] when empty (CEN-A2).
    pub previous: BlockHash,
    /// The tree state at `connecting` (CEN-B5).
    pub curve_tree_root: shekyl_types::CurveTreeRoot,
    /// The parent's gross emission (CEN-F13's accumulator); zero at genesis.
    pub parent_coins_generated: shekyl_units::AtomicUnits,
    /// Everything burned through the tip.
    pub total_burned: shekyl_units::AtomicUnits,
    /// CEN-F17's `n` at `connecting`: the archival shards the parent
    /// chain's fold has closed, read through the validator's own definition
    /// (`shekyl_chain_rules::closed_shards_before`, `shekyl_types::shard_of`
    /// the parent's `cumulative_archival_len`), so the producer prices the
    /// fee split at the operand the validator reads
    /// (`rules::miner::BurnOperands`; E6 slice 7 wave B, re-keyed from the
    /// leaf count's frozen-segment count by DRS-E4 commit 4).
    pub closed_shards: shekyl_economics::ClosedShardCount,
    /// CEN-F20's window at `connecting`.
    pub tx_volume: shekyl_economics::TxVolume,
    /// CEN-C2's median at `connecting`; `None` at genesis.
    pub median_timestamp: Option<shekyl_types::Timestamp>,
    /// CEN-G6/G6b's two medians at `connecting` — what the producer's
    /// coinbase is priced against and its body bounded by, read through
    /// the validator's own definition (`effective_median_at`, slice 7 Q4:
    /// one derivation, two consumers) and never from the store's recorded
    /// `long_term_effective_median(tip)`, which is one block stale.
    pub medians: EffectiveMedian,
}

/// The recorded tip, as the dialer's handshake carries it (`SyncPayload`'s
/// fields): the block count, the tip's cumulative difficulty and its
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainTip {
    /// Blocks recorded: the tip's height plus one, the count the
    /// handshake's `current_height` reports.
    pub count: shekyl_types::ChainCount,
    /// The tip's cumulative difficulty.
    pub cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty,
    /// The tip's identity.
    pub top_id: BlockHash,
}

/// `TipChanged` (`DRS_X_STORE_FLIP.md` DX-Q2 item 5): the one source of the
/// tip. The connector publishes it on a `watch` after every committed
/// connect, pop and switch — after the write returns, never before the
/// commit — and once at start. `seq` rises with each publication, so a
/// consumer can tell two publications of one tip apart (a pop and the
/// connect back) and say which it last acted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipChanged {
    /// The publication's number: 0 at start, one more each time.
    pub seq: u64,
    /// The tip; `None` on an empty chain.
    pub tip: Option<ChainTip>,
}

/// A receiver of [`TipChanged`], for a consumer (the dialer's handshake,
/// new-block relay, the sync owner, the RPC, the pool, the miner's
/// template producer).
#[derive(Clone, Copy, Debug)]
pub struct WatchTip;

/// The recorded tip on `store` now.
fn chain_tip(store: &ChainStore) -> Result<Option<ChainTip>, StoreError> {
    let read = store.begin_read()?;
    let Some(tip) = read.tip()?.recorded else {
        return Ok(None);
    };
    let AtHeight::Recorded(info) = read.block_info(tip.height)? else {
        unreachable!("the recorded tip has its row");
    };
    Ok(Some(ChainTip {
        count: shekyl_types::ChainCount::with_tip(tip.height)
            .expect("a recorded tip has a successor count"),
        cumulative_difficulty: info.cumulative_difficulty,
        top_id: tip.hash,
    }))
}

/// What the actor is built from.
pub struct ConnectorArgs {
    /// The store this actor alone writes. Shared, so the readers that place
    /// arrivals and answer the RPC take their snapshots off the same file
    /// (the ingest service's router, `StoreFacts`); none of them writes.
    pub store: Arc<ChainStore>,
    /// Which rules are in force at each height (RD-Q10's driver half).
    pub rules: ChainRules,
}

/// The store behind its latch: the only way to a write closure, refusing
/// every write after the first store-terminal fault (module docs). Reads
/// stay open.
struct Writer {
    store: Arc<ChainStore>,
    over: Option<RunEnd>,
}

impl Writer {
    const fn live(store: Arc<ChainStore>) -> Self {
        Self { store, over: None }
    }

    /// One write closure, or [`RunFault::Over`] once a terminal fault has
    /// been replied. A terminal fault out of `f` arms the latch; the first
    /// stands.
    fn write<R, F>(&mut self, f: F) -> Result<R, RunFault>
    where
        F: for<'id> FnOnce(&mut WriteBatch<'_, 'id>) -> Result<R, RunFault>,
    {
        if let Some(end) = self.over {
            return Err(RunFault::Over(end));
        }
        let result = self.store.write(f);
        self.latch(result)
    }

    /// One read through a write batch that **aborts**. The producer's
    /// [`TemplateFacts`](crate::TemplateFacts): the validator's view and
    /// its poison latch, and no commit. A terminal fault arms the same
    /// latch `write` does.
    fn inspect<R, F>(&mut self, f: F) -> Result<R, RunFault>
    where
        F: for<'id> FnOnce(&mut WriteBatch<'_, 'id>) -> Result<R, RunFault>,
    {
        if let Some(end) = self.over {
            return Err(RunFault::Over(end));
        }
        let result = self.store.inspect(f);
        self.latch(result)
    }

    /// The store's regtest door, in its own transaction, behind the same
    /// latch: the one write that is not a batch. The store refuses it
    /// under an anchored trust, on an empty chain and for a persona with
    /// no record; each of those is the store's `Cannot`, terminal like any
    /// other store fault — the replay cannot reach the daemon's archival
    /// state without the bit, so the run is over.
    fn inject(
        &mut self,
        trust: shekyl_chain_rules::Trust,
        credit: ServeCredit,
    ) -> Result<BlockHeight, RunFault> {
        if let Some(end) = self.over {
            return Err(RunFault::Over(end));
        }
        let result = self
            .store
            .regtest_inject_serve_credit(trust, credit.persona, credit.shard, credit.epoch)
            .map_err(RunFault::Store);
        self.latch(result)
    }

    /// The store's regtest draw issue, behind the same latch as
    /// [`Self::inject`] and terminal on the same refusals.
    fn issue_draws(
        &mut self,
        trust: shekyl_chain_rules::Trust,
        issue: &IssueDraws,
    ) -> Result<(), RunFault> {
        if let Some(end) = self.over {
            return Err(RunFault::Over(end));
        }
        let result = self
            .store
            .regtest_issue_draws(trust, issue.epoch, &issue.draws, issue.digest)
            .map_err(RunFault::Store);
        self.latch(result)
    }

    /// The store for one operation that reads a snapshot and then writes —
    /// the switch, which judges on a snapshot before its write closure and
    /// keeps the verdicts alive through it (`switch.rs`). The same latch as
    /// [`Self::write`]: refused once over, armed by a terminal fault.
    fn with_store<R, F>(&mut self, f: F) -> Result<R, RunFault>
    where
        F: FnOnce(&ChainStore) -> Result<R, RunFault>,
    {
        if let Some(end) = self.over {
            return Err(RunFault::Over(end));
        }
        let result = f(&self.store);
        self.latch(result)
    }

    /// Arm the latch on a terminal fault; the first stands.
    fn latch<R>(&mut self, result: Result<R, RunFault>) -> Result<R, RunFault> {
        if let Some(end) = result.as_ref().err().and_then(RunEnd::of) {
            self.over.get_or_insert(end);
        }
        result
    }

    /// A read snapshot — open on a halted store, so the driver can still
    /// name the store's state (or meet the same hole the validator did).
    fn read(&self) -> Result<ReadSnapshot<'_>, StoreError> {
        self.store.begin_read()
    }
}

/// The single writer (module docs).
pub struct Connector {
    writer: Writer,
    /// [`TipChanged`]'s one publisher.
    tip: tokio::sync::watch::Sender<TipChanged>,
    /// The `following_degraded` latch as the store holds it, published after
    /// every write that sets it (`DRS_X_STORE_FLIP.md` DX-Q2 item 8). `None`
    /// is clear.
    degraded: tokio::sync::watch::Sender<Option<FollowingDegraded>>,
    rules: ChainRules,
    /// What the run takes on the release's word — `rules.trust()`, read
    /// once at start. A field rather than a call so a test can reach the
    /// checkpoint arm of the fork choice with a fixture table no regtest
    /// run carries ([`AnchorForTests`]).
    trust: shekyl_chain_rules::Trust,
    /// Drawable sets the count has already built, keyed by the epoch and
    /// the opening block's hash. Not chain state (`SO-D12b`).
    memo: DrawableMemo,
}

impl Actor for Connector {
    type Args = ConnectorArgs;
    type Error = RunFault;

    async fn on_start(args: ConnectorArgs, _actor_ref: ActorRef<Self>) -> Result<Self, RunFault> {
        let tip = chain_tip(&args.store)?;
        let degraded = args
            .store
            .begin_read()?
            .get_property::<FollowingDegradedCell>()?;
        Ok(Self {
            tip: tokio::sync::watch::Sender::new(TipChanged { seq: 0, tip }),
            degraded: tokio::sync::watch::Sender::new(degraded),
            writer: Writer::live(args.store),
            rules: args.rules,
            trust: args.rules.trust(),
            memo: DrawableMemo::new(),
        })
    }

    /// No restart (RD-Q11): a panic stops the actor and it stays stopped.
    /// The kameo default, pinned here so a framework change cannot turn a
    /// halt into a retry loop.
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, RunFault> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }
}

impl Connector {
    /// Publish the tip after a committed write (module docs: `TipChanged`).
    /// A read that fails here leaves the last publication standing: the
    /// next write meets the same store.
    pub(crate) fn publish_tip(&self) {
        if let Ok(tip) = chain_tip(&self.writer.store) {
            self.tip.send_modify(|now| {
                now.seq += 1;
                now.tip = tip;
            });
        }
    }
}

/// Chain sync's evidence of a heavier chain past the cap
/// (`P2P_3_CHAIN_SYNC_BRIEF.md` §A item 7): write the `following_degraded`
/// latch in the connector's own transaction. One latch, one writer. The
/// reply is whether this message set it; a latch already set keeps its
/// first evidence.
#[derive(Clone, Copy, Debug)]
pub struct RaiseAlarm(pub FollowingDegraded);

/// A receiver of the `following_degraded` latch: `None` is clear.
#[derive(Clone, Copy, Debug)]
pub struct WatchLatch;

impl Message<RaiseAlarm> for Connector {
    type Reply = Result<bool, RunFault>;

    async fn handle(
        &mut self,
        msg: RaiseAlarm,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let evidence = msg.0;
        let set = self.writer.write(|batch| {
            batch
                .raise_following_degraded(&evidence)
                .map_err(RunFault::Store)
        })?;
        if set {
            self.degraded.send_replace(Some(evidence));
        }
        Ok(set)
    }
}

impl Message<WatchLatch> for Connector {
    type Reply = tokio::sync::watch::Receiver<Option<FollowingDegraded>>;

    async fn handle(
        &mut self,
        _: WatchLatch,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.degraded.subscribe()
    }
}

impl Message<WatchTip> for Connector {
    type Reply = tokio::sync::watch::Receiver<TipChanged>;

    async fn handle(&mut self, _: WatchTip, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.tip.subscribe()
    }
}

/// The death rule's second bound (`shekyl_chain_store`'s `store/alt.rs`):
/// after a connect at `height`, every alt block at or below the last anchor
/// at or below it leaves with its bodies. Its fork point would be below the
/// anchor, which CEN-E2 refuses at offer and at the switch, so nothing can
/// promote it. The store's own connect applies the cap; the anchors are the
/// release's trust, which the store does not hold.
pub(crate) fn retire_below_the_anchor(
    batch: &shekyl_chain_store::store::WriteBatch<'_, '_>,
    trust: &shekyl_chain_rules::Trust,
    height: BlockHeight,
) -> Result<u64, shekyl_chain_store::store::StoreError> {
    match trust.anchors().last_at_or_below(height) {
        Some(anchor) => batch.retire_alt_blocks(anchor.height),
        None => Ok(0),
    }
}

impl Message<Apply> for Connector {
    type Reply = Result<Applied, RunFault>;

    async fn handle(&mut self, msg: Apply, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let rules = self.rules;
        let trust = self.trust;
        let memo = &mut self.memo;
        let applied = self.writer.write(|batch| {
            let view = batch.chain_view();
            let mut applied = Applied::default();
            for (claimed, formed) in msg.0 {
                // The height is the store's to say, not the source's: the
                // rule set in force and the row the block is recorded
                // under are both keyed by the height the
                // chain connects at, which is `tip + 1` on this view (the
                // tip advances as the batch connects). The tuple's height
                // is the source's bookkeeping; where the two disagree the
                // source is wrong about the chain, and that is a driver
                // defect surfaced before anything is judged under the
                // wrong schedule (#852 review).
                // The parent's hash is CEN-A2's operand inside `validate`,
                // not a second copy of this height check. A source that
                // names the connecting height and a different parent is a
                // wrong block: a verdict, and the writer stays up. The
                // live service only applies a block whose parent was the
                // tip, so it places that A2 again rather than cancelling
                // the span.
                let (height, _) = connecting(view.tip()?)?;
                if claimed != height {
                    return Err(RunFault::HeightClaim {
                        claimed,
                        connecting: height,
                    });
                }
                let formed = match formed {
                    Ok(formed) => formed,
                    Err(refused) => {
                        applied.refused = Some((height, refused));
                        break;
                    }
                };
                let in_force = rules.in_force(height);
                match validate_with_memo(formed, &view, &in_force, &trust, Some(memo)) {
                    Ok(Ok(valid)) => {
                        let hash = valid.block().hash();
                        let root_after = valid.block().root_after();
                        let weights = *valid.block().weights();
                        let emission = *valid.block().emission();
                        let archival = valid.block().archival().clone();
                        applied
                            .exercised
                            .extend(valid.coverage().iter().map(CenRow::as_str));
                        batch.connect(valid, in_force)?;
                        retire_below_the_anchor(batch, &trust, height)?;
                        applied.connected.push((height, hash));
                        applied.roots.push((height, root_after));
                        applied.weights.push((height, weights));
                        applied.emission.push((height, emission));
                        applied.archival.push((height, archival));
                    }
                    Ok(Err(refused)) => {
                        applied.refused = Some((height, refused));
                        break;
                    }
                    Err(fault) => return Err(validate_fault(batch, height, fault)),
                }
            }
            Ok(applied)
        })?;
        if !applied.connected.is_empty() {
            self.publish_tip();
        }
        Ok(applied)
    }
}

impl Message<Rewind> for Connector {
    type Reply = Result<Rewound, RunFault>;

    async fn handle(&mut self, msg: Rewind, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let to = msg.to;
        let rewound = self.writer.write(|batch| {
            let tip = batch.chain_view().tip()?.map(|t| t.height);
            let popped = match tip {
                Some(tip) if tip >= to => tip.to_raw() - to.to_raw(),
                other => return Err(RunFault::RewindTarget { to, tip: other }),
            };
            // The popped blocks' identities, read before they go: an alt
            // branch built on one no longer reaches the main chain, and
            // leaves with them (`store/alt.rs`, the invariant). A switch's
            // pops demote what they pop instead, so this is the rewind's.
            let view = batch.chain_view();
            let mut gone = Vec::new();
            for height in to.to_raw() + 1..=to.to_raw() + popped {
                match view.header_at(BlockHeight::from_raw(height))? {
                    AtHeight::Recorded(record) => gone.push(record.hash),
                    AtHeight::AboveTip => unreachable!("every height to the tip is recorded"),
                }
            }
            drop(view);
            // One run of pops, then SI-5 over the tree they left
            // (`pop_many`): the belt is the run's, not each pop's.
            batch.pop_many(popped)?;
            batch.retire_alt_blocks_on(&gone)?;
            Ok(Rewound { popped })
        })?;
        if rewound.popped > 0 {
            self.publish_tip();
        }
        Ok(rewound)
    }
}

impl Message<Inject> for Connector {
    type Reply = Result<Injected, RunFault>;

    async fn handle(&mut self, msg: Inject, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let Inject(credit) = msg;
        if !matches!(self.rules, ChainRules::Regtest { .. }) {
            return Err(RunFault::InjectOffRegtest {
                credit,
                rules: self.rules,
            });
        }
        let at = self.writer.inject(self.trust, credit)?;
        Ok(Injected { at })
    }
}

impl Message<IssueDraws> for Connector {
    type Reply = Result<(), RunFault>;

    async fn handle(
        &mut self,
        msg: IssueDraws,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if !matches!(self.rules, ChainRules::Regtest { .. }) {
            return Err(RunFault::IssueOffRegtest {
                epoch: msg.epoch,
                rules: self.rules,
            });
        }
        self.writer.issue_draws(self.trust, &msg)
    }
}

impl Message<Digest> for Connector {
    type Reply = Result<crate::trace::Digest, RunFault>;

    async fn handle(&mut self, _: Digest, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(self.writer.read()?.logical_state_digest_v0()?)
    }
}

impl Message<ArchivalState> for Connector {
    type Reply = Result<ArchivalSnapshot, RunFault>;

    async fn handle(
        &mut self,
        _: ArchivalState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.archival_snapshot()?)
    }
}

impl Message<CheckpointState> for Connector {
    type Reply = Result<TipEncodings, RunFault>;

    async fn handle(
        &mut self,
        _: CheckpointState,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let read = self.writer.read()?;
        Ok(TipEncodings {
            tip: read.tip()?.recorded.map(|t| t.height),
            digest: read.logical_state_digest_v0()?,
            archival: read.archival_snapshot()?,
        })
    }
}

impl Message<TemplateFacts> for Connector {
    type Reply = Result<ChainFacts, RunFault>;

    /// Read on the validator's view, inside a batch that aborts. Every
    /// operand — `total_burned` included — comes off that one view, and
    /// `tx_volume_window` / `mtp_median_at` / `effective_median_at` are the
    /// rules' own definitions.
    /// A hole or a decreasing prefix sum halts the writer; nothing commits.
    async fn handle(
        &mut self,
        _: TemplateFacts,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.writer.inspect(|batch| {
            let total_burned = batch.total_burned()?;
            let view = batch.chain_view();
            let tip = view.tip()?;
            let (connecting, previous) = connecting(tip)?;
            let curve_tree_root = present(
                batch,
                connecting,
                PerHeightRecord::CurveTreeRoot,
                view.root_at(connecting),
            )?;
            let parent_coins_generated = match tip {
                None => shekyl_units::AtomicUnits::ZERO,
                Some(t) => definition(batch, recorded(&view, t.height))?.coins_generated,
            };
            let closed_shards = definition(
                batch,
                shekyl_chain_rules::closed_shards_before(&view, connecting),
            )?;
            let tx_volume = definition(
                batch,
                shekyl_chain_rules::tx_volume_window(&view, connecting),
            )?;
            let median_timestamp =
                definition(batch, shekyl_chain_rules::mtp_median_at(&view, connecting))?;
            let medians = definition(
                batch,
                shekyl_chain_rules::effective_median_at(&view, connecting),
            )?;
            Ok(ChainFacts {
                connecting,
                previous,
                curve_tree_root,
                parent_coins_generated,
                total_burned,
                closed_shards,
                tx_volume,
                median_timestamp,
                medians,
            })
        })
    }
}

/// A `validate` fault on the connect batch, as the connector's reply — one
/// mapping for `Apply` and the switch's promotion. The corrupt arm arms the
/// halt on this batch (SI-10); [`fault_reply`] maps the rest.
fn validate_fault(
    batch: &WriteBatch<'_, '_>,
    height: BlockHeight,
    fault: Fault<StoreError>,
) -> RunFault {
    fault_reply(height, fault, |observed| {
        RunFault::Store(batch.refuse_corrupt(observed))
    })
}

/// The height the next block connects at and the hash it must name as its
/// parent, from the recorded tip: `(0, NULL)` on an empty chain, else
/// `(tip + 1, tip.hash)`. The one derivation both handlers use — the
/// producer to price a template, `Apply` to hold a source's claimed height
/// to it — so the two cannot drift. A tip with no successor is
/// [`RunFault::NoNextHeight`], not a saturated height.
fn connecting(tip: Option<shekyl_chain_rules::Tip>) -> Result<(BlockHeight, BlockHash), RunFault> {
    match tip {
        None => Ok((BlockHeight::ZERO, BlockHash::NULL)),
        Some(t) => Ok((
            t.height
                .checked_add(BlockCount::ONE)
                .ok_or(RunFault::NoNextHeight { tip: t.height })?,
            t.hash,
        )),
    }
}

/// A [`ViewRead`] from a definition, as a connector fault. A hole halts.
fn definition<T>(
    batch: &WriteBatch<'_, '_>,
    read: Result<T, ViewRead<StoreError>>,
) -> Result<T, RunFault> {
    match read {
        Ok(value) => Ok(value),
        Err(ViewRead::View(fault)) => Err(RunFault::Store(fault)),
        Err(ViewRead::Corrupt(corrupt)) => Err(RunFault::Store(batch.refuse_corrupt(corrupt))),
    }
}

/// A height the producer asked for as recorded. `AboveTip` inside the
/// range the caller derived (`tip + 1` for the live root) is
/// [`Corrupt::HoleBelowTip`] for `record` and halts; a store fault passes
/// through, and an in-range hole is already that fault from the view.
fn present<T>(
    batch: &WriteBatch<'_, '_>,
    height: BlockHeight,
    record: PerHeightRecord,
    at: Result<AtHeight<T>, StoreError>,
) -> Result<T, RunFault> {
    match at {
        Ok(AtHeight::Recorded(value)) => Ok(value),
        Ok(AtHeight::AboveTip) => Err(RunFault::Store(
            batch.refuse_corrupt(Corrupt::HoleBelowTip { at: height, record }),
        )),
        Err(fault) => Err(RunFault::Store(fault)),
    }
}

impl Message<HashAt> for Connector {
    type Reply = Result<Option<BlockHash>, RunFault>;

    async fn handle(&mut self, msg: HashAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(match self.writer.read()?.block_info(msg.height)? {
            AtHeight::Recorded(info) => Some(info.hash),
            AtHeight::AboveTip => None,
        })
    }
}

impl Message<ObserveTarget> for Connector {
    type Reply = Result<(), RunFault>;

    async fn handle(
        &mut self,
        msg: ObserveTarget,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rule_set = self.rules.in_force(msg.height);
        self.writer.write(|batch| {
            let view = batch.chain_view();
            let (height, _) = connecting(view.tip()?)?;
            if msg.height != height {
                return Err(RunFault::HeightClaim {
                    claimed: msg.height,
                    connecting: height,
                });
            }
            let observed = match shekyl_chain_rules::target_claim(&view, height, &rule_set) {
                // CEN-D6 is a verdict on a consistent window, not a fault.
                Ok(Err(_refused)) => return Ok(()),
                Ok(Ok(target)) => {
                    shekyl_chain_rules::cumulative_difficulty_after(&view, height, target)
                        .map(|_work| ())
                }
                Err(fault) => Err(fault),
            };
            match observed {
                Ok(()) => Ok(()),
                Err(Fault::View(e)) => Err(RunFault::Store(e)),
                Err(Fault::Corrupt(corrupt)) => Err(RunFault::Store(batch.refuse_corrupt(corrupt))),
                Err(Fault::Stale(stale)) => unreachable!("a derivation is never stale: {stale}"),
            }
        })
    }
}

impl Message<HeaderAt> for Connector {
    type Reply = Result<Option<HeaderRecord>, RunFault>;

    async fn handle(
        &mut self,
        msg: HeaderAt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let read = self.writer.read()?;
        let AtHeight::Recorded(info) = read.block_info(msg.height)? else {
            return Ok(None);
        };
        let AtHeight::Recorded(body) = read.block(msg.height)? else {
            return Ok(None);
        };
        Ok(Some(HeaderRecord {
            hash: info.hash,
            header: body.block.header,
            cumulative_difficulty: info.cumulative_difficulty,
        }))
    }
}

impl Message<RootAt> for Connector {
    type Reply = Result<Option<CurveTreeRoot>, RunFault>;

    async fn handle(&mut self, msg: RootAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(match self.writer.read()?.root_at(msg.height)? {
            AtHeight::Recorded(root) => Some(root),
            AtHeight::AboveTip => None,
        })
    }
}

impl Message<BondRecordOf> for Connector {
    type Reply = Result<Option<BondRecord>, RunFault>;

    async fn handle(
        &mut self,
        msg: BondRecordOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.bond_record(&msg.persona)?)
    }
}

impl Message<BudgetAccruingOf> for Connector {
    type Reply = Result<Option<AtomicUnits>, RunFault>;

    async fn handle(
        &mut self,
        msg: BudgetAccruingOf,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.budget_accruing(msg.epoch)?)
    }
}
