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
//! Between messages the actor holds the store, the rule set in force, the
//! facts provider (`facts.rs`: the E2 trace's `borrow` door, or production
//! composition from the owners), and nothing mutable.
//!
//! # The supervision table, as code
//!
//! Every non-verdict outcome the contracts can return maps to a lifecycle;
//! none inherits the framework's default. The [`Apply`] handler is the
//! table (§1.1). **Store-terminal faults end the actor; everything else is
//! a reply the driver owns.** A replay driver may treat a stale seed as
//! run-ending; E3 re-forms on the same actor. A refusal is never `Over`.
//!
//! | outcome | here |
//! | --- | --- |
//! | `form` refused (`Err(InvalidBlock)` in the formed verdict) or `validate` refused | **a verdict, not a fault**: recorded in [`Applied::refused`]; this run of `Extend`s stops there (its child cannot connect) and what connected before it lands; **the writer stays up** |
//! | `Fault::View(store error)` | **halt**: the batch aborts, the error is the reply, the actor is over |
//! | `Fault::Corrupt` | `WriteBatch::refuse_corrupt` arms the halt (SI-10) and its `InvariantViolated` — carrying the validator's value — is the reply; the batch aborts; **terminal** |
//! | `Fault::Stale(Seed { .. })` | a **driver defect** in replay (RD-Q5): the reply carries the claim, the expectation, and the validator's `Retry`; the writer stays up so a later caller can re-`form` |
//! | `Fault::Stale(RuleSet { .. })` | a **driver defect** (the schedule handed the two stages different sets): surfaced; the writer stays up |
//! | the source's height for an `Extend` is not `tip + 1` on the batch's view | a **driver defect** ([`RunFault::HeightClaim`]): surfaced before the rule set is chosen or a fact is composed under the wrong height; the writer stays up |
//! | the facts provider has nothing at the height | the run cannot connect honestly: surfaced ([`RunFault::NoFacts`]); the writer stays up |
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
    recorded, validate, AtHeight, CenRow, ChainView, Corrupt, Fault, InvalidBlock, Retry, Stale,
    StructurallyValid, Verdict, ViewRead,
};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError, StoreInvariant, WriteBatch};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};

use crate::facts::{FactsFault, FactsFor};
use crate::schedule::ChainRules;

/// Why the writer is over: store-terminal faults only. `Copy` data, so it
/// can be repeated on every later `Apply` / `Rewind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// The store halted (a belt, or SI-10 through `refuse_corrupt`).
    Halted(StoreInvariant),
    /// A store engine or capability error ended the writer.
    StoreFaulted,
}

impl RunEnd {
    /// The end a fault brings, if it is store-terminal: a store error ends
    /// the writer; a driver defect, a missing fact and a bad rewind target
    /// are replies the driver owns, and the writer stays up.
    const fn of(fault: &RunFault) -> Option<Self> {
        match fault {
            RunFault::Store(StoreError::InvariantViolated(row)) => Some(Self::Halted(*row)),
            RunFault::Store(_) => Some(Self::StoreFaulted),
            RunFault::StaleSeed { .. }
            | RunFault::StaleRuleSet { .. }
            | RunFault::HeightClaim { .. }
            | RunFault::NoFacts { .. }
            | RunFault::NoNextHeight { .. }
            | RunFault::RewindTarget { .. }
            | RunFault::Over(_) => None,
        }
    }
}

/// The reply error of a connector message: the first occurrence carries
/// its detail, every later message carries [`RunFault::Over`].
#[derive(Debug, thiserror::Error)]
pub enum RunFault {
    /// The store refused or failed (a belt's halt is
    /// `StoreError::InvariantViolated`).
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The driver's seed claim disagreed with the store (RD-Q5: a defect).
    #[error("driver defect: seed claim at height {height} was {claimed:?}, the chain holds {expected:?} ({retry:?})")]
    StaleSeed {
        /// The connecting height.
        height: BlockHeight,
        /// What the driver claimed.
        claimed: BlockHash,
        /// What the store holds at the seed height.
        expected: BlockHash,
        /// What the validator would allow next.
        retry: Retry,
    },
    /// `form` and `validate` were handed different rule sets.
    #[error(
        "driver defect: rule set handed to form differs from the one in force at height {height}"
    )]
    StaleRuleSet {
        /// The connecting height.
        height: BlockHeight,
    },
    /// The source's height for an `Extend` is not the height the chain
    /// connects at (`tip + 1` on the batch's view). Nothing is judged: the
    /// rule set, the facts and the record are all keyed by the connecting
    /// height, and a block judged under the claimed one would be judged
    /// under the wrong schedule. A driver defect; the writer stays up.
    #[error(
        "driver defect: the source claims height {claimed} for a block the chain connects at {connecting}"
    )]
    HeightClaim {
        /// The source's height for the event.
        claimed: BlockHeight,
        /// `tip + 1` as the store holds it.
        connecting: BlockHeight,
    },
    /// The facts provider has nothing for `height` — a trace that does not
    /// cover it, or a producer that did not price it ([`FactsFault::None`]).
    #[error("no connect facts for height {height}; connect cannot be handed what nobody composed")]
    NoFacts {
        /// The connecting height.
        height: BlockHeight,
    },
    /// The recorded tip is `u64::MAX`: there is no next height to build at.
    /// A chain that long has no successor; the writer stays up.
    #[error("tip {tip} has no successor height")]
    NoNextHeight {
        /// The tip that cannot be extended.
        tip: BlockHeight,
    },
    /// A rewind to `to` when the tip is `tip`.
    #[error("rewind to {to} is not below the tip {tip:?}")]
    RewindTarget {
        /// The target.
        to: BlockHeight,
        /// The tip at the time.
        tip: Option<BlockHeight>,
    },
    /// The writer is over: a store-terminal fault was already replied.
    #[error("the writer is over: {0:?}")]
    Over(RunEnd),
}

/// What an [`Apply`] did: the blocks that landed, and the refusal that
/// stopped the run of `Extend`s if one did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Connected blocks, in order.
    pub connected: Vec<(BlockHeight, BlockHash)>,
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

/// The redb-side logical state now (commit 2), for the digest sink.
#[derive(Clone, Copy, Debug)]
pub struct Digest;

/// The hash of the block recorded at a height, for the driver's seed claim
/// when its ledger's window has moved past that height (`seed` module
/// docs). `None` above the tip.
#[derive(Clone, Copy, Debug)]
pub struct HashAt {
    /// The height asked for.
    pub height: BlockHeight,
}

/// What a block producer needs from the chain to build the next
/// candidate, read on the view the validator will judge it against and
/// through the definitions the validator uses (`tx_volume_window`,
/// `mtp_median_at`) — so the template is priced at the operands it will be
/// judged by, never at a second copy of them. The `get_block_template`
/// read path in the shape E3 will serve it; the slice-6 scenario driver is
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
    /// CEN-F20's window at `connecting`.
    pub tx_volume: shekyl_economics::TxVolume,
    /// CEN-C2's median at `connecting`; `None` at genesis.
    pub median_timestamp: Option<shekyl_types::Timestamp>,
}

/// What the actor is built from.
pub struct ConnectorArgs<F> {
    /// The store this actor alone writes.
    pub store: ChainStore,
    /// Which rules are in force at each height (RD-Q10's driver half).
    pub rules: ChainRules,
    /// Where `connect`'s facts come from ([`FactsFor`]): the E2 trace, or
    /// production composition from the owners (`facts.rs`).
    pub facts: Arc<F>,
}

/// The store behind its latch: the only way to a write closure, refusing
/// every write after the first store-terminal fault (module docs). Reads
/// stay open.
struct Writer {
    store: ChainStore,
    over: Option<RunEnd>,
}

impl Writer {
    const fn live(store: ChainStore) -> Self {
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
        if let Some(end) = result.as_ref().err().and_then(RunEnd::of) {
            self.over.get_or_insert(end);
        }
        result
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

/// The single writer (module docs), over a facts provider `F`.
pub struct Connector<F> {
    writer: Writer,
    rules: ChainRules,
    facts: Arc<F>,
}

impl<F: FactsFor + Send + Sync + 'static> Actor for Connector<F> {
    type Args = ConnectorArgs<F>;
    type Error = RunFault;

    async fn on_start(
        args: ConnectorArgs<F>,
        _actor_ref: ActorRef<Self>,
    ) -> Result<Self, RunFault> {
        Ok(Self {
            writer: Writer::live(args.store),
            rules: args.rules,
            facts: args.facts,
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

impl<F: FactsFor + Send + Sync + 'static> Message<Apply> for Connector<F> {
    type Reply = Result<Applied, RunFault>;

    async fn handle(&mut self, msg: Apply, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let rules = self.rules;
        let facts = Arc::clone(&self.facts);
        self.writer.write(|batch| {
            let view = batch.chain_view();
            let mut applied = Applied::default();
            for (claimed, formed) in msg.0 {
                // The height is the store's to say, not the source's: the
                // rule set in force, the facts composed, and the row the
                // block is recorded under are all keyed by the height the
                // chain connects at, which is `tip + 1` on this view (the
                // tip advances as the batch connects). The tuple's height
                // is the source's bookkeeping; where the two disagree the
                // source is wrong about the chain, and that is a driver
                // defect surfaced before anything is judged under the
                // wrong schedule (#852 review).
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
                match validate(formed, &view, &in_force, &rules.trust()) {
                    Ok(Ok(valid)) => {
                        // The seam: facts read against the same view the
                        // verdict was judged on, from whoever composes
                        // them (`facts.rs`). A missing height is the
                        // caller's; a view fault is the store's; a hole
                        // below the tip is `Corrupt` and halts.
                        let facts = match facts.facts_for(height, &valid, &view) {
                            Ok(facts) => facts,
                            Err(FactsFault::None { height }) => {
                                return Err(RunFault::NoFacts { height })
                            }
                            Err(FactsFault::View(e)) => return Err(RunFault::Store(e)),
                            Err(FactsFault::Corrupt(observed)) => {
                                return Err(RunFault::Store(batch.refuse_corrupt(observed)))
                            }
                        };
                        let hash = valid.block().hash();
                        applied
                            .exercised
                            .extend(valid.coverage().iter().map(CenRow::as_str));
                        batch.connect(valid, facts, in_force)?;
                        applied.connected.push((height, hash));
                    }
                    Ok(Err(refused)) => {
                        applied.refused = Some((height, refused));
                        break;
                    }
                    Err(Fault::View(e)) => return Err(RunFault::Store(e)),
                    // SI-10: the refusal arms the halt and *is* the error —
                    // `ChainStore::write` makes an `InvariantViolated` win
                    // over anything else the closure returns, so the row
                    // (which carries the validator's `Corrupt` value) is
                    // what the caller sees, with no second wrapper to drift
                    // from it.
                    Err(Fault::Corrupt(observed)) => {
                        return Err(RunFault::Store(batch.refuse_corrupt(observed)))
                    }
                    Err(Fault::Stale(Stale::Seed {
                        claimed,
                        expected,
                        retry,
                    })) => {
                        return Err(RunFault::StaleSeed {
                            height,
                            claimed,
                            expected,
                            retry,
                        })
                    }
                    Err(Fault::Stale(Stale::RuleSet { .. })) => {
                        return Err(RunFault::StaleRuleSet { height })
                    }
                }
            }
            Ok(applied)
        })
    }
}

impl<F: FactsFor + Send + Sync + 'static> Message<Rewind> for Connector<F> {
    type Reply = Result<Rewound, RunFault>;

    async fn handle(&mut self, msg: Rewind, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let to = msg.to;
        self.writer.write(|batch| {
            let mut popped = 0u64;
            loop {
                let tip = batch.chain_view().tip()?.map(|t| t.height);
                match tip {
                    Some(tip) if tip > to => {
                        batch.pop()?;
                        popped += 1;
                    }
                    Some(tip) if tip == to => return Ok(Rewound { popped }),
                    other => return Err(RunFault::RewindTarget { to, tip: other }),
                }
            }
        })
    }
}

impl<F: FactsFor + Send + Sync + 'static> Message<Digest> for Connector<F> {
    type Reply = Result<crate::trace::Digest, RunFault>;

    async fn handle(&mut self, _: Digest, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(self.writer.read()?.logical_state_digest_v0()?)
    }
}

impl<F: FactsFor + Send + Sync + 'static> Message<TemplateFacts> for Connector<F> {
    type Reply = Result<ChainFacts, RunFault>;

    /// Read on the validator's view, inside a batch that aborts. Every
    /// operand — `total_burned` included — comes off that one view, and
    /// `tx_volume_window` / `mtp_median_at` are the rules' own definitions.
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
            let curve_tree_root = present(batch, connecting, view.root_at(connecting))?;
            let parent_coins_generated = match tip {
                None => shekyl_units::AtomicUnits::ZERO,
                Some(t) => definition(batch, recorded(&view, t.height))?.coins_generated,
            };
            let tx_volume = definition(
                batch,
                shekyl_chain_rules::tx_volume_window(&view, connecting),
            )?;
            let median_timestamp =
                definition(batch, shekyl_chain_rules::mtp_median_at(&view, connecting))?;
            Ok(ChainFacts {
                connecting,
                previous,
                curve_tree_root,
                parent_coins_generated,
                total_burned,
                tx_volume,
                median_timestamp,
            })
        })
    }
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
/// range the caller derived (`tip + 1` for the live root, the tip itself
/// for its block) is [`Corrupt::HoleBelowTip`] and halts; a store fault
/// passes through, and an in-range hole is already that fault from the view.
fn present<T>(
    batch: &WriteBatch<'_, '_>,
    height: BlockHeight,
    at: Result<AtHeight<T>, StoreError>,
) -> Result<T, RunFault> {
    match at {
        Ok(AtHeight::Recorded(value)) => Ok(value),
        Ok(AtHeight::AboveTip) => Err(RunFault::Store(
            batch.refuse_corrupt(Corrupt::HoleBelowTip { at: height }),
        )),
        Err(fault) => Err(RunFault::Store(fault)),
    }
}

impl<F: FactsFor + Send + Sync + 'static> Message<HashAt> for Connector<F> {
    type Reply = Result<Option<BlockHash>, RunFault>;

    async fn handle(&mut self, msg: HashAt, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(match self.writer.read()?.block_info(msg.height)? {
            AtHeight::Recorded(info) => Some(info.hash),
            AtHeight::AboveTip => None,
        })
    }
}
