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
//! trace's `borrow` door, and nothing mutable.
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
//! | the trace has no facts at the height | the run cannot connect honestly: surfaced ([`RunFault::NoFacts`]); the writer stays up |
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
    validate, AtHeight, CenRow, ChainView, Fault, InvalidBlock, Retry, Stale, StructurallyValid,
    Verdict,
};
use shekyl_chain_store::store::{ChainStore, ReadSnapshot, StoreError, StoreInvariant, WriteBatch};
use shekyl_types::{BlockHash, BlockHeight};

use crate::schedule::ChainRules;
use crate::trace::Trace;

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
            | RunFault::NoFacts { .. }
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
    /// The trace does not cover `height`.
    #[error(
        "the trace has no facts for height {height}; connect cannot be handed passed-through facts"
    )]
    NoFacts {
        /// The connecting height.
        height: BlockHeight,
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

/// What the actor is built from.
pub struct ConnectorArgs {
    /// The store this actor alone writes.
    pub store: ChainStore,
    /// Which rules are in force at each height (RD-Q10's driver half).
    pub rules: ChainRules,
    /// The trace, for the `borrow` door.
    pub trace: Arc<Trace>,
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

    /// A read snapshot — open on a halted store, so the driver can still
    /// name the store's state (or meet the same hole the validator did).
    fn read(&self) -> Result<ReadSnapshot<'_>, StoreError> {
        self.store.begin_read()
    }
}

/// The single writer (module docs).
pub struct Connector {
    writer: Writer,
    rules: ChainRules,
    trace: Arc<Trace>,
}

impl Actor for Connector {
    type Args = ConnectorArgs;
    type Error = RunFault;

    async fn on_start(args: ConnectorArgs, _actor_ref: ActorRef<Self>) -> Result<Self, RunFault> {
        Ok(Self {
            writer: Writer::live(args.store),
            rules: args.rules,
            trace: args.trace,
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

impl Message<Apply> for Connector {
    type Reply = Result<Applied, RunFault>;

    async fn handle(&mut self, msg: Apply, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let rules = self.rules;
        let trace = Arc::clone(&self.trace);
        self.writer.write(|batch| {
            let view = batch.chain_view();
            let mut applied = Applied::default();
            for (height, formed) in msg.0 {
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
                        let Some(facts) = trace.borrow(height) else {
                            return Err(RunFault::NoFacts { height });
                        };
                        let hash = valid.block().hash();
                        applied
                            .exercised
                            .extend(valid.coverage().iter().map(CenRow::as_str));
                        batch.connect(valid, facts.into(), in_force)?;
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

impl Message<Rewind> for Connector {
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

impl Message<Digest> for Connector {
    type Reply = Result<crate::trace::Digest, RunFault>;

    async fn handle(&mut self, _: Digest, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(self.writer.read()?.logical_state_digest_v0()?)
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
