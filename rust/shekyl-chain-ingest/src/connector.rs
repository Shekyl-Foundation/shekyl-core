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
//! [`Apply`] is a bounded run of consecutive `Extend`s in one closure (its
//! length is the checkpoint granularity), a [`Rewind`] is one closure of
//! pops. Between messages the actor holds the store, the rule set in force,
//! the trace's `borrow` door, and nothing mutable.
//!
//! # The supervision table, as code
//!
//! Every non-verdict outcome the contracts can return maps to a lifecycle;
//! none inherits the framework's default. The [`Apply`] handler is the
//! table (§1.1):
//!
//! | outcome | here |
//! | --- | --- |
//! | `form` refused (`Err(InvalidBlock)` in the staged verdict) or `validate` refused | **a verdict, not a fault**: recorded in [`Applied::refused`]; the run of `Extend`s stops there (its child cannot connect) and what connected before it lands |
//! | `Fault::View(store error)` | **halt**: the batch aborts, the error is the reply, the actor is over |
//! | `Fault::Corrupt` | `WriteBatch::refuse_corrupt` arms the halt (SI-10) and its `InvariantViolated` — carrying the validator's value — is the reply; the batch aborts; **terminal** |
//! | `Fault::Stale(Seed { .. })` | a **driver defect** in replay (RD-Q5): surfaced on first occurrence with the claim and the expectation; terminal for the run |
//! | `Fault::Stale(RuleSet { .. })` | a **driver defect** (the schedule handed the two stages different sets): surfaced, not retried |
//! | the trace has no facts at the height | the run cannot connect honestly: surfaced ([`RunFault::NoFacts`]) |
//!
//! **No restart.** `on_panic` breaks; nothing supervises this actor into
//! coming back (RD-Q11, RULED): a halt laundered into a retry loop is the
//! `InvalidBlock`-mapping failure in another shape. Once a terminal fault
//! has been replied, every later message is refused with
//! [`RunFault::Over`] until the driver stops the actor — the test written
//! first in this commit holds that the actor does not come back.
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
    validate, CenRow, ChainView, Fault, InvalidBlock, Retry, Stale, StructurallyValid, Verdict,
};
use shekyl_chain_store::digest_v0::LogicalStateDigestV0;
use shekyl_chain_store::store::{ChainStore, StoreError, StoreInvariant};
use shekyl_types::{BlockHash, BlockHeight};

use crate::schedule::ChainRules;
use crate::trace::Trace;

/// Why a run ended, as the actor remembers it after the reply that carried
/// the detail. `Copy` data only, so it can be repeated on every later
/// message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEnd {
    /// The store halted (a belt, or SI-10 through `refuse_corrupt`).
    Halted(StoreInvariant),
    /// A store engine or capability error ended the run.
    StoreFaulted,
    /// The driver's seed claim disagreed with the store at `height`.
    StaleSeed {
        /// The connecting height.
        height: BlockHeight,
    },
    /// `form` and `validate` were handed different rule sets at `height`.
    StaleRuleSet {
        /// The connecting height.
        height: BlockHeight,
    },
    /// The trace has no facts for `height`.
    NoFacts {
        /// The connecting height.
        height: BlockHeight,
    },
    /// A block was refused at `height`; the chain past it cannot connect.
    Refused {
        /// The refused height.
        height: BlockHeight,
    },
    /// A rewind named a target the chain cannot reach.
    RewindTarget {
        /// The target.
        to: BlockHeight,
    },
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
    /// The run is over; the first fault was already replied.
    #[error("the run is over: {0:?}")]
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
    /// Blocks popped.
    pub popped: u64,
    /// The tip after the rewind.
    pub tip: Option<BlockHeight>,
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

/// What the actor is built from.
pub struct ConnectorArgs {
    /// The store this actor alone writes.
    pub store: ChainStore,
    /// Which rules are in force at each height (RD-Q10's driver half).
    pub rules: ChainRules,
    /// The trace, for the `borrow` door.
    pub trace: Arc<Trace>,
}

/// The single writer (module docs).
pub struct Connector {
    store: ChainStore,
    rules: ChainRules,
    trace: Arc<Trace>,
    over: Option<RunEnd>,
}

impl Connector {
    fn end(&mut self, end: RunEnd) {
        if self.over.is_none() {
            self.over = Some(end);
        }
    }

    fn over(&self) -> Result<(), RunFault> {
        match self.over {
            Some(end) => Err(RunFault::Over(end)),
            None => Ok(()),
        }
    }

    fn end_for(fault: &RunFault) -> Option<RunEnd> {
        Some(match fault {
            RunFault::Store(StoreError::InvariantViolated(row)) => RunEnd::Halted(*row),
            RunFault::Store(_) => RunEnd::StoreFaulted,
            RunFault::StaleSeed { height, .. } => RunEnd::StaleSeed { height: *height },
            RunFault::StaleRuleSet { height } => RunEnd::StaleRuleSet { height: *height },
            RunFault::NoFacts { height } => RunEnd::NoFacts { height: *height },
            RunFault::RewindTarget { to, .. } => RunEnd::RewindTarget { to: *to },
            RunFault::Over(_) => return None,
        })
    }
}

impl Actor for Connector {
    type Args = ConnectorArgs;
    type Error = RunFault;

    async fn on_start(args: ConnectorArgs, _actor_ref: ActorRef<Self>) -> Result<Self, RunFault> {
        Ok(Self {
            store: args.store,
            rules: args.rules,
            trace: args.trace,
            over: None,
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
        self.over()?;
        let rules = self.rules;
        let trace = Arc::clone(&self.trace);
        let result: Result<Applied, RunFault> = self.store.write(|batch| {
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
                match validate(formed, &view, &in_force) {
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
        });
        match result {
            Ok(applied) => {
                if let Some((height, _)) = &applied.refused {
                    self.end(RunEnd::Refused { height: *height });
                }
                Ok(applied)
            }
            Err(fault) => {
                if let Some(end) = Self::end_for(&fault) {
                    self.end(end);
                }
                Err(fault)
            }
        }
    }
}

impl Message<Rewind> for Connector {
    type Reply = Result<Rewound, RunFault>;

    async fn handle(&mut self, msg: Rewind, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.over()?;
        let to = msg.to;
        let result: Result<Rewound, RunFault> = self.store.write(|batch| {
            let mut popped = 0u64;
            loop {
                let tip = batch.chain_view().tip()?.map(|t| t.height);
                match tip {
                    Some(tip) if tip > to => {
                        batch.pop()?;
                        popped += 1;
                    }
                    Some(tip) if tip == to => {
                        return Ok(Rewound {
                            popped,
                            tip: Some(tip),
                        })
                    }
                    other => return Err(RunFault::RewindTarget { to, tip: other }),
                }
            }
        });
        if let Err(fault) = &result {
            if let Some(end) = Self::end_for(fault) {
                self.end(end);
            }
        }
        result
    }
}

impl Message<Digest> for Connector {
    type Reply = Result<LogicalStateDigestV0, RunFault>;

    async fn handle(&mut self, _: Digest, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(self.store.begin_read()?.logical_state_digest_v0()?)
    }
}
