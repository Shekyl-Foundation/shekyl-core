// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The connector's reply: what ends the writer, and what the driver owns.
//!
//! The actor file holds the messages. This module holds the answer those
//! messages share, so a new message maps a fault by calling [`fault_reply`]
//! rather than growing another copy of the stale arms.

use crate::schedule::ChainRules;
use crate::source::ServeCredit;
use shekyl_chain_rules::{Corrupt, Fault, ReferenceMismatch, Retry, Stale, Target, TxSlot};
use shekyl_chain_store::store::{StoreError, StoreInvariant};
use shekyl_types::{BlockHash, BlockHeight, SettlementEpoch};

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
    pub(crate) const fn of(fault: &RunFault) -> Option<Self> {
        match fault {
            RunFault::Store(StoreError::InvariantViolated(row)) => Some(Self::Halted(*row)),
            RunFault::Store(_) => Some(Self::StoreFaulted),
            RunFault::StaleSeed { .. }
            | RunFault::StaleTarget { .. }
            | RunFault::StaleReference { .. }
            | RunFault::StaleRuleSet { .. }
            | RunFault::HeightClaim { .. }
            | RunFault::NoNextHeight { .. }
            | RunFault::RewindTarget { .. }
            | RunFault::InjectOffRegtest { .. }
            | RunFault::IssueOffRegtest { .. }
            | RunFault::NotAlternative { .. }
            | RunFault::StalePlan { .. }
            | RunFault::PlanMismatch { .. }
            | RunFault::Over(_) => None,
        }
    }
}

/// Which part of a [`super::Reorganize`] disagreed with the store's plan.
/// A driver defect; the writer stays up. The sentence is the reply; the
/// variant is what a test matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanMismatchReason {
    /// `AltChain::build` found the alternative tip unlinked.
    AlternativeTipUnheld,
    /// The alternative tip is a recorded block, so the chain has no entries.
    AlternativeTipRecorded,
    /// The fork choice, re-derived on the actor, keeps the incumbent.
    IncumbentKept,
    /// The formed promotions are not one per alternative-chain entry.
    PromotedLength,
    /// A formed promotion is not its alt row's identity or witness.
    PromotedRow,
    /// The formed demotions are not the recorded chain above the fork.
    DemotedChain,
    /// The block `form` refused is not an entry of the alternative chain.
    RefusedBlockUnheld,
}

impl std::fmt::Display for PlanMismatchReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlternativeTipUnheld => "the plan's alternative tip is not held",
            Self::AlternativeTipRecorded => "the plan's alternative tip is a recorded block",
            Self::IncumbentKept => "the fork choice keeps the incumbent",
            Self::PromotedLength => "the promoted blocks are not the alternative chain's entries",
            Self::PromotedRow => "a promoted block is not its alt row (identity or witness)",
            Self::DemotedChain => "the demoted blocks are not the recorded chain above the fork point (identity or witness)",
            Self::RefusedBlockUnheld => "the block form refused is not an entry of the alternative chain",
        })
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
    /// The driver's target claim disagreed with the target the store's
    /// headers derive (RD-Q5's class: a defect — the ledger and the store
    /// described different chains).
    #[error("driver defect: target claim at height {height} was {claimed}, the chain derives {expected} ({retry:?})")]
    StaleTarget {
        /// The connecting height.
        height: BlockHeight,
        /// What the driver claimed.
        claimed: Target,
        /// What the store's headers derive.
        expected: Target,
        /// What the validator would allow next.
        retry: Retry,
    },
    /// The driver's reference claim for a listed body disagreed with the
    /// chain — the height or the root at the body's `reference_block`, or
    /// no claim where the chain holds the reference in the window
    /// (`CHAIN_RULES_CRATE.md` §4.6, the third claim). RD-Q5's class: a
    /// defect — the driver's header chain and the store described
    /// different chains — never a verdict and never a second verify.
    #[error("driver defect: reference claim at height {height}, slot {slot:?}, for {reference:?}: claimed {claimed:?}, the chain holds {expected:?} ({retry:?})", claimed = claims.claimed, expected = claims.expected)]
    StaleReference {
        /// The connecting height.
        height: BlockHeight,
        /// The listed slot whose body names the reference.
        slot: TxSlot,
        /// The `reference_block` the body names.
        reference: BlockHash,
        /// What the driver claimed against what the chain holds.
        claims: Box<ReferenceMismatch>,
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
    /// rule set and the record are both keyed by the connecting height,
    /// and a block judged under the claimed one would be judged
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
    /// An [`super::Inject`] under rules other than regtest. The out-of-band
    /// write has one producer — the regtest injector — and no chain but a
    /// regtest chain can carry one (DRS-E4 §3.8 item 3); refused here,
    /// before the store sees it, so a source that carries one into a
    /// scheduled replay is a driver fault and not a store-terminal one.
    #[error("inject for {persona} (shard {shard}, epoch {epoch}) under {rules:?}: the out-of-band serve credit is regtest-only", persona = credit.persona, shard = credit.shard, epoch = credit.epoch)]
    InjectOffRegtest {
        /// The credit refused.
        credit: ServeCredit,
        /// The rules the connector runs under.
        rules: ChainRules,
    },
    /// An [`super::IssueDraws`] under rules other than regtest: the door has
    /// one producer, as [`super::Inject`]'s has, and is refused here for the
    /// same reason.
    #[error("issue of draws for epoch {epoch} under {rules:?}: the out-of-band draw issue is regtest-only")]
    IssueOffRegtest {
        /// The epoch the draws were for.
        epoch: SettlementEpoch,
        /// The rules the connector runs under.
        rules: ChainRules,
    },
    /// An [`super::OfferAlt`] for a block whose parent is the recorded tip:
    /// an extension, which is an [`super::Apply`]'s. A driver defect; the
    /// writer stays up.
    #[error("driver defect: block offered as an alternative extends the tip {parent:?}")]
    NotAlternative {
        /// The block's parent, the recorded tip.
        parent: BlockHash,
    },
    /// A [`super::Reorganize`] whose plan was made against a tip the store no
    /// longer holds. A driver defect (the plan is stale), never a switch; the
    /// writer stays up.
    #[error("driver defect: switch planned against tip {planned:?}, the store's tip is {tip:?}")]
    StalePlan {
        /// The plan's tip.
        planned: shekyl_chain_rules::Tip,
        /// The store's tip now.
        tip: Option<shekyl_chain_rules::Tip>,
    },
    /// A [`super::Reorganize`] whose formed blocks are not the ones the store's
    /// plan names, or whose fork choice no longer switches. A driver defect;
    /// the writer stays up.
    #[error("driver defect: the switch's blocks do not match its plan ({reason})")]
    PlanMismatch {
        /// Which part disagreed.
        reason: PlanMismatchReason,
    },
    /// The writer is over: a store-terminal fault was already replied.
    #[error("the writer is over: {0:?}")]
    Over(RunEnd),
}

/// A `validate` or cheap-tier fault, as the connector's reply.
///
/// `arm_corrupt` is the one difference between the two sites: on the connect
/// batch the refusal is `batch.refuse_corrupt` inside the live write; over a
/// snapshot the refusal is a write whose only job is to arm the halt.
pub(crate) fn fault_reply(
    height: BlockHeight,
    fault: Fault<StoreError>,
    arm_corrupt: impl FnOnce(Corrupt) -> RunFault,
) -> RunFault {
    match fault {
        Fault::View(e) => RunFault::Store(e),
        Fault::Corrupt(observed) => arm_corrupt(observed),
        Fault::Stale(Stale::Seed {
            claimed,
            expected,
            retry,
        }) => RunFault::StaleSeed {
            height,
            claimed,
            expected,
            retry,
        },
        Fault::Stale(Stale::Target {
            claimed,
            expected,
            retry,
        }) => RunFault::StaleTarget {
            height,
            claimed,
            expected,
            retry,
        },
        Fault::Stale(Stale::Reference {
            slot,
            reference,
            claims,
            retry,
        }) => RunFault::StaleReference {
            height,
            slot,
            reference,
            claims,
            retry,
        },
        Fault::Stale(Stale::RuleSet { .. }) => RunFault::StaleRuleSet { height },
    }
}
