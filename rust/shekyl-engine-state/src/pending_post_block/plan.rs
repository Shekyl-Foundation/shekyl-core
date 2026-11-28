// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A stake before it is sent (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q2, BD-Q3,
//! §3.6): the plan the request seals, the post signed at its due block, and
//! the ended row a plan that never bonded leaves behind.
//!
//! One persona is in one stage. The transitions live here so the check a
//! replacement post must pass has one body, and so a blocked attempt records
//! its reason on the row that is actually waiting.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot};

use super::{
    record_was_sent, OutcomeKind, PendingBondPost, PendingKind, RecordKind, SealAdmission,
    StakingOutcome,
};

/// The obligation a planned stake takes on, as the plan keeps it until it is
/// signed at its due block (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3: "the
/// holdings descriptor (the posture)", new in v15).
///
/// The persisted twin of engine-core's `StakePosture` (rule 118: the
/// state-shaped copy lives with the record that persists it), carrying the
/// holdings the bond posts at its due block.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum PlannedPosture {
    /// The whole-corpus backstop (`CompleteTree` holdings).
    SupportCompleteTree,
    /// A market bond over the named shards (`ShardSetCompact` holdings),
    /// named at the request. The production request refuses the market
    /// posture until shard assignment exists (`COMPLETETREE_ACTIVATION.md`
    /// §10 item 1); the emission walk's market-bond fixture plans through it.
    Market {
        /// The shard ids, in the order the request named them.
        shard_ids: Vec<u64>,
    },
}

/// Why a plan at or past its due block was not signed on its last attempt
/// (BD-Q3 as ruled 2026-11-26: "`in_flight` shows the reason"). Written
/// when an attempt is blocked, cleared when the plan is signed or ends.
///
/// Two classes, because they end differently. A **temporary** reason is
/// retried every tick with no limit. A **limited** reason is retried every
/// tick until the plan's maximum wait from its due block, and a plan whose
/// attempt is still blocked by one at that point ends as
/// [`PlanEnding::WaitedOut`].
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum PlanWait {
    /// Temporary: the wallet's node could not be read.
    NodeUnreachable,
    /// Temporary: the wallet's node is still synchronizing.
    NodeSyncing,
    /// Temporary: the persona scan, the curve tree or the wallet ledger is
    /// behind the chain, so the funding, the final shards or a canonical
    /// reference cannot be read yet.
    WalletBehind,
    /// Limited: the fee at the live rate is above what the funding holds
    /// beyond the bond's floor.
    FeeAboveFunding,
    /// Limited: the wallet's daemon is not this computer's node, and the
    /// shards the bond owes are read only from the wallet's own node.
    NodeNotLocal,
    /// Limited: the node's reply did not match the chain the persona scan
    /// verified.
    NodeMismatch,
    /// Limited: the persona body store could not write a shard.
    StoreFailed,
    /// Limited: the post could not be assembled for a reason this wallet
    /// cannot name more closely (the cause is in the wallet's log). Limited
    /// so a plan that can never be assembled ends and its funding returns.
    AssemblyFailed,
}

impl PlanWait {
    /// Whether this reason counts toward the plan's maximum wait.
    #[must_use]
    pub const fn is_limited(self) -> bool {
        match self {
            Self::NodeUnreachable | Self::NodeSyncing | Self::WalletBehind => false,
            Self::FeeAboveFunding
            | Self::NodeNotLocal
            | Self::NodeMismatch
            | Self::StoreFailed
            | Self::AssemblyFailed => true,
        }
    }
}

/// One durable planned stake: the persona, the funding it reserves from the
/// request, and what it needs to be signed at its due block (BD-Q2, BD-Q3;
/// v15). Nothing in it is signed and no byte of it has been sent, so no bond
/// can land from it.
///
/// The due is not stored: it is `max(a + 1 + draw, requested_at)` on the
/// daemon-claimed count clock, where `a` is recomputed each tick from the
/// live records of the reserved funding (BD-Q2), so a reorg that moves the
/// funding moves the due with it.
///
/// `P`-side behavioral history, like [`PendingBondPost`]: redacted `Debug`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PendingBondPlan {
    /// The owning persona's slot ordinal.
    pub p_slot: PSlot,
    /// The persona the stake is for.
    pub persona: PCanonicalId,
    /// The obligation the bond takes on.
    pub posture: PlannedPosture,
    /// The delay draw `s ~ U[0, W]`, taken once at the request. Never
    /// re-drawn: a second sample biases the post earlier (BD-Q2).
    pub draw: BlockCount,
    /// The daemon-claimed count at the request: the due is never before it.
    pub requested_at: ChainCount,
    /// The funding outputs reserved for the bond from the request on.
    pub funding_gindexes: Vec<GlobalOutputIndex>,
    /// The highest block the reserved funding sits in. An output missing from
    /// the persona scan's live set counts as spent only once the sealed scan
    /// has covered this block: absence from a scan that has not reached it
    /// is not a spend.
    pub funded_through: BlockHeight,
    /// Why the last attempt at or past due was not signed, if it was blocked.
    pub wait: Option<PlanWait>,
}

impl std::fmt::Debug for PendingBondPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingBondPlan(<redacted pending-plan>)")
    }
}

/// How a plan ended without a bond (BD-Q3 as ruled 2026-11-26). A persona
/// sees at most one funding and one drain, so a plan that ends without a
/// bond ends the persona: its funding is drained to the principal, its slot
/// is retired, and staking again is a new persona.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum PlanEnding {
    /// A reserved funding output was spent by another transaction. Nothing
    /// outside the wallet can spend `P`'s outputs. Whatever is left is
    /// drained.
    SpentElsewhere,
    /// The owner withdrew the plan before it was signed.
    Withdrawn,
    /// The shards the bond owes can no longer be bonded: the wallet's node
    /// has discarded their bodies.
    Unbondable,
    /// The plan's maximum wait from its due block passed while its attempts
    /// were still blocked by a limited reason.
    WaitedOut,
}

/// A plan that ended without a bond and whose persona still holds funding
/// to drain (v15): "ended, drain owed". It is written in the same seal that
/// removes the plan, so a crash between the ending and the drain leaves a
/// record the next open acts on, never a funded persona with no record.
///
/// It reserves nothing: the drain that empties the persona selects its
/// whole live funding, and nothing else spends a persona that never bonded
/// (no claim, no exit). It stays until the persona holds no live funding
/// and has no live drain, then its slot is retired.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct EndedPlan {
    /// The persona's slot ordinal, kept derivable until the drain is done.
    pub p_slot: PSlot,
    /// The persona whose plan ended.
    pub persona: PCanonicalId,
    /// How it ended.
    pub ending: PlanEnding,
    /// The highest block the persona's funding sat in when its stake ended.
    /// Its slot counts as drained only once the sealed scan has covered this
    /// block and holds none of its funding.
    pub funded_through: BlockHeight,
}

impl std::fmt::Debug for EndedPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndedPlan")
            .field("p_slot", &"<redacted>")
            .field("persona", &"<redacted>")
            .field("ending", &self.ending)
            .field("funded_through", &self.funded_through)
            .finish()
    }
}

/// What [`PendingPostBlock::sign_plan`](super::PendingPostBlock::sign_plan) and [`PendingPostBlock::resign_post`](super::PendingPostBlock::resign_post)
/// decided about a post signed outside the pending lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAdmission {
    /// The signed post took the record's place.
    Signed,
    /// The plan (or the never-sent post) is gone: withdrawn or ended while
    /// the post was proved. The signed bytes are discarded unsent.
    PlanGone,
    /// A submit of the held post was attempted; it is never re-signed.
    AlreadySent,
    /// A reservation was released since the assembly read its funding.
    /// Retry from a fresh read.
    Stale,
    /// Another record reserves one of the post's inputs. Retry from a fresh
    /// read.
    InputRaced,
}

/// What [`PendingPostBlock::withdraw_plan`](super::PendingPostBlock::withdraw_plan) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Withdrawal {
    /// The plan ended as withdrawn; its funding is drained next.
    Withdrawn(EndedPlan),
    /// The post is already signed: a signed post refuses withdrawal.
    AlreadySigned,
    /// The persona has no plan.
    NoPlan,
}

/// Where one persona's stake stands. One persona is in one stage
/// (`ARCHIVAL_BOND_POST_DELAY.md` §3.6). [`PendingPostBlock::stake_stage`](super::PendingPostBlock::stake_stage)
/// is the only scan; a new stage is a new arm, and every transition matches
/// it.
#[derive(Clone, Copy, Debug)]
pub enum StakeStage<'a> {
    /// Sealed at the request. Nothing is signed.
    Plan(&'a PendingBondPlan),
    /// Signed, and no submit has been attempted.
    Unsent(&'a PendingBondPost),
    /// A submit was attempted. The bytes are never replaced (BD-Q3 Rule 1).
    Sent(&'a PendingBondPost),
    /// Ended without a bond. Its funding drain is owed.
    Ended(&'a EndedPlan),
}

impl<'a> StakeStage<'a> {
    /// The persona this stage belongs to.
    #[must_use]
    pub fn persona(self) -> PCanonicalId {
        match self {
            Self::Plan(plan) => plan.persona,
            Self::Unsent(post) | Self::Sent(post) => post.persona,
            Self::Ended(ended) => ended.persona,
        }
    }

    /// The slot this stage keeps derivable.
    #[must_use]
    pub fn p_slot(self) -> PSlot {
        match self {
            Self::Plan(plan) => plan.p_slot,
            Self::Unsent(post) | Self::Sent(post) => post.p_slot,
            Self::Ended(ended) => ended.p_slot,
        }
    }

    /// The row that can still be signed or ended. A sent post and an ended
    /// plan are not waiting.
    #[must_use]
    pub fn waiting(self) -> Option<WaitingStake<'a>> {
        match self {
            Self::Plan(plan) => Some(WaitingStake::Plan(plan)),
            Self::Unsent(post) => Some(WaitingStake::Unsent(post)),
            Self::Sent(_) | Self::Ended(_) => None,
        }
    }
}

/// A stake that has not been sent: a plan, or a post no submit has touched.
/// Endings, the wait reason, and a signature touch only this.
#[derive(Clone, Copy, Debug)]
pub enum WaitingStake<'a> {
    /// Sealed at the request.
    Plan(&'a PendingBondPlan),
    /// Signed, and no submit has been attempted.
    Unsent(&'a PendingBondPost),
}

impl<'a> WaitingStake<'a> {
    /// The persona this row is for.
    #[must_use]
    pub fn persona(self) -> PCanonicalId {
        match self {
            Self::Plan(plan) => plan.persona,
            Self::Unsent(post) => post.persona,
        }
    }

    /// The funding the row reserved.
    #[must_use]
    pub fn funding_gindexes(self) -> &'a [GlobalOutputIndex] {
        match self {
            Self::Plan(plan) => &plan.funding_gindexes,
            Self::Unsent(post) => &post.funding_gindexes,
        }
    }

    /// The highest block that funding sits in.
    #[must_use]
    pub fn funded_through(self) -> BlockHeight {
        match self {
            Self::Plan(plan) => plan.funded_through,
            Self::Unsent(post) => post.funded_through,
        }
    }
}

/// An ended plan whose drain is done. Constructible only by
/// [`PendingPostBlock::drained_plans`](super::PendingPostBlock::drained_plans), so holding one is the predicate:
/// the sealed scan covers the funding block, the slot holds no live funding,
/// and no drain is in flight.
///
/// Not persisted. The actor's funded gate still refuses a slot that gained
/// funding after the read that produced this value.
#[derive(Clone, PartialEq, Eq)]
pub struct DrainedEndedPlan {
    ended: EndedPlan,
}

impl DrainedEndedPlan {
    /// The ended row the drain predicate accepted.
    #[must_use]
    pub fn ended(&self) -> &EndedPlan {
        &self.ended
    }

    /// The persona whose plan ended.
    #[must_use]
    pub fn persona(&self) -> PCanonicalId {
        self.ended.persona
    }

    /// The slot the retirement wipes.
    #[must_use]
    pub fn p_slot(&self) -> PSlot {
        self.ended.p_slot
    }
}

impl std::fmt::Debug for DrainedEndedPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DrainedEndedPlan")
            .field(&self.ended)
            .finish()
    }
}

/// Write `wait` into `slot` when it differs. One comparison for the plan
/// and the unsent post.
fn assign_wait(slot: &mut Option<PlanWait>, wait: Option<PlanWait>) -> bool {
    if *slot == wait {
        return false;
    }
    *slot = wait;
    true
}

/// Which row [`PendingPostBlock::stake_stage`](super::PendingPostBlock::stake_stage) names. The index is the
/// scan's result, so a mutation does not scan again.
enum StakeAt {
    Plan(usize),
    Unsent(usize),
    Sent(usize),
    Ended(usize),
}

impl super::PendingPostBlock {
    /// The one scan of `persona`'s stake. A plan outranks a post, and a post
    /// outranks an ended row: the live row is what a transition acts on.
    fn locate(&self, persona: &PCanonicalId) -> Option<StakeAt> {
        if let Some(idx) = self.plans.iter().position(|p| &p.persona == persona) {
            return Some(StakeAt::Plan(idx));
        }
        if let Some(idx) = self.posts.iter().position(|p| &p.persona == persona) {
            let post = &self.posts[idx];
            return Some(if record_was_sent(post.state, post.terminal) {
                StakeAt::Sent(idx)
            } else {
                StakeAt::Unsent(idx)
            });
        }
        self.ended_plans
            .iter()
            .position(|p| &p.persona == persona)
            .map(StakeAt::Ended)
    }

    /// Where `persona`'s stake stands, if it has one.
    #[must_use]
    pub fn stake_stage(&self, persona: &PCanonicalId) -> Option<StakeStage<'_>> {
        Some(match self.locate(persona)? {
            StakeAt::Plan(idx) => StakeStage::Plan(&self.plans[idx]),
            StakeAt::Unsent(idx) => StakeStage::Unsent(&self.posts[idx]),
            StakeAt::Sent(idx) => StakeStage::Sent(&self.posts[idx]),
            StakeAt::Ended(idx) => StakeStage::Ended(&self.ended_plans[idx]),
        })
    }

    /// Stakes that have not been sent: the rows an ending, a wait, or a
    /// signature may touch.
    pub fn waiting_stakes(&self) -> impl Iterator<Item = WaitingStake<'_>> + '_ {
        self.stake_stages().filter_map(StakeStage::waiting)
    }

    /// Every stake row, in stage order: plans, then posts, then ended plans.
    pub fn stake_stages(&self) -> impl Iterator<Item = StakeStage<'_>> + '_ {
        let plans = self.plans.iter().map(StakeStage::Plan);
        let posts = self.posts.iter().map(|post| {
            if record_was_sent(post.state, post.terminal) {
                StakeStage::Sent(post)
            } else {
                StakeStage::Unsent(post)
            }
        });
        let ended = self.ended_plans.iter().map(StakeStage::Ended);
        plans.chain(posts).chain(ended)
    }

    /// Seal a planned stake at the request (BD-Q3): classify it as a stake
    /// for its persona, and insert it iff admitted. The plan reserves its
    /// funding from here on.
    pub fn seal_plan(&mut self, plan: PendingBondPlan, snapshot_generation: u64) -> SealAdmission {
        match self.classify_seal(
            PendingKind::Post,
            &plan.persona,
            &plan.funding_gindexes,
            snapshot_generation,
        ) {
            SealAdmission::Admit => {}
            refused => return refused,
        }
        self.replace_outcome(RecordKind::Post, &plan.persona);
        self.plans.push(plan);
        SealAdmission::Admit
    }

    /// Replace `persona`'s plan with the post signed at its due block, in one
    /// mutation (BD-Q3). Checked, because assembly runs outside the pending
    /// lock and the plan can change under it:
    ///
    /// - the plan must still be there: an owner who withdrew it while the
    ///   post was being proved wins, and the signed bytes are discarded
    ///   unsent ([`SignAdmission::PlanGone`]);
    /// - no reservation may have been released since the assembly read its
    ///   funding ([`SignAdmission::Stale`]);
    /// - the post's inputs must be free of every other record's reservation
    ///   ([`SignAdmission::InputRaced`]). The plan's own reservation does not
    ///   count against it: the post takes the plan's place.
    ///
    /// The plan's removal releases nothing (the post holds the funding in the
    /// same mutation), so the generation does not move.
    #[must_use]
    pub fn sign_plan(
        &mut self,
        mut post: PendingBondPost,
        snapshot_generation: u64,
    ) -> SignAdmission {
        let Some(idx) = self.plans.iter().position(|p| p.persona == post.persona) else {
            return SignAdmission::PlanGone;
        };
        let own = self.plans[idx].funding_gindexes.clone();
        if let Some(refused) =
            self.replacement_refused(&own, &post.funding_gindexes, snapshot_generation)
        {
            return refused;
        }
        // A post that just signed is not waiting.
        post.wait = None;
        self.plans.remove(idx);
        self.posts.push(post);
        SignAdmission::Signed
    }

    /// Replace `persona`'s signed post with one signed again at a canonical
    /// reference, iff no submit of it was ever attempted (BD-Q3 Rule 1: a
    /// post never sent may be re-signed; a sent one never is). The reservation
    /// check is [`Self::sign_plan`]'s, against the post's own reservation.
    #[must_use]
    pub fn resign_post(
        &mut self,
        mut post: PendingBondPost,
        snapshot_generation: u64,
    ) -> SignAdmission {
        let Some(idx) = self.posts.iter().position(|p| p.persona == post.persona) else {
            return SignAdmission::PlanGone;
        };
        if record_was_sent(self.posts[idx].state, self.posts[idx].terminal) {
            return SignAdmission::AlreadySent;
        }
        let own = self.posts[idx].funding_gindexes.clone();
        if let Some(refused) =
            self.replacement_refused(&own, &post.funding_gindexes, snapshot_generation)
        {
            return refused;
        }
        post.wait = None;
        self.posts[idx] = post;
        SignAdmission::Signed
    }

    /// Whether a post signed outside the lock may take `own`'s place.
    /// `None` admits it. The generation and the other records' reservations
    /// are the whole check; the caller's row is excluded because the post
    /// replaces it in the same mutation.
    fn replacement_refused(
        &self,
        own: &[GlobalOutputIndex],
        incoming: &[GlobalOutputIndex],
        snapshot_generation: u64,
    ) -> Option<SignAdmission> {
        if snapshot_generation != self.generation {
            return Some(SignAdmission::Stale);
        }
        let others: BTreeSet<GlobalOutputIndex> = self
            .reserved_gindexes()
            .into_iter()
            .filter(|g| !own.contains(g))
            .collect();
        incoming
            .iter()
            .any(|g| others.contains(g))
            .then_some(SignAdmission::InputRaced)
    }

    /// Record why `persona`'s stake was not signed on this attempt, on the
    /// plan or on the post never sent. A sent post is not waiting, and
    /// neither is an ended plan. Returns `true` when the stored reason
    /// changed (the caller seals only then).
    #[must_use]
    pub fn set_sign_wait(&mut self, persona: &PCanonicalId, wait: Option<PlanWait>) -> bool {
        match self.locate(persona) {
            Some(StakeAt::Plan(idx)) => assign_wait(&mut self.plans[idx].wait, wait),
            Some(StakeAt::Unsent(idx)) => assign_wait(&mut self.posts[idx].wait, wait),
            Some(StakeAt::Sent(_) | StakeAt::Ended(_)) | None => false,
        }
    }

    /// End `persona`'s stake without a bond, in one mutation: its plan, or its
    /// signed post if no submit of it was ever attempted, goes with its
    /// reservation; an [`EndedPlan`] takes its place until the persona's
    /// funding is drained; and the outcome is written (BD-Q3 as ruled
    /// 2026-11-26). Nothing was sent, so no bond can land and the outcome is
    /// not a sent one. `None` when the persona has neither, or its post was
    /// sent (a sent post ends at its end date, never here).
    #[must_use]
    pub fn end_plan(
        &mut self,
        persona: &PCanonicalId,
        ending: PlanEnding,
        at_height: BlockHeight,
    ) -> Option<EndedPlan> {
        // A sent post ends at its end date. An ended plan is already ended.
        let (p_slot, funded_through) = match self.locate(persona)? {
            StakeAt::Plan(idx) => {
                let plan = self.plans.remove(idx);
                (plan.p_slot, plan.funded_through)
            }
            StakeAt::Unsent(idx) => {
                let post = self.posts.remove(idx);
                (post.p_slot, post.funded_through)
            }
            StakeAt::Sent(_) | StakeAt::Ended(_) => return None,
        };
        self.generation += 1;
        let ended = EndedPlan {
            p_slot,
            persona: *persona,
            ending,
            funded_through,
        };
        self.ended_plans.push(ended.clone());
        self.replace_outcome(RecordKind::Post, persona);
        self.outcomes.push(StakingOutcome {
            kind: RecordKind::Post,
            persona: *persona,
            outcome: OutcomeKind::from(ending),
            at_height,
            sent: false,
        });
        Some(ended)
    }

    /// Remove `persona`'s plan with no outcome: the undo of a plan seal
    /// whose save was not confirmed (`seal_reporting`'s guard), so a plan a
    /// power loss could take is never acted on. Not an ending.
    #[must_use]
    pub fn remove_plan(&mut self, persona: &PCanonicalId) -> Option<PendingBondPlan> {
        let idx = self.plans.iter().position(|p| &p.persona == persona)?;
        self.generation += 1;
        Some(self.plans.remove(idx))
    }

    /// The owner withdraws `persona`'s stake (BD-Q3 as ruled 2026-11-26):
    /// allowed at any time before the post is signed, including while the
    /// plan waits past its due block; refused once it is signed.
    #[must_use]
    pub fn withdraw_plan(&mut self, persona: &PCanonicalId, at_height: BlockHeight) -> Withdrawal {
        match self.stake_stage(persona) {
            // Signed, sent or not: the ruling refuses withdrawal once the
            // post exists. The unsent post still ends on its own terms.
            Some(StakeStage::Unsent(_) | StakeStage::Sent(_)) => Withdrawal::AlreadySigned,
            Some(StakeStage::Plan(_)) => {
                match self.end_plan(persona, PlanEnding::Withdrawn, at_height) {
                    Some(ended) => Withdrawal::Withdrawn(ended),
                    None => Withdrawal::NoPlan,
                }
            }
            Some(StakeStage::Ended(_)) | None => Withdrawal::NoPlan,
        }
    }

    /// Ended plans whose persona's slot holds no live funding and has no
    /// live drain, judged only once the sealed scan has covered the block the
    /// funding sat in (absence from a scan short of it is not a spend). Each
    /// item is a [`DrainedEndedPlan`]: the only way to mint one, so a
    /// retirement witness built from it is this predicate. The caller retires
    /// the persona durably, then [`Self::drop_retired_plans`] removes the record.
    pub fn drained_plans<'a>(
        &'a self,
        funded_slots: &'a BTreeSet<PSlot>,
        scanned_through: Option<BlockHeight>,
    ) -> impl Iterator<Item = DrainedEndedPlan> + 'a {
        self.ended_plans
            .iter()
            .filter(move |ended| {
                scanned_through.is_some_and(|s| s >= ended.funded_through)
                    && !funded_slots.contains(&ended.p_slot)
                    && !self.has_live_drain_for(&ended.persona)
            })
            .cloned()
            .map(|ended| DrainedEndedPlan { ended })
    }

    /// Remove every ended plan whose persona is durably retired: the retired
    /// record now carries the slot's retirement, so the pending record has
    /// served its purpose. Retire first, remove second, so a crash between
    /// the two leaves a record that re-fires the retirement, never a funded
    /// or unretired persona with no record. An ended plan reserves nothing,
    /// so the generation does not move.
    #[must_use]
    pub fn drop_retired_plans(&mut self, retired: &BTreeSet<PCanonicalId>) -> Vec<EndedPlan> {
        let mut out = Vec::new();
        self.ended_plans.retain(|ended| {
            if retired.contains(&ended.persona) {
                out.push(ended.clone());
                false
            } else {
                true
            }
        });
        out
    }
}

#[cfg(test)]
#[path = "plan_block_tests.rs"]
mod plan_block_tests;
