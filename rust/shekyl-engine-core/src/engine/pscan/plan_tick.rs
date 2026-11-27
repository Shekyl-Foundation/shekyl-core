// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The plan half of the dispatch tick (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q2,
//! BD-Q3, §3.6): the seam through which the engine signs a due stake and
//! drains an ended persona, the choice of what to sign this tick, the
//! spent-elsewhere ending decided from the scan's evidence, and the sign
//! phase that records what blocked it. Carved out of `dispatch.rs`, whose
//! driver keeps the order of the phases and the single send.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_engine_state::pending_post_block::{record_was_sent, EndedPlan, PlanEnding, PlanWait};
use shekyl_engine_state::{PendingBondPlan, PendingBondPost, PendingPostBlock};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, GlobalOutputIndex, PCanonicalId, PSlot};
use tokio_util::sync::CancellationToken;

use super::dispatch::{DispatchError, PendingPostStore, PendingSealStore, TickEvidence};
use crate::engine::bond_plan::{
    canonical_reference, past_max_wait, plan_due, FundingPlace, SignSubject,
};

/// What one attempt to sign a stake at its due block came to
/// (`ARCHIVAL_BOND_POST_DELAY.md` BD-Q3; how a plan ends, ruled 2026-11-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanAttempt {
    /// The plan (or a post never sent) was replaced by a post signed at the
    /// canonical reference for this tick's tip. The driver marks and sends
    /// it in the same tick.
    Signed,
    /// The attempt was blocked. A temporary reason retries every tick; a
    /// limited one retries until the plan's maximum wait from its due block.
    Wait(PlanWait),
    /// The shards the bond owes can no longer be bonded. The plan ends at
    /// once and its funding is drained.
    Unbondable,
    /// The record changed under the attempt (withdrawn, ended, or a
    /// reservation released): nothing to record, and the next tick reads the
    /// new state.
    Raced,
}

/// The driver's signing seam: the engine assembles, proves and signs a due
/// stake, and drains a persona whose plan ended. The driver decides **when**; the engine does the work and
/// owns every secret (BD-Q3: "the driver has the engine assemble, then seals
/// the signed bytes, then sends"). Tests script the outcomes.
pub(crate) trait BondPlanSigner: Send + Sync + 'static {
    /// Sign `persona`'s due plan, or re-sign its post never sent, at the
    /// canonical reference for `tip`, and seal it in place of the record.
    fn sign_at_due(
        &self,
        persona: PCanonicalId,
        tip: ChainCount,
    ) -> impl std::future::Future<Output = PlanAttempt> + Send;

    /// Send the drain that empties the ended persona at `p_slot` to the
    /// principal: a sweep to zero with no exit reserve (it never bonded, so
    /// it owes no exit). A fee above the funding, or any other refusal, waits
    /// for the next tick; there is no maximum, because nothing else can return
    /// these funds.
    fn drain_ended(
        &self,
        p_slot: PSlot,
        persona: PCanonicalId,
    ) -> impl std::future::Future<Output = ()> + Send;

    /// The persona at `p_slot` ended without a bond: it stops being the
    /// active persona, so it never receives a second funding, and its
    /// retirement is not held back as active. Called for every ended plan on
    /// every tick. The actor call is idempotent, so a tick whose previous
    /// call failed deactivates it on the next one.
    fn persona_ended(&self, p_slot: PSlot) -> impl std::future::Future<Output = ()> + Send;

    /// The ended persona at `p_slot` is durably retired (its retired record is
    /// in the scan's seal): its slot leaves the live staking record this
    /// session, as the open-time reconcile would, so staking again takes a
    /// new persona.
    fn slot_retired(&self, p_slot: PSlot) -> impl std::future::Future<Output = ()> + Send;
}

/// A post never sent whose reference is no longer the canonical one for
/// `tip`: it is signed again before its first send (BD-Q3 Rule 1), never
/// sent at an older age. Lowest persona first.
pub(super) fn resign_candidate(posts: &[PendingBondPost], tip: ChainCount) -> Option<SignSubject> {
    let canonical = canonical_reference(tip)?;
    posts
        .iter()
        .filter(|p| !record_was_sent(p.state, p.terminal) && p.reference_height != canonical)
        .map(|p| SignSubject::UnsentPost {
            persona: p.persona,
            due: p.due,
        })
        .min_by_key(|subject| subject.persona())
}

/// The due plan to sign this tick: the earliest due at or below `tip`
/// (BD-Q2), ties by persona. A plan whose funding has no live record has no
/// due; the spent-elsewhere ending has already removed it this pass.
pub(super) fn sign_candidate(
    plans: &[PendingBondPlan],
    funding: &BTreeMap<GlobalOutputIndex, FundingPlace>,
    reorg_depth: BlockCount,
    tip: ChainCount,
) -> Option<SignSubject> {
    plans
        .iter()
        .filter_map(|p| {
            plan_due(p, funding, reorg_depth).map(|due| SignSubject::Plan {
                persona: p.persona,
                due,
            })
        })
        .filter(|subject| subject.due() <= tip)
        .min_by_key(|subject| (subject.due(), subject.persona()))
}

/// What to sign this tick: a post never sent whose reference aged first
/// (BD-Q3 Rule 1), else the earliest due plan (BD-Q2). A post never sent
/// comes before a plan, because it was due first.
pub(super) fn select_sign_target(
    block: &PendingPostBlock,
    funding: &BTreeMap<GlobalOutputIndex, FundingPlace>,
    reorg_depth: BlockCount,
    tip: ChainCount,
) -> Option<SignSubject> {
    resign_candidate(block.posts(), tip)
        .or_else(|| sign_candidate(block.plans(), funding, reorg_depth, tip))
}

/// End every plan, and every post never sent, whose reserved funding left
/// the reorg-deep live set (ruled 2026-11-26): it was spent by another
/// transaction, since nothing outside the wallet can spend `P`'s outputs
/// and a record never sent cannot have landed. Whatever is left is drained.
/// Absence counts only once the sealed scan has covered the block the
/// funding sits in: an output missing from a scan that has not reached it (a
/// rescan, a reset seal) is not spent.
pub(super) fn end_spent_elsewhere(
    block: &mut PendingPostBlock,
    evidence: &TickEvidence<'_>,
    at: BlockHeight,
) -> Vec<EndedPlan> {
    let covered = |through: BlockHeight| evidence.scanned_through.is_some_and(|s| s >= through);
    let gone = |gindexes: &[GlobalOutputIndex]| {
        gindexes.iter().any(|g| !evidence.live_funding.contains(g))
    };
    let spent: Vec<PCanonicalId> = block
        .plans()
        .iter()
        .filter(|p| covered(p.funded_through) && gone(&p.funding_gindexes))
        .map(|p| p.persona)
        .chain(
            block
                .posts()
                .iter()
                .filter(|p| {
                    !record_was_sent(p.state, p.terminal)
                        && covered(p.funded_through)
                        && gone(&p.funding_gindexes)
                })
                .map(|p| p.persona),
        )
        .collect();
    spent
        .iter()
        .filter_map(|persona| block.end_plan(persona, PlanEnding::SpentElsewhere, at))
        .collect()
}

/// The sign phase (outside the pending lock): the engine assembles and seals
/// the signed post itself, through the same gate; this records what blocked
/// an attempt, and ends a plan that is unbondable, or still blocked for a
/// limited reason past its maximum wait. An ended persona is deactivated at
/// once.
pub(super) async fn sign_due<S: PendingSealStore, G: BondPlanSigner>(
    store: &PendingPostStore<S>,
    signer: &G,
    target: SignSubject,
    tip: ChainCount,
    at: BlockHeight,
    cancel: &CancellationToken,
) -> Result<(), DispatchError> {
    // A close does not wait out a fill or a proof: the attempt is dropped,
    // and its one write, the checked seal, is a single atomic save that
    // either happened or did not. The next open signs again.
    let attempt = tokio::select! {
        biased;
        () = cancel.cancelled() => return Ok(()),
        attempt = signer.sign_at_due(target.persona(), tip) => attempt,
    };
    let ended = match attempt {
        PlanAttempt::Signed | PlanAttempt::Raced => None,
        PlanAttempt::Wait(wait) => {
            let waited_out = wait.is_limited() && past_max_wait(target.due(), tip);
            let ended = store
                .mutate(|block| {
                    let mut changed = block.set_sign_wait(&target.persona(), Some(wait));
                    let ended = waited_out
                        .then(|| block.end_plan(&target.persona(), PlanEnding::WaitedOut, at))
                        .flatten();
                    changed |= ended.is_some();
                    (changed, ended)
                })
                .await
                .map_err(|e| DispatchError::Store(Box::new(e)))?;
            if ended.is_some() {
                tracing::warn!(
                    ?wait,
                    "staking: a planned stake could still not be signed when its maximum \
                     wait passed; it ended, nothing was sent, and its funding is returned to \
                     this wallet"
                );
            } else {
                tracing::info!(?wait, "staking: a due stake was not signed this tick");
            }
            ended
        }
        PlanAttempt::Unbondable => {
            let ended = store
                .mutate(|block| {
                    let ended = block.end_plan(&target.persona(), PlanEnding::Unbondable, at);
                    (ended.is_some(), ended)
                })
                .await
                .map_err(|e| DispatchError::Store(Box::new(e)))?;
            if ended.is_some() {
                tracing::warn!(
                    "staking: the shards a planned stake owes can no longer be bonded; it \
                     ended, nothing was sent, and its funding is returned to this wallet"
                );
            }
            ended
        }
    };
    if let Some(ended) = ended {
        signer.persona_ended(ended.p_slot).await;
    }
    Ok(())
}

/// What one tick hands back to the scan task: the ended personas whose
/// funding is drained and that the task retires, the way it retires a
/// released persona (the actor wipe behind the funded gate, then the durable
/// retired record). The driver drops their pending records once the retired
/// set shows them, on a later tick.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct TickOutcome {
    /// Ended plans to retire, in record order.
    pub(crate) retire: Vec<EndedPlan>,
}

/// What the plan half of phase 1 decided, under the pending lock.
pub(super) struct PlanPass {
    /// Plans (or posts never sent) whose reserved funding was spent by
    /// another transaction this tick: ended as `spent_elsewhere`.
    pub(super) spent_elsewhere: Vec<EndedPlan>,
    /// Ended plans whose persona's funding is drained: the task retires them.
    pub(super) drained: Vec<EndedPlan>,
    /// The stake to sign this tick, chosen from a covered seal.
    pub(super) sign: Option<SignSubject>,
    /// The one ended persona whose drain is owed this tick, if any.
    pub(super) drain_owed: Option<(PSlot, PCanonicalId)>,
    /// Slots of ended personas whose retirement is durable: their records
    /// were dropped this tick, and they leave the live staking record.
    pub(super) retired_slots: Vec<PSlot>,
    /// Every ended plan's slot. Each tick deactivates these, so a failed
    /// deactivation is retried while the row remains.
    pub(super) ended_slots: Vec<PSlot>,
}

/// The plan half of phase 1: end what was spent elsewhere, drop ended plans
/// whose persona the scan has durably retired, find the ended plans whose
/// funding is drained (the task retires them) and the one drain owed, and,
/// from a covered seal only, choose what to sign. Returns whether the block
/// changed.
pub(super) fn plan_pass(
    block: &mut PendingPostBlock,
    evidence: &TickEvidence<'_>,
    covered: bool,
    reorg_depth: BlockCount,
    tip: ChainCount,
    at: BlockHeight,
) -> (bool, PlanPass) {
    let funded_slots: BTreeSet<PSlot> = evidence.funding.values().map(|f| f.p_slot).collect();
    let spent_elsewhere = end_spent_elsewhere(block, evidence, at);
    let dropped = block.drop_retired_plans(evidence.retired);
    let changed = !spent_elsewhere.is_empty() || !dropped.is_empty();
    let retired_slots = dropped.iter().map(|e| e.p_slot).collect();
    let ended_slots = block
        .ended_plans()
        .iter()
        .map(|ended| ended.p_slot)
        .collect();
    let drained: Vec<EndedPlan> = block
        .drained_plans(&funded_slots, evidence.scanned_through)
        .cloned()
        .collect();
    let drain_owed = block
        .ended_plans()
        .iter()
        .find(|e| funded_slots.contains(&e.p_slot) && !block.has_live_drain_for(&e.persona))
        .map(|e| (e.p_slot, e.persona));
    let sign = covered
        .then(|| select_sign_target(block, evidence.funding, reorg_depth, tip))
        .flatten();
    (
        changed,
        PlanPass {
            spent_elsewhere,
            drained,
            sign,
            drain_owed,
            retired_slots,
            ended_slots,
        },
    )
}

/// After the seal that decided them: each durably retired slot leaves the
/// live staking record, and every ended plan's persona stops being the
/// active one. The second call covers endings from earlier ticks whose
/// deactivation did not land.
pub(super) async fn report_plan_endings<G: BondPlanSigner>(signer: &G, pass: &PlanPass) {
    for slot in &pass.retired_slots {
        signer.slot_retired(*slot).await;
    }
    for slot in &pass.ended_slots {
        signer.persona_ended(*slot).await;
    }
    let ended = &pass.spent_elsewhere;
    if !ended.is_empty() {
        tracing::warn!(
            count = ended.len(),
            "staking: a planned stake's funding was spent by another transaction; the stake \
             ended as spent elsewhere, nothing was sent, and whatever is left is returned to \
             this wallet"
        );
    }
}
