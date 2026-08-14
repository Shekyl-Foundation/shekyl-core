// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Persist-before-use for archival bond records — the [`PersistedBondTicket`]
//! typestate (typed contract #1, `ARCHIVAL_BOND_CONSTRUCTION.md` §10.2) and its
//! sole producer [`Engine::persist_bond_record`].
//!
//! # Why a typestate, not a discipline
//!
//! A bond's building persona must have its live-bond record durably committed
//! **before** the persona key signs the bond. The ordering is load-bearing:
//! under Model D the seed is gone after `assemble()`, so the bonded-union
//! derive-forward set is reconstructed at reopen *from the persisted record*. If
//! a crash lands between the sign and the persist, reopen reconstructs a set
//! that is **behind reality** and the building persona can fall out of the
//! derived set entirely — unreachable for the wallet's life, the bond
//! un-unbondable. Persist-before-use makes the only crash failure a *wasted
//! slot* (cursor ahead of chain — benign, slots are free), never a *lost* one.
//!
//! A two-line sign/persist reordering is invisible in review and catastrophic
//! in effect, so the ordering is lifted into the type system rather than left as
//! a comment: [`Engine::persist_bond_record`] returns a [`PersistedBondTicket`],
//! and 2c-2b's `plan_bond_post(ticket: PersistedBondTicket, ..)` *consumes* it. With
//! no other constructor, "sign before persist" has no expressible form — there
//! is no ticket to pass.
//!
//! # Why the ticket witnesses durability
//!
//! The only way to obtain a [`PersistedBondTicket`] is to call
//! [`Engine::persist_bond_record`], whose body goes through
//! [`PersistenceEngine::save_state`] → `shekyl-engine-file`'s `atomic_write_file`
//! (`tmp → fsync → rename → fsync(parent)`). The ticket therefore witnesses a
//! **durable, crash-atomic** commit, not merely an in-memory mutation — the
//! persist-before-use guarantee is downstream of the same write atomicity the
//! `LMDB_WRITE_ATOMICITY_AUDIT` lineage covers for every ledger block.
//!
//! # The cross-split seam
//!
//! This module *produces* the type (PR 2c-2a); the 2c-2b request path *consumes*
//! it. The contract between the two PRs is a Rust type the consumer cannot
//! forge, not a convention it has to remember. Inert until 2c-2b wires the
//! consumer, so the producer carries `#[allow(dead_code)]`.

use shekyl_engine_state::StakingBlock;
use shekyl_types::PCanonicalId;

use super::pscan::reconcile::{PReconcileSet, ReconcileVerdict};

use super::error::PersistenceError;
use super::lifecycle::drive_persistence;
use super::stake_engine::PSlot;
use super::traits::PersistenceEngine;
use super::{Engine, EngineSignerKind, LocalLedger};

/// Proof that an archival bond's per-persona live-bond record was **durably
/// persisted** for a specific persona slot (typed contract #1).
///
/// Minted only by [`Engine::persist_bond_record`] after a successful
/// crash-atomic `save_state`; the field is module-private and there is no other
/// constructor, so a ticket cannot exist without the durable commit having
/// happened. Consumed **by value** by 2c-2b's `plan_bond_post`, so one persist
/// authorizes one sign — persist-before-use, enforced structurally.
///
/// Deliberately **not** `Clone`: a ticket is single-use evidence of one commit;
/// duplicating it would let one persist authorize two signs (mirrors the
/// `AllKeysBlob` Not-Clone discipline, `21-reversion-clause-discipline.mdc`).
/// Reopen this only if a 2c-2b caller provably needs to re-sign the *same*
/// already-persisted record, with documented justification.
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)] // inert until 2c-2b consumes it via plan_bond_post
pub(crate) struct PersistedBondTicket {
    /// The persona slot whose live-bond record this ticket witnesses. Bound so
    /// 2c-2b's `plan_bond_post` can assert the ticket matches the persona being
    /// signed (a ticket for slot A cannot authorize a sign for slot B).
    p_slot: PSlot,
}

#[allow(dead_code)] // inert until 2c-2b consumes it via plan_bond_post
impl PersistedBondTicket {
    /// The persona slot this ticket was minted for.
    #[must_use]
    pub(crate) fn p_slot(&self) -> PSlot {
        self.p_slot
    }

    /// Test-only ticket constructor for negative-control tests that need a
    /// ticket without going through the real `Engine::persist_bond_record`
    /// path (e.g. slot-mismatch tests that need a ticket for a specific slot
    /// that was never actually persisted).
    ///
    /// **Must not be used in production paths.** The name is intentionally
    /// awkward to prevent accidental use: a legitimate caller always goes
    /// through `persist_bond_record`.
    #[cfg(test)]
    pub(crate) fn __test_only_forge(p_slot: PSlot) -> Self {
        Self { p_slot }
    }
}

// `D: DaemonEngine` / `L = LocalLedger` / `R = LocalRefresh` specialization
// mirrors `Engine::close` (see `lifecycle.rs`): the persist path acquires a
// `LocalLedger` write guard to mutate the `StakingBlock`, then a read guard to
// hand `&WalletLedger` to `save_state`, exactly as `close` does for the final
// flush. The trait surface does not yet expose a borrowed-state mutation
// accessor (Stage 4 design space).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: super::traits::DaemonEngine,
        E: super::traits::EconomicsEngine,
        P: super::traits::PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, LocalLedger, E, super::LocalRefresh, P, F>
{
    /// Durably commit the live-bond record for persona `slot`, returning the
    /// [`PersistedBondTicket`] that 2c-2b's `plan_bond_post` consumes.
    ///
    /// Records `slot` in [`StakingBlock::bonded_slots`] (idempotent — a repeat
    /// of an already-recorded slot is a no-op on the set), flips
    /// `staking_enabled` on (a wallet that holds a bond *must* re-derive that
    /// persona at the next `assemble()`, which `staking_enabled` gates), and
    /// advances the persona cursor to the scan-reconciled monotone value
    /// ([`StakingBlock::monotone_current_slot_from_record`]) so the persisted
    /// cursor never sits at or below a bonded slot — the privacy guard against
    /// re-activating a rotated-past persona.
    ///
    /// The mutation commits to the in-memory ledger under a write guard, which
    /// is dropped before the read-guarded `save_state` (the two guards are on
    /// the same `RwLock`; holding the write guard across the save would
    /// deadlock). On `Ok`, the record is durably on disk (`atomic_write_file`),
    /// so the returned ticket witnesses a crash-atomic commit.
    ///
    /// # Errors
    ///
    /// [`PersistenceError`] if the durable `save_state` fails; in that case **no
    /// ticket is produced**, so the caller cannot proceed to sign — persist
    /// failure fails the operation closed, never open.
    #[allow(dead_code)] // inert until 2c-2b consumes the ticket via plan_bond_post
    pub(crate) fn persist_bond_record(
        &self,
        slot: PSlot,
    ) -> Result<PersistedBondTicket, PersistenceError> {
        // Mutate the staking block under a scoped write guard, then drop it
        // before saving (same lock; write-then-read would deadlock).
        {
            let mut guard = self.ledger.write();
            let staking: &mut StakingBlock = &mut guard.ledger.staking;
            staking.staking_enabled = true;
            let index = slot.index();
            if !staking.bonded_slots.contains(&index) {
                staking.bonded_slots.push(index);
            }
            // Monotone-forward: cursor never at/below an observed bonded slot.
            staking.p_slot = staking.monotone_current_slot_from_record();
        }

        // Durable, crash-atomic write — the property the ticket witnesses.
        let ledger_guard = self.ledger.read();
        drive_persistence(
            self.persistence
                .save_state(self.state_wrap_key(), &ledger_guard.ledger),
        )
        .map_err(Into::into)?;
        drop(ledger_guard);

        Ok(PersistedBondTicket { p_slot: slot })
    }
}

/// What one open-time phantom sweep did (SP-R0 **arm #3**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhantomSlotSweep {
    /// Slots dropped from `bonded_slots` (confirmed-absent, no pending post).
    pub(crate) dropped: Vec<u32>,
    /// Whether the sweep emptied `bonded_slots` and flipped
    /// `staking_enabled` off (the wallet reverts to a non-staker).
    pub(crate) staking_disabled: bool,
}

/// SP-R0 **arm #3** — the open-time phantom `bonded_slots` GC
/// (`ARCHIVAL_BOND_SP_R0_PLAN.md` §3; FOLLOWUPS "2d full-scan reconciliation
/// of `bonded_slots` / `p_slot`"). Runs at the derive-time locus the
/// `StakingBlock` hint design anticipated: **before** the persona derive, so
/// a phantom staker reopens as a clean non-staker (no actor, no scan, no
/// derivation "for nothing").
///
/// A slot is phantom **iff** it has **no pending post** AND its persona is
/// [`ReconcileVerdict::AbsentWithinCovered`] over the sealed scan evidence —
/// where a slot with a **bond-watch sighting** (`StakingBlock::bond_sightings`)
/// is evaluated with the height-gated verdict at its first-sighting height,
/// not the whole-covered form. The conditions are jointly airtight against
/// wrongful GC of a *real* bond (the stuck-funds failure this design forbids):
///
/// - pre-broadcast and pre-confirmation, the signed post sits durably in
///   `.wallet.pending` — the pending guard skips it (W3);
/// - post-confirmation but pre-scan-coverage, the pending record **still
///   exists** — dispatch releases it only on the scan's own reorg-deep
///   `BondPostMatch` (never on a daemon claim), so the pending record is the
///   bridge across the scan lag; once released, the match is in the evidence
///   and the verdict is `Present`;
/// - a **probe-adopted** bond (principal-scan sighting, SA-R-6 from-seed
///   reconstruction) has no pending record — its sighting row is its bridge:
///   evidence short of the sighted height reads `OutsideCovered` (kept);
///   coverage past it with no match means the sighted block reorged out
///   (dropped, correctly). A `Present` verdict prunes the sighting — the
///   seal's own match row supersedes it.
///
/// `OutsideCovered` (nothing scanned / frontier at zero) keeps every slot —
/// absence-≠-unscanned is [`PReconcileSet`]'s type-level gate. The `p_slot`
/// cursor is **never lowered**: a dropped slot stays burned (the monotone
/// no-reuse invariant, `StakingBlock::monotone_current_slot`).
///
/// # Binding contract for the release side (GF-7 dispatch, not yet built)
///
/// The two-condition guard above is airtight **only while** the pending
/// record's durable removal is ordered **at-or-after** the durable seal of
/// the match-bearing pscan state. Nothing in this crate releases a pending
/// post today, so the ordering cannot currently be violated — but the GF-7
/// dispatch driver will, and it MUST write the release in the same atomic
/// seal transaction as (or strictly after) the pscan-state seal that
/// carries the observed [`BondPostMatch`](super::pscan::scan_step::BondPostMatch).
/// A release that becomes durable first opens a crash window where this GC
/// sees "no pending record + stale confirmed-absence" and drops a REAL
/// on-chain bond — permanently, since the burned cursor forbids re-adopting
/// the slot. The dispatch PR must land a crash-ordering test against this
/// exact window before any release path ships (mirrored in
/// `ARCHIVAL_STAKE_ACTIVATION_PLAN.md` and on
/// [`PendingPostState`](shekyl_engine_state::pending_post_block::PendingPostState)).
pub(crate) fn reconcile_phantom_bonded_slots<E>(
    staking: &mut StakingBlock,
    evidence: &PReconcileSet,
    pending_slots: &std::collections::BTreeSet<u32>,
    mut id_of_slot: impl FnMut(u32) -> Result<PCanonicalId, E>,
) -> Result<PhantomSlotSweep, E> {
    // Membership, not walk-order: `bonded_slots` is *kept* sorted by its
    // writers, but this sweep must not depend on that — a deserialized
    // hint that lost its order (corrupt file, older writer) would make
    // an order-assuming `binary_search` miss phantoms. `BTreeSet` is
    // the membership structure; the returned `dropped` is still a
    // sorted `Vec` (BTreeSet iteration).
    let mut dropped = std::collections::BTreeSet::new();
    let mut pruned_sightings = Vec::new();
    for &slot in &staking.bonded_slots {
        if pending_slots.contains(&slot) {
            continue; // W3 / scan-lag bridge: a pending post is never phantom.
        }
        let id = id_of_slot(slot)?;
        // A slot the principal scan's bond watch sighted is evaluated with
        // the **height-gated** verdict at its first-sighting height: a
        // P-scan seal whose coverage has not reached the sighted block reads
        // `OutsideCovered` and keeps the slot — a probe-adopted real bond
        // must not be GC'd as phantom against evidence that predates it
        // (restore-path bonds have no pending record, so the W3 bridge
        // above cannot protect them; the sighting row is their bridge).
        // Coverage past the sighting with no match means the sighted block
        // reorged out — the drop is then correct, and the sighting row goes
        // with it. `Present` supersedes the sighting: the P-scan's own
        // evidence now carries the match, so the bridge is pruned.
        let verdict = match staking.bond_sightings.get(&slot) {
            Some(&sighted_at) => evidence.reconcile(id, sighted_at),
            None => evidence.reconcile_full_scan(id),
        };
        match verdict {
            ReconcileVerdict::AbsentWithinCovered => {
                dropped.insert(slot);
                if staking.bond_sightings.contains_key(&slot) {
                    pruned_sightings.push(slot);
                }
            }
            ReconcileVerdict::Present { .. } => {
                if staking.bond_sightings.contains_key(&slot) {
                    pruned_sightings.push(slot);
                }
            }
            ReconcileVerdict::OutsideCovered => {}
        }
    }
    if !dropped.is_empty() {
        staking.bonded_slots.retain(|s| !dropped.contains(s));
    }
    for slot in pruned_sightings {
        staking.bond_sightings.remove(&slot);
    }
    let staking_disabled = staking.bonded_slots.is_empty() && !dropped.is_empty();
    if staking_disabled {
        staking.staking_enabled = false;
    }
    Ok(PhantomSlotSweep {
        dropped: dropped.into_iter().collect(),
        staking_disabled,
    })
}

/// What one open-time chain-evidence pass did to the staking record
/// (SP-R0 **arm #4**).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainBondAdoption {
    /// Slots ADOPTED into `bonded_slots` from a chain-observed bond post
    /// the live hint had lost. Ascending.
    pub(crate) adopted: Vec<u32>,
    /// The highest walked `Present` slot, when it moved `p_slot` beyond the
    /// hint-fed heal. `None` when the tail held no `Present`, or the cursor
    /// already sat above it.
    pub(crate) raised_above: Option<u32>,
}

/// SP-R0 **arm #4** (SA-5, SA-R-6) — reconcile the persona record against
/// chain-observed bond posts in the lookahead tail, so a rolled-back sealed
/// cursor can neither re-offer a slot that already has on-chain activity
/// **nor strand the bond that proves it**.
///
/// Two effects, in order, over the same walk:
///
/// 1. **Adopt.** A `Present` slot the live hint has lost is pushed back into
///    `bonded_slots` (and `staking_enabled` re-armed). This is the half that
///    keeps the raise from being a fund-loss: `bonded_slots` is the only
///    input that holds a persona in
///    [`StakingBlock::derive_forward_slots`], and under Model D the seed is
///    gone after `assemble`, so a persona outside that set is unreachable
///    for the wallet's life — its bond un-unbondable. Raising the cursor
///    past a `Present` slot without adopting it would do exactly that, and
///    the on-chain bond that would justify healing is *durable* evidence
///    (`PScanState::bond_post_matches` survives every open until arm #2's
///    retire-time prune), so a wallet that skipped the adopt would keep
///    proof of a bond it can no longer spend.
/// 2. **Burn.** `p_slot` is lifted above the highest walked `Present`. For an
///    adopted slot this is implied by the hint-fed heal, but the explicit
///    [`StakingBlock::monotone_current_slot`] call is **load-bearing for the
///    refused ones**: a durably-RETIRED slot must burn the cursor and must
///    NOT be adopted (re-arming a retired persona is the forever-derive
///    problem arm #2 exists to kill). Do not "simplify" this call away.
///
/// `retired_slots` is the adopt-refusal set. Arm #2's retire prune drops a
/// retired persona's match rows in the same seal that writes its
/// `RetiredPersonaRecord`, so a retired slot should already read
/// `AbsentWithinCovered` — this guard does not lean on that other module's
/// atomicity promise.
///
/// Phantoms are [`ReconcileVerdict::AbsentWithinCovered`], disjoint from
/// `Present`, so they can neither adopt nor raise regardless of apply order.
///
/// Scope: a record rolled back within the lookahead, healed from the sealed
/// pscan evidence. Because the selection sequence is dense and a sealed
/// `StakingBlock` rolls back as a unit, the slots a k-step rollback loses
/// begin exactly at the rolled-back cursor — which is why the walk is the
/// tail and not a widening probe. The **from-seed** case (nothing derived or
/// scanned — no pscan evidence at all) is owned by the principal scan's
/// **bond watch**: the open-built probe-id cache
/// (`StakingBlock::persona_id_cache`, width `ARCHIVAL_PERSONA_PROBE_WINDOW`)
/// plus the refresh/rescan sighting → merge adoption
/// (`merge::adopt_bond_sightings`), whose sighting rows this module's arm #3
/// then honors via the height-gated verdict.
pub(crate) fn adopt_chain_bonds_and_raise_cursor<E>(
    staking: &mut StakingBlock,
    evidence: &PReconcileSet,
    retired_slots: &std::collections::BTreeSet<u32>,
    lookahead: u32,
    mut id_of_slot: impl FnMut(u32) -> Result<PCanonicalId, E>,
) -> Result<ChainBondAdoption, E> {
    staking.p_slot = staking.monotone_current_slot_from_record();
    let cursor = staking.p_slot;

    let mut adopted = Vec::new();
    let mut chain_high: Option<u32> = None;
    for offset in 0..=lookahead {
        // `checked_add` drops the out-of-range tail rather than wrapping to
        // slot 0 (which would re-walk a moved-past persona).
        let Some(slot) = cursor.checked_add(offset) else {
            break;
        };
        let id = id_of_slot(slot)?;
        if !matches!(
            evidence.reconcile_full_scan(id),
            ReconcileVerdict::Present { .. }
        ) {
            continue;
        }
        // The walk is ascending, so the last `Present` is the highest.
        chain_high = Some(slot);
        // Adopt unless the wallet durably retired this persona: a retired
        // slot burns the cursor (below) but never re-enters the hint.
        //
        // `push` keeps `bonded_slots` ascending without a sort: the walk
        // starts at `monotone_current_slot_from_record()`, which is already
        // strictly above every recorded slot, so an adopted slot is strictly
        // greater than every entry the vec holds. That matters because the
        // vec is PERSISTED — an out-of-order append would let two wallets in
        // the same logical state serialize to different bytes.
        if !retired_slots.contains(&slot) && !staking.bonded_slots.contains(&slot) {
            staking.bonded_slots.push(slot);
            adopted.push(slot);
        }
    }

    if !adopted.is_empty() {
        // A chain-proven bond makes this wallet a staker again: the actor
        // must spawn or the adopted persona is never derived.
        staking.staking_enabled = true;
    }

    let mut raised_above = None;
    if let Some(high) = chain_high {
        let raised = staking.monotone_current_slot(Some(high));
        // The walk starts AT the cursor, so any `Present` it finds sits at or
        // above it and `high + 1` clears it — except at the `u32::MAX`
        // saturation edge, where the cursor is already total and cannot move.
        // That edge is the only way this stays `None` with a `Present` in hand.
        if raised > staking.p_slot {
            staking.p_slot = raised;
            raised_above = Some(high);
        }
    }
    Ok(ChainBondAdoption {
        adopted,
        raised_above,
    })
}

/// Run the SP-R0 open-time staking reconciliation over sealed scan `evidence`.
///
/// - **arm #2** (retired GC): burn the retired slots into the cursor, then drop
///   them from the live hint (records-driven — the wallet's own ledger — so no
///   absence gate needed); an emptied hint reverts the wallet to a non-staker (a
///   fully-retired wallet must not spawn an actor "for nothing" every open).
/// - **arm #3** (phantom GC): drop confirmed-absent, unpended phantom slots
///   ([`reconcile_phantom_bonded_slots`]).
/// - **arm #4** (SA-5): adopt chain-proven bonds the hint lost and lift the
///   cursor above the lookahead tail
///   ([`adopt_chain_bonds_and_raise_cursor`]).
///
/// # Precondition — retired slots sit below every live bond
///
/// This pass relies on the persona-lifecycle invariant that **slots are used in
/// strictly increasing order and a slot is not retired until it is defunded**.
/// Together those make `retired_slots` a prefix `{0..=r}` lying strictly *below*
/// every slot that still holds a live bond: a persona is retired only after its
/// own bond is drained, and use is in order, so a live bond never sits under a
/// retired slot. Arm #2 therefore burns the cursor to `highest_retired + 1`
/// knowing no live bond sits at or below it, so arm #4's lookahead walk — which
/// starts at the burned cursor — cannot step over a live bond.
///
/// The inverse (a live dormant bond at a slot *below* a higher retired slot) is
/// **unrepresentable**: it requires retiring a persona out of lifecycle order,
/// before an older funded one is drained. Retirement is driven solely by
/// scanned on-chain unbond posts (`record_unbond`), and the drain/unbond path
/// that produces those posts must never defund out of order. If a future path
/// makes it reachable, that path is the bug — not this reconstruction;
/// `FOLLOWUPS.md` carries the reopen the drain/retire lane owes.
///
/// **The burn precedes the drop.** `retain` is destructive: once a retired slot
/// leaves `bonded_slots`, `monotone_current_slot_from_record` can no longer see
/// it, so a cursor that rolled back below a retired slot would be free to
/// re-offer it — the exact SA-R-6 reuse this pass exists to prevent, and one
/// arm #4 cannot repair whenever the retired slot sits outside the lookahead.
///
/// `Present` and `AbsentWithinCovered` are disjoint, so a phantom can neither
/// raise nor be adopted regardless of apply order. `id_of_slot` is shared by
/// arms #3 and #4; arm #4 walks only the lookahead tail, so each remaining
/// bonded slot is derived once in this pass.
pub(crate) fn reconcile_staking_at_open<E>(
    staking: &mut StakingBlock,
    evidence: &PReconcileSet,
    pending_slots: &std::collections::BTreeSet<u32>,
    retired_slots: &std::collections::BTreeSet<u32>,
    lookahead: u32,
    mut id_of_slot: impl FnMut(u32) -> Result<PCanonicalId, E>,
) -> Result<(), E> {
    // arm #2 — drop durably-retired slots before anything derives. The
    // derive-forward subtraction follows for free: the lookahead starts at the
    // monotone cursor, kept strictly above every observed bonded slot.
    if let Some(&highest_retired) = retired_slots.iter().next_back() {
        // Burn FIRST (see the fn docs): a `RetiredPersonaRecord` is durable
        // proof this wallet bonded that slot, so the high-water mark is owed
        // whether or not the live hint still lists it.
        staking.p_slot = staking.monotone_current_slot(Some(highest_retired));

        let before = staking.bonded_slots.len();
        staking.bonded_slots.retain(|s| !retired_slots.contains(s));
        // A retired slot's bond-watch sighting goes with it: the sighting is
        // the not-yet-corroborated bridge for a LIVE adoption, and a retired
        // slot must not look adopted to any sighting consumer (the W2 resume
        // guard, arm #3's height-gated verdict).
        staking
            .bond_sightings
            .retain(|s, _| !retired_slots.contains(s));
        let dropped = before - staking.bonded_slots.len();
        if dropped > 0 {
            if staking.bonded_slots.is_empty() {
                staking.staking_enabled = false;
            }
            tracing::info!(
                dropped,
                cursor = staking.p_slot,
                reverted = !staking.staking_enabled,
                "SP-R0 arm #2: retired slots cleaned from the live hint at open"
            );
        }
    }

    // arm #3 — phantom GC.
    let sweep = reconcile_phantom_bonded_slots(staking, evidence, pending_slots, &mut id_of_slot)?;
    if !sweep.dropped.is_empty() {
        tracing::info!(
            dropped = sweep.dropped.len(),
            staking_disabled = sweep.staking_disabled,
            "SP-R0 arm #3: phantom bonded_slots collected at open"
        );
    }

    // arm #4 — adopt + raise (SA-5, SA-R-6): SAME evidence, AFTER the drops.
    let chain = adopt_chain_bonds_and_raise_cursor(
        staking,
        evidence,
        retired_slots,
        lookahead,
        &mut id_of_slot,
    )?;
    if !chain.adopted.is_empty() {
        tracing::info!(
            adopted = chain.adopted.len(),
            "SP-R0 arm #4: chain-proven bonds re-adopted into the live hint at open"
        );
    }
    if let Some(high) = chain.raised_above {
        tracing::info!(
            chain_high = high,
            cursor = staking.p_slot,
            "SP-R0 arm #4: monotone p_slot cursor raised from scan evidence"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::pscan::exhaustiveness::VerifiedBatch;
    use crate::engine::pscan::scan_step::BondPostMatch;
    use shekyl_types::BlockHeight;

    fn staking(bonded: &[u32]) -> StakingBlock {
        StakingBlock {
            staking_enabled: !bonded.is_empty(),
            bonded_slots: bonded.to_vec(),
            ..Default::default()
        }
    }

    fn id(b: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([b; 32])
    }

    /// Evidence covering `[0, high)` carrying `matches`.
    fn evidence(high: u64, matches: Vec<BondPostMatch>) -> PReconcileSet {
        PReconcileSet::from_verified_scan(
            VerifiedBatch::for_test(0, high, [1; 32]).range(),
            matches,
        )
    }

    fn match_for(persona: PCanonicalId, height: u64) -> BondPostMatch {
        BondPostMatch {
            height: BlockHeight::from_raw(height),
            p_canonical_id: persona,
            post_kind: 0,
        }
    }

    /// Arm #3 unit matrix: pending-guarded, present, absent, unscanned —
    /// only confirmed-absent-and-unpended drops; emptying flips the flag.
    #[test]
    fn phantom_sweep_drops_only_confirmed_absent_unpended_slots() {
        // Slot 0: pending post (W3 bridge) — kept even though absent.
        // Slot 1: present in evidence — kept.
        // Slot 2: absent within covered, no pending — DROPPED.
        let mut st = staking(&[0, 1, 2]);
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        let pending: std::collections::BTreeSet<u32> = [0u32].into_iter().collect();
        let sweep = reconcile_phantom_bonded_slots(&mut st, &ev, &pending, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("sweep");
        assert_eq!(sweep.dropped, vec![2]);
        assert!(!sweep.staking_disabled, "slots remain");
        assert_eq!(st.bonded_slots, vec![0, 1]);
        assert!(st.staking_enabled);
    }

    /// Membership in `dropped` must not assume `bonded_slots` is sorted.
    /// This bites against a `binary_search` on walk-order `dropped` (a
    /// descending hint would leave the later-walked phantom in the vec);
    /// it does NOT cover writers keeping the hint sorted.
    #[test]
    fn phantom_sweep_drops_phantoms_from_an_unsorted_hint() {
        // Descending on purpose: walk order is 2 then 0. Both absent,
        // no pending. An order-assuming membership test on dropped=[2,0]
        // misses 0.
        let mut st = staking(&[2, 0]);
        let ev = evidence(100, Vec::new());
        let sweep = reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("sweep");
        assert_eq!(
            sweep.dropped,
            vec![0, 2],
            "both phantoms, sorted in the report"
        );
        assert!(st.bonded_slots.is_empty(), "neither phantom survives");
        assert!(sweep.staking_disabled);
    }

    /// Nothing exhaustively scanned ⇒ `OutsideCovered` ⇒ nothing drops —
    /// the absence-≠-unscanned gate, exercised through the sweep.
    #[test]
    fn phantom_sweep_keeps_everything_when_nothing_is_covered() {
        let mut st = staking(&[7]);
        let ev = evidence(0, Vec::new());
        let sweep = reconcile_phantom_bonded_slots(
            &mut st,
            &ev,
            &std::collections::BTreeSet::new(),
            |_| Ok::<_, ()>(id(9)),
        )
        .expect("sweep");
        assert!(sweep.dropped.is_empty());
        assert_eq!(st.bonded_slots, vec![7], "unscanned absence never GCs");
        assert!(st.staking_enabled);
    }

    /// The stale-seal survival case (the mandatory bond-watch fix): a
    /// probe-adopted slot with a sighting at height 50 must survive arm #3
    /// against a pscan seal whose coverage stops at 20 — the whole-covered
    /// verdict would read `AbsentWithinCovered` (covered, no match) and
    /// permanently GC a real bond that has no pending record to bridge it.
    /// Greenable only by the height-gated verdict: coverage short of the
    /// sighting reads `OutsideCovered` and keeps the slot.
    #[test]
    fn phantom_sweep_keeps_a_sighted_slot_the_seal_has_not_covered() {
        let mut st = staking(&[3]);
        st.record_first_sighting(3, BlockHeight::from_raw(50));
        let ev = evidence(20, Vec::new()); // covered [0,20): predates the sighting
        let sweep =
            reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
                .expect("sweep");
        assert!(sweep.dropped.is_empty(), "sighted slot must survive");
        assert_eq!(st.bonded_slots, vec![3]);
        assert!(
            st.bond_sightings.contains_key(&3),
            "the bridge stays until the seal covers or refutes it"
        );
    }

    /// Coverage PAST the sighting with no match: the sighted block reorged
    /// out — the drop is then correct, and the sighting row goes with it.
    #[test]
    fn phantom_sweep_drops_a_sighted_slot_the_seal_covered_and_refuted() {
        let mut st = staking(&[3]);
        st.record_first_sighting(3, BlockHeight::from_raw(50));
        let ev = evidence(100, Vec::new()); // covered [0,100): past the sighting, no match
        let sweep =
            reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
                .expect("sweep");
        assert_eq!(sweep.dropped, vec![3], "reorged-out sighting drops");
        assert!(st.bonded_slots.is_empty());
        assert!(
            !st.bond_sightings.contains_key(&3),
            "a refuted sighting is pruned with its slot"
        );
    }

    /// `Present` supersedes the sighting: once the P-scan's own evidence
    /// carries the match, the bridge row is pruned and the slot stays.
    #[test]
    fn phantom_sweep_prunes_a_sighting_the_seal_now_corroborates() {
        let mut st = staking(&[3]);
        st.record_first_sighting(3, BlockHeight::from_raw(50));
        let ev = evidence(100, vec![match_for(id(3), 50)]);
        let sweep =
            reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
                .expect("sweep");
        assert!(sweep.dropped.is_empty());
        assert_eq!(st.bonded_slots, vec![3], "corroborated slot stays");
        assert!(
            !st.bond_sightings.contains_key(&3),
            "the seal's own match row supersedes the sighting bridge"
        );
    }

    /// The empty retired set, spelled once.
    fn no_retired() -> std::collections::BTreeSet<u32> {
        std::collections::BTreeSet::new()
    }

    /// Arm #4 (SA-5): the load-bearing rollback — a later slot is *missing*
    /// from the hint (the sealed `StakingBlock` rolled back as a unit) and is
    /// found only in the lookahead tail. The bond is ADOPTED, not merely
    /// burned past: burning alone would raise the cursor over a live on-chain
    /// bond and, since `bonded_slots` is the only thing that holds a persona
    /// in the derive-forward set under Model D, strand it forever.
    #[test]
    fn raise_adopts_a_lookahead_present_missing_from_the_hint() {
        // Reality was bonded {0,1} cursor 2; rolled back to bonded {0} cursor 1.
        let mut st = staking(&[0]);
        st.p_slot = 1;
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert_eq!(chain.raised_above, Some(1));
        assert_eq!(
            chain.adopted,
            vec![1],
            "the chain-proven bond is re-adopted"
        );
        assert_eq!(
            st.bonded_slots,
            vec![0, 1],
            "slot 1 is back in the derive-forward set — its bond can still be unbonded"
        );
        assert!(st.staking_enabled);
        assert_eq!(st.p_slot, 2, "cursor lifted to one past the observed bond");
    }

    /// The adopted slot must actually reach the derive-forward set — the
    /// property that makes the bond spendable. Asserted against the real
    /// selection function, not a restatement of `bonded_slots`.
    #[test]
    fn adopted_slot_reaches_the_derive_forward_set() {
        let mut st = staking(&[0]);
        st.p_slot = 1;
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert!(
            st.derive_forward_slots(2).contains(&1),
            "an adopted bond must be derived at the next spawn, or it is lost"
        );
    }

    /// Adoption appends in ascending order without sorting, because the walk
    /// begins strictly above every recorded slot. `bonded_slots` is persisted,
    /// so an out-of-order append would let two wallets in the same logical
    /// state serialize to different bytes. Pinned against a hint whose highest
    /// entry sits well below the cursor.
    #[test]
    fn adoption_keeps_the_persisted_hint_ascending() {
        let mut st = staking(&[0, 5]);
        st.p_slot = 0; // from_record = max(0, 5 + 1) = 6, so the walk is {6,7,8}
        let ev = evidence(100, vec![match_for(id(6), 10)]);
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert_eq!(chain.adopted, vec![6]);
        assert_eq!(
            st.bonded_slots,
            vec![0, 5, 6],
            "an adopted slot is always above every recorded slot — no sort needed"
        );
        assert!(
            st.bonded_slots.windows(2).all(|w| w[0] < w[1]),
            "persisted hint must stay ascending"
        );
    }

    /// A durably-RETIRED slot is the one `Present` arm #4 refuses to adopt:
    /// re-arming a retired persona is the forever-derive problem arm #2
    /// exists to kill. It still burns the cursor. This bites against
    /// dropping the `retired_slots` guard.
    #[test]
    fn raise_burns_past_a_retired_present_without_adopting_it() {
        let mut st = staking(&[]); // non-staker: hint empty, flag off
        st.p_slot = 1;
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        let retired: std::collections::BTreeSet<u32> = [1u32].into_iter().collect();
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &retired, 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert!(
            chain.adopted.is_empty(),
            "a retired persona is never re-armed"
        );
        assert!(!st.staking_enabled, "and the wallet stays a non-staker");
        assert_eq!(chain.raised_above, Some(1));
        assert_eq!(st.p_slot, 2, "but the retired slot still burns the cursor");
    }

    /// A `Present` already in `bonded_slots` is neither re-adopted (no
    /// duplicate row) nor a second raise — the hint already accounts for it,
    /// and it sits below the walked tail.
    #[test]
    fn raise_is_a_noop_when_the_hint_already_covers_the_present() {
        let mut st = staking(&[0, 1]);
        st.p_slot = 2;
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert_eq!(chain.raised_above, None, "hint already accounts for it");
        assert!(chain.adopted.is_empty(), "no duplicate hint row");
        assert_eq!(st.bonded_slots, vec![0, 1]);
        assert_eq!(st.p_slot, 2);
    }

    /// A phantom (absent-within-covered) contributes no chain raise and no
    /// adoption: arm #4 keys on `Present`, so a slot with no real bond can
    /// neither burn the cursor forward nor re-enter the hint.
    #[test]
    fn raise_ignores_phantom_slots() {
        let mut st = staking(&[0, 1]);
        st.p_slot = 0;
        let ev = evidence(100, Vec::new()); // covered, but no match → AbsentWithinCovered
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert_eq!(chain.raised_above, None, "no lookahead Present → no raise");
        assert!(chain.adopted.is_empty());
        assert_eq!(
            st.p_slot, 2,
            "hint-fed heal still applies; a phantom does not push further"
        );
    }

    /// Unscanned evidence (`high == 0` ⇒ `OutsideCovered`) never chain-raises
    /// and never adopts — absence-≠-unscanned holds on the raise side too.
    #[test]
    fn raise_does_nothing_when_unscanned() {
        let mut st = staking(&[5]);
        st.p_slot = 3;
        let ev = evidence(0, Vec::new());
        let chain = adopt_chain_bonds_and_raise_cursor(&mut st, &ev, &no_retired(), 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("raise");
        assert_eq!(chain.raised_above, None);
        assert!(chain.adopted.is_empty());
        assert_eq!(
            st.p_slot, 6,
            "unscanned evidence does not chain-raise; hint-fed heal still applies"
        );
    }

    /// Orchestrator: retired drop + phantom drop + lookahead-only adoption.
    /// This bites against a compose that skips arm #4 after emptying the
    /// hint, or that burns past the chain-proven bond instead of adopting it.
    #[test]
    fn reconcile_at_open_drops_phantoms_and_adopts_the_chain_proven_bond() {
        // Rolled-back hint {0, 2}, cursor 1.
        // Slot 0 retired; slot 2 phantom; slot 1 Present on chain, missing
        // from the hint — the SA-5 case.
        let mut st = staking(&[0, 2]);
        st.p_slot = 1;
        let ev = evidence(100, vec![match_for(id(1), 10)]);
        let pending = std::collections::BTreeSet::new();
        let retired: std::collections::BTreeSet<u32> = [0u32].into_iter().collect();
        reconcile_staking_at_open(&mut st, &ev, &pending, &retired, 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("reconcile");
        assert_eq!(
            st.bonded_slots,
            vec![1],
            "0 retired and 2 phantom drop; 1 is adopted from the chain"
        );
        assert!(
            st.staking_enabled,
            "a chain-proven bond makes this wallet a staker again"
        );
        assert_eq!(st.p_slot, 2, "lookahead Present at 1 lifts the cursor");
    }

    /// Arm #2 burns BEFORE it drops: a cursor rolled back below a retired
    /// slot that sits outside the lookahead is still forbidden from
    /// re-offering it. This bites against reordering the `retain` ahead of
    /// the burn — the ordering arm #4 cannot repair at that distance.
    #[test]
    fn reconcile_at_open_burns_a_retired_slot_beyond_the_lookahead() {
        // Retired slot 9; the record rolled back to bonded {} cursor 1.
        let mut st = staking(&[9]);
        st.p_slot = 1;
        let ev = evidence(100, Vec::new());
        let pending = std::collections::BTreeSet::new();
        let retired: std::collections::BTreeSet<u32> = [9u32].into_iter().collect();
        reconcile_staking_at_open(&mut st, &ev, &pending, &retired, 2, |slot| {
            Ok::<_, ()>(id(u8::try_from(slot).unwrap()))
        })
        .expect("reconcile");
        assert!(
            st.bonded_slots.is_empty(),
            "the retired slot leaves the hint"
        );
        assert_eq!(
            st.p_slot, 10,
            "the retired slot burned the cursor before the drop erased it"
        );
    }

    /// Emptying `bonded_slots` reverts the wallet to a non-staker, and the
    /// cursor is untouched (the dropped slot stays burned).
    #[test]
    fn phantom_sweep_emptying_disables_staking_and_keeps_the_cursor() {
        let mut st = staking(&[3]);
        let cursor_before = st.p_slot;
        let ev = evidence(50, Vec::new());
        let sweep = reconcile_phantom_bonded_slots(
            &mut st,
            &ev,
            &std::collections::BTreeSet::new(),
            |_| Ok::<_, ()>(id(3)),
        )
        .expect("sweep");
        assert_eq!(sweep.dropped, vec![3]);
        assert!(sweep.staking_disabled);
        assert!(!st.staking_enabled);
        assert!(st.bonded_slots.is_empty());
        assert_eq!(
            st.p_slot, cursor_before,
            "no-reuse: the cursor never lowers"
        );
    }

    /// A derivation error aborts the sweep with NO mutation — fail closed,
    /// never a partial drop.
    #[test]
    fn phantom_sweep_derivation_failure_leaves_state_untouched() {
        let mut st = staking(&[1, 2]);
        let ev = evidence(50, Vec::new());
        let err = reconcile_phantom_bonded_slots(
            &mut st,
            &ev,
            &std::collections::BTreeSet::new(),
            |slot| if slot == 2 { Err("boom") } else { Ok(id(1)) },
        )
        .expect_err("derivation failure propagates");
        assert_eq!(err, "boom");
        assert_eq!(st.bonded_slots, vec![1, 2], "no partial mutation on error");
        assert!(st.staking_enabled);
    }

    use shekyl_address::Network;
    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_rpc_transport::HttpRpc;
    use tempfile::tempdir;

    use crate::engine::{Credentials, DaemonClient, EngineCreateParams, OpenedEngine, SoloSigner};

    /// A `DaemonClient` against a never-resolved URL. The persist path issues no
    /// RPC; the daemon is held only to build the `Engine`. Mirrors the bridge in
    /// `lifecycle.rs`'s `dummy_daemon` (sync body → async ctor via the ambient
    /// multi-thread runtime), which is why every test here is `multi_thread`.
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct HttpRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    /// The ticket witnesses a durable commit, not an in-memory mutation: a record
    /// persisted, then closed and reopened through the real
    /// seal → `atomic_write_file` → read path, is still present with the cursor
    /// advanced monotonically past the bonded slot. Also covers idempotency (a
    /// repeat persist of the same slot neither duplicates the slot nor moves the
    /// cursor).
    #[tokio::test(flavor = "multi_thread")]
    async fn persist_bond_record_commits_durably_and_survives_reopen() {
        let tmp = tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network: Network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // A fresh wallet stakes nothing.
        {
            let g = engine.ledger.read();
            assert!(!g.ledger.staking.staking_enabled);
            assert!(g.ledger.staking.bonded_slots.is_empty());
            assert_eq!(g.ledger.staking.p_slot, 0);
        }

        let slot = PSlot::from_raw(7);
        let ticket = engine
            .persist_bond_record(slot)
            .expect("persist bond record");
        assert_eq!(ticket.p_slot(), slot);

        // In-memory effect: enabled, slot recorded, cursor monotone-advanced past it.
        {
            let g = engine.ledger.read();
            assert!(g.ledger.staking.staking_enabled);
            assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
            assert_eq!(g.ledger.staking.p_slot, 8); // max(0, 7 + 1)
        }

        // Idempotent: re-persisting the same slot is a no-op on the set and cursor.
        let ticket_again = engine
            .persist_bond_record(slot)
            .expect("re-persist same slot");
        assert_eq!(ticket_again.p_slot(), slot);
        {
            let g = engine.ledger.read();
            assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
            assert_eq!(g.ledger.staking.p_slot, 8);
        }

        engine.close(&creds).expect("close created wallet");

        // Durability: the record survives a real seal → write → read round trip.
        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        assert!(
            matches!(opened, OpenedEngine::Loaded(_)),
            "expected loaded state"
        );
        let reopened = opened.into_wallet();

        let g = reopened.ledger.read();
        assert!(g.ledger.staking.staking_enabled);
        assert_eq!(g.ledger.staking.bonded_slots, vec![7]);
        assert_eq!(g.ledger.staking.p_slot, 8);
    }

    /// A corrupt (undecodable) pscan seal must NOT brick a staker's wallet
    /// open: the open-time reconcile degrades to keeping the bonded hint
    /// and skipping the chain-fed raise (warn loud) — the seal is auxiliary,
    /// re-derivable scan state. Skipping the drops is conservative for
    /// funds (keep, never drop). The scan path itself still fails loud on
    /// the same seal at `start_pscan` (fail-closed for the scan, not for
    /// the open).
    #[tokio::test(flavor = "multi_thread")]
    async fn corrupt_pscan_seal_degrades_the_gc_and_still_opens() {
        let tmp = tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let creds = Credentials::password_only(b"pw");
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network: Network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
        engine
            .persist_bond_record(PSlot::from_raw(2))
            .expect("persist bond record");
        engine.close(&creds).expect("close");

        // Truncated garbage where the sealed pscan state should be.
        std::fs::write(
            shekyl_engine_file::paths::pscan_state_path_from(&base_path),
            b"not a sealed pscan state",
        )
        .expect("corrupt the seal");

        let reopened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("open must survive a corrupt auxiliary seal")
        .into_wallet();
        let g = reopened.ledger.read();
        assert!(g.ledger.staking.staking_enabled, "no wrongful GC");
        assert_eq!(g.ledger.staking.bonded_slots, vec![2], "slots kept");
    }

    /// The persist→reopen seam wires Model D end to end: a fresh wallet is a
    /// non-staker (no actor), and after a bond record is persisted, reopen
    /// spawns the `StakeEngine` over exactly `{bonded} ∪ {cursor ..= cursor+k}`
    /// — the bonded slot held for unbonding, the lookahead window held for
    /// in-session rotation, and nothing outside it.
    #[tokio::test(flavor = "multi_thread")]
    async fn staker_reopen_spawns_stake_engine_over_bonded_union_lookahead() {
        use crate::engine::stake_engine::{StakeEngineError, ARCHIVAL_PERSONA_LOOKAHEAD};

        let tmp = tempdir().expect("tempdir");
        let base_path = tmp.path().join("wallet");
        let password: &[u8] = b"correct horse battery staple";
        let creds = Credentials::password_only(password);
        let seed = fixed_seed();

        let params = EngineCreateParams::for_test_full(&base_path, &creds, &seed);
        let network: Network = params.network;
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

        // A fresh wallet is not a staker: no actor, no derived personas.
        assert!(engine.stake.is_none(), "non-staker spawns no StakeEngine");

        // Become a staker at slot 3; the cursor advances to max(0, 3 + 1) = 4.
        engine
            .persist_bond_record(PSlot::from_raw(3))
            .expect("persist bond record");
        engine.close(&creds).expect("close created wallet");

        let opened = Engine::<SoloSigner>::open_full(
            &base_path,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen FULL wallet");
        assert!(
            matches!(opened, OpenedEngine::Loaded(_)),
            "expected loaded state"
        );
        let reopened = opened.into_wallet();

        let stake = reopened
            .stake
            .as_ref()
            .expect("a staker reopen spawns a StakeEngine");

        // The bonded slot is held — reachable for unbonding after the seed is gone.
        stake
            .mint_handle(PSlot::from_raw(3))
            .await
            .expect("bonded slot 3 is held");

        // The full lookahead window from the cursor is held.
        let cursor = 4u32;
        for offset in 0..=ARCHIVAL_PERSONA_LOOKAHEAD {
            stake
                .mint_handle(PSlot::from_raw(cursor + offset))
                .await
                .unwrap_or_else(|e| panic!("cursor+{offset} must be held, got {e:?}"));
        }

        // One slot past the window is not held — a real domain state (reopen to extend).
        let beyond = cursor + ARCHIVAL_PERSONA_LOOKAHEAD + 1;
        assert!(
            matches!(
                stake.mint_handle(PSlot::from_raw(beyond)).await,
                Err(StakeEngineError::LookaheadExhausted { .. })
            ),
            "slot beyond the lookahead window must not be held"
        );

        // A slot below the cursor that is not bonded is not held either.
        assert!(
            matches!(
                stake.mint_handle(PSlot::from_raw(2)).await,
                Err(StakeEngineError::LookaheadExhausted { .. })
            ),
            "an unbonded slot below the cursor must not be held"
        );
    }
}
