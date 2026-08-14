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
///   evidence short of the sighted height reads `OutsideCovered` (kept), and
///   so does evidence whose coverage was gathered **without the persona
///   watched** over the sighted height (the [`PReconcileSet`] per-persona
///   watch floor — a restore-path seal that advanced past the bond while
///   watching only other personas makes no absence claim about this one).
///   Coverage past the sighting *with the persona watched* and no match
///   means the sighted block reorged out (dropped, correctly). A `Present`
///   verdict prunes the sighting — the seal's own match row supersedes it.
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
#[path = "stake_persist_tests.rs"]
mod tests;
