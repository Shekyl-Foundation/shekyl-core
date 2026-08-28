// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **PR-P4 slice 3 — the retire walk.** The judge that has to run before
//! anything makes the `Unbond` exit reachable.
//!
//! # What this walk judges
//!
//! `PRINCIPAL_STAKE_LIFECYCLE.md` (PR-P4 row) names three propositions: **the
//! wipe**, **the funded gate**, and **the seal-then-act crash ordering**. All
//! three are engine-level by nature — actor state, outcome enums, persisted
//! store — which is why this is not a daemon walk.
//!
//! **This walk asserts two of them.** The seal-then-act ordering is *not
//! observable with the existing scaffolding*, for a reason recorded in full at
//! section 3 below: the seal and the retire dispatch both sit inside the
//! per-batch scan loop, so reaching them needs a served chain longer than the
//! ~270k-block cursor the claim-window expiry requires. It is recorded as a
//! named limit and registered in `docs/FOLLOWUPS.md` rather than asserted
//! weakly — a walk that cannot fail on its subject is worse than an absent
//! one, and a first draft of exactly that test passed while doing nothing.
//!
//! # Why it exists when `pscan/task_tests.rs` already covers retire
//!
//! Those tests observe the **dispatch bookkeeping**: the session-dedup set,
//! `retired_records()`, the pending trigger. That is real coverage and this
//! walk does not duplicate it. But none of it observes the **actor**, and the
//! gap has a shape worth naming: `dispatch_retires` inserts into
//! `retired_this_session` on **both** the `Retired` and the `NotHeld` arm, so
//! `retired.contains(&id)` is true whether the persona was wiped or was never
//! held at all. A `retire_bonded` that returned `Retired { slot }` while
//! removing nothing would pass every existing assertion.
//!
//! So the walk's contribution is one thing applied to both live arms: an
//! **independent observation of actor state** —
//! [`StakeEngineHandle::persona_canonical_id`], a *different* handler reading
//! the same `held` map, which answers `LookaheadExhausted` once the slot is
//! gone. Nothing else in the tree asserts that a retired persona is actually
//! gone from the actor.
//!
//! # What "observe the wipe" can and cannot mean
//!
//! `wipe_bonded(persona)` is `drop(persona)`; the zeroization is per-field
//! `ZeroizeOnDrop` on the key bundle, running at that drop. After the drop
//! there is no reference, so **"the key bytes are zeroed" is structurally
//! guaranteed and not observable** — inspecting freed memory is not something
//! a test may do. What is observable is that the persona is **gone from the
//! actor and unusable**, and that is what these assertions say. The stronger
//! claim is the type system's, not this walk's.
//!
//! # The fixture precondition is load-bearing (rule 47)
//!
//! The irreversibility here does **not** live in the key wipe — the comment at
//! the seal-then-act site is explicit that a crashed retire re-fires and "the
//! persona re-derives from seed", and `test_fixtures::derive_bundle` is
//! deterministic for exactly that reason. It lives in the **durable
//! retired-record**: `PScanAccrual::retire_persona` returns `false` for an id
//! already in `retired`, and the open path stops deriving a retired slot.
//!
//! A subject that is *already retired* therefore answers `NotHeld`, takes a
//! different path, and **still satisfies an outcome-shaped assertion** — a
//! green run that judged nothing. [`the_second_retire_is_the_no_op_a_stale_fixture_would_hide`]
//! exercises exactly that degradation, so the hazard is demonstrated here
//! rather than only described.
//!
//! **What this walk does and does not face.** It builds its state fresh
//! in-process ([`walk_accrual`]) and never loads a persisted scan store, so it
//! cannot *encounter* the stale-store case; saying otherwise would overstate
//! what is judged. [`assert_walk_precondition`] is therefore a **tripwire on
//! the fixture builder**, not a live check: it fails if a future edit to
//! `walk_accrual` seeds a retired-record or drops the pending trigger, either
//! of which would make every arm below vacuous while still reporting green.
//! The store-backed form of this hazard belongs to a walk that actually loads
//! a store — the daemon walk, or whatever closes the seal-then-act seam.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::MAX_CLAIM_AGE_W;
use shekyl_crypto_pq::archival_p::ArchivalPKeys;
use shekyl_engine_state::pscan_state::PScanState;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};

use crate::engine::pscan::accrual::PScanAccrual;
use crate::engine::stake_engine::test_fixtures::derive_bundle;
use crate::engine::stake_engine::{
    persona_canonical_id, FundedSlots, PSlot, RetireOutcome, RetirementWitness, StakeEngineError,
    StakeEngineHandle,
};

/// The slot the walk retires, and the slot it keeps active so the retire is
/// never refused for the *wrong* reason (`SkippedActive` would mask the arm
/// under test).
const RETIRE_SLOT: u32 = 1;
const ACTIVE_SLOT: u32 = 0;

/// Spawn an actor holding both slots, with `ACTIVE_SLOT` active and
/// `RETIRE_SLOT` bonded — the only shape in which the retire arms are the ones
/// being exercised.
///
/// **The returned id is computed from the very bundle the actor is handed**,
/// not from a second derivation of the same slot. Both would agree today —
/// `derive_bundle` is deterministic and the fixture module says so — but that
/// makes "the id names the persona the actor holds" a property held *by
/// determinism* rather than *by construction*. Deriving once and reading the id
/// off the same value before it moves into the map removes the dependency
/// instead of relying on it, and halves the PQC key derivations this fixture
/// pays on every one of its callers.
fn spawn_walk_actor() -> (StakeEngineHandle, PCanonicalId) {
    let active_bundle = derive_bundle(ACTIVE_SLOT);
    let retire_bundle = derive_bundle(RETIRE_SLOT);
    let id = persona_canonical_id(&retire_bundle).expect("fixture key encodes");

    let bundles: BTreeMap<PSlot, ArchivalPKeys> = [
        (PSlot::from_raw(ACTIVE_SLOT), active_bundle),
        (PSlot::from_raw(RETIRE_SLOT), retire_bundle),
    ]
    .into_iter()
    .collect();
    let bonded: BTreeSet<PSlot> = [PSlot::from_raw(RETIRE_SLOT)].into_iter().collect();
    let handle = StakeEngineHandle::spawn(bundles, bonded, Some(PSlot::from_raw(ACTIVE_SLOT)));
    (handle, id)
}

/// The settled epoch at which `unbond_epoch = 0` has fallen out of the claim
/// window — the eligibility the witness constructor tests.
fn expired_settled() -> SettlementEpoch {
    SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1)
}

/// A settled epoch at which `unbond_epoch = 0` is still claimable, so
/// `from_confirmed_unbond` refuses to build a witness at all.
fn unexpired_settled() -> SettlementEpoch {
    SettlementEpoch::from_raw(0)
}

/// **Rule 47 applied to the fixture — a tripwire on [`walk_accrual`], not a
/// live check.** Against today's builder both assertions hold by construction
/// and cannot fail; they exist so that an edit which seeds a retired-record or
/// drops the pending trigger fails *here*, loudly, instead of quietly making
/// every arm below exercise the idempotent no-op while still reporting green.
/// Bite it by adding a `RetiredPersonaRecord` for the subject in
/// `walk_accrual`.
fn assert_walk_precondition(accrual: &PScanAccrual, id: &PCanonicalId) {
    assert!(
        !accrual
            .retired_records()
            .iter()
            .any(|r| r.p_canonical_id == *id),
        "walk precondition: the persona is already durably retired, so this run \
         would exercise the idempotent no-op and pass without judging the wipe — \
         the fixture must be built fresh (see the module header)"
    );
    assert!(
        accrual.pending_unbonds().contains_key(id),
        "walk precondition: no pending retire trigger for the subject, so no \
         retire can fire and the walk would judge nothing"
    );
}

/// Is the persona's key material still reachable through the actor?
///
/// The **independent** observable:
/// [`StakeEngineHandle::persona_canonical_id`] asks the actor's
/// `ProjectPersonaCanonicalId` handler, which reads the same `held` map that
/// `retire_bonded` mutates — so the walk is not grading `retire_bonded` by the
/// enum `retire_bonded` chose to return. (The message type itself is private
/// to the actor module and is named in prose rather than linked.)
async fn persona_still_held(stake: &StakeEngineHandle, slot: u32) -> bool {
    match stake.persona_canonical_id(PSlot::from_raw(slot)).await {
        Ok(_) => true,
        Err(StakeEngineError::LookaheadExhausted { .. }) => false,
        Err(other) => panic!("unexpected error probing held state: {other:?}"),
    }
}

/// Build the walk's starting accrual: one pending retire trigger for the
/// subject, a cursor high enough that `settled_epoch()` has passed the claim
/// window, and no retired-record.
fn walk_accrual(id: PCanonicalId) -> PScanAccrual {
    use shekyl_engine_state::pscan_cursor::PScanCursor;

    let cursor_height = (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
    let mut pending = BTreeMap::new();
    pending.insert(id, SettlementEpoch::from_raw(0));
    let state = PScanState::new(
        PScanCursor::at(BlockHeight::from_raw(cursor_height), [0u8; 32]),
        BTreeMap::new(),
        pending,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    );
    PScanAccrual::from_state(&state)
}

// ---------------------------------------------------------------------------
// 1. The wipe
// ---------------------------------------------------------------------------

/// **The wipe, observed through a different handler than the one that did it.**
///
/// The edit that makes this red is deleting the `held.remove(&slot)` /
/// `wipe_bonded` pair from `retire_bonded` while still returning
/// `Retired { slot }` — which every existing retire assertion survives, because
/// they read the dispatch bookkeeping rather than the actor.
#[tokio::test]
async fn a_retired_persona_is_gone_from_the_actor() {
    let (stake, id) = spawn_walk_actor();
    let accrual = walk_accrual(id);
    assert_walk_precondition(&accrual, &id);

    // Precondition, stated as an assertion rather than assumed: the key
    // material IS reachable before the retire. Without this the post-condition
    // below is satisfied by a persona that was never held.
    assert!(
        persona_still_held(&stake, RETIRE_SLOT).await,
        "the subject must be held before the walk retires it"
    );

    let witness = RetirementWitness::from_confirmed_unbond(
        id,
        SettlementEpoch::from_raw(0),
        expired_settled(),
    )
    .expect("epoch 0 has fallen out of the claim window at settled = W+1");
    let outcome = stake
        .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
        .await
        .expect("actor is up");

    assert_eq!(
        outcome,
        RetireOutcome::Retired {
            slot: PSlot::from_raw(RETIRE_SLOT)
        },
        "an expired, unfunded, non-active persona is wiped"
    );
    assert!(
        !persona_still_held(&stake, RETIRE_SLOT).await,
        "THE ASSERTION THIS WALK EXISTS FOR: after the retire the persona's key \
         material is no longer reachable through the actor. Zeroization itself is \
         the key bundle's ZeroizeOnDrop and is not observable here; this is the \
         reachable half — see the module header."
    );
}

/// **Negative control for the wipe.** With the confirmation predicate
/// unsatisfied there is no witness, so no retire can fire — and the walk's
/// post-condition must be the thing that goes red, not a downstream symptom.
#[tokio::test]
async fn without_the_confirmation_predicate_the_key_material_stays_readable() {
    let (stake, id) = spawn_walk_actor();

    // The predicate IS the guard: `from_confirmed_unbond` refuses to construct a
    // witness while the persona can still claim, so the unsafe state is
    // unreachable rather than checked.
    assert!(
        RetirementWitness::from_confirmed_unbond(
            id,
            SettlementEpoch::from_raw(0),
            unexpired_settled()
        )
        .is_none(),
        "a still-claimable persona yields no witness"
    );
    assert!(
        persona_still_held(&stake, RETIRE_SLOT).await,
        "no witness, no wipe: the key material stays readable"
    );
}

/// **The degradation a stale fixture would hide, demonstrated.**
///
/// The retire is idempotent: re-handing a witness for a persona that is already
/// gone answers `NotHeld`, which is correct and is what makes a crashed retire
/// safe to re-fire. It is also what makes a *stale* fixture dangerous — a run
/// whose subject was retired before the walk started takes this path, and an
/// assertion shaped like "the outcome is not an error" would still pass while
/// judging nothing.
///
/// Recorded as a test rather than a warning in prose because that is the
/// difference between a hazard the reader is told about and one the suite can
/// see. It is also why [`assert_walk_precondition`] exists.
#[tokio::test]
async fn the_second_retire_is_the_no_op_a_stale_fixture_would_hide() {
    let (stake, id) = spawn_walk_actor();
    let accrual = walk_accrual(id);
    assert_walk_precondition(&accrual, &id);

    let witness = || {
        RetirementWitness::from_confirmed_unbond(
            id,
            SettlementEpoch::from_raw(0),
            expired_settled(),
        )
        .expect("eligible")
    };

    let first = stake
        .retire_bonded_persona(witness(), std::sync::Arc::new(FundedSlots::default()))
        .await
        .expect("actor is up");
    assert_eq!(
        first,
        RetireOutcome::Retired {
            slot: PSlot::from_raw(RETIRE_SLOT)
        },
        "the first retire wipes"
    );

    let second = stake
        .retire_bonded_persona(witness(), std::sync::Arc::new(FundedSlots::default()))
        .await
        .expect("actor is up");
    assert_eq!(
        second,
        RetireOutcome::NotHeld,
        "the second is the idempotent no-op — SAME witness, SAME call, and the \
         only thing distinguishing it from the first is prior state. A walk \
         started from a stale fixture begins here."
    );
    assert!(
        !persona_still_held(&stake, RETIRE_SLOT).await,
        "and the persona stays gone across the no-op"
    );
}

// ---------------------------------------------------------------------------
// 2. The funded gate
// ---------------------------------------------------------------------------

/// **The funded gate discriminates.** Both arms, same fixture, differing only
/// in the funded set — because either arm alone is consistent with a constant
/// function. Funded-only would prove the gate can refuse; unfunded-only would
/// prove the wipe can fire; only the pair proves it *gates*.
///
/// Observed at the actor, not through `RetireOutcome`: the funded arm must
/// leave the key material readable, which is the property the gate exists for
/// (wiping a funded slot strands spendable `P` funds, since the open path stops
/// deriving a retired slot).
#[tokio::test]
async fn the_funded_gate_refuses_and_the_unfunded_case_proceeds() {
    let subject_slot = PSlot::from_raw(RETIRE_SLOT);

    // --- Arm A: funded → refused, key material survives ---
    let (stake, id) = spawn_walk_actor();
    let accrual = walk_accrual(id);
    assert_walk_precondition(&accrual, &id);

    let funded = std::sync::Arc::new(FundedSlots::from_slots([subject_slot]));
    let witness = RetirementWitness::from_confirmed_unbond(
        id,
        SettlementEpoch::from_raw(0),
        expired_settled(),
    )
    .expect("eligible");
    let refused = stake
        .retire_bonded_persona(witness, funded)
        .await
        .expect("actor is up");
    assert_eq!(
        refused,
        RetireOutcome::SkippedFunded { slot: subject_slot },
        "an expired persona whose slot still holds unspent funding is refused"
    );
    assert!(
        persona_still_held(&stake, RETIRE_SLOT).await,
        "the refusal is a REFUSAL: the funded slot's key material is untouched, \
         which is the whole point — a wiped funded slot strands its funds"
    );

    // --- Arm B: same fixture, unfunded → proceeds ---
    let (stake_b, id_b) = spawn_walk_actor();
    let witness_b = RetirementWitness::from_confirmed_unbond(
        id_b,
        SettlementEpoch::from_raw(0),
        expired_settled(),
    )
    .expect("eligible");
    let allowed = stake_b
        .retire_bonded_persona(witness_b, std::sync::Arc::new(FundedSlots::default()))
        .await
        .expect("actor is up");
    assert_eq!(
        allowed,
        RetireOutcome::Retired { slot: subject_slot },
        "the SAME persona, differing only in the funded set, is wiped"
    );
    assert!(
        !persona_still_held(&stake_b, RETIRE_SLOT).await,
        "and the wipe reached the actor"
    );
}

// ---------------------------------------------------------------------------
// 3. Seal-then-act crash ordering — NOT OBSERVABLE HERE, and why
// ---------------------------------------------------------------------------
//
// The third proposition the PR-P4 row names has **no assertion in this walk**,
// deliberately, because the existing scaffolding cannot observe it and a test
// that cannot fail on its subject is worse than an absent one.
//
// The ordering lives inside `pscan_sweep`: `store.save(..)` (sealing the
// `pending_unbonds` trigger) and then `dispatch_retires(..)` (the irreversible
// wipe). Both statements sit **inside the per-batch scan loop**
// (`while accrual.next_height() < horizon`), so neither runs unless the sweep
// has blocks to scan.
//
// The walk's subject must have an *expired* claim window, which means
// `settled_epoch()` past `MAX_CLAIM_AGE_W` — a cursor around
// `(W + 2) * SETTLEMENT_EPOCH_BLOCKS`, ~270k blocks. Reaching the seal through
// the real loop therefore needs a served chain longer than that cursor plus the
// reorg depth. `pscan/task_tests.rs` records the same arithmetic for the same
// reason ("a real scan to settled = W+1 would be ~270k blocks") and calls
// `dispatch_retires` directly instead. Lowering the cursor is not a way out:
// the cursor is what makes the persona retirable at all.
//
// A first draft of this walk DID assert the ordering, by pre-seeding an
// injectable store and reading the state back after a run. It passed. It was
// vacuous: the read returned the walk's own fixture, because `save()` had never
// been called. A save counter turned it red, which is how the limit above was
// found rather than shipped. That counter is why this section is a comment
// instead of a green test.
//
// What IS already covered elsewhere, so the gap is narrower than it looks: the
// pending trigger's survival and re-fire are asserted in
// `pscan/task_tests.rs` (`dispatch_defers_retire_while_the_slot_holds_unspent_funding`
// keeps the trigger for a later sweep; the dedup test shows the corroborated
// prune removing it). What no test observes is that the **seal precedes the
// wipe**.
//
// Closing it needs one of two things, and both are their own slice:
//   1. a seam that reaches the seal/dispatch pair without a 270k-block scan
//      (e.g. lifting them out of the batch loop, which is a production change
//      with its own reasoning), or
//   2. the daemon walk, where a real chain exists.
//
// Registered rather than left implicit — see `docs/FOLLOWUPS.md`.
