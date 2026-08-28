// Copyright (c) 2025-2026, The Shekyl Foundation
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
//! **This walk asserts all three.**
//!
//! Getting there took two corrections worth keeping, because both are the
//! failure this walk exists to catch, committed while building it:
//!
//! 1. A draft of the seal-then-act test **passed while doing nothing** — it
//!    pre-seeded the store and read the state back, so the read returned its
//!    own fixture and `save()` had never been called. A save counter turned it
//!    red. That counter is still in [`CrashAfterSealStore`].
//! 2. The limit that replaced it — "unobservable; reaching the seal needs a
//!    ~270k-block chain" — was **wrong**, and wrong in a specific way:
//!    it reasoned from the existing `TestDaemon` harness instead of from the
//!    [`BlockSource`](crate::engine::pscan::block_source::BlockSource)
//!    interface, which is `tip_height` plus a single-height `block_at`. The
//!    sweep scans `[frontier, horizon)`; with the frontier seeded at the
//!    cursor that is ONE block, which [`WalkBlockSource`] serves.
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
//! gone.
//!
//! **Measured, and narrower than a first draft of this header claimed.** Under
//! that bite the eight `pscan/task_tests.rs` tests all stay green — but
//! `stake_engine_tests::retire_wipes_a_terminal_persona_and_is_idempotent`
//! goes red, because its *second* retire would answer `Retired` instead of
//! `NotHeld`. So this walk is **not** the tree's first assertion that removal
//! occurred. The difference is how it is observed: that test **infers**
//! removal from a later call's outcome, while this one **reads the state
//! directly** through a handler that does not mutate it. The genuinely new
//! coverage is the funded arm — that a *refused* retire leaves the key
//! material readable, which nothing else asserts at the actor.
//!
//! The first draft said "nothing else in the tree asserts this", from running
//! `--lib pscan::task` and generalising to the tree. Recorded because the
//! walk's whole subject is claims that outrun what was measured.
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
//! **Where that hazard is live, and where it is not.** The direct-actor tests
//! spawn a fresh actor per test and never touch a store, so they cannot
//! encounter it. The seal-then-act test **does** load state through
//! [`CrashAfterSealStore`] and drive the real sweep over it — so that is the
//! one place [`assert_walk_precondition`] guards behaviour rather than
//! decorating it, and it is called there and nowhere else.

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

/// **Rule 47 applied to the fixture, and it guards the ONE test whose state it
/// reaches.** [`walk_accrual`]'s state is consumed by the seal-then-act test,
/// which drives the real sweep over it; there the pending trigger is what makes
/// a retire fire at all and a seeded retired-record would divert it to the
/// idempotent no-op.
///
/// It is deliberately **not** called from the direct-actor tests. Those hand a
/// witness straight to the actor and never touch an accrual, so asserting on
/// one there would be a tripwire wired to nothing — an earlier revision did
/// exactly that, and the assertion moved while the behaviour it claimed to
/// guard did not.
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

/// The cursor height at which the subject's claim window has expired, so the
/// retire is eligible. Shared by the fixture and the synthetic block source,
/// which must agree on it.
fn walk_cursor_height() -> u64 {
    (MAX_CLAIM_AGE_W + 2) * shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS
}

/// Build the walk's starting accrual: one pending retire trigger for the
/// subject, a cursor high enough that `settled_epoch()` has passed the claim
/// window, and no retired-record.
fn walk_accrual(id: PCanonicalId) -> PScanAccrual {
    use shekyl_engine_state::pscan_cursor::PScanCursor;

    let cursor_height = walk_cursor_height();
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
/// `Retired { slot }`. All eight `pscan/task_tests.rs` tests survive that edit
/// — they read the dispatch bookkeeping, and `retired_this_session` is written
/// on both the `Retired` and `NotHeld` arms — but
/// `stake_engine_tests::retire_wipes_a_terminal_persona_and_is_idempotent`
/// does not: its second retire would answer `Retired`. This assertion is the
/// *direct* reading of the same fact that test infers from a later outcome.
#[tokio::test]
async fn a_retired_persona_is_gone_from_the_actor() {
    let (stake, id) = spawn_walk_actor();

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
// 3. Seal-then-act crash ordering
// ---------------------------------------------------------------------------
//
// A first draft of this walk recorded the ordering as UNOBSERVABLE, reasoning
// that `store.save` and `dispatch_retires` sit inside `pscan_sweep`'s per-batch
// loop and the subject needs a ~270k-block cursor, so the loop could not be
// reached without serving ~270k blocks. **That was wrong, and the error is
// worth naming: it reasoned from the existing harness rather than from the
// interface.** `BlockSource` is two methods — `tip_height` and a
// single-height `block_at` — so a synthetic source serves any height on
// demand. The loop scans `[frontier, horizon)`, and with the frontier seeded
// at the cursor that range is ONE block.

/// Serves exactly the sliver the sweep needs: a tip just past
/// `cursor + reorg_depth`, and one synthetic block at the cursor whose parent
/// hash matches the seeded frontier (the exhaustiveness check compares against
/// `accrual.frontier_hash()`, so it must).
struct WalkBlockSource {
    cursor_height: u64,
}

impl crate::engine::pscan::block_source::BlockSource for WalkBlockSource {
    fn tip_height(
        &self,
    ) -> impl std::future::Future<
        Output = Result<BlockHeight, crate::engine::pscan::block_source::BlockSourceError>,
    > + Send {
        // horizon = tip - reorg_depth must exceed the frontier by exactly one.
        let tip = BlockHeight::from_raw(self.cursor_height + WALK_REORG_DEPTH + 2);
        async move { Ok(tip) }
    }

    fn block_at(
        &self,
        height: BlockHeight,
    ) -> impl std::future::Future<
        Output = Result<
            Option<shekyl_scanner::ScannableBlock>,
            crate::engine::pscan::block_source::BlockSourceError,
        >,
    > + Send {
        let block = walk_block(self.cursor_height, height.to_raw());
        async move { Ok(Some(block)) }
    }
}

const WALK_REORG_DEPTH: u64 = 1;

/// The synthetic block at `h`, chained from the seeded frontier.
///
/// **Chaining is load-bearing across the restart.** The exhaustiveness check
/// compares a block's `previous` against `accrual.frontier_hash()`, and run 1's
/// seal *advances* the cursor — so run 2 resumes one height higher and its
/// block must chain to the hash run 1 sealed, not to the seeded `[0u8; 32]`.
/// A first version returned `[0u8; 32]` at every height; run 2 then failed
/// exhaustiveness, the sweep never reached the dispatch, and the retire did not
/// re-fire.
fn walk_block(cursor_height: u64, h: u64) -> shekyl_scanner::ScannableBlock {
    use crate::engine::test_support::make_synthetic_block;
    let mut block = make_synthetic_block(cursor_height, [0u8; 32]);
    let mut at = cursor_height;
    while at < h {
        let prev = block.block.hash();
        at += 1;
        block = make_synthetic_block(at, prev);
    }
    block
}

/// A [`PScanStore`] that lands the seal and then simulates the crash.
///
/// `save()` records the state, **counts the write**, and cancels the token.
/// `dispatch_retires` checks `cancel.is_cancelled()` at the top of its
/// candidate loop — before it builds a witness and before it asks the actor —
/// so the wipe cannot run. That is the "crashed between seal and act" state,
/// reached deterministically rather than by racing a real abort.
///
/// The counter is not decoration: the state is pre-seeded, so reading it back
/// would otherwise return the walk's own fixture and pass with `save()` never
/// called. A draft of this test did exactly that.
#[derive(Clone)]
struct CrashAfterSealStore {
    state: std::sync::Arc<std::sync::Mutex<Option<PScanState>>>,
    saves: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cancel_on_save: Option<tokio_util::sync::CancellationToken>,
}

#[derive(Debug, thiserror::Error)]
#[error("walk store error")]
struct WalkStoreErr;

impl crate::engine::pscan::task::PScanStore for CrashAfterSealStore {
    type Error = WalkStoreErr;

    fn load(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<PScanState>, WalkStoreErr>> + Send {
        let loaded = self.state.lock().unwrap().clone();
        async move { Ok(loaded) }
    }

    fn save(
        &self,
        state: &PScanState,
    ) -> impl std::future::Future<Output = Result<(), WalkStoreErr>> + Send {
        *self.state.lock().unwrap() = Some(state.clone());
        self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(cancel) = &self.cancel_on_save {
            cancel.cancel();
        }
        async move { Ok(()) }
    }
}

/// One tick, then cancel — so a run that is not simulating a crash still
/// terminates after exactly one sweep.
struct OneTickThenCancel {
    fired: bool,
    cancel: tokio_util::sync::CancellationToken,
}

impl crate::engine::pscan::cadence::ScanSchedule for OneTickThenCancel {
    fn next_tick(&mut self) -> impl std::future::Future<Output = ()> + Send {
        let first = !self.fired;
        self.fired = true;
        if !first {
            self.cancel.cancel();
        }
        async move {
            if !first {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Drive one sweep of the real loop over the seeded state.
async fn run_one_sweep(
    stake: StakeEngineHandle,
    store: CrashAfterSealStore,
    cancel: tokio_util::sync::CancellationToken,
    cursor_height: u64,
) {
    use crate::engine::pscan::task::{run_pscan_task, PScanConfig, PScanSlot, PScanStore as _};

    let initial = store.load().await.expect("load");
    let schedule = OneTickThenCancel {
        fired: false,
        cancel: cancel.clone(),
    };
    let guard = PScanSlot::new().try_claim().expect("fresh slot claims");
    run_pscan_task(
        WalkBlockSource { cursor_height },
        stake,
        store,
        schedule,
        PScanConfig {
            reorg_depth: WALK_REORG_DEPTH,
            batch_blocks: 1,
        },
        initial,
        (),
        cancel,
        guard,
    )
    .await;
}

/// **Seal-then-act: the trigger is durable before the wipe, and the wipe
/// re-fires from it after the crash.**
///
/// Two runs over one store. The first crashes the instant the seal lands; the
/// second resumes from exactly what that seal left behind.
///
/// # What this proves, and what it does not
///
/// It proves **the seal precedes the wipe** — run 1 sealed a durable trigger
/// while the persona was still held — and **the trigger re-fires**: run 2 wiped
/// from the sealed state alone.
///
/// It also **detects the reordering**, which an earlier draft of this comment
/// said a walk could not do. Bite-verified: hoisting the `dispatch_retires`
/// call above the seal in `pscan_sweep` turns this test red on the
/// "MUST NOT have run" assertion, because the wipe then lands before the
/// crash-at-seal can stop it.
///
/// What it still does not prove is that act-then-seal would *lose* the trigger
/// under a real crash — that is an argument about durability semantics, not
/// something a test observes. The boundary is recorded so a green run is never
/// read as the stronger claim.
#[tokio::test]
async fn a_crash_after_the_seal_leaves_the_trigger_durable_and_the_retire_re_fires() {
    let (stake, id) = spawn_walk_actor();
    let cursor_height = walk_cursor_height();
    let accrual = walk_accrual(id);
    // The one place the precondition guards real behaviour: this state is
    // driven through the sweep below, so a missing trigger or a seeded
    // retired-record would silently divert the retire.
    assert_walk_precondition(&accrual, &id);
    let seeded = accrual.to_state();

    // --- Run 1: crash the instant the seal lands ---
    let cancel = tokio_util::sync::CancellationToken::new();
    let store = CrashAfterSealStore {
        state: std::sync::Arc::new(std::sync::Mutex::new(Some(seeded))),
        saves: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        cancel_on_save: Some(cancel.clone()),
    };
    run_one_sweep(stake.clone(), store.clone(), cancel, cursor_height).await;

    assert!(
        store.saves.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the loop must actually have sealed — the store is pre-seeded, so reading \
         the state back would otherwise just return the walk's own fixture"
    );
    assert!(
        persona_still_held(&stake, RETIRE_SLOT).await,
        "crashed between seal and act: the irreversible wipe MUST NOT have run"
    );
    let sealed = store
        .state
        .lock()
        .unwrap()
        .clone()
        .expect("the seal landed");
    assert!(
        PScanAccrual::from_state(&sealed)
            .pending_unbonds()
            .contains_key(&id),
        "and the trigger that justifies the wipe IS durable — that is the \
         ordering: seal first, act second"
    );

    // --- Run 2: restart from exactly what the crash left behind ---
    let (stake2, id2) = spawn_walk_actor();
    assert_eq!(
        id2, id,
        "the persona re-derives from seed across the restart"
    );
    assert!(
        persona_still_held(&stake2, RETIRE_SLOT).await,
        "the restarted wallet holds it again (re-derived, not resurrected)"
    );
    let cancel2 = tokio_util::sync::CancellationToken::new();
    let store2 = CrashAfterSealStore {
        state: std::sync::Arc::new(std::sync::Mutex::new(Some(sealed))),
        saves: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        cancel_on_save: None,
    };
    run_one_sweep(stake2.clone(), store2, cancel2, cursor_height).await;

    assert!(
        !persona_still_held(&stake2, RETIRE_SLOT).await,
        "the durable trigger re-fired the retire after the crash, and THIS time \
         the wipe reached the actor"
    );
}
