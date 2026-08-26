// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the open-time staking reconcile (`engine/stake_persist.rs`).
//!
//! Wired as a `#[path]` child of `stake_persist::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

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

/// Evidence covering `[0, high)` carrying `matches`, with every test
/// persona (`id(0)..id(9)`) watched from genesis — the classic
/// staker-from-birth shape, so the arm matrix below exercises the
/// covered/absent/present axes without the provenance gate interfering.
/// The provenance axis has its own test
/// (`phantom_sweep_keeps_a_sighted_slot_its_persona_was_never_watched_for`).
fn evidence(high: u64, matches: Vec<BondPostMatch>) -> PReconcileSet {
    PReconcileSet::from_verified_scan(
        VerifiedBatch::for_test(0, high, [1; 32]).range(),
        matches,
        (0..10u8)
            .map(|b| (id(b), BlockHeight::from_raw(0)))
            .collect(),
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
    let sweep =
        reconcile_phantom_bonded_slots(&mut st, &ev, &std::collections::BTreeSet::new(), |_| {
            Ok::<_, ()>(id(9))
        })
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
    let sweep = reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
        .expect("sweep");
    assert!(sweep.dropped.is_empty(), "sighted slot must survive");
    assert_eq!(st.bonded_slots, vec![3]);
    assert!(
        st.bond_sightings.contains_key(&3),
        "the bridge stays until the seal covers or refutes it"
    );
}

/// The provenance route (the review's stuck-funds finding): a
/// probe-adopted slot whose sighting sits BELOW an already-advanced seal
/// frontier, where the persona was NEVER watched while that coverage
/// accumulated (restore-then-rescan: the pscan sealed `[0, tip)` watching
/// only other personas, then a lower-floor rescan sighted this bond).
/// The whole-covered *and* the height-gated verdicts both sit inside
/// covered here — only the per-persona watch floor keeps the real bond
/// out of the GC. Greenable only by the provenance gate.
#[test]
fn phantom_sweep_keeps_a_sighted_slot_its_persona_was_never_watched_for() {
    let mut st = staking(&[3]);
    st.record_first_sighting(3, BlockHeight::from_raw(50));
    // Coverage [0, 100) is PAST the sighting — but gathered with a watch
    // that never contained this persona (id(0xEE) has no floor row).
    let ev = PReconcileSet::from_verified_scan(
        VerifiedBatch::for_test(0, 100, [1; 32]).range(),
        Vec::new(),
        std::collections::BTreeMap::new(),
    );
    let sweep =
        reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(0xEE)))
            .expect("sweep");
    assert!(
        sweep.dropped.is_empty(),
        "coverage gathered without the persona watched must not GC its bond"
    );
    assert_eq!(st.bonded_slots, vec![3]);
    assert!(
        st.bond_sightings.contains_key(&3),
        "the bridge stays until watched coverage corroborates or refutes it"
    );
}

/// Coverage PAST the sighting with no match: the sighted block reorged
/// out — the drop is then correct, and the sighting row goes with it.
#[test]
fn phantom_sweep_drops_a_sighted_slot_the_seal_covered_and_refuted() {
    let mut st = staking(&[3]);
    st.record_first_sighting(3, BlockHeight::from_raw(50));
    let ev = evidence(100, Vec::new()); // covered [0,100): past the sighting, no match
    let sweep = reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
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
    let sweep = reconcile_phantom_bonded_slots(&mut st, &ev, &no_retired(), |_| Ok::<_, ()>(id(3)))
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
    let sweep =
        reconcile_phantom_bonded_slots(&mut st, &ev, &std::collections::BTreeSet::new(), |_| {
            Ok::<_, ()>(id(3))
        })
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
    let err =
        reconcile_phantom_bonded_slots(&mut st, &ev, &std::collections::BTreeSet::new(), |slot| {
            if slot == 2 {
                Err("boom")
            } else {
                Ok(id(1))
            }
        })
        .expect_err("derivation failure propagates");
    assert_eq!(err, "boom");
    assert_eq!(st.bonded_slots, vec![1, 2], "no partial mutation on error");
    assert!(st.staking_enabled);
}

use shekyl_address::Network;
use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
use shekyl_engine_file::SafetyOverrides;
use tempfile::tempdir;

use crate::engine::{Credentials, EngineCreateParams, OpenedEngine, SoloSigner};

use crate::engine::test_support::dummy_daemon;

/// This suite's deterministic seed (multiplier 7).
fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
    crate::engine::test_support::fixed_seed(7)
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
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
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

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
