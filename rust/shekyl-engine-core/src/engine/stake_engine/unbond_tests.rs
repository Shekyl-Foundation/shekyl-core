// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the Unbond bond-post producer (`engine/stake_engine/unbond.rs`).
//!
//! Wired as a `#[path]` child of `unbond::tests`, so `use super::*` resolves
//! into the producer module and private items stay testable; the sibling file
//! exists so the decomposition ratchet counts the production module, not its
//! test suite (the `stake_engine_tests.rs` / `proofs_tests.rs` pattern).

use shekyl_archival_retention::{
    HoldingsDescriptor, HoldingsKind, ShardSet, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_types::ChainCount;

use crate::engine::emission_source::{BondContext, ClaimSourceFor, EmissionClaimSource};

use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_engine_state::pscan_state::MintLineageOutput;
use shekyl_wire::{Ct, Input, Transaction};

use crate::engine::synthetic_tree::consistent_synthetic_path;

use super::super::test_fixtures::{constructed_record, derive_bundle, spawn_over};

use super::*;

/// The record-state arms are tested here as PRECONDITIONS, not as verifier
/// behaviour. Driving `verify_unbond_bond_post` into `CooldownNotElapsed`
/// would test consensus, which already covers itself; what is worth
/// asserting on this side is that the producer refuses first, so the
/// failure reaches the user at the wallet instead of at the chain.
fn ready() -> UnbondRecordState {
    UnbondRecordState {
        p_id: PCanonicalId::from_bytes([7u8; 32]),
        bonded_total_atomic: 3 * 750_000_000,
        bad_interval_count: 0,
        last_served: ServeAnchor::ServedAt(4),
        last_settled_slash: SlashWatermark::SettledThrough(4),
        // The boundary, read from the config-generated constant rather than
        // written out: a fixture that hardcodes the genesis value states the
        // cooldown a second time, and the copy is what goes stale.
        current_settlement_epoch: 4 + RELEASE_COOLDOWN_EPOCHS,
    }
}

#[test]
fn a_ready_record_passes_every_precondition() {
    ready()
        .ensure_exit_ready()
        .expect("a ready record must not be refused");
}

#[test]
fn a_full_interval_log_is_refused_with_its_bound() {
    let mut r = ready();
    r.bad_interval_count = MAX_BOND_BAD_INTERVALS;
    assert_eq!(
        r.ensure_exit_ready(),
        Err(UnbondNotReady::IntervalLogFull {
            count: MAX_BOND_BAD_INTERVALS,
            max: MAX_BOND_BAD_INTERVALS,
        })
    );
}

/// The refusal ORDER is consensus's, not a convenient one — on the exact
/// state where the two orders disagree.
///
/// `verify_unbond_bond_post` checks `NothingToUnbond` (step 3) before
/// `IntervalLogFull` (step 9). A record that is both zero-balance and
/// interval-log-full satisfies both conditions, so it is the only input
/// that can tell which order this function actually runs. Leaving the
/// zero-balance check to the builder made this state report
/// `IntervalLogFull` while the chain would say `NothingToUnbond` — a wallet
/// and a chain disagreeing about why an irreversible operation was refused.
///
/// The single-condition cases are asserted alongside, so a fix that
/// reordered into a *different* wrong order would not pass.
#[test]
fn the_refusal_order_is_the_verifiers_where_two_conditions_both_hold() {
    let mut r = ready();
    r.bonded_total_atomic = 0;
    r.bad_interval_count = MAX_BOND_BAD_INTERVALS;
    assert_eq!(
        r.ensure_exit_ready(),
        Err(UnbondNotReady::NothingToUnbond),
        "both conditions hold; the verifier names the balance first"
    );

    // Each alone still names itself, so the ordering fix did not collapse
    // one arm into the other.
    let mut only_zero = ready();
    only_zero.bonded_total_atomic = 0;
    assert_eq!(
        only_zero.ensure_exit_ready(),
        Err(UnbondNotReady::NothingToUnbond)
    );
    let mut only_full = ready();
    only_full.bad_interval_count = MAX_BOND_BAD_INTERVALS;
    assert_eq!(
        only_full.ensure_exit_ready(),
        Err(UnbondNotReady::IntervalLogFull {
            count: MAX_BOND_BAD_INTERVALS,
            max: MAX_BOND_BAD_INTERVALS,
        })
    );
}

/// The exit fee used by these tests. A real one is the canonical
/// weight-priced floor resolved engine-side; any value works here because
/// the balance rule is an equation, not a threshold.
const EXIT_FEE: u64 = 10_000;

/// Two REAL P-paid funding inputs for `slot` in one depth-consistent
/// synthetic leaf chunk — the same machinery the drain's actor tests use,
/// so these exits are **proved**, not stubbed. Without real inputs the
/// assembly would stop at the prover and never reach the auth slot, which
/// is the part with no other coverage.
fn exit_funding(slot: u32) -> (Vec<FundingInputContext>, TreeContext) {
    let keys = derive_bundle(slot);
    let (rec0, leaf0) = constructed_record(
        &keys,
        11,
        5,
        600_000,
        0,
        MintLineageOutput::ExternalTransfer,
    );
    let (rec1, leaf1) = constructed_record(
        &keys,
        22,
        6,
        400_000,
        1,
        MintLineageOutput::ExternalTransfer,
    );
    let leaf_chunk = vec![leaf0, leaf1];
    let depth = 2u8;
    let (c1_layers, c2_layers, tree_root) = consistent_synthetic_path(&leaf_chunk, depth);
    let tree_ctx = TreeContext {
        reference_block: [7u8; 32],
        tree_root,
        tree_depth: depth,
    };
    let funding = vec![
        FundingInputContext {
            record: rec0,
            leaf_chunk: leaf_chunk.clone(),
            c1_layers: c1_layers.clone(),
            c2_layers: c2_layers.clone(),
        },
        FundingInputContext {
            record: rec1,
            leaf_chunk,
            c1_layers,
            c2_layers,
        },
    ];
    (funding, tree_ctx)
}

/// The handler refuses a record fetched for a different persona.
///
/// This is the arm the constructor cannot cover. `ClaimSourceFor` proves the
/// facts describe the persona they were *fetched* for; only the handler can
/// prove that persona is the one whose *handle* is being spent, because the
/// handle is a separate value arriving on the same message. Driving it
/// through the actor is the only way the two meet.
///
/// The positive control matters as much as the refusal: a record fetched for
/// the handle's own persona must get **past** this check. Without it the test
/// would still pass if the handler refused everything, which is the failure
/// mode a binding check is most likely to have.
#[tokio::test]
async fn a_record_read_for_another_persona_is_refused_at_the_actor() {
    let slot = 3u32;
    let stake = spawn_over(&[slot], &[], Some(slot));
    let p_slot = PSlot::from_raw(slot);
    // Two identical draws rather than a clone: `FundingInputContext` is
    // deliberately not `Clone` (a funding set is a reservation, not a value
    // to duplicate), so each attempt gets its own.
    let (funding, tree_ctx) = exit_funding(slot);

    // A record that is ready in every respect EXCEPT whose persona it
    // describes, so a refusal can only be the binding check.
    let ready_source = || EmissionClaimSource {
        chain_height: ChainCount::from_raw(30001),
        current_settled_epoch: 4 + RELEASE_COOLDOWN_EPOCHS,
        bond: Some(BondContext {
            join_settlement_epoch: 1,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![4]).expect("one shard"),
            },
            claimed_settlement_epochs: vec![1],
            bonded_total_atomic: 3 * 750_000_000,
            bad_interval_count: 0,
            last_served: ServeAnchor::ServedAt(4),
            last_settled_slash: SlashWatermark::SettledThrough(4),
        }),
        epochs: vec![],
    };

    // Someone else's record, honestly fetched for THEM.
    let stranger = PCanonicalId::from_bytes([0xEE; 32]);
    let theirs = ClaimSourceFor::for_test(stranger, ready_source());
    let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
    let err = stake
        .assemble_unbond(AssembleUnbond {
            handle,
            record: UnbondRecordState::from_claim_source(&theirs).expect("bond record"),
            funding,
            tree_ctx: tree_ctx.clone(),
            fee: EXIT_FEE,
        })
        .await
        .expect_err("a record read for another persona must not build this exit");
    assert!(
        matches!(err, StakeEngineError::RecordPersonaMismatch),
        "expected RecordPersonaMismatch, got {err:?}"
    );

    // Positive control: the same record, fetched for THIS persona, clears
    // the binding check and assembles.
    let mine = stake
        .persona_canonical_id(p_slot)
        .await
        .expect("project this persona's canonical id");
    let ours = ClaimSourceFor::for_test(mine, ready_source());
    let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
    let (funding, _) = exit_funding(slot);
    let post = stake
        .assemble_unbond(AssembleUnbond {
            handle,
            record: UnbondRecordState::from_claim_source(&ours).expect("bond record"),
            funding,
            tree_ctx,
            fee: EXIT_FEE,
        })
        .await
        .expect("this persona's own record assembles");
    assert_eq!(post.funding_gindexes.len(), 2);
    let mut cursor: &[u8] = post.bound_tx.bytes();
    Transaction::read(&mut cursor).expect("assembled bytes parse whole");
}

/// An exit assembled with **no funding inputs** is refused by name, not by
/// the prover.
///
/// A bond post carries at least one real `txin_to_key` spend input —
/// `bond_post_funding_floor_met`, which the handler calls rather than
/// restating, and which the daemon still decides in its own C++ copy
/// ("Archival bond-post tx requires at least one txin_to_key funding
/// input"). Consensus binds it *after* `check_archival_bond_post_input` and
/// *before* every amount rule (pseudoOuts count, reference block, balance);
/// the handler's call sits in the same place — after the record-state arms,
/// before the funding arithmetic — so the wallet and the chain cannot
/// disagree about why the exit was refused, and a caller who also got the
/// fee wrong is told about the missing input first, exactly as a node would.
///
/// Nothing else on the wallet side catches this state, which is why the
/// guard is not redundant with the checks around it: the sufficiency test
/// compares `funding_total + bond_debit` against the fee and released
/// collateral alone clears it, and `verify_debit_funding` closes
/// tautologically because the outputs are derived from that same `sources`
/// term. Before the guard the refusal arrived from inside the prover as
/// `Build { stage: "proving" }` wrapping `TxBuilderError::NoInputs` —
/// naming the pipeline stage where a condition belongs.
///
/// The positive control is the sibling actor tests: both assemble an
/// equivalently ready record with two real funding inputs from the same
/// fixture, so a guard that refused everything would take them red.
#[tokio::test]
async fn an_exit_with_no_funding_inputs_is_refused_by_name() {
    let slot = 7u32;
    let stake = spawn_over(&[slot], &[], Some(slot));
    let p_slot = PSlot::from_raw(slot);
    // The paths are drawn and then dropped: a tree context is still needed
    // to form the message, and building it the ordinary way keeps the only
    // difference from an assembling exit the funding vector itself.
    let (_, tree_ctx) = exit_funding(slot);

    // Ready in every respect except the funding, and bound to THIS handle's
    // persona so step 3 cannot be what refuses.
    let mine = stake
        .persona_canonical_id(p_slot)
        .await
        .expect("project this persona's canonical id");
    let record = UnbondRecordState {
        p_id: mine,
        ..ready()
    };

    let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
    let err = stake
        .assemble_unbond(AssembleUnbond {
            handle,
            record,
            funding: vec![],
            tree_ctx,
            fee: EXIT_FEE,
        })
        .await
        .expect_err("an exit with no funding input must not assemble");
    assert!(
        matches!(
            err,
            StakeEngineError::Assembly(BondAssemblyError::FundingInputsRequired)
        ),
        "expected FundingInputsRequired, got {err:?}"
    );
}

/// **The exit authorizes under `bond_spend_pk` — never the identity key.**
///
/// This is the one place an `Unbond` diverges from every credit post, and
/// with the regtest walk landing in its own PR, nothing else in this
/// repository exercises it. `archival_debit_auth_pin`
/// (`src/cryptonote_core/blockchain.cpp`) rejects a debit whose `pqc_auths`
/// slot key is not the record's COMMITTED `bond_spend_pk`, and names the
/// identity key as forbidden by construction — a compromised serving host
/// holds `hybrid_sign_sk` and could otherwise authorize a
/// collateral-draining exit. There is no Rust arm of that pin to call
/// against, so the assertion is made on the assembled bytes.
///
/// **Both halves are load-bearing, and so is the third.** "Equals
/// `bond_spend_pk`" alone would pass if the two keys happened to be the
/// same value; "differs from the identity key" alone would pass for any
/// unrelated third key. Asserting first that the two keys genuinely DIFFER
/// is what makes the pair a discriminant rather than two agreeable facts.
///
/// The slot INDEX is asserted too, because the pin reads one specific slot:
/// consensus indexes `tx.pqc_auths[archival_bond_post_index]`, and
/// `pqc_auths` has no length prefix — its count is `nvin`. A correct key in
/// the wrong slot authorizes nothing.
#[tokio::test]
async fn the_exit_authorizes_under_bond_spend_pk_never_the_identity_key() {
    let slot = 5u32;
    let stake = spawn_over(&[slot], &[], Some(slot));
    let p_slot = PSlot::from_raw(slot);
    let (funding, tree_ctx) = exit_funding(slot);

    let mine = stake
        .persona_canonical_id(p_slot)
        .await
        .expect("project this persona's canonical id");
    let ours = ClaimSourceFor::for_test(
        mine,
        EmissionClaimSource {
            chain_height: ChainCount::from_raw(30001),
            current_settled_epoch: 4 + RELEASE_COOLDOWN_EPOCHS,
            bond: Some(BondContext {
                join_settlement_epoch: 1,
                holdings: HoldingsDescriptor {
                    kind: HoldingsKind::ShardSetCompact,
                    shard_ids: ShardSet::new(vec![4]).expect("one shard"),
                },
                claimed_settlement_epochs: vec![1],
                bonded_total_atomic: 3 * 750_000_000,
                bad_interval_count: 0,
                last_served: ServeAnchor::ServedAt(4),
                last_settled_slash: SlashWatermark::SettledThrough(4),
            }),
            epochs: vec![],
        },
    );
    let handle = stake.mint_handle(p_slot).await.expect("mint a handle");
    let post = stake
        .assemble_unbond(AssembleUnbond {
            handle,
            record: UnbondRecordState::from_claim_source(&ours).expect("bond record"),
            funding,
            tree_ctx,
            fee: EXIT_FEE,
        })
        .await
        .expect("the exit assembles");

    let mut cursor: &[u8] = post.bound_tx.bytes();
    let tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");

    // The slot the pin reads: the bond post's own index in `vin`.
    let Ct::Fcmp { ref pqc_auths, .. } = tx.ct else {
        panic!("an assembled exit is an FCMP transaction")
    };
    assert_eq!(
        pqc_auths.len(),
        tx.prefix.inputs.len(),
        "pqc_auths is index-parallel with vin (no length prefix; count is nvin)"
    );
    let bond_idx = tx
        .prefix
        .inputs
        .iter()
        .position(|i| matches!(i, Input::BondPost(_)))
        .expect("the assembled exit carries a bond-post input");
    let Some(Input::BondPost(bond)) = tx.prefix.inputs.get(bond_idx) else {
        unreachable!("position matched BondPost")
    };

    let keys = derive_bundle(slot);
    let bond_spend_pk = keys
        .bond_spend_pk
        .to_canonical_bytes()
        .expect("bond_spend_pk encodes");
    let identity_pk = &bond.hybrid_public_key;

    // The discriminant is only a discriminant if the two keys differ.
    assert_ne!(
        &bond_spend_pk, identity_pk,
        "GF-1 assumes distinct identity and debit-authorizer keys; if these \
         ever coincide the assertions below stop discriminating"
    );

    let auth = &pqc_auths[bond_idx];
    assert_eq!(
        &auth.hybrid_public_key, &bond_spend_pk,
        "the debit auth slot must carry the record's committed bond_spend_pk"
    );
    assert_ne!(
        &auth.hybrid_public_key, identity_pk,
        "the identity key never authorizes a value-out (archival_debit_auth_pin)"
    );
    // …and the signature was made with the SECRET half of that key.
    //
    // Without this the pair above is not enough: publishing
    // `bond_spend_pk` while signing with `hybrid_sign_sk` satisfies every
    // key assertion and is rejected by every node. The mutation the auth
    // slot is most likely to suffer is a one-token swap in the signing
    // call, and only verification is on that axis.
    //
    // `pqc_signing_payload_hashes` is the same method the daemon's
    // `verify_pqc_auths` calls, under the same domain — so this is the real
    // check over the real bytes, not a restatement of what the handler did.
    let payload_hashes = tx.pqc_signing_payload_hashes();
    assert_eq!(payload_hashes.len(), pqc_auths.len());
    let pk = HybridPublicKey::from_canonical_bytes(&auth.hybrid_public_key)
        .expect("the auth slot carries a canonical hybrid public key");
    let sig = HybridSignature::from_canonical_bytes(&auth.hybrid_signature)
        .expect("the auth slot carries a canonical hybrid signature");
    HybridEd25519MlDsa
        .verify(
            &pk,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_PQC_AUTH_TX,
            &payload_hashes[bond_idx],
            &sig,
        )
        .expect("the debit auth must verify under bond_spend_pk");
}

/// A record read for one persona cannot be spent through another's handle.
///
/// The constructor is what makes this hard to get wrong — record facts and
/// the settled epoch come from one response together — but the binding
/// itself is the handler's equality check, because the handle is a separate
/// value that arrives on the same message. This asserts the id survives
/// construction so that check has something true to compare; the handler's
/// refusal is exercised where the actor is driven.
#[test]
fn the_record_carries_the_persona_it_was_read_for() {
    let want = PCanonicalId::from_bytes([0xA5; 32]);
    let source = EmissionClaimSource {
        chain_height: ChainCount::from_raw(30001),
        current_settled_epoch: 3,
        bond: Some(BondContext {
            join_settlement_epoch: 1,
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: ShardSet::new(vec![4]).expect("one shard"),
            },
            claimed_settlement_epochs: vec![1],
            bonded_total_atomic: 2_250_000_000,
            bad_interval_count: 1,
            last_served: ServeAnchor::ServedAt(4),
            last_settled_slash: SlashWatermark::SettledThrough(4),
        }),
        epochs: vec![],
    };
    let fetched = ClaimSourceFor::for_test(want, source);
    let state =
        UnbondRecordState::from_claim_source(&fetched).expect("the response carries a bond record");
    assert_eq!(state.p_id(), want);
    assert_ne!(state.p_id(), PCanonicalId::from_bytes([0x5A; 32]));
    // Every fact came from this one response, including the settled epoch
    // the anchors are judged against.
    assert_eq!(state.bonded_total_atomic(), 2_250_000_000);
    assert_eq!(state.bad_interval_count, 1);
    assert_eq!(state.current_settlement_epoch, 3);
}

/// No bond record is "nothing to assess", not an error: the caller reports
/// it rather than refusing with a cause that would imply a record exists.
#[test]
fn a_response_without_a_bond_record_yields_no_state() {
    let source = EmissionClaimSource {
        chain_height: ChainCount::from_raw(30001),
        current_settled_epoch: 3,
        bond: None,
        epochs: vec![],
    };
    let fetched = ClaimSourceFor::for_test(PCanonicalId::from_bytes([1; 32]), source);
    assert!(UnbondRecordState::from_claim_source(&fetched).is_none());
}

/// Epoch 0 is a real settlement epoch, and this is the refusal that proves
/// the error reports the anchor it was given rather than a stand-in for it.
///
/// The arm is only reachable for a served record, which invites deriving
/// the epoch from that reasoning instead of carrying it — an `Option`
/// unwrapped to its default. That renders a record served at epoch 0 and a
/// record with no anchor at all as the same `0`, and the second is the
/// *permissive* state: the message would name the absence of the condition
/// that is in fact blocking the exit. So this asserts the rendering too,
/// not just the variant — the collapse lives in the string, not the shape.
#[test]
fn a_record_served_at_epoch_zero_is_refused_by_its_own_anchor() {
    // Premise, from consensus's own predicate rather than restated here: an
    // exit at the very epoch a record served is inside the cooldown.
    assert!(
        !release_cooldown_elapsed(Some(0), 0),
        "premise: the serving epoch itself is not past the cooldown"
    );
    let mut r = ready();
    r.last_served = ServeAnchor::ServedAt(0);
    r.last_settled_slash = SlashWatermark::SettledThrough(0);
    r.current_settlement_epoch = 0;

    let err = r
        .ensure_exit_ready()
        .expect_err("a record inside its cooldown must be refused");
    assert_eq!(
        err,
        UnbondNotReady::CooldownNotElapsed {
            last_served: ServeAnchor::ServedAt(0),
            current_settlement_epoch: 0,
        }
    );
    let rendered = err.to_string();
    assert!(rendered.contains("last served epoch 0"), "{rendered}");
    assert!(
        !rendered.contains("never"),
        "a record served at epoch 0 must not read as never served: {rendered}"
    );
}

/// One epoch short of the boundary is refused; the boundary itself is not.
/// Asserting both sides is what makes this a boundary test rather than a
/// test that any old value fails.
#[test]
fn the_cooldown_boundary_is_refused_below_and_allowed_at() {
    let mut r = ready();
    // Both sides derived from the constant for the reason `ready()` gives:
    // the boundary is `anchor + RELEASE_COOLDOWN_EPOCHS`, and writing 5 and
    // 6 restates the genesis cooldown in a third place.
    let boundary = 4 + RELEASE_COOLDOWN_EPOCHS;
    r.current_settlement_epoch = boundary - 1;
    assert_eq!(
        r.ensure_exit_ready(),
        Err(UnbondNotReady::CooldownNotElapsed {
            last_served: ServeAnchor::ServedAt(4),
            current_settlement_epoch: boundary - 1,
        })
    );
    r.current_settlement_epoch = boundary;
    r.ensure_exit_ready()
        .expect("the boundary epoch itself is elapsed");
}

/// Slash settlement is a separate gate from the cooldown and is NOT implied
/// by it: this record's cooldown has elapsed and it is still refused,
/// because the scheduler has not folded the anchor epoch. That is the
/// one-block connect-ordering race the second predicate closes.
#[test]
fn slash_settlement_is_checked_even_when_the_cooldown_has_elapsed() {
    let mut r = ready();
    r.last_settled_slash = SlashWatermark::SettledThrough(3);
    assert!(release_cooldown_elapsed(
        r.last_served.as_verify_operand(),
        r.current_settlement_epoch
    ));
    assert_eq!(
        r.ensure_exit_ready(),
        Err(UnbondNotReady::SlashSettlementPending {
            last_served: ServeAnchor::ServedAt(4),
            watermark: SlashWatermark::SettledThrough(3),
        })
    );
}

/// A watermark of "nothing settled yet" refuses a served record — the one
/// operand whose absence is restrictive rather than permissive. A shared
/// "absent" encoding across both anchors would have made this permissive by
/// construction, which is why they are separate types.
#[test]
fn an_unsettled_scheduler_refuses_a_served_record() {
    let mut r = ready();
    r.last_settled_slash = SlashWatermark::NothingSettled;
    assert_eq!(
        r.ensure_exit_ready(),
        Err(UnbondNotReady::SlashSettlementPending {
            last_served: ServeAnchor::ServedAt(4),
            watermark: SlashWatermark::NothingSettled,
        })
    );
}

/// A never-served record exits immediately: both predicates are vacuous,
/// and the watermark being absent does not matter because there is no
/// anchor to cover. The permissive branch is correct when the daemon
/// asserts it — the producer must not be fail-closed on a fact not in
/// doubt.
#[test]
fn a_never_served_record_is_ready_regardless_of_the_watermark() {
    let mut r = ready();
    r.last_served = ServeAnchor::NeverServed;
    r.last_settled_slash = SlashWatermark::NothingSettled;
    r.current_settlement_epoch = 0;
    r.ensure_exit_ready()
        .expect("nothing served means nothing whose settlement an exit could outrun");
}
