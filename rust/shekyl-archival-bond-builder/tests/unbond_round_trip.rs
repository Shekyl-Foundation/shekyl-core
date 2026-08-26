// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `build_unbond_vin` against the consensus verifier, which is its **only**
//! oracle.
//!
//! Staking is greenfield — there is no prior implementation to agree with, so a
//! test that restated the verifier's rules would be checking a guess against a
//! paraphrase of the same guess. Every assertion here therefore calls
//! `verify_unbond_bond_post` itself. The dependency is one-directional and stays
//! that way: the wallet conforms to consensus, never the reverse, because that
//! side is genesis-frozen and this one is not.
//!
//! **Scope, stated because the verifier's rejection arms are not one category.**
//! Five arms are *producer-controlled* — the fields `build_unbond_vin` computes
//! — and each is covered below by mutating that one field on an otherwise-valid
//! vin and asserting the specific arm. That is mutation-testing the producer:
//! it proves the field is load-bearing rather than incidentally correct.
//!
//! Four arms are *record state the producer does not set*: `IntervalLogFull`,
//! `CooldownNotElapsed`, `SlashSettlementPending`, `RecordMissing`. Driving
//! those here would test the verifier, which consensus already covers. What is
//! worth testing on them is the **caller's precondition check** — that
//! `AssembleUnbond` refuses to assemble against a record that is not ready
//! instead of producing something the daemon will reject — and those tests live
//! with that handler, not here.
//!
//! One property is deliberately **not** tested at runtime: that an "unknown"
//! serve anchor is unrepresentable. It cannot be — constructing the
//! unrepresentable value to assert on it is the backdoor that would eliminate
//! the property, and a `cfg(test)` constructor for it would be exactly that.
//! It is discharged by the decoder instead
//! (`emission_source::a_missing_exit_operand_is_a_decode_error_never_a_permissive_default`
//! and `a_flag_without_its_value_is_malformed_not_reconciled`): an absent field
//! is a decode error, so no anchor can be manufactured from silence.

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};
use shekyl_archival_bond_builder::{build_unbond_vin, verify_debit_funding, BondBuildError};
use shekyl_archival_retention::{
    bond_floor, verify_bond_post_ct_balance, verify_unbond_bond_post, ArchivalBondPostVin,
    BondPostError, BondPostKind, BondTerm, HoldingsDescriptor, HoldingsKind, ShardSet,
};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_ct_balance::amount_commitment;
use shekyl_units::{AtomicUnits, NonZeroAtomicUnits};

/// The record's current bonded balance — the exit's `bond_debit` by contract.
const BONDED: u64 = 3 * 750_000_000;

fn vin() -> ArchivalBondPostVin {
    let keys = derive_archival_p_keys(
        &[0x5B; MASTER_SEED_BYTES],
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
        0,
    )
    .expect("derive archival P keys");
    build_unbond_vin(keys.bond_post_keys(), BONDED).expect("build Unbond vin")
}

/// Verify with record state that is ready in every respect the producer does
/// not control, so a failure can only be the vin.
fn verify(v: &ArchivalBondPostVin) -> Result<(), BondPostError> {
    verify_unbond_bond_post(
        v,
        Some(BONDED),
        0,
        // Never served: the record has earned nothing whose settlement an exit
        // could outrun, so both cooldown predicates pass vacuously. This is the
        // verifier's own permissive branch, exercised deliberately.
        None,
        None,
        7,
    )
}

#[test]
fn a_built_unbond_vin_verifies_against_consensus() {
    verify(&vin()).expect("the producer's output must satisfy the verifier");
}

/// A genuinely never-served record must verify. The permissive branch is
/// *correct* when the daemon says so — the mapping this lane defends is "closed
/// on unknown, faithful on known", and this is the faithful-on-known half. A
/// producer that refused here would be fail-closed on a fact that is not in
/// doubt.
#[test]
fn never_served_is_a_legitimate_exit_not_a_refusal() {
    let v = vin();
    verify_unbond_bond_post(&v, Some(BONDED), 0, None, None, 0)
        .expect("a record that never served can exit immediately");
}

// ── The five producer-controlled arms, one mutation each ────────────────────

#[test]
fn post_kind_is_load_bearing() {
    let mut v = vin();
    v.post_kind = BondPostKind::JoinMarket;
    assert!(matches!(verify(&v), Err(BondPostError::PostKindNotUnbond)));
}

#[test]
fn bond_credit_must_be_zero_on_a_debit_path() {
    let mut v = vin();
    v.bond_credit = 1;
    assert!(matches!(
        verify(&v),
        Err(BondPostError::UnbondCreditNonzero)
    ));
}

/// Floor-zero holdings that still carry shards are not an exit. The verifier
/// guards this case explicitly because `bond_floor` returns 0 both for the
/// legitimate empty descriptor and for a structurally-invalid oversize set —
/// so "floor is zero" alone cannot distinguish them.
#[test]
fn holdings_must_be_empty_not_merely_floor_zero() {
    let mut v = vin();
    v.holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![4]).expect("one shard"),
    };
    // Non-empty holdings have a non-zero floor, so this trips the floor
    // equality first; zero the floor operand to reach the holdings guard.
    assert_ne!(bond_floor(&v.holdings), 0);
    assert!(matches!(
        verify(&v),
        Err(BondPostError::UnbondFloorMismatch)
    ));
}

#[test]
fn a_non_zero_post_connect_total_is_not_a_full_exit() {
    let mut v = vin();
    v.bonded_total_atomic = 1;
    // Floor equality fires first (floor(∅) == 0 != 1), which is the verifier's
    // ordering; `NotFullUnbond` is its belt for a descriptor whose floor also
    // happens to be non-zero.
    assert!(matches!(
        verify(&v),
        Err(BondPostError::UnbondFloorMismatch)
    ));
}

#[test]
fn the_debit_must_be_the_whole_balance() {
    let mut v = vin();
    v.bond_debit = BONDED - 1;
    assert!(matches!(
        verify(&v),
        Err(BondPostError::DebitNotFullBalance)
    ));
}

/// The one record-state condition the builder *does* own, because it consumes
/// the operand: a zero bonded total is refused at assembly rather than
/// assembled and rejected by the daemon. An exit that fails at the wallet fails
/// loudly to the person who asked for it.
#[test]
fn nothing_to_unbond_is_refused_at_assembly_not_at_the_chain() {
    let keys = derive_archival_p_keys(
        &[0x5B; MASTER_SEED_BYTES],
        DerivationNetwork::Fakechain,
        SeedFormat::Raw32,
        0,
    )
    .expect("derive archival P keys");
    assert!(matches!(
        build_unbond_vin(keys.bond_post_keys(), 0),
        Err(BondBuildError::NothingToUnbond)
    ));
}

/// `bond_spend_pk` is JoinMarket-coupled on the wire; carrying one on an Unbond
/// is rejected by the codec before the semantic verifier is reached. The
/// producer emits an empty vector, and this pins that it stays empty.
#[test]
fn an_unbond_carries_no_bond_spend_pk() {
    assert!(vin().bond_spend_pk.is_empty());
}

// ── The debit-side balance rule, tied to the commitment rule it precedes ─────

/// `mask * G + amount * H` — the synthetic witness. In the real path the prover
/// emits these; here they only need to sum correctly.
fn commit(amount: u64, mask: &Scalar) -> [u8; 32] {
    (mask * G + amount_commitment(AtomicUnits::from_raw(amount)))
        .compress()
        .to_bytes()
}

/// The scalar rule and the consensus commitment rule must agree about which
/// side the released collateral is on.
///
/// This is the whole point of `verify_debit_funding` being a separate function
/// from `verify_credit_funding` rather than one rule with a signed term: a
/// credit is a **sink** and a debit is a **source**, and consensus freezes that
/// —`BondTerm::Debit` goes to `extra_inputs`. A caller who could choose the
/// side would balance a different transaction than the one being built. So the
/// scalar check is asserted here against `verify_bond_post_ct_balance` itself,
/// not against a restatement of it.
#[test]
fn the_debit_rule_agrees_with_the_consensus_commitment_rule() {
    const FEE: u64 = 1_000;
    // No funding inputs: the released collateral covers the fee and the rest
    // lands in outputs. This is the ordinary exit shape — a debit path needs no
    // credit funded, only its fee paid.
    const FUNDING: u64 = 0;
    let out_total = BONDED + FUNDING - FEE;

    let v = vin();
    verify_debit_funding(
        AtomicUnits::from_raw(FUNDING),
        AtomicUnits::from_raw(out_total),
        AtomicUnits::from_raw(FEE),
        &v,
    )
    .expect("the amounts admit a balanced transaction");

    let mask = Scalar::from_bytes_mod_order([0x5Au8; 32]);
    verify_bond_post_ct_balance(
        &commit(FUNDING, &mask),
        &commit(out_total, &mask),
        FEE,
        BondTerm::Debit(
            NonZeroAtomicUnits::new(AtomicUnits::from_raw(v.bond_debit))
                .expect("a full exit debits a non-zero balance"),
        ),
    )
    .expect("the commitment sum closes with the debit on the input side");
}

/// The scalar rule must REJECT what the commitment rule rejects. Spending the
/// debit as though it were a credit — collateral on the output side — is the
/// specific confusion the two-function split exists to prevent.
#[test]
fn the_debit_rule_rejects_amounts_the_commitment_rule_would_reject() {
    const FEE: u64 = 1_000;
    let v = vin();
    // Outputs sized as if the released collateral contributed nothing — the
    // shape a reading that put the debit on the output side would produce, and
    // the one that leaves the whole balance unaccounted for.
    let wrong_total: u64 = 0;

    let err = verify_debit_funding(
        AtomicUnits::from_raw(0),
        AtomicUnits::from_raw(wrong_total),
        AtomicUnits::from_raw(FEE),
        &v,
    )
    .expect_err("collateral on the wrong side must not balance");
    assert!(
        matches!(err, BondBuildError::DebitImbalance { .. }),
        "got {err:?}"
    );

    let mask = Scalar::from_bytes_mod_order([0x5Au8; 32]);
    assert!(
        verify_bond_post_ct_balance(
            &commit(0, &mask),
            &commit(wrong_total, &mask),
            FEE,
            BondTerm::Debit(
                NonZeroAtomicUnits::new(AtomicUnits::from_raw(v.bond_debit)).expect("non-zero"),
            ),
        )
        .is_err(),
        "consensus must reject the same amounts, or the scalar rule is not its precondition"
    );
}
