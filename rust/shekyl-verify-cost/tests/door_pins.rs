// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pins for the door sequence the drift gate times
//! (`benches/relay_admission_verify_iai.rs`, BA-T1).
//!
//! The gate asserts its own fixture verifies before it is timed, so a
//! fixture that stopped verifying cannot be counted. That assert is only as
//! good as [`DoorStatus`]: if a refused check could leave it reading
//! `verified()`, the gate would time a reject path and pass. So the status
//! is pinned here from both sides, under `cargo test` where CI sees it:
//!
//! 1. **Positive limb**: a fixture built by the wallet's signer and the
//!    production provers verifies in every check.
//! 2. **Negative limbs**: a forged signature is named at its input and a
//!    range proof over other commitments fails the range check, each
//!    leaving the other three checks accepting and `verified()` false.
//! 3. **Shape**: a fixture whose parts disagree on the shape is refused at
//!    construction, before anything can time it.
//! 4. **Order**: the builder asks the signer for one message per input,
//!    input 0 then input 1. The gate and the hedged tests share that order.

use std::cell::RefCell;

use rand_core::OsRng;

use shekyl_verify_cost::connect::{build_bp, build_pqc_auth};
use shekyl_verify_cost::door::{
    build_door_fixture, build_door_fixture_with, door_verify, stand_in_signed_hash, DoorFixture,
};
use shekyl_verify_cost::relay::{admission_verify, build_fixture, ChunkLayout};

/// Two inputs, so a refusal can be named at an input other than the first.
fn two_input_fixture() -> DoorFixture {
    build_door_fixture(&mut OsRng, 2, 2, 2, ChunkLayout::Spread)
}

#[test]
fn the_builder_signs_each_input_in_order() {
    let messages = RefCell::new(Vec::new());
    let fixture =
        build_door_fixture_with(&mut OsRng, 2, 2, 2, ChunkLayout::Spread, |rng, message| {
            messages.borrow_mut().push(message);
            build_pqc_auth(rng, message)
        });
    assert_eq!(
        messages.into_inner(),
        vec![stand_in_signed_hash(0), stand_in_signed_hash(1)]
    );
    assert!(
        door_verify(&fixture).verified(),
        "the signer's auths are the fixture's"
    );
}

#[test]
fn a_door_fixture_verifies_in_every_check() {
    let fixture = two_input_fixture();
    let status = door_verify(&fixture);
    assert!(status.verified(), "{status:?}");
    // The masks and the proof are the admission pair's own bodies.
    assert!(admission_verify(&fixture.adm).verified());
}

#[test]
fn a_forged_signature_is_named_at_its_input_and_nowhere_else() {
    let mut fixture = two_input_fixture();
    let last = fixture.auths[1].signature.len() - 1;
    fixture.auths[1].signature[last] ^= 0x01;
    let status = door_verify(&fixture);
    assert!(
        matches!(status.signatures, Err((1, _))),
        "the forgery is input 1's: {status:?}"
    );
    assert!(status.masks.is_ok(), "{status:?}");
    assert!(matches!(status.membership, Ok(true)), "{status:?}");
    assert!(status.range, "{status:?}");
    assert!(!status.verified());
}

#[test]
fn a_range_proof_over_other_commitments_fails_only_the_range_check() {
    let mut fixture = two_input_fixture();
    // The same two commitments in the other order: both still valid points,
    // so the proof is judged against another statement rather than refused
    // as unparseable. (`build_bp`'s commitments are fixed, so a second call
    // would hand back the same ones.)
    fixture.bp.commitments.swap(0, 1);
    let status = door_verify(&fixture);
    assert!(!status.range, "{status:?}");
    assert!(status.masks.is_ok(), "{status:?}");
    assert!(status.signatures.is_ok(), "{status:?}");
    assert!(matches!(status.membership, Ok(true)), "{status:?}");
    assert!(!status.verified());
}

#[test]
#[should_panic(expected = "one hybrid signature per input")]
fn a_signature_count_other_than_the_input_count_is_refused() {
    let adm = build_fixture(&mut OsRng, 2, 2, 2, ChunkLayout::Shared);
    let auths = vec![build_pqc_auth(&mut OsRng, stand_in_signed_hash(0))];
    let _refused = DoorFixture::new(adm, auths, build_bp(&mut OsRng, 2));
}

#[test]
#[should_panic(expected = "the range proof covers every output")]
fn a_range_proof_over_another_output_count_is_refused() {
    let adm = build_fixture(&mut OsRng, 1, 2, 2, ChunkLayout::Shared);
    let auths = vec![build_pqc_auth(&mut OsRng, stand_in_signed_hash(0))];
    let _refused = DoorFixture::new(adm, auths, build_bp(&mut OsRng, 3));
}
