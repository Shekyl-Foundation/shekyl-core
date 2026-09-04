// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-L11: the admission gates and the curve-tree leaf builder must agree.
//!
//! `blockchain_db.cpp`'s leaf collector aborts (rather than silently dropping
//! the output) when `construct_leaf` fails, on the strength of two upstream
//! gates: `shekyl_check_output_keys` behind `check_outs_valid`, and
//! `shekyl_check_commitment_masks` behind `check_commitment_mask_valid`. That
//! abort is unreachable only while *everything the gates accept, the leaf
//! builder can encode*.
//!
//! This is the falsifier for that claim. Loosening either gate — admitting a
//! non-canonical, torsioned, or identity point — turns these red here, at the
//! gate, instead of turning a live daemon into one that aborts at block
//! connect. The C++ throw itself is deliberately not the subject: it cannot be
//! reached without first breaking one of these gates.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use shekyl_fcmp::tree::construct_leaf;
use shekyl_ffi::ct_balance_ffi::{
    shekyl_check_commitment_masks, shekyl_check_output_keys, SHEKYL_OUTPUT_POINTS_OK,
};

/// Adversarial and benign 32-byte encodings, named by what they probe.
fn probe_points() -> Vec<(&'static str, [u8; 32])> {
    let mut out: Vec<(&'static str, [u8; 32])> = Vec::new();

    // The Ed25519 basepoint: canonical, prime-order, non-identity.
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    out.push(("ed25519 basepoint", basepoint));

    // Identity (the encoding of the neutral element).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    out.push(("identity", identity));

    // All-zero bytes decode fine — y = 0 is a canonical encoding of a
    // small-order point (x^2 = -1) — so this probe is rejected for TORSION,
    // not for being undecodable. Named precisely because the distinction is
    // the whole point of the gate: on-curve is not the bar, prime-order is.
    out.push(("all zero (canonical small-order)", [0u8; 32]));

    // All-ones: y above the field modulus — non-canonical.
    out.push(("all ones (non-canonical y)", [0xffu8; 32]));

    // A non-trivial prime-order point: 5*G. Without this the commitment-mask
    // gate rejects every probe — it refuses bare G and the identity as
    // amount-leaking trivial forms on top of the canonical/torsion gates — and
    // the mask implication below would hold vacuously, never once exercising
    // the accepted branch it exists to constrain.
    out.push((
        "5*G (non-trivial prime-order)",
        (ED25519_BASEPOINT_POINT * Scalar::from(5u8))
            .compress()
            .to_bytes(),
    ));

    // A small-order (torsion) point: order 8, on-curve but not prime-order.
    out.push((
        "small-order (torsion)",
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
    ));

    out
}

/// A leaf needs all three of O, Hp(O) and C to encode; hold two of them at a
/// known-good value so each case isolates the probe under test.
fn good_point() -> [u8; 32] {
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    basepoint
}

#[test]
fn output_key_gate_accepts_only_what_the_leaf_builder_encodes() {
    let good = good_point();
    for (name, probe) in probe_points() {
        let gate_ok =
            unsafe { shekyl_check_output_keys(probe.as_ptr(), 1) } == SHEKYL_OUTPUT_POINTS_OK;
        let leaf_ok = construct_leaf(&probe, &good, &[0u8; 32]).is_some();
        assert!(
            !gate_ok || leaf_ok,
            "output-key gate accepts {name}, but construct_leaf cannot encode it: \
             blockchain_db.cpp's leaf collector would abort at block connect (CEN-L11)"
        );
    }
}

#[test]
fn commitment_mask_gate_accepts_only_what_the_leaf_builder_encodes() {
    let good = good_point();
    for (name, probe) in probe_points() {
        let gate_ok =
            unsafe { shekyl_check_commitment_masks(probe.as_ptr(), 1, std::ptr::null(), 0) }
                == SHEKYL_OUTPUT_POINTS_OK;
        let leaf_ok = construct_leaf(&good, &probe, &[0u8; 32]).is_some();
        assert!(
            !gate_ok || leaf_ok,
            "commitment gate accepts {name}, but construct_leaf cannot encode it: \
             blockchain_db.cpp's leaf collector would abort at block connect (CEN-L11)"
        );
    }
}

/// The suite is only meaningful if the probes exercise both verdicts **for
/// each gate independently**: an all-rejecting probe set satisfies every
/// implication above vacuously, and the two gates do not accept the same
/// inputs — the mask gate additionally refuses bare `G` and the identity as
/// amount-leaking trivial forms, so a probe set that is non-vacuous for output
/// keys can still be all-rejecting for masks. Checking only one gate is how
/// that hole stayed open until review.
#[test]
fn probe_set_exercises_both_verdicts_for_each_gate() {
    let good = good_point();

    let mut key_accepted = 0usize;
    let mut key_rejected = 0usize;
    let mut mask_accepted = 0usize;
    let mut mask_rejected = 0usize;

    for (_, probe) in probe_points() {
        if unsafe { shekyl_check_output_keys(probe.as_ptr(), 1) } == SHEKYL_OUTPUT_POINTS_OK {
            key_accepted += 1;
        } else {
            key_rejected += 1;
        }
        if unsafe { shekyl_check_commitment_masks(probe.as_ptr(), 1, std::ptr::null(), 0) }
            == SHEKYL_OUTPUT_POINTS_OK
        {
            mask_accepted += 1;
        } else {
            mask_rejected += 1;
        }
    }

    assert!(
        key_accepted > 0,
        "no probe is accepted by the output-key gate — its implication is vacuous"
    );
    assert!(
        key_rejected > 0,
        "no probe is rejected by the output-key gate — its implication is vacuous"
    );
    assert!(
        mask_accepted > 0,
        "no probe is accepted by the commitment-mask gate — its implication is vacuous"
    );
    assert!(
        mask_rejected > 0,
        "no probe is rejected by the commitment-mask gate — its implication is vacuous"
    );

    // And the known-good point must encode, or every implication above holds
    // for the wrong reason.
    assert!(construct_leaf(&good, &good, &[0u8; 32]).is_some());
}
