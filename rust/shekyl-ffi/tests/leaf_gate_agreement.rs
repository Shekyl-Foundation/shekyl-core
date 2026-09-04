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

    // All-zero bytes: not a valid compressed point encoding.
    out.push(("all zero", [0u8; 32]));

    // All-ones: y above the field modulus — non-canonical.
    out.push(("all ones (non-canonical y)", [0xffu8; 32]));

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

/// The suite is only meaningful if the probes actually exercise both verdicts:
/// an all-rejecting or all-accepting probe set would satisfy the implications
/// above vacuously.
#[test]
fn probe_set_exercises_both_verdicts() {
    let good = good_point();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for (_, probe) in probe_points() {
        if unsafe { shekyl_check_output_keys(probe.as_ptr(), 1) } == SHEKYL_OUTPUT_POINTS_OK {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(
        accepted > 0,
        "no probe is accepted — the gate check is vacuous"
    );
    assert!(
        rejected > 0,
        "no probe is rejected — the gate check is vacuous"
    );
    // And the known-good point must encode, or every implication above holds
    // for the wrong reason.
    assert!(construct_leaf(&good, &good, &[0u8; 32]).is_some());
}
