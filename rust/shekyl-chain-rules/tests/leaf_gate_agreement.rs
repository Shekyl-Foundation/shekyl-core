// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-L11: the admission gates and the curve-tree leaf builder must agree.
//!
//! The drain that grows the curve tree (`shekyl-chain-rules` `drain.rs`)
//! halts the writer (`Corrupt::LeafNotConstructible`) rather than silently
//! dropping an output when `construct_leaf` refuses a recorded output's
//! points, on the strength of two upstream gates every admitted transaction
//! passed: CEN-H7 (`shekyl_ct_balance::check_output_keys`, `rules/tx.rs`) over
//! the output keys, and CEN-H17 (`shekyl_ct_balance::check_commitment_masks`)
//! over the commitment masks. That halt is unreachable only while
//! *everything the gates accept, the leaf builder can encode*.
//!
//! This is the falsifier for that claim. Loosening either gate — admitting a
//! non-canonical, torsioned, or identity point — turns these red here, at the
//! gate, instead of turning a live daemon into one that halts at block
//! connect. The halt itself is deliberately not the subject: it cannot be
//! reached without first breaking one of these gates. The calls are the
//! bodies H7 and H17 run, on one output of a spend (`MaskSubject::Spend`).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use shekyl_ct_balance::{check_commitment_masks, check_output_keys, MaskSubject};
use shekyl_fcmp::tree::construct_leaf;

/// CEN-H7's body over one output key.
fn output_key_gate_accepts(key: &[u8; 32]) -> bool {
    check_output_keys(key).is_ok()
}

/// CEN-H17's body over one spend output's commitment mask.
fn mask_gate_accepts(mask: &[u8; 32]) -> bool {
    check_commitment_masks(mask, 1, MaskSubject::Spend).is_ok()
}

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

/// A leaf needs O, C and the output's `0x07` commitment point CM to encode
/// (`Hp(O)` is derived from O); hold two of them at a known-good value so each
/// case isolates the probe under test.
fn good_point() -> [u8; 32] {
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    basepoint
}

#[test]
fn output_key_gate_accepts_only_what_the_leaf_builder_encodes() {
    let good = good_point();
    for (name, probe) in probe_points() {
        let gate_ok = output_key_gate_accepts(&probe);
        // The third argument is the output's `0x07` commitment point (PL-D3,
        // the leaf's 4th scalar), gated separately by the content rule; a
        // known-good point isolates this gate.
        let leaf_ok = construct_leaf(&probe, &good, &good).is_ok();
        assert!(
            !gate_ok || leaf_ok,
            "output-key gate accepts {name}, but construct_leaf cannot encode it: \
             the drain would halt the writer at block connect (CEN-L11)"
        );
    }
}

#[test]
fn commitment_mask_gate_accepts_only_what_the_leaf_builder_encodes() {
    let good = good_point();
    for (name, probe) in probe_points() {
        let gate_ok = mask_gate_accepts(&probe);
        let leaf_ok = construct_leaf(&good, &probe, &good).is_ok();
        assert!(
            !gate_ok || leaf_ok,
            "commitment gate accepts {name}, but construct_leaf cannot encode it: \
             the drain would halt the writer at block connect (CEN-L11)"
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
        if output_key_gate_accepts(&probe) {
            key_accepted += 1;
        } else {
            key_rejected += 1;
        }
        if mask_gate_accepts(&probe) {
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
    assert!(construct_leaf(&good, &good, &good).is_ok());
}
