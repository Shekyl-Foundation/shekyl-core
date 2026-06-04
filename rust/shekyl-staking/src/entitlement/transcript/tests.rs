// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Locks the entitlement FS challenge preimage **field set and order**
//! (§6.4.1 decision 3). These are the anti-splicing invariants: every public
//! input — and `μ_claim` — is absorbed, at a fixed offset, so the prover and
//! the C++/FFI verifier cannot drift on what is hashed.

use super::*;

/// Build inputs with each field filled by a distinct byte, so the byte at any
/// position reveals which field it belongs to.
fn distinct_inputs() -> EntitlementChallengeInputs {
    EntitlementChallengeInputs {
        g: [0x01; FIELD_LEN],
        h: [0x02; FIELD_LEN],
        n_le: [0x03; FIELD_LEN],
        d_le: [0x04; FIELD_LEN],
        c_tilde: [0x05; FIELD_LEN],
        c_claim: [0x06; FIELD_LEN],
        c_rho: [0x07; FIELD_LEN],
        r: [0x08; FIELD_LEN],
        mu_claim: [0x09; FIELD_LEN],
    }
}

#[test]
fn preimage_length_is_domain_plus_nine_fields() {
    let p = distinct_inputs().preimage();
    assert_eq!(p.len(), PREIMAGE_LEN);
    assert_eq!(PREIMAGE_LEN, ENTITLEMENT_FS_DOMAIN.len() + 9 * 32);
}

#[test]
fn domain_separator_prefixes_the_preimage() {
    let p = distinct_inputs().preimage();
    assert_eq!(&p[..ENTITLEMENT_FS_DOMAIN.len()], ENTITLEMENT_FS_DOMAIN);
}

#[test]
fn domain_is_distinct_from_reserve_dleq() {
    // Sharing a transcript domain across two statements is a soundness footgun
    // (§6.4.1). The entitlement must not reuse the reserve-DLEQ string.
    assert_ne!(ENTITLEMENT_FS_DOMAIN, b"shekyl-reserve-proof-dleq-v1");
    assert_eq!(ENTITLEMENT_FS_DOMAIN, b"shekyl-stake-entitlement-v1");
}

/// The consensus-critical KAT: each field lands at its documented offset, in
/// the pinned order `G, H, N_le, D_le, C~, C_claim, C_ρ, R, μ_claim`.
#[test]
fn every_field_lands_at_its_documented_offset() {
    let inp = distinct_inputs();
    let p = inp.preimage();
    let field = |off: usize| &p[off..off + FIELD_LEN];

    assert_eq!(field(offset::G), &inp.g);
    assert_eq!(field(offset::H), &inp.h);
    assert_eq!(field(offset::N_LE), &inp.n_le);
    assert_eq!(field(offset::D_LE), &inp.d_le);
    assert_eq!(field(offset::C_TILDE), &inp.c_tilde);
    assert_eq!(field(offset::C_CLAIM), &inp.c_claim);
    assert_eq!(field(offset::C_RHO), &inp.c_rho);
    assert_eq!(field(offset::R), &inp.r);
    assert_eq!(field(offset::MU_CLAIM), &inp.mu_claim);

    // Offsets are contiguous and exhaust the preimage.
    assert_eq!(offset::MU_CLAIM + FIELD_LEN, PREIMAGE_LEN);
}

/// Perturbing **any** field — generators, public scalars, the three
/// commitments, the nonce, or the binding root — changes the preimage, and only
/// within that field's 32-byte window. This is the anti-splicing property at
/// the serialization layer: no field is droppable or ignorable.
#[test]
fn every_field_is_load_bearing() {
    let base = distinct_inputs();
    let base_p = base.preimage();

    let perturbations: [(usize, EntitlementChallengeInputs); 9] = [
        (
            offset::G,
            EntitlementChallengeInputs {
                g: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::H,
            EntitlementChallengeInputs {
                h: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::N_LE,
            EntitlementChallengeInputs {
                n_le: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::D_LE,
            EntitlementChallengeInputs {
                d_le: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::C_TILDE,
            EntitlementChallengeInputs {
                c_tilde: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::C_CLAIM,
            EntitlementChallengeInputs {
                c_claim: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::C_RHO,
            EntitlementChallengeInputs {
                c_rho: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::R,
            EntitlementChallengeInputs {
                r: [0xAA; FIELD_LEN],
                ..base
            },
        ),
        (
            offset::MU_CLAIM,
            EntitlementChallengeInputs {
                mu_claim: [0xAA; FIELD_LEN],
                ..base
            },
        ),
    ];

    for (off, perturbed) in perturbations {
        let p = perturbed.preimage();
        assert_ne!(p, base_p, "field at offset {off} must affect the preimage");
        // The change is confined to that field's window.
        assert_eq!(&p[..off], &base_p[..off]);
        assert_eq!(&p[off + FIELD_LEN..], &base_p[off + FIELD_LEN..]);
    }
}

/// `μ_claim = signable_tx_hash` is the shared binding root: a claim that differs
/// only in its nullifier set / outputs / root has a different `μ_claim`, hence a
/// different entitlement challenge preimage — the spliced-entitlement rejection
/// (§6.4.1 decision 3 anti-splice argument), reduced to bytes.
#[test]
fn mu_claim_distinguishes_otherwise_identical_claims() {
    let claim_a = distinct_inputs();
    let claim_b = EntitlementChallengeInputs {
        mu_claim: [0xFE; FIELD_LEN],
        ..claim_a
    };
    assert_ne!(claim_a.preimage(), claim_b.preimage());
}
