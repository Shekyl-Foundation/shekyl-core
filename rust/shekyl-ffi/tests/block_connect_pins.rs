// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pins for the GAP-7 cold-block bench (`benches/block_connect_verify.rs`).
//!
//! A bench that measures the wrong thing is worse than none, so what the
//! bench claims about its own fixtures is asserted HERE, under `cargo test`,
//! where CI sees it:
//!
//! 1. **Cap saturation** — the constructed worst-case candidates actually
//!    saturate the caps the census ratifies (CEN-H1's 1 MB, CEN-H3's
//!    149 400 weight, the 600 000 = 2×zone budget), so the worst case is as
//!    adversarial as the CONSTANTS say, not as the fixture happens to be.
//! 2. **Positive limbs** — every crypto component the bench times VERIFIES
//!    (else the bench times a reject path and reports a fiction).
//! 3. **Proxy fidelity** — the Bp+ proxy accepts what the production prover
//!    emits and rejects a corrupted statement, so its numbers describe
//!    verification work rather than an error path. (Prover→shipped-verifier
//!    acceptance is production fact — tx-builder's proofs are what the C++
//!    path accepts, layout pinned by its
//!    `bulletproof_oxide_layout_parses_as_wire_bpplus` — so prover→proxy
//!    acceptance asserted here closes the triangle.)

use rand_core::OsRng;

#[path = "../benches/block_connect_fixture.rs"]
mod fx;

use fx::relay::{admission_verify, ChunkLayout, ADMISSION_OK};
use fx::{
    bp_verify, build_bp, build_connect_tx, build_pqc_auth, parse_wire, pqc_verify_code,
    pqc_verify_code_against,
};

/// CEN-H1: serialized tx size cap.
const MAX_TX_SIZE: usize = 1_000_000;
/// CEN-H3: per-tx weight cap = zone/2 − coinbase reserve.
const TX_WEIGHT_LIMIT: usize = 149_400;
/// The permanent floor operating point: 2 × the 300 000 penalty-free zone.
const BUDGET_AT_ZONE: usize = 600_000;

#[test]
fn candidate_shapes_saturate_their_caps() {
    for (n_in, n_out) in [(8usize, 2usize), (1usize, 16usize), (8, 16)] {
        let fx = build_connect_tx(&mut OsRng, n_in, n_out, 2, ChunkLayout::Spread);

        // The wire must round-trip at the claimed shape — the parse fixture
        // and the crypto fixtures must describe the SAME transaction shape.
        let parsed = parse_wire(&fx);
        assert_eq!(parsed.prefix.inputs.len(), n_in, "parsed input arity");
        assert_eq!(parsed.prefix.outputs.len(), n_out, "parsed output arity");
        assert_eq!((fx.n_in, fx.n_out), (n_in, n_out), "fixture shape record");

        // The extra's INTERIOR must parse too. `Transaction::from_bytes`
        // treats `prefix.extra` as an opaque byte run (§9.4: V(extra_len) ·
        // bytes), so the arity asserts above cannot see a mis-encoded field —
        // the first cut of the 0x07 block omitted its length varint (per a
        // defective GTWF §9.6a sentence) and every pin stayed green. This
        // opt-in `parse_extra` round-trip is what makes interior encoding
        // failures visible.
        let fields = parsed
            .prefix
            .parse_extra()
            .expect("tx_extra interior must parse");
        let kem_fields = fields
            .iter()
            .filter(|f| matches!(f, shekyl_wire::tx_extra::TxExtraField::PqcKemCiphertext(_)))
            .count();
        assert_eq!(kem_fields, n_out, "one 0x06 KEM field per output");
        let leaf_blobs: Vec<usize> = fields
            .iter()
            .filter_map(|f| match f {
                shekyl_wire::tx_extra::TxExtraField::PqcLeafHashes(b) => Some(b.len()),
                _ => None,
            })
            .collect();
        assert_eq!(
            leaf_blobs,
            vec![32 * n_out],
            "exactly one 0x07 field carrying 32·n_out leaf-hash bytes"
        );

        // Per-tx caps hold — the fixture is admissible under what R2 ratifies.
        assert!(
            fx.wire_bytes.len() <= MAX_TX_SIZE,
            "shape ({n_in},{n_out}): serialized {} exceeds CEN-H1 cap",
            fx.wire_bytes.len()
        );
        assert!(
            fx.weight <= TX_WEIGHT_LIMIT,
            "shape ({n_in},{n_out}): weight {} exceeds CEN-H3 cap",
            fx.weight
        );
        // Weight ≥ size always (clawback is additive) — the invariant Q6's
        // "H3 binds tighter" reasoning rests on.
        assert!(fx.weight >= fx.wire_bytes.len());

        // Budget saturation at the floor operating point: N txs fit, N+1 do
        // not — the block the bench prices is full to within one tx.
        let n_txs = BUDGET_AT_ZONE / fx.weight;
        assert!(n_txs >= 1, "shape ({n_in},{n_out}): no tx fits the budget");
        assert!(n_txs * fx.weight <= BUDGET_AT_ZONE);
        assert!(
            (n_txs + 1) * fx.weight > BUDGET_AT_ZONE,
            "shape ({n_in},{n_out}): budget not saturated — {} txs of weight {} \
             leave more than one tx of headroom",
            n_txs,
            fx.weight
        );

        // Positive limbs: everything the bench times verifies.
        assert_eq!(
            admission_verify(&fx.adm),
            ADMISSION_OK,
            "shape ({n_in},{n_out}): admission fixture must verify"
        );
        assert_eq!(
            pqc_verify_code(&fx.pqc),
            0,
            "shape ({n_in},{n_out}): pqc auth must verify"
        );
        assert!(
            bp_verify(&fx.bp),
            "shape ({n_in},{n_out}): bp+ fixture must verify"
        );
    }
}

#[test]
fn bp_proxy_fidelity_positive_and_negative() {
    let bp = build_bp(&mut OsRng, 16);
    // Positive limb: the proxy accepts what the production prover emits.
    assert!(
        bp_verify(&bp),
        "proxy must accept the production prover's proof"
    );

    // Negative limb: a corrupted statement is rejected — the proxy is a
    // verifier, not a parser that waves proofs through.
    let mut corrupted = fx::BpFixture {
        proof: bp.proof.clone(),
        commitments: bp.commitments.clone(),
    };
    let mut bytes = corrupted.commitments[0].0;
    bytes[8] ^= 0x40;
    corrupted.commitments[0] = shekyl_curve_io::CompressedPoint(bytes);
    assert!(
        !bp_verify(&corrupted),
        "proxy must reject a corrupted commitment"
    );
}

#[test]
fn pqc_fixture_fidelity_positive_and_negative() {
    let auth = build_pqc_auth([0x11; 32]);
    assert_eq!(pqc_verify_code(&auth), 0, "hybrid sig must verify");

    // Wrong message → CryptoVerifyFailed (10), never success.
    assert_ne!(
        pqc_verify_code_against(&auth, &[0x22; 32]),
        0,
        "hybrid sig must not verify a different message"
    );

    // Corrupted signature → rejected (decode failure or verify failure).
    let mut corrupted = fx::PqcAuthFixture {
        public_key: auth.public_key.clone(),
        signature: auth.signature.clone(),
        message: auth.message,
    };
    let mid = corrupted.signature.len() / 2;
    corrupted.signature[mid] ^= 0x01;
    assert_ne!(
        pqc_verify_code(&corrupted),
        0,
        "corrupted hybrid sig must not verify"
    );
}
