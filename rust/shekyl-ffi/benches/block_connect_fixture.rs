// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared fixture support for the GAP-7 cold-block connect bench
//! (`block_connect_verify.rs`) and its pins (`tests/block_connect_pins.rs`).
//!
//! Builds one **shape-true connect transaction**: the FCMP++ admission fixture
//! (real proof, via the relay bench's [`relay::build_fixture`]), a real hybrid
//! Ed25519+ML-DSA-65 signature over the fixture's signable hash, a real Bp+
//! aggregate range proof over `n_out` commitments, and the assembled
//! `shekyl_wire::Transaction` whose `weight()` — the single Rust owner of the
//! C++ `get_transaction_weight` semantics — is what the bench's budget math
//! and the pins' cap-saturation assertions run on.
//!
//! Nothing here is semantically block-valid end to end (the outputs' keys are
//! synthetic, the extra's KEM ciphertexts are random bytes); what IS real is
//! every component a **verifier pays for** — proof bytes, signature bytes,
//! commitment count, serialized layout — because those are the axes the bench
//! measures. The pins assert exactly that split: the crypto components verify
//! (positive limb), and the wire round-trips at the claimed shape.

use rand_core::{CryptoRng, OsRng, RngCore};

use curve25519_dalek::scalar::Scalar;
use shekyl_bulletproofs::Bulletproof;
use shekyl_curve_io::CompressedPoint;
use shekyl_curve_primitives::Commitment;
use shekyl_wire::transaction::{
    BpPlus, Ct, CtBase, Input, Output, PqcAuth, Prunable, Transaction, TxPrefix,
};
use shekyl_wire::tx_extra::{
    HYBRID_KEM_CT_BYTES, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, TX_EXTRA_TAG_PQC_LEAF_HASHES,
};

use shekyl_ffi::{shekyl_buffer_free, shekyl_pqc_keypair_generate, shekyl_pqc_sign};

#[path = "relay_admission_fixture.rs"]
pub mod relay;

/// A real hybrid Ed25519+ML-DSA-65 auth: key, signature, and the message it
/// signs (the admission fixture's signable tx hash — the same binding the
/// daemon's `verify_transaction_pqc_auth` checks per input).
pub struct PqcAuthFixture {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub message: [u8; 32],
}

/// Generate a keypair and sign `message` through the same FFI surface the
/// daemon consumes (`shekyl_pqc_keypair_generate` / `shekyl_pqc_sign`), so the
/// byte lengths entering the wire fixture are the production encodings, not
/// guesses.
pub fn build_pqc_auth(message: [u8; 32]) -> PqcAuthFixture {
    unsafe {
        let kp = shekyl_pqc_keypair_generate();
        assert!(kp.success, "pqc keypair generation failed");
        let sig = shekyl_pqc_sign(
            kp.secret_key.ptr,
            kp.secret_key.len,
            message.as_ptr(),
            message.len(),
        );
        assert!(sig.success, "pqc sign failed");

        let public_key = std::slice::from_raw_parts(kp.public_key.ptr, kp.public_key.len).to_vec();
        let signature = std::slice::from_raw_parts(sig.signature.ptr, sig.signature.len).to_vec();

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);

        PqcAuthFixture {
            public_key,
            signature,
            message,
        }
    }
}

/// One hybrid verification through the daemon's entry point
/// (`shekyl_pqc_verify`, scheme 1). `0` is the only success code.
pub fn pqc_verify_code(auth: &PqcAuthFixture) -> u8 {
    pqc_verify_code_against(auth, &auth.message)
}

/// Verify `auth` against an arbitrary message — the negative limb's hook.
pub fn pqc_verify_code_against(auth: &PqcAuthFixture, message: &[u8]) -> u8 {
    shekyl_ffi::shekyl_pqc_verify(
        1,
        auth.public_key.as_ptr(),
        auth.public_key.len(),
        auth.signature.as_ptr(),
        auth.signature.len(),
        message.as_ptr(),
        message.len(),
    )
}

/// A real Bp+ aggregate range proof over `n_out` commitments, plus the
/// commitments it must verify against.
///
/// **PROXY LABEL — read before using any number this produces.** This is the
/// Rust verifier (`shekyl-bulletproofs`, the sibling of the production
/// prover); the SHIPPED acceptance-path verifier is the inherited C++
/// `src/fcmp/bulletproofs_plus.cc` (CEN-H19, §10 R6 — disposition pending),
/// which a Rust bench cannot time. The proxy bounds the SHAPE question (does
/// output-density compete with input-density); the shipped verifier's absolute
/// cost stays CEN-H19's question.
pub struct BpFixture {
    pub proof: Bulletproof,
    pub commitments: Vec<CompressedPoint>,
}

/// Prove `n_out` in-range amounts with the production prover
/// (`Bulletproof::prove_plus` — the same call `shekyl-tx-builder` makes at
/// `sign.rs:112`).
pub fn build_bp<R: RngCore + CryptoRng>(rng: &mut R, n_out: usize) -> BpFixture {
    let commitments: Vec<Commitment> = (0..n_out)
        .map(|i| Commitment::new(Scalar::from((i + 7) as u64), 1_000 + i as u64))
        .collect();
    let compressed = commitments
        .iter()
        .map(|c| c.calculate().compress().into())
        .collect();
    let proof = Bulletproof::prove_plus(rng, commitments).expect("bp+ prove");
    BpFixture {
        proof,
        commitments: compressed,
    }
}

/// Verify the Bp+ proxy fixture. `true` is the only acceptable result for a
/// fixture the bench times (self-witness, same rule as `ADMISSION_OK`).
pub fn bp_verify(fx: &BpFixture) -> bool {
    fx.proof.verify(&mut OsRng, &fx.commitments)
}

/// Everything the cold-block connect path pays for one transaction, at one
/// shape — plus the wire form that prices it.
pub struct ConnectTxFixture {
    pub adm: relay::AdmissionFixture,
    pub pqc: PqcAuthFixture,
    pub bp: BpFixture,
    pub wire_bytes: Vec<u8>,
    /// `Transaction::weight()` — serialized length + Bp+ clawback, the value
    /// block weight and fees are charged against.
    pub weight: usize,
    pub n_in: usize,
    pub n_out: usize,
}

/// Build the full per-tx fixture at shape `(n_in, n_out)`.
///
/// The admission fixture carries the real FCMP++ proof; the wire assembly
/// mirrors `shekyl-tx-builder`'s `build_wire_tx` field for field (the Bp+
/// bytes round-trip through `BpPlus::from_bytes` exactly as the builder's
/// pinned layout test does), so `weight()` prices real component lengths.
pub fn build_connect_tx<R: RngCore + CryptoRng>(
    rng: &mut R,
    n_in: usize,
    n_out: usize,
    tree_depth: u8,
    layout: relay::ChunkLayout,
) -> ConnectTxFixture {
    let adm = relay::build_fixture(rng, n_in, n_out, tree_depth, layout);
    let pqc = build_pqc_auth(adm.signable_tx_hash);
    let bp = build_bp(rng, n_out);

    // Inputs: n_in FCMP++ spends, key images from the admission fixture.
    let inputs: Vec<Input> = adm
        .key_images_flat
        .chunks_exact(32)
        .map(|ki| Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image: ki.try_into().expect("32-byte key image"),
        })
        .collect();
    assert_eq!(inputs.len(), n_in, "admission fixture input arity");

    // Outputs: n_out view-tagged keys (synthetic key bytes; the verifier cost
    // of an output lives in Bp+/CT, which are real above).
    let outputs: Vec<Output> = (0..n_out)
        .map(|i| {
            let tag = u8::try_from(i).expect("n_out <= 16");
            Output {
                amount: 0,
                key: [tag + 1; 32],
                view_tag: tag,
            }
        })
        .collect();

    // tx_extra per GTWF §9.6a: per-output 0x06 (varint len ‖ x25519[32] ‖
    // ML-KEM-768 ct[1088]) and one 0x07 carrying 32·n_out leaf-hash bytes
    // (deliberately NOT self-describing — parsed by output count).
    let mut extra = Vec::with_capacity(n_out * (HYBRID_KEM_CT_BYTES + 3) + 32 * n_out + 2);
    for i in 0..n_out {
        extra.push(TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT);
        // varint(1120): 1120 = 0xE0 ‖ 0x08 in LEB128.
        extra.push(0xE0);
        extra.push(0x08);
        extra.extend(std::iter::repeat_n(
            u8::try_from(i).expect("n_out <= 16"),
            HYBRID_KEM_CT_BYTES,
        ));
    }
    // 0x07 is per NEW OUTPUT (h_pqc = Blake2b(pqc_pk) of each created
    // output) — NOT the admission fixture's `pqc_hashes_flat`, which is
    // per-INPUT (the spent outputs' leaf scalars feeding the membership
    // proof). Conflating the two mis-prices the wire by (n_in − n_out)·32
    // bytes; the first run of the pins caught exactly that. The bytes here
    // are synthetic filler: no measured call verifies them (the leaf-hash
    // FFI term is measured on its own fixture), so only their LENGTH prices
    // the wire, and the length is the per-output contract.
    extra.push(TX_EXTRA_TAG_PQC_LEAF_HASHES);
    for i in 0..n_out {
        let nib = 0xB0u8 | (u8::try_from(i).expect("n_out <= 16") & 0x0F);
        extra.extend(std::iter::repeat_n(nib, 32));
    }

    // Bp+ bytes: oxide `write` and wire `BpPlus` share the exact layout
    // (pinned by tx-builder's `bulletproof_oxide_layout_parses_as_wire_bpplus`).
    let mut bp_bytes = Vec::new();
    bp.proof.write(&mut bp_bytes).expect("bp+ write");
    let bp_plus = BpPlus::from_bytes(&bp_bytes).expect("bp+ bytes parse as wire BpPlus");

    let pqc_auths: Vec<PqcAuth> = (0..n_in)
        .map(|_| PqcAuth {
            auth_version: 1,
            scheme_id: 1, // single-signer hybrid Ed25519+ML-DSA-65
            flags: 0,
            hybrid_public_key: pqc.public_key.clone(),
            hybrid_signature: pqc.signature.clone(),
        })
        .collect();

    let commitments: Vec<[u8; 32]> = bp.commitments.iter().map(|c| c.0).collect();

    let tx = Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs,
            outputs,
            extra,
        },
        ct: Ct::Fcmp {
            fee: 1,
            reference_block: [0xAB; 32],
            base: CtBase {
                enc_amounts: vec![[0u8; 9]; n_out],
                enc_labels: vec![[0u8; 9]; n_out],
                commitments,
            },
            pqc_auths,
            prunable: Some(Prunable {
                bulletproofs: vec![bp_plus],
                tree_depth: u64::from(tree_depth.max(2)) - 1,
                fcmp_proof: adm.proof.clone(),
                pseudo_outs: adm
                    .pseudo_outs_flat
                    .chunks_exact(32)
                    .map(|c| c.try_into().expect("32-byte pseudo out"))
                    .collect(),
                serve_credit_pruned: Vec::new(),
            }),
        },
    };

    let mut wire_bytes = Vec::new();
    tx.write(&mut wire_bytes).expect("wire write");
    let weight = tx.weight();

    ConnectTxFixture {
        adm,
        pqc,
        bp,
        wire_bytes,
        weight,
        n_in,
        n_out,
    }
}

/// Parse the fixture's wire bytes through the production parser — the bench's
/// parse term. Returns the parsed tx so the pins can assert shape agreement.
pub fn parse_wire(fx: &ConnectTxFixture) -> Transaction {
    Transaction::from_bytes(&fx.wire_bytes).expect("wire parse")
}
