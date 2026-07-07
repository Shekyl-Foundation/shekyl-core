// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pinned scan-time `view_tag` known-answer test — the Q13 / FA-6 freeze gate.
//!
//! Genesis freezes the wire `view_tag` as **ML-KEM-derived** (FA-6 §4.2:
//! `derive_view_tag_prefilter`, HKDF-SHA512 over the ML-KEM-768 shared secret).
//! The danger Q13 (`GENESIS_TX_WIRE_FORMAT.md` §6) calls out: if the scanner's
//! derivation ever drifts from the frozen one, **every output silently fails to
//! scan** — and the existing `construct → scan` round-trips can't catch it,
//! because they mint *fresh* keys each run, so both sides move together and the
//! test stays green. The unit KAT in `derivation.rs` only pins
//! `ml_kem_ss → tag`; it never decapsulates from a captured ciphertext.
//!
//! This KAT closes that gap by pinning a **captured output** against a frozen
//! fixture (`docs/test_vectors/PQC_SCAN_OUTPUT_KAT.json`):
//!
//!   * **builder pin** — re-run [`construct_output`] from the frozen inputs and
//!     assert every on-wire output field is byte-identical, `view_tag` included.
//!     A change to `derive_view_tag_prefilter`'s salt / label / hash, or to the
//!     KEM-seed / commitment / encryption derivation, fails here.
//!   * **scanner pin** — run the real scanner entry
//!     [`scan_output_recover_with_ml_kem_dk`] (universal ML-KEM decap from the
//!     frozen ciphertext, then `view_tag` compare, then recovery) and assert it
//!     recovers the exact amount and spend pubkey that were committed.
//!
//! The recipient keypair is frozen as an *input* (minted once via the
//! `#[ignore]`d `gen_scan_output_kat` generator below — no deterministic-keypair
//! primitive is exposed), so the fixture is self-contained and the `expected`
//! fields are a pure, reproducible function of the frozen inputs
//! (`construct_output` is deterministic).

use std::path::{Path, PathBuf};

use shekyl_crypto_pq::kem::{HybridX25519MlKem, KeyEncapsulation, MlKemDecapsKey};
use shekyl_crypto_pq::output::{construct_output, scan_output_recover_with_ml_kem_dk};

#[derive(serde::Serialize, serde::Deserialize)]
struct Vector {
    // ── frozen inputs ────────────────────────────────────────────────────
    tx_key: String,
    recipient_x25519_pk: String,
    recipient_x25519_sk: String,
    recipient_ml_kem_ek: String,
    recipient_ml_kem_dk: String,
    spend_key: String,
    amount: u64,
    output_index: u64,
    // ── expected captured output (deterministic fn of the inputs) ─────────
    output_key: String,
    commitment: String,
    enc_amount: String,
    amount_tag: u8,
    enc_label: String,
    label_tag: u8,
    /// The on-wire ML-KEM-derived view tag — the value Q13 freezes.
    view_tag: u8,
    kem_ct_x25519: String,
    kem_ct_ml_kem: String,
    h_pqc: String,
    pqc_public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VectorFile {
    description: String,
    vectors: Vec<Vector>,
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/PQC_SCAN_OUTPUT_KAT.json")
}

fn load() -> VectorFile {
    let json = std::fs::read_to_string(fixture_path()).unwrap_or_else(|e| {
        panic!(
            "failed to read {} ({e}); run `cargo test -p shekyl-crypto-pq \
             --test scan_output_kat -- --ignored gen_scan_output_kat` to mint it",
            fixture_path().display()
        )
    });
    serde_json::from_str(&json).expect("failed to parse PQC_SCAN_OUTPUT_KAT.json")
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().expect("32-byte hex")
}
fn h8(s: &str) -> [u8; 8] {
    hex::decode(s).unwrap().try_into().expect("8-byte hex")
}
fn hv(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn scan_output_view_tag_kat() {
    let file = load();
    assert!(
        !file.vectors.is_empty(),
        "no vectors in PQC_SCAN_OUTPUT_KAT.json"
    );

    for (i, v) in file.vectors.iter().enumerate() {
        // ── builder pin: reconstruct the output and assert byte-identity ──
        let out = construct_output(
            &h32(&v.tx_key),
            &h32(&v.recipient_x25519_pk),
            &hv(&v.recipient_ml_kem_ek),
            &h32(&v.spend_key),
            v.amount,
            v.output_index,
        )
        .unwrap_or_else(|e| panic!("vector {i}: construct_output failed: {e:?}"));

        assert_eq!(
            hex::encode(out.output_key),
            v.output_key,
            "vector {i}: output_key"
        );
        assert_eq!(
            hex::encode(out.commitment),
            v.commitment,
            "vector {i}: commitment"
        );
        assert_eq!(
            hex::encode(out.enc_amount),
            v.enc_amount,
            "vector {i}: enc_amount"
        );
        assert_eq!(out.amount_tag, v.amount_tag, "vector {i}: amount_tag");
        assert_eq!(
            hex::encode(out.enc_label),
            v.enc_label,
            "vector {i}: enc_label"
        );
        assert_eq!(out.label_tag, v.label_tag, "vector {i}: label_tag");
        // THE freeze pin: the ML-KEM-derived view tag must match the captured byte.
        assert_eq!(
            out.view_tag_prefilter, v.view_tag,
            "vector {i}: view_tag drifted — derive_view_tag_prefilter changed"
        );
        assert_eq!(
            hex::encode(out.kem_ciphertext_x25519),
            v.kem_ct_x25519,
            "vector {i}: kem_ct_x25519"
        );
        assert_eq!(
            hex::encode(&out.kem_ciphertext_ml_kem),
            v.kem_ct_ml_kem,
            "vector {i}: kem_ct_ml_kem"
        );
        assert_eq!(hex::encode(out.h_pqc), v.h_pqc, "vector {i}: h_pqc");
        assert_eq!(
            hex::encode(&out.pqc_public_key),
            v.pqc_public_key,
            "vector {i}: pqc_public_key"
        );

        // ── scanner pin: decap the FROZEN ciphertext via the real scanner entry ──
        let dk = MlKemDecapsKey::from_bytes(&hv(&v.recipient_ml_kem_dk))
            .unwrap_or_else(|e| panic!("vector {i}: parse ml_kem_dk failed: {e:?}"));
        let rec = scan_output_recover_with_ml_kem_dk(
            &h32(&v.recipient_x25519_sk),
            &dk,
            &h32(&v.kem_ct_x25519),
            &hv(&v.kem_ct_ml_kem),
            &h32(&v.output_key),
            &h32(&v.commitment),
            &h8(&v.enc_amount),
            v.amount_tag,
            &h8(&v.enc_label),
            v.label_tag,
            v.view_tag,
            v.output_index,
        )
        .unwrap_or_else(|e| {
            panic!("vector {i}: scan must recover the frozen captured output, got {e:?}")
        });

        // Recovery must invert construction: same amount, same spend pubkey.
        assert_eq!(rec.amount, v.amount, "vector {i}: recovered amount");
        assert_eq!(
            hex::encode(rec.recovered_spend_key),
            v.spend_key,
            "vector {i}: recovered spend pubkey"
        );
    }
}

/// Regenerate `PQC_SCAN_OUTPUT_KAT.json` in place. Reuses the fixture's frozen
/// inputs when it already exists (so `expected` is reproduced deterministically
/// after a *deliberate* derivation change); mints fresh recipient keypairs only
/// on first creation. Run explicitly:
///
/// ```text
/// cargo test -p shekyl-crypto-pq --test scan_output_kat -- --ignored gen_scan_output_kat
/// ```
#[test]
#[ignore = "regenerates the committed fixture; run explicitly with --ignored"]
fn gen_scan_output_kat() {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, scalar::Scalar};

    struct Spec {
        tx_key: [u8; 32],
        x25519_pk: [u8; 32],
        x25519_sk: [u8; 32],
        ml_kem_ek: Vec<u8>,
        ml_kem_dk: Vec<u8>,
        spend_key: [u8; 32],
        amount: u64,
        output_index: u64,
    }

    // Prefer the committed inputs (reproducible regen); mint only if absent.
    let specs: Vec<Spec> = match std::fs::read_to_string(fixture_path())
        .ok()
        .and_then(|s| serde_json::from_str::<VectorFile>(&s).ok())
    {
        Some(file) => file
            .vectors
            .iter()
            .map(|v| Spec {
                tx_key: h32(&v.tx_key),
                x25519_pk: h32(&v.recipient_x25519_pk),
                x25519_sk: h32(&v.recipient_x25519_sk),
                ml_kem_ek: hv(&v.recipient_ml_kem_ek),
                ml_kem_dk: hv(&v.recipient_ml_kem_dk),
                spend_key: h32(&v.spend_key),
                amount: v.amount,
                output_index: v.output_index,
            })
            .collect(),
        None => {
            // Per-vector deterministic params: (tx-key seed byte, spend scalar,
            // amount, output_index). Only the recipient keypair is random (frozen
            // once into the fixture). Explicit constants avoid lossy int casts.
            const PARAMS: [(u8, u64, u64, u64); 2] =
                [(0x42, 1_000, 1_000_000, 0), (0x43, 1_001, 2_000_000, 3)];
            PARAMS
                .iter()
                .map(|&(seed_byte, spend_scalar, amount, output_index)| {
                    let (pk, sk) = HybridX25519MlKem.keypair_generate().expect("keypair");
                    // Deterministic, canonical scalar seed for the tx key.
                    let tx_key = Scalar::from_bytes_mod_order([seed_byte; 32]).to_bytes();
                    // Deterministic valid spend pubkey B = b*G.
                    let spend_key = (Scalar::from(spend_scalar) * G).compress().to_bytes();
                    Spec {
                        tx_key,
                        x25519_pk: pk.x25519,
                        x25519_sk: sk.x25519,
                        ml_kem_ek: pk.ml_kem,
                        ml_kem_dk: sk.ml_kem.clone(),
                        spend_key,
                        amount,
                        output_index,
                    }
                })
                .collect()
        }
    };

    let vectors: Vec<Vector> = specs
        .iter()
        .map(|s| {
            let out = construct_output(
                &s.tx_key,
                &s.x25519_pk,
                &s.ml_kem_ek,
                &s.spend_key,
                s.amount,
                s.output_index,
            )
            .expect("construct_output");
            Vector {
                tx_key: hex::encode(s.tx_key),
                recipient_x25519_pk: hex::encode(s.x25519_pk),
                recipient_x25519_sk: hex::encode(s.x25519_sk),
                recipient_ml_kem_ek: hex::encode(&s.ml_kem_ek),
                recipient_ml_kem_dk: hex::encode(&s.ml_kem_dk),
                spend_key: hex::encode(s.spend_key),
                amount: s.amount,
                output_index: s.output_index,
                output_key: hex::encode(out.output_key),
                commitment: hex::encode(out.commitment),
                enc_amount: hex::encode(out.enc_amount),
                amount_tag: out.amount_tag,
                enc_label: hex::encode(out.enc_label),
                label_tag: out.label_tag,
                view_tag: out.view_tag_prefilter,
                kem_ct_x25519: hex::encode(out.kem_ciphertext_x25519),
                kem_ct_ml_kem: hex::encode(&out.kem_ciphertext_ml_kem),
                h_pqc: hex::encode(out.h_pqc),
                pqc_public_key: hex::encode(&out.pqc_public_key),
            }
        })
        .collect();

    let file = VectorFile {
        description: "Q13/FA-6 pinned scan-time view_tag KAT. Each vector freezes a \
            recipient keypair + construct_output inputs and the resulting captured \
            output; tests/scan_output_kat.rs asserts construct_output reproduces the \
            output byte-for-byte (view_tag included) and scan_output_recover_with_ml_kem_dk \
            recovers the committed amount + spend pubkey. Regenerate with \
            `cargo test -p shekyl-crypto-pq --test scan_output_kat -- --ignored gen_scan_output_kat`."
            .into(),
        vectors,
    };

    let json = serde_json::to_string_pretty(&file).expect("serialize");
    std::fs::write(fixture_path(), json + "\n").expect("write fixture");
    eprintln!("wrote {}", fixture_path().display());
}
