// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Pinned **positive** KATs for the v2 nested hybrid combiner — one vector per
//! signing surface (rule 30 pinned-test-vector discipline).
//!
//! Why these exist: the workspace's sign and verify share one implementation,
//! so a self-round-trip test cannot catch an edit that moves *both* — a new
//! preimage framing, a changed domain constant, a reordered outer message all
//! pass every round-trip while invalidating every previously produced
//! signature. Each vector here is a signature minted by an earlier build; the
//! current build must still (a) verify it under the fixture's domain, and
//! (b) **reject** it under every other surface's domain — pinning both the
//! construction and the cross-surface separation (SA-R-2/SA-R-5).
//!
//! The fixture also pins the domain *strings* against the Rust constants, so
//! renaming or re-pointing a `SCHEME_DOMAIN_*` constant fails here rather than
//! silently re-keying a surface.
//!
//! Frozen negative twin: `docs/PQC_TEST_VECTOR_001.json` (a v1 *parallel*
//! signature, never regenerated) is rejected at parse — see
//! `frozen_v1_vector_is_rejected_at_parse` in `signature.rs`. This file is the
//! positive half of that boundary.
//!
//! Regenerate (construction change only — the writer is idempotent while the
//! pinned signatures still verify):
//! `cargo test -p shekyl-crypto-pq --test kat_hybrid_v2 -- --ignored`

use serde_json::{json, Value};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION, SCHEME_DOMAIN_EMISSION_BACKING, SCHEME_DOMAIN_EMISSION_CLAIM,
    SCHEME_DOMAIN_PQC_AUTH_TX, SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG, SCHEME_DOMAIN_SERVE_CREDIT,
};
use std::path::{Path, PathBuf};

/// Every ratified signing surface and its scheme-level domain constant. A new
/// `SCHEME_DOMAIN_*` constant must be added here (the pinned test counts the
/// fixture's vectors against this table, so forgetting is loud).
const SURFACES: [(&str, &[u8]); 6] = [
    ("pqc_auth_tx", SCHEME_DOMAIN_PQC_AUTH_TX),
    ("pqc_auth_tx_multisig", SCHEME_DOMAIN_PQC_AUTH_TX_MULTISIG),
    ("emission_claim", SCHEME_DOMAIN_EMISSION_CLAIM),
    ("emission_backing", SCHEME_DOMAIN_EMISSION_BACKING),
    ("attestation", SCHEME_DOMAIN_ATTESTATION),
    ("serve_credit", SCHEME_DOMAIN_SERVE_CREDIT),
];

/// One shared message: the cross-domain negatives below prove the *domain*
/// separates the surfaces even over identical message bytes, which is the
/// whole SA-R-2 property.
///
/// The string is **frozen with the pinned signatures**: every vector was
/// minted over exactly these bytes, so editing the literal (even cosmetically
/// — the "seven" is historical; bond_post was retired in SA-2b) invalidates
/// every pinned signature and forces a wholesale re-mint, destroying the
/// cross-build pin continuity this fixture exists for. The live surface count
/// is enforced against `SURFACES.len()`, never against this string.
const KAT_MESSAGE: &[u8] = b"shekyl-hybrid-v2-kat: one message, seven surfaces";

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/PQC_HYBRID_V2_KAT.json")
}

fn read_fixture() -> Value {
    let raw = std::fs::read_to_string(fixture_path()).expect("PQC_HYBRID_V2_KAT.json readable");
    serde_json::from_str(&raw).expect("PQC_HYBRID_V2_KAT.json parses")
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn hybrid_v2_pinned_vectors_verify_per_surface() {
    let kat = read_fixture();
    let scheme = HybridEd25519MlDsa;

    let pk = HybridPublicKey::from_canonical_bytes(&decode_hex(
        kat["hybrid_public_key_hex"].as_str().expect("pk hex"),
    ))
    .expect("pinned public key parses");
    let message = decode_hex(kat["message_hex"].as_str().expect("message hex"));
    assert_eq!(
        message, KAT_MESSAGE,
        "fixture message drifted from the test"
    );

    let vectors = kat["vectors"].as_array().expect("vectors array");
    assert_eq!(
        vectors.len(),
        SURFACES.len(),
        "one pinned vector per ratified surface — regenerate after adding a surface"
    );

    for (i, ((surface, domain), vector)) in SURFACES.iter().zip(vectors).enumerate() {
        assert_eq!(
            vector["surface"].as_str(),
            Some(*surface),
            "vector {i}: surface order drifted from the SURFACES table"
        );
        // Tripwire: the fixture pins the domain *string*; editing the Rust
        // constant (or re-pointing a surface at another string) fails here.
        assert_eq!(
            vector["domain_utf8"].as_str().map(str::as_bytes),
            Some(*domain),
            "vector {i} ({surface}): SCHEME_DOMAIN constant drifted from the pinned string"
        );

        let sig_bytes = decode_hex(vector["hybrid_signature_hex"].as_str().expect("sig hex"));
        assert_eq!(
            sig_bytes.len(),
            HybridSignature::CANONICAL_LEN,
            "vector {i} ({surface}): canonical signature length"
        );
        let sig = HybridSignature::from_canonical_bytes(&sig_bytes)
            .expect("pinned v2 signature parses (version byte 2)");

        // The pinned positive: a signature minted by an earlier build must
        // still verify — sign/verify co-drift cannot pass this.
        scheme
            .verify(&pk, domain, &message, &sig)
            .unwrap_or_else(|e| {
                panic!("vector {i} ({surface}): pinned signature must verify: {e:?}")
            });

        // Cross-surface negatives: the same signature must be dead on every
        // other surface (SA-R-2 — the domain is the separation).
        for (other_surface, other_domain) in &SURFACES {
            if other_domain == domain {
                continue;
            }
            assert!(
                scheme.verify(&pk, other_domain, &message, &sig).is_err(),
                "vector {i} ({surface}): signature must not verify under {other_surface}"
            );
        }
    }
}

/// Regenerate `docs/test_vectors/PQC_HYBRID_V2_KAT.json` in place.
///
/// Idempotent while the construction is unchanged: the pinned keypair is
/// reused whenever it parses, and each pinned signature is reused whenever it
/// still verifies under its surface — so an incidental rerun rewrites the file
/// byte-identically instead of churning anchors (the gate-2 lesson). Only a
/// genuine construction change (which invalidates the pinned signatures)
/// re-signs, and only a corrupt/missing fixture re-mints the keypair.
#[test]
#[ignore = "writes docs/test_vectors/PQC_HYBRID_V2_KAT.json"]
fn regenerate_hybrid_v2_kat() {
    let scheme = HybridEd25519MlDsa;
    let path = fixture_path();
    let existing: Option<Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    let pinned_keypair = existing.as_ref().and_then(|v| {
        let pk = HybridPublicKey::from_canonical_bytes(&decode_hex(
            v["hybrid_public_key_hex"].as_str()?,
        ))
        .ok()?;
        let sk = HybridSecretKey::from_canonical_bytes(&decode_hex(
            v["hybrid_secret_key_hex"].as_str()?,
        ))
        .ok()?;
        Some((pk, sk))
    });
    let (pk, sk) = pinned_keypair.unwrap_or_else(|| {
        scheme
            .generate_ephemeral_keypair_for_tests()
            .expect("keypair")
    });

    let vectors: Vec<Value> = SURFACES
        .iter()
        .enumerate()
        .map(|(i, (surface, domain))| {
            let reusable = existing
                .as_ref()
                .and_then(|v| v["vectors"].as_array()?.get(i)?["hybrid_signature_hex"].as_str())
                .map(decode_hex)
                .and_then(|bytes| HybridSignature::from_canonical_bytes(&bytes).ok())
                .filter(|sig| scheme.verify(&pk, domain, KAT_MESSAGE, sig).is_ok());
            let sig =
                reusable.unwrap_or_else(|| scheme.sign(&sk, domain, KAT_MESSAGE).expect("sign"));
            json!({
                "surface": surface,
                "domain_utf8": String::from_utf8(domain.to_vec()).expect("utf8 domain"),
                "hybrid_signature_hex": hex::encode(sig.to_canonical_bytes().expect("sig bytes")),
            })
        })
        .collect();

    let doc = json!({
        "description": "Pinned positive KATs for the v2 nested hybrid combiner \
                        (PQ-inner/Ed-outer, 64-byte cSHAKE256 preimage), one vector per \
                        signing surface over one shared message. Consumed by \
                        shekyl-crypto-pq/tests/kat_hybrid_v2.rs; the frozen v1 negative \
                        twin is docs/PQC_TEST_VECTOR_001.json (never regenerated).",
        "scheme": "ed25519_ml_dsa_65_nested_v2",
        "message_utf8": String::from_utf8(KAT_MESSAGE.to_vec()).expect("utf8 message"),
        "message_hex": hex::encode(KAT_MESSAGE),
        "hybrid_public_key_hex": hex::encode(pk.to_canonical_bytes().expect("pk bytes")),
        "hybrid_secret_key_hex": hex::encode(sk.to_canonical_bytes().expect("sk bytes")),
        "vectors": vectors,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    eprintln!("wrote {}", path.display());
}
