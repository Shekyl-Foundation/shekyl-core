// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! NIST ACVP conformance for the pinned `fips205` SLH-DSA-SHA2-192s paths
//! (`WALLET_MESSAGE_SIGNING.md` SM-R-8 adoption terms).
//!
//! The vectors are imported into `docs/test_vectors/SLH_DSA_192S_ACVP/`
//! from NIST's own ACVP-Server repository — **not** taken from the
//! crate's bundled copies — with provenance (source commit + sha256 of
//! the source files) in the manifest. This is the check that forecloses
//! the one implementation-defect branch that could not be fixed after
//! the genesis freeze: a nonconforming `keygen_with_seeds` would commit
//! nonconforming public keys into frozen addresses, and a corrected
//! crate could never re-derive them. With keygen proven conforming
//! before the freeze, any later sign/verify defect is patchable without
//! format impact.

use fips205::slh_dsa_sha2_192s as slh;
use fips205::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use serde::Deserialize;

const KEYGEN: &str = include_str!("../../../docs/test_vectors/SLH_DSA_192S_ACVP/keygen.json");
const SIGGEN: &str = include_str!("../../../docs/test_vectors/SLH_DSA_192S_ACVP/siggen.json");
const SIGVER: &str = include_str!("../../../docs/test_vectors/SLH_DSA_192S_ACVP/sigver.json");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn unhex_n<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("vector length")
}

#[derive(Deserialize)]
struct KeygenFile {
    cases: Vec<KeygenCase>,
}

#[derive(Deserialize)]
struct KeygenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "skSeed")]
    sk_seed: String,
    #[serde(rename = "skPrf")]
    sk_prf: String,
    #[serde(rename = "pkSeed")]
    pk_seed: String,
    pk: String,
    sk: String,
}

/// Every ACVP keyGen case: `keygen_with_seeds(skSeed, skPrf, pkSeed)`
/// must reproduce NIST's expected public AND secret key bytes. This is
/// the conformance the in-module derivation KAT (a freeze-pin) rests on.
#[test]
fn keygen_with_seeds_matches_nist_acvp() {
    let file: KeygenFile = serde_json::from_str(KEYGEN).expect("keygen.json");
    assert_eq!(file.cases.len(), 10, "the imported group carries 10 cases");
    for case in &file.cases {
        let sk_seed: [u8; 24] = unhex_n(&case.sk_seed);
        let sk_prf: [u8; 24] = unhex_n(&case.sk_prf);
        let pk_seed: [u8; 24] = unhex_n(&case.pk_seed);
        let (pk, sk) = slh::KG::keygen_with_seeds(&sk_seed, &sk_prf, &pk_seed);
        assert_eq!(
            pk.into_bytes().to_vec(),
            unhex(&case.pk),
            "tcId {}: public key diverged from NIST",
            case.tc_id
        );
        assert_eq!(
            sk.into_bytes().to_vec(),
            unhex(&case.sk),
            "tcId {}: secret key diverged from NIST",
            case.tc_id
        );
    }
}

#[derive(Deserialize)]
struct SiggenFile {
    cases: Vec<SiggenCase>,
}

#[derive(Deserialize)]
struct SiggenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    context: String,
    signature: String,
}

/// ACVP sigGen (external interface, pure, deterministic): signing with
/// `hedged = false` must reproduce NIST's expected signature bytes —
/// one empty-context case and one non-empty-context case, so the `ctx`
/// plumbing is proven in both positions (the production surface pins
/// `ctx = ""`; conformance covers the primitive either way).
#[test]
fn deterministic_sign_matches_nist_acvp() {
    let file: SiggenFile = serde_json::from_str(SIGGEN).expect("siggen.json");
    let mut ctx_lens = Vec::new();
    for case in &file.cases {
        let sk_bytes: [u8; slh::SK_LEN] = unhex_n(&case.sk);
        let sk = slh::PrivateKey::try_from_bytes(&sk_bytes).expect("sk parses");
        let ctx = unhex(&case.context);
        ctx_lens.push(ctx.len());
        let sig = sk
            .try_sign(&unhex(&case.message), &ctx, false)
            .expect("deterministic sign");
        assert_eq!(
            sig.to_vec(),
            unhex(&case.signature),
            "tcId {}: deterministic signature diverged from NIST",
            case.tc_id
        );
    }
    assert!(
        ctx_lens.contains(&0) && ctx_lens.iter().any(|&l| l > 0),
        "selection must exercise empty AND non-empty contexts"
    );
}

#[derive(Deserialize)]
struct SigverFile {
    cases: Vec<SigverCase>,
}

#[derive(Deserialize)]
struct SigverCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    message: String,
    context: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: String,
}

/// ACVP sigVer (external interface, pure): the verdict must match NIST's
/// on every selected case — one valid, three invalid with distinct
/// reasons (including a wrong-length signature, which must refuse at the
/// fixed-width parse rather than reach the verifier).
#[test]
fn verify_matches_nist_acvp() {
    let file: SigverFile = serde_json::from_str(SIGVER).expect("sigver.json");
    let mut passed_seen = false;
    let mut failed_seen = 0u32;
    for case in &file.cases {
        let pk_bytes: [u8; slh::PK_LEN] = unhex_n(&case.pk);
        let pk = slh::PublicKey::try_from_bytes(&pk_bytes).expect("pk parses");
        let sig = unhex(&case.signature);
        let verdict = match <&[u8; slh::SIG_LEN]>::try_from(sig.as_slice()) {
            Ok(sig_arr) => pk.verify(&unhex(&case.message), sig_arr, &unhex(&case.context)),
            // A signature that is not even SIG_LEN bytes refuses at the
            // parse — the reject-don't-truncate posture.
            Err(_) => false,
        };
        assert_eq!(
            verdict, case.test_passed,
            "tcId {} ({}): verdict diverged from NIST",
            case.tc_id, case.reason
        );
        if case.test_passed {
            passed_seen = true;
        } else {
            failed_seen += 1;
        }
    }
    assert!(
        passed_seen && failed_seen == 3,
        "selection must carry 1 passing + 3 distinct failing cases"
    );
}
