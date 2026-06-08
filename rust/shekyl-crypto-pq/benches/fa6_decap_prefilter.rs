// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FA-6 §8.5.1 smoke: per-output decap + `view_tag_prefilter` reject path.
//!
//! Full scenario A/B counts run via `fa6_decap_prefilter_gate` binary on Pi 4.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use shekyl_crypto_pq::derivation::derive_view_tag_prefilter;
use shekyl_crypto_pq::kem::{MlKemDecapsKey, ML_KEM_768_CT_LEN, ML_KEM_768_DK_LEN};
use shekyl_crypto_pq::output::ml_kem_decap_prefilter_with_parsed_dk;

fn bench_fa6_decap_prefilter_reject(c: &mut Criterion) {
    let (ek, dk) = ml_kem_768::KG::try_keygen().expect("keygen");
    let (_ss, ct) = ek.try_encaps().expect("encaps");
    let dk_bytes: [u8; ML_KEM_768_DK_LEN] = dk.into_bytes();
    let ct_bytes: [u8; ML_KEM_768_CT_LEN] = ct.into_bytes();
    let parsed_dk = MlKemDecapsKey::from_bytes(&dk_bytes).expect("parse dk");
    let dk_inner = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes).expect("parse dk inner");
    let ct_inner = ml_kem_768::CipherText::try_from_bytes(ct_bytes).expect("parse ct");
    let ss0: [u8; 32] = dk_inner.try_decaps(&ct_inner).expect("decap").into_bytes();
    let wrong_tag = derive_view_tag_prefilter(&ss0, 0).wrapping_add(1);

    c.bench_function("fa6_decap_prefilter_reject_path", |b| {
        b.iter(|| {
            let result = ml_kem_decap_prefilter_with_parsed_dk(
                black_box(&parsed_dk),
                black_box(&ct_bytes),
                black_box(wrong_tag),
                black_box(0),
            );
            assert!(result.is_err(), "wrong tag must reject");
        });
    });
}

criterion_group!(fa6_benches, bench_fa6_decap_prefilter_reject);
criterion_main!(fa6_benches);
