// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Frozen-hex KAT on the **derived** generator points.
//!
//! These generators are genesis-frozen: the FCMP++ membership/range proofs are
//! verified against exactly these points, so any drift silently changes which
//! proofs are valid — a consensus corruption that compiles clean. The Bulletproof
//! generator tables are *varint-derived* (`BulletproofGenerators::new` feeds
//! `shekyl_io::write_varint(&i, …)` into each generator's hash preimage), so this
//! KAT is what backstops the `shekyl-io` / `shekyl-curve-io` serialization layer:
//! a future "tidy-up" of the varint utility that shifts its output would move these
//! points, and only a release-running assertion on the points themselves catches it.
//!
//! The pre-existing coverage does **not** do this:
//! - [`super::test_vectors`] pins `biased_hash_to_point` (the function, against the
//!   Monero `tests.txt` vectors), not the derived tables.
//! - [`super::single_and_multithreaded_generators`] asserts the single- and
//!   multi-threaded builders agree — but both call the same `write_varint`, so a
//!   varint shift drifts both together and the assert stays green.
//! - The only point-equality in the builder is a `debug_assert`, compiled out in
//!   release.
//!
//! This is a plain `#[test]` (not a `debug_assert`): it runs and asserts in release.
//! If a toolchain/dependency bump legitimately re-derives a point, regenerate these
//! constants in the same PR and justify the change against the genesis freeze.

use group::GroupEncoding;
use sha3::{Digest, Keccak256};

use helioselene::{Helios, Selene};

use crate::{
    BulletproofGenerators, FcmpGenerators, H_pow_2, FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, H,
    HELIOS_HASH_INIT, SELENE_HASH_INIT, T,
};

fn ed_hex(p: &curve25519_dalek::EdwardsPoint) -> String {
    hex::encode(p.compress().to_bytes())
}

/// Keccak-256 over the concatenated compressed bytes of a Bulletproof generator
/// table (`G` then `H`), built with the genesis DST `prefix`.
fn bp_digest(prefix: &'static [u8]) -> String {
    let g = BulletproofGenerators::new(prefix);
    let mut h = Keccak256::new();
    for p in &g.G {
        h.update(p.compress().to_bytes());
    }
    for p in &g.H {
        h.update(p.compress().to_bytes());
    }
    hex::encode(h.finalize())
}

/// Keccak-256 over an FCMP generator set (`g, h, g_bold, h_bold`).
fn fcmp_digest<C>(gens: &FcmpGenerators<C>) -> String
where
    C: ciphersuite::Ciphersuite,
    C::G: GroupEncoding<Repr = [u8; 32]>,
{
    let mut h = Keccak256::new();
    h.update(gens.generators.g().to_bytes());
    h.update(gens.generators.h().to_bytes());
    for p in gens.generators.g_bold_slice() {
        h.update(p.to_bytes());
    }
    for p in gens.generators.h_bold_slice() {
        h.update(p.to_bytes());
    }
    hex::encode(h.finalize())
}

#[test]
fn frozen_singletons() {
    assert_eq!(
        ed_hex(&H),
        "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94",
        "Pedersen amount generator H moved"
    );
    assert_eq!(
        ed_hex(&T),
        "61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526",
        "key-image blinding generator T moved"
    );
    assert_eq!(
        ed_hex(&FCMP_PLUS_PLUS_U),
        "506b23f6d6e530997abcacc6fd347734b14c2bd79bea00eeb04857e8eadd1a8a",
        "FCMP++ generator U moved"
    );
    assert_eq!(
        ed_hex(&FCMP_PLUS_PLUS_V),
        "6935f413f83109138a7a14b409552d3b76d88fca81bb5927e9a1e130cdfe29f9",
        "FCMP++ generator V moved"
    );
    assert_eq!(
        hex::encode(HELIOS_HASH_INIT.to_bytes()),
        "139352002b5c2011a636f8cfa1c14c1f93510c8054929578c44b69638f7c070d",
        "Helios hash-init generator moved"
    );
    assert_eq!(
        hex::encode(SELENE_HASH_INIT.to_bytes()),
        "8681759fee95c1c97169b8d1476cfab7da101edef5932cf03053ae56f7081d07",
        "Selene hash-init generator moved"
    );
}

#[test]
fn frozen_h_pow_2_head() {
    // The first four entries of the amount-bit table H * 2^i.
    let expected = [
        "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94",
        "8faa448ae4b3e2bb3d4d130909f55fcd79711c1c83cdbccadd42cbe1515e8712",
        "12a7d62c7791654a57f3e67694ed50b49a7d9e3fc1e4c7a0bde29d187e9cc71d",
        "789ab9934b49c4f9e6785c6d57a498b3ead443f04f13df110c5427b4f214c739",
    ];
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(ed_hex(&H_pow_2()[i]), *want, "H_pow_2[{i}] moved");
    }
}

#[test]
fn frozen_bulletproof_tables() {
    // Varint-derived tables — the direct backstop for the io/curve-io varint.
    assert_eq!(
        bp_digest(b"bulletproof"),
        "7cff383078801a697f3f0a6f49322b9a10c06abc50a1425477d97214a64b8144",
        "Bulletproof generator table moved"
    );
    assert_eq!(
        bp_digest(b"bulletproof_plus"),
        "1889356594fef8a7d84eb3eabdce1d5d763bdfbc73a178e3718035f075dbe9cc",
        "Bulletproof+ generator table moved"
    );
}

#[test]
fn frozen_fcmp_tables() {
    assert_eq!(
        fcmp_digest(&FcmpGenerators::<Helios>::new()),
        "a34f6eedcdaf2e182366f8a39cbfb547948b16e32abab03e5d7225a49df9d71d",
        "FCMP Helios generator table moved"
    );
    assert_eq!(
        fcmp_digest(&FcmpGenerators::<Selene>::new()),
        "962475d4395396be7196a15581ea57b5a2cbd5a8f15cb451c467447a25b7ca3e",
        "FCMP Selene generator table moved"
    );
}
