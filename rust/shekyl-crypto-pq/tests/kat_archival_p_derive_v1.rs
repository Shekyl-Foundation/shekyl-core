// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tier-1/Tier-2 Known Answer Tests for the frozen ARCHIVAL_P_DERIVE_V1 pipeline.
//!
//! Corpus: `docs/test_vectors/ARCHIVAL_P_DERIVE_V1/{manifest.json,vectors.json}`.
//! Regenerate after a deliberate, documented derivation bump:
//! `cargo test -p shekyl-crypto-pq kat_regenerate_archival_p_derive_v1 -- --ignored --nocapture`
//!
//! This KAT belongs on the `aarch64` qemu-user lane (`depends.yml`): `P`'s
//! derivation is the third cross-arch-deterministic primitive, and a single
//! divergent bit on ARM means an ARM-phone user cannot recover their own bond.
//!
//! The Tier-2 `p_canonical_id_hex` is computed here via an **inline** cSHAKE256
//! (independent of `shekyl-archival-retention::id`). The companion cross-check
//! in `shekyl-archival-retention` recomputes it through `id.rs` and asserts the
//! same pinned value, proving the two cSHAKE paths agree.

use std::path::PathBuf;

use serde::Deserialize;
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{
    derive_archival_p_keys, derive_p_account_sign_seed, derive_p_bond_spend_ed_seed,
    derive_p_bond_spend_ml_dsa_seed, derive_p_kem_d_z, derive_p_ml_dsa_seed, derive_p_spend_wide,
    derive_p_view_wide, ArchivalPKeys,
};
use shekyl_crypto_pq::archival_p_freeze::archival_p_derive_manifest_self_check;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V1/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V1/vectors.json");

/// cSHAKE256 customization for the archival principal identity (mirrors
/// `shekyl-archival-retention::id::P_CANONICAL_ID_CUSTOMIZATION`).
const P_CANONICAL_ID_CUSTOMIZATION: &[u8] = b"shekyl/archival-p-id-v1";

/// Independent SP 800-185 cSHAKE256 with 32-byte output (the second of the two
/// paths the cross-check proves equal). Intentionally a fresh implementation,
/// not a call into `archival-retention`.
fn inline_cshake256_32(customization: &[u8], input: &[u8]) -> [u8; 32] {
    use sha3::digest::core_api::CoreWrapper;
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{CShake256, CShake256Core};

    let core = CShake256Core::new(customization);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

fn p_canonical_id(keys: &ArchivalPKeys) -> [u8; 32] {
    let bond_bytes = keys
        .hybrid_bond_id()
        .to_canonical_bytes()
        .expect("hybrid_bond_id canonical bytes");
    inline_cshake256_32(P_CANONICAL_ID_CUSTOMIZATION, &bond_bytes)
}

// ---------------------------------------------------------------------------
// Corpus schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ManifestFile {
    derivation_version: String,
    vectors_sha256_hex: String,
    tier1_count: usize,
    tier2_count: usize,
}

#[derive(Debug, Deserialize)]
struct VectorsFile {
    tier1: Vec<Tier1Vector>,
    tier2: Vec<Tier2Vector>,
}

#[derive(Debug, Deserialize)]
struct Tier1Vector {
    id: String,
    kind: String,
    master_seed_hex: String,
    network: String,
    seed_format: String,
    p_slot: u32,
    #[serde(default)]
    p_slot_b: Option<u32>,
    expected: Tier1Expected,
}

#[derive(Debug, Deserialize)]
struct Tier1Expected {
    #[serde(default)]
    out_hex: Option<String>,
    #[serde(default)]
    out_a_hex: Option<String>,
    #[serde(default)]
    out_b_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Tier2Vector {
    id: String,
    network: String,
    seed_format: String,
    master_seed_hex: String,
    p_slot: u32,
    expected: Tier2Expected,
}

#[derive(Debug, Deserialize)]
struct Tier2Expected {
    spend_pk_hex: String,
    view_pk_hex: String,
    x25519_pk_hex: String,
    ml_kem_ek_hex: String,
    hybrid_sign_pk_hex: String,
    bond_spend_pk_hex: String,
    p_canonical_id_hex: String,
    spend_sk_hex: String,
    view_sk_hex: String,
    ml_kem_dk_hex: String,
    hybrid_sign_sk_hex: String,
    bond_spend_sk_hex: String,
}

fn parse_network(s: &str) -> DerivationNetwork {
    match s {
        "mainnet" => DerivationNetwork::Mainnet,
        "testnet" => DerivationNetwork::Testnet,
        "stagenet" => DerivationNetwork::Stagenet,
        "fakechain" => DerivationNetwork::Fakechain,
        other => panic!("unknown network: {other}"),
    }
}

fn parse_seed_format(s: &str) -> SeedFormat {
    match s {
        "bip39" => SeedFormat::Bip39,
        "raw32" => SeedFormat::Raw32,
        other => panic!("unknown seed_format: {other}"),
    }
}

fn decode_master(s: &str) -> [u8; MASTER_SEED_BYTES] {
    let bytes = hex::decode(s).expect("master_seed hex");
    assert_eq!(bytes.len(), MASTER_SEED_BYTES, "master_seed length");
    let mut out = [0u8; MASTER_SEED_BYTES];
    out.copy_from_slice(&bytes);
    out
}

fn keys_for(v_network: &str, v_format: &str, master_hex: &str, p_slot: u32) -> ArchivalPKeys {
    let net = parse_network(v_network);
    let fmt = parse_seed_format(v_format);
    let master = decode_master(master_hex);
    derive_archival_p_keys(&master, net, fmt, p_slot).expect("derive_archival_p_keys")
}

fn run_tier1(v: &Tier1Vector) {
    let net = parse_network(&v.network);
    let fmt = parse_seed_format(&v.seed_format);
    let master = decode_master(&v.master_seed_hex);

    match v.kind.as_str() {
        "spend_wide" | "view_wide" | "kem_d_z" => {
            let out = match v.kind.as_str() {
                "spend_wide" => derive_p_spend_wide(&master, net, fmt, v.p_slot),
                "view_wide" => derive_p_view_wide(&master, net, fmt, v.p_slot),
                "kem_d_z" => derive_p_kem_d_z(&master, net, fmt, v.p_slot),
                _ => unreachable!(),
            };
            let exp = v.expected.out_hex.as_deref().expect("out_hex");
            assert_eq!(hex::encode(out.as_slice()), exp, "{}", v.id);
        }
        "account_sign_seed" | "ml_dsa_seed" | "bond_spend_ed_seed" | "bond_spend_ml_dsa_seed" => {
            let out = match v.kind.as_str() {
                "account_sign_seed" => derive_p_account_sign_seed(&master, net, fmt, v.p_slot),
                "ml_dsa_seed" => derive_p_ml_dsa_seed(&master, net, fmt, v.p_slot),
                "bond_spend_ed_seed" => derive_p_bond_spend_ed_seed(&master, net, fmt, v.p_slot),
                "bond_spend_ml_dsa_seed" => {
                    derive_p_bond_spend_ml_dsa_seed(&master, net, fmt, v.p_slot)
                }
                _ => unreachable!(),
            };
            let exp = v.expected.out_hex.as_deref().expect("out_hex");
            assert_eq!(hex::encode(out.as_slice()), exp, "{}", v.id);
        }
        "slot_separation" => {
            // Same inputs, two p_slots: identity keys must differ.
            let p_slot_b = v.p_slot_b.expect("p_slot_b");
            let a = derive_archival_p_keys(&master, net, fmt, v.p_slot).unwrap();
            let b = derive_archival_p_keys(&master, net, fmt, p_slot_b).unwrap();
            let a_hex = hex::encode(a.hybrid_sign_pk.to_canonical_bytes().unwrap());
            let b_hex = hex::encode(b.hybrid_sign_pk.to_canonical_bytes().unwrap());
            assert_eq!(
                a_hex,
                v.expected.out_a_hex.as_deref().expect("out_a_hex"),
                "{} a",
                v.id
            );
            assert_eq!(
                b_hex,
                v.expected.out_b_hex.as_deref().expect("out_b_hex"),
                "{} b",
                v.id
            );
            assert_ne!(a_hex, b_hex, "{} slots must differ", v.id);
        }
        "label_separation" => {
            // GF-1-carve: identity Ed25519 seed vs bond-spend Ed25519 seed must
            // differ under the same (seed, net, fmt, slot) — distinct labels.
            let acct = derive_p_account_sign_seed(&master, net, fmt, v.p_slot);
            let bond = derive_p_bond_spend_ed_seed(&master, net, fmt, v.p_slot);
            let a_hex = hex::encode(acct.as_slice());
            let b_hex = hex::encode(bond.as_slice());
            assert_eq!(
                a_hex,
                v.expected.out_a_hex.as_deref().expect("out_a_hex"),
                "{} a",
                v.id
            );
            assert_eq!(
                b_hex,
                v.expected.out_b_hex.as_deref().expect("out_b_hex"),
                "{} b",
                v.id
            );
            assert_ne!(a_hex, b_hex, "{} labels must differ", v.id);
        }
        other => panic!("unknown tier1 kind: {other}"),
    }
}

fn run_tier2(v: &Tier2Vector) {
    let k = keys_for(&v.network, &v.seed_format, &v.master_seed_hex, v.p_slot);
    let e = &v.expected;

    assert_eq!(
        hex::encode(k.spend_pk.as_canonical_bytes()),
        e.spend_pk_hex,
        "{} spend_pk",
        v.id
    );
    assert_eq!(
        hex::encode(k.view_pk.as_canonical_bytes()),
        e.view_pk_hex,
        "{} view_pk",
        v.id
    );
    assert_eq!(
        hex::encode(k.x25519_pk),
        e.x25519_pk_hex,
        "{} x25519_pk",
        v.id
    );
    assert_eq!(
        hex::encode(k.ml_kem_ek),
        e.ml_kem_ek_hex,
        "{} ml_kem_ek",
        v.id
    );
    assert_eq!(
        hex::encode(k.hybrid_sign_pk.to_canonical_bytes().unwrap()),
        e.hybrid_sign_pk_hex,
        "{} hybrid_sign_pk",
        v.id
    );
    assert_eq!(
        hex::encode(k.bond_spend_pk.to_canonical_bytes().unwrap()),
        e.bond_spend_pk_hex,
        "{} bond_spend_pk",
        v.id
    );
    assert_eq!(
        hex::encode(p_canonical_id(&k)),
        e.p_canonical_id_hex,
        "{} p_canonical_id",
        v.id
    );

    assert_eq!(
        hex::encode(k.spend_sk.as_canonical_bytes()),
        e.spend_sk_hex,
        "{} spend_sk",
        v.id
    );
    assert_eq!(
        hex::encode(k.view_sk.as_canonical_bytes()),
        e.view_sk_hex,
        "{} view_sk",
        v.id
    );
    assert_eq!(
        hex::encode(k.ml_kem_dk.as_canonical_bytes()),
        e.ml_kem_dk_hex,
        "{} ml_kem_dk",
        v.id
    );
    assert_eq!(
        hex::encode(k.hybrid_sign_sk.to_canonical_bytes().unwrap()),
        e.hybrid_sign_sk_hex,
        "{} hybrid_sign_sk",
        v.id
    );
    assert_eq!(
        hex::encode(k.bond_spend_sk.to_canonical_bytes().unwrap()),
        e.bond_spend_sk_hex,
        "{} bond_spend_sk",
        v.id
    );

    // Identity must never equal the address spend pubkey (privacy property of
    // the §9.3 dedicated-account-sign-seed resolution).
    assert_ne!(
        &k.hybrid_sign_pk.ed25519,
        k.spend_pk.as_canonical_bytes(),
        "{} identity must not reuse address spend pubkey",
        v.id
    );
}

#[test]
fn kat_archival_p_derive_v1_vectors() {
    use sha2::{Digest, Sha256};

    archival_p_derive_manifest_self_check().expect("corpus manifest hash pin");

    let manifest: ManifestFile =
        serde_json::from_str(MANIFEST_JSON).expect("manifest.json must parse");
    assert_eq!(manifest.derivation_version, "v1", "derivation_version");
    assert_eq!(
        manifest.vectors_sha256_hex,
        hex::encode(Sha256::digest(VECTORS_JSON.as_bytes())),
        "manifest vectors_sha256_hex must equal sha256sum of on-disk vectors.json"
    );

    let file: VectorsFile = serde_json::from_str(VECTORS_JSON).expect("vectors.json must parse");
    assert_eq!(file.tier1.len(), manifest.tier1_count, "tier1_count");
    assert_eq!(file.tier2.len(), manifest.tier2_count, "tier2_count");

    for v in &file.tier1 {
        run_tier1(v);
    }
    for v in &file.tier2 {
        run_tier2(v);
    }
}

// ---------------------------------------------------------------------------
// Fixture regenerator (run with --ignored)
// ---------------------------------------------------------------------------

const MASTER_33: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];
const MASTER_44: [u8; MASTER_SEED_BYTES] = [0x44u8; MASTER_SEED_BYTES];

fn build_tier1_vectors() -> Vec<serde_json::Value> {
    let net = DerivationNetwork::Mainnet;
    let fmt = SeedFormat::Bip39;
    let m = &MASTER_33;

    let spend = derive_p_spend_wide(m, net, fmt, 0);
    let view = derive_p_view_wide(m, net, fmt, 0);
    let kem = derive_p_kem_d_z(m, net, fmt, 0);
    let acct = derive_p_account_sign_seed(m, net, fmt, 0);
    let mldsa = derive_p_ml_dsa_seed(m, net, fmt, 0);
    let bond_ed = derive_p_bond_spend_ed_seed(m, net, fmt, 0);
    let bond_ml = derive_p_bond_spend_ml_dsa_seed(m, net, fmt, 0);

    let slot0 = derive_archival_p_keys(m, net, fmt, 0).unwrap();
    let slot7 = derive_archival_p_keys(m, net, fmt, 7).unwrap();

    let mk_intermediate = |id: &str, kind: &str, slot: u32, out: &[u8]| {
        serde_json::json!({
            "id": id, "kind": kind,
            "master_seed_hex": hex::encode(m), "network": "mainnet", "seed_format": "bip39",
            "p_slot": slot,
            "expected": { "out_hex": hex::encode(out) }
        })
    };

    vec![
        mk_intermediate(
            "spend_wide_mainnet_bip39_slot0",
            "spend_wide",
            0,
            spend.as_slice(),
        ),
        mk_intermediate(
            "view_wide_mainnet_bip39_slot0",
            "view_wide",
            0,
            view.as_slice(),
        ),
        mk_intermediate("kem_d_z_mainnet_bip39_slot0", "kem_d_z", 0, kem.as_slice()),
        mk_intermediate(
            "account_sign_seed_mainnet_bip39_slot0",
            "account_sign_seed",
            0,
            acct.as_slice(),
        ),
        mk_intermediate(
            "ml_dsa_seed_mainnet_bip39_slot0",
            "ml_dsa_seed",
            0,
            mldsa.as_slice(),
        ),
        mk_intermediate(
            "bond_spend_ed_seed_mainnet_bip39_slot0",
            "bond_spend_ed_seed",
            0,
            bond_ed.as_slice(),
        ),
        mk_intermediate(
            "bond_spend_ml_dsa_seed_mainnet_bip39_slot0",
            "bond_spend_ml_dsa_seed",
            0,
            bond_ml.as_slice(),
        ),
        serde_json::json!({
            "id": "slot_separation_slot0_vs_slot7", "kind": "slot_separation",
            "master_seed_hex": hex::encode(m), "network": "mainnet", "seed_format": "bip39",
            "p_slot": 0, "p_slot_b": 7,
            "expected": {
                "out_a_hex": hex::encode(slot0.hybrid_sign_pk.to_canonical_bytes().unwrap()),
                "out_b_hex": hex::encode(slot7.hybrid_sign_pk.to_canonical_bytes().unwrap())
            }
        }),
        serde_json::json!({
            "id": "label_separation_account_sign_vs_bond_spend_ed", "kind": "label_separation",
            "master_seed_hex": hex::encode(m), "network": "mainnet", "seed_format": "bip39",
            "p_slot": 0,
            "expected": {
                "out_a_hex": hex::encode(acct.as_slice()),
                "out_b_hex": hex::encode(bond_ed.as_slice())
            }
        }),
    ]
}

fn build_tier2_vector(
    id: &str,
    network: &str,
    seed_format: &str,
    master: &[u8; MASTER_SEED_BYTES],
    p_slot: u32,
) -> serde_json::Value {
    let net = parse_network(network);
    let fmt = parse_seed_format(seed_format);
    let k = derive_archival_p_keys(master, net, fmt, p_slot).unwrap();
    serde_json::json!({
        "id": id,
        "network": network,
        "seed_format": seed_format,
        "master_seed_hex": hex::encode(master),
        "p_slot": p_slot,
        "expected": {
            "spend_pk_hex": hex::encode(k.spend_pk.as_canonical_bytes()),
            "view_pk_hex": hex::encode(k.view_pk.as_canonical_bytes()),
            "x25519_pk_hex": hex::encode(k.x25519_pk),
            "ml_kem_ek_hex": hex::encode(k.ml_kem_ek),
            "hybrid_sign_pk_hex": hex::encode(k.hybrid_sign_pk.to_canonical_bytes().unwrap()),
            "bond_spend_pk_hex": hex::encode(k.bond_spend_pk.to_canonical_bytes().unwrap()),
            "p_canonical_id_hex": hex::encode(p_canonical_id(&k)),
            "spend_sk_hex": hex::encode(k.spend_sk.as_canonical_bytes()),
            "view_sk_hex": hex::encode(k.view_sk.as_canonical_bytes()),
            "ml_kem_dk_hex": hex::encode(k.ml_kem_dk.as_canonical_bytes()),
            "hybrid_sign_sk_hex": hex::encode(k.hybrid_sign_sk.to_canonical_bytes().unwrap()),
            "bond_spend_sk_hex": hex::encode(k.bond_spend_sk.to_canonical_bytes().unwrap())
        }
    })
}

fn build_tier2_vectors() -> Vec<serde_json::Value> {
    vec![
        build_tier2_vector("mainnet_bip39_slot0", "mainnet", "bip39", &MASTER_33, 0),
        build_tier2_vector("mainnet_bip39_slot7", "mainnet", "bip39", &MASTER_33, 7),
        build_tier2_vector("testnet_raw32_slot0", "testnet", "raw32", &MASTER_44, 0),
        build_tier2_vector("stagenet_bip39_slot3", "stagenet", "bip39", &MASTER_33, 3),
    ]
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/ARCHIVAL_P_DERIVE_V1")
}

/// Regenerates the on-disk KAT corpus. Run manually after a deliberate derivation bump.
#[test]
#[ignore = "fixture regenerator; run manually after derivation corpus changes"]
fn kat_regenerate_archival_p_derive_v1() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let dir = corpus_dir();
    fs::create_dir_all(&dir).expect("mkdir corpus dir");

    let tier1 = build_tier1_vectors();
    let tier2 = build_tier2_vectors();
    let vectors = serde_json::json!({ "tier1": tier1, "tier2": tier2 });
    let vectors_pretty = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    let vectors_on_disk = format!("{vectors_pretty}\n");
    let vectors_path = dir.join("vectors.json");
    fs::write(&vectors_path, &vectors_on_disk).expect("write vectors.json");

    let vectors_hash = Sha256::digest(vectors_on_disk.as_bytes());
    let manifest_body = serde_json::json!({
        "_comment": [
            "Tier-1/Tier-2 Known Answer Test fixtures for ARCHIVAL_P_DERIVE_V1.",
            "Tier-1 pins the per-row HKDF intermediates and the label/slot",
            "separation properties; Tier-2 pins end-to-end ArchivalPKeys public",
            "and secret material plus p_canonical_id (inline cSHAKE256).",
            "vectors_sha256_hex covers the exact on-disk bytes of vectors.json",
            "(verify with `sha256sum vectors.json`).",
            "Belongs on the aarch64 qemu lane: third cross-arch-deterministic",
            "primitive; a divergent bit means an ARM user cannot recover a bond.",
            "Regenerate only on a deliberate, documented derivation-version bump:",
            "cargo test -p shekyl-crypto-pq kat_regenerate_archival_p_derive_v1 -- --ignored --nocapture"
        ],
        "derivation_version": "v1",
        "fips203_pin": "=0.4.3",
        "vectors_sha256_hex": hex::encode(vectors_hash),
        "regeneration_command": "cargo test -p shekyl-crypto-pq kat_regenerate_archival_p_derive_v1 -- --ignored --nocapture",
        "tier1_count": tier1.len(),
        "tier2_count": tier2.len()
    });
    let manifest_pretty = serde_json::to_string_pretty(&manifest_body).expect("serialize manifest");
    let manifest_on_disk = format!("{manifest_pretty}\n");
    let manifest_path = dir.join("manifest.json");
    fs::write(&manifest_path, &manifest_on_disk).expect("write manifest.json");

    let mut corpus_hasher = Sha256::new();
    corpus_hasher.update(manifest_on_disk.as_bytes());
    corpus_hasher.update(vectors_on_disk.as_bytes());
    let corpus_hash = corpus_hasher.finalize();

    eprintln!("wrote {}", vectors_path.display());
    eprintln!("wrote {}", manifest_path.display());
    eprintln!("vectors_sha256_hex = {}", hex::encode(vectors_hash));
    eprintln!(
        "corpus_sha256_hex (manifest+vectors on-disk) = {}",
        hex::encode(corpus_hash)
    );
    eprintln!("update ARCHIVAL_P_DERIVE_MANIFEST_HASH in archival_p_freeze.rs");
}
