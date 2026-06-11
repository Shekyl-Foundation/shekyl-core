// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tier-1/Tier-2 Known Answer Tests for the frozen ADDRESS_DERIVATION_V1 pipeline.
//!
//! Corpus: `docs/test_vectors/ADDRESS_DERIVATION_V1/{manifest.json,vectors.json}`.
//! Regenerate after a deliberate, documented derivation bump:
//! `cargo test -p shekyl-crypto-pq kat_regenerate_address_derivation_v1 -- --ignored --nocapture`

use std::path::PathBuf;

use serde::Deserialize;
use shekyl_crypto_pq::account::{
    self, check_pqc_public_key_matches_view, derive_kem_d_z, derive_spend_wide, derive_view_wide,
    generate_account_from_bip39, generate_account_from_raw_seed, ml_kem_chacha_seed_from_d_z,
    normalize_seed, rederive_account, wide_reduce_to_scalar, AllKeysBlob, DerivationNetwork,
    SeedFormat, MASTER_SEED_BYTES, RAW_SEED_BYTES,
};
use shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check;
use shekyl_crypto_pq::bip39;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V1/vectors.json");

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
    #[serde(default)]
    ikm_hex: Option<String>,
    #[serde(default)]
    master_seed_hex: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    seed_format: Option<String>,
    #[serde(default)]
    d_z_hex: Option<String>,
    #[serde(default)]
    network_a: Option<String>,
    #[serde(default)]
    format_a: Option<String>,
    #[serde(default)]
    network_b: Option<String>,
    #[serde(default)]
    format_b: Option<String>,
    expected: Tier1Expected,
}

#[derive(Debug, Deserialize)]
struct Tier1Expected {
    #[serde(default)]
    master_seed_hex: Option<String>,
    #[serde(default)]
    wide_hex: Option<String>,
    #[serde(default)]
    chacha_seed_hex: Option<String>,
    #[serde(default)]
    spend_sk_a_hex: Option<String>,
    #[serde(default)]
    spend_sk_b_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Tier2Vector {
    id: String,
    tier: u8,
    network: String,
    seed_format: String,
    #[serde(default)]
    mnemonic_words: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    raw_seed_hex: Option<String>,
    expected: Tier2Expected,
}

#[derive(Debug, Deserialize)]
struct Tier2Expected {
    master_seed_hex: String,
    spend_pk_hex: String,
    view_pk_hex: String,
    x25519_pk_hex: String,
    ml_kem_ek_hex: String,
    pqc_public_key_hex: String,
    classical_address_bytes_hex: String,
    spend_sk_hex: String,
    view_sk_hex: String,
    ml_kem_dk_hex: String,
}

fn decode_hex<const N: usize>(s: &str, label: &str) -> [u8; N] {
    let bytes = hex::decode(s).unwrap_or_else(|e| panic!("{label}: invalid hex: {e}"));
    assert_eq!(
        bytes.len(),
        N,
        "{label}: expected {N} bytes, got {}",
        bytes.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
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

fn blob_to_tier2_expected(
    blob: &AllKeysBlob,
    master_seed: &[u8; MASTER_SEED_BYTES],
) -> Tier2Expected {
    Tier2Expected {
        master_seed_hex: hex::encode(master_seed),
        spend_pk_hex: hex::encode(blob.spend_pk.as_canonical_bytes()),
        view_pk_hex: hex::encode(blob.view_pk.as_canonical_bytes()),
        x25519_pk_hex: hex::encode(blob.x25519_pk),
        ml_kem_ek_hex: hex::encode(blob.ml_kem_ek),
        pqc_public_key_hex: hex::encode(blob.pqc_public_key),
        classical_address_bytes_hex: hex::encode(blob.classical_address_bytes),
        spend_sk_hex: hex::encode(blob.spend_sk.as_canonical_bytes()),
        view_sk_hex: hex::encode(blob.view_sk.as_canonical_bytes()),
        ml_kem_dk_hex: hex::encode(blob.ml_kem_dk.as_canonical_bytes()),
    }
}

fn assert_tier2_expected(
    blob: &AllKeysBlob,
    master_seed: &[u8; MASTER_SEED_BYTES],
    exp: &Tier2Expected,
) {
    let got = blob_to_tier2_expected(blob, master_seed);
    assert_eq!(got.master_seed_hex, exp.master_seed_hex, "master_seed_hex");
    assert_eq!(got.spend_pk_hex, exp.spend_pk_hex, "spend_pk_hex");
    assert_eq!(got.view_pk_hex, exp.view_pk_hex, "view_pk_hex");
    assert_eq!(got.x25519_pk_hex, exp.x25519_pk_hex, "x25519_pk_hex");
    assert_eq!(got.ml_kem_ek_hex, exp.ml_kem_ek_hex, "ml_kem_ek_hex");
    assert_eq!(
        got.pqc_public_key_hex, exp.pqc_public_key_hex,
        "pqc_public_key_hex"
    );
    assert_eq!(
        got.classical_address_bytes_hex, exp.classical_address_bytes_hex,
        "classical_address_bytes_hex"
    );
    assert_eq!(got.spend_sk_hex, exp.spend_sk_hex, "spend_sk_hex");
    assert_eq!(got.view_sk_hex, exp.view_sk_hex, "view_sk_hex");
    assert_eq!(got.ml_kem_dk_hex, exp.ml_kem_dk_hex, "ml_kem_dk_hex");

    let pqc: [u8; account::PQC_PUBLIC_KEY_BYTES] =
        decode_hex(&exp.pqc_public_key_hex, "pqc_public_key_hex");
    let view_pk: [u8; 32] = decode_hex(&exp.view_pk_hex, "view_pk_hex");
    check_pqc_public_key_matches_view(&pqc, &view_pk)
        .expect("check_pqc_public_key_matches_view on Tier-2 golden");
}

fn run_tier1(v: &Tier1Vector) {
    match v.kind.as_str() {
        "normalize_seed" => {
            let ikm = hex::decode(v.ikm_hex.as_ref().expect("ikm_hex")).expect("ikm hex");
            let got = normalize_seed(&ikm);
            let exp: [u8; MASTER_SEED_BYTES] = decode_hex(
                v.expected
                    .master_seed_hex
                    .as_ref()
                    .expect("master_seed_hex"),
                &v.id,
            );
            assert_eq!(got.as_slice(), exp.as_slice(), "{}", v.id);
        }
        "derive_spend_wide" | "derive_view_wide" | "derive_kem_d_z" => {
            let master = decode_hex(v.master_seed_hex.as_ref().expect("master_seed_hex"), &v.id);
            let net = parse_network(v.network.as_ref().expect("network"));
            let fmt = parse_seed_format(v.seed_format.as_ref().expect("seed_format"));
            let wide = match v.kind.as_str() {
                "derive_spend_wide" => derive_spend_wide(&master, net, fmt),
                "derive_view_wide" => derive_view_wide(&master, net, fmt),
                "derive_kem_d_z" => derive_kem_d_z(&master, net, fmt),
                _ => unreachable!(),
            };
            let exp: [u8; 64] = decode_hex(v.expected.wide_hex.as_ref().expect("wide_hex"), &v.id);
            assert_eq!(wide.as_slice(), exp.as_slice(), "{}", v.id);
        }
        "ml_kem_chacha_seed" => {
            let d_z = decode_hex(v.d_z_hex.as_ref().expect("d_z_hex"), &v.id);
            let got = ml_kem_chacha_seed_from_d_z(&d_z);
            let exp: [u8; 32] = decode_hex(
                v.expected
                    .chacha_seed_hex
                    .as_ref()
                    .expect("chacha_seed_hex"),
                &v.id,
            );
            assert_eq!(got, exp, "{}", v.id);
        }
        "network_format_separation" => {
            let master = decode_hex(v.master_seed_hex.as_ref().expect("master_seed_hex"), &v.id);
            let net_a = parse_network(v.network_a.as_ref().expect("network_a"));
            let fmt_a = parse_seed_format(v.format_a.as_ref().expect("format_a"));
            let net_b = parse_network(v.network_b.as_ref().expect("network_b"));
            let fmt_b = parse_seed_format(v.format_b.as_ref().expect("format_b"));
            let sk_a = wide_reduce_to_scalar(&derive_spend_wide(&master, net_a, fmt_a));
            let sk_b = wide_reduce_to_scalar(&derive_spend_wide(&master, net_b, fmt_b));
            let exp_a = decode_hex(
                v.expected.spend_sk_a_hex.as_ref().expect("spend_sk_a_hex"),
                &v.id,
            );
            let exp_b = decode_hex(
                v.expected.spend_sk_b_hex.as_ref().expect("spend_sk_b_hex"),
                &v.id,
            );
            assert_eq!(sk_a.as_bytes(), &exp_a, "{} spend_sk_a", v.id);
            assert_eq!(sk_b.as_bytes(), &exp_b, "{} spend_sk_b", v.id);
            assert_ne!(sk_a.as_bytes(), sk_b.as_bytes(), "{} must differ", v.id);
        }
        other => panic!("unknown tier1 kind: {other}"),
    }
}

fn run_tier2(v: &Tier2Vector) {
    assert_eq!(v.tier, 2);
    let net = parse_network(&v.network);
    let fmt = parse_seed_format(&v.seed_format);
    let (master_seed, blob) = match fmt {
        SeedFormat::Bip39 => {
            let words = v.mnemonic_words.as_ref().expect("mnemonic_words");
            let passphrase = v.passphrase.as_deref().unwrap_or("");
            let (seed, blob) = generate_account_from_bip39(words, passphrase, net)
                .expect("generate_account_from_bip39");
            (seed, blob)
        }
        SeedFormat::Raw32 => {
            let raw: [u8; RAW_SEED_BYTES] =
                decode_hex(v.raw_seed_hex.as_ref().expect("raw_seed_hex"), &v.id);
            let (seed, blob) =
                generate_account_from_raw_seed(&raw, net).expect("generate_account_from_raw_seed");
            (seed, blob)
        }
    };
    assert_tier2_expected(&blob, &master_seed, &v.expected);

    // Rederive path must reproduce the full golden blob (public and secret
    // material), not just a subset of it.
    let blob2 = rederive_account(&master_seed, net, fmt).expect("rederive_account");
    assert_tier2_expected(&blob2, &master_seed, &v.expected);
}

#[test]
fn kat_address_derivation_v1_vectors() {
    use sha2::{Digest, Sha256};

    address_derivation_manifest_self_check().expect("corpus manifest hash pin");

    // The manifest's self-describing fields must match the corpus they
    // describe; otherwise they are decorative and will drift.
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

    // Network / seed-format / passphrase separation: every Tier-2 vector must
    // produce a distinct account. Replaces the inline
    // `different_passphrases_yield_different_accounts` behavior test that the
    // corpus extraction removed from `account.rs`.
    for (i, a) in file.tier2.iter().enumerate() {
        for b in &file.tier2[i + 1..] {
            assert_ne!(
                a.expected.spend_pk_hex, b.expected.spend_pk_hex,
                "tier2 {} and {} must derive distinct spend keys",
                a.id, b.id
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture regenerator (run with --ignored)
// ---------------------------------------------------------------------------

fn zero_entropy_mnemonic() -> String {
    let entropy = [0u8; 32];
    bip39::mnemonic_from_entropy(&entropy).expect("mnemonic_from_entropy")
}

fn build_tier1_vectors() -> Vec<serde_json::Value> {
    let hello_ikm = b"hello";
    let hello_master = normalize_seed(hello_ikm);
    let master_11 = [0x11u8; MASTER_SEED_BYTES];
    let master_22 = [0x22u8; MASTER_SEED_BYTES];
    let d_z_sample = [0x7Au8; 64];

    let spend_mainnet =
        derive_spend_wide(&master_11, DerivationNetwork::Mainnet, SeedFormat::Bip39);
    let view_mainnet = derive_view_wide(&master_11, DerivationNetwork::Mainnet, SeedFormat::Bip39);
    let kem_mainnet = derive_kem_d_z(&master_11, DerivationNetwork::Mainnet, SeedFormat::Bip39);
    let chacha = ml_kem_chacha_seed_from_d_z(&d_z_sample);

    let sk_mainnet = wide_reduce_to_scalar(&derive_spend_wide(
        &master_11,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
    ));
    let sk_stagenet = wide_reduce_to_scalar(&derive_spend_wide(
        &master_11,
        DerivationNetwork::Stagenet,
        SeedFormat::Bip39,
    ));

    vec![
        serde_json::json!({
            "id": "normalize_seed_hello",
            "kind": "normalize_seed",
            "ikm_hex": hex::encode(hello_ikm),
            "expected": { "master_seed_hex": hex::encode(hello_master.as_slice()) }
        }),
        serde_json::json!({
            "id": "derive_spend_wide_mainnet_bip39",
            "kind": "derive_spend_wide",
            "master_seed_hex": hex::encode(master_11),
            "network": "mainnet",
            "seed_format": "bip39",
            "expected": { "wide_hex": hex::encode(spend_mainnet.as_slice()) }
        }),
        serde_json::json!({
            "id": "derive_view_wide_mainnet_bip39",
            "kind": "derive_view_wide",
            "master_seed_hex": hex::encode(master_11),
            "network": "mainnet",
            "seed_format": "bip39",
            "expected": { "wide_hex": hex::encode(view_mainnet.as_slice()) }
        }),
        serde_json::json!({
            "id": "derive_kem_d_z_mainnet_bip39",
            "kind": "derive_kem_d_z",
            "master_seed_hex": hex::encode(master_11),
            "network": "mainnet",
            "seed_format": "bip39",
            "expected": { "wide_hex": hex::encode(kem_mainnet.as_slice()) }
        }),
        serde_json::json!({
            "id": "ml_kem_chacha_seed_sample",
            "kind": "ml_kem_chacha_seed",
            "d_z_hex": hex::encode(d_z_sample),
            "expected": { "chacha_seed_hex": hex::encode(chacha) }
        }),
        serde_json::json!({
            "id": "network_format_separation_mainnet_vs_stagenet",
            "kind": "network_format_separation",
            "master_seed_hex": hex::encode(master_11),
            "network_a": "mainnet",
            "format_a": "bip39",
            "network_b": "stagenet",
            "format_b": "bip39",
            "expected": {
                "spend_sk_a_hex": hex::encode(sk_mainnet.as_bytes()),
                "spend_sk_b_hex": hex::encode(sk_stagenet.as_bytes())
            }
        }),
        serde_json::json!({
            "id": "network_format_separation_testnet_raw32_vs_mainnet_bip39",
            "kind": "network_format_separation",
            "master_seed_hex": hex::encode(master_22),
            "network_a": "testnet",
            "format_a": "raw32",
            "network_b": "mainnet",
            "format_b": "bip39",
            "expected": {
                "spend_sk_a_hex": hex::encode(
                    wide_reduce_to_scalar(&derive_spend_wide(
                        &master_22,
                        DerivationNetwork::Testnet,
                        SeedFormat::Raw32,
                    ))
                    .as_bytes()
                ),
                "spend_sk_b_hex": hex::encode(
                    wide_reduce_to_scalar(&derive_spend_wide(
                        &master_22,
                        DerivationNetwork::Mainnet,
                        SeedFormat::Bip39,
                    ))
                    .as_bytes()
                )
            }
        }),
    ]
}

fn build_tier2_vector(
    id: &str,
    network: DerivationNetwork,
    fmt: SeedFormat,
    mnemonic: Option<&str>,
    passphrase: &str,
    raw_seed: Option<[u8; RAW_SEED_BYTES]>,
) -> serde_json::Value {
    let (master_seed, blob) = match fmt {
        SeedFormat::Bip39 => {
            let words = mnemonic.expect("mnemonic");
            generate_account_from_bip39(words, passphrase, network).expect("bip39 gen")
        }
        SeedFormat::Raw32 => {
            let raw = raw_seed.expect("raw_seed");
            generate_account_from_raw_seed(&raw, network).expect("raw32 gen")
        }
    };
    let exp = blob_to_tier2_expected(&blob, &master_seed);
    let network_s = match network {
        DerivationNetwork::Mainnet => "mainnet",
        DerivationNetwork::Testnet => "testnet",
        DerivationNetwork::Stagenet => "stagenet",
        DerivationNetwork::Fakechain => "fakechain",
    };
    let format_s = match fmt {
        SeedFormat::Bip39 => "bip39",
        SeedFormat::Raw32 => "raw32",
    };
    let mut obj = serde_json::json!({
        "id": id,
        "tier": 2,
        "network": network_s,
        "seed_format": format_s,
        "passphrase": passphrase,
        "expected": {
            "master_seed_hex": exp.master_seed_hex,
            "spend_pk_hex": exp.spend_pk_hex,
            "view_pk_hex": exp.view_pk_hex,
            "x25519_pk_hex": exp.x25519_pk_hex,
            "ml_kem_ek_hex": exp.ml_kem_ek_hex,
            "pqc_public_key_hex": exp.pqc_public_key_hex,
            "classical_address_bytes_hex": exp.classical_address_bytes_hex,
            "spend_sk_hex": exp.spend_sk_hex,
            "view_sk_hex": exp.view_sk_hex,
            "ml_kem_dk_hex": exp.ml_kem_dk_hex
        }
    });
    if let SeedFormat::Bip39 = fmt {
        obj["mnemonic_words"] = serde_json::Value::String(mnemonic.unwrap().to_string());
    }
    if let Some(raw) = raw_seed {
        obj["raw_seed_hex"] = serde_json::Value::String(hex::encode(raw));
    }
    obj
}

fn build_tier2_vectors() -> Vec<serde_json::Value> {
    let zero_words = zero_entropy_mnemonic();
    let entropy_55 = [0x55u8; 32];
    let words_55 = bip39::mnemonic_from_entropy(&entropy_55).expect("mnemonic");
    let raw_aa = [0xAAu8; RAW_SEED_BYTES];

    vec![
        build_tier2_vector(
            "mainnet_bip39_zero_entropy",
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            Some(&zero_words),
            "",
            None,
        ),
        build_tier2_vector(
            "mainnet_bip39_trezor_passphrase",
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            Some(&zero_words),
            "TREZOR",
            None,
        ),
        build_tier2_vector(
            "mainnet_bip39_entropy_55_empty_passphrase",
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            Some(&words_55),
            "",
            None,
        ),
        build_tier2_vector(
            "testnet_raw32_fixed",
            DerivationNetwork::Testnet,
            SeedFormat::Raw32,
            None,
            "",
            Some(raw_aa),
        ),
        build_tier2_vector(
            "stagenet_bip39_zero_entropy",
            DerivationNetwork::Stagenet,
            SeedFormat::Bip39,
            Some(&zero_words),
            "",
            None,
        ),
    ]
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/ADDRESS_DERIVATION_V1")
}

/// Regenerates the on-disk KAT corpus. Run manually after a deliberate derivation bump.
#[test]
#[ignore = "fixture regenerator; run manually after derivation corpus changes"]
fn kat_regenerate_address_derivation_v1() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let dir = corpus_dir();
    fs::create_dir_all(&dir).expect("mkdir corpus dir");

    let tier1 = build_tier1_vectors();
    let tier2 = build_tier2_vectors();
    let vectors = serde_json::json!({
        "tier1": tier1,
        "tier2": tier2
    });
    let vectors_pretty = serde_json::to_string_pretty(&vectors).expect("serialize vectors");
    let vectors_path = dir.join("vectors.json");
    let vectors_on_disk = format!("{vectors_pretty}\n");
    fs::write(&vectors_path, &vectors_on_disk).expect("write vectors.json");

    // Hash the exact on-disk bytes (trailing newline included) so external
    // verification is just `sha256sum vectors.json`.
    let vectors_hash = Sha256::digest(vectors_on_disk.as_bytes());
    let manifest_body = serde_json::json!({
        "_comment": [
            "Tier-1/Tier-2 Known Answer Test fixtures for ADDRESS_DERIVATION_V1.",
            "Tier-1 pins intermediate derivation steps; Tier-2 pins end-to-end",
            "account material from generate_account_from_* / rederive_account.",
            "vectors_sha256_hex covers the exact on-disk bytes of vectors.json",
            "(verify with `sha256sum vectors.json`).",
            "Regenerate only on a deliberate, documented derivation-version bump:",
            "cargo test -p shekyl-crypto-pq kat_regenerate_address_derivation_v1 -- --ignored --nocapture",
            "",
            "ML-KEM keygen uses fips203 =0.4.3 with the SHA3-ChaCha intermediary",
            "(see account.rs module doc). Tier-3 BIP-39 wordlist/PBKDF2 vectors",
            "live in rust/shekyl-crypto-pq/src/bip39.rs tests; Tier-4 KEM derive",
            "vectors live in KEM_DERIVE_V1_KAT.json (derivation.rs inline KAT)."
        ],
        "derivation_version": "v1",
        "fips203_pin": "=0.4.3",
        "vectors_sha256_hex": hex::encode(vectors_hash),
        "regeneration_command": "cargo test -p shekyl-crypto-pq kat_regenerate_address_derivation_v1 -- --ignored --nocapture",
        "tier1_count": tier1.len(),
        "tier2_count": tier2.len()
    });
    let manifest_pretty = serde_json::to_string_pretty(&manifest_body).expect("serialize manifest");
    let manifest_path = dir.join("manifest.json");
    let manifest_on_disk = format!("{manifest_pretty}\n");
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
    eprintln!("update ADDRESS_DERIVATION_MANIFEST_HASH in address_derivation_freeze.rs");
}
