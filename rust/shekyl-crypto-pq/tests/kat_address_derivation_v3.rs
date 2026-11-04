// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tier-1/Tier-2 vectors for the frozen ADDRESS_DERIVATION_V3 pipeline: a
//! wallet's one 32-byte secret, `normalize_seed`, then HKDF-SHA-512 under
//! `salt_for(net)` = `name_id(net)` ‖ `shekyl-master-derive-v3`
//! (`NETWORK_IDENTITY.md` NI-R7, NI-R10; `V3_WALLET_DECISION_LOG.md`,
//! 2026-11-03 and 2026-11-04).
//!
//! Corpus: `docs/test_vectors/ADDRESS_DERIVATION_V3/{manifest.json,vectors.json}`.
//!
//! # Oracle, per value (rule 50)
//!
//! Independent: every value that is HKDF/hash/modular arithmetic or Ed25519
//! base-point arithmetic is recomputed from the vectors' inputs by
//! `scripts/kat/address_derivation_v3_oracle.py` (stdlib Python, RFC 5869 by
//! hand), which CI runs in `docs-gates.yml`: the salts, `normalize_seed`, the
//! spend/view/KEM wide outputs, the ML-KEM ChaCha seed, the spend/view
//! scalars, the Ed25519 spend/view public keys, the X25519 key, the
//! classical address's `version ‖ spend ‖ view` prefix, and the two 24-word
//! spellings against the published BIP-39 reference vectors.
//!
//! Self-pinned (drift tripwire only; no implementation outside this crate
//! vouches for them): the ML-KEM-768 encap/decap keys, the SLH-DSA-192s
//! message-signing key inside `classical_address_bytes`, and therefore the
//! `pqc_public_key` suffix.
//!
//! Regenerating is a decision, not a command; the regenerator refuses
//! unless the invocation cites the decision-log entry:
//!
//! ```text
//! SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-crypto-pq --test kat_address_derivation_v3 \
//!   kat_regenerate_address_derivation_v3 -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use serde::Deserialize;
use shekyl_crypto_pq::account::{
    self, account_from_seed, account_from_words, check_pqc_public_key_matches_view, derive_kem_d_z,
    derive_spend_wide, derive_view_wide, ml_kem_chacha_seed_from_d_z, normalize_seed,
    rederive_account, salt_for, wide_reduce_to_scalar, AllKeysBlob, Network, MASTER_SEED_BYTES,
    SEED_BYTES,
};
use shekyl_crypto_pq::address_derivation_freeze::address_derivation_manifest_self_check;
use shekyl_crypto_pq::bip39;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V3/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ADDRESS_DERIVATION_V3/vectors.json");

/// The manifest's `derivation_version`: the corpus version and the salt it
/// was derived under.
const DERIVATION_VERSION: &str = "v3 (salt name_id(net) || shekyl-master-derive-v3)";

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
    d_z_hex: Option<String>,
    #[serde(default)]
    network_a: Option<String>,
    #[serde(default)]
    network_b: Option<String>,
    expected: Tier1Expected,
}

#[derive(Debug, Deserialize)]
struct Tier1Expected {
    #[serde(default)]
    salt_hex: Option<String>,
    #[serde(default)]
    master_seed_hex: Option<String>,
    #[serde(default)]
    wide_hex: Option<String>,
    #[serde(default)]
    scalar_hex: Option<String>,
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
    seed_hex: String,
    #[serde(default)]
    mnemonic_words: Option<String>,
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

fn parse_network(s: &str) -> Network {
    Network::from_name(s).unwrap_or_else(|| panic!("unknown network: {s}"))
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
    id: &str,
    blob: &AllKeysBlob,
    master_seed: &[u8; MASTER_SEED_BYTES],
    exp: &Tier2Expected,
) {
    let got = blob_to_tier2_expected(blob, master_seed);
    assert_eq!(
        got.master_seed_hex, exp.master_seed_hex,
        "{id} master_seed_hex"
    );
    assert_eq!(got.spend_pk_hex, exp.spend_pk_hex, "{id} spend_pk_hex");
    assert_eq!(got.view_pk_hex, exp.view_pk_hex, "{id} view_pk_hex");
    assert_eq!(got.x25519_pk_hex, exp.x25519_pk_hex, "{id} x25519_pk_hex");
    assert_eq!(got.ml_kem_ek_hex, exp.ml_kem_ek_hex, "{id} ml_kem_ek_hex");
    assert_eq!(
        got.pqc_public_key_hex, exp.pqc_public_key_hex,
        "{id} pqc_public_key_hex"
    );
    assert_eq!(
        got.classical_address_bytes_hex, exp.classical_address_bytes_hex,
        "{id} classical_address_bytes_hex"
    );
    assert_eq!(got.spend_sk_hex, exp.spend_sk_hex, "{id} spend_sk_hex");
    assert_eq!(got.view_sk_hex, exp.view_sk_hex, "{id} view_sk_hex");
    assert_eq!(got.ml_kem_dk_hex, exp.ml_kem_dk_hex, "{id} ml_kem_dk_hex");

    let pqc: [u8; account::PQC_PUBLIC_KEY_BYTES] =
        decode_hex(&exp.pqc_public_key_hex, "pqc_public_key_hex");
    let view_pk: [u8; 32] = decode_hex(&exp.view_pk_hex, "view_pk_hex");
    check_pqc_public_key_matches_view(&pqc, &view_pk)
        .expect("check_pqc_public_key_matches_view on Tier-2 golden");
}

fn wide_for(kind: &str, master: &[u8; MASTER_SEED_BYTES], net: Network) -> [u8; 64] {
    let wide = match kind {
        "derive_spend_wide" => derive_spend_wide(master, net),
        "derive_view_wide" => derive_view_wide(master, net),
        "derive_kem_d_z" => derive_kem_d_z(master, net),
        other => unreachable!("not a wide kind: {other}"),
    };
    *wide
}

fn run_tier1(v: &Tier1Vector) {
    match v.kind.as_str() {
        "salt_for" => {
            let net = parse_network(v.network.as_ref().expect("network"));
            let exp = v.expected.salt_hex.as_deref().expect("salt_hex");
            assert_eq!(hex::encode(salt_for(net)), exp, "{}", v.id);
        }
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
            let wide = wide_for(&v.kind, &master, net);
            let exp: [u8; 64] = decode_hex(v.expected.wide_hex.as_ref().expect("wide_hex"), &v.id);
            assert_eq!(wide, exp, "{}", v.id);
            // The spend and view outputs collapse to scalars; the KEM output
            // feeds the ChaCha seed instead and carries no scalar.
            match (v.kind.as_str(), v.expected.scalar_hex.as_deref()) {
                ("derive_kem_d_z", None) => {}
                ("derive_kem_d_z", Some(_)) => panic!("{}: d_z carries no scalar", v.id),
                (_, Some(exp_scalar)) => assert_eq!(
                    hex::encode(wide_reduce_to_scalar(&wide).as_bytes()),
                    exp_scalar,
                    "{} scalar",
                    v.id
                ),
                (_, None) => panic!("{}: scalar_hex missing", v.id),
            }
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
            assert_eq!(*got, exp, "{}", v.id);
        }
        "network_separation" => {
            let master = decode_hex(v.master_seed_hex.as_ref().expect("master_seed_hex"), &v.id);
            let net_a = parse_network(v.network_a.as_ref().expect("network_a"));
            let net_b = parse_network(v.network_b.as_ref().expect("network_b"));
            let sk_a = wide_reduce_to_scalar(&derive_spend_wide(&master, net_a));
            let sk_b = wide_reduce_to_scalar(&derive_spend_wide(&master, net_b));
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
            // A live computation, so dropping `net` from the salt fails here
            // even if the corpus is rebuilt around the new bytes.
            assert_ne!(sk_a.as_bytes(), sk_b.as_bytes(), "{} must differ", v.id);
        }
        other => panic!("unknown tier1 kind: {other}"),
    }
}

fn run_tier2(v: &Tier2Vector) {
    assert_eq!(v.tier, 2);
    let net = parse_network(&v.network);
    let seed: [u8; SEED_BYTES] = decode_hex(&v.seed_hex, &v.id);

    // The bytes path: what every network's wallet runs (NI-R7).
    let (master_seed, blob) = account_from_seed(&seed, net).expect("account_from_seed");
    assert_tier2_expected(&v.id, &blob, &master_seed, &v.expected);

    // The words path, where the vector carries words: the 24 words are the
    // 32 bytes' spelling, so they decode to `seed_hex` and give the same
    // wallet, byte for byte.
    if let Some(words) = v.mnemonic_words.as_deref() {
        let account::WordsAccount {
            seed: words_seed,
            master_seed: words_master,
            blob: words_blob,
        } = account_from_words(words, net).expect("account_from_words");
        assert_eq!(
            hex::encode(words_seed.as_slice()),
            v.seed_hex,
            "{}: words must decode to seed_hex",
            v.id
        );
        assert_tier2_expected(&v.id, &words_blob, &words_master, &v.expected);
        assert_eq!(
            bip39::mnemonic_from_entropy(&seed).expect("mnemonic_from_entropy"),
            words,
            "{}: seed_hex must spell as mnemonic_words",
            v.id
        );
    }

    // Rederive path (every wallet open) must reproduce the full golden blob,
    // public and secret material.
    let blob2 = rederive_account(&master_seed, net).expect("rederive_account");
    assert_tier2_expected(&v.id, &blob2, &master_seed, &v.expected);
}

#[test]
fn kat_address_derivation_v3_vectors() {
    use sha2::{Digest, Sha256};

    address_derivation_manifest_self_check().expect("corpus manifest hash pin");

    // The manifest's self-describing fields must match the corpus they
    // describe; otherwise they are decorative and will drift.
    let manifest: ManifestFile =
        serde_json::from_str(MANIFEST_JSON).expect("manifest.json must parse");
    assert_eq!(
        manifest.derivation_version, DERIVATION_VERSION,
        "derivation_version"
    );
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

    // Every network is covered at Tier 2, and at least one vector proves
    // the words path (rule 47: the suite asserts its own subjects exist).
    for net in Network::ALL {
        assert!(
            file.tier2.iter().any(|v| v.network == net.name()),
            "no Tier-2 vector on {net}"
        );
    }
    assert!(
        file.tier2.iter().any(|v| v.mnemonic_words.is_some()),
        "no Tier-2 vector derives from words"
    );

    // Every Tier-2 vector is a distinct account; same-seed vectors on
    // different networks are the end-to-end network separation.
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
// Fixture regenerator (armed; run with --ignored)
// ---------------------------------------------------------------------------

const MASTER_11: [u8; MASTER_SEED_BYTES] = [0x11u8; MASTER_SEED_BYTES];
const MASTER_22: [u8; MASTER_SEED_BYTES] = [0x22u8; MASTER_SEED_BYTES];

fn wide_vector(kind: &str, net: Network) -> serde_json::Value {
    let wide = wide_for(kind, &MASTER_11, net);
    let short = kind.trim_start_matches("derive_");
    let mut expected = serde_json::json!({ "wide_hex": hex::encode(wide) });
    if kind != "derive_kem_d_z" {
        expected["scalar_hex"] =
            serde_json::Value::String(hex::encode(wide_reduce_to_scalar(&wide).as_bytes()));
    }
    serde_json::json!({
        "id": format!("{short}_{}", net.name()),
        "kind": kind,
        "master_seed_hex": hex::encode(MASTER_11),
        "network": net.name(),
        "expected": expected
    })
}

fn separation_vector(net_a: Network, net_b: Network) -> serde_json::Value {
    let sk_a = wide_reduce_to_scalar(&derive_spend_wide(&MASTER_22, net_a));
    let sk_b = wide_reduce_to_scalar(&derive_spend_wide(&MASTER_22, net_b));
    serde_json::json!({
        "id": format!("network_separation_{}_vs_{}", net_a.name(), net_b.name()),
        "kind": "network_separation",
        "master_seed_hex": hex::encode(MASTER_22),
        "network_a": net_a.name(),
        "network_b": net_b.name(),
        "expected": {
            "spend_sk_a_hex": hex::encode(sk_a.as_bytes()),
            "spend_sk_b_hex": hex::encode(sk_b.as_bytes())
        }
    })
}

fn build_tier1_vectors() -> Vec<serde_json::Value> {
    let mut out = Vec::new();

    for net in Network::ALL {
        out.push(serde_json::json!({
            "id": format!("salt_for_{}", net.name()),
            "kind": "salt_for",
            "network": net.name(),
            "expected": { "salt_hex": hex::encode(salt_for(net)) }
        }));
    }

    // normalize_seed over the input shape production feeds it (a 32-byte
    // seed), plus a short input: the function is HKDF over any length.
    for (id, ikm) in [
        ("normalize_seed_zero32", [0u8; SEED_BYTES].to_vec()),
        ("normalize_seed_hello", b"hello".to_vec()),
    ] {
        let master = normalize_seed(&ikm);
        out.push(serde_json::json!({
            "id": id,
            "kind": "normalize_seed",
            "ikm_hex": hex::encode(&ikm),
            "expected": { "master_seed_hex": hex::encode(master.as_slice()) }
        }));
    }

    for net in Network::ALL {
        for kind in ["derive_spend_wide", "derive_view_wide", "derive_kem_d_z"] {
            out.push(wide_vector(kind, net));
        }
    }

    let d_z_sample = [0x7Au8; 64];
    out.push(serde_json::json!({
        "id": "ml_kem_chacha_seed_sample",
        "kind": "ml_kem_chacha_seed",
        "d_z_hex": hex::encode(d_z_sample),
        "expected": { "chacha_seed_hex": hex::encode(*ml_kem_chacha_seed_from_d_z(&d_z_sample)) }
    }));

    // Mainnet/stagenet and testnet/regtest: every network on one side of a
    // pinned separation pair.
    out.push(separation_vector(Network::Mainnet, Network::Stagenet));
    out.push(separation_vector(Network::Testnet, Network::Regtest));
    out
}

fn build_tier2_vector(
    id: &str,
    net: Network,
    seed: [u8; SEED_BYTES],
    words: bool,
) -> serde_json::Value {
    let (master_seed, blob) = account_from_seed(&seed, net).expect("account_from_seed");
    let exp = blob_to_tier2_expected(&blob, &master_seed);
    let mut obj = serde_json::json!({
        "id": id,
        "tier": 2,
        "network": net.name(),
        "seed_hex": hex::encode(seed),
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
    if words {
        obj["mnemonic_words"] = serde_json::Value::String(
            bip39::mnemonic_from_entropy(&seed).expect("mnemonic_from_entropy"),
        );
    }
    obj
}

fn build_tier2_vectors() -> Vec<serde_json::Value> {
    // The all-zero and all-0x7f seeds are BIP-39 reference entropies, so
    // their word spellings are externally checkable; the oracle does so.
    let zero = [0u8; SEED_BYTES];
    vec![
        build_tier2_vector("mainnet_words_zero_seed", Network::Mainnet, zero, true),
        build_tier2_vector("testnet_zero_seed", Network::Testnet, zero, false),
        build_tier2_vector("stagenet_zero_seed", Network::Stagenet, zero, false),
        build_tier2_vector("regtest_zero_seed", Network::Regtest, zero, false),
        build_tier2_vector(
            "mainnet_seed_55",
            Network::Mainnet,
            [0x55; SEED_BYTES],
            false,
        ),
        build_tier2_vector(
            "regtest_words_seed_7f",
            Network::Regtest,
            [0x7f; SEED_BYTES],
            true,
        ),
    ]
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/ADDRESS_DERIVATION_V3")
}

/// Regenerates the on-disk corpus. Armed: it refuses unless
/// `SHEKYL_PINNED_REGEN_DECISION` cites the decision-log entry that moved
/// the derivation. Everything is derived from fixed inputs, so a rerun with
/// nothing changed rewrites the files byte-identically.
#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn kat_regenerate_address_derivation_v3() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let decision =
        shekyl_crypto_pq::test_support::regen_decision_or_refuse("ADDRESS_DERIVATION_V3");

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
            "Tier-1/Tier-2 vectors for ADDRESS_DERIVATION_V3: seed (32 bytes, every",
            "network) -> normalize_seed -> HKDF-SHA-512 under salt_for(net) =",
            "name_id(net) || 'shekyl-master-derive-v3' (NETWORK_IDENTITY.md",
            "NI-R7, NI-R10). Tier-1 pins the intermediate steps on all four",
            "networks; Tier-2 pins whole accounts from account_from_seed, and from",
            "account_from_words where mnemonic_words is present (words and bytes",
            "give the same wallet), re-checked through rederive_account.",
            "vectors_sha256_hex covers the exact on-disk bytes of vectors.json",
            "(verify with `sha256sum vectors.json`).",
            "",
            "Oracles (rule 50): see oracle_independent and oracle_self_pinned.",
            "The independent values are recomputed by",
            "scripts/kat/address_derivation_v3_oracle.py (stdlib Python, RFC 5869",
            "by hand), run in CI by docs-gates.yml. ML-KEM keygen uses",
            "fips203 =0.4.3 with the SHA3-ChaCha intermediary (account.rs)."
        ],
        "derivation_version": DERIVATION_VERSION,
        "fips203_pin": "=0.4.3",
        "oracle_independent": [
            "tier1 salt_for.salt_hex",
            "tier1 normalize_seed.master_seed_hex",
            "tier1 derive_spend_wide / derive_view_wide / derive_kem_d_z .wide_hex",
            "tier1 derive_spend_wide / derive_view_wide .scalar_hex",
            "tier1 ml_kem_chacha_seed.chacha_seed_hex",
            "tier1 network_separation.spend_sk_a_hex / spend_sk_b_hex",
            "tier2 master_seed_hex, spend_sk_hex, view_sk_hex",
            "tier2 spend_pk_hex, view_pk_hex (Ed25519 base-point multiplication)",
            "tier2 x25519_pk_hex (Edwards-to-Montgomery map of view_pk), and the first 32 bytes of pqc_public_key_hex",
            "tier2 classical_address_bytes_hex first 65 bytes (version 0x01 || spend_pk || view_pk)",
            "tier2 mnemonic_words <-> seed_hex (published BIP-39 reference vectors)"
        ],
        "oracle_self_pinned": [
            "tier2 ml_kem_ek_hex, ml_kem_dk_hex, and the ML-KEM suffix of pqc_public_key_hex (fips203 keygen)",
            "tier2 classical_address_bytes_hex bytes 65.. (the SLH-DSA-192s message-signing public key)"
        ],
        "regeneration_decision": decision,
        "regeneration_note": "Re-recorded from ADDRESS_DERIVATION_V2 by the V3_WALLET_DECISION_LOG.md entry of 2026-11-03 (One secret, one derivation): the seed format and passphrase leave the derivation, and the salt binds the network's name.",
        "vectors_sha256_hex": hex::encode(vectors_hash),
        "regeneration_command": "SHEKYL_PINNED_REGEN_DECISION=\"YYYY-MM-DD <rationale>\" cargo test -p shekyl-crypto-pq --test kat_address_derivation_v3 kat_regenerate_address_derivation_v3 -- --ignored --nocapture",
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

    eprintln!("regenerated under decision: {decision}");
    eprintln!("wrote {}", vectors_path.display());
    eprintln!("wrote {}", manifest_path.display());
    eprintln!("vectors_sha256_hex = {}", hex::encode(vectors_hash));
    eprintln!(
        "corpus_sha256_hex (manifest+vectors on-disk) = {}",
        hex::encode(corpus_hash)
    );
    eprintln!("update ADDRESS_DERIVATION_MANIFEST_HASH in address_derivation_freeze.rs");
}
