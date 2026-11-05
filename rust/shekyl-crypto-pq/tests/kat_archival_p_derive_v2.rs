// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tier-1/Tier-2 vectors for the frozen ARCHIVAL_P_DERIVE_V2 pipeline:
//! `ARCHIVAL_P_DERIVE_V1`'s labels, info strings and key constructions,
//! under the salt `salt_for(net)` = `name_id(net)` ‖
//! `shekyl-master-derive-v3`, with no seed format (`NETWORK_IDENTITY.md`
//! NI-R7, NI-R10; `V3_WALLET_DECISION_LOG.md`, 2026-11-03 and 2026-11-04).
//!
//! Corpus: `docs/test_vectors/ARCHIVAL_P_DERIVE_V2/{manifest.json,vectors.json}`.
//!
//! # Oracle, per value (rule 50)
//!
//! Independent: every Tier-1 HKDF output (each label, `LABEL ‖ 0x00 ‖
//! p_slot_le32`), the `hs_id` Ed25519 public keys (RFC 8032 keygen), and the
//! Tier-2 payment scalars and their Ed25519/X25519 public keys are
//! recomputed from the vectors' inputs by
//! `scripts/kat/address_derivation_v3_oracle.py`, which CI runs in
//! `docs-gates.yml`. Self-pinned (drift tripwire only): the ML-KEM-768,
//! ML-DSA-65 and FN-DSA-1024 key material, the hybrid keys built from it,
//! `slot_separation` (hybrid public keys) and `p_canonical_id`.
//!
//! Regenerating is a decision, not a command; the regenerator refuses
//! unless the invocation cites the decision-log entry:
//!
//! ```text
//! SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
//!   cargo test -p shekyl-crypto-pq --test kat_archival_p_derive_v2 \
//!   kat_regenerate_archival_p_derive_v2 -- --ignored --nocapture
//! ```
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
use shekyl_crypto_pq::account::{Network, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{
    derive_archival_p_keys, derive_p_account_sign_seed, derive_p_bond_spend_ed_seed,
    derive_p_bond_spend_ml_dsa_seed, derive_p_hs_id_seed, derive_p_kem_d_z, derive_p_ml_dsa_seed,
    derive_p_receipt_ed_seed, derive_p_receipt_fn_dsa_seed, derive_p_spend_wide,
    derive_p_view_wide, ArchivalPKeys,
};
use shekyl_crypto_pq::archival_p_freeze::archival_p_derive_manifest_self_check;

const MANIFEST_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V2/manifest.json");
const VECTORS_JSON: &str =
    include_str!("../../../docs/test_vectors/ARCHIVAL_P_DERIVE_V2/vectors.json");

/// cSHAKE256 customization for the archival principal identity (mirrors
/// `shekyl-archival-retention::id::P_CANONICAL_ID_CUSTOMIZATION`).
const P_CANONICAL_ID_CUSTOMIZATION: &[u8] = b"shekyl/archival-p-id-v1";

/// The manifest's `derivation_version`: the corpus version and the salt it
/// was derived under.
const DERIVATION_VERSION: &str = "v2 (salt name_id(net) || shekyl-master-derive-v3)";

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
    p_slot: u32,
    #[serde(default)]
    p_slot_b: Option<u32>,
    /// Second network for `*_network_separation` kinds (varies only `net`).
    #[serde(default)]
    network_b: Option<String>,
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
    receipt_sign_pk_hex: String,
    p_canonical_id_hex: String,
    spend_sk_hex: String,
    view_sk_hex: String,
    ml_kem_dk_hex: String,
    hybrid_sign_sk_hex: String,
    bond_spend_sk_hex: String,
}

fn parse_network(s: &str) -> Network {
    Network::from_name(s).unwrap_or_else(|| panic!("unknown network: {s}"))
}

fn decode_master(s: &str) -> [u8; MASTER_SEED_BYTES] {
    let bytes = hex::decode(s).expect("master_seed hex");
    assert_eq!(bytes.len(), MASTER_SEED_BYTES, "master_seed length");
    let mut out = [0u8; MASTER_SEED_BYTES];
    out.copy_from_slice(&bytes);
    out
}

/// Both values are pinned, and they are not the same value. `differ` names
/// why a collapse is a bug: `"labels must differ"`, `"networks must differ"`,
/// `"slots must differ"`.
fn assert_pinned_pair(id: &str, a: &[u8], b: &[u8], exp_a: &str, exp_b: &str, differ: &str) {
    let a_hex = hex::encode(a);
    let b_hex = hex::encode(b);
    assert_eq!(a_hex, exp_a, "{id} a");
    assert_eq!(b_hex, exp_b, "{id} b");
    assert_ne!(a_hex, b_hex, "{id} {differ}");
}

fn keys_for(v_network: &str, master_hex: &str, p_slot: u32) -> ArchivalPKeys {
    let net = parse_network(v_network);
    let master = decode_master(master_hex);
    derive_archival_p_keys(&master, net, p_slot).expect("derive_archival_p_keys")
}

fn run_tier1(v: &Tier1Vector) {
    let net = parse_network(&v.network);
    let master = decode_master(&v.master_seed_hex);

    match v.kind.as_str() {
        "spend_wide" | "view_wide" | "kem_d_z" => {
            let out = match v.kind.as_str() {
                "spend_wide" => derive_p_spend_wide(&master, net, v.p_slot),
                "view_wide" => derive_p_view_wide(&master, net, v.p_slot),
                "kem_d_z" => derive_p_kem_d_z(&master, net, v.p_slot),
                _ => unreachable!(),
            };
            let exp = v.expected.out_hex.as_deref().expect("out_hex");
            assert_eq!(hex::encode(out.as_slice()), exp, "{}", v.id);
        }
        "account_sign_seed"
        | "ml_dsa_seed"
        | "bond_spend_ed_seed"
        | "bond_spend_ml_dsa_seed"
        | "receipt_ed_seed"
        | "receipt_fn_dsa_seed"
        | "hs_id_seed" => {
            let out = match v.kind.as_str() {
                "account_sign_seed" => derive_p_account_sign_seed(&master, net, v.p_slot),
                "ml_dsa_seed" => derive_p_ml_dsa_seed(&master, net, v.p_slot),
                "bond_spend_ed_seed" => derive_p_bond_spend_ed_seed(&master, net, v.p_slot),
                "bond_spend_ml_dsa_seed" => derive_p_bond_spend_ml_dsa_seed(&master, net, v.p_slot),
                "receipt_ed_seed" => derive_p_receipt_ed_seed(&master, net, v.p_slot),
                "receipt_fn_dsa_seed" => derive_p_receipt_fn_dsa_seed(&master, net, v.p_slot),
                "hs_id_seed" => derive_p_hs_id_seed(&master, net, v.p_slot),
                _ => unreachable!(),
            };
            let exp = v.expected.out_hex.as_deref().expect("out_hex");
            assert_eq!(hex::encode(out.as_slice()), exp, "{}", v.id);

            // SH-2: the persona bundle now CARRIES `hs_id_seed` (the master is
            // gone after derivation under Model D, so "rederive on each serve"
            // is not reachable). Two producers of one value is exactly the
            // drift shape this file exists to stop, so the bundle's field is
            // asserted against the same pinned vector rather than trusted to
            // agree with the free function beside it.
            //
            // This is a bundle-shape check, not a frozen-surface one: no
            // label or vector exists for it beyond the pinned seed.
            if v.kind == "hs_id_seed" {
                let bundle = derive_archival_p_keys(&master, net, v.p_slot)
                    .expect("bundle derives for a pinned vector");
                assert_eq!(
                    hex::encode(bundle.hs_id_seed()),
                    exp,
                    "{}: bundle hs_id_seed diverged from the pinned vector",
                    v.id
                );
            }
        }
        "hs_id_pubkey" => {
            // The GF-9 serving key's Ed25519 PUBLIC key is the v3 `.onion`
            // address's public key. Pinning it (not just the seed) closes the
            // cross-arch gap that matters: a divergent bit here leaves an ARM
            // user's persona unreachable at its advertised `.onion`. The
            // seed→pubkey step is RFC 8032 keygen, exactly what tor applies.
            let seed = derive_p_hs_id_seed(&master, net, v.p_slot);
            let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            let exp = v.expected.out_hex.as_deref().expect("out_hex");
            assert_eq!(hex::encode(pk), exp, "{}", v.id);
        }
        "hs_id_label_separation" | "receipt_label_separation" | "label_separation" => {
            // Two seeds under one (seed, net, slot). hs-id vs account-sign:
            // the serving onion is not the on-chain identity. receipt vs
            // account-sign: scheme 3 shares no seed with the identity key.
            // label_separation: the GF-1 identity seed is not the bond-spend seed.
            let (a, b) = match v.kind.as_str() {
                "hs_id_label_separation" => (
                    derive_p_hs_id_seed(&master, net, v.p_slot),
                    derive_p_account_sign_seed(&master, net, v.p_slot),
                ),
                "receipt_label_separation" => (
                    derive_p_receipt_ed_seed(&master, net, v.p_slot),
                    derive_p_account_sign_seed(&master, net, v.p_slot),
                ),
                "label_separation" => (
                    derive_p_account_sign_seed(&master, net, v.p_slot),
                    derive_p_bond_spend_ed_seed(&master, net, v.p_slot),
                ),
                _ => unreachable!(),
            };
            assert_pinned_pair(
                &v.id,
                a.as_slice(),
                b.as_slice(),
                v.expected.out_a_hex.as_deref().expect("out_a_hex"),
                v.expected.out_b_hex.as_deref().expect("out_b_hex"),
                "labels must differ",
            );
        }
        "hs_id_network_separation" | "receipt_network_separation" => {
            // The salt is `salt_for(net)`. The inequality is a live
            // computation, so dropping `net` fails here even if the corpus is
            // rebuilt around the new bytes. One wallet must not serve at the
            // same `.onion`, or hold the same receipt key, on two networks.
            let net_b = parse_network(v.network_b.as_deref().expect("network_b"));
            let (a, b) = match v.kind.as_str() {
                "hs_id_network_separation" => (
                    derive_p_hs_id_seed(&master, net, v.p_slot),
                    derive_p_hs_id_seed(&master, net_b, v.p_slot),
                ),
                "receipt_network_separation" => (
                    derive_p_receipt_fn_dsa_seed(&master, net, v.p_slot),
                    derive_p_receipt_fn_dsa_seed(&master, net_b, v.p_slot),
                ),
                _ => unreachable!(),
            };
            assert_pinned_pair(
                &v.id,
                a.as_slice(),
                b.as_slice(),
                v.expected.out_a_hex.as_deref().expect("out_a_hex"),
                v.expected.out_b_hex.as_deref().expect("out_b_hex"),
                "networks must differ",
            );
        }
        "slot_separation" => {
            // Same inputs, two p_slots: identity keys must differ.
            let p_slot_b = v.p_slot_b.expect("p_slot_b");
            let a = derive_archival_p_keys(&master, net, v.p_slot).unwrap();
            let b = derive_archival_p_keys(&master, net, p_slot_b).unwrap();
            assert_pinned_pair(
                &v.id,
                &a.hybrid_sign_pk.to_canonical_bytes().unwrap(),
                &b.hybrid_sign_pk.to_canonical_bytes().unwrap(),
                v.expected.out_a_hex.as_deref().expect("out_a_hex"),
                v.expected.out_b_hex.as_deref().expect("out_b_hex"),
                "slots must differ",
            );
        }
        other => panic!("unknown tier1 kind: {other}"),
    }
}

fn run_tier2(v: &Tier2Vector) {
    let k = keys_for(&v.network, &v.master_seed_hex, v.p_slot);
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
    // The receipt key's secret half has no encoding by design; it is pinned
    // through the two Tier-1 seeds it is generated from and through this
    // public half, which is what the bond record will carry.
    assert_eq!(
        hex::encode(k.receipt_sign_pk.to_canonical_bytes()),
        e.receipt_sign_pk_hex,
        "{} receipt_sign_pk",
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
fn kat_archival_p_derive_v2_vectors() {
    use sha2::{Digest, Sha256};

    archival_p_derive_manifest_self_check().expect("corpus manifest hash pin");

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

    // Every network is covered at Tier 2 and by an `hs_id` row (rule 47:
    // the suite asserts its own subjects exist).
    for net in Network::ALL {
        assert!(
            file.tier2.iter().any(|v| v.network == net.name()),
            "no Tier-2 vector on {net}"
        );
        assert!(
            file.tier1
                .iter()
                .any(|v| v.kind == "hs_id_pubkey" && v.network == net.name()),
            "no hs_id_pubkey vector on {net}"
        );
    }
}

// ---------------------------------------------------------------------------
// Fixture regenerator (armed; run with --ignored)
// ---------------------------------------------------------------------------

const MASTER_33: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];
const MASTER_44: [u8; MASTER_SEED_BYTES] = [0x44u8; MASTER_SEED_BYTES];

fn hs_id_pubkey(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

fn row(
    id: &str,
    kind: &str,
    master: &[u8; MASTER_SEED_BYTES],
    net: Network,
    slot: u32,
    out: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "id": id, "kind": kind,
        "master_seed_hex": hex::encode(master), "network": net.name(),
        "p_slot": slot,
        "expected": { "out_hex": hex::encode(out) }
    })
}

fn pair(
    id: &str,
    kind: &str,
    net: Network,
    network_b: Option<Network>,
    slots: (u32, Option<u32>),
    out_a: &[u8],
    out_b: &[u8],
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "id": id, "kind": kind,
        "master_seed_hex": hex::encode(MASTER_33), "network": net.name(),
        "p_slot": slots.0,
        "expected": { "out_a_hex": hex::encode(out_a), "out_b_hex": hex::encode(out_b) }
    });
    if let Some(net_b) = network_b {
        v["network_b"] = serde_json::Value::String(net_b.name().to_string());
    }
    if let Some(slot_b) = slots.1 {
        v["p_slot_b"] = serde_json::Value::from(slot_b);
    }
    v
}

fn build_tier1_vectors() -> Vec<serde_json::Value> {
    let net = Network::Mainnet;
    let m = &MASTER_33;

    let spend = derive_p_spend_wide(m, net, 0);
    let view = derive_p_view_wide(m, net, 0);
    let kem = derive_p_kem_d_z(m, net, 0);
    let acct = derive_p_account_sign_seed(m, net, 0);
    let mldsa = derive_p_ml_dsa_seed(m, net, 0);
    let bond_ed = derive_p_bond_spend_ed_seed(m, net, 0);
    let bond_ml = derive_p_bond_spend_ml_dsa_seed(m, net, 0);
    let receipt_ed = derive_p_receipt_ed_seed(m, net, 0);
    let receipt_fn_dsa = derive_p_receipt_fn_dsa_seed(m, net, 0);
    let receipt_fn_dsa_net_b = derive_p_receipt_fn_dsa_seed(m, Network::Testnet, 0);
    let hs_id = derive_p_hs_id_seed(m, net, 0);

    let mut out = vec![
        row(
            "spend_wide_mainnet_slot0",
            "spend_wide",
            m,
            net,
            0,
            spend.as_slice(),
        ),
        row(
            "view_wide_mainnet_slot0",
            "view_wide",
            m,
            net,
            0,
            view.as_slice(),
        ),
        row(
            "kem_d_z_mainnet_slot0",
            "kem_d_z",
            m,
            net,
            0,
            kem.as_slice(),
        ),
        row(
            "account_sign_seed_mainnet_slot0",
            "account_sign_seed",
            m,
            net,
            0,
            acct.as_slice(),
        ),
        row(
            "ml_dsa_seed_mainnet_slot0",
            "ml_dsa_seed",
            m,
            net,
            0,
            mldsa.as_slice(),
        ),
        row(
            "bond_spend_ed_seed_mainnet_slot0",
            "bond_spend_ed_seed",
            m,
            net,
            0,
            bond_ed.as_slice(),
        ),
        row(
            "bond_spend_ml_dsa_seed_mainnet_slot0",
            "bond_spend_ml_dsa_seed",
            m,
            net,
            0,
            bond_ml.as_slice(),
        ),
        row(
            "receipt_ed_seed_mainnet_slot0",
            "receipt_ed_seed",
            m,
            net,
            0,
            receipt_ed.as_slice(),
        ),
        row(
            "receipt_fn_dsa_seed_mainnet_slot0",
            "receipt_fn_dsa_seed",
            m,
            net,
            0,
            receipt_fn_dsa.as_slice(),
        ),
        row(
            "hs_id_seed_mainnet_slot0",
            "hs_id_seed",
            m,
            net,
            0,
            hs_id.as_slice(),
        ),
        row(
            "hs_id_pubkey_mainnet_slot0",
            "hs_id_pubkey",
            m,
            net,
            0,
            &hs_id_pubkey(&hs_id),
        ),
    ];

    // `hs_id` is network-scoped like every sibling (salt = salt_for(net)),
    // but it is *not* an `ArchivalPKeys` field, so Tier-2's network matrix
    // does not reach it: these rows pin it on the other three networks, at
    // the Tier-2 rows' (master, slot) pairs.
    for (net, master, slot) in [
        (Network::Testnet, &MASTER_44, 0),
        (Network::Stagenet, &MASTER_33, 3),
        (Network::Regtest, &MASTER_44, 2),
    ] {
        let seed = derive_p_hs_id_seed(master, net, slot);
        let name = net.name();
        out.push(row(
            &format!("hs_id_seed_{name}_slot{slot}"),
            "hs_id_seed",
            master,
            net,
            slot,
            seed.as_slice(),
        ));
        out.push(row(
            &format!("hs_id_pubkey_{name}_slot{slot}"),
            "hs_id_pubkey",
            master,
            net,
            slot,
            &hs_id_pubkey(&seed),
        ));
    }

    let hs_id_testnet = derive_p_hs_id_seed(m, Network::Testnet, 0);
    let hs_id_stagenet = derive_p_hs_id_seed(m, Network::Stagenet, 0);
    let hs_id_regtest = derive_p_hs_id_seed(m, Network::Regtest, 0);
    let slot0 = derive_archival_p_keys(m, net, 0).unwrap();
    let slot7 = derive_archival_p_keys(m, net, 7).unwrap();

    out.extend([
        pair(
            "hs_id_network_separation_mainnet_vs_testnet",
            "hs_id_network_separation",
            Network::Mainnet,
            Some(Network::Testnet),
            (0, None),
            hs_id.as_slice(),
            hs_id_testnet.as_slice(),
        ),
        pair(
            "hs_id_network_separation_stagenet_vs_regtest",
            "hs_id_network_separation",
            Network::Stagenet,
            Some(Network::Regtest),
            (0, None),
            hs_id_stagenet.as_slice(),
            hs_id_regtest.as_slice(),
        ),
        pair(
            "hs_id_label_separation_hs_id_vs_account_sign",
            "hs_id_label_separation",
            net,
            None,
            (0, None),
            hs_id.as_slice(),
            acct.as_slice(),
        ),
        pair(
            "receipt_network_separation_mainnet_vs_testnet",
            "receipt_network_separation",
            Network::Mainnet,
            Some(Network::Testnet),
            (0, None),
            receipt_fn_dsa.as_slice(),
            receipt_fn_dsa_net_b.as_slice(),
        ),
        pair(
            "receipt_label_separation_receipt_vs_account_sign",
            "receipt_label_separation",
            net,
            None,
            (0, None),
            receipt_ed.as_slice(),
            acct.as_slice(),
        ),
        pair(
            "slot_separation_slot0_vs_slot7",
            "slot_separation",
            net,
            None,
            (0, Some(7)),
            &slot0.hybrid_sign_pk.to_canonical_bytes().unwrap(),
            &slot7.hybrid_sign_pk.to_canonical_bytes().unwrap(),
        ),
        pair(
            "label_separation_account_sign_vs_bond_spend_ed",
            "label_separation",
            net,
            None,
            (0, None),
            acct.as_slice(),
            bond_ed.as_slice(),
        ),
    ]);
    out
}

fn build_tier2_vector(
    id: &str,
    net: Network,
    master: &[u8; MASTER_SEED_BYTES],
    p_slot: u32,
) -> serde_json::Value {
    let k = derive_archival_p_keys(master, net, p_slot).unwrap();
    serde_json::json!({
        "id": id,
        "network": net.name(),
        "master_seed_hex": hex::encode(master),
        "p_slot": p_slot,
        "expected": {
            "spend_pk_hex": hex::encode(k.spend_pk.as_canonical_bytes()),
            "view_pk_hex": hex::encode(k.view_pk.as_canonical_bytes()),
            "x25519_pk_hex": hex::encode(k.x25519_pk),
            "ml_kem_ek_hex": hex::encode(k.ml_kem_ek),
            "hybrid_sign_pk_hex": hex::encode(k.hybrid_sign_pk.to_canonical_bytes().unwrap()),
            "bond_spend_pk_hex": hex::encode(k.bond_spend_pk.to_canonical_bytes().unwrap()),
            "receipt_sign_pk_hex": hex::encode(k.receipt_sign_pk.to_canonical_bytes()),
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
        build_tier2_vector("mainnet_slot0", Network::Mainnet, &MASTER_33, 0),
        build_tier2_vector("mainnet_slot7", Network::Mainnet, &MASTER_33, 7),
        build_tier2_vector("testnet_slot0", Network::Testnet, &MASTER_44, 0),
        build_tier2_vector("stagenet_slot3", Network::Stagenet, &MASTER_33, 3),
        build_tier2_vector("regtest_slot2", Network::Regtest, &MASTER_44, 2),
    ]
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test_vectors/ARCHIVAL_P_DERIVE_V2")
}

/// Regenerates the on-disk corpus. Armed: it refuses unless
/// `SHEKYL_PINNED_REGEN_DECISION` cites the decision-log entry that moved
/// the derivation. Everything is derived from fixed inputs, so a rerun with
/// nothing changed rewrites the files byte-identically.
#[test]
#[ignore = "armed fixture regenerator; requires SHEKYL_PINNED_REGEN_DECISION"]
fn kat_regenerate_archival_p_derive_v2() {
    use sha2::{Digest, Sha256};
    use std::fs;

    let decision = shekyl_crypto_pq::test_support::regen_decision_or_refuse("ARCHIVAL_P_DERIVE_V2");

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
            "Tier-1/Tier-2 vectors for ARCHIVAL_P_DERIVE_V2: ARCHIVAL_P_DERIVE_V1's",
            "labels and info strings (LABEL || 0x00 || p_slot_le32) under the salt",
            "salt_for(net) = name_id(net) || 'shekyl-master-derive-v3', with",
            "no seed format (NETWORK_IDENTITY.md NI-R7, NI-R10). Tier-1 pins the",
            "per-label HKDF outputs, the hs_id public key on all four networks, and",
            "the label/network/slot separation properties; Tier-2 pins whole",
            "ArchivalPKeys bundles on all four networks plus p_canonical_id",
            "(inline cSHAKE256). vectors_sha256_hex covers the exact on-disk bytes",
            "of vectors.json (verify with `sha256sum vectors.json`).",
            "Belongs on the aarch64 qemu lane: a divergent bit means an ARM user",
            "cannot recover a bond.",
            "",
            "Oracles (rule 50): see oracle_independent and oracle_self_pinned.",
            "The independent values are recomputed by",
            "scripts/kat/address_derivation_v3_oracle.py (stdlib Python, RFC 5869",
            "by hand), run in CI by docs-gates.yml."
        ],
        "derivation_version": DERIVATION_VERSION,
        "fips203_pin": "=0.4.3",
        "fn_dsa_pin": "=0.4.0",
        "oracle_independent": [
            "tier1 every single-output kind's out_hex (HKDF-SHA-512 per label)",
            "tier1 hs_id_pubkey.out_hex (RFC 8032 keygen of the HKDF seed)",
            "tier1 *_network_separation / *_label_separation out_a_hex / out_b_hex",
            "tier2 spend_sk_hex, view_sk_hex (HKDF then reduction mod l)",
            "tier2 spend_pk_hex, view_pk_hex (Ed25519 base-point multiplication)",
            "tier2 x25519_pk_hex (Edwards-to-Montgomery map of view_pk)"
        ],
        "oracle_self_pinned": [
            "tier1 slot_separation (hybrid Ed25519 + ML-DSA-65 public keys)",
            "tier2 ml_kem_ek_hex, ml_kem_dk_hex (fips203 keygen)",
            "tier2 hybrid_sign_pk_hex, hybrid_sign_sk_hex, bond_spend_pk_hex, bond_spend_sk_hex (ML-DSA-65 halves)",
            "tier2 receipt_sign_pk_hex (FN-DSA-1024 half)",
            "tier2 p_canonical_id_hex (cSHAKE256 of the hybrid identity key; cross-checked against shekyl-archival-retention's id.rs, not against an outside implementation)"
        ],
        "regeneration_decision": decision,
        "regeneration_note": "Re-recorded from ARCHIVAL_P_DERIVE_V1 by the V3_WALLET_DECISION_LOG.md entry of 2026-11-03 (One secret, one derivation): the labels are unchanged; the salt drops the seed format and binds the network's name.",
        "vectors_sha256_hex": hex::encode(vectors_hash),
        "regeneration_command": "SHEKYL_PINNED_REGEN_DECISION=\"YYYY-MM-DD <rationale>\" cargo test -p shekyl-crypto-pq --test kat_archival_p_derive_v2 kat_regenerate_archival_p_derive_v2 -- --ignored --nocapture",
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

    eprintln!("regenerated under decision: {decision}");
    eprintln!("wrote {}", vectors_path.display());
    eprintln!("wrote {}", manifest_path.display());
    eprintln!("vectors_sha256_hex = {}", hex::encode(vectors_hash));
    eprintln!(
        "corpus_sha256_hex (manifest+vectors on-disk) = {}",
        hex::encode(corpus_hash)
    );
    eprintln!("update ARCHIVAL_P_DERIVE_MANIFEST_HASH in archival_p_freeze.rs");
}
