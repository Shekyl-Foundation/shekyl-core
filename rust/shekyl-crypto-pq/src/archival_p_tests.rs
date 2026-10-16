// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

const MASTER: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

fn keys() -> ArchivalPKeys {
    derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0)
        .expect("derive P keys")
}

/// The identity-only fast path is byte-identical to the full bundle's
/// `hybrid_bond_id` — same KDF labels, same build, no new domain. This
/// bites against either path changing its seed derivation alone (the
/// probe cache and the resident actor would then disagree on a persona's
/// public id and the bond watch would sight nothing).
#[test]
fn identity_pk_matches_the_full_bundle() {
    for slot in [0u32, 1, 7, 4_000_000] {
        let full =
            derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, slot)
                .expect("full bundle");
        let fast = derive_archival_p_identity_pk(
            &MASTER,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            slot,
        )
        .expect("identity-only");
        assert_eq!(
            fast.to_canonical_bytes().expect("encode fast"),
            full.hybrid_bond_id()
                .to_canonical_bytes()
                .expect("encode full"),
            "slot {slot}: identity-only derivation diverged from the bundle"
        );
    }
}

/// The identity-only path keeps the permitted-seed-format gate.
#[test]
fn identity_pk_refuses_a_forbidden_seed_format() {
    assert!(derive_archival_p_identity_pk(
        &MASTER,
        DerivationNetwork::Mainnet,
        SeedFormat::Raw32,
        0
    )
    .is_err());
}

#[test]
fn derivation_is_deterministic() {
    let a = keys();
    let b = keys();
    assert_eq!(
        a.hybrid_sign_pk.to_canonical_bytes().unwrap(),
        b.hybrid_sign_pk.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        a.bond_spend_pk.to_canonical_bytes().unwrap(),
        b.bond_spend_pk.to_canonical_bytes().unwrap()
    );
    assert_eq!(
        a.spend_pk.as_canonical_bytes(),
        b.spend_pk.as_canonical_bytes()
    );
}

#[test]
fn hybrid_bond_id_is_the_identity_key() {
    let k = keys();
    assert_eq!(
        k.hybrid_bond_id().to_canonical_bytes().unwrap(),
        k.hybrid_sign_pk.to_canonical_bytes().unwrap(),
        "hybrid_bond_id must equal hybrid_sign_pk (§9.4)"
    );
}

/// GF-1-carve independence: the identity key, the debit authorizer, and the
/// address spend key are derived under distinct labels and must be distinct
/// keys. A future label-drift that collapsed two of them would trip here.
#[test]
fn identity_debit_and_address_keys_are_independent() {
    let k = keys();
    assert_ne!(
        k.hybrid_sign_pk.ed25519, k.bond_spend_pk.ed25519,
        "identity and bond-spend Ed25519 halves must differ"
    );
    assert_ne!(
        k.hybrid_sign_pk.ml_dsa, k.bond_spend_pk.ml_dsa,
        "identity and bond-spend ML-DSA halves must differ"
    );
    // The identity Ed25519 half is a dedicated seed, NOT the address spend
    // pubkey — the privacy property the §9.3 resolution establishes.
    assert_ne!(
        &k.hybrid_sign_pk.ed25519,
        k.spend_pk.as_canonical_bytes(),
        "identity Ed25519 must not equal the address spend pubkey (privacy)"
    );
}

/// Label-sensitivity negative: wrong label → wrong key. This proves the
/// GF-1-carve independence is delivered by domain separation in the HKDF
/// `info`, not merely asserted — the standoff-trap discipline applied to
/// label drift. A change to any label string flips the derived bytes.
#[test]
fn wrong_label_yields_different_key() {
    // Same (seed, net, fmt, slot); only the label differs.
    let account = p_expand_32(
        &MASTER,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        ARCHIVAL_P_ACCOUNT_SIGN_INFO,
        0,
    );
    let bond = p_expand_32(
        &MASTER,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        ARCHIVAL_P_BOND_SPEND_ED_INFO,
        0,
    );
    assert_ne!(
        account.as_slice(),
        bond.as_slice(),
        "distinct labels must give distinct seeds"
    );

    // A one-byte label perturbation must also diverge.
    let mut tweaked = ARCHIVAL_P_ACCOUNT_SIGN_INFO.to_vec();
    let last = tweaked.len() - 1;
    tweaked[last] ^= 0x01;
    let perturbed = p_expand_32(
        &MASTER,
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        &tweaked,
        0,
    );
    assert_ne!(
        account.as_slice(),
        perturbed.as_slice(),
        "a 1-byte label change must change the seed"
    );

    // GF-9 serving key is a distinct label from the identity account-sign seed:
    // the two L=32 Ed25519 seeds under the same (seed, net, fmt, slot) must
    // differ, or the serving `.onion` would leak the on-chain identity key.
    let hs_id = derive_p_hs_id_seed(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0);
    assert_ne!(
        account.as_slice(),
        hs_id.as_slice(),
        "hs-id serving seed must differ from the identity account-sign seed"
    );
}

/// `p_slot` separation: distinct slots derive distinct personas.
#[test]
fn distinct_slots_yield_distinct_personas() {
    let k0 =
        derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0).unwrap();
    let k1 =
        derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 1).unwrap();
    assert_ne!(
        k0.hybrid_sign_pk.to_canonical_bytes().unwrap(),
        k1.hybrid_sign_pk.to_canonical_bytes().unwrap()
    );
    assert_ne!(
        k0.spend_pk.as_canonical_bytes(),
        k1.spend_pk.as_canonical_bytes()
    );
}

/// Recovery: a wallet restored from its seed holds the receipt key the
/// bond record names. A receipt signed before the restore verifies under
/// the public half derived after it, and the derivation is the one the
/// two seed functions and the scheme's seeded key generation compose to.
#[test]
fn receipt_key_recovers_from_the_seed() {
    use crate::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT};

    let before = keys();
    let after = keys();
    assert_eq!(before.receipt_sign_pk, after.receipt_sign_pk);

    let transcript = [0x5a_u8; 112];
    let receipt = HybridEd25519FnDsa
        .sign(&before.receipt_sign_sk, SCHEME_DOMAIN_RECEIPT, &transcript)
        .expect("the receipt key signs");
    HybridEd25519FnDsa
        .verify(
            &after.receipt_sign_pk,
            SCHEME_DOMAIN_RECEIPT,
            &transcript,
            &receipt,
        )
        .expect("a receipt made before a restore verifies after it");

    let ed = derive_p_receipt_ed_seed(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0);
    let fn_dsa =
        derive_p_receipt_fn_dsa_seed(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 0);
    let (composed, _) =
        HybridEd25519FnDsa::keypair_from_seeds(&ed, &fn_dsa).expect("seeded keygen");
    assert_eq!(
        composed, before.receipt_sign_pk,
        "the bundle's receipt key is the two labelled seeds through seeded keygen"
    );
}

/// The receipt key is per slot and per network, as every sibling is: a
/// persona's receipts link to no other persona of the wallet, and the
/// same wallet's receipt key on stagenet is not its key on mainnet.
#[test]
fn receipt_key_is_scoped_to_slot_and_network() {
    let here = keys();
    let other_slot =
        derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Bip39, 1)
            .expect("slot 1");
    let other_net =
        derive_archival_p_keys(&MASTER, DerivationNetwork::Stagenet, SeedFormat::Bip39, 0)
            .expect("stagenet");
    let other_seed = derive_archival_p_keys(
        &[0x34u8; MASTER_SEED_BYTES],
        DerivationNetwork::Mainnet,
        SeedFormat::Bip39,
        0,
    )
    .expect("another wallet");
    for (what, other) in [
        ("slot", &other_slot),
        ("network", &other_net),
        ("seed", &other_seed),
    ] {
        assert_ne!(
            here.receipt_sign_pk, other.receipt_sign_pk,
            "a different {what} must give a different receipt key"
        );
    }
}

/// Algorithm isolation (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §6.3): the
/// receipt key shares no seed with the identity key, the bond-spend key
/// or the onion identity. Its Ed25519 half is the one place a shared seed
/// would show as equal public bytes.
#[test]
fn receipt_key_shares_no_seed_with_its_siblings() {
    let net = DerivationNetwork::Mainnet;
    let fmt = SeedFormat::Bip39;
    let receipt_ed = derive_p_receipt_ed_seed(&MASTER, net, fmt, 0);
    let receipt_fn_dsa = derive_p_receipt_fn_dsa_seed(&MASTER, net, fmt, 0);
    assert_ne!(receipt_ed.as_slice(), receipt_fn_dsa.as_slice());
    for (what, sibling) in [
        (
            "account-sign",
            derive_p_account_sign_seed(&MASTER, net, fmt, 0),
        ),
        ("ml-dsa", derive_p_ml_dsa_seed(&MASTER, net, fmt, 0)),
        (
            "bond-spend ed25519",
            derive_p_bond_spend_ed_seed(&MASTER, net, fmt, 0),
        ),
        (
            "bond-spend ml-dsa",
            derive_p_bond_spend_ml_dsa_seed(&MASTER, net, fmt, 0),
        ),
        ("hs-id", derive_p_hs_id_seed(&MASTER, net, fmt, 0)),
    ] {
        assert_ne!(
            receipt_ed.as_slice(),
            sibling.as_slice(),
            "receipt ed25519 vs {what}"
        );
        assert_ne!(
            receipt_fn_dsa.as_slice(),
            sibling.as_slice(),
            "receipt fn-dsa vs {what}"
        );
    }

    let k = keys();
    let receipt_ed_pk = SigningKey::from_bytes(&receipt_ed)
        .verifying_key()
        .to_bytes();
    assert_ne!(receipt_ed_pk, k.hybrid_sign_pk.ed25519);
    assert_ne!(receipt_ed_pk, k.bond_spend_pk.ed25519);
    assert_ne!(&receipt_ed_pk, k.spend_pk.as_canonical_bytes());
}

/// The frozen info-string layout: `LABEL ‖ 0x00 ‖ p_slot_le32`.
#[test]
fn info_string_layout_is_frozen() {
    let info = p_info(ARCHIVAL_P_SPEND_INFO, 0x0403_0201);
    let mut expected = ARCHIVAL_P_SPEND_INFO.to_vec();
    expected.push(0x00);
    expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(info, expected);
}

/// The seed format gate rejects an impermissible (network, format) pair.
#[test]
fn rejects_impermissible_seed_format() {
    let r = derive_archival_p_keys(&MASTER, DerivationNetwork::Mainnet, SeedFormat::Raw32, 0);
    assert!(r.is_err(), "mainnet must reject raw32");
}
