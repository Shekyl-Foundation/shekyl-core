// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Golden KATs for the deterministic genesis build (rule 30: pinned vectors).
//!
//! The fixture is five testnet recipients derived in-test from fixed raw-32
//! seeds (`[i; 32]`) — self-contained, no committed secrets, independent of
//! the real allocation files. The pins commit to the whole chain:
//! tx-key derivation → construct_output (deterministic KEM) → wire encoding
//! → extra ordering → tx hash → v9 block hash. Any drift in any layer fails
//! loudly here.

use sha2::{Digest, Sha256};
use shekyl_address::Network;
use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};
use shekyl_genesis_tool::builder::{build_genesis_tx, genesis_block};
use shekyl_genesis_tool::recipients::{parse_and_validate, Recipient};
use shekyl_genesis_tool::txkey::{derive_genesis_tx_secret, tx_pubkey};
use shekyl_wire::tx_extra::{self, TxExtraField, HYBRID_KEM_CT_BYTES, PQC_LEAF_HASH_BYTES};

/// Synthetic nonce for the block-id pin (testnet's real GENESIS_NONCE value,
/// but nothing here depends on the config).
const KAT_NONCE: u32 = 10101;

// --- pinned vectors (recaptured 2026-08-16: fork-(ii) address layout) ---
const KAT_TX_SECRET_HEX: &str = "2540c575756f712a0a72036a53a30a5bb460deff15a98e56d4775d165a744c06";
const KAT_TX_PUB_HEX: &str = "2a1386ec4b6065142492394c0406cf76e291f6355a5aac4694678aca62e0d460";
const KAT_BLOB_LEN: usize = 6263;
const KAT_BLOB_SHA256_HEX: &str =
    "f2600783b9833d358ac566d812f9932459231948dc2f58ffb8f872720d46a578";
const KAT_TX_HASH_HEX: &str = "875b38eaff2d853e69a206d33ecdad29282f81af7ec72700877af3896f281949";
const KAT_BLOCK_ID_HEX: &str = "3d5f6792e5bb020b1fef8e379f7799aedc9b7e4cc0459d52b41f6d31d1bb6716";
// ----------------------------------------------------------------------------

fn fixture_recipients() -> Vec<Recipient> {
    let entries: Vec<serde_json::Value> = (1..=5u8)
        .map(|i| {
            let seed = [i; 32];
            let (_master, blob) = generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
                .expect("fixture account");
            let address = blob
                .to_address(Network::Testnet)
                .encode()
                .expect("fixture address");
            serde_json::json!({
                "label": format!("KAT fixture {i}"),
                "address": address,
                "amount_atomic": 20_000_000_000_000u64,
            })
        })
        .collect();
    let body = serde_json::json!({ "network": "testnet", "recipients": entries }).to_string();
    parse_and_validate(&body, Network::Testnet).expect("fixture validates")
}

#[test]
fn golden_kat() {
    let recipients = fixture_recipients();

    let tx_secret = derive_genesis_tx_secret(Network::Testnet, &recipients);
    let tx_pub = tx_pubkey(&tx_secret);

    let built = build_genesis_tx(Network::Testnet, &recipients).expect("build");
    let blob = built.tx.serialize();
    let blob_sha256 = hex::encode(Sha256::digest(&blob));
    let block = genesis_block(built.tx, KAT_NONCE).expect("block");

    // Capture aid: on any mismatch the actual values are printed here.
    eprintln!("tx_secret      = {}", hex::encode(tx_secret));
    eprintln!("tx_pub         = {}", hex::encode(tx_pub));
    eprintln!("blob_len       = {}", blob.len());
    eprintln!("blob_sha256    = {blob_sha256}");
    eprintln!("tx_hash        = {}", hex::encode(built.tx_hash));
    eprintln!("block_id       = {}", hex::encode(block.hash()));

    assert_eq!(hex::encode(tx_secret), KAT_TX_SECRET_HEX, "tx secret drift");
    assert_eq!(hex::encode(tx_pub), KAT_TX_PUB_HEX, "tx pubkey drift");
    assert_eq!(blob.len(), KAT_BLOB_LEN, "serialized length drift");
    assert_eq!(blob_sha256, KAT_BLOB_SHA256_HEX, "serialized bytes drift");
    assert_eq!(hex::encode(built.tx_hash), KAT_TX_HASH_HEX, "tx hash drift");
    assert_eq!(
        hex::encode(block.hash()),
        KAT_BLOCK_ID_HEX,
        "block id drift"
    );
}

/// The network string is part of the derivation preimage: identical
/// recipients on different networks must yield different tx keys.
#[test]
fn txkey_domain_separation_by_network() {
    let recipients = fixture_recipients();
    let testnet = derive_genesis_tx_secret(Network::Testnet, &recipients);
    let mainnet = derive_genesis_tx_secret(Network::Mainnet, &recipients);
    let stagenet = derive_genesis_tx_secret(Network::Stagenet, &recipients);
    assert_ne!(testnet, mainnet);
    assert_ne!(testnet, stagenet);
    assert_ne!(mainnet, stagenet);
}

/// The emitted extra must be the C++ `sort_tx_extra` fixed point for the
/// genesis field subset: `0x01` pubkey, aggregated `0x06`, aggregated `0x07`
/// (pick order: `src/cryptonote_basic/cryptonote_format_utils.cpp`,
/// `sort_tx_extra`). If the field set ever grows, this test forces the
/// ordering question to be re-answered against the C++ sorter.
#[test]
fn extra_is_canonical_fixed_point() {
    let recipients = fixture_recipients();
    let tx_secret = derive_genesis_tx_secret(Network::Testnet, &recipients);
    let tx_pub = tx_pubkey(&tx_secret);
    let built = build_genesis_tx(Network::Testnet, &recipients).expect("build");

    let extra = &built.tx.prefix.extra;
    let fields = tx_extra::parse(extra).expect("extra parses");
    assert_eq!(fields.len(), 3, "genesis extra has exactly three fields");
    assert!(
        matches!(fields[0], TxExtraField::PubKey(k) if k == tx_pub),
        "field 0 must be the 0x01 tx pubkey"
    );
    assert!(
        matches!(&fields[1], TxExtraField::PqcKemCiphertext(b)
            if b.len() == recipients.len() * HYBRID_KEM_CT_BYTES),
        "field 1 must be the aggregated 0x06 KEM blob"
    );
    assert!(
        matches!(&fields[2], TxExtraField::PqcLeafHashes(b)
            if b.len() == recipients.len() * PQC_LEAF_HASH_BYTES),
        "field 2 must be the aggregated 0x07 leaf-hash blob"
    );
    // Raw byte anchors: tag 0x01 at offset 0, tag 0x06 right after the
    // 32-byte pubkey.
    assert_eq!(extra[0], tx_extra::TX_EXTRA_TAG_PUBKEY);
    assert_eq!(extra[33], tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT);
}
