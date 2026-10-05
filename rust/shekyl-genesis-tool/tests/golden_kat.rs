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
use shekyl_wire::tx_extra::{
    self, TxExtraField, COINBASE_NONCE_BYTES, HYBRID_KEM_CT_BYTES, PQC_LEAF_ENTRY_LEN,
};

/// Synthetic nonce for the block-id pin (testnet's real GENESIS_NONCE value,
/// but nothing here depends on the config).
const KAT_NONCE: u32 = 10101;

// --- pinned vectors (recaptured 2026-08-16: genesis-txkey-v2 payment identity) ---
const KAT_TX_SECRET_HEX: &str = "f5c1a3a255f52bdb04fe23448d941ed4ec70fea47a9eee658f4468f79617a602";
const KAT_TX_PUB_HEX: &str = "6e78259c37b956a355c36e67c72037279170d260a4ea0e6ebbc8c3a7d711eac1";
// Re-pinned 2026-09-23 with `TXE-Q6′` (`TX_EXTRA_RUST_CUTOVER.md` §6): the
// genesis extra gained the fixed 8-byte `0x02` nonce (eight zero bytes) after
// the pubkey, +10 bytes (tag ‖ length ‖ 8), so the blob, its sha256, the tx
// hash and the block id all moved. Before that, 2026-09-14 with `PL-D3`
// (`docs/V3_WALLET_DECISION_LOG.md`): the `0x07` field grew from 32 to 64
// bytes per output. tx secret / pubkey are unchanged by construction.
const KAT_BLOB_LEN: usize = 6433;
const KAT_BLOB_SHA256_HEX: &str =
    "cabd1da6890eb7711e541b34c3a1191b96b4aa2943f1d42cd4d6917143e86906";
const KAT_TX_HASH_HEX: &str = "0afa62002ecad8d04bdff18b6cdcab414796de6f1262f14f5c2308943c16434f";
const KAT_BLOCK_ID_HEX: &str = "87846edf0e1eaa567f9db3e904a66564b84baa9108b48b0ca2d03c949698b7b0";
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

/// The emitted extra is the coinbase grammar's one layout
/// (`check_coinbase_extra_shape`, `TXE-Q6′`): `0x01` pubkey, `0x02` nonce of
/// eight zero bytes, aggregated `0x06`, aggregated `0x07`. If the grammar
/// ever changes, this test forces the layout question to be re-answered
/// against the rule — and against `shekyl_coinbase_extra`, whose output the
/// C++ `mining_parity` test requires to reproduce these bytes exactly.
#[test]
fn extra_is_canonical_fixed_point() {
    let recipients = fixture_recipients();
    let tx_secret = derive_genesis_tx_secret(Network::Testnet, &recipients);
    let tx_pub = tx_pubkey(&tx_secret);
    let built = build_genesis_tx(Network::Testnet, &recipients).expect("build");

    let extra = &built.tx.prefix.extra;
    let fields = tx_extra::parse(extra).expect("extra parses");
    tx_extra::check_coinbase_extra_shape(&fields, recipients.len())
        .expect("genesis extra satisfies the coinbase grammar");
    assert_eq!(fields.len(), 4, "genesis extra has exactly four fields");
    assert!(
        matches!(fields[0], TxExtraField::PubKey(k) if k == tx_pub),
        "field 0 must be the 0x01 tx pubkey"
    );
    assert!(
        matches!(&fields[1], TxExtraField::Nonce(b) if *b == vec![0u8; COINBASE_NONCE_BYTES]),
        "field 1 must be the 0x02 nonce of eight zero bytes"
    );
    assert!(
        matches!(&fields[2], TxExtraField::PqcKemCiphertext(b)
            if b.len() == recipients.len() * HYBRID_KEM_CT_BYTES),
        "field 2 must be the aggregated 0x06 KEM blob"
    );
    assert!(
        matches!(&fields[3], TxExtraField::PqcLeafEntries(b)
            if b.len() == recipients.len() * PQC_LEAF_ENTRY_LEN),
        "field 3 must be the aggregated 0x07 leaf-entry blob"
    );
    // Raw byte anchors: tag 0x01 at offset 0; tag 0x02 and its length byte
    // right after the 32-byte pubkey; tag 0x06 after the eight nonce bytes.
    assert_eq!(extra[0], tx_extra::TX_EXTRA_TAG_PUBKEY);
    assert_eq!(extra[33], tx_extra::TX_EXTRA_TAG_NONCE);
    assert_eq!(extra[34] as usize, COINBASE_NONCE_BYTES);
    assert_eq!(extra[43], tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT);
}
