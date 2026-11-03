// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Golden KATs for the deterministic genesis build (rule 30: pinned vectors).
//!
//! The fixture is five testnet recipients derived in-test from fixed
//! 32-byte seeds (`[i; 32]`) — self-contained, no committed secrets, independent of
//! the real allocation files. The pins commit to the whole chain:
//! tx-key derivation → construct_output (deterministic KEM) → wire encoding
//! → extra ordering → tx hash → v9 block hash. Any drift in any layer fails
//! loudly here.

use sha2::{Digest, Sha256};
use shekyl_address::Network;
use shekyl_crypto_pq::account::account_from_seed;
use shekyl_genesis_tool::builder::{build_genesis_tx, genesis_block, GENESIS_DRAW_COMMITMENT};
use shekyl_genesis_tool::recipients::{parse_and_validate, Recipient};
use shekyl_genesis_tool::txkey::{derive_genesis_tx_secret, tx_pubkey};
use shekyl_wire::tx_extra::{
    self, TxExtraField, COINBASE_NONCE_BYTES, HYBRID_KEM_CT_BYTES, PQC_LEAF_ENTRY_LEN,
};

/// Synthetic nonce for the block-id pin. It was testnet's `GENESIS_NONCE`
/// until the nonce was rotated; nothing here depends on the config, so the
/// vector stays as recorded.
const KAT_NONCE: u32 = 10101;

// --- pinned vectors (recaptured 2026-08-16: genesis-txkey-v2 payment identity) ---
// Re-pinned 2026-11-03 with "One secret, one derivation" (NI-R7, NI-R10,
// `docs/V3_WALLET_DECISION_LOG.md`): the fixture recipients' keys are now
// `account_from_seed` under the v2 network salt, so their addresses moved, and
// with them every value below that commits to the recipients (the tx secret
// and pubkey, the serialized bytes, the tx hash, the block id). The length is
// unchanged: no layout moved.
const KAT_TX_SECRET_HEX: &str = "e52da8c2958981cf4c6055f605b96e06155dd9ad515a593ba54f132ffe297e05";
const KAT_TX_PUB_HEX: &str = "bd6eb2c7df7c87f60d3616ae89b46189626362ad3cbd0760928c0b2daee0cabc";
// Re-pinned 2026-10-11 with `SO-D12i` (`ARCHIVAL_SETTLEMENT_WRITER.md` §16.8):
// the genesis extra gained the `0x0C` draw commitment (32 zero bytes) after the
// nonce, +33 bytes (tag ‖ 32), so the blob, its sha256, the tx hash and the
// block id all moved. Before that, 2026-09-23 with `TXE-Q6′` (`TX_EXTRA_RUST_CUTOVER.md` §6): the
// genesis extra gained the fixed 8-byte `0x02` nonce (eight zero bytes) after
// the pubkey, +10 bytes (tag ‖ length ‖ 8), so the blob, its sha256, the tx
// hash and the block id all moved. Before that, 2026-09-14 with `PL-D3`
// (`docs/V3_WALLET_DECISION_LOG.md`): the `0x07` field grew from 32 to 64
// bytes per output. tx secret / pubkey were unchanged by those layout moves.
const KAT_BLOB_LEN: usize = 6466;
const KAT_BLOB_SHA256_HEX: &str =
    "c6f746ab4f138d466c03e3d27772de740b9a33d8885da7d52ae7badf04f12d3a";
const KAT_TX_HASH_HEX: &str = "b1d9360bc3d676699678af78eba140554b2e6afc9d5ffe2905bd1b4b95ec4f2b";
const KAT_BLOCK_ID_HEX: &str = "aa45634caf8a0e6c63f14a217d82c88296cbb10ec93c9474773ae27f66ded874";
// ----------------------------------------------------------------------------

fn fixture_recipients() -> Vec<Recipient> {
    let entries: Vec<serde_json::Value> = (1..=5u8)
        .map(|i| {
            let seed = [i; 32];
            let (_master, blob) =
                account_from_seed(&seed, Network::Testnet).expect("fixture account");
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
/// eight zero bytes, the `0x0C` draw commitment, aggregated `0x06`,
/// aggregated `0x07`. If the grammar
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
    assert_eq!(fields.len(), 5, "genesis extra has exactly five fields");
    assert!(
        matches!(fields[0], TxExtraField::PubKey(k) if k == tx_pub),
        "field 0 must be the 0x01 tx pubkey"
    );
    assert!(
        matches!(&fields[1], TxExtraField::Nonce(b) if *b == vec![0u8; COINBASE_NONCE_BYTES]),
        "field 1 must be the 0x02 nonce of eight zero bytes"
    );
    // The genesis commitment is the ruled 32 zero bytes, present as a field
    // like any other block's. This is the pin of the value; the grammar
    // above admitted it without reading it.
    assert_eq!(
        fields[2],
        TxExtraField::DrawCommitment(GENESIS_DRAW_COMMITMENT),
        "field 2 must be the 0x0C draw commitment genesis commits to"
    );
    assert_eq!(GENESIS_DRAW_COMMITMENT.as_bytes(), &[0u8; 32]);
    assert!(
        matches!(&fields[3], TxExtraField::PqcKemCiphertext(b)
            if b.len() == recipients.len() * HYBRID_KEM_CT_BYTES),
        "field 3 must be the aggregated 0x06 KEM blob"
    );
    assert!(
        matches!(&fields[4], TxExtraField::PqcLeafEntries(b)
            if b.len() == recipients.len() * PQC_LEAF_ENTRY_LEN),
        "field 4 must be the aggregated 0x07 leaf-entry blob"
    );
    // Raw byte anchors: tag 0x01 at offset 0; tag 0x02 and its length byte
    // right after the 32-byte pubkey; tag 0x0C after the eight nonce bytes;
    // tag 0x06 after the 32 commitment bytes.
    assert_eq!(extra[0], tx_extra::TX_EXTRA_TAG_PUBKEY);
    assert_eq!(extra[33], tx_extra::TX_EXTRA_TAG_NONCE);
    assert_eq!(extra[34] as usize, COINBASE_NONCE_BYTES);
    assert_eq!(extra[43], tx_extra::TX_EXTRA_TAG_DRAW_COMMITMENT);
    assert_eq!(extra[76], tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT);
}
