// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The genesis block ids, derived in pure Rust from the pinned `GENESIS_TX`
//! and `GENESIS_NONCE` of each network, against the published pins.
//!
//! This is the pin the C++ `mining_parity.genesis_identity_is_pow_independent`
//! held: it assembled each network's genesis through `generate_genesis_block`
//! and froze the block id. That constructor was deleted with the C++ chain
//! (DRS-X); the Rust owner is [`genesis_block`], the same assembly
//! (`shekyl-genesis-tool`'s `geblock block-id`). The genesis block is mined at
//! difficulty 1, so the pinned nonce stands verbatim and the id is
//! Keccak(serialized header): PoW-independent.
//!
//! The three literals are the ones `shekyl-rpc-types`' `identity.rs` serves
//! to clients and `docs/GENESIS_ALLOCATIONS.md` publishes; the mainnet id is
//! also derived from the captured h0 blob by
//! `shekyl-wire/tests/coinbase_hash.rs` (`MAINNET_GENESIS_BLOCK_ID`). A
//! legitimate pre-genesis remint moves `GENESIS_TX`, these literals and
//! `identity.rs` in the same change.

use std::path::PathBuf;

use shekyl_address::Network;
use shekyl_genesis_tool::builder::genesis_block;
use shekyl_genesis_tool::config_pin::load_config_pins;
use shekyl_wire::transaction::Transaction;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const PINNED_GENESIS_BLOCK_IDS: [(Network, &str); 3] = [
    (
        Network::Mainnet,
        "d7af382339b2cd0c4ee4b2ea0afe7426f34bc2971495d9873fd4cec2107ad8ed",
    ),
    (
        Network::Testnet,
        "e895bf2baa4ea4ccb07620d354e544a4be243bf329925f6a8a51631da18033da",
    ),
    (
        Network::Stagenet,
        "371e8fa310afb0c6089e47398ebe02c4e2aa1820e8ccfd32e328558b99677c60",
    ),
];

#[test]
fn each_networks_genesis_block_id_is_the_published_pin() {
    let config_h = repo_root().join("src/cryptonote_config.h");
    let pins =
        load_config_pins(&config_h).unwrap_or_else(|e| panic!("{}: {e}", config_h.display()));

    for (net, pinned_id) in PINNED_GENESIS_BLOCK_IDS {
        let pin = pins.for_network(net);
        let blob = hex::decode(&pin.genesis_tx_hex)
            .unwrap_or_else(|e| panic!("{}: GENESIS_TX is not hex: {e}", net.as_str()));
        let tx = Transaction::from_bytes(&blob)
            .unwrap_or_else(|e| panic!("{}: GENESIS_TX does not parse: {e}", net.as_str()));
        let block = genesis_block(tx, pin.genesis_nonce)
            .unwrap_or_else(|e| panic!("{}: genesis block: {e}", net.as_str()));

        assert_eq!(
            block.header.nonce,
            pin.genesis_nonce,
            "{}: the difficulty-1 genesis keeps its pinned nonce",
            net.as_str()
        );
        assert_eq!(
            hex::encode(block.hash()),
            pinned_id,
            "{}: genesis block id moved",
            net.as_str()
        );
    }
}
