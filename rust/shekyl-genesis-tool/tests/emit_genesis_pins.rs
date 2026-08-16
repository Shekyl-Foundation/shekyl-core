// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One-shot pin emitter for a genesis remint. Run:
//! `cargo test -p shekyl-genesis-tool --test emit_genesis_pins -- --ignored --nocapture`

use std::fs;
use std::path::PathBuf;

use shekyl_address::Network;
use shekyl_genesis_tool::builder::{build_genesis_tx, genesis_block};
use shekyl_genesis_tool::config_pin::load_config_pins;
use shekyl_genesis_tool::recipients::load_and_validate;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "writes recaptured genesis artifacts; run after a tx-key remint"]
fn emit_genesis_pins() {
    let root = repo_root();
    let config_h = root.join("src/cryptonote_config.h");
    let pins = load_config_pins(&config_h).expect("load pins");
    let mut config_text = fs::read_to_string(&config_h).expect("read cryptonote_config.h");

    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let rec_path = root
            .join("config")
            .join(format!("genesis_recipients.{}.json", net.as_str()));
        let recipients = load_and_validate(&rec_path, net).expect("recipients");
        let built = build_genesis_tx(net, &recipients).expect("build tx");
        let nonce = pins.for_network(net).genesis_nonce;
        let tx_hash = hex::encode(built.tx_hash);
        let tx_hex = built.hex.clone();
        let block = genesis_block(built.tx, nonce).expect("block");
        let block_id = hex::encode(block.hash());

        eprintln!(
            "{net}: nonce={nonce} tx_hash={tx_hash} block_id={block_id} hex_len={}",
            tx_hex.len(),
            net = net.as_str()
        );

        let old_hex = &pins.for_network(net).genesis_tx_hex;
        assert!(
            config_text.contains(old_hex),
            "{}: pinned hex not found in cryptonote_config.h",
            net.as_str()
        );
        config_text = config_text.replacen(old_hex, &tx_hex, 1);

        if net == Network::Mainnet {
            let h0_path = root.join("rust/shekyl-wire/tests/vectors/regtest_coinbase_h0.block");
            let blob = block.serialize();
            fs::write(&h0_path, &blob).expect("write h0 blob");
            eprintln!("wrote {} ({} bytes)", h0_path.display(), blob.len());
            eprintln!("h0 miner_tx_hash={tx_hash}");
            eprintln!("h0 block_hash={block_id}");
        }
    }

    fs::write(&config_h, config_text).expect("write cryptonote_config.h");
    eprintln!("updated {}", config_h.display());
}
