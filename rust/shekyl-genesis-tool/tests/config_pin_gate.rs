// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The config-pin CI gate: the committed recipients files must (a) always be
//! valid, and (b) rebuild byte-for-byte into the `GENESIS_TX` pins in
//! `src/cryptonote_config.h`.
//!
//! (b) is what the deterministic tx key exists for: the pinned genesis is
//! reproducible from committed inputs, so drift between the recipients
//! files and the pins is a CI failure instead of a silent lie.
//!
//! The **parser** is gated separately (see
//! [`config_pins_parse_from_real_header`]) so a region-model break — which
//! would make `geblock verify` unable to find the pins at all — fails with a
//! parser diagnostic rather than as a confusing byte-compare miss.

use shekyl_address::Network;
use shekyl_genesis_tool::config_pin::{load_config_pins, verify_networks};
use shekyl_genesis_tool::recipients::load_and_validate;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Always on: every committed recipients file parses, is for the network its
/// filename claims, and satisfies the 5 × 20,000 SKL allocation invariants
/// with canonical post-#327 addresses.
#[test]
fn recipients_files_are_valid() {
    for net in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let path = repo_root()
            .join("config")
            .join(format!("genesis_recipients.{}.json", net.as_str()));
        let recipients =
            load_and_validate(&path, net).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(recipients.len(), 5);
    }
}

/// Always on: the real `cryptonote_config.h` must yield exactly three
/// networks' pins with even-length non-empty hex and parseable nonces.
///
/// This is the load-bearing check that the pin scraper still understands
/// the header (east-const house style, namespace regions, config_t fields
/// excluded). Byte-compare against the rebuilt genesis is a separate test
/// below ([`genesis_hex_matches_config_pin`]).
#[test]
fn config_pins_parse_from_real_header() {
    let path = repo_root().join("src/cryptonote_config.h");
    let pins = load_config_pins(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));

    for (net, pin) in [
        (Network::Mainnet, &pins.mainnet),
        (Network::Testnet, &pins.testnet),
        (Network::Stagenet, &pins.stagenet),
    ] {
        assert!(
            !pin.genesis_tx_hex.is_empty(),
            "{}: GENESIS_TX empty",
            net.as_str()
        );
        assert_eq!(
            pin.genesis_tx_hex.len() % 2,
            0,
            "{}: GENESIS_TX odd length {}",
            net.as_str(),
            pin.genesis_tx_hex.len()
        );
        assert!(
            pin.genesis_tx_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}: GENESIS_TX not hex",
            net.as_str()
        );
        // Nonces are network-distinct today; a zero would be a parse miss
        // against the live header (mainnet 10000, testnet 10101, stagenet 10002).
        assert_ne!(
            pin.genesis_nonce,
            0,
            "{}: GENESIS_NONCE parsed as 0",
            net.as_str()
        );
    }
    assert_ne!(
        pins.mainnet.genesis_nonce, pins.testnet.genesis_nonce,
        "mainnet/testnet nonces must differ"
    );
    assert_ne!(
        pins.mainnet.genesis_nonce, pins.stagenet.genesis_nonce,
        "mainnet/stagenet nonces must differ"
    );
    assert_ne!(
        pins.testnet.genesis_nonce, pins.stagenet.genesis_nonce,
        "testnet/stagenet nonces must differ"
    );
}

/// The byte-compare gate: rebuilding every network from the committed
/// recipients files must reproduce the `GENESIS_TX` pins byte for byte. A
/// drift between the recipients files and the pins — in either direction —
/// fails CI instead of shipping a genesis nobody can reproduce.
#[test]
fn genesis_hex_matches_config_pin() {
    let root = repo_root();
    let outcomes = verify_networks(&root.join("src/cryptonote_config.h"), &root.join("config"))
        .expect("verify runs");
    for o in &outcomes {
        assert!(
            o.matches,
            "{}: rebuilt genesis hex does not match the cryptonote_config.h pin \
             (built {} chars, pinned {}, first mismatch {:?})",
            o.network.as_str(),
            o.built_len,
            o.pinned_len,
            o.first_mismatch
        );
    }
}
