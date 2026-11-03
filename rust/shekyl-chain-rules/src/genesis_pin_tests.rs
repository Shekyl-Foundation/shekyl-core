// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `genesis_pin.rs` — the release-carried genesis pin on every public network
//! (`CHAIN_RULES_SLICE_4.md` Q3), and nothing above it (S1, design review
//! 2026-11-03).

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

use super::GenesisPin;

const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

const fn hash(fill: u8) -> BlockHash {
    BlockHash::from_bytes([fill; 32])
}

/// Every public network pins its genesis and nothing else, and each
/// network's genesis is its own. Rule 71 rides along: the three tables
/// have the same shape and differ only in the datum a network is.
#[test]
fn every_public_network_pins_its_own_genesis_and_nothing_above_it() {
    let mut seen = std::collections::BTreeSet::new();
    for network in NETWORKS {
        let table = GenesisPin::for_network(network);
        assert_ne!(table, GenesisPin::NONE, "{network:?}");
        let genesis = table.expected_at(height(0)).expect("genesis is pinned");
        for above in [1, 2, 1_000, u64::MAX] {
            assert_eq!(
                table.expected_at(height(above)),
                None,
                "{network:?} at {above}"
            );
        }
        assert!(
            seen.insert(genesis),
            "{network:?}: each network has its own genesis"
        );
    }
}

/// The genesis hashes are **derived**, not restated: rebuild each network's
/// genesis block from `cryptonote_config.h`'s `GENESIS_TX` / `GENESIS_NONCE`
/// pins the way `generate_genesis_block` does (the genesis tool's builder,
/// which `geblock verify` holds byte-equal to the pins) and assert the
/// table carries that block's identity. A remint of genesis fails here
/// until the table follows.
#[test]
fn the_genesis_pin_is_the_configured_genesis_block() {
    use shekyl_genesis_tool::builder::genesis_block;
    use shekyl_genesis_tool::config_pin::parse_config_genesis;
    let config_h = include_str!("../../../src/cryptonote_config.h");
    let pins = parse_config_genesis(config_h).expect("cryptonote_config.h carries the pins");
    for network in NETWORKS {
        let pin = pins.for_network(network);
        let tx_bytes = unhex(&pin.genesis_tx_hex);
        let tx = shekyl_wire::Transaction::from_bytes(&tx_bytes).expect("GENESIS_TX decodes");
        let block = genesis_block(tx, pin.genesis_nonce).expect("genesis block assembles");
        assert_eq!(
            GenesisPin::for_network(network).expected_at(height(0)),
            Some(block.hash()),
            "{network:?}: the pin is the block cryptonote_config.h configures"
        );
    }
}

/// The client identity's genesis pins (`shekyl_rpc_types::genesis_hash_for`,
/// `VC-D18`) and this table are two Rust homes of one fact; they cannot
/// drift.
#[test]
fn the_genesis_pin_agrees_with_the_client_identity_pins() {
    use shekyl_rpc_types::DaemonNetwork;
    for (network, daemon) in [
        (Network::Mainnet, DaemonNetwork::Mainnet),
        (Network::Testnet, DaemonNetwork::Testnet),
        (Network::Stagenet, DaemonNetwork::Stagenet),
    ] {
        assert_eq!(
            GenesisPin::for_network(network).expected_at(height(0)),
            Some(BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(
                daemon
            ))),
            "{network:?}"
        );
    }
}

/// Regtest's pin is the genesis a regtest node connects: the client
/// identity's fakechain genesis, which is mainnet's configured block.
#[test]
fn the_fakechain_pin_is_the_genesis_a_regtest_node_connects() {
    use shekyl_rpc_types::DaemonNetwork;
    assert_eq!(
        GenesisPin::FAKECHAIN.expected_at(height(0)),
        Some(BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(
            DaemonNetwork::Fakechain
        )))
    );
}

/// Lowercase hex to bytes, for the `GENESIS_TX` pin. Local so the crate does
/// not take a hex dependency for one test.
fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "even-length hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// A fixture pin answers at height 0 only, and the empty table nowhere.
#[test]
fn expected_at_is_genesis_only() {
    const PINNED: GenesisPin = GenesisPin::for_tests(Some(hash(0x60)));
    assert_eq!(PINNED.expected_at(height(0)), Some(hash(0x60)));
    assert_eq!(PINNED.expected_at(height(1)), None);
    assert_eq!(GenesisPin::NONE.expected_at(height(0)), None);
}

/// `Debug` prints whether genesis is pinned, never the hash.
#[test]
fn debug_says_whether_genesis_is_pinned() {
    assert_eq!(
        format!("{:?}", GenesisPin::NONE),
        "GenesisPin { genesis: \"none\" }"
    );
    assert_eq!(
        format!("{:?}", GenesisPin::for_network(Network::Mainnet)),
        "GenesisPin { genesis: \"pinned\" }"
    );
}
