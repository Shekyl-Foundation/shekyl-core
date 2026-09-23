// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `anchors.rs` — the release-carried table: genesis on every public network,
//! ascending by construction, read through three named accessors
//! (`CHAIN_RULES_SLICE_3.md` §4.1, §5).

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

use super::{well_formed, Anchor, ReleaseAnchors};

const NETWORKS: [Network; 3] = [Network::Mainnet, Network::Testnet, Network::Stagenet];

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

const fn hash(fill: u8) -> BlockHash {
    BlockHash::from_bytes([fill; 32])
}

const fn anchor(raw: u64, fill: u8) -> Anchor {
    Anchor {
        height: height(raw),
        hash: hash(fill),
    }
}

/// A two-anchor fixture table: heights 3 and 10.
const TWO: ReleaseAnchors = ReleaseAnchors::for_tests(&[anchor(3, 0xA3), anchor(10, 0xB0)]);

/// The only anchor is genesis (`CHAIN_RULES_SLICE_4.md` Q3 (a); replaces
/// `no_release_has_shipped_an_anchor_yet`, refuted by design). No release
/// has shipped a *checkpoint* anchor (PDM-Q5's launch-window item is open):
/// this bites the day the first one lands — that edit is deliberate, and
/// this test is what makes it fail loudly rather than pass quietly. Rule 71
/// rides along: the three tables have the same shape, and differ only in
/// the datum a network is (its genesis).
#[test]
fn the_only_anchor_is_genesis_until_the_first_checkpoint_release() {
    let mut seen = std::collections::BTreeSet::new();
    for network in NETWORKS {
        let table = ReleaseAnchors::for_network(network);
        assert_ne!(table, ReleaseAnchors::EMPTY, "{network:?}");
        let genesis = table.current().expect("genesis is anchored");
        assert_eq!(
            genesis.height,
            height(0),
            "{network:?}: the one anchor is at 0"
        );
        assert!(table.covers(height(0)));
        assert!(
            !table.covers(height(1)),
            "{network:?}: nothing above genesis"
        );
        assert_eq!(table.expected_at(height(0)), Some(genesis.hash));
        assert_eq!(table.expected_at(height(1)), None);
        assert!(
            seen.insert(genesis.hash),
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
fn the_genesis_anchor_is_the_configured_genesis_block() {
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
            ReleaseAnchors::for_network(network).expected_at(height(0)),
            Some(block.hash()),
            "{network:?}: the anchor is the block cryptonote_config.h configures"
        );
    }
}

/// The client identity's genesis pins (`shekyl_rpc_types::genesis_hash_for`,
/// `VC-D18`) and this table are two Rust homes of one fact; they cannot
/// drift.
#[test]
fn the_genesis_anchor_agrees_with_the_client_identity_pins() {
    use shekyl_rpc_types::DaemonNetwork;
    for (network, daemon) in [
        (Network::Mainnet, DaemonNetwork::Mainnet),
        (Network::Testnet, DaemonNetwork::Testnet),
        (Network::Stagenet, DaemonNetwork::Stagenet),
    ] {
        assert_eq!(
            ReleaseAnchors::for_network(network).expected_at(height(0)),
            Some(BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(
                daemon
            ))),
            "{network:?}"
        );
    }
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

/// `expected_at` answers at exactly the anchored heights and nowhere else.
#[test]
fn expected_at_is_exact() {
    assert_eq!(TWO.expected_at(height(3)), Some(hash(0xA3)));
    assert_eq!(TWO.expected_at(height(10)), Some(hash(0xB0)));
    for unanchored in [0, 2, 4, 9, 11, u64::MAX] {
        assert_eq!(
            TWO.expected_at(height(unanchored)),
            None,
            "height {unanchored}"
        );
    }
}

/// `current` is the last entry — `C` — and `covers` is `≤ C` (band 1).
#[test]
fn current_is_the_last_entry_and_covers_is_at_or_below_it() {
    assert_eq!(TWO.current(), Some(anchor(10, 0xB0)));
    assert!(TWO.covers(height(0)));
    assert!(TWO.covers(height(3)));
    assert!(TWO.covers(height(10)));
    assert!(!TWO.covers(height(11)));
}

/// The invariant `for_network`'s tables are const-asserted against:
/// strictly ascending. Equal heights and descent both fail it; the empty
/// and single-entry tables trivially hold it.
#[test]
fn well_formed_is_strictly_ascending() {
    const ONE: &[Anchor] = &[anchor(0, 9)];
    const ASC: &[Anchor] = &[anchor(1, 1), anchor(2, 2)];
    const EQUAL: &[Anchor] = &[anchor(5, 1), anchor(5, 2)];
    const DESC: &[Anchor] = &[anchor(7, 1), anchor(6, 2)];
    assert!(well_formed(&ReleaseAnchors::EMPTY));
    assert!(well_formed(&ReleaseAnchors { entries: ONE }));
    assert!(well_formed(&ReleaseAnchors { entries: ASC }));
    assert!(!well_formed(&ReleaseAnchors { entries: EQUAL }));
    assert!(!well_formed(&ReleaseAnchors { entries: DESC }));
}

/// The fixture constructor refuses what the compile-time gate would: a
/// fixture cannot smuggle in a table production could not carry.
#[test]
#[should_panic(expected = "not strictly ascending")]
fn for_tests_refuses_a_malformed_table() {
    const REPEATED: &[Anchor] = &[anchor(4, 1), anchor(4, 2)];
    let table = ReleaseAnchors::for_tests(REPEATED);
    unreachable!("constructed {table:?}");
}

/// `Debug` prints heights, not hashes.
#[test]
fn debug_names_heights() {
    assert_eq!(
        format!("{TWO:?}"),
        "ReleaseAnchors { count: 2, heights: [3, 10] }"
    );
}
