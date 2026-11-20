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

const NETWORKS: [Network; 4] = Network::ALL;

const fn height(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

const fn hash(fill: u8) -> BlockHash {
    BlockHash::from_bytes([fill; 32])
}

/// Every network pins its genesis and nothing else, and each network's
/// genesis is its own. Rule 71 rides along: the four tables have the same
/// shape and differ only in the datum a network is.
#[test]
fn every_network_pins_its_own_genesis_and_nothing_above_it() {
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

/// The pin is the network table's genesis (`NETWORK_IDENTITY.md` NI-Q3),
/// which the genesis tool rebuilds from each recipients file, and the
/// client identity's pin (`shekyl_rpc_types::genesis_hash_for`, `VC-D18`)
/// is the same fact.
#[test]
fn the_genesis_pin_is_the_tables_genesis() {
    for network in NETWORKS {
        let table = BlockHash::from_bytes(network.genesis().hash());
        assert_eq!(
            GenesisPin::for_network(network).expected_at(height(0)),
            Some(table),
            "{network}"
        );
        assert_eq!(
            BlockHash::from_bytes(shekyl_rpc_types::genesis_hash_for(network)),
            table,
            "{network}: the client identity's pin"
        );
    }
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
