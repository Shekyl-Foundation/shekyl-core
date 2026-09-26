// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `anchors.rs` — the release-carried table: the genesis pin on every public
//! network, the checkpoints ascending from height 1 by construction, read
//! through three named accessors (`CHAIN_RULES_SLICE_3.md` §4.1, §5;
//! `CHAIN_RULES_SLICE_4.md` Q3).

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

/// A two-anchor fixture table with no genesis pin: heights 3 and 10.
const TWO: ReleaseAnchors = ReleaseAnchors::for_tests(None, &[anchor(3, 0xA3), anchor(10, 0xB0)]);

/// Every public network pins its genesis and anchors nothing: band 1 is
/// empty, `assumevalid = 0` is `Trust::Full`, and genesis — verified by
/// equality through `expected_at`, in no band — is not `current()`
/// (`CHAIN_RULES_SLICE_4.md` Q3 (a), and the PDM lane's answer, 2026-09-22;
/// replaces `no_release_has_shipped_an_anchor_yet`, refuted by design). No
/// release has shipped a checkpoint (PDM-Q5's launch-window item is open):
/// this bites the day the first one lands — that edit is deliberate, and
/// this test is what makes it fail loudly rather than pass quietly. Rule 71
/// rides along: the three tables have the same shape, and differ only in
/// the datum a network is (its genesis).
#[test]
fn band_one_is_empty_until_the_first_checkpoint_release() {
    let mut seen = std::collections::BTreeSet::new();
    for network in NETWORKS {
        let table = ReleaseAnchors::for_network(network);
        assert_ne!(table, ReleaseAnchors::EMPTY, "{network:?}");
        assert_eq!(table.current(), None, "{network:?}: no anchor at all");
        assert!(
            !table.covers(height(0)),
            "{network:?}: genesis is in no trust band"
        );
        assert!(!table.covers(height(1)), "{network:?}");
        let genesis = table.expected_at(height(0)).expect("genesis is pinned");
        assert_eq!(table.expected_at(height(1)), None);
        assert_eq!(
            table.pins().collect::<Vec<_>>(),
            vec![(height(0), genesis)],
            "{network:?}: the genesis pin is the only pin"
        );
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
fn the_genesis_pin_agrees_with_the_client_identity_pins() {
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

/// `expected_at` answers at exactly the pinned heights and nowhere else:
/// the anchored heights, and height 0 when a genesis is pinned.
#[test]
fn expected_at_is_exact() {
    assert_eq!(TWO.expected_at(height(3)), Some(hash(0xA3)));
    assert_eq!(TWO.expected_at(height(10)), Some(hash(0xB0)));
    for unpinned in [0, 2, 4, 9, 11, u64::MAX] {
        assert_eq!(TWO.expected_at(height(unpinned)), None, "height {unpinned}");
    }
    const PINNED: ReleaseAnchors = ReleaseAnchors::for_tests(Some(hash(0x60)), &[anchor(3, 0xA3)]);
    assert_eq!(PINNED.expected_at(height(0)), Some(hash(0x60)));
    assert_eq!(PINNED.expected_at(height(3)), Some(hash(0xA3)));
    assert_eq!(PINNED.expected_at(height(1)), None);
    assert_eq!(
        PINNED.pins().collect::<Vec<_>>(),
        vec![(height(0), hash(0x60)), (height(3), hash(0xA3))]
    );
}

/// `current` is the last checkpoint — `C` — and `covers` is `≤ C` (band 1).
/// A genesis pin changes neither: it is not an anchor.
#[test]
fn current_is_the_last_checkpoint_and_covers_is_at_or_below_it() {
    assert_eq!(TWO.current(), Some(anchor(10, 0xB0)));
    assert!(TWO.covers(height(0)));
    assert!(TWO.covers(height(3)));
    assert!(TWO.covers(height(10)));
    assert!(!TWO.covers(height(11)));
    const GENESIS_ONLY: ReleaseAnchors = ReleaseAnchors::for_tests(Some(hash(0x60)), &[]);
    assert_eq!(GENESIS_ONLY.current(), None);
    assert!(!GENESIS_ONLY.covers(height(0)));
}

/// The invariant `for_network`'s tables are const-asserted against: the
/// checkpoints are strictly ascending from height `≥ 1`. Equal heights,
/// descent, and an "anchor" at genesis all fail it; the empty table, a
/// genesis pin alone, and a single checkpoint trivially hold it.
#[test]
fn well_formed_is_strictly_ascending_from_height_one() {
    const ONE: &[Anchor] = &[anchor(1, 9)];
    const ASC: &[Anchor] = &[anchor(1, 1), anchor(2, 2)];
    const EQUAL: &[Anchor] = &[anchor(5, 1), anchor(5, 2)];
    const DESC: &[Anchor] = &[anchor(7, 1), anchor(6, 2)];
    const AT_GENESIS: &[Anchor] = &[anchor(0, 9), anchor(4, 4)];
    let table = |checkpoints| ReleaseAnchors {
        genesis: Some(hash(0x60)),
        checkpoints,
    };
    assert!(well_formed(&ReleaseAnchors::EMPTY));
    assert!(well_formed(&table(&[])));
    assert!(well_formed(&table(ONE)));
    assert!(well_formed(&table(ASC)));
    assert!(!well_formed(&table(EQUAL)));
    assert!(!well_formed(&table(DESC)));
    assert!(!well_formed(&table(AT_GENESIS)));
}

/// The fixture constructor refuses what the compile-time gate would: a
/// fixture cannot smuggle in a table production could not carry.
#[test]
#[should_panic(expected = "not strictly ascending from height 1")]
fn for_tests_refuses_a_malformed_table() {
    const REPEATED: &[Anchor] = &[anchor(4, 1), anchor(4, 2)];
    let table = ReleaseAnchors::for_tests(None, REPEATED);
    unreachable!("constructed {table:?}");
}

/// Nor an anchor at genesis: "genesis is the anchor" is not constructible.
#[test]
#[should_panic(expected = "not strictly ascending from height 1")]
fn for_tests_refuses_an_anchor_at_genesis() {
    const AT_GENESIS: &[Anchor] = &[anchor(0, 1)];
    let table = ReleaseAnchors::for_tests(Some(hash(0x60)), AT_GENESIS);
    unreachable!("constructed {table:?}");
}

/// `Debug` prints whether genesis is pinned and the checkpoint heights,
/// never hashes.
#[test]
fn debug_names_heights() {
    assert_eq!(
        format!("{TWO:?}"),
        "ReleaseAnchors { genesis: \"none\", checkpoints: [3, 10] }"
    );
    assert_eq!(
        format!("{:?}", ReleaseAnchors::for_network(Network::Mainnet)),
        "ReleaseAnchors { genesis: \"pinned\", checkpoints: [] }"
    );
}
