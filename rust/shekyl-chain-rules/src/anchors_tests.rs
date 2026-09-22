// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `anchors.rs` — the release-carried table: empty on every network today,
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

/// No release has shipped an anchor (PDM-Q5's launch-window item is
/// open). Bites the day the first entry lands: that edit is deliberate,
/// and this test is what makes it fail loudly rather than pass quietly.
/// Rule 71 rides along: the three tables are identical *as data*.
#[test]
fn no_release_has_shipped_an_anchor_yet() {
    for network in NETWORKS {
        let table = ReleaseAnchors::for_network(network);
        assert_eq!(table, ReleaseAnchors::EMPTY, "{network:?}");
        assert_eq!(table.current(), None);
        assert!(!table.covers(height(0)));
        assert_eq!(table.expected_at(height(0)), None);
    }
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
