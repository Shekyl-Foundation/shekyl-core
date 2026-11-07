// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-E5 at the public-network open.
//!
//! Each test names the edit that turns it red. A round-trip of one pin
//! function through itself does not: the file's block hash is what
//! `connect` recorded, and the table is what the open was given.

use std::time::Duration;

use shekyl_address::Network;
use shekyl_chain_rules::{GenesisConflict, GenesisPin};
use shekyl_types::{BlockHash, BlockHeight};

use super::connect_fixtures::connect_chain;
use super::store_tests::{production_horizons, tmp, EPOCH};
use super::*;
use crate::apply_policy::ApplyPolicy;
use crate::redb_recovery::{bytes_and_mtime, mark_recovery_required};

/// Far enough behind the clock that a write cannot share the snapshot's
/// timestamp on a filesystem whose modification-time tick is a second or two.
const BEFORE_THE_SNAPSHOT: Duration = Duration::from_secs(120);

fn record(path: &std::path::Path, blocks: usize) -> Vec<BlockHash> {
    let store = ChainStore::create(path, EPOCH).expect("unanchored create");
    let listed = vec![Vec::new(); blocks];
    let hashes = connect_chain(&store, &listed).hashes;
    assert_eq!(hashes.len(), blocks, "every listed block connected");
    hashes
}

fn released(path: &std::path::Path, pin: &GenesisPin) -> Result<ChainStore, StoreError> {
    ChainStore::with_genesis(path, ApplyPolicy::Full, production_horizons(), pin)
        .map(|(store, _cut)| store)
}

fn pin_of(pin: &GenesisPin) -> BlockHash {
    pin.expected_at(BlockHeight::ZERO)
        .expect("a public pin names genesis")
}

/// Set `path`'s modification time to [`BEFORE_THE_SNAPSHOT`] ago.
///
/// The handle is read-write, and the open does not truncate. Windows
/// refuses [`std::fs::File::set_modified`] on a read-only handle.
fn age_mtime(path: &std::path::Path) {
    let aged = std::time::SystemTime::now()
        .checked_sub(BEFORE_THE_SNAPSHOT)
        .expect("the clock reaches back");
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("the store file")
        .set_modified(aged)
        .expect("age the modification time");
}

fn release_pin(err: StoreError) -> GenesisConflict {
    match err {
        StoreError::Cannot(StoreCannot::ForeignGenesis(conflict)) => conflict,
        other => panic!("admission refused with {other}"),
    }
}

/// Red if an empty file is treated as a contradiction.
#[test]
fn an_empty_file_agrees_with_a_public_table() {
    let path = tmp("release-empty");
    let pin = GenesisPin::for_network(Network::Mainnet);
    let store = released(&path, &pin).expect("an empty file contradicts nothing");
    let tip = store.begin_read().expect("read").tip().expect("tip");
    assert!(tip.recorded.is_none());
}

/// Red if the open compares the pin to anything other than the recorded
/// block, or refuses a file that carries it.
#[test]
fn a_file_whose_genesis_is_the_pin_opens() {
    let path = tmp("release-match");
    let recorded = record(&path, 1);
    let pin = GenesisPin::for_tests(Some(recorded[0]));
    let store = released(&path, &pin).expect("the recorded genesis is the pin");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("the block is still there");
    assert_eq!(tip.height, BlockHeight::ZERO);
    assert_eq!(tip.hash, recorded[0]);
    assert_eq!(pin_of(&pin), recorded[0]);
}

/// Red if admission ignores the table it was given, reports one network's
/// pin for another, or fails to name both the pin and the file's block.
/// A matching table is the other test; this one must refuse.
#[test]
fn a_foreign_genesis_is_refused_on_every_public_network() {
    let path = tmp("release-foreign");
    let recorded = record(&path, 1);
    let mut pinned = Vec::new();
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let pin = GenesisPin::for_network(network);
        let conflict = release_pin(released(&path, &pin).expect_err("a synthetic genesis"));
        let expected = pin_of(&pin);
        assert_eq!(
            conflict,
            GenesisConflict {
                expected,
                recorded: recorded[0],
            }
        );
        assert_ne!(
            expected, recorded[0],
            "{network:?} must not be the fixture id"
        );
        pinned.push(expected);
    }
    assert_ne!(pinned[0], pinned[1]);
    assert_ne!(pinned[0], pinned[2]);
    assert_ne!(pinned[1], pinned[2]);
}

/// Red if admission runs only after the writable open: a writable open
/// writes into the file even with nothing committed (the engine records
/// its allocator state when it closes), so a store from another network
/// would be refused after it had been changed.
#[test]
fn a_foreign_genesis_is_refused_with_the_file_untouched() {
    let path = tmp("release-foreign-untouched");
    let recorded = record(&path, 1);
    // A filesystem tick of a second or two would hide a write that lands
    // in the same tick as the snapshot. Age the file first, then snapshot,
    // so any later write moves the modification time.
    age_mtime(&path);
    let before = bytes_and_mtime(&path);
    let testnet = GenesisPin::for_network(Network::Testnet);
    let conflict = release_pin(released(&path, &testnet).expect_err("another network's store"));
    assert_eq!(conflict.recorded, recorded[0]);
    assert_eq!(conflict.expected, pin_of(&testnet));
    assert_eq!(
        bytes_and_mtime(&path),
        before,
        "a refused store keeps its bytes and its modification time"
    );
}

/// A foreign store a crash left needing recovery cannot be judged on a
/// read-only open (redb refuses one, `RepairAborted`). The writable open
/// repairs it, the engine restoring the file's own committed state, and
/// the admission after it refuses the store: still another network's
/// chain, with its block 0 intact. The one refusal that writes. Red if
/// the repair arm skips the admission, or if the repair drops the block.
#[test]
fn a_foreign_genesis_that_needs_repair_is_repaired_then_refused_with_its_chain_intact() {
    let path = tmp("release-foreign-repair");
    let recorded = record(&path, 1);
    mark_recovery_required(&path);
    assert!(crate::redb_recovery::read_only_open_is_repair_aborted(
        &path
    ));
    let testnet = GenesisPin::for_network(Network::Testnet);
    let conflict = release_pin(released(&path, &testnet).expect_err("another network's store"));
    assert_eq!(conflict.expected, pin_of(&testnet));
    assert_eq!(conflict.recorded, recorded[0]);
    let store = ChainStore::create(&path, EPOCH).expect("the repaired file is a store");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("block 0");
    assert_eq!(
        tip.hash, recorded[0],
        "nothing lost: its own chain is intact"
    );
    drop(store);
}

/// Red if `create` starts admitting. The synthetic id is not a public pin,
/// and the harness door has to keep it.
#[test]
fn an_unpinned_create_keeps_a_synthetic_genesis() {
    let path = tmp("release-unanchored");
    let recorded = record(&path, 1);
    let mainnet = GenesisPin::for_network(Network::Mainnet);
    let _ = release_pin(released(&path, &mainnet).expect_err("the public door refuses"));
    let store = ChainStore::create(&path, EPOCH).expect("create does not admit");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("block 0");
    assert_eq!(tip.hash, recorded[0]);
}

/// Red if `GenesisPin::NONE` is treated as a public table. Fakechain
/// is this table, not a nettype branch inside admission.
#[test]
fn an_empty_table_agrees_with_a_synthetic_genesis() {
    let path = tmp("release-empty-table");
    let recorded = record(&path, 1);
    let store = released(&path, &GenesisPin::NONE).expect("nothing is pinned");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("block 0");
    assert_eq!(tip.hash, recorded[0]);
}

/// Red if the reader twin skips admission, or if it refuses a file whose
/// genesis is the pin.
#[test]
fn a_reader_admits_the_same_pins() {
    let path = tmp("release-reader");
    let recorded = record(&path, 1);
    let mainnet = GenesisPin::for_network(Network::Mainnet);
    let conflict = release_pin(
        ChainStore::open_read_only_with_genesis(&path, production_horizons(), &mainnet)
            .expect_err("a reader refuses a foreign genesis"),
    );
    assert_eq!(conflict.expected, pin_of(&mainnet));
    assert_eq!(conflict.recorded, recorded[0]);

    let matching = GenesisPin::for_tests(Some(recorded[0]));
    let store = ChainStore::open_read_only_with_genesis(&path, production_horizons(), &matching)
        .expect("a reader opens a file that carries the pin");
    assert!(store.is_read_only());
}
