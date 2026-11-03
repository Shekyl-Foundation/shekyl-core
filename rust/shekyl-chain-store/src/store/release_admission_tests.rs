// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-E5 at the public-network open.
//!
//! Each test names the edit that turns it red. A round-trip of one pin
//! function through itself does not: the file's block hash is what
//! `connect` recorded, and the table is what the open was given.

use shekyl_address::Network;
use shekyl_chain_rules::{GenesisConflict, GenesisPin};
use shekyl_types::{BlockHash, BlockHeight};

use super::connect_fixtures::connect_chain;
use super::store_tests::{cleanup, production_horizons, tmp, EPOCH};
use super::*;
use crate::apply_policy::ApplyPolicy;

fn record(path: &std::path::Path, blocks: usize) -> Vec<BlockHash> {
    let store = ChainStore::create(path, EPOCH).expect("unanchored create");
    let listed = vec![Vec::new(); blocks];
    let hashes = connect_chain(&store, &listed).hashes;
    assert_eq!(hashes.len(), blocks, "every listed block connected");
    hashes
}

fn released(path: &std::path::Path, anchors: &GenesisPin) -> Result<ChainStore, StoreError> {
    ChainStore::with_genesis(path, ApplyPolicy::Full, production_horizons(), anchors)
        .map(|(store, _cut)| store)
}

fn pin_of(anchors: &GenesisPin) -> BlockHash {
    anchors
        .expected_at(BlockHeight::ZERO)
        .expect("a public table pins genesis")
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
    let anchors = GenesisPin::for_network(Network::Mainnet);
    let store = released(&path, &anchors).expect("an empty file contradicts nothing");
    let tip = store.begin_read().expect("read").tip().expect("tip");
    assert!(tip.recorded.is_none());
    cleanup(&path);
}

/// Red if the open compares the pin to anything other than the recorded
/// block, or refuses a file that carries it.
#[test]
fn a_file_whose_genesis_is_the_pin_opens() {
    let path = tmp("release-match");
    let recorded = record(&path, 1);
    let anchors = GenesisPin::for_tests(Some(recorded[0]));
    let store = released(&path, &anchors).expect("the recorded genesis is the pin");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("the block is still there");
    assert_eq!(tip.height, BlockHeight::ZERO);
    assert_eq!(tip.hash, recorded[0]);
    assert_eq!(pin_of(&anchors), recorded[0]);
    cleanup(&path);
}

/// Red if admission ignores the table it was given, reports one network's
/// pin for another, or fails to name both the pin and the file's block.
/// A matching table is the other test; this one must refuse.
#[test]
fn a_foreign_genesis_is_refused_on_every_public_network() {
    let path = tmp("release-foreign");
    let recorded = record(&path, 1);
    let mut pins = Vec::new();
    for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
        let anchors = GenesisPin::for_network(network);
        let conflict = release_pin(released(&path, &anchors).expect_err("a synthetic genesis"));
        let expected = pin_of(&anchors);
        assert_eq!(
            conflict,
            GenesisConflict {
                height: BlockHeight::ZERO,
                expected,
                recorded: Some(recorded[0]),
            }
        );
        assert_ne!(
            expected, recorded[0],
            "{network:?} must not be the fixture id"
        );
        pins.push(expected);
    }
    assert_ne!(pins[0], pins[1]);
    assert_ne!(pins[0], pins[2]);
    assert_ne!(pins[1], pins[2]);
    cleanup(&path);
}

/// Red if admission runs only after the writable open: a writable open
/// writes into the file even with nothing committed (the engine records
/// its allocator state when it closes), so a store from another network
/// would be refused after it had been changed.
#[test]
fn a_foreign_genesis_is_refused_with_the_file_untouched() {
    let path = tmp("release-foreign-untouched");
    let recorded = record(&path, 1);
    let before = file_state(&path);
    let testnet = GenesisPin::for_network(Network::Testnet);
    let conflict = release_pin(released(&path, &testnet).expect_err("another network's store"));
    assert_eq!(conflict.recorded, Some(recorded[0]));
    assert_eq!(conflict.expected, pin_of(&testnet));
    assert_eq!(
        file_state(&path),
        before,
        "a refused store keeps its bytes and its modification time"
    );
    cleanup(&path);
}

/// The file's bytes and modification time.
fn file_state(path: &std::path::Path) -> (Vec<u8>, std::time::SystemTime) {
    let bytes = std::fs::read(path).expect("read the store file");
    let modified = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .expect("the store file's modification time");
    (bytes, modified)
}

/// Red if `create` starts admitting. The synthetic id is not a public pin,
/// and the harness door has to keep it.
#[test]
fn an_unanchored_open_keeps_a_synthetic_genesis() {
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
    cleanup(&path);
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
    cleanup(&path);
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
    assert_eq!(conflict.height, BlockHeight::ZERO);
    assert_eq!(conflict.expected, pin_of(&mainnet));
    assert_eq!(conflict.recorded, Some(recorded[0]));

    let matching = GenesisPin::for_tests(Some(recorded[0]));
    let store = ChainStore::open_read_only_with_genesis(&path, production_horizons(), &matching)
        .expect("a reader opens a file that carries the pin");
    assert!(store.is_read_only());
    cleanup(&path);
}
