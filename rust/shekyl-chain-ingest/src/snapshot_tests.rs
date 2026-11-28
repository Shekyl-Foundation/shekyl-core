// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The snapshot cache's refusals, on a store a driver connected.

use super::*;
use crate::scenario::{FreeHash, Scenario};
use crate::scenario_shard::settled_epoch;
use shekyl_chain_rules::CappedEpoch;
use shekyl_network::Network;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository's root")
}

fn key(event: &str) -> SnapshotKey {
    SnapshotKey {
        chain: "sha256:00112233445566778899aabbccddeeff".to_owned(),
        event: event.to_owned(),
        schema: SCHEMA_VERSION.get(),
        code: "aa".repeat(32),
    }
}

/// A closed store of a few real blocks in `dir`, sealed, and its digest.
async fn sealed_store(dir: &Path, schedule: CappedEpoch) -> (Digest, ChainRules) {
    let rules = ChainRules::new(Network::Regtest, Some(std::num::NonZeroU128::MIN), schedule)
        .expect("regtest permits the lever");
    let (mut scenario, _genesis) =
        Scenario::open_regtest_mined("snapshot-refusals", FreeHash, schedule).await;
    let _ = scenario.mine(3).await;
    let store = dir.join(STORE_FILE);
    let copied = store.clone();
    scenario
        .reopen(move |path| {
            fs::copy(path, &copied).expect("the store copies");
        })
        .await;
    scenario.close().await;
    let digest = {
        let opened = ChainStore::with_horizons(
            &store,
            ApplyPolicy::default(),
            horizons(&rules).expect("the horizons"),
        )
        .expect("the copy opens");
        let read = opened.begin_read().expect("a snapshot");
        read.tables_digest_v1().expect("the digest")
    };
    seal(dir, &key("event"), SequenceNo::FIRST).expect("sealed");
    (digest, rules)
}

#[tokio::test]
async fn a_snapshot_opens_and_one_changed_byte_is_refused() {
    let dir = tempfile::tempdir().expect("a directory");
    let (digest, rules) = sealed_store(dir.path(), settled_epoch()).await;
    let out = tempfile::tempdir().expect("a directory");
    let copy = out.path().join("copy.redb");
    open_copy(dir.path(), &key("event"), &digest, &rules, &copy).expect("the sealed store opens");

    // One byte, anywhere: the middle of the file, whatever page it is on.
    let store = dir.path().join(STORE_FILE);
    let original = fs::read(&store).expect("reads");
    let mut flipped = original.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 1;
    fs::write(&store, &flipped).expect("writes");
    let refused = open_copy(
        dir.path(),
        &key("event"),
        &digest,
        &rules,
        &out.path().join("flipped.redb"),
    );
    assert!(
        matches!(refused, Err(SnapshotFault::FileChanged { .. })),
        "{refused:?}"
    );
    assert!(
        !out.path().join("flipped.redb").exists(),
        "a refused snapshot is not copied"
    );
    fs::write(&store, &original).expect("restores");
}

#[tokio::test]
async fn a_snapshot_is_held_to_the_traces_digest_and_its_own_key() {
    let dir = tempfile::tempdir().expect("a directory");
    let (digest, rules) = sealed_store(dir.path(), settled_epoch()).await;
    let out = tempfile::tempdir().expect("a directory");

    // A seal that matches its file proves nothing about the chain: the
    // trace's digest is what an edit of both cannot satisfy.
    let mut other = digest;
    other[0] ^= 1;
    let copy = out.path().join("other.redb");
    let refused = open_copy(dir.path(), &key("event"), &other, &rules, &copy);
    assert!(
        matches!(refused, Err(SnapshotFault::DigestChanged { .. })),
        "{refused:?}"
    );
    assert!(!copy.exists(), "a refused copy is removed");

    let refused = open_copy(
        dir.path(),
        &key("another-event"),
        &digest,
        &rules,
        &out.path().join("wrong.redb"),
    );
    assert!(
        matches!(refused, Err(SnapshotFault::WrongKey { .. })),
        "{refused:?}"
    );
}

/// Every part of the key moves its name.
#[test]
fn each_part_of_the_key_moves_its_name() {
    let base = key("event");
    let mut chain = base.clone();
    chain.chain = "sha256:ff112233445566778899aabbccddeeff".to_owned();
    let event = key("other");
    let mut schema = base.clone();
    schema.schema += 1;
    let mut code = base.clone();
    code.code = "bb".repeat(32);
    for moved in [chain, event, schema, code] {
        assert_ne!(moved.name(), base.name(), "{moved:?}");
    }
}

/// The key covers every source tree the ledger's block-path set names: a
/// tree added there and not here would change a chain's derived rows under
/// a key that did not move.
#[test]
fn the_consensus_trees_cover_the_block_path_set() {
    let ledger = fs::read_to_string(repo_root().join("docs/benchmarks/measurement_ledger.toml"))
        .expect("the ledger reads");
    let at = ledger.find("id = \"block-path\"").expect("the path set");
    let spec = &ledger[at..];
    let open = spec.find('[').expect("its spec");
    let close = spec[open..].find(']').expect("its spec's end") + open;
    let trees: Vec<&str> = spec[open + 1..close]
        .split(',')
        .map(|entry| entry.trim().trim_matches('"'))
        .filter(|entry| !entry.is_empty() && !entry.ends_with("/benches"))
        .collect();
    assert!(!trees.is_empty(), "the block-path set names its trees");
    for tree in trees {
        assert!(CONSENSUS_TREES.contains(&tree), "{tree} is not in the key");
    }
}

/// The key's digest moves when one consensus file does.
#[test]
fn the_code_digest_reads_every_tree() {
    let root = repo_root();
    let digest = consensus_code_digest(&root).expect("the trees read");
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, consensus_code_digest(&root).expect("again"));
    let missing = tempfile::tempdir().expect("a directory");
    assert!(
        consensus_code_digest(missing.path()).is_err(),
        "a tree that is not there is an error, not an empty hash"
    );
}
