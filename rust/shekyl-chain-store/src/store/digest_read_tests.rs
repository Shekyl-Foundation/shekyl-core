// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `ReadSnapshot::logical_state_digest_v0` (DRS-E2 RD-F5): the redb
//! assembly agrees with the pure function over independently gathered
//! inputs, carries its components, is pop-symmetric, and refuses a hole.

use shekyl_chain_rules::AtHeight;
use shekyl_types::{BlockHeight, CurveTreeRoot};

use super::connect_fixtures::{connect_chain, root_at_height, spend};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::digest_v0::{chain_component, digest_v0, spent_accumulator, LogicalStateDigestV0};
use crate::schema::CURVE_TREE_ROOTS;

/// Three blocks: genesis, one spend, two spends — three key images.
fn three_blocks() -> Vec<Vec<shekyl_wire::Transaction>> {
    vec![vec![], vec![spend(1, 1)], vec![spend(2, 1), spend(3, 1)]]
}

/// The three families gathered **without** the assembly under test: block
/// hashes one point read at a time, key images through K2, the root from
/// the fixture's own function of height (what `connect_chain` handed in).
fn independent_inputs(
    snap: &ReadSnapshot<'_>,
    tip: u64,
) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, CurveTreeRoot) {
    let hashes: Vec<[u8; 32]> = (0..=tip)
        .map(|h| {
            let AtHeight::Recorded(info) = snap.block_info(BlockHeight::from_raw(h)).expect("read")
            else {
                panic!("block_info[{h}] below the tip");
            };
            info.hash.to_bytes()
        })
        .collect();
    let spent: Vec<[u8; 32]> = snap
        .key_images()
        .expect("k2")
        .map(|k| k.expect("row").to_bytes())
        .collect();
    (hashes, spent, root_at_height(tip + 1))
}

#[test]
fn an_empty_store_digests_the_empty_families_and_the_empty_tree() {
    let path = tmp("digest-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let got = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    assert_eq!(
        got,
        LogicalStateDigestV0 {
            n_blocks: 0,
            n_spent: 0,
            chain: chain_component(&[]),
            spent: spent_accumulator(&[]),
            curve_root: CurveTreeRoot::EMPTY,
            digest: digest_v0(&[], &[], CurveTreeRoot::EMPTY.as_bytes()),
        }
    );
    cleanup(&path);
}

#[test]
fn the_redb_assembly_equals_the_pure_function_over_independently_read_inputs() {
    let path = tmp("digest-three");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes_connected = connect_chain(&store, &three_blocks());
    let snap = store.begin_read().expect("read");
    let (hashes, spent, root) = independent_inputs(&snap, 2);
    assert_eq!(
        hashes,
        hashes_connected
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>(),
        "the height-ordered hashes are the connected blocks'"
    );
    assert_eq!(spent.len(), 3, "three key images were spent");

    let got = snap.logical_state_digest_v0().expect("digest");
    assert_eq!(got.n_blocks, 3);
    assert_eq!(got.n_spent, 3);
    assert_eq!(got.chain, chain_component(&hashes));
    assert_eq!(got.spent, spent_accumulator(&spent));
    assert_eq!(
        got.curve_root, root,
        "the live root is curve_tree_roots[tip + 1]"
    );
    assert_eq!(
        got.digest,
        digest_v0(&hashes, &spent, root.as_bytes()),
        "assembled from components, the outer digest is the pure function's"
    );
    // The components are not the digest: a consumer that read only the
    // outer value could not tell the borrowed root from the real families.
    assert_ne!(got.chain, got.digest);
    assert_ne!(got.spent, got.digest);
    cleanup(&path);
}

#[test]
fn pop_returns_the_digest_to_its_earlier_value() {
    // Pop symmetry is the property DRS-0's set-shaped accumulator was built
    // for; the full-scan digest must agree with it on the same state.
    let path = tmp("digest-pop");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let blocks = three_blocks();
    connect_chain(&store, &blocks[..2]);
    let before = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    // Connect the third block on top, then pop it.
    let store2_path = tmp("digest-pop-full");
    let full = ChainStore::create(&store2_path, EPOCH).expect("create");
    connect_chain(&full, &blocks);
    let with_three = full
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    assert_ne!(with_three.digest, before.digest);
    assert_eq!(with_three.n_blocks, 3);
    let out: Result<Popped, TestErr> = full.write(|batch| Ok(batch.pop()?));
    out.expect("pop");
    let after = full
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    assert_eq!(
        after, before,
        "two stores at the same logical state digest alike"
    );
    cleanup(&path);
    cleanup(&store2_path);
}

#[test]
fn a_missing_live_root_row_is_si7_naming_curve_tree_roots() {
    let path = tmp("digest-root-hole");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &three_blocks());
    drop(store);
    {
        let db = redb::Database::open(&path).expect("open raw");
        let txn = db.begin_write().expect("write");
        {
            let mut roots = txn.open_table(CURVE_TREE_ROOTS).expect("t");
            roots.remove(3u64).expect("remove tip + 1");
        }
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let err = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect_err("hole");
    assert!(
        matches!(
            err,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "curve_tree_roots",
                fault: CellFault::Absent,
            })
        ),
        "got {err:?}"
    );
    cleanup(&path);
}
