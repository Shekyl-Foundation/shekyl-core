// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `BatchView` tests (S-CHAIN-W commit 5): `root_at(h)` reads key `h` with
//! height 0 the empty tree (SCW-19), absence classified against the tip
//! (`AboveTip` only above it; a hole below it is SI-7), `block_at` parsed
//! from the recorded blob and held to `block_info`'s identity, batch-local
//! visibility across two blocks (SCW-13), and the corrupt-read → SI-7 →
//! poison path.

use shekyl_chain_rules::{validate, AtHeight, Candidate, ChainView, RuleSet};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE_ROW};
use super::*;
use crate::codec::{BlockInfo, Canonical, CurveRoot};
use crate::lmdb_order::{Hash32, LmdbHashKey};
use crate::schema::{BLOCKS, BLOCK_INFO, CURVE_TREE_ROOTS, SPENT_KEYS};

/// A coinbase the block parser accepts back (§2.5: a sole `gen` input and
/// a `Null` ct), with one output so the per-output base arrays are
/// non-empty. `block_at` parses the recorded blob, so the fixture must
/// round-trip — the rules crate's inputless fixture would not.
fn coinbase(height: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height + 60,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount: 0,
                key: [0x44; 32],
                view_tag: 1,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]],
            enc_labels: vec![[0x66; 9]],
            commitments: vec![[0x77; 32]],
        }),
    }
}

fn block(height: u64, timestamp: u64) -> Block {
    let blk = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp,
            previous: [0x11; 32],
            nonce: 7,
            curve_tree_root: [0x22; 32],
            attestation_root: [0x33; 32],
        },
        miner_transaction: coinbase(height),
        transaction_hashes: Vec::new(),
    };
    assert_eq!(
        Block::from_bytes(&blk.serialize()).expect("fixture round-trips"),
        blk
    );
    blk
}

/// Write the two rows `block_at` reads, as a connect will.
fn record_block(batch: &WriteBatch<'_, '_>, height: u64, blk: &Block) -> Result<(), StoreError> {
    let info = BlockInfo {
        timestamp: blk.header.timestamp,
        coins_generated: 0,
        weight: 0,
        cumulative_difficulty: 1,
        hash: Hash32::from_bytes(blk.hash()),
        rct_outputs: 0,
        long_term_weight: 0,
    };
    batch
        .open_insert_table(BLOCK_INFO, PROBE_ROW)?
        .insert(height, info.encode().as_slice())?;
    batch
        .open_insert_table(BLOCKS, PROBE_ROW)?
        .insert(height, blk.serialize().as_slice())?;
    Ok(())
}

fn record_root(batch: &WriteBatch<'_, '_>, key: u64, byte: u8) -> Result<(), StoreError> {
    batch
        .open_insert_table(CURVE_TREE_ROOTS, PROBE_ROW)?
        .insert(key, CurveRoot::from_bytes([byte; 32]).encode().as_slice())
}

#[test]
fn root_at_reads_key_h_and_height_zero_is_the_empty_tree() {
    let path = tmp("view-root");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        // Two blocks recorded (tip = 1). Block h's connect writes the
        // post-drain root at h + 1, so the rows are 1 and 2 — and the state
        // *at* height h is key h.
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        record_root(batch, 1, 0xa1)?;
        record_root(batch, 2, 0xa2)?;
        let view = batch.chain_view();
        assert_eq!(
            view.root_at(BlockHeight::from_raw(0))?,
            AtHeight::Recorded(CurveTreeRoot::EMPTY),
            "height 0 has no row in either store: the tree there is empty"
        );
        assert_eq!(
            view.root_at(BlockHeight::from_raw(1))?,
            AtHeight::Recorded(CurveTreeRoot::from_bytes([0xa1; 32])),
            "root_at(1) is key 1 — written by block 0's connect, the anchor for a reference to 1"
        );
        assert_eq!(
            view.root_at(BlockHeight::from_raw(2))?,
            AtHeight::Recorded(CurveTreeRoot::from_bytes([0xa2; 32])),
            "tip + 1 is recorded: the state a candidate at 2 is checked against (CEN-B5)"
        );
        assert_eq!(
            view.root_at(BlockHeight::from_raw(3))?,
            AtHeight::AboveTip,
            "nothing has connected into height 3"
        );
        assert_eq!(
            view.root_at(BlockHeight::from_raw(u64::MAX))?,
            AtHeight::AboveTip
        );
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

#[test]
fn root_at_on_an_empty_chain_is_the_empty_tree_at_zero_and_above_tip_after() {
    let path = tmp("view-root-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        assert_eq!(
            view.root_at(BlockHeight::ZERO)?,
            AtHeight::Recorded(CurveTreeRoot::EMPTY)
        );
        assert_eq!(view.root_at(BlockHeight::from_raw(1))?, AtHeight::AboveTip);
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

/// A root row missing **inside** `1..=tip + 1` is store corruption, not
/// "above the tip": SI-7 with `Absent`, and the batch is poisoned. This is
/// the shape the LMDB reader got wrong (32 zero bytes for a missing key,
/// CEN-I12's absent-key walk) made unrepresentable.
#[test]
fn a_root_hole_below_the_tip_is_si7_not_above_tip() {
    let path = tmp("view-root-hole");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        record_root(batch, 2, 0xa2)?; // key 1 deliberately missing
        let e = batch
            .chain_view()
            .root_at(BlockHeight::from_raw(1))
            .expect_err("key 1 must exist once block 0 has connected");
        assert!(
            matches!(
                e,
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "curve_tree_roots",
                    fault: CellFault::Absent,
                })
            ),
            "{e}"
        );
        Ok(())
    });
    assert!(
        matches!(out, Err(TestErr::Store(ref msg)) if msg.contains("typed cell `curve_tree_roots`")),
        "{out:?}"
    );
    cleanup(&path);
}

#[test]
fn block_at_returns_the_identity_and_the_header_parsed_from_the_recorded_blob() {
    let path = tmp("view-block");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let blk = block(0, 1_700_000_000);
    let out: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &blk)?;
        let view = batch.chain_view();
        let AtHeight::Recorded(recorded) = view.block_at(BlockHeight::ZERO)? else {
            panic!("block 0 is recorded");
        };
        assert_eq!(recorded.hash, BlockHash::from_bytes(blk.hash()));
        assert_eq!(recorded.header, blk.header);
        assert_eq!(
            view.block_at(BlockHeight::from_raw(1))?,
            AtHeight::AboveTip,
            "dense below the tip, absent above it"
        );
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

/// A `block_info` row missing below the tip is a hole, not an above-tip
/// absence: SI-7 `Absent`, batch poisoned.
#[test]
fn a_block_info_hole_below_the_tip_is_si7_not_above_tip() {
    let path = tmp("view-block-hole");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 2, &block(2, 1_120))?; // height 1 deliberately missing
        let e = batch
            .chain_view()
            .block_at(BlockHeight::from_raw(1))
            .expect_err("height 1 is below the tip and must be recorded");
        assert!(
            matches!(
                e,
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "block_info",
                    fault: CellFault::Absent,
                })
            ),
            "{e}"
        );
        Ok(())
    });
    assert!(matches!(out, Err(TestErr::Store(_))), "{out:?}");
    cleanup(&path);
}

/// The blob must hash to the identity `block_info` records for it: a
/// replaced blob is never exposed to a rule as a `(hash, header)` pair.
#[test]
fn a_block_blob_that_does_not_hash_to_block_info_is_si7() {
    let path = tmp("view-block-identity");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        let recorded = block(0, 1_000);
        let replaced = block(0, 2_000); // parses, wrong identity
        let info = BlockInfo {
            timestamp: recorded.header.timestamp,
            coins_generated: 0,
            weight: 0,
            cumulative_difficulty: 1,
            hash: Hash32::from_bytes(recorded.hash()),
            rct_outputs: 0,
            long_term_weight: 0,
        };
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(0, info.encode().as_slice())?;
        batch
            .open_insert_table(BLOCKS, PROBE_ROW)?
            .insert(0, replaced.serialize().as_slice())?;
        let e = batch
            .chain_view()
            .block_at(BlockHeight::ZERO)
            .expect_err("blob identity differs from block_info.hash");
        assert!(
            e.to_string().contains("does not hash to block_info.hash"),
            "{e}"
        );
        Ok(())
    });
    assert!(matches!(out, Err(TestErr::Store(_))), "{out:?}");
    cleanup(&path);
}

#[test]
fn has_key_image_reads_spent_keys_and_sees_the_batch_s_own_writes() {
    let path = tmp("view-ki");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let spent = KeyImage::from_bytes([0x5e; 32]);
    let fresh = KeyImage::from_bytes([0x0f; 32]);
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        assert!(!view.has_key_image(&spent)?, "empty chain");
        batch
            .open_insert_table(SPENT_KEYS, PROBE_ROW)?
            .insert(LmdbHashKey::from_bytes(*spent.as_bytes()), ())?;
        // The same view, no new snapshot: a write earlier in this batch is
        // visible to a validation later in it (SCW-13).
        assert!(view.has_key_image(&spent)?);
        assert!(!view.has_key_image(&fresh)?);
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

/// The reason the view is a batch projection and not a snapshot: block 1,
/// validated inside the batch that recorded block 0, sees block 0.
#[test]
fn a_second_block_in_one_batch_validates_against_the_chain_the_first_left() {
    let path = tmp("view-two-blocks");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let genesis = block(0, 1_000);
    let out: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &genesis)?;
        record_root(batch, 1, 0xaa)?;
        let view = batch.chain_view();
        // A verdict minted against this batch's view, over a view that
        // already contains block 0 — `validate` with zero rules reads
        // nothing, so what this pins is the type plumbing: the verdict is
        // `ChainValid<'id, BatchView<'_, 'id>>` and its view saw the block.
        let valid = validate(
            Candidate::new(block(1, 1_060), Vec::new()),
            &view,
            &RuleSet::GENESIS,
        )?
        .expect("zero rules refuse nothing");
        assert_eq!(valid.rule_set_id(), RuleSet::GENESIS.id());
        let AtHeight::Recorded(recorded) = view.block_at(BlockHeight::ZERO)? else {
            panic!("block 0 is visible to the second block's validation");
        };
        assert_eq!(recorded.hash, BlockHash::from_bytes(genesis.hash()));
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

#[test]
fn a_corrupt_typed_cell_read_through_the_view_is_si7_and_poisons_the_batch() {
    let path = tmp("view-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Plant a `block_info` row that is not 88 bytes, and a `blocks` row that
    // is not a block.
    let planted: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(3, [1u8, 2, 3].as_slice())?;
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(4, block(9, 9).hash().as_slice())?; // wrong width too, but 32 B
        Ok(())
    });
    planted.expect("plant");

    // The closure swallows the fault and returns Ok; the batch still refuses.
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let e = view
            .block_at(BlockHeight::from_raw(3))
            .expect_err("a 3-byte block_info is not a BlockInfo");
        assert!(
            matches!(
                e,
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "block_info",
                    ..
                })
            ),
            "{e}"
        );
        Ok(())
    });
    assert!(
        matches!(
            out,
            Err(TestErr::Store(ref msg)) if msg.contains("SI-7 violated: typed cell `block_info`")
        ),
        "{out:?}"
    );

    // A `block_info` row with no `blocks` row is the other SI-7 shape.
    let planted: Result<(), TestErr> = store.write(|batch| {
        let info = BlockInfo {
            timestamp: 1,
            coins_generated: 0,
            weight: 0,
            cumulative_difficulty: 1,
            hash: Hash32::from_bytes([9; 32]),
            rct_outputs: 0,
            long_term_weight: 0,
        };
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(7, info.encode().as_slice())?;
        Ok(())
    });
    planted.expect("plant");
    let out: Result<(), TestErr> = store.write(|batch| {
        let e = batch
            .chain_view()
            .block_at(BlockHeight::from_raw(7))
            .expect_err("block_info without blocks");
        assert!(e.to_string().contains("typed cell `blocks`"), "{e}");
        Ok(())
    });
    assert!(matches!(out, Err(TestErr::Store(_))), "{out:?}");
    cleanup(&path);
}
