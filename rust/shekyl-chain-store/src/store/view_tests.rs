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

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{validate, AtHeight, Candidate, ChainView, Fault, RuleSet, Trust};
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Block, BlockHeader, Transaction};

use super::connect_fixtures::formed;
use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE_ROW};
use super::*;
use crate::codec::{forged, BlockBody, BlockInfo, Canonical, CodecError, Present, Raw};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{BLOCKS, BLOCK_INFO, CURVE_TREE_ROOTS, SPENT_KEYS, UNDO_LOG};

/// The store's fault is the only outer arm these tests expect; the
/// validation crate's own arms are fixture bugs here, named as such.
fn view_fault(fault: Fault<StoreError>) -> StoreError {
    match fault {
        Fault::View(fault) => fault,
        Fault::Stale(stale) => panic!("fixture claim went stale: {stale}"),
        Fault::Corrupt(corrupt) => panic!("fixture view is corrupt: {corrupt}"),
    }
}

/// The rules harness's coinbase: round-trips through the block parser
/// (§2.5: a sole `gen` input and a `Null` ct) and satisfies every landed
/// 4.F row. Since slice 4 the harness fixture is the valid one; this
/// file's private copy (keys that were not points) went with it.
fn coinbase(height: u64) -> Transaction {
    fixture::coinbase(height)
}

fn block(height: u64, timestamp: u64) -> Block {
    let blk = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp,
            previous: BlockHash::from_bytes([0x11; 32]),
            nonce: 7,
            // Recorded blocks are written straight into the tables here
            // (not through `validate`), so this header is not judged under
            // CEN-B5; the value is a placeholder, as it is in LMDB fixtures.
            curve_tree_root: CurveTreeRoot::from_bytes([0x22; 32]),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
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
        timestamp: shekyl_types::Timestamp::from_raw(blk.header.timestamp),
        coins_generated: shekyl_units::AtomicUnits::ZERO,
        weight: shekyl_types::BlockWeight::ZERO,
        cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
        hash: blk.hash(),
        rct_outputs: 0,
        long_term_weight: shekyl_types::LongTermWeight::ZERO,
        cumulative_tx_count: 0,
        long_term_effective_median: shekyl_types::LongTermWeight::ZERO,
    };
    batch
        .open_insert_table(BLOCK_INFO, PROBE_ROW)?
        .insert(height, info.encoded().as_encoded())?;
    batch
        .open_insert_table(BLOCKS, PROBE_ROW)?
        .insert(height, Raw::<BlockBody>::new(&blk.serialize()))?;
    Ok(())
}

fn record_root(batch: &WriteBatch<'_, '_>, key: u64, byte: u8) -> Result<(), StoreError> {
    batch
        .open_insert_table(CURVE_TREE_ROOTS, PROBE_ROW)?
        .insert(
            key,
            CurveTreeRoot::from_bytes([byte; 32]).encoded().as_encoded(),
        )
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

/// `tip()` is the trait's read of the same `block_info.last()` the other
/// two classify against: `None` on an empty chain, then the last recorded
/// block's height and identity — the identity `block_at` returns for that
/// height, so a rule reading `previous == tip.hash` (CEN-A2) and one reading
/// `block_at(tip.height)` agree by construction (E6 slice 1).
#[test]
fn tip_is_none_on_an_empty_chain_and_the_last_recorded_identity_after() {
    let path = tmp("view-tip");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        assert_eq!(view.tip()?, None, "empty chain: no tip, not a sentinel");

        let b0 = block(0, 1_000);
        record_block(batch, 0, &b0)?;
        let tip = view.tip()?.expect("one block recorded");
        assert_eq!(tip.height, BlockHeight::ZERO);
        assert_eq!(tip.hash, b0.hash());

        let b1 = block(1, 1_060);
        record_block(batch, 1, &b1)?;
        let tip = view.tip()?.expect("two blocks recorded");
        assert_eq!(tip.height, BlockHeight::from_raw(1));
        assert_eq!(tip.hash, b1.hash());
        let AtHeight::Recorded(recorded) = view.block_at(tip.height)? else {
            panic!("the tip's height is recorded");
        };
        assert_eq!(
            recorded.hash, tip.hash,
            "tip() and block_at(tip.height) name one block"
        );
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
    // Obtaining the branded view is chain work: the SI-7 latches the halt
    // even though `connect` was never called (PR #757 review).
    assert_eq!(
        store.connect_state(),
        ConnectState::Halted {
            at_height: BlockHeight::from_raw(2),
            row: StoreInvariant::CellCorrupt {
                key: "curve_tree_roots",
                fault: CellFault::Absent,
            },
        }
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
        assert_eq!(recorded.hash, blk.hash());
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
            timestamp: shekyl_types::Timestamp::from_raw(recorded.header.timestamp),
            coins_generated: shekyl_units::AtomicUnits::ZERO,
            weight: shekyl_types::BlockWeight::ZERO,
            cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
            hash: recorded.hash(),
            rct_outputs: 0,
            long_term_weight: shekyl_types::LongTermWeight::ZERO,
            cumulative_tx_count: 0,
            long_term_effective_median: shekyl_types::LongTermWeight::ZERO,
        };
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(0, info.encoded().as_encoded())?;
        batch
            .open_insert_table(BLOCKS, PROBE_ROW)?
            .insert(0, Raw::<BlockBody>::new(&replaced.serialize()))?;
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
            .insert(LmdbHashKey::from_bytes(*spent.as_bytes()), Present)?;
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
        // already contains block 0. Since E6 slice 1 the rules READ the view:
        // CEN-A2 wants `previous == tip.hash` and CEN-B5 wants the header's
        // root to be `root_at(1)` — the row recorded above — so block 1
        // passes only if the projection shows it block 0 and the root block
        // 0 left. The title's claim is now the verdict, not just the type.
        let mut b1 = block(1, 1_060);
        b1.header.previous = genesis.hash();
        b1.header.curve_tree_root = CurveTreeRoot::from_bytes([0xaa; 32]);
        let valid = validate(
            formed(&view, Candidate::new(b1, Vec::new()))?,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        )
        .map_err(view_fault)?
        .expect("block 1 built on block 0 satisfies every landed rule");
        assert_eq!(valid.rule_set_id(), RuleSet::GENESIS.id());
        assert!(valid.coverage().contains(shekyl_chain_rules::CenRow::A2));
        assert!(valid.coverage().contains(shekyl_chain_rules::CenRow::B5));
        // And a block 1 that does not build on block 0 is refused, not
        // connected-then-caught: the rule sits in front of SI-2's belt.
        let mut orphan = block(1, 1_060);
        orphan.header.curve_tree_root = CurveTreeRoot::from_bytes([0xaa; 32]);
        let Err(refused) = validate(
            formed(&view, Candidate::new(orphan, Vec::new()))?,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        )
        .map_err(view_fault)?
        else {
            panic!("a block 1 not built on block 0 is refused");
        };
        // The row and the locus, read off the refusal — this crate never
        // names the verdict type (conversion-ban clause 2).
        assert_eq!(refused.rule, shekyl_chain_rules::CenRow::A2);
        assert_eq!(refused.locus, shekyl_chain_rules::Locus::Block);
        let AtHeight::Recorded(recorded) = view.block_at(BlockHeight::ZERO)? else {
            panic!("block 0 is visible to the second block's validation");
        };
        assert_eq!(recorded.hash, genesis.hash());
        Ok(())
    });
    assert_eq!(out, Ok(()));
    cleanup(&path);
}

/// A corrupt row read through the view is SI-7, and the batch refuses to
/// commit even when the closure swallows the fault. Planted on the surface
/// where a corrupt row is still **representable**: a `blocks` blob that does
/// not parse. It used to be planted as a 3-byte `block_info` row; under
/// §11.1(f) `block_info` is `Coded<BlockInfo>`, fixed-width 104, and the
/// crate refuses a wrong width before redb would assert it — a wrong-width
/// `block_info` row cannot reach
/// the file (`a_wrong_width_row_is_refused_before_it_can_reach_a_coded_table` below), so its
/// `Undecodable` arm has no instance to pin.
#[test]
fn a_corrupt_row_read_through_the_view_is_si7_and_poisons_the_batch() {
    let path = tmp("view-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        record_block(batch, 2, &block(2, 1_120))?;
        Ok(())
    });
    planted.expect("plant");
    drop(store);
    // Below the tip, with its `block_info` row intact: the blob alone is
    // what does not decode. Planted around the write boundary — a crate
    // handle would refuse an unparseable `BlockBody` as `RowIllFormed`.
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(BLOCKS)
            .expect("t")
            .insert(1, Raw::<BlockBody>::new(&[1u8, 2, 3]))
            .expect("plant");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");

    // The closure swallows the fault and returns Ok; the batch still refuses.
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let e = view
            .block_at(BlockHeight::from_raw(1))
            .expect_err("a 3-byte blob is not a block");
        assert!(
            matches!(
                e,
                StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                    key: "blocks",
                    fault: CellFault::Undecodable(CodecError::Invalid {
                        codec: "block",
                        reason: "block blob does not parse",
                    }),
                })
            ),
            "{e}"
        );
        Ok(())
    });
    assert!(
        matches!(
            out,
            Err(TestErr::Store(ref msg)) if msg.contains("SI-7 violated: typed cell `blocks`")
        ),
        "{out:?}"
    );
    cleanup(&path);
}

#[test]
fn a_block_info_row_with_no_blocks_row_is_si7() {
    let path = tmp("view-info-without-blocks");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        let info = BlockInfo {
            timestamp: shekyl_types::Timestamp::from_raw(1),
            coins_generated: shekyl_units::AtomicUnits::ZERO,
            weight: shekyl_types::BlockWeight::ZERO,
            cumulative_difficulty: shekyl_difficulty::CumulativeDifficulty::from_raw(1),
            hash: shekyl_types::BlockHash::from_bytes([9; 32]),
            rct_outputs: 0,
            long_term_weight: shekyl_types::LongTermWeight::ZERO,
            cumulative_tx_count: 0,
            long_term_effective_median: shekyl_types::LongTermWeight::ZERO,
        };
        batch
            .open_insert_table(BLOCK_INFO, PROBE_ROW)?
            .insert(7, info.encoded().as_encoded())?;
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

// --- chain_reads: one body, two transactions (S-CHAIN-R commit 1) --------

/// The shared body over a **read** transaction returns exactly what the
/// batch view returned over the **write** transaction for the same rows —
/// tip, identity, verified body. Read after the store is dropped, through a
/// raw redb handle: the snapshot reader (S-CHAIN-R commit 3) will sit on the
/// same `ReadTransaction` impl, and this pins that the impl exists and
/// agrees before it has a production caller.
#[test]
fn the_read_transaction_body_agrees_with_the_batch_body() {
    use super::chain_reads;
    use shekyl_chain_rules::RecordedBlock;
    let path = tmp("view-chain-reads-agree");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let blk0 = block(0, 1_000);
    let blk1 = block(1, 1_060);
    let seen: Result<(AtHeight<RecordedBlock>, AtHeight<RecordedBlock>), TestErr> =
        store.write(|batch| {
            record_block(batch, 0, &blk0)?;
            record_block(batch, 1, &blk1)?;
            let view = batch.chain_view();
            Ok((
                view.block_at(BlockHeight::from_raw(1))?,
                view.block_at(BlockHeight::from_raw(2))?,
            ))
        });
    let (batch_tip_block, batch_above) = seen.expect("write");
    drop(store);

    let db = redb::Database::open(&path).expect("raw open");
    let txn = db.begin_read().expect("raw read");
    let tip = chain_reads::tip_of(&txn)
        .expect("tip_of")
        .expect("two blocks recorded");
    assert_eq!(tip.0, 1);
    assert_eq!(tip.1.hash, blk1.hash());
    match chain_reads::block_body(&txn, Some(&tip), 1).expect("block_body") {
        AtHeight::Recorded((info, body)) => {
            assert_eq!(info.hash, blk1.hash());
            assert_eq!(body, blk1);
            assert_eq!(
                batch_tip_block,
                AtHeight::Recorded(RecordedBlock {
                    hash: info.hash,
                    header: body.header,
                    cumulative_difficulty: info.cumulative_difficulty,
                    coins_generated: info.coins_generated,
                    cumulative_tx_count: info.cumulative_tx_count,
                }),
                "the batch view is the same body wrapped, with the row's work"
            );
        }
        AtHeight::AboveTip => panic!("height 1 is the tip"),
    }
    assert!(matches!(
        chain_reads::block_body(&txn, Some(&tip), 2).expect("above tip"),
        AtHeight::AboveTip
    ));
    assert_eq!(batch_above, AtHeight::AboveTip);
    drop(txn);
    drop(db);
    cleanup(&path);
}

/// On the read side a hole below the tip is the same SI-7 `Absent` the
/// batch view arms — classified in the shared body — and a corrupt blob is
/// the same SI-7 on `blocks`. Nothing is poisoned: there is no batch. The
/// difference between the two readers is the wrap, not the classification.
#[test]
fn the_read_transaction_body_classifies_holes_and_bad_blobs_as_si7() {
    use super::chain_reads::{self, ReadFault};
    let path = tmp("view-chain-reads-holes");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        record_block(batch, 2, &block(2, 1_120))?;
        Ok(())
    });
    planted.expect("plant");
    drop(store);

    // Punch a hole at 1 and corrupt the blob at 2, bypassing the store.
    let db = redb::Database::open(&path).expect("raw open");
    {
        let txn = db.begin_write().expect("raw write");
        {
            let mut blocks = txn.open_table(BLOCKS).expect("blocks");
            blocks.remove(1).expect("remove 1");
            let rewritten = block(2, 9_999).serialize();
            blocks
                .insert(2, Raw::<BlockBody>::new(&rewritten))
                .expect("rewrite 2");
        }
        txn.commit().expect("commit");
    }
    let txn = db.begin_read().expect("raw read");
    let tip = chain_reads::tip_of(&txn).expect("tip_of");
    assert_eq!(tip.as_ref().map(|t| t.0), Some(2));
    match chain_reads::block_body(&txn, tip.as_ref(), 1) {
        Err(ReadFault::Invariant(StoreInvariant::CellCorrupt {
            key: "blocks",
            fault: CellFault::Absent,
        })) => {}
        other => panic!("a hole below the tip is SI-7 Absent on `blocks`, got {other:?}"),
    }
    match chain_reads::block_body(&txn, tip.as_ref(), 2) {
        Err(ReadFault::Invariant(StoreInvariant::CellCorrupt {
            key: "blocks",
            fault: CellFault::Undecodable(_),
        })) => {}
        other => panic!(
            "a blob that does not hash to block_info.hash is SI-7 on `blocks`, got {other:?}"
        ),
    }
    // And a plain absent cell in a table that exists is `Ok(None)`: the
    // caller classifies it. (Asked of `block_info`, not `curve_tree_roots`:
    // nothing in this fixture has written a root, and until the layout
    // commit seals the chain table set an unwritten table is
    // `TableDoesNotExist` — SCR-17, amendment A2, S-CHAIN-R commit 2.)
    let none: Option<BlockInfo> =
        chain_reads::cell(&txn, BLOCK_INFO, 5, "block_info").expect("cell");
    assert!(none.is_none());
    drop(txn);
    drop(db);
    cleanup(&path);
}

/// §11.1(f): a `Coded<V>` table reports `V::FIXED_WIDTH` to the engine, and
/// the engine **asserts** it in `LeafBuilder::append` (redb 4.1
/// `btree_base.rs`) — a panic that poisons the transaction lock. So the
/// scenario this test used to pin — `block_info[tip]` rewritten to 87 bytes,
/// then SI-7 `Undecodable` on every classified read (the PR #764 review's
/// case) — has **no representable instance**: the bytes never reach the
/// file. The tightening it motivated stands (`chain_reads` module docs, *The
/// tip is one decoded read*); what changed is that `BlockInfo`, whose codec
/// checks only width (now 104 bytes), can no longer be undecodable in a file
/// redb accepted.
///
/// This test pins what replaced the scenario: the wrong-width write is
/// refused **by this crate, as a value**, before the engine's assertion.
/// `Canonical::encoded` cannot produce it, but redb's `Value::from_bytes` is
/// a public trait method and can (`codec::forged` is that call, spelled
/// once for the tests), so every write through the crate's handles checks the
/// width first (`keyed::check_row`) and returns `StoreCannot::RowWidth`.
/// Nothing lands, nothing panics, and the store is still usable afterwards.
#[test]
fn a_wrong_width_row_is_refused_before_it_can_reach_a_coded_table() {
    let path = tmp("view-wrong-width");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        Ok(())
    });
    planted.expect("plant");
    let refused: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_upsert_table(BLOCK_INFO)?
            .upsert(1, forged(&[0xee; 103]))?;
        Ok(())
    });
    let expected = StoreError::from(StoreCannot::RowWidth {
        table: "block_info",
        expected: BlockInfo::FIXED_WIDTH.expect("fixed"),
        actual: 103,
    })
    .to_string();
    assert_eq!(refused, Err(TestErr::Store(expected)));
    // The refused write left nothing behind, and the writer is not halted:
    // a caller error is a refusal (`StoreCannot`), not an invariant.
    assert_eq!(store.connect_state(), ConnectState::Live);
    let out: Result<(), TestErr> = store.write(|batch| {
        let AtHeight::Recorded(recorded) = batch
            .chain_view()
            .block_at(BlockHeight::from_raw(1))
            .expect("block_at(1)")
        else {
            panic!("height 1 is recorded");
        };
        assert_eq!(recorded.hash, block(1, 1_060).hash());
        Ok(())
    });
    assert_eq!(out, Ok(()), "the recorded rows are as they were");
    cleanup(&path);
}

/// Variable-width `Coded<V>` reports `fixed_width() == None`, so the width
/// check is a no-op. The insertion boundary still runs `V::decode` via
/// `Restorable::well_formed`: a forged `Encoded<UndoLog>` that is not a
/// row never reaches the file.
#[test]
fn a_variable_width_coded_row_that_does_not_decode_is_refused() {
    let path = tmp("view-ill-formed-undo");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let refused: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_upsert_table(UNDO_LOG)?
            .upsert(0, forged(&[0xee; 3]))?;
        Ok(())
    });
    let expected = StoreError::from(StoreCannot::RowIllFormed {
        table: "undo_log",
        reason: "row does not decode under the table's codec",
    })
    .to_string();
    assert_eq!(refused, Err(TestErr::Store(expected)));
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}
