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

use shekyl_chain_rules::{validate, AtHeight, Candidate, ChainView, RuleSet, Tip};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use super::store_tests::{cleanup, tmp, TestErr, EPOCH, PROBE_ROW};
use super::*;
use crate::codec::{BlockInfo, Canonical, CodecError, CurveRoot};
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
            // Recorded blocks are written straight into the tables here
            // (not through `validate`), so this header is not judged under
            // CEN-B5; the value is a placeholder, as it is in LMDB fixtures.
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
        assert_eq!(
            Tip::connecting_height(view.tip()?.as_ref()),
            BlockHeight::ZERO
        );

        let b0 = block(0, 1_000);
        record_block(batch, 0, &b0)?;
        let tip = view.tip()?.expect("one block recorded");
        assert_eq!(tip.height, BlockHeight::ZERO);
        assert_eq!(tip.hash, BlockHash::from_bytes(b0.hash()));
        assert_eq!(Tip::connecting_height(Some(&tip)), BlockHeight::from_raw(1));

        let b1 = block(1, 1_060);
        record_block(batch, 1, &b1)?;
        let tip = view.tip()?.expect("two blocks recorded");
        assert_eq!(tip.height, BlockHeight::from_raw(1));
        assert_eq!(tip.hash, BlockHash::from_bytes(b1.hash()));
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
        // already contains block 0. Since E6 slice 1 the rules READ the view:
        // CEN-A2 wants `previous == tip.hash` and CEN-B5 wants the header's
        // root to be `root_at(1)` — the row recorded above — so block 1
        // passes only if the projection shows it block 0 and the root block
        // 0 left. The title's claim is now the verdict, not just the type.
        let mut b1 = block(1, 1_060);
        b1.header.previous = genesis.hash();
        b1.header.curve_tree_root = [0xaa; 32];
        let valid = validate(Candidate::new(b1, Vec::new()), &view, &RuleSet::GENESIS)?
            .expect("block 1 built on block 0 satisfies every landed rule");
        assert_eq!(valid.rule_set_id(), RuleSet::GENESIS.id());
        assert!(valid.coverage().contains(shekyl_chain_rules::CenRow::A2));
        assert!(valid.coverage().contains(shekyl_chain_rules::CenRow::B5));
        // And a block 1 that does not build on block 0 is refused, not
        // connected-then-caught: the rule sits in front of SI-2's belt.
        let mut orphan = block(1, 1_060);
        orphan.header.curve_tree_root = [0xaa; 32];
        let Err(refused) = validate(Candidate::new(orphan, Vec::new()), &view, &RuleSet::GENESIS)?
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
    cleanup(&path);
}

#[test]
fn a_block_info_row_with_no_blocks_row_is_si7() {
    let path = tmp("view-info-without-blocks");
    let store = ChainStore::create(&path, EPOCH).expect("create");
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
    assert_eq!(tip.1.hash.to_bytes(), blk1.hash());
    match chain_reads::block_body(&txn, Some(&tip), 1).expect("block_body") {
        AtHeight::Recorded((hash, body)) => {
            assert_eq!(hash.to_bytes(), blk1.hash());
            assert_eq!(body, blk1);
            assert_eq!(
                batch_tip_block,
                AtHeight::Recorded(RecordedBlock {
                    hash: BlockHash::from_bytes(hash.to_bytes()),
                    header: body.header,
                }),
                "the batch view is the same body wrapped"
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
            blocks.insert(2, rewritten.as_slice()).expect("rewrite 2");
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

/// The one deliberate tightening the shared body brought (its module docs,
/// *The tip is one decoded read*), pinned as the scenario the PR #764 review
/// named: heights 0 and 1 recorded, `block_info[1]` — the tip — rewritten
/// to bytes that do not decode. Before, `block_at(0)` succeeded and
/// `block_at(2)` was `AboveTip` because the tip was read by key alone; now
/// **every** classified read is SI-7 `block_info` / `Undecodable` and the
/// batch is poisoned — a store whose tip row does not decode has no trusted
/// tip, and `connect` would poison on this same row before its first belt.
#[test]
fn an_undecodable_tip_row_is_si7_on_every_classified_read() {
    let path = tmp("view-undecodable-tip");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let planted: Result<(), TestErr> = store.write(|batch| {
        record_block(batch, 0, &block(0, 1_000))?;
        record_block(batch, 1, &block(1, 1_060))?;
        Ok(())
    });
    planted.expect("plant");
    drop(store);
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        {
            let mut infos = txn.open_table(BLOCK_INFO).expect("block_info");
            infos
                .insert(1, &[0xee; 87][..])
                .expect("87 bytes: not a BlockInfo");
        }
        txn.commit().expect("commit");
    }
    // One handle per height: the branded-view SI-7 halts the *writer*, and
    // the halt lives in the handle (DRS §3.6.2 — re-derived on restart,
    // never persisted). A second `write` on the same handle is refused at
    // admission as `WriterHalted` before the closure runs, which would let
    // the outer assertion pass without `block_at` ever being called — the
    // PR #764 review caught exactly that. The outer assertion also names
    // the row, so a refusal cannot satisfy it.
    for asked in [0u64, 1, 2] {
        let store = ChainStore::create(&path, EPOCH).expect("reopen");
        assert_eq!(store.connect_state(), ConnectState::Live, "fresh handle");
        let mut ran = false;
        let out: Result<(), TestErr> = store.write(|batch| {
            ran = true;
            let e = batch
                .chain_view()
                .block_at(BlockHeight::from_raw(asked))
                .expect_err("the tip row does not decode");
            assert!(
                matches!(
                    e,
                    StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                        key: "block_info",
                        fault: CellFault::Undecodable(_),
                    })
                ),
                "block_at({asked}): {e}"
            );
            Ok(())
        });
        assert!(ran, "block_at({asked}) must actually run");
        let expected = StoreError::from(StoreInvariant::CellCorrupt {
            key: "block_info",
            fault: CellFault::Undecodable(CodecError::Length {
                codec: "block_info",
                expected: 88,
                actual: 87,
            }),
        })
        .to_string();
        assert_eq!(
            out,
            Err(TestErr::Store(expected)),
            "block_at({asked}) must poison the batch with the tip row's SI-7"
        );
        assert!(
            matches!(store.connect_state(), ConnectState::Halted { .. }),
            "the branded-view SI-7 halts the writer (block_at({asked}))"
        );
    }
    cleanup(&path);
}
